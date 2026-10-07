"""Enrichissement : couche d'intelligence externe.

Justification du choix de l'API (question explicitement posee au cahier des charges) :

    API RETENUE : ipwho.is
        - HTTPS natif, ce qui evite d'envoyer nos adresses IP observees en clair ;
        - aucune cle d'API, donc aucune fuite de secret possible dans le code ;
        - repond en JSON avec le pays, la ville, l'operateur, le numero de
          systeme autonome et le domaine de l'operateur ;
        - quota annonce suffisant pour un usage pedagogique.

    API DE SECOURS : ip-api.com
        - interrogee uniquement si la premiere ne repond pas ;
        - limitee a HTTP en version gratuite, ce qui est acceptable en secours
          car aucun secret n'y transite.

    CE QUE NOUS ENVOYONS : uniquement l'adresse IP distante deja observee dans
    le trafic. Jamais de donnee locale, jamais de contenu de paquet.

    CE QUE NOUS RECEVONS : pays, ville, operateur, organisation, ASN, domaine.

    CE QUE NOUS EN FAISONS : ces elements sont ajoutes a la section FAITS de
    l'explication, marques comme provenant d'une source externe. Ils ne servent
    jamais a deduire un comportement : le pays d'une adresse ne prouve rien sur
    l'intention de son proprietaire.

Les adresses privees ne declenchent AUCUN appel externe : leur nature est
determinee localement, elle ne s'enrichit pas.
"""

from __future__ import annotations

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

import httpx

from app.analysis.protocols import classify_address, describe_scope
from app.models import IPIntel

PRIMARY_API = "https://ipwho.is/{ip}"
FALLBACK_API = "http://ip-api.com/json/{ip}"
REVERSE_DNS_TIMEOUT = 2.0
# Un appel toutes les 1,5 s au maximum : respecte les quotas des API gratuites
MIN_INTERVAL_BETWEEN_CALLS = 1.5


class IPEnricher:
    """Enrichit une adresse IP, avec cache et degradation gracieuse."""

    def __init__(self, repository, settings) -> None:
        self.repo = repository
        self.settings = settings
        self._lock = threading.RLock()
        self._last_call = 0.0
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="enrich")
        self._client = httpx.Client(timeout=6.0, headers={"User-Agent": "packet-analyzer/1.0"})
        self.calls_made = 0
        self.cache_hits = 0

    # ------------------------------------------------------------------
    def lookup(self, ip: str | None) -> IPIntel:
        """Retourne les informations connues sur une adresse. Ne leve jamais."""
        if not ip:
            return IPIntel(ip="?", error="adresse absente")

        scope = classify_address(ip)
        intel = IPIntel(ip=ip, scope=scope, fetched_at=time.time())

        # Une adresse locale s'explique seule : aucun appel externe n'est utile.
        if scope != "public":
            intel.source = "classification locale"
            return intel

        # 1. Cache
        cached = self._from_cache(ip)
        if cached is not None:
            self.cache_hits += 1
            return cached

        if not self.settings.enrich_enabled:
            intel.source = "desactive"
            return intel

        # 2. Appel reseau
        intel = self._fetch(ip, scope)
        try:
            self.repo.save_intel(intel)
        except Exception:
            pass  # un cache indisponible ne doit pas casser l'analyse
        return intel

    # ------------------------------------------------------------------
    def _from_cache(self, ip: str) -> IPIntel | None:
        try:
            return self.repo.get_intel(ip, self.settings.enrich_cache_ttl_hours)
        except Exception:
            return None

    # ------------------------------------------------------------------
    def _fetch(self, ip: str, scope: str) -> IPIntel:
        """Interroge l'API principale, puis la seconde en cas d'echec."""
        self._respect_rate_limit()

        result = self._query_primary(ip)
        if result is None:
            result = self._query_fallback(ip)

        if result is None:
            return IPIntel(
                ip=ip, scope=scope, fetched_at=time.time(),
                error="aucune source externe n'a repondu",
            )

        result.scope = scope
        result.fetched_at = time.time()
        result.reverse_dns = self._reverse_dns(ip)
        return result

    # ------------------------------------------------------------------
    def _respect_rate_limit(self) -> None:
        with self._lock:
            elapsed = time.time() - self._last_call
            if elapsed < MIN_INTERVAL_BETWEEN_CALLS:
                time.sleep(MIN_INTERVAL_BETWEEN_CALLS - elapsed)
            self._last_call = time.time()
            self.calls_made += 1

    # ------------------------------------------------------------------
    def _query_primary(self, ip: str) -> IPIntel | None:
        """ipwho.is : HTTPS, sans cle."""
        try:
            response = self._client.get(PRIMARY_API.format(ip=ip))
            if response.status_code != 200:
                return None
            data = response.json()
            if not data.get("success", True):
                return None
            connection = data.get("connection") or {}
            return IPIntel(
                ip=ip,
                country=data.get("country"),
                country_code=data.get("country_code"),
                city=data.get("city"),
                isp=connection.get("isp") or connection.get("org"),
                org=connection.get("org"),
                asn=f"AS{connection['asn']}" if connection.get("asn") else None,
                source="ipwho.is",
            )
        except Exception:
            return None

    # ------------------------------------------------------------------
    def _query_fallback(self, ip: str) -> IPIntel | None:
        """ip-api.com : servie uniquement en secours."""
        try:
            response = self._client.get(
                FALLBACK_API.format(ip=ip),
                params={"fields": "status,country,countryCode,city,isp,org,as"},
            )
            if response.status_code != 200:
                return None
            data = response.json()
            if data.get("status") != "success":
                return None
            asn = data.get("as")
            return IPIntel(
                ip=ip,
                country=data.get("country"),
                country_code=data.get("countryCode"),
                city=data.get("city"),
                isp=data.get("isp"),
                org=data.get("org"),
                asn=asn.split(" ")[0] if asn else None,
                source="ip-api.com (secours)",
            )
        except Exception:
            return None

    # ------------------------------------------------------------------
    def _reverse_dns(self, ip: str) -> str | None:
        """Nom DNS inverse, avec delai maximal pour ne jamais bloquer l'analyse."""
        try:
            future = self._executor.submit(socket.gethostbyaddr, ip)
            name = future.result(timeout=REVERSE_DNS_TIMEOUT)[0]
            return name.rstrip(".").lower() or None
        except (FutureTimeout, socket.herror, socket.gaierror, OSError):
            return None
        except Exception:
            return None

    # ------------------------------------------------------------------
    @staticmethod
    def describe(ip: str) -> str:
        """Description immediate de la portee d'une adresse, sans appel reseau."""
        return describe_scope(ip)

    def close(self) -> None:
        try:
            self._client.close()
            self._executor.shutdown(wait=False)
        except Exception:
            pass
