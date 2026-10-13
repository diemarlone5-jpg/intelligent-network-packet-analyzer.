"""Stockage distant Supabase, via son API REST (PostgREST).

Pourquoi Supabase plutot qu'une base classique ?
    - l'application deployee en ligne doit lire un historique produit ailleurs
      (la capture n'est possible que sur la machine locale) : il faut donc une
      base joignable par HTTP, pas un fichier local ;
    - Supabase fournit une API REST immediatement exploitable, sans ecrire de
      serveur intermediaire ;
    - le meme jeu de tables sert au mode local et au mode en ligne.

Securite : la cle utilisee est la cle `service_role`, qui contourne les
politiques d'acces. Elle reste donc EXCLUSIVEMENT cote serveur, dans une
variable d'environnement. Elle ne doit jamais apparaitre dans le code, dans le
depot Git, ni dans une page web.
"""

from __future__ import annotations

import json
import time

import httpx

from app.models import Event, Flow, IPIntel, PacketRecord
from app.storage.base import Repository

TABLE_SESSIONS = "capture_sessions"
TABLE_FLOWS = "flows"
TABLE_EVENTS = "events"
TABLE_PACKETS = "packets"
TABLE_INTEL = "ip_intel"


def _adresse_rest(url: str) -> str:
    """Adresse de l'API REST, quelle que soit la forme de l'URL fournie.

    POURQUOI CETTE TOLERANCE

    L'interface de Supabase affiche l'adresse du projet sous plusieurs formes
    selon l'endroit ou l'on clique, et l'une d'elles finit par `/rest/v1/`. La
    coller telle quelle avec un code qui rajoute `/rest/v1` produit une adresse
    `/rest/v1/rest/v1` : toutes les requetes echouent en 404, avec un message qui
    ne dit pas pourquoi.

    On accepte donc les deux formes. Un utilisateur ne doit pas avoir a deviner
    laquelle est la bonne.
    """
    adresse = url.strip().rstrip("/")
    for suffixe in ("/rest/v1", "/rest"):
        if adresse.endswith(suffixe):
            adresse = adresse[: -len(suffixe)]
            break
    return adresse.rstrip("/") + "/rest/v1"


class SupabaseRepository(Repository):
    """Implementation distante du contrat de stockage.

    Chaque methode est protegee : une panne reseau ne doit jamais interrompre
    une capture en cours. Les erreurs sont conservees dans `last_error` pour
    etre affichees a l'utilisateur, jamais levees vers la couche d'analyse.
    """

    def __init__(self, url: str, service_key: str) -> None:
        self.base = _adresse_rest(url)
        self.service_key = service_key
        self.last_error: str | None = None
        self._client = httpx.Client(timeout=12.0, headers=self._headers())

    def _headers(self, extra: dict | None = None) -> dict[str, str]:
        """Entetes d'authentification.

        Supabase a deux generations de cles, et elles ne se presentent pas de la
        meme facon :

        - les cles historiques sont des JWT : elles exigent `apikey` ET
          `Authorization: Bearer` ;
        - les nouvelles cles `sb_publishable_...` / `sb_secret_...` ne sont PAS
          des jetons. Si on les met aussi dans `Authorization`, la passerelle
          tente de les lire comme un JWT et peut refuser la requete.

        On n'envoie donc le second entete que lorsqu'il a un sens : c'est ce que
        recommande la documentation Supabase pour les nouvelles cles.
        """
        headers = {"apikey": self.service_key, "Content-Type": "application/json"}
        if not self.service_key.startswith("sb_"):
            headers["Authorization"] = f"Bearer {self.service_key}"
        if extra:
            headers.update(extra)
        return headers

    # ------------------------------------------------------------------
    def _get(self, table: str, params: dict | None = None) -> list[dict] | None:
        try:
            response = self._client.get(f"{self.base}/{table}", params=params or {})
            if response.status_code >= 400:
                self.last_error = f"Supabase {table} : HTTP {response.status_code}"
                return None
            return response.json()
        except Exception as exc:
            self.last_error = f"Supabase injoignable ({type(exc).__name__})"
            return None

    def _insert(self, table: str, rows: list[dict], upsert_on: str | None = None) -> bool:
        """Ecrit des lignes. Avec `upsert_on`, remplace au lieu de dupliquer.

        POURQUOI `on_conflict` EST OBLIGATOIRE

        `Prefer: resolution=merge-duplicates` ne suffit pas : sans autre
        precision, PostgREST fusionne sur la CLE PRIMAIRE. Or nos tables ont un
        identifiant technique (`id`) qui ne rentre jamais en conflit, et une
        AUTRE contrainte d'unicite qui, elle, conflit a chaque renvoi — par
        exemple `(session_id, flow_key)` pour les communications.

        Resultat sans ce parametre : la des deuxieme envoi, Supabase repond
        HTTP 409 « duplicate key value violates unique constraint ». Les
        communications etaient donc ecrites une fois puis plus jamais mises a
        jour, alors que le moteur les renvoie toutes les 5 secondes.
        """
        if not rows:
            return True
        headers = {"Prefer": "return=minimal"}
        params: dict | None = None
        if upsert_on:
            headers["Prefer"] = "resolution=merge-duplicates,return=minimal"
            params = {"on_conflict": upsert_on}
        try:
            response = self._client.post(
                f"{self.base}/{table}",
                params=params or {},
                content=json.dumps(rows, default=str),
                headers=self._headers(headers),
            )
            if response.status_code >= 400:
                self.last_error = f"Ecriture {table} refusee : HTTP {response.status_code}"
                return False
            return True
        except Exception as exc:
            self.last_error = f"Ecriture {table} impossible ({type(exc).__name__})"
            return False

    # ------------------------------------------------------------------
    def init_schema(self) -> None:
        """Supabase ne cree pas de tables par API : le schema est applique
        depuis le fichier `schema/supabase.sql` dans l'editeur SQL du projet."""
        self.ping()

    def ping(self) -> bool:
        result = self._get(TABLE_SESSIONS, {"select": "id", "limit": 1})
        if result is None:
            return False
        self.last_error = None
        return True

    # ------------------------------------------------------------------
    def create_session(self, *, mode: str, interface: str, interface_name: str,
                       filter: str = "") -> int:
        payload = [{
            "started_at": time.time(), "mode": mode, "interface": interface,
            "interface_name": interface_name, "filter": filter,
        }]
        try:
            response = self._client.post(
                f"{self.base}/{TABLE_SESSIONS}",
                content=json.dumps(payload),
                headers=self._headers({"Prefer": "return=representation"}),
            )
            if response.status_code < 400 and response.json():
                return int(response.json()[0]["id"])
        except Exception as exc:
            self.last_error = f"Creation de session distante impossible ({type(exc).__name__})"
        # Identifiant local de repli : jamais None, pour ne pas casser l'appelant
        return int(time.time() * 1000) % 2_000_000_000

    def close_session(self, session_id: int, *, packets: int, bytes_total: int,
                      flows: int, events: int, note: str | None = None) -> None:
        payload = {
            "stopped_at": time.time(), "packets": packets, "bytes_total": bytes_total,
            "flows_count": flows, "events_count": events, "note": note,
        }
        try:
            self._client.patch(
                f"{self.base}/{TABLE_SESSIONS}",
                params={"id": f"eq.{session_id}"},
                content=json.dumps(payload, default=str),
                headers=self._headers({"Prefer": "return=minimal"}),
            )
        except Exception as exc:
            self.last_error = f"Cloture de session distante impossible ({type(exc).__name__})"

    def list_sessions(self, limit: int = 50) -> list[dict]:
        return self._get(TABLE_SESSIONS, {
            "select": "*", "order": "started_at.desc", "limit": limit,
        }) or []

    def close_orphan_sessions(self, note: str) -> int:
        """Cloture les sessions distantes restees ouvertes."""
        try:
            response = self._client.patch(
                f"{self.base}/{TABLE_SESSIONS}",
                params={"stopped_at": "is.null"},
                content=json.dumps({"stopped_at": time.time(), "note": note}),
                headers=self._headers({"Prefer": "return=representation"}),
            )
            if response.status_code < 400:
                return len(response.json() or [])
        except Exception as exc:
            self.last_error = f"Cloture des sessions orphelines impossible ({type(exc).__name__})"
        return 0

    def get_session(self, session_id: int) -> dict | None:
        rows = self._get(TABLE_SESSIONS, {"select": "*", "id": f"eq.{session_id}"})
        return rows[0] if rows else None

    # ------------------------------------------------------------------
    def save_flows(self, session_id: int, flows: list[Flow]) -> None:
        rows = [{
            "session_id": session_id, "flow_key": f.key,
            "first_seen": f.first_seen, "last_seen": f.last_seen,
            "duration": f.duration, "src": f.src, "dst": f.dst,
            "src_port": f.src_port, "dst_port": f.dst_port,
            "transport": f.transport, "app_protocol": f.app_protocol,
            "domain": f.domain, "state": f.state, "tcp_state": f.tcp_state,
            "packets": f.packets, "bytes_total": f.bytes_total,
            "bytes_fwd": f.bytes_fwd, "bytes_rev": f.bytes_rev,
            "retransmissions": f.retransmissions, "risk_score": f.risk_score,
            "explanation": getattr(f, "explanation_text", None),
        } for f in flows]
        self._insert(TABLE_FLOWS, rows, upsert_on="session_id,flow_key")

    def list_flows(self, session_id: int | None = None, limit: int = 500) -> list[dict]:
        params = {"select": "*", "order": "last_seen.desc", "limit": limit}
        if session_id is not None:
            params["session_id"] = f"eq.{session_id}"
        return self._get(TABLE_FLOWS, params) or []

    # ------------------------------------------------------------------
    def save_events(self, session_id: int, events: list[Event]) -> None:
        rows = [{
            "session_id": session_id, "ts": e.ts, "kind": e.kind, "rule": e.rule,
            "severity": e.severity, "title": e.title, "explanation": e.explanation,
            "evidence": e.evidence, "actor": e.actor, "flow_key": e.flow_key,
        } for e in events]
        self._insert(TABLE_EVENTS, rows)

    def list_events(self, session_id: int | None = None, limit: int = 300) -> list[dict]:
        params = {"select": "*", "order": "ts.desc", "limit": limit}
        if session_id is not None:
            params["session_id"] = f"eq.{session_id}"
        rows = self._get(TABLE_EVENTS, params) or []
        for row in rows:
            if isinstance(row.get("evidence"), str):
                try:
                    row["evidence"] = json.loads(row["evidence"])
                except (TypeError, json.JSONDecodeError):
                    row["evidence"] = {}
        return rows

    # ------------------------------------------------------------------
    def save_packets(self, session_id: int, records: list[PacketRecord]) -> None:
        rows = [{
            "session_id": session_id, "number": r.number, "ts": r.ts,
            "src": r.src, "dst": r.dst, "src_port": r.src_port,
            "dst_port": r.dst_port, "protocol": r.protocol,
            "transport": r.transport, "size": r.size,
            "tcp_flags": r.tcp_flags, "ttl": r.ttl, "info": r.info,
            "domain": r.domain,
        } for r in records]
        self._insert(TABLE_PACKETS, rows)

    def list_packets(self, session_id: int | None = None, limit: int = 200) -> list[dict]:
        params = {"select": "*", "order": "number.asc", "limit": limit}
        if session_id is not None:
            params["session_id"] = f"eq.{session_id}"
        return self._get(TABLE_PACKETS, params) or []

    # ------------------------------------------------------------------
    def get_intel(self, ip: str, max_age_hours: float) -> IPIntel | None:
        rows = self._get(TABLE_INTEL, {"select": "*", "ip": f"eq.{ip}"})
        if not rows:
            return None
        row = rows[0]
        age_hours = (time.time() - (row.get("fetched_at") or 0)) / 3600.0
        if age_hours > max_age_hours:
            return None
        return IPIntel(
            ip=row["ip"], scope=row.get("scope") or "inconnu",
            country=row.get("country"), country_code=row.get("country_code"),
            city=row.get("city"), isp=row.get("isp"), org=row.get("org"),
            asn=row.get("asn"), reverse_dns=row.get("reverse_dns"),
            source=row.get("source"), fetched_at=row.get("fetched_at") or 0.0,
            error=row.get("error"),
        )

    def save_intel(self, intel: IPIntel) -> None:
        self._insert(TABLE_INTEL, [{
            "ip": intel.ip, "scope": intel.scope, "country": intel.country,
            "country_code": intel.country_code, "city": intel.city,
            "isp": intel.isp, "org": intel.org, "asn": intel.asn,
            "reverse_dns": intel.reverse_dns, "source": intel.source,
            "fetched_at": intel.fetched_at, "error": intel.error,
        }], upsert_on="ip")

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass
