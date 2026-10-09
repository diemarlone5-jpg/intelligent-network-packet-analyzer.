"""Moteur d'analyse : assemble toutes les couches en un seul service.

C'est le point de rencontre du pipeline demande par le cahier des charges :

    CAPTURER  -> agent de capture (Scapy / Npcap)
    ANALYSER  -> parseur de paquets + table des communications
    COMPRENDRE-> base de connaissance des protocoles
    EXPLIQUER -> moteur d'explication (faits / interpretations)
    DETECTER  -> analyse comportementale
    STOCKER   -> depot SQLite et/ou Supabase
    EXPOSER   -> interface web (couche separee, voir app/web)

Le moteur est concu pour etre pilote par l'interface web : il ne fait aucun
affichage et ne connait ni HTML ni HTTP. Cette separation permet de le tester
directement, sans lancer de serveur.
"""

from __future__ import annotations

import threading
import time
from collections import Counter, OrderedDict, deque
from typing import Any

from app.analysis.detectors import BehaviorAnalyzer, DetectionConfig
from app.analysis.devices import DeviceTable
from app.analysis.explain import Explainer
from app.analysis.flows import FlowTable
from app.analysis.parser import PacketParser
from app.analysis.protocols import classify_address
from app.capture.agent import CaptureAgent
from app.capture.interfaces import local_ips
from app.models import Event, Flow, PacketRecord

# Intervalle du fil d'analyse (detection + persistance)

ANALYSIS_INTERVAL_SECONDS = 3.0
# Nombre de paquets bruts conserves en base par session
PACKET_SAMPLE_LIMIT = 3000


class AnalyzerEngine:
    """Service central : un seul exemplaire par processus."""

    def __init__(self, settings, repository, enricher=None) -> None:
        self.settings = settings
        self.repo = repository
        self.enricher = enricher

        self.is_local_time = time.time
        self._local_ips = local_ips()

        self.parser = PacketParser(self._local_ips)
        self.flows = FlowTable(is_local=self.parser.is_local)
        self.detectors = BehaviorAnalyzer(DetectionConfig(), is_local=self.parser.is_local)
        self.explainer = Explainer(is_local=self.parser.is_local)

        self.agent = CaptureAgent(self._handle_packet, on_error=self._record_error)

        self._lock = threading.RLock()
        self._packets: deque[PacketRecord] = deque(maxlen=settings.max_packets_buffer)
        self._events: deque[Event] = deque(maxlen=1000)
        self._pending_packets: list[PacketRecord] = []
        self._errors: deque[tuple[float, str]] = deque(maxlen=50)
        self._notes: deque[tuple[float, str]] = deque(maxlen=50)

        # Octets bruts des paquets recents, pour la vue detaillee (arbre des
        # couches et vidage hexadecimal). Bornes comme le tampon d'affichage :
        # conserver tout le trafic ferait exploser la memoire sans rien apporter
        # a l'analyse.
        self._raw: "OrderedDict[int, bytes]" = OrderedDict()

        # Geographie des adresses distantes, alimentee en arriere-plan. La liste
        # des paquets doit rester instantanee : elle ne lit donc que ce cache,
        # jamais le reseau.
        self._intel: dict[str, dict] = {}
        self._enrich_pending: deque[str] = deque(maxlen=500)

        # Appareils du reseau local et services qu'ils diffusent (ARP, mDNS).
        self.devices = DeviceTable(self.parser.is_local)

        # Compteurs incrementaux : les statistiques doivent rester instantanees
        # meme apres plusieurs centaines de milliers de paquets.
        self._counter = 0
        self._protocols: Counter[str] = Counter()
        self._sources: Counter[str] = Counter()
        self._destinations: Counter[str] = Counter()
        self._ports: Counter[str] = Counter()
        self._domains: Counter[str] = Counter()
        self._total_bytes = 0
        self._started_at: float | None = None

        self.session_id: int | None = None
        self.nat64_prefixes: tuple[str, ...] = ()
        self.nat64_prefix: str | None = None
        self._last_persist = 0.0
        self._thread: threading.Thread | None = None
        self._enrich_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    # ==================================================================
    # Cycle de vie
    # ==================================================================
    def start(self) -> None:
        """Demarre le fil d'analyse en arriere-plan."""
        if self._thread and self._thread.is_alive():
            return

        # Une session laissee ouverte par un arret brutal (coupure, processus
        # tue) resterait eternellement « en cours » dans l'historique. On la
        # cloture au demarrage, avec une note expliquant pourquoi.
        try:
            closed = self.repo.close_orphan_sessions(
                "interrompue : l'application ne s'est pas arretee proprement"
            )
            if closed:
                self._record_note(
                    f"{closed} session(s) precedemment interrompue(s) ont ete cloturees."
                )
        except Exception as exc:
            self._record_error(f"Cloture des sessions orphelines impossible : {type(exc).__name__}")

        # Determine une fois pour toutes le prefixe de traduction du reseau
        # (RFC 7050). Le faire ici evite une requete DNS au milieu du traitement
        # d'un paquet, et permet d'afficher le resultat a l'utilisateur.
        try:
            from app.analysis.protocols import discover_nat64_prefixes
            self.nat64_prefixes = discover_nat64_prefixes()
        except Exception:
            self.nat64_prefixes = ()
        self.nat64_prefix = self.nat64_prefixes[0] if self.nat64_prefixes else None

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._analysis_loop,
                                        name="analyzer-engine", daemon=True)
        self._thread.start()

        # Fil d'enrichissement : il ne fait rien tant qu'aucune adresse
        # inconnue n'est observee, mais doit tourner des le demarrage pour
        # repondre sans delai a la premiere capture.
        self._enrich_thread = threading.Thread(target=self._enrichment_loop,
                                               name="analyzer-enrichment", daemon=True)
        self._enrich_thread.start()

    def shutdown(self) -> None:
        """Arrete proprement la capture puis le fil d'analyse."""
        self.stop_capture()
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5.0)

    # ==================================================================
    # Capture
    # ==================================================================
    def start_capture(self, iface_id: str | None = None, iface_name: str | None = None,
                      bpf_filter: str = "") -> tuple[bool, str]:
        if not self.settings.is_local:
            return False, ("Cette instance fonctionne en mode consultation : la "
                           "capture reseau n'y est pas disponible.")
        if self.agent.running:
            return False, "Une capture est deja en cours."

        self.reset()
        ok, message = self.agent.start(iface_id, iface_name, bpf_filter)
        if not ok:
            return False, message

        self._started_at = time.time()
        try:
            self.session_id = self.repo.create_session(
                mode=self.settings.mode,
                interface=self.agent.iface_id or "",
                interface_name=self.agent.iface_name or "",
                filter=bpf_filter,
            )
        except Exception as exc:
            # La capture reste utilisable meme si l'historique echoue : on
            # n'interrompt pas une observation en cours pour un probleme de base.
            self.session_id = None
            self._record_error(f"Historique indisponible : {type(exc).__name__}")
            return True, f"{message} (attention : historique non enregistre)"
        return True, message

    def stop_capture(self) -> tuple[bool, str]:
        if not self.agent.running:
            return False, "Aucune capture en cours."
        ok, message = self.agent.stop()
        self._persist(force=True)
        if self.session_id is not None:
            try:
                self.repo.close_session(
                    self.session_id,
                    packets=self.agent.packets_seen,
                    bytes_total=self.agent.bytes_seen,
                    flows=self.flows.count(),
                    events=len(self._events),
                )
            except Exception as exc:
                self._record_error(f"Cloture de session impossible : {type(exc).__name__}")
        return ok, message

    def reset(self) -> None:
        """Vide les tampons et les compteurs avant une nouvelle capture."""
        with self._lock:
            self._packets.clear()
            self._events.clear()
            self._pending_packets.clear()
            self._raw.clear()
            self.flows.clear()
            self.devices.clear()
            self._counter = 0
            self._protocols.clear()
            self._sources.clear()
            self._destinations.clear()
            self._ports.clear()
            self._domains.clear()
            self._total_bytes = 0
            self.agent.reset_counters()
            self.session_id = None
            # Le cache geographique est conserve : une adresse deja identifiee
            # n'a pas besoin d'etre redemandee a la source externe.

    # ==================================================================
    # Traitement d'un paquet
    # ==================================================================
    def _handle_packet(self, packet) -> None:
        """Appele par le fil de capture pour chaque paquet. Ne doit pas lever."""
        with self._lock:
            record = self.parser.parse(packet, self._counter + 1)
            self._counter += 1

            self._packets.append(record)
            if len(self._pending_packets) < PACKET_SAMPLE_LIMIT:
                self._pending_packets.append(record)

            # Octets d'origine : `original` est pose par Scapy lors de la
            # dissection, ce qui evite de reconstruire le paquet. On ne
            # conserve rien au-dela du tampon d'affichage.
            self._raw[record.number] = getattr(packet, "original", None) or bytes(packet)
            while len(self._raw) > self.settings.max_packets_buffer:
                self._raw.popitem(last=False)

            self.flows.observe(record)

            # Compteurs statistiques
            self._total_bytes += record.size
            self._protocols[record.protocol] += 1
            self._sources[record.src] += 1
            self._destinations[record.dst] += 1
            if record.dst_port is not None:
                self._ports[f"{record.dst_port}/{record.transport or '?'}"] += 1
            if record.domain:
                self._domains[record.domain] += 1

            self._queue_geolocation(record)
            # Appareils du reseau local : alimente depuis les diffusions que
            # tout le monde peut lire (ARP, mDNS). Aucune lecture de trafic
            # prive, aucun dechiffrement.
            self.devices.observe(record)

    # ------------------------------------------------------------------
    def _counterparty(self, record: PacketRecord) -> str | None:
        """Adresse de l'interlocuteur : celle qui n'est pas la machine locale.

        C'est celle qui a du sens a geolocaliser. Pour un echange purement
        local, il n'y en a pas.
        """
        src_local = self.parser.is_local(record.src)
        dst_local = self.parser.is_local(record.dst)
        if src_local and not dst_local:
            return record.dst
        if dst_local and not src_local:
            return record.src
        return None

    def _queue_geolocation(self, record: PacketRecord) -> None:
        """Met en file l'adresse distante a enrichir, si utile et pas deja connue."""
        if self.enricher is None or not self.settings.enrich_enabled:
            return
        adresse = self._counterparty(record)
        if not adresse or adresse in self._intel:
            return
        if classify_address(adresse) != "public":
            return
        if adresse in self._enrich_pending:
            return
        self._enrich_pending.append(adresse)

    def _enrichment_loop(self) -> None:
        """Enrichit les adresses distantes en arriere-plan, une par une.

        En dehors du chemin critique : l'affichage des paquets ne doit jamais
        attendre un appel reseau, et la source externe impose son propre rythme.
        """
        while not self._stop_event.is_set():
            adresse = None
            with self._lock:
                if self._enrich_pending:
                    adresse = self._enrich_pending.popleft()
            if adresse is None:
                self._stop_event.wait(1.0)
                continue
            try:
                intel = self.enricher.lookup(adresse)
                with self._lock:
                    self._intel[adresse] = intel.to_dict()
            except Exception:
                with self._lock:
                    self._intel[adresse] = {"ip": adresse, "error": "enrichissement indisponible"}

    def _record_error(self, message: str) -> None:
        """Consigne un probleme reel. Affiche comme avertissement a l'utilisateur."""
        with self._lock:
            self._errors.append((time.time(), message))

    def _record_note(self, message: str) -> None:
        """Consigne une information. N'est PAS presentee comme une erreur.

        La distinction compte : melanger les deux ferait apparaitre un simple
        compte rendu de demarrage comme un incident, et l'utilisateur perdrait
        confiance dans les avertissements qui comptent vraiment.
        """
        with self._lock:
            self._notes.append((time.time(), message))

    # ==================================================================
    # Fil d'analyse
    # ==================================================================
    def _analysis_loop(self) -> None:
        """Detecte les comportements et enregistre l'historique, periodiquement."""
        while not self._stop_event.is_set():
            try:
                if self.agent.running:
                    self._analyse_once()
                self._persist()
            except Exception as exc:  # pragma: no cover - protection du fil
                self._record_error(f"Analyse interrompue puis reprise : {type(exc).__name__}")
            self._stop_event.wait(ANALYSIS_INTERVAL_SECONDS)

    def _analyse_once(self) -> None:
        now = time.time()
        self.flows.tick(now)
        flows = self.flows.snapshot()
        new_events = self.detectors.analyze(flows, now)

        with self._lock:
            for event in new_events:
                self._events.appendleft(event)
            if new_events and self.session_id is not None:
                try:
                    self.repo.save_events(self.session_id, new_events)
                except Exception as exc:
                    self._record_error(f"Evenement non enregistre : {type(exc).__name__}")

    def _persist(self, force: bool = False) -> None:
        """Enregistre l'etat courant. Echec silencieux : l'analyse continue."""
        now = time.time()
        if not force and now - self._last_persist < 5.0:
            return
        self._last_persist = now
        if self.session_id is None:
            return

        flows = self.flows.snapshot()
        # On joint a chaque flux le titre de son explication : l'historique
        # reste lisible sans avoir a recalculer l'analyse.
        for flow in flows:
            try:
                flow.explanation_text = self.explainer.explain_flow(flow).headline
            except Exception:
                flow.explanation_text = None

        with self._lock:
            pending = list(self._pending_packets)
            self._pending_packets.clear()

        try:
            self.repo.save_flows(self.session_id, flows)
            if pending:
                self.repo.save_packets(self.session_id, pending)
        except Exception as exc:
            self._record_error(f"Persistance reportee : {type(exc).__name__}")

    # ==================================================================
    # Lecture pour l'interface
    # ==================================================================
    def packet_snapshot(self, limit: int = 200, protocol: str | None = None,
                        search: str | None = None) -> list[dict]:
        with self._lock:
            records = list(self._packets)
        records.reverse()  # le plus recent en premier

        if protocol:
            records = [r for r in records if r.protocol.lower() == protocol.lower()]
        if search:
            needle = search.lower()
            records = [
                r for r in records
                if needle in r.src.lower() or needle in r.dst.lower()
                or (r.domain and needle in r.domain)
                or needle in (r.tcp_flags or "").lower()
            ]
        return [self._packet_view(r) for r in records[:limit]]

    def _packet_view(self, record: PacketRecord) -> dict:
        """Vue enrichie d'un paquet : la geographie de l'interlocuteur y est
        jointe depuis le cache local, sans aucun appel reseau."""
        data = record.to_dict()
        adresse = self._counterparty(record)
        data["geo_ip"] = adresse
        data["geo"] = self._intel.get(adresse) if adresse else None
        return data

    def packet_detail(self, number: int) -> dict | None:
        """Vue complete d'un paquet : arbre des couches et contenu brut.

        C'est l'equivalent des deux panneaux du bas de Wireshark. Retourne None
        si le paquet n'est plus dans le tampon (ou n'a jamais existe).
        """
        from app.analysis.dissect import dissect

        with self._lock:
            record = next((r for r in self._packets if r.number == number), None)
            raw = self._raw.get(number)

        if record is None:
            return None

        data = self._packet_view(record)
        data["dissection"] = dissect(raw or b"")
        data["raw_available"] = bool(raw)
        return data

    def geolocation_snapshot(self, limit: int = 200) -> list[dict]:
        """Adresses distantes geolocalisees, les plus vues en premier."""
        with self._lock:
            compteurs = Counter(self._sources) + Counter(self._destinations)
            cache = dict(self._intel)

        resultats = []
        for adresse, info in cache.items():
            entree = dict(info)
            entree["packets"] = compteurs.get(adresse, 0)
            resultats.append(entree)
        resultats.sort(key=lambda item: item.get("packets", 0), reverse=True)
        return resultats[:limit]

    # ------------------------------------------------------------------
    def devices_snapshot(self) -> dict:
        """Appareils du reseau local et services qu'ils diffusent.

        Les deux listes sont separees volontairement : un appareil qui CHERCHE
        un service n'est pas un appareil qui le PROPOSE, et confondre les deux
        ferait dire a l'outil le contraire de ce qui s'est passe.
        """
        with self._lock:
            return {
                "devices": self.devices.snapshot(),
                "services": self.devices.services_snapshot(),
                "count": self.devices.count(),
                "local_addresses": sorted(self.parser.local_ips),
            }

    def flow_snapshot(self, limit: int = 200, only_active: bool = False) -> list[dict]:
        flows = self.flows.snapshot()
        if only_active:
            flows = [f for f in flows if f.state in ("en cours", "etablie", "nouvelle")]
        return [self._flow_view(f) for f in flows[:limit]]

    def _flow_view(self, flow: Flow) -> dict:
        """Vue enrichie d'une communication, destinee a l'interface.

        Le service, l'etat lisible, le sens de l'initiative et le niveau de
        risque sont calcules ici plutot que dans le navigateur : l'interface web
        doit se contenter d'afficher, jamais d'interpreter.
        """
        from app.analysis.flows import (
            infer_direction,
            resolve_service_port,
            state_label,
        )
        from app.analysis.protocols import lookup_port
        from app.analysis.risk import assess_flow

        data = flow.to_dict()
        try:
            service_port = resolve_service_port(flow)
            info = lookup_port(service_port, flow.transport)
            data["service"] = info.service if info else None
            data["service_port"] = service_port
            data["service_sensitive"] = bool(info and info.sensitive)
            data["state_label"] = state_label(flow)
            data["direction"] = infer_direction(flow, self.parser.is_local)
            data["caveats"] = [] if flow.handshake_seen else [
                "Le debut de cette communication n'a pas ete observe."
            ]

            # Le risque alimente a la fois l'affichage et l'historique : le
            # calculer ici evite de le recalculer lors de la persistance.
            risk = assess_flow(flow, self.parser.is_local)
            data["risk"] = risk.to_dict()
            flow.risk_score = risk.score
            flow.risk_label = risk.label
        except Exception:
            # Une vue degradee reste preferable a une page en erreur
            data.setdefault("service", None)
            data.setdefault("state_label", flow.state)
            data.setdefault("direction", "inconnu")
            data.setdefault("risk", {"score": 0, "label": "inconnu",
                                     "summary": "", "reasons": []})
        return data

    def event_snapshot(self, limit: int = 100) -> list[dict]:
        with self._lock:
            return [e.to_dict() for e in list(self._events)[:limit]]

    def error_snapshot(self, limit: int = 10) -> list[str]:
        with self._lock:
            return [msg for _, msg in list(self._errors)[-limit:]][::-1]

    def note_snapshot(self, limit: int = 10) -> list[str]:
        with self._lock:
            return [msg for _, msg in list(self._notes)[-limit:]][::-1]

    # ==================================================================
    # Explication d'une communication
    # ==================================================================
    def explain_flow(self, key: str, with_intel: bool = True) -> dict | None:
        flow = self.flows.get(key)
        if flow is None:
            return None
        intel = None
        if with_intel and self.enricher is not None:
            try:
                intel = self.enricher.lookup(flow.distant())
            except Exception:
                intel = None
        explanation = self.explainer.explain_flow(flow, intel=intel)
        payload = explanation.to_dict()
        payload["flow"] = flow.to_dict()
        payload["intel"] = intel.to_dict() if intel else None

        # Le risque accompagne l'explication : la vue detaillee doit presenter
        # informations techniques, analyse, explication ET risque / statut.
        from app.analysis.risk import assess_flow
        payload["risk"] = assess_flow(flow, self.parser.is_local).to_dict()
        return payload

    # ==================================================================
    # Statistiques (tableau de bord)
    # ==================================================================
    def stats(self) -> dict[str, Any]:
        with self._lock:
            flows = self.flows.count()
            active = sum(
                1 for f in self.flows.snapshot()
                if f.state in ("en cours", "etablie", "nouvelle")
            )
            packets = self._counter
            total_bytes = self._total_bytes
            protocols = self._protocols.most_common(8)
            sources = self._sources.most_common(6)
            destinations = self._destinations.most_common(6)
            ports = self._ports.most_common(8)
            domains = self._domains.most_common(8)
            events = list(self._events)

        by_kind = Counter(e.kind for e in events)
        by_severity = Counter(e.severity for e in events)

        activity = {e.actor for e in events if e.actor}

        return {
            "capture": self.agent.stats(),
            "mode": self.settings.mode,
            "session_id": self.session_id,
            "packets": packets,
            "bytes": total_bytes,
            "flows": flows,
            "active_flows": active,
            "events": len(events),
            "events_by_kind": dict(by_kind),
            "events_by_severity": dict(by_severity),
            "protocols": [{"name": n, "count": c} for n, c in protocols],
            "top_sources": [{"ip": ip, "count": c} for ip, c in sources],
            "top_destinations": [{"ip": ip, "count": c} for ip, c in destinations],
            "top_ports": [{"port": p, "count": c} for p, c in ports],
            "top_domains": [{"domain": d, "count": c} for d, c in domains],
            "hosts_to_watch": sorted(activity)[:8],
            # L'identification geographique se fait en arriere-plan : ce compteur
            # permet a l'interface d'expliquer un tiret, plutot que de laisser
            # croire a une adresse sans pays.
            "geo_pending": len(self._enrich_pending),
            "geo_known": len(self._intel),
            "public_destinations": sorted({
                d for d, _ in destinations if classify_address(d) == "public"
            })[:12],
            "errors": self.error_snapshot(5),
            "notes": self.note_snapshot(3),
            "nat64_prefix": self.nat64_prefix,
            "nat64_prefixes": list(self.nat64_prefixes),
            "uptime": (time.time() - self._started_at) if self._started_at else 0.0,
        }

    # ==================================================================
    # Historique (mode consultation)
    # ==================================================================
    def history(self, session_id: int | None = None) -> dict:
        """Vue de l'historique enregistre, utilisee par le mode en ligne."""
        sessions = self.repo.list_sessions(limit=50)
        target = session_id or (sessions[0]["id"] if sessions else None)
        if target is None:
            return {"sessions": [], "session": None, "flows": [], "events": [], "packets": []}
        return {
            "sessions": sessions,
            "session": self.repo.get_session(target),
            "flows": self.repo.list_flows(target, limit=200),
            "events": self.repo.list_events(target, limit=100),
            "packets": self.repo.list_packets(target, limit=200),
        }
