"""Construction du contexte fourni a la couche d'intelligence.

Le contexte est volontairement structure et ferme : c'est la SEULE matiere que
la couche d'intelligence recevra. Tout ce qui n'y figure pas ne peut pas etre
mentionne dans un resume, puisque le verificateur (voir summarizer.py) rejette
toute entite absente de ces listes.

C'est ce qui rend la garantie « aucune invention » verifiable plutot que
declarative.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.analysis.flows import human_bytes, human_duration, resolve_service_port, state_label
from app.analysis.protocols import lookup_port

# Reconnaissance des entites qui pourraient etre inventees, utilisees a la fois
# pour recenser ce qui est autorise et pour verifier la reponse du modele.
IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    r"|\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b"
)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)


@dataclass
class SessionContext:
    """Photographie structuree de ce qui a ete reellement observe."""

    packets: int = 0
    flows: int = 0
    active_flows: int = 0
    bytes_total: int = 0
    duration_seconds: float = 0.0
    mode: str = "local"
    protocols: list[dict[str, Any]] = field(default_factory=list)
    top_sources: list[dict[str, Any]] = field(default_factory=list)
    top_destinations: list[dict[str, Any]] = field(default_factory=list)
    top_ports: list[dict[str, Any]] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    key_flows: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    sensitive_services: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    def allowed_entities(self) -> dict[str, set[str]]:
        """Recense tout ce que le resume a le DROIT de mentionner.

        Sert de reference au verificateur : une entite citee qui n'est pas ici
        est une invention.
        """
        ips: set[str] = set()
        domains: set[str] = set(self.domains)
        services: set[str] = set(self.sensitive_services)

        for collection in (self.top_sources, self.top_destinations):
            for entry in collection:
                ips.add(str(entry.get("ip", "")))
        for flow in self.key_flows:
            ips.add(str(flow.get("observer", "")))
            ips.add(str(flow.get("distant", "")))
            if flow.get("domain"):
                domains.add(str(flow["domain"]))
            if flow.get("service"):
                services.add(str(flow["service"]))
        for protocol in self.protocols:
            services.add(str(protocol.get("name", "")))
        for port in self.top_ports:
            services.add(str(port.get("port", "")))

        return {
            "ips": {value for value in ips if value},
            "domains": {value.lower() for value in domains if value},
            "services": {value.lower() for value in services if value},
        }

    # ------------------------------------------------------------------
    def to_prompt(self) -> dict[str, Any]:
        """Representation compacte transmise au modele."""
        return {
            "observation": {
                "paquets": self.packets,
                "communications": self.flows,
                "communications_actives": self.active_flows,
                "volume_total": human_bytes(self.bytes_total),
                "duree_observation": human_duration(self.duration_seconds),
                "mode": self.mode,
            },
            "protocoles": self.protocols,
            "principales_sources": self.top_sources,
            "principales_destinations": self.top_destinations,
            "ports_frequents": self.top_ports,
            "noms_de_domaine_observes": self.domains,
            "communications_notables": self.key_flows,
            "evenements_detectes": self.events,
            "services_sensibles_observes": self.sensitive_services,
        }


# --------------------------------------------------------------------------
# Construction
# --------------------------------------------------------------------------


def build_session_context(engine, max_flows: int = 12) -> SessionContext:
    """Construit le contexte a partir de l'etat courant du moteur.

    Aucune analyse n'est refaite ici : on lit ce que le moteur a deja calcule.
    """
    stats = engine.stats()
    is_local = engine.parser.is_local

    context = SessionContext(
        packets=stats.get("packets", 0),
        flows=stats.get("flows", 0),
        active_flows=stats.get("active_flows", 0),
        bytes_total=stats.get("bytes", 0),
        duration_seconds=stats.get("uptime", 0.0),
        mode=stats.get("mode", "local"),
        protocols=stats.get("protocols", []),
        top_sources=stats.get("top_sources", []),
        top_destinations=stats.get("top_destinations", []),
        top_ports=stats.get("top_ports", []),
        domains=[entry["domain"] for entry in stats.get("top_domains", [])
                 if entry.get("domain")],
        events=[
            {"type": event.get("kind"), "titre": event.get("title"),
             "regle": event.get("rule"), "gravite": event.get("severity")}
            for event in engine.event_snapshot(limit=10)
        ],
    )

    # Communications notables : les plus volumineuses, puis celles a risque.
    flows = engine.flows.snapshot()
    flows.sort(key=lambda f: (f.risk_score, f.bytes_total), reverse=True)

    sensitive: set[str] = set()
    hostnames: set[str] = set()

    for flow in flows[:max_flows]:
        service_port = resolve_service_port(flow)
        info = lookup_port(service_port, flow.transport)
        if info and info.sensitive:
            sensitive.add(info.service)
        if flow.domain:
            hostnames.add(flow.domain)
        context.key_flows.append({
            "hote_local": flow.observer(),
            "hote_distant": flow.distant(),
            "service": info.service if info else None,
            "port": service_port,
            "domaine": flow.domain,
            "transport": flow.transport,
            "etat": state_label(flow),
            "paquets": flow.packets,
            "volume": human_bytes(flow.bytes_total),
            "duree": human_duration(flow.duration),
            "risque": flow.risk_label,
            "score_risque": flow.risk_score,
        })

    context.sensitive_services = sorted(sensitive)
    context.hostnames = sorted(hostnames)
    return context
