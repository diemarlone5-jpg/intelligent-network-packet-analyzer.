"""Modeles de donnees partages par tout le projet.

Trois objets circulent entre les couches :

    PacketRecord  -> un paquet brut, tel qu'observe (aucune interpretation)
    Flow          -> une communication : un ensemble de paquets regroupes
    Event         -> un fait remarquable detecte par l'analyse comportementale

Le vocabulaire `kind` des evenements est impose par le cahier des charges :

    OBSERVATION  : fait mesurable, indiscutable ("312 paquets vers 40 destinations")
    HYPOTHESE    : lecture probable de l'observation ("compatible avec un balayage")
    ALERTE       : observation associee a un risque connu et documente

Le projet ne doit jamais presenter une HYPOTHESE comme une OBSERVATION.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


# --------------------------------------------------------------------------
# Niveaux et vocabulaires normalises
# --------------------------------------------------------------------------

KIND_OBSERVATION = "OBSERVATION"
KIND_HYPOTHESE = "HYPOTHESE"
KIND_ALERTE = "ALERTE"

SEVERITIES = ("info", "faible", "moyen", "eleve")

# Etats d'une communication, du point de vue de l'observateur
STATE_NEW = "nouvelle"
STATE_ONGOING = "en cours"
STATE_ESTABLISHED = "etablie"
STATE_CLOSED = "fermee"
STATE_FAILED = "echec"
STATE_IDLE = "inactive"
STATE_UNKNOWN = "inconnu"


def _clean(value: Any) -> Any:
    """Rend une valeur serialisable en JSON (les types scapy ne le sont pas)."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _clean(v) for k, v in value.items()}
    return str(value)


class Serializable:
    """Mixin : conversion en dictionnaire propre, prete pour JSON ou base."""

    def to_dict(self) -> dict[str, Any]:
        return {k: _clean(v) for k, v in asdict(self).items()}  # type: ignore[call-overload]

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, default=str)


# --------------------------------------------------------------------------
# Paquet
# --------------------------------------------------------------------------


@dataclass
class PacketRecord(Serializable):
    """Un paquet capture, traduit en champs plats et exploitables.

    Aucun champ de ce modele n'est une deduction : tout vient du paquet.
    Les champs optionnels restent a None lorsque l'information est absente
    (paquet tronque, protocole non reconnu...). Le code appelant doit
    toujours traiter le cas None.
    """

    number: int
    ts: float
    src: str
    dst: str
    protocol: str                    # protocole le plus precis identifie
    size: int                        # taille totale en octets
    src_mac: str | None = None       # adresse materielle de l'emetteur (couche Ethernet)
    dst_mac: str | None = None       # adresse materielle du destinataire
    transport: str | None = None     # TCP / UDP / ICMP / None
    src_port: int | None = None
    dst_port: int | None = None
    ttl: int | None = None
    tcp_flags: str | None = None     # "SYN", "SYN,ACK", "FIN,ACK", "RST"...
    tcp_seq: int | None = None       # numero de sequence, pour reperer les retransmissions
    payload_len: int = 0
    info: str = ""
    direction: str | None = None     # sortant / entrant / interne / inconnu
    layers: list[str] = field(default_factory=list)
    dns_query: str | None = None
    dns_is_query: bool | None = None  # True = question posee, False = reponse
    http_host: str | None = None
    tls_sni: str | None = None
    malformed: bool = False

    @property
    def domain(self) -> str | None:
        """Nom de domaine associe au paquet, quelle que soit la source."""
        return self.tls_sni or self.http_host or self.dns_query


# --------------------------------------------------------------------------
# Communication (flux)
# --------------------------------------------------------------------------


@dataclass
class Flow(Serializable):
    """Une communication : plusieurs paquets regroupes sous une meme identite.

    L'identite retenue est le quintuplet (protocole, ip1, port1, ip2, port2)
    rendu *bidirectionnel* : les deux sens de l'echange appartiennent au meme
    flux, car une communication est une conversation, pas un paquet.
    """

    key: str
    src: str
    dst: str
    src_port: int | None
    dst_port: int | None
    transport: str
    first_seen: float
    last_seen: float
    packets: int = 0
    bytes_total: int = 0
    bytes_fwd: int = 0               # sens initiateur -> destinataire
    bytes_rev: int = 0
    state: str = STATE_NEW
    tcp_state: str | None = None
    service_port: int | None = None   # port du service, deduit du SYN initiateur
    handshake_seen: bool = False      # avons-nous observe le debut de la connexion ?
    app_protocol: str | None = None  # DNS / HTTP / TLS / DHCP...
    domain: str | None = None        # SNI, en-tete Host ou requete DNS
    initiator: str | None = None     # qui a envoye le premier paquet
    local_side: str | None = None    # "src" | "dst" | None
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    retransmissions: int = 0
    risk_score: int = 0              # 0-100
    risk_label: str = "faible"

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    def observer(self) -> str:
        """L'hote local vu depuis cette communication."""
        if self.local_side == "dst":
            return self.dst
        return self.src

    def distant(self) -> str:
        """L'hote distant vu depuis cette communication."""
        if self.local_side == "dst":
            return self.src
        return self.dst

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["duration"] = round(self.duration, 3)
        data["observer"] = self.observer()
        data["distant"] = self.distant()
        return data


# --------------------------------------------------------------------------
# Evenement
# --------------------------------------------------------------------------


@dataclass
class Event(Serializable):
    """Un fait remarquable, toujours accompagne de sa justification.

    `evidence` contient les valeurs reellement mesurees qui ont declenche la
    regle : c'est ce qui permet de repondre a la question "quelle information
    est reellement observee, et laquelle est deduite ?".
    """

    ts: float
    kind: str                        # OBSERVATION / HYPOTHESE / ALERTE
    rule: str                        # identifiant technique de la regle
    title: str
    explanation: str
    severity: str = "info"
    evidence: dict[str, Any] = field(default_factory=dict)
    flow_key: str | None = None
    actor: str | None = None         # hote concerne (IP)
    id: int | None = None


# --------------------------------------------------------------------------
# Enrichissement
# --------------------------------------------------------------------------


@dataclass
class IPIntel(Serializable):
    """Informations obtenues aupres d'une source externe pour une adresse IP."""

    ip: str
    scope: str = "inconnu"           # prive / public / loopback / multicast / lien-local
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    isp: str | None = None
    org: str | None = None
    asn: str | None = None
    reverse_dns: str | None = None
    source: str | None = None        # quelle API a repondu
    fetched_at: float = 0.0
    error: str | None = None

    @property
    def is_public(self) -> bool:
        return self.scope == "public"
