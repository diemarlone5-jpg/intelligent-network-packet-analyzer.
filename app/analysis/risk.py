"""Evaluation du risque d'une communication.

Le cahier des charges demande, dans la vue detaillee, quatre elements :
    informations techniques + analyse + explication humaine + RISQUE / STATUT.

Ce module produit le dernier. Sa regle est la meme que partout ailleurs :
**seuls des faits observes entrent dans le calcul**, et chaque point attribue
est accompagne de la raison exacte qui l'a justifie.

Le score n'est pas une probabilitie d'attaque. C'est un indicateur d'attention :
il repond a la question "cette communication merite-t-elle que je m'y arrete ?",
pas a la question "est-ce une attaque ?".

Un score eleve sur une communication parfaitement legitime est normal : un
serveur SSH administre volontairement depuis Internet est a la fois legitime et
digne d'attention. L'interface affiche donc toujours les raisons, pour que
l'utilisateur juge.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.analysis.protocols import classify_address, lookup_port
from app.models import Flow

# Libelles par tranche de score
LEVELS = (
    (0, "faible", "Aucun element particulier ne retient l'attention."),
    (15, "modere", "Quelques elements justifient un coup d'oeil."),
    (35, "eleve", "Plusieurs elements meritent une verification."),
    (60, "critique", "Faisceau d'elements convergents : a examiner."),
)


@dataclass
class RiskReason:
    """Une raison chiffree, toujours rattachee a un fait observable."""

    fact: str
    points: int
    basis: str


@dataclass
class RiskAssessment:
    score: int
    label: str
    summary: str
    reasons: list[RiskReason] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "label": self.label,
            "summary": self.summary,
            "reasons": [
                {"fact": r.fact, "points": r.points, "basis": r.basis}
                for r in self.reasons
            ],
        }


# --------------------------------------------------------------------------
# Bareme
# --------------------------------------------------------------------------

# Services documentes comme sensibles : leur exposition elargit la surface
POINTS_SERVICE_SENSIBLE_ENTRANT = 25
POINTS_SERVICE_SENSIBLE_SORTANT = 12
# Protocole en clair susceptible de transporter des identifiants
POINTS_PROTOCOLE_EN_CLAIR = 15
# Connexion refusee : revele une recherche de service inexistant
POINTS_CONNEXION_REFUSEE = 10
# Connexion entrante depuis une adresse publique vers un service local
POINTS_ENTRANT_PUBLIC = 10
# Volume important vers un hote public non identifie
POINTS_VOLUME_NON_IDENTIFIE = 10
# Port non documente en sortie
POINTS_PORT_NON_DOCUMENTE = 5
# Trafic chiffre dont la destination reste inconnue (pas de SNI)
POINTS_CHIFFRE_SANS_DOMAINE = 5
# Nombre eleve de retransmissions : reseau degrade ou interference
POINTS_RETRANSMISSIONS = 5

# Services dont le protocole transporte des identifiants en clair
SERVICES_EN_CLAIR_SENSIBLES = {
    "Telnet", "FTP (controle)", "HTTP", "POP3", "IMAP", "SMTP", "LDAP", "SNMP",
    "NetBIOS", "NetBIOS datagramme", "NetBIOS session", "PPTP", "TFTP", "SIP",
    "SSDP", "LLMNR",
}


def _level_for(score: int) -> tuple[str, str]:
    label, summary = LEVELS[0][1], LEVELS[0][2]
    for seuil, nom, texte in LEVELS:
        if score >= seuil:
            label, summary = nom, texte
    return label, summary


def assess_flow(flow: Flow, is_local) -> RiskAssessment:
    """Evalue le risque d'une communication a partir de faits observes."""
    from app.analysis.flows import infer_direction, resolve_service_port

    reasons: list[RiskReason] = []
    service_port = resolve_service_port(flow)
    port_info = lookup_port(service_port, flow.transport)
    direction = infer_direction(flow, is_local)
    distant_scope = classify_address(flow.distant())

    # --- connexion refusee -------------------------------------------------
    if flow.state == "echec" or flow.rst_count > 0:
        reasons.append(RiskReason(
            fact=f"connexion reinitialisee ({flow.rst_count} fois)",
            points=POINTS_CONNEXION_REFUSEE,
            basis="un RST a ete reellement observe dans les paquets",
        ))

    # --- service sensible --------------------------------------------------
    if port_info and port_info.sensitive:
        if direction == "distant":
            reasons.append(RiskReason(
                fact=f"service sensible {port_info.service} joignable sur le port {service_port}",
                points=POINTS_SERVICE_SENSIBLE_ENTRANT,
                basis="connexion entrante vers un port documente comme sensible",
            ))
        else:
            reasons.append(RiskReason(
                fact=f"communication sortante vers {port_info.service} (port {service_port})",
                points=POINTS_SERVICE_SENSIBLE_SORTANT,
                basis="le port figure dans la base comme sensible",
            ))

    # --- protocole en clair ------------------------------------------------
    if port_info and port_info.cleartext and port_info.service in SERVICES_EN_CLAIR_SENSIBLES:
        if flow.packets >= 4:
            reasons.append(RiskReason(
                fact=f"echanges {port_info.service} non chiffres ({flow.packets} paquets)",
                points=POINTS_PROTOCOLE_EN_CLAIR,
                basis="le protocole ne chiffre pas ses echanges par conception",
            ))

    # --- entrant depuis Internet -------------------------------------------
    # Un prefixe de traduction (NAT64) est lui aussi hors du reseau local.
    if direction == "distant" and distant_scope in ("public", "traduction"):
        reasons.append(RiskReason(
            fact=f"connexion entrante depuis une adresse publique ({flow.distant()})",
            points=POINTS_ENTRANT_PUBLIC,
            basis="l'adresse source est hors du reseau local (classification RFC)",
        ))

    # --- volume vers un hote non identifie ---------------------------------
    if (flow.bytes_total > 500_000 and distant_scope in ("public", "traduction")
            and not flow.domain and flow.app_protocol != "DNS"):
        reasons.append(RiskReason(
            fact=f"{flow.bytes_total} octets echangees avec {flow.distant()}, non identifie",
            points=POINTS_VOLUME_NON_IDENTIFIE,
            basis="volume eleve et aucun nom de domaine observe pour identifier la destination",
        ))

    # --- port non documente -------------------------------------------------
    if port_info is None and service_port is not None and flow.packets >= 3:
        reasons.append(RiskReason(
            fact=f"port de service non documente ({service_port})",
            points=POINTS_PORT_NON_DOCUMENTE,
            basis="aucune entree correspondante dans la base de connaissance",
        ))

    # --- trafic chiffre sans destination visible ----------------------------
    if (flow.app_protocol == "TLS" and not flow.domain and flow.packets >= 5
            and distant_scope == "public"):
        reasons.append(RiskReason(
            fact="trafic chiffre sans nom de domaine annonce",
            points=POINTS_CHIFFRE_SANS_DOMAINE,
            basis="aucun SNI observe : la destination reste indeterminee",
        ))

    # --- retransmissions ----------------------------------------------------
    if flow.retransmissions >= 5:
        reasons.append(RiskReason(
            fact=f"{flow.retransmissions} retransmissions estimees",
            points=POINTS_RETRANSMISSIONS,
            basis="numeros de sequence repetes dans le meme sens",
        ))

    score = min(100, sum(r.points for r in reasons))
    label, summary = _level_for(score)

    # Le resume doit rester coherent avec la liste des raisons : annoncer
    # "aucun element" alors qu'une raison est affichee juste en dessous serait
    # contradictoire, et ferait douter de la fiabilite de l'ensemble.
    if score == 0:
        summary = "Aucun element particulier ne retient l'attention."
    elif label == "faible":
        summary = ("Un element a ete note, sans gravite : le detail est donne "
                   "ci-dessous.")

    return RiskAssessment(score=score, label=label, summary=summary, reasons=reasons)
