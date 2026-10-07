"""Base de connaissance reseau : conventions d'usage des ports et protocoles.

Ce module ne regarde JAMAIS un paquet. Il repond a une seule question :

    "Quand on observe le port X en transport Y, qu'est-ce que cela
     signifie habituellement ?"

C'est le coeur de la separation FAIT / INTERPRETATION exigee par le cahier
des charges :

    FAIT OBSERVE     -> "port de destination = 443"          (mesurable)
    INTERPRETATION   -> "port generalement associe a HTTPS"  (convention)

Un port est une *convention*, pas une preuve : rien n'empeche un service
d'ecouter sur un port inhabituel. Chaque entree est donc assortie d'un
niveau de confiance que le moteur d'explication doit respecter.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Literal

Confidence = Literal["haute", "moyenne", "faible"]


# --------------------------------------------------------------------------
# Description d'un port
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PortInfo:
    """Ce que l'on sait d'un port, en langage comprehensible."""

    port: int
    transport: str          # "tcp" | "udp" | "tcp/udp"
    service: str            # nom court : "HTTPS", "DNS"...
    meaning: str            # ce que fait ce service
    why: str                # pourquoi on l'utilise
    confidence: Confidence = "moyenne"
    sensitive: bool = False  # merite l'attention d'un analyste
    cleartext: bool | None = None  # contenu lisible sans dechiffrement ?

    @property
    def display(self) -> str:
        return f"{self.service} (port {self.port}/{self.transport})"


def _p(port, transport, service, meaning, why, confidence="moyenne",
       sensitive=False, cleartext=None) -> PortInfo:
    return PortInfo(port, transport, service, meaning, why, confidence, sensitive, cleartext)


# --------------------------------------------------------------------------
# Ports documentes (IANA + usages de fait)
# --------------------------------------------------------------------------

_PORT_LIST: list[PortInfo] = [
    # --- Web ---
    _p(80, "tcp", "HTTP",
       "transfert de pages web non chiffre",
       "c'est le port historique du Web ; encore tres utilise pour les "
       "redirections vers HTTPS, les API internes et les pages de portails captifs",
       "haute", cleartext=True),
    _p(8080, "tcp", "HTTP alternatif",
       "service web sur un port non privilegie",
       "souvent utilise pour les serveurs de developpement, proxys et interfaces "
       "d'administration ; il s'agit generalement de HTTP en clair",
       "moyenne", cleartext=True),
    _p(8000, "tcp", "HTTP de developpement",
       "serveur web de developpement",
       "port par defaut de nombreux frameworks Python (Django, FastAPI) et de "
       "serveurs de test ; rarement expose en production",
       "moyenne", cleartext=True),
    _p(443, "tcp", "HTTPS",
       "trafic web chiffre par TLS",
       "le contenu est chiffre : l'observateur voit le volume, le rythme et "
       "parfois le nom de domaine (SNI), mais pas le contenu",
       "haute"),
    _p(443, "udp", "QUIC",
       "transport chiffre moderne base sur UDP",
       "HTTP/3 utilise QUIC sur UDP/443 pour reduire la latence ; le trafic "
       "est chiffre",
       "moyenne"),
    _p(8443, "tcp", "HTTPS alternatif",
       "interface web chiffree sur port non privilegie",
       "frequent pour les consoles d'administration (routeurs, hyperviseurs, "
       "panneaux de controle)",
       "moyenne"),
    _p(3000, "tcp", "serveur de developpement",
       "application web en cours de developpement",
       "port par defaut de Node.js/React/Vite ; en developpement local c'est "
       "attendu, vu depuis l'exterieur c'est inhabituel",
       "faible", cleartext=True),

    # --- Resolution de noms ---
    _p(53, "udp", "DNS",
       "resolution de nom de domaine",
       "la majorite des requetes DNS tiennent dans un seul datagramme UDP, "
       "d'ou l'usage d'UDP ; le nom interroge est visible en clair",
       "haute", cleartext=True),
    _p(53, "tcp", "DNS sur TCP",
       "resolution DNS pour reponses volumineuses",
       "TCP est utilise quand la reponse depasse la taille d'un datagramme UDP, "
       "pour les transferts de zone ou quand la reponse est signee (DNSSEC)",
       "haute", cleartext=True),
    _p(853, "tcp", "DNS over TLS",
       "resolution DNS chiffree",
       "chiffre les requetes DNS pour empecher l'observation des noms visites",
       "haute"),
    _p(5353, "udp", "mDNS",
       "resolution de noms sur le reseau local",
       "permet aux appareils du reseau local (imprimantes, objets connectes, "
       "PC) de se decouvrir sans serveur DNS central ; trafic de diffusion",
       "haute", cleartext=True),

    # --- Infrastructure locale ---
    _p(67, "udp", "DHCP serveur",
       "attribution automatique d'adresses IP",
       "le serveur DHCP ecoute sur 67 et repond au client sur 68 ; c'est ainsi "
       "qu'un appareil obtient son adresse IP",
       "haute", cleartext=True),
    _p(68, "udp", "DHCP client",
       "demande d'adresse IP",
       "un appareil qui vient de se connecter reclame une configuration reseau",
       "haute", cleartext=True),
    _p(123, "udp", "NTP",
       "synchronisation de l'heure",
       "UDP suffit car une requete NTP tient en un paquet et une reponse perdue "
       "n'est pas grave : il suffit de redemander",
       "haute"),
    _p(137, "udp", "NetBIOS",
       "resolution de noms Windows sur le reseau local",
       "protocole herite de Windows pour nommer les machines du reseau local ; "
       "il expose des informations sur le parc",
       "moyenne", sensitive=True, cleartext=True),
    _p(138, "udp", "NetBIOS datagramme",
       "diffusion de noms Windows",
       "service de diffusion lie a NetBIOS",
       "moyenne", sensitive=True, cleartext=True),
    _p(139, "tcp", "NetBIOS session",
       "partage de fichiers Windows ancien",
       "predecesseur de SMB direct ; sa presence signale un reseau Windows "
       "ancien ou mal configure",
       "moyenne", sensitive=True),
    _p(1900, "udp", "SSDP",
       "decouverte de services UPnP",
       "les objets connectes annoncent leur presence en diffusion ; tres "
       "verbeux et souvent exploite pour cartographier un reseau",
       "moyenne", sensitive=True, cleartext=True),
    _p(5355, "udp", "LLMNR",
       "resolution de noms locale Windows",
       "repli de Windows quand le DNS echoue ; peut etre detourne pour "
       "intercepter des identifiants",
       "moyenne", sensitive=True, cleartext=True),
    _p(445, "tcp", "SMB",
       "partage de fichiers et d'imprimantes Windows",
       "protocole central du partage Windows ; il a ete la cible de "
       "vulnerabilites majeures (WannaCry) et ne devrait jamais etre expose "
       "sur Internet",
       "haute", sensitive=True),
    _p(3389, "tcp", "Bureau a distance (RDP)",
       "prise de controle graphique d'une machine",
       "permet d'administrer Windows a distance ; expose sur Internet, il est "
       "constamment balaye et attaque par force brute",
       "haute", sensitive=True),
    _p(5900, "tcp", "VNC",
       "bureau a distance multi-plateforme",
       "alternative a RDP, souvent sans chiffrement fort ; a reserver au "
       "reseau local ou a un tunnel",
       "haute", sensitive=True),

    # --- Administration et transfert ---
    _p(22, "tcp", "SSH",
       "administration a distance chiffree",
       "remplace Telnet ; tout est chiffre, y compris le mot de passe et les "
       "fichiers transferes (SFTP, SCP)",
       "haute"),
    _p(23, "tcp", "Telnet",
       "administration a distance NON chiffree",
       "protocole historique abandonne car mot de passe et commandes "
       "circulent en clair ; sa presence sur un reseau moderne est une "
       "faiblesse",
       "haute", sensitive=True, cleartext=True),
    _p(21, "tcp", "FTP (controle)",
       "transfert de fichiers non chiffre",
       "les identifiants et les fichiers circulent en clair ; remplace par "
       "SFTP sur le port 22",
       "haute", sensitive=True, cleartext=True),
    _p(20, "tcp", "FTP (donnees)",
       "canal de donnees FTP en mode actif",
       "le serveur ouvre cette connexion vers le client pour envoyer le fichier",
       "moyenne", cleartext=True),
    _p(69, "udp", "TFTP",
       "transfert de fichiers tres simple",
       "sans authentification ; utilise pour demarrer des equipements "
       "(PXE) ou mettre a jour des firmwares",
       "haute", sensitive=True, cleartext=True),

    # --- Messagerie ---
    _p(25, "tcp", "SMTP",
       "envoi de courriel entre serveurs",
       "canal historique du transfert de mail ; rarement chiffre et souvent "
       "refuse par les fournisseurs (port 587 privilegie)",
       "haute", cleartext=True),
    _p(587, "tcp", "SMTP soumission",
       "envoi de courriel par un client",
       "port moderne d'envoi, avec authentification puis passage en TLS",
       "haute"),
    _p(465, "tcp", "SMTP over TLS",
       "envoi de courriel chiffre des le depart",
       "variante completement chiffree de l'envoi de mail",
       "haute"),
    _p(110, "tcp", "POP3",
       "releve de courriel non chiffre",
       "telecharge les messages puis les supprime du serveur ; remplace par "
       "IMAPS (993)",
       "haute", cleartext=True),
    _p(143, "tcp", "IMAP",
       "consultation de courriel cote serveur",
       "garde les messages sur le serveur et les synchronise sur plusieurs "
       "appareils",
       "haute", cleartext=True),
    _p(993, "tcp", "IMAPS",
       "consultation de courriel chiffree",
       "version TLS d'IMAP ; c'est le standard actuel des clients mail",
       "haute"),
    _p(995, "tcp", "POP3S",
       "releve de courriel chiffre",
       "version TLS de POP3",
       "haute"),

    # --- Bases de donnees ---
    _p(3306, "tcp", "MySQL / MariaDB",
       "base de donnees relationnelle",
       "aucun chiffrement par defaut : une connexion a ce port depuis "
       "l'exterieur du reseau local merite une verification immediate",
       "haute", sensitive=True),
    _p(5432, "tcp", "PostgreSQL",
       "base de donnees relationnelle",
       "le chiffrement depend de la configuration ; l'acces devrait etre "
       "restreint au reseau applicatif",
       "haute", sensitive=True),
    _p(1433, "tcp", "Microsoft SQL Server",
       "base de donnees relationnelle Microsoft",
       "cible frequente de balayages et d'attaques par force brute",
       "haute", sensitive=True),
    _p(6379, "tcp", "Redis",
       "base de donnees en memoire",
       "ecoute souvent sans authentification lorsqu'il est mal configure ; "
       "une exposition directe est une faille grave",
       "haute", sensitive=True),
    _p(27017, "tcp", "MongoDB",
       "base de donnees orientee documents",
       "meme risque que Redis : des instances exposees sans mot de passe sont "
       "regulierement trouvees et videes",
       "haute", sensitive=True),
    _p(11211, "tcp/udp", "Memcached",
       "cache en memoire",
       "utilise pour accelerer les sites ; les instances ouvertes servent "
       "d'amplificateurs d'attaques par deni de service",
       "haute", sensitive=True),
    _p(9200, "tcp", "Elasticsearch",
       "moteur de recherche et d'indexation",
       "souvent deploye sans authentification en interne ; expose sur "
       "Internet il divulgue l'integralite des donnees indexees",
       "moyenne", sensitive=True),

    # --- Annuaire et authentification ---
    _p(389, "tcp", "LDAP",
       "annuaire d'entreprise (utilisateurs, groupes)",
       "interroge l'annuaire ; non chiffre, il peut reveler la structure du "
       "systeme d'information",
       "haute", sensitive=True, cleartext=True),
    _p(636, "tcp", "LDAPS",
       "annuaire d'entreprise chiffre",
       "version TLS de LDAP, y compris pour l'authentification",
       "haute"),
    _p(88, "tcp/udp", "Kerberos",
       "authentification d'entreprise",
       "distribue des tickets d'authentification dans un domaine Windows ; "
       "cible connue d'attaques par extraction de tickets",
       "haute", sensitive=True),

    # --- Supervision ---
    _p(161, "udp", "SNMP",
       "supervision d'equipements reseau",
       "interroge routeurs et serveurs ; les versions 1 et 2c utilisent une "
       "cle commune transmise en clair",
       "haute", sensitive=True, cleartext=True),
    _p(514, "udp", "Syslog",
       "journalisation centralisee",
       "les equipements envoient leurs journaux ; le contenu circule en clair",
       "haute", cleartext=True),
    _p(135, "tcp", "RPC Windows",
       "appel de procedures distantes Microsoft",
       "ouvre dynamiquement d'autres ports ; son observation aide a cartographier "
       "un parc Windows",
       "moyenne", sensitive=True),

    # --- Tunnel et VPN ---
    _p(500, "udp", "IKE",
       "negociation de tunnel IPsec",
       "premiere etape de l'etablissement d'un VPN IPsec",
       "haute"),
    _p(4500, "udp", "IPsec NAT-T",
       "tunnel IPsec derriere un routeur",
       "encapsule IPsec dans UDP pour traverser les routeurs qui font du NAT",
       "haute"),
    _p(1194, "udp", "OpenVPN",
       "tunnel VPN OpenVPN",
       "choix par defaut d'OpenVPN ; le trafic interne est chiffre",
       "moyenne"),
    _p(1723, "tcp", "PPTP",
       "VPN obsolete",
       "protocole dont le chiffrement est casse depuis longtemps ; son usage "
       "est un signe de configuration obsolete",
       "haute", sensitive=True),

    # --- Telephonie et messagerie instantanee ---
    _p(5060, "tcp/udp", "SIP",
       "signalisation de telephonie sur IP",
       "etablit les appels VoIP ; sans TLS, les identifiants d'appel peuvent "
       "circuler en clair",
       "haute", sensitive=True, cleartext=True),
    _p(5061, "tcp", "SIP over TLS",
       "signalisation d'appel chiffree",
       "version chiffree de SIP",
       "haute"),
    _p(5228, "tcp", "Google Play / FCM",
       "notifications et mises a jour Android",
       "les appareils Android y maintiennent une connexion permanente ; "
       "attendu sur un reseau d'entreprise, peut surprendre sans contexte",
       "moyenne"),
    _p(5222, "tcp", "XMPP",
       "messagerie instantanee federée",
       "protocole ouvert de messagerie ; souvent chiffre par TLS",
       "moyenne"),

    # --- Ports a surveiller ---
    _p(4444, "tcp", "Metasploit (par defaut)",
       "port d'ecoute plante par defaut par un outil d'exploitation",
       "Metasploit utilise ce port par defaut pour ses connexions entrantes ; "
       "sa presence peut trahir un outil offensif",
       "faible", sensitive=True),
    _p(31337, "tcp", "Back Orifice",
       "port historique de cheval de Troie",
       "port associe a un outil de prise de controle a distance des annees "
       "1990 ; encore utilise par convention dans certaines portes derobees",
       "faible", sensitive=True),
    _p(1337, "tcp", "Port non standard",
       "service quelconque sur leet-speak",
       "aucun standard ; souvent choisi volontairement pour sortir des "
       "statistiques habituelles",
       "faible", sensitive=True),
]

PORT_KNOWLEDGE: dict[tuple[str, int], PortInfo] = {}
for _info in _PORT_LIST:
    for _t in _info.transport.split("/"):
        PORT_KNOWLEDGE[(_t, _info.port)] = _info

# Liste sans doublon, pour la page de reference : chaque service n'y apparait
# qu'une fois, meme lorsqu'il est documente sur les deux transports.
ALL_PORTS: tuple[PortInfo, ...] = tuple(_PORT_LIST)


def knowledge_base_export() -> dict:
    """Exporte la base de connaissance pour l'affichage.

    Utilise par la page « Protocoles » : le visiteur peut y consulter les
    conventions documentees et verifier ce que l'application sait interpreter.
    """
    return {
        "ports": [
            {
                "port": p.port,
                "transport": p.transport.upper(),
                "service": p.service,
                "meaning": p.meaning,
                "why": p.why,
                "confidence": p.confidence,
                "sensitive": p.sensitive,
                "cleartext": p.cleartext,
            }
            for p in sorted(ALL_PORTS, key=lambda p: (p.port, p.transport))
        ],
        "transports": [
            {"name": name, "role": info.role, "reliability": info.reliability,
             "example": info.example}
            for name, info in TRANSPORT_KNOWLEDGE.items()
        ],
        "applications": [
            {"name": info.name, "what": info.what, "readable": info.readable,
             "clues": info.clues}
            for info in APP_PROTOCOLS.values()
        ],
        "tcp_flags": [
            {"flags": flags, "meaning": meaning}
            for flags, meaning in TCP_FLAG_MEANING.items()
        ],
        "network": [
            {"term": term, "meaning": meaning}
            for term, meaning in NETWORK_KNOWLEDGE.items()
        ],
        "scopes": [
            {"key": key, "label": label} for key, label in SCOPE_LABELS.items()
        ],
    }


def lookup_port(port: int | None, transport: str | None) -> PortInfo | None:
    """Retourne la connaissance associee a un port, ou None si inconnue.

    Le transport est essaye d'abord, puis on retombe sur l'autre transport
    (un service TCP observe en UDP reste plus probablement ce service que
    du bruit). Cette recherche de repli est signalee par une confiance plus
    basse.
    """
    if port is None:
        return None
    t = (transport or "").lower()
    if t and (t, port) in PORT_KNOWLEDGE:
        return PORT_KNOWLEDGE[(t, port)]
    other = "udp" if t == "tcp" else "tcp"
    if (other, port) in PORT_KNOWLEDGE:
        found = PORT_KNOWLEDGE[(other, port)]
        return PortInfo(
            found.port, found.transport, found.service, found.meaning,
            found.why, confidence="faible", sensitive=found.sensitive,
            cleartext=found.cleartext,
        )
    return None


def is_sensitive_port(port: int | None, transport: str | None) -> bool:
    info = lookup_port(port, transport)
    return bool(info and info.sensitive)


# --------------------------------------------------------------------------
# Protocoles de transport et de reseau
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TransportInfo:
    name: str
    role: str
    reliability: str
    example: str


TRANSPORT_KNOWLEDGE: dict[str, TransportInfo] = {
    "TCP": TransportInfo(
        "TCP",
        "etablit une connexion, verifie que chaque octet arrive et le remet "
        "dans l'ordre",
        "fiable : toute donnee perdue est renvoyee automatiquement",
        "navigation web, messagerie, transfert de fichiers",
    ),
    "UDP": TransportInfo(
        "UDP",
        "envoie des datagrammes independants, sans connexion ni accuse de "
        "reception",
        "non fiable mais tres rapide et leger",
        "DNS, video en direct, jeux en ligne, NTP",
    ),
    "ICMP": TransportInfo(
        "ICMP",
        "transporte des messages de controle et d'erreur sur le reseau, et "
        "non des donnees utilisateur",
        "hors du mecanisme de fiabilite de TCP",
        "commande ping, messages 'destination injoignable'",
    ),
    "ARP": TransportInfo(
        "ARP",
        "traduit une adresse IP en adresse materielle (MAC) sur le reseau local",
        "protocole local, non routable",
        "une machine demande 'qui possede l'adresse 192.168.1.1 ?'",
    ),
}

NETWORK_KNOWLEDGE = {
    "IP": "l'adresse logique qui identifie une machine sur le reseau ; elle "
          "permet d'acheminer un paquet jusqu'a destination",
    "MAC": "l'adresse materielle gravee dans la carte reseau ; elle n'a de "
           "sens que sur le reseau local",
    "TTL": "compteur decrémenté à chaque routeur traversé ; il empêche qu'un "
           "paquet tourne indéfiniment et permet d'estimer le nombre de "
           "routeurs franchis (64, 128 et 255 sont les valeurs de départ "
           "les plus courantes)",
    "PAQUET": "une tranche de donnees a laquelle on a ajoute les informations "
              "necessaires pour l'acheminer (qui envoie, a qui, quel "
              "protocole) ; une communication est une suite de paquets",
}

TCP_FLAG_MEANING = {
    "S": "SYN : demande d'ouverture de connexion (premier contact)",
    "SA": "SYN,ACK : le serveur accepte et repond",
    "A": "ACK : accuse de reception",
    "PA": "PSH,ACK : donnees envoyees et acquittees en meme temps",
    "FA": "FIN,ACK : demande de fermeture normale de la connexion",
    "F": "FIN : demande de fermeture normale",
    "RA": "RST,ACK : fermeture brutale ou refus de connexion",
    "R": "RST : connexion reinitialisee",
}


# --------------------------------------------------------------------------
# Application : ce que l'on peut reconnaitre dans le contenu
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AppProtocolInfo:
    name: str
    what: str
    readable: bool          # le contenu est-il lisible en clair ?
    clues: str              # sur quels indices on le reconnait


APP_PROTOCOLS: dict[str, AppProtocolInfo] = {
    "DNS": AppProtocolInfo(
        "DNS",
        "traduit un nom de domaine en adresse IP, et inversement",
        True,
        "port 53 ou 5353, structure de question/reponse propre au DNS",
    ),
    "HTTP": AppProtocolInfo(
        "HTTP",
        "transporte les pages web et les requetes d'API en clair",
        True,
        "port 80/8080 et premiere ligne de texte comme 'GET / HTTP/1.1'",
    ),
    "TLS": AppProtocolInfo(
        "TLS",
        "chiffre une communication : personne sur le chemin ne peut lire le "
        "contenu, mais le nom du serveur peut rester visible lors de la "
        "negociation initiale",
        False,
        "port 443/8443 et premier octet de contenu valant 0x16 (ClientHello)",
    ),
    "DHCP": AppProtocolInfo(
        "DHCP",
        "attribue automatiquement une configuration reseau a un appareil",
        True,
        "ports 67/68 et structure de message DHCP",
    ),
    "mDNS": AppProtocolInfo(
        "mDNS",
        "permet aux appareils du reseau local de se decouvrir mutuellement",
        True,
        "port 5353 en diffusion, format proche de DNS",
    ),
    "SSDP": AppProtocolInfo(
        "SSDP",
        "annonce et decouvre des services (imprimantes, telephones, objets "
        "connectes) sur le reseau local",
        True,
        "port 1900 en diffusion, requetes de type NOTIFY/M-SEARCH",
    ),
    "NTP": AppProtocolInfo(
        "NTP",
        "synchronise l'horloge des machines",
        True,
        "port 123 et structure de message NTP",
    ),
    "ICMP": AppProtocolInfo(
        "ICMP",
        "transporte des messages de controle : un 'ping' ou une erreur de "
        "routage, jamais des donnees utilisateur",
        True,
        "absence de port, type et code ICMP",
    ),
    "ARP": AppProtocolInfo(
        "ARP",
        "fait le lien entre adresse IP et adresse materielle sur le reseau local",
        True,
        "trame de diffusion portant une question 'qui possede telle IP ?'",
    ),
    "QUIC": AppProtocolInfo(
        "QUIC",
        "transport chiffre a faible latence servant HTTP/3",
        False,
        "UDP port 443 et en-tete long a version QUIC",
    ),
}


# --------------------------------------------------------------------------
# Portee d'une adresse
# --------------------------------------------------------------------------

SCOPE_LABELS = {
    "prive": "adresse privee (reseau local)",
    "public": "adresse publique (joignable sur Internet)",
    "loopback": "adresse de boucle locale (la machine se parle a elle-meme)",
    "multicast": "adresse de diffusion groupee",
    "lien-local": "adresse locale automatique (aucun serveur DHCP n'a repondu)",
    "reserve": "plage reservee ou non attribuee",
    "traduction": "prefixe de traduction (plusieurs destinations reelles derriere)",
    "inconnu": "nature indeterminee",
}

# Prefixes de transition IPv6 : ils ne designent PAS une machine unique mais
# une passerelle derriere laquelle se trouvent de nombreuses destinations.
# Les prendre pour un hote ferait dire a l'analyse « un serveur concentre 97 %
# du trafic » alors qu'il s'agit en realite de dizaines de serveurs distincts.
TRANSLATION_NETWORKS = (
    "64:ff9b::/96",       # NAT64 (RFC 6052)
    "64:ff9b:1::/48",     # NAT64 local (RFC 8215)
    "2002::/16",          # 6to4 (RFC 3056)
    "2001::/32",          # Teredo (RFC 4380)
    "::ffff:0:0/96",      # IPv4-mapped
)


def is_translation_prefix(ip: str | None) -> bool:
    """L'adresse est-elle un prefixe de traduction IPv6 ?

    Ce n'est pas un hote : c'est une passerelle. La distinguer evite des
    conclusions trompeuses sur « l'hote qui concentre le trafic ».
    """
    if not ip or ":" not in ip:
        return False
    import ipaddress as _ipaddress

    try:
        address = _ipaddress.ip_address(ip)
    except ValueError:
        return False
    for network in TRANSLATION_NETWORKS:
        try:
            if address in _ipaddress.ip_network(network):
                return True
        except ValueError:
            continue
    return False


def classify_address(ip: str | None) -> str:
    """Classe une adresse IP : prive, public, loopback, multicast, lien-local.

    Cette classification est un FAIT (deduit des plages RFC), pas une
    interpretation : elle alimente l'explication sans jamais la remplacer.
    """
    if not ip:
        return "inconnu"

    if is_translation_prefix(ip):
        return "traduction"

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "inconnu"

    if addr.is_loopback:
        return "loopback"
    if addr.is_multicast:
        return "multicast"
    if addr.is_link_local:
        return "lien-local"
    if addr.is_private:
        return "prive"
    if addr.is_reserved:
        return "reserve"
    return "public"


def describe_scope(ip: str | None) -> str:
    return SCOPE_LABELS.get(classify_address(ip), "nature indeterminee")
