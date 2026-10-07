"""Detection des interfaces reseau utilisables pour la capture.

Sur Windows, les interfaces remontees par Npcap portent des noms techniques
(\\Device\\NPF_{GUID}) parfaitement illisibles pour un utilisateur. Ce module
les traduit en noms comprehensibles ("Wi-Fi", "Ethernet") et y associe les
adresses IP de la machine.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

from scapy.all import conf, get_if_addr, get_if_list

from app.analysis.protocols import classify_address


@dataclass
class InterfaceInfo:
    """Une interface reseau telle qu'elle sera presentee a l'utilisateur."""

    id: str                         # identifiant technique attendu par Npcap
    name: str                       # nom lisible
    description: str = ""
    addresses: list[str] = field(default_factory=list)
    is_loopback: bool = False
    is_virtual: bool = False        # carte logicielle (Hyper-V, VirtualBox, VPN...)

    @property
    def display(self) -> str:
        addr = ", ".join(self.addresses) if self.addresses else "sans adresse IPv4"
        return f"{self.name} ({addr})"

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "description": self.description,
            "addresses": self.addresses, "is_loopback": self.is_loopback,
            "is_virtual": self.is_virtual, "display": self.display,
        }


# Marqueurs des cartes logicielles : elles transportent du trafic de machine
# virtuelle ou de tunnel, jamais le trafic reel de l'utilisateur.
VIRTUAL_MARKERS = (
    "virtual", "hyper-v", "vethernet", "vmware", "virtualbox", "vbox",
    "wsl", "tap-", "tun", "openvpn", "wireguard", "loopback",
)


def _is_virtual(name: str, description: str) -> bool:
    text = f"{name} {description}".lower()
    return any(marker in text for marker in VIRTUAL_MARKERS)


def _windows_interfaces() -> dict[str, dict]:
    """Table guid -> metadonnees, fournie par Scapy sur Windows."""
    try:
        from scapy.arch.windows import get_windows_if_list
        result = {}
        for entry in get_windows_if_list():
            guid = (entry.get("guid") or "").strip("{}")
            if guid:
                result[guid.lower()] = entry
        return result
    except Exception:
        return {}


def _name_from_description(description: str) -> str:
    """Traduit une description technique en nom court comprehensible."""
    text = (description or "").lower()
    if not text:
        return "Interface"
    if "wi-fi" in text or "wifi" in text or "wireless" in text or "802.11" in text:
        return "Wi-Fi"
    if "loopback" in text:
        return "Boucle locale"
    if "hyper-v" in text:
        return "Hyper-V (machine virtuelle)"
    if "virtualbox" in text:
        return "VirtualBox (machine virtuelle)"
    if "vmware" in text:
        return "VMware (machine virtuelle)"
    if "wsl" in text or "linux" in text:
        return "WSL (sous-systeme Linux)"
    if "bluetooth" in text:
        return "Bluetooth"
    if "vpn" in text or "tap" in text or "tun" in text:
        return "Interface VPN"
    if "ethernet" in text or "realtek" in text or "intel(r)" in text:
        return "Ethernet"
    return (description or "Interface")[:38]


def _usable_address(iface: "InterfaceInfo") -> str | None:
    """Retourne la premiere adresse reellement utilisable d'une interface.

    Une adresse en 169.254.x.x est attribuee automatiquement par Windows quand
    aucune configuration reseau n'a ete obtenue : la carte est deconnectee.
    La choisir pour la capture donne l'illusion d'un outil en panne, alors
    qu'aucun paquet ne circulera jamais dessus.
    """
    for addr in iface.addresses:
        if classify_address(addr) not in ("lien-local", "loopback", "inconnu"):
            return addr
    return None


def list_interfaces() -> list[InterfaceInfo]:
    """Liste les interfaces capturables, les plus utiles en premier.

    Ne leve jamais d'exception : en cas d'echec de Npcap, la liste peut etre
    vide et l'interface web doit savoir l'afficher proprement.
    """
    win_meta = _windows_interfaces()
    interfaces: list[InterfaceInfo] = []

    try:
        raw_ids = list(get_if_list())
    except Exception:
        return []

    for iface_id in raw_ids:
        guid = ""
        if iface_id.startswith("\\Device\\NPF_"):
            guid = iface_id.replace("\\Device\\NPF_", "").strip("{}").lower()

        meta = win_meta.get(guid, {})
        description = meta.get("description", "") or ""

        addresses: list[str] = []
        ips = meta.get("ips") or []
        addresses.extend([ip for ip in ips if ":" not in ip])  # IPv4 seulement
        try:
            fallback = get_if_addr(iface_id)
            if fallback and fallback != "0.0.0.0" and fallback not in addresses:
                addresses.append(fallback)
        except Exception:
            pass

        is_loopback = "loopback" in iface_id.lower() or "loopback" in description.lower()
        name = meta.get("name") or _name_from_description(description)
        if is_loopback:
            name = "Boucle locale"

        interfaces.append(InterfaceInfo(
            id=iface_id,
            name=name if isinstance(name, str) else str(name),
            description=description,
            addresses=addresses,
            is_loopback=is_loopback,
            is_virtual=_is_virtual(str(name), description),
        ))

    # Tri : adresse reellement utilisable d'abord, puis carte physique, puis nom
    interfaces.sort(key=lambda i: (
        _usable_address(i) is None,
        i.is_loopback,
        i.is_virtual,
        i.name.lower(),
    ))
    return interfaces


def primary_address() -> str | None:
    """Adresse locale utilisee pour sortir sur Internet, si elle existe.

    C'est le critere le plus fiable pour identifier la carte qui porte le
    trafic reel : le systeme d'exploitation la choisit lui-meme en fonction
    de sa table de routage.
    """
    import socket as _socket

    try:
        probe = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        probe.settimeout(0.5)
        probe.connect(("8.8.8.8", 80))
        address = probe.getsockname()[0]
        probe.close()
        return address
    except Exception:
        return None


def pick_default_interface() -> InterfaceInfo | None:
    """Choisit l'interface qui porte reellement le trafic de la machine.

    Ordre de priorite :
      1. la carte qui detient l'adresse utilisee pour joindre Internet ;
      2. a defaut, une carte physique (Wi-Fi ou Ethernet) avec adresse routable ;
      3. a defaut, toute carte non virtuelle avec une adresse routable.
    Retourne None si aucune interface ne convient.
    """
    interfaces = list_interfaces()

    # 1. La carte qui porte la route par defaut
    primary = primary_address()
    if primary:
        for iface in interfaces:
            if primary in iface.addresses:
                return iface

    # 2. Une carte physique
    physical = [
        i for i in interfaces
        if _usable_address(i) and not i.is_loopback and not i.is_virtual
    ]
    if physical:
        return physical[0]

    # 3. N'importe quelle carte non virtuelle utilisable
    usable = [i for i in interfaces if _usable_address(i) and not i.is_loopback]
    return usable[0] if usable else None


def local_ips() -> set[str]:
    """Toutes les adresses IPv4 de la machine, y compris la boucle locale.

    Sert a qualifier le sens des communications (sortant / entrant / interne).
    """
    addresses = {"127.0.0.1"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            addresses.add(info[4][0])
    except Exception:
        pass
    for iface in list_interfaces():
        addresses.update(iface.addresses)

    # Adresse utilisee pour joindre Internet : la plus representative
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.settimeout(0.5)
        probe.connect(("8.8.8.8", 80))
        addresses.add(probe.getsockname()[0])
        probe.close()
    except Exception:
        pass

    return {a for a in addresses if a and a != "0.0.0.0"}


def find_interface(identifier: str) -> InterfaceInfo | None:
    """Retrouve une interface par identifiant technique, nom court ou adresse."""
    if not identifier:
        return None
    for iface in list_interfaces():
        if identifier in (iface.id, iface.name) or identifier in iface.addresses:
            return iface
    return None


def capture_available() -> tuple[bool, str]:
    """Verifie que la capture est reellement possible.

    Retourne (disponible, message). Le message explique la cause en clair,
    car une capture impossible est la premiere erreur que rencontrera
    l'utilisateur.
    """
    try:
        interfaces = list_interfaces()
    except Exception as exc:
        return False, f"Le pilote de capture n'a pas pu etre interroge ({type(exc).__name__})."

    if not interfaces:
        return False, (
            "Aucune interface de capture trouvee. Le pilote Npcap (Windows) ou "
            "libpcap (Linux/macOS) est probablement absent."
        )
    try:
        socket_obj = conf.L2listen(iface=conf.iface)
        socket_obj.close()
        return True, f"{len(interfaces)} interface(s) detectee(s)."
    except Exception as exc:
        return False, (
            f"Le pilote repond mais l'ouverture a echoue : {type(exc).__name__}. "
            "Sur Windows, installez Npcap en cochant « autoriser les "
            "utilisateurs non administrateurs a capturer »."
        )
