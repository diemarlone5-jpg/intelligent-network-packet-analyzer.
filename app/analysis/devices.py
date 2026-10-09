"""Appareils presents sur le reseau local et services qu'ils annoncent.

POURQUOI CE MODULE

Sur un reseau Wi-Fi chiffre (WPA2) relie par un commutateur, il est
physiquement impossible de lire les conversations des autres appareils : chaque
machine chiffre ses trames avec sa propre cle, et un commutateur n'envoie une
trame qu'au port de destination. Aucun programme ne contourne cela.

En revanche, certaines informations sont diffusees a TOUT le reseau, par
conception :

    - les requetes ARP (« qui a l'adresse 192.168.1.4 ? ») revelent l'existence
      et l'adresse materielle de chaque appareil ;
    - le mDNS / DNS-SD (port 5353, groupes 224.0.0.251 et ff02::fb) : les
      appareils y annoncent les services qu'ils proposent et y cherchent ceux
      qu'ils veulent utiliser ;
    - le SSDP / UPnP (port 1900, groupe 239.255.255.250).

Ces diffusions sont lisibles par tout le monde, et c'est exactement ce qu'un
outil comme Wireshark montre aussi. C'est ainsi qu'on peut savoir qu'un appareil
du reseau fait tourner Spotify, sans jamais lire sa musique.

CE QUE CE MODULE NE FAIT PAS

Il ne lit aucun contenu prive, ne dechiffre rien, n'intercepte rien. Il se
contente de rassembler ce que les appareils diffusent volontairement.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

# --------------------------------------------------------------------------
# Types de services DNS-SD -> ce que cela veut dire en clair
#
# Sources : registre des types de services DNS-SD de l'IANA, et documentation
# officielle des editeurs. Les entrees dont l'origine n'est pas certaine sont
# volontairement absentes : mieux vaut « service non documente » qu'une
# affirmation inventee.
# --------------------------------------------------------------------------

SERVICE_LABELS: dict[str, str] = {
    # --- Musique et multimedia ---
    "_spotify-connect": "Spotify Connect",
    "_googlecast": "Google Cast (Chromecast, Android TV)",
    "_airplay": "AirPlay (diffusion video Apple)",
    "_raop": "AirPlay audio (Apple)",
    "_sonos": "Enceinte Sonos",
    "_daap": "Partage musical (iTunes)",
    "_amzn-wplay": "Amazon (Fire TV)",
    "_androidtvremote2": "Android TV (telecommande)",
    "_mediaremotetv": "Apple TV",

    # --- Ordinateurs et appareils Apple ---
    "_apple-mobdev2": "Appareil Apple (iPhone, iPad, Mac)",
    "_companion-link": "Apple (continuite entre appareils)",
    "_touch-able": "Telecommande Apple (Remote)",
    "_sleep-proxy": "Apple (reveil reseau)",
    "_device-info": "Information sur l'appareil",
    "_rdlink": "Mac (bureau a distance)",

    # --- Ordinateurs et partage ---
    "_smb": "Partage de fichiers Windows (SMB)",
    "_afpovertcp": "Partage de fichiers Apple (AFP)",
    "_workstation": "Poste de travail (partage Unix)",
    "_ssh": "Acces distant SSH",
    "_sftp-ssh": "Transfert de fichiers SFTP",
    "_ftp": "Transfert de fichiers FTP",
    "_rfb": "Partage d'ecran (VNC)",
    "_rdp": "Bureau a distance Windows",
    "_http": "Service web local",
    "_https": "Service web securise local",

    # --- Impression ---
    "_ipp": "Imprimante (IPP)",
    "_ipps": "Imprimante securisee (IPPS)",
    "_printer": "Imprimante (LPD)",
    "_pdl-datastream": "Imprimante (flux brut)",

    # --- Maison connectee ---
    "_homekit": "Maison connectee (HomeKit)",
    "_hap": "Accessoire maison connectee (HomeKit)",
    "_matter": "Objet connecte (Matter)",
    "_matterc": "Objet connecte (Matter, commissionnement)",
    "_googlezone": "Enceinte Google (groupe multiroom)",
    "_miio": "Appareil Xiaomi",

    # --- Jeux et divers ---
    "_minecraft": "Serveur Minecraft",
    "_steam": "Steam (jeux)",
    "_xbox": "Xbox",
    "_ps5": "PlayStation 5",

    # --- Mecanique du reseau ---
    "_services": "Liste des services proposes par cet appareil",
    "_dosvc": "Windows Update (livraison optimisee)",
    "_dns-sd": "Recherche de services (navigation)",
}

# Protocoles diffuses par les routeurs et objets connectes (SSDP / UPnP)
UPNP_DEVICE_LABELS: dict[str, str] = {
    "internetgatewaydevice": "Box / routeur Internet",
    "wanconnectiondevice": "Passerelle Internet",
    "mediarenderer": "Lecteur multimedia (lecture sur l'appareil)",
    "mediaserver": "Serveur multimedia (partage de contenu)",
    "printer": "Imprimante reseau",
    "scanner": "Scanner reseau",
    "basic": "Appareil UPnP",
}


def explain_service(name: str | None) -> tuple[str | None, str | None]:
    """Traduit un nom DNS-SD en (etiquette lisible, nom de l'appareil).

    Exemples :
        « smart-tv-A1B2._googlecast._tcp.local »
            -> (« Google Cast (Chromecast, Android TV) », « smart-tv-A1B2 »)
        « DESKTOP-ABC.local »
            -> (None, « DESKTOP-ABC »)

    Retourne (None, None) si le nom est vide ou n'a pas de sens exploitable.
    """
    if not name:
        return None, None

    original = str(name).strip().rstrip(".")
    if not original:
        return None, None

    # La casse d'origine est conservee pour l'affichage : « Bose-ST10 » se lit
    # mieux que « bose-st10 ». Seuls les identifiants techniques (le type de
    # service) sont normalises, car ce sont des cles de comparaison.
    morceaux_origine = original.split(".")
    morceaux = [morceau.lower() for morceau in morceaux_origine]

    # Nom de service : <instance>._<service>._<protocole>.local
    for index, morceau in enumerate(morceaux):
        if not morceau.startswith("_"):
            continue
        if index + 1 >= len(morceaux):
            break
        # Le nom du service est porte par le morceau qui suit la tete "_xxx"
        type_service = morceau
        if index > 0:
            instance = ".".join(morceaux_origine[:index])
        else:
            # Cas « _services._dns-sd._udp.local » : pas d'instance, c'est une
            # interrogation sur les types de services disponibles.
            instance = ""
        etiquette = SERVICE_LABELS.get(type_service)
        return etiquette, (instance or None)

    # Pas de service : c'est un simple nom d'hote (« DESKTOP-ABC.local »)
    if len(morceaux) >= 2 and morceaux[-1] == "local":
        return None, morceaux_origine[0] or None
    return None, None


def service_type_of(name: str | None) -> str | None:
    """Retourne le type de service brut (« _googlecast ») d'un nom DNS-SD."""
    if not name:
        return None
    for morceau in str(name).strip().rstrip(".").split("."):
        if morceau.startswith("_"):
            return morceau.lower()
    return None


# --------------------------------------------------------------------------
# Appareils
# --------------------------------------------------------------------------


@dataclass
class Device:
    """Un appareil identifie sur le reseau local, et ce qu'on a observe de lui."""

    ip: str
    mac: str | None = None
    hostname: str | None = None
    packets: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    is_local: bool = False
    # Service -> (etiquette, annonce par l'appareil lui-meme ?)
    services: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "packets": self.packets,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "is_local": self.is_local,
            "services": [
                {"type": t, **infos}
                for t, infos in sorted(self.services.items())
            ],
        }


class DeviceTable:
    """Rassemble les appareils vus sur le reseau et les services annonces.

    Alimentee paquet par paquet, elle ne fait aucune requete reseau et ne
    conserve que des compteurs bornes.
    """

    def __init__(self, is_local: Callable[[str], bool], max_devices: int = 400) -> None:
        self._is_local = is_local
        self._max_devices = max_devices
        self._devices: dict[str, Device] = {}
        self._services: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    def clear(self) -> None:
        self._devices.clear()
        self._services.clear()

    # ------------------------------------------------------------------
    def observe(self, record) -> None:
        """Integre un paquet. Ne doit jamais lever."""
        try:
            self._observe_addresses(record)
            self._observe_arp(record)
            self._observe_service(record)
        except Exception:
            # Un paquet exotique ne doit jamais interrompre la capture.
            pass

    # ------------------------------------------------------------------
    def _observe_addresses(self, record) -> None:
        """Compte les paquets emis par chaque adresse locale.

        Seules les adresses EMETTRICES creent un appareil. Une adresse qui
        n'apparait que comme destination n'est pas une preuve d'existence : une
        requete ARP « qui a 192.168.1.10 ? » cite une adresse qui peut tres bien
        n'etre attribuee a personne. Un appareil, c'est quelque chose qui a
        parle.
        """
        if getattr(record, "malformed", False):
            return

        adresse = record.src
        if not adresse or adresse == "?":
            return
        if not self._keep_address(adresse):
            return

        appareil = self._devices.get(adresse)
        if appareil is None:
            if len(self._devices) >= self._max_devices:
                return
            appareil = Device(
                ip=adresse,
                first_seen=record.ts,
                is_local=self._is_local(adresse),
            )
            self._devices[adresse] = appareil

        appareil.packets += 1
        appareil.last_seen = record.ts

        # Une adresse physique n'est retenue que si elle appartient vraiment a
        # l'appareil : pour une trame relayee par la box, la source materielle
        # est celle de la box, pas celle de l'emetteur.
        if record.src_mac and appareil.mac is None:
            if self._mac_is_usable(record.src_mac, record.dst_mac):
                appareil.mac = record.src_mac

    @staticmethod
    def _mac_is_usable(src_mac: str | None, dst_mac: str | None) -> bool:
        """Ecarte les adresses physiques de diffusion et de multicast.

        ff:ff:ff:ff:ff:ff et 01:00:5e:xx designent « tout le monde », pas un
        appareil precis : les enregistrer comme identite serait faux.
        """
        if not src_mac:
            return False
        if src_mac == "ff:ff:ff:ff:ff:ff":
            return False
        if src_mac.startswith("01:00:5e") or src_mac.startswith("33:33"):
            return False
        return True

    @staticmethod
    def _keep_address(adresse: str) -> bool:
        """Retient les adresses du reseau local (v4 privee, v6 locale)."""
        texte = adresse.split("%")[0]
        if texte.startswith(("224.", "239.", "255.")) or texte in ("0.0.0.0", "?"):
            return False
        # Adresses de diffusion : « 192.168.1.255 » designe tout le monde sur le
        # reseau, pas un appareil. La compter comme un appareil serait faux.
        if texte.endswith(".255"):
            return False
        if texte.startswith(("192.168.", "10.")):
            return True
        if texte.startswith("172."):
            try:
                deuxieme = int(texte.split(".")[1])
            except (IndexError, ValueError):
                return False
            return 16 <= deuxieme <= 31
        if texte.startswith(("fe80:", "fd", "fc")):
            return True
        return False

    # ------------------------------------------------------------------
    def _observe_arp(self, record) -> None:
        """ARP est la source la plus fiable du couple adresse IP / adresse physique.

        Un appareil qui repond a une requete ARP donne lui-meme les deux
        informations : rien n'est deduit.
        """
        if getattr(record, "protocol", "") != "ARP":
            return
        if not record.src or not record.src_mac:
            return
        if not self._keep_address(record.src):
            return

        appareil = self._devices.get(record.src)
        if appareil is None:
            if len(self._devices) >= self._max_devices:
                return
            appareil = Device(ip=record.src, first_seen=record.ts,
                              is_local=self._is_local(record.src))
            self._devices[record.src] = appareil
        if self._mac_is_usable(record.src_mac, None):
            appareil.mac = record.src_mac

    # ------------------------------------------------------------------
    def _observe_service(self, record) -> None:
        """Retient les services mDNS / DNS-SD vus sur le reseau.

        Deux cas bien distincts, qu'il ne faut pas confondre :

          - l'appareil POSE UNE QUESTION (« qui propose du Spotify ? ») : cela
            prouve qu'un logiciel cherchant ce service tourne sur cet appareil ;
          - l'appareil REPOND (« moi, je propose du Spotify ») : cela prouve que
            l'appareil lui-meme rend ce service.

        Confondre les deux ferait dire a l'outil l'inverse de la verite.
        """
        nom = getattr(record, "dns_query", None)
        if not nom:
            return
        if "." not in nom:
            return
        if not nom.endswith(".local"):
            return

        etiquette, instance = explain_service(nom)
        type_service = service_type_of(nom)
        if not type_service:
            return

        # Un service sans etiquette documentee n'est pas affiche : inventer un
        # sens serait pire que de se taire.
        est_annonce = getattr(record, "dns_is_query", None) is False

        entree = self._services.get(type_service)
        if entree is None:
            entree = {
                "type": type_service,
                "label": etiquette,
                "instances": set(),
                "announced": False,
                "searched": False,
                "first_seen": record.ts,
                "last_seen": record.ts,
                "actors": set(),
            }
            self._services[type_service] = entree

        entree["last_seen"] = record.ts
        if instance:
            entree["instances"].add(instance)
        if est_annonce:
            entree["announced"] = True
        else:
            entree["searched"] = True
        if record.src and self._keep_address(record.src):
            entree["actors"].add(record.src)

        # Le service est rattache a l'appareil emetteur, avec la precision du
        # sens : « recherche » n'est pas « propose ».
        if record.src and self._keep_address(record.src):
            appareil = self._devices.get(record.src)
            if appareil is not None:
                infos = appareil.services.get(type_service)
                if infos is None:
                    infos = {"label": etiquette, "searched": False,
                             "announced": False, "instances": []}
                    appareil.services[type_service] = infos
                if est_annonce:
                    infos["announced"] = True
                else:
                    infos["searched"] = True
                if instance and instance not in infos["instances"]:
                    infos["instances"].append(instance)
            # Le nom d'hote se deduit des annonces mDNS de l'appareil
            if instance and appareil is not None and appareil.hostname is None:
                if type_service in ("_device-info", "_workstation", "_smb"):
                    appareil.hostname = instance

    # ------------------------------------------------------------------
    def snapshot(self) -> list[dict[str, Any]]:
        """Appareils observes, les plus actifs d'abord.

        Un appareil physique porte generalement plusieurs adresses (une IPv4 et
        une ou plusieurs IPv6). Les presenter comme autant d'appareils
        differents donnerait une image fausse du reseau : elles sont donc
        regroupees par adresse materielle, qui est l'identite reelle de la
        machine. Un appareil dont l'adresse materielle est inconnue reste une
        ligne a part, faute de pouvoir l'apparier.
        """
        groupes: dict[str, dict[str, Any]] = {}

        for appareil in self._devices.values():
            cle = appareil.mac or f"ip:{appareil.ip}"
            groupe = groupes.get(cle)
            if groupe is None:
                groupe = {
                    "key": cle,
                    "mac": appareil.mac,
                    "hostname": None,
                    "addresses": [],
                    "packets": 0,
                    "first_seen": appareil.first_seen,
                    "last_seen": appareil.last_seen,
                    "is_local": False,
                    "services": {},
                }
                groupes[cle] = groupe

            groupe["addresses"].append(appareil.ip)
            groupe["packets"] += appareil.packets
            groupe["first_seen"] = min(groupe["first_seen"], appareil.first_seen)
            groupe["last_seen"] = max(groupe["last_seen"], appareil.last_seen)
            groupe["is_local"] = groupe["is_local"] or appareil.is_local
            if appareil.hostname and not groupe["hostname"]:
                groupe["hostname"] = appareil.hostname

            for type_service, infos in appareil.services.items():
                cible = groupe["services"].get(type_service)
                if cible is None:
                    cible = {"type": type_service, "label": infos.get("label"),
                             "searched": False, "announced": False, "instances": []}
                    groupe["services"][type_service] = cible
                cible["searched"] = cible["searched"] or infos.get("searched", False)
                cible["announced"] = cible["announced"] or infos.get("announced", False)
                for instance in infos.get("instances", []):
                    if instance not in cible["instances"]:
                        cible["instances"].append(instance)

        resultats = []
        for groupe in groupes.values():
            groupe["addresses"].sort()
            groupe["ip"] = groupe["addresses"][0] if groupe["addresses"] else "?"
            groupe["services"] = sorted(groupe["services"].values(),
                                        key=lambda s: s.get("label") or "zzz")
            resultats.append(groupe)

        resultats.sort(key=lambda a: a["packets"], reverse=True)
        return resultats

    def services_snapshot(self) -> list[dict[str, Any]]:
        """Services vus sur le reseau, annonces et recherches separes.

        Les services dont le type n'est pas documente sont regroupes en une
        seule entree : ils existent bel et bien (les octets le prouvent) mais
        l'outil ne peut pas dire ce qu'ils font. Quatre lignes « service non
        documente » n'apprendraient rien et masqueraient les services
        identifiables.
        """
        documentes: list[dict[str, Any]] = []
        non_documentes: list[dict[str, Any]] = []

        for entree in self._services.values():
            element = {
                "type": entree["type"],
                "label": entree["label"],
                "instances": sorted(entree["instances"]),
                "announced": entree["announced"],
                "searched": entree["searched"],
                "actors": sorted(entree["actors"]),
                "first_seen": entree["first_seen"],
                "last_seen": entree["last_seen"],
            }
            (documentes if entree["label"] else non_documentes).append(element)

        documentes.sort(key=lambda s: (not s["announced"], s["label"]))

        if non_documentes:
            documentes.append({
                "type": "proprietaire",
                "label": None,
                "is_unlabelled": True,
                "count": len(non_documentes),
                "announced": any(s["announced"] for s in non_documentes),
                "searched": any(s["searched"] for s in non_documentes),
                "instances": sorted({i for s in non_documentes for i in s["instances"]}),
                "actors": sorted({a for s in non_documentes for a in s["actors"]}),
                "types": sorted(s["type"] for s in non_documentes),
                "first_seen": min(s["first_seen"] for s in non_documentes),
                "last_seen": max(s["last_seen"] for s in non_documentes),
            })

        return documentes

    def count(self) -> int:
        return len(self._devices)
