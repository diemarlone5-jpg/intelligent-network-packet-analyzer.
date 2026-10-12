"""Lecture et ecriture de fichiers PCAP (le format que Wireshark ouvre).

POURQUOI CE MODULE

Le cahier des charges demande de pouvoir confronter ce que l'application
affirme avec une reference reconnue. Un fichier PCAP est cette passerelle : on
exporte la capture, on l'ouvre dans Wireshark, et on compare paquet par paquet.
Sans export, l'utilisateur est oblige de croire l'application sur parole.

FORMAT (RFC « pcap », celui de libpcap)

En-tete global, 24 octets :
    magic (4) | version majeure (2) | mineure (2) | fuseau (4) | sigfigs (4)
    | longueur max capturee (4) | type de lien (4)

Puis, pour chaque paquet :
    secondes (4) | microsecondes (4) | longueur conservee (4)
    | longueur d'origine (4) | les octets

Le magic dit aussi l'ordre des octets : 0xa1b2c3d4 en gros-boutiste,
0xd4c3b2a1 en petit-boutiste. Les variantes en nanosecondes existent
(0xa1b23c4d / 0x4d3cb2a1) : on sait les lire.

TYPE DE LIEN

Le premier enregistrement ne commence pas au meme endroit selon l'interface
capturee : par une en-tete Ethernet (14 octets) sur une carte reseau, ou
directement par l'en-tete IP sur une interface « brut » (loopback Linux). Se
tromper de type de lien donne un fichier que Wireshark ouvre... en affichant
n'importe quoi. On le deduit donc du contenu, pas d'une supposition.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timezone

# Types de lien (valeurs normalisees par libpcap).
LINKTYPE_ETHERNET = 1
LINKTYPE_IP = 101           # « raw IP » : pas d'en-tete Ethernet

# Magic du format. La VALEUR est toujours 0xA1B2C3D4 ; c'est son ecriture qui
# dit l'ordre des octets du fichier.
#   fichier petit-boutiste -> octets D4 C3 B2 A1
#   fichier gros-boutiste  -> octets A1 B2 C3 D4
# Relu en petit-boutiste, le magic vaut donc 0xA1B2C3D4 pour un fichier
# petit-boutiste, et 0xD4C3B2A1 pour un fichier gros-boutiste. Inverser ces
# deux valeurs produit un fichier dont l'en-tete annonce un ordre et dont le
# contenu en utilise un autre : Wireshark l'ouvre alors en affichant
# n'importe quoi.
_MAGIC_MICRO = 0xA1B2C3D4
_MAGIC_NANO = 0xA1B23C4D

# Types d'EtherType qui confirment une en-tete Ethernet.
_ETHERTYPES = {0x0800, 0x86DD, 0x0806, 0x8100, 0x88CC, 0x8847}

LONGUEUR_MAX = 65535


class PcapErreur(ValueError):
    """Fichier illisible ou tronque."""


@dataclass(frozen=True)
class Enregistrement:
    """Un paquet tel qu'il figure dans le fichier.

    taille_origine vaut 0 quand elle n'est pas fournie : elle est alors deduite
    de la longueur des octets. C'est le cas courant, et obliger l'appelant a la
    calculer lui-meme l'aurait pousse a se tromper.
    """

    ts: float               # instant, en secondes depuis l'epoque UNIX
    donnees: bytes          # octets conserves
    taille_origine: int = 0  # taille sur le fil (0 = deduire des octets)


# ------------------------------------------------------------------ ecriture

def deviner_type_lien(paquets: list[bytes]) -> int:
    """Deduit le type de lien du contenu, pas d'une supposition.

    On cherche une en-tete Ethernet credible : le champ EtherType, a l'offset
    12, vaut une valeur connue. Si aucun paquet ne le confirme, on considere
    qu'il s'agit d'IP brut.
    """
    for donnees in paquets:
        if len(donnees) >= 14:
            ethertype = struct.unpack("!H", donnees[12:14])[0]
            if ethertype in _ETHERTYPES:
                return LINKTYPE_ETHERNET
    return LINKTYPE_IP


def ecrire_pcap(enregistrements: list[Enregistrement],
                type_lien: int | None = None) -> bytes:
    """Construit un fichier PCAP complet, en petit-boutiste.

    L'ordre petit-boutiste est celui que produisent les systemes courants ; il
    est lu par toutes les versions de Wireshark.
    """
    if type_lien is None:
        type_lien = deviner_type_lien([e.donnees for e in enregistrements[:200]])

    morceaux = [struct.pack("<IHHiIII",
                            _MAGIC_MICRO,      # magic (dit l'ordre des octets)
                            2, 4,              # version 2.4
                            0,                 # fuseau : on stocke en UTC
                            0,                 # sigfigs, inutilise
                            LONGUEUR_MAX,      # longueur max capturee
                            type_lien)]

    for enregistrement in enregistrements:
        secondes = int(enregistrement.ts)
        microsecondes = int(round((enregistrement.ts - secondes) * 1_000_000))
        # Un arrondi peut atteindre la seconde suivante : on corrige, sinon le
        # fichier contient un instant invalide.
        if microsecondes >= 1_000_000:
            secondes += 1
            microsecondes -= 1_000_000
        elif microsecondes < 0:
            microsecondes = 0

        donnees = enregistrement.donnees
        origine = max(enregistrement.taille_origine or len(donnees), len(donnees))
        morceaux.append(struct.pack("<IIII", secondes, microsecondes,
                                    len(donnees), origine))
        morceaux.append(donnees)

    return b"".join(morceaux)


# ------------------------------------------------------------------- lecture

def lire_pcap(donnees: bytes) -> tuple[int, list[Enregistrement]]:
    """Lit un fichier PCAP et retourne (type de lien, enregistrements).

    Leve PcapErreur avec un message comprehensible si le fichier est etranger
    au format ou s'il est tronque : un echec silencieux ferait croire a un
    fichier vide.
    """
    if len(donnees) < 24:
        raise PcapErreur("Fichier trop court pour être un fichier PCAP "
                         "(moins de 24 octets).")

    magic = struct.unpack("<I", donnees[:4])[0]
    if magic == _MAGIC_MICRO:
        ordre, echelle = "<", 1_000_000
    elif magic == 0xD4C3B2A1:
        ordre, echelle = ">", 1_000_000
    elif magic == _MAGIC_NANO:
        ordre, echelle = "<", 1_000_000_000
    elif magic == 0x4D3CB2A1:
        ordre, echelle = ">", 1_000_000_000
    else:
        raise PcapErreur(
            "Ce fichier n'est pas au format PCAP. S'il s'agit d'un fichier "
            "PCAPNG (le format récent de Wireshark), il n'est pas encore "
            "accepté."
        )

    # Certains fichiers issus d'appareils embarques sont en PCAPNG : on le
    # detecte pour donner un message utile plutot qu'un « magic invalide ».
    if donnees[4:8] == b"\r\n\x1a\n" or magic == 0x0A1A2B3C:
        raise PcapErreur("Ce fichier est au format PCAPNG, pas PCAP classique.")

    _, _, _, _, _, _, type_lien = struct.unpack(ordre + "IHHiIII", donnees[:24])

    enregistrements: list[Enregistrement] = []
    position = 24
    total = len(donnees)

    while position < total:
        if position + 16 > total:
            raise PcapErreur("Fichier tronqué : il s'arrête au milieu d'un "
                             "en-tête de paquet.")
        secondes, fraction, conservee, origine = struct.unpack(
            ordre + "IIII", donnees[position:position + 16])
        position += 16

        if position + conservee > total:
            raise PcapErreur("Fichier tronqué : il manque les octets du "
                             f"paquet n° {len(enregistrements) + 1}.")

        octets = donnees[position:position + conservee]
        position += conservee
        enregistrements.append(Enregistrement(
            ts=secondes + fraction / echelle,
            donnees=octets,
            taille_origine=origine or conservee,
        ))

    return type_lien, enregistrements


def horodatage_lisible(ts: float) -> str:
    """Instant en texte, en UTC : le format reste comparable d'une machine a
    l'autre, ce qu'une heure locale ne garantit pas."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
