"""Dissection detaillee d'un paquet : couches et contenu brut.

C'est ce qui separe un simple tableau d'un veritable outil d'analyse. Dans
Wireshark, cliquer sur un paquet ouvre deux panneaux :

    - l'arbre des protocoles empiles (Ethernet > IP > TCP > TLS), champ par
      champ, avec la valeur de chacun ;
    - le contenu brut en hexadecimal et en ASCII, aligne sur 16 octets.

Ce module produit exactement ces deux vues a partir des octets reellement
captures. Il ne conserve rien et ne conclut rien : il montre.

Aucune exception ne doit remonter : un paquet exotique ou tronque doit produire
une vue partielle, pas une page en erreur.
"""

from __future__ import annotations

import string
from typing import Any

# Octets imprimables pour la colonne ASCII du vidage hexadecimal
_PRINTABLE = set(bytes(string.printable, "ascii")) - set(b"\t\n\r\x0b\x0c")

# Champs dont l'affichage brut est illisible : on les presente en hexadecimal
_BYTES_FIELDS = {"load", "options", "payload", "data"}


def _format_value(value: Any) -> str:
    """Rend une valeur de champ lisible, quelle que soit sa nature."""
    if value is None:
        return "—"
    if isinstance(value, (bytes, bytearray)):
        if not value:
            return "(vide)"
        apercu = value[:24].hex(" ")
        if len(value) > 24:
            return f"{apercu} … ({len(value)} octets)"
        return f"{apercu} ({len(value)} octets)"
    if isinstance(value, (list, tuple)):
        if not value:
            return "[]"
        elements = [_format_value(item) for item in value[:6]]
        texte = ", ".join(elements)
        return f"[{texte}{' …' if len(value) > 6 else ''}]"
    if isinstance(value, bool):
        return "oui" if value else "non"
    return str(value)


def dissect(raw: bytes) -> dict[str, Any]:
    """Decoupe un paquet brut en couches, chacune avec ses champs.

    Retourne :
        {
          "layers": [ {"name": ..., "summary": ..., "fields": [...]}, ... ],
          "hex":    [ {"offset": ..., "hex": ..., "ascii": ...}, ... ],
          "size":   nombre d'octets,
          "error":  message eventuel
        }
    """
    resultat: dict[str, Any] = {"layers": [], "hex": [], "size": len(raw or b""), "error": None}

    if not raw:
        resultat["error"] = "Les octets de ce paquet ne sont plus disponibles."
        return resultat

    resultat["hex"] = hex_dump(raw)

    try:
        from scapy.layers.l2 import Ether
        from scapy.packet import NoPayload

        packet = Ether(raw)
        couche = packet
        profondeur = 0

        while couche is not None and profondeur < 16:
            nom_classe = couche.__class__.__name__
            if isinstance(couche, NoPayload) or nom_classe == "NoPayload":
                break

            champs: list[dict[str, str]] = []
            try:
                for champ in couche.fields_desc:
                    try:
                        valeur = couche.getfieldval(champ.name)
                    except Exception:
                        continue
                    champs.append({
                        "name": champ.name,
                        "label": _label_for(nom_classe, champ.name),
                        "value": _format_value(valeur),
                    })
            except Exception:
                champs = []

            # La charge utile brute n'est pas un "champ" au sens de Scapy :
            # on l'ajoute pour montrer ce qui n'a pas ete disséque plus haut.
            if nom_classe in ("Raw",) and not champs:
                charge = bytes(couche)
                champs.append({
                    "name": "load",
                    "label": "Donnees brutes",
                    "value": _format_value(charge),
                })

            try:
                resume = couche.summary()
            except Exception:
                resume = nom_classe

            resultat["layers"].append({
                "name": nom_classe,
                "summary": resume,
                "fields": champs,
            })

            suivant = couche.payload
            if suivant is None or suivant.__class__.__name__ == "NoPayload":
                break
            couche = suivant
            profondeur += 1

    except Exception as exc:
        resultat["error"] = (
            f"Ce paquet n'a pas pu etre disséque entierement ({type(exc).__name__}). "
            "Le contenu brut ci-dessous reste exact."
        )

    return resultat


def _label_for(layer: str, field: str) -> str:
    """Traduit un nom de champ technique en libelle comprehensible.

    Le nom brut reste affiche en petit : l'utilisateur doit pouvoir faire le
    lien avec la documentation du protocole.
    """
    traductions = {
        ("Ether", "dst"): "Adresse materielle de destination",
        ("Ether", "src"): "Adresse materielle source",
        ("Ether", "type"): "Type de protocole encapsule",
        ("IP", "version"): "Version du protocole Internet",
        ("IP", "ihl"): "Longueur de l'en-tete (en mots de 32 bits)",
        ("IP", "tos"): "Type de service",
        ("IP", "len"): "Longueur totale annoncee",
        ("IP", "id"): "Identifiant du paquet",
        ("IP", "flags"): "Drapeaux de fragmentation",
        ("IP", "frag"): "Position dans la fragmentation",
        ("IP", "ttl"): "Duree de vie restante (nombre de routeurs franchissables)",
        ("IP", "proto"): "Protocole transporte",
        ("IP", "chksum"): "Somme de controle de l'en-tete",
        ("IP", "src"): "Adresse IP source",
        ("IP", "dst"): "Adresse IP de destination",
        ("TCP", "sport"): "Port source",
        ("TCP", "dport"): "Port de destination",
        ("TCP", "seq"): "Numero de sequence",
        ("TCP", "ack"): "Numero d'accuse de reception",
        ("TCP", "dataofs"): "Taille de l'en-tete TCP",
        ("TCP", "flags"): "Drapeaux de controle",
        ("TCP", "window"): "Taille de la fenetre de reception",
        ("TCP", "chksum"): "Somme de controle",
        ("UDP", "sport"): "Port source",
        ("UDP", "dport"): "Port de destination",
        ("UDP", "len"): "Longueur du datagramme",
        ("UDP", "chksum"): "Somme de controle",
        ("ICMP", "type"): "Type de message",
        ("ICMP", "code"): "Code de precision",
        ("DNS", "id"): "Identifiant de la transaction",
        ("DNS", "qr"): "Question (0) ou reponse (1)",
        ("DNS", "qd"): "Question posee",
        ("DNS", "an"): "Enregistrements de reponse",
        ("ARP", "op"): "Operation (1 = question, 2 = reponse)",
        ("ARP", "psrc"): "Adresse IP de l'emetteur",
        ("ARP", "pdst"): "Adresse IP recherchee",
        ("ARP", "hwsrc"): "Adresse materielle de l'emetteur",
        ("IPv6", "src"): "Adresse IPv6 source",
        ("IPv6", "dst"): "Adresse IPv6 de destination",
        ("IPv6", "hlim"): "Limite de sauts restante",
        ("IPv6", "nh"): "Protocole encapsule",
    }
    return traductions.get((layer, field), field)


def hex_dump(raw: bytes, largeur: int = 16, limite: int = 1024) -> list[dict[str, str]]:
    """Vidage hexadecimal et ASCII, comme le panneau bas de Wireshark.

    `limite` borne le nombre d'octets affiches : au-dela, la vue n'apporte plus
    rien a l'analyse et surchargerait le navigateur.
    """
    lignes: list[dict[str, str]] = []
    donnees = raw[:limite]

    for position in range(0, len(donnees), largeur):
        bloc = donnees[position:position + largeur]

        # Groupe de 8 octets separes pour faciliter la lecture
        gauche = " ".join(f"{octet:02x}" for octet in bloc[:8])
        droite = " ".join(f"{octet:02x}" for octet in bloc[8:])

        ascii_ligne = "".join(
            chr(octet) if octet in _PRINTABLE else "." for octet in bloc
        )

        lignes.append({
            "offset": f"{position:04x}",
            "hex": f"{gauche:<23} {droite:<23}",
            "ascii": ascii_ligne,
        })

    if len(raw) > limite:
        lignes.append({
            "offset": "…",
            "hex": f"({len(raw) - limite} octets supplementaires non affiches)",
            "ascii": "",
        })
    return lignes
