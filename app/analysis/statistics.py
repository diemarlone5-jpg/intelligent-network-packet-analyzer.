"""Statistiques de capture : repartition par taille et hierarchie des protocoles.

POURQUOI CE MODULE

Ces deux vues repondent a des questions que les compteurs bruts ne permettent
pas de trancher :

- La repartition par taille dit si le reseau transporte des petites trames de
  signalisation ou de gros transferts. Un lien sature par des paquets de 1500
  octets ne se diagnostique pas comme un lien sature par des milliers de petites
  trames : ce sont deux problemes differents.
- La hierarchie par VOLUME dit ce qui occupe reellement le reseau. Un protocole
  peut etre minoritaire en nombre de paquets et majoritaire en octets (un
  transfert de fichier), ou l'inverse (une boucle de signalisation). Compter les
  paquets ne suffit pas a repondre a « qu'est-ce qui sature ma connexion ? ».

Tout ici est du calcul pur : aucune de ces fonctions ne devine, et aucune ne
qualifie ce qu'elle mesure d'anormal.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

# Bornes hautes des tranches, dans l'ordre. Les valeurs suivent les seuils
# classiques de l'analyse reseau : 64 octets est la plus petite trame Ethernet,
# 1518 la plus grande trame Ethernet standard (sans les extensions recentes).
TRANCHES: tuple[tuple[int, str], ...] = (
    (64, "0 – 63"),
    (128, "64 – 127"),
    (256, "128 – 255"),
    (512, "256 – 511"),
    (1024, "512 – 1023"),
    (1518, "1024 – 1517"),
)
LIBELLE_MAX = "1518 et plus"


def tranche_de(taille: int) -> str:
    """Tranche a laquelle appartient une taille de paquet."""
    for borne, libelle in TRANCHES:
        if taille < borne:
            return libelle
    return LIBELLE_MAX


def ordre_des_tranches() -> list[str]:
    """Toutes les tranches possibles, de la plus petite a la plus grande.

    On les parcourt dans cet ordre a l'affichage : une liste tiree du compteur
    apparaitrait dans l'ordre d'arrivee des paquets, ce qui rendrait le
    graphique illisible.
    """
    return [libelle for _, libelle in TRANCHES] + [LIBELLE_MAX]


def repartition_par_taille(tailles: Iterable[int]) -> list[dict]:
    """Compte les paquets par tranche de taille, tranches vides comprises.

    On conserve les tranches vides : les retirer ferait glisser les barres les
    unes vers les autres et laisserait croire a une continuite qui n'existe pas.
    """
    comptes: dict[str, int] = {libelle: 0 for libelle in ordre_des_tranches()}
    total = 0
    for taille in tailles:
        comptes[tranche_de(taille)] += 1
        total += 1

    return [
        {
            "label": libelle,
            "count": comptes[libelle],
            "percent": round(comptes[libelle] * 100.0 / total, 1) if total else 0.0,
        }
        for libelle in ordre_des_tranches()
    ]


def repartition_depuis_comptes(comptes: Mapping[str, int]) -> list[dict]:
    """Meme resultat que repartition_par_taille, a partir de comptes deja faits.

    Le moteur tient des compteurs incrementaux : reparcourir toute la capture a
    chaque affichage couterait cher des que la capture devient longue.
    """
    total = sum(comptes.values())
    return [
        {
            "label": libelle,
            "count": comptes.get(libelle, 0),
            "percent": round(comptes.get(libelle, 0) * 100.0 / total, 1) if total else 0.0,
        }
        for libelle in ordre_des_tranches()
    ]


def hierarchie(octets_par_protocole: Mapping[str, int],
               limite: int = 10) -> list[dict]:
    """Hierarchie des protocoles par volume, avec pourcentage du total.

    Le pourcentage porte sur les octets, pas sur les paquets : c'est la question
    « qu'est-ce qui occupe le reseau » a laquelle on repond ici.

    Les protocoles au-dela de la limite sont regroupes sous « autres » plutot
    que supprimes : sinon la somme des pourcentages affiches ne ferait plus 100 %
    et l'utilisateur croirait a une erreur de calcul.
    """
    elements = [(nom, valeur) for nom, valeur in octets_par_protocole.items() if valeur > 0]
    elements.sort(key=lambda paire: (-paire[1], paire[0]))

    total = sum(valeur for _, valeur in elements)
    if not total:
        return []

    gardes = elements[:limite]
    restants = elements[limite:]

    resultat = [
        {
            "name": nom,
            "bytes": valeur,
            "percent": round(valeur * 100.0 / total, 1),
        }
        for nom, valeur in gardes
    ]

    if restants:
        valeur = sum(octets for _, octets in restants)
        resultat.append({
            "name": "autres (%d)" % len(restants),
            "bytes": valeur,
            "percent": round(valeur * 100.0 / total, 1),
        })

    return resultat


def debit_par_seconde(octets: int, secondes: float) -> float:
    """Debit en octets par seconde. Sert uniquement a l'affichage."""
    if secondes <= 0:
        return 0.0
    return octets / secondes
