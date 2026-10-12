"""Tests des statistiques de capture."""

from __future__ import annotations

import pytest

from app.analysis.statistics import (
    LIBELLE_MAX,
    debit_par_seconde,
    hierarchie,
    ordre_des_tranches,
    repartition_par_taille,
    tranche_de,
)


# --------------------------------------------------------- taille -> tranche

@pytest.mark.parametrize("taille, attendu", [
    (0, "0 – 63"),
    (63, "0 – 63"),
    (64, "64 – 127"),          # la borne basse appartient a la tranche suivante
    (127, "64 – 127"),
    (128, "128 – 255"),
    (255, "128 – 255"),
    (256, "256 – 511"),
    (511, "256 – 511"),
    (512, "512 – 1023"),
    (1023, "512 – 1023"),
    (1024, "1024 – 1517"),
    (1517, "1024 – 1517"),
    (1518, LIBELLE_MAX),       # 1518 est la plus grande trame Ethernet standard
    (9000, LIBELLE_MAX),       # trame geante
])
def test_chaque_taille_tombe_dans_la_bonne_tranche(taille, attendu):
    assert tranche_de(taille) == attendu


def test_les_tranches_sont_ordonnees():
    """L'ordre d'affichage doit etre croissant, pas l'ordre d'arrivee."""
    tranches = ordre_des_tranches()
    assert tranches[0] == "0 – 63"
    assert tranches[-1] == LIBELLE_MAX
    assert len(tranches) == 7


# ------------------------------------------------------------ repartition

def test_la_repartition_garde_les_tranches_vides():
    """Retirer les tranches vides collerait les barres les unes aux autres."""
    resultat = repartition_par_taille([100, 100, 100])
    assert len(resultat) == 7
    assert [ligne["count"] for ligne in resultat] == [0, 3, 0, 0, 0, 0, 0]


def test_les_pourcentages_de_la_repartition_font_cent():
    resultat = repartition_par_taille([50, 100, 200, 1500])
    total = sum(ligne["percent"] for ligne in resultat)
    assert total == pytest.approx(100.0, abs=0.2)


def test_une_capture_vide_ne_divise_pas_par_zero():
    resultat = repartition_par_taille([])
    assert len(resultat) == 7
    assert all(ligne["percent"] == 0.0 for ligne in resultat)


# --------------------------------------------------------------- hierarchie

def test_la_hierarchie_classe_par_volume_decroissant():
    resultat = hierarchie({"TLS": 900, "DNS": 100, "QUIC": 5000})
    assert [ligne["name"] for ligne in resultat] == ["QUIC", "TLS", "DNS"]
    assert resultat[0]["percent"] == pytest.approx(83.3, abs=0.1)


def test_la_hierarchie_regroupe_au_dela_de_la_limite():
    """Sans regroupement, la somme des pourcentages affiches ne ferait plus
    100 % et l'utilisateur croirait a une erreur de calcul."""
    octets = {f"P{i}": (20 - i) * 100 for i in range(15)}
    resultat = hierarchie(octets, limite=10)

    assert len(resultat) == 11                  # 10 gardes + « autres »
    assert resultat[-1]["name"].startswith("autres (")
    assert sum(ligne["percent"] for ligne in resultat) == pytest.approx(100.0, abs=0.2)


def test_la_hierarchie_ignore_les_protocoles_a_zero():
    resultat = hierarchie({"TLS": 100, "Protocole inconnu": 0})
    assert [ligne["name"] for ligne in resultat] == ["TLS"]


def test_la_hierarchie_vide_ne_plante_pas():
    assert hierarchie({}) == []
    assert hierarchie({"TLS": 0}) == []


# ------------------------------------------------------------------- debit

def test_le_debit_ne_divise_pas_par_zero():
    assert debit_par_seconde(500, 0) == 0.0
    assert debit_par_seconde(500, -1) == 0.0
    assert debit_par_seconde(500, 2) == 250.0
