"""Tests de la reconstitution d'une conversation (« Follow TCP Stream »).

Ce qui est verifie ici n'est pas le confort, c'est la JUSTESSE : un texte
reconstitue dans le desordre, ou avec des octets manquants recolles
silencieusement, est pire qu'une absence de reconstitution — il a l'air vrai.
"""

from __future__ import annotations

import pytest

from app.config import Settings
from app.engine import AnalyzerEngine, _decoder
from app.web.app import create_app

assembler = AnalyzerEngine._assembler


@pytest.fixture
def client(tmp_path):
    """Client en mode local : la reconstitution lit les paquets du moteur."""
    from fastapi.testclient import TestClient

    reglages = Settings(env="test", mode="local", secret_key="x" * 48,
                        sqlite_path=tmp_path / "stream.db", enrich_enabled=False)
    with TestClient(create_app(reglages)) as test_client:
        yield test_client


class FauxFlux:
    key = "tcp:192.168.1.10:50000-93.184.216.34:80"
    first_seen = 1000.0


def segments(*paires, ts=1000.0, flags="A"):
    """(numero de sequence, contenu) -> segments tels que produits par le moteur."""
    return [{"seq": seq, "donnees": donnees, "ts": ts, "flags": flags, "number": i}
            for i, (seq, donnees) in enumerate(paires)]


# ------------------------------------------------------------------ decodage

def test_le_texte_lisible_est_reconnu():
    texte, est_texte = _decoder(b"GET / HTTP/1.1\r\nHost: exemple.fr\r\n\r\n")
    assert est_texte is True
    assert texte.startswith("GET /")


def test_un_contenu_chiffre_n_est_pas_presente_comme_du_texte():
    """Un contenu binaire decode de force produit des caracteres de
    remplacement : l'afficher comme du texte ferait croire a un bug."""
    binaire = bytes(range(256)) * 8
    texte, est_texte = _decoder(binaire)
    assert est_texte is False
    assert texte == ""


def test_un_texte_accentue_reste_du_texte():
    texte, est_texte = _decoder("Café crème — naïve".encode("utf-8"))
    assert est_texte is True
    assert "Café" in texte


def test_un_contenu_vide_est_considere_comme_du_texte():
    assert _decoder(b"") == ("", True)


# ------------------------------------------------------------------- ordre

def test_les_segments_sont_remis_dans_l_ordre_des_octets():
    """L'ordre d'arrivee n'est pas l'ordre du contenu : sur un reseau charge,
    les paquets arrivent desordonnes.

    Les numeros de sequence sont CONTIGUS (1000, 1008, 1011), sinon la
    reconstitution signalerait a juste titre des octets manquants.
    """
    sens = {"aller": segments((1011, b"monde"), (1000, b"bonjour "), (1008, b"le ")),
            "retour": []}
    resultat = assembler(FauxFlux, sens, 200_000)

    assert resultat["sens"][0]["texte"] == "bonjour le monde"
    assert resultat["trous"] == 0


def test_les_deux_sens_sont_separes():
    sens = {"aller": segments((1, b"question")),
            "retour": segments((1, b"reponse"))}
    resultat = assembler(FauxFlux, sens, 200_000)

    directions = [s["direction"] for s in resultat["sens"]]
    assert directions == ["aller", "retour"]
    assert resultat["sens"][0]["texte"] == "question"
    assert resultat["sens"][1]["texte"] == "reponse"


def test_les_retransmissions_ne_dupliquent_pas_le_texte():
    """Une retransmission porte le meme numero de sequence : la compter deux
    fois doublerait le texte."""
    sens = {"aller": segments((1000, b"identique"), (1000, b"identique")),
            "retour": []}
    resultat = assembler(FauxFlux, sens, 200_000)

    assert resultat["sens"][0]["texte"] == "identique"
    assert resultat["sens"][0]["segments"] == 1


# -------------------------------------------------------------------- trous

def test_un_trou_est_signale_et_non_comble():
    """Recoller les morceaux sans le dire produirait un texte continu qui n'a
    jamais circule tel quel."""
    sens = {"aller": segments((1000, b"debut"), (5000, b"fin")), "retour": []}
    resultat = assembler(FauxFlux, sens, 200_000)

    texte = resultat["sens"][0]["texte"]
    assert "octets manquants" in texte
    assert resultat["trous"] == 1
    assert resultat["note"] is not None
    assert "manquent" in resultat["note"]


def test_des_segments_contigus_ne_produisent_aucun_trou():
    sens = {"aller": segments((1000, b"abc"), (1003, b"def"), (1006, b"ghi")),
            "retour": []}
    resultat = assembler(FauxFlux, sens, 200_000)

    assert resultat["trous"] == 0
    assert resultat["sens"][0]["texte"] == "abcdefghi"


def test_les_paquets_sans_charge_utile_ne_comptent_pas_comme_un_trou():
    """Un ACK sans donnees a un numero de sequence, mais n'apporte aucun octet :
    le signaler comme un trou serait une fausse alerte."""
    sens = {"aller": segments((1000, b"abc"), (1003, b"")), "retour": []}
    resultat = assembler(FauxFlux, sens, 200_000)

    # Le segment vide est adjacent, il n'y a pas de trou.
    assert resultat["trous"] == 0


# ------------------------------------------------------------- reserve claire

def test_un_contenu_chiffre_produit_une_reserve_explicite():
    sens = {"aller": [{"seq": 1, "donnees": bytes(range(256)) * 4,
                       "ts": 0.0, "number": 1}], "retour": []}
    resultat = assembler(FauxFlux, sens, 200_000)

    assert resultat["chiffre"] is True
    assert resultat["note"] is not None
    assert "chiffré" in resultat["note"]
    assert resultat["sens"][0]["texte"] is None
    assert resultat["sens"][0]["binaire"] is True


def test_un_sens_sans_paquet_n_apparait_pas():
    resultat = assembler(FauxFlux, {"aller": [], "retour": []}, 200_000)
    assert resultat["sens"] == []


def test_un_sens_de_pure_signalisation_est_signale_comme_tel():
    """Un sens peut ne porter que des SYN et des ACK : l'afficher comme un bloc
    vide laisserait croire a une reconstitution ratee."""
    sens = {"aller": [{"seq": 1000, "donnees": b"", "ts": 1000.0,
                       "flags": "S", "number": 1}], "retour": []}
    resultat = assembler(FauxFlux, sens, 200_000)

    assert resultat["sens"][0]["sans_contenu"] is True
    assert resultat["sens"][0]["octets"] == 0
    assert resultat["trous"] == 0


def test_l_ouverture_et_la_fermeture_ne_creent_pas_de_faux_trou():
    """Le SYN et le FIN consomment un numero de sequence sans transporter
    d'octet : les ignorer ferait apparaitre un faux trou d'un octet dans toute
    conversation dont on a vu l'ouverture."""
    sens = {"aller": [
        {"seq": 1000, "donnees": b"", "ts": 1000.0, "flags": "S", "number": 1},
        {"seq": 1001, "donnees": b"bonjour", "ts": 1000.1, "flags": "PA", "number": 2},
        {"seq": 1008, "donnees": b"", "ts": 1000.2, "flags": "FA", "number": 3},
    ], "retour": []}
    resultat = assembler(FauxFlux, sens, 200_000)

    assert resultat["trous"] == 0
    assert resultat["sens"][0]["texte"] == "bonjour"


def test_un_debut_manquant_est_signale():
    """Le moteur ne garde que les derniers paquets : sans cet avertissement,
    l'utilisateur croirait lire l'echange depuis son debut."""
    # Le flux a commence a 1000 s, mais les premiers segments encore en memoire
    # datent de 1060 s : il manque une minute.
    sens = {"aller": segments((1000, b"suite"), ts=1060.0), "retour": []}
    resultat = assembler(FauxFlux, sens, 200_000)

    assert resultat["debut_manquant"] is True
    assert "début" in resultat["note"]


def test_un_debut_present_n_est_pas_signale():
    sens = {"aller": segments((1000, b"depuis le debut"), ts=1000.5), "retour": []}
    resultat = assembler(FauxFlux, sens, 200_000)

    assert resultat["debut_manquant"] is False


# ------------------------------------------------------- limite de volume

def test_le_contenu_est_borne_et_le_dit():
    gros = [{"seq": i * 1000, "donnees": b"x" * 1000, "ts": 0.0, "number": i}
            for i in range(400)]
    resultat = assembler(FauxFlux, {"aller": gros, "retour": []}, 5000)

    assert "tronquee" in resultat["sens"][0]["texte"]
    assert resultat["sens"][0]["octets"] < 20_000


# ------------------------------------------------------------------- routes

def test_la_route_refuse_une_communication_non_designee(client):
    reponse = client.get("/api/stream", params={"key": ""})
    assert reponse.status_code == 400
    assert reponse.json()["ok"] is False


def test_la_route_signale_une_communication_inconnue(client):
    reponse = client.get("/api/stream", params={"key": "tcp:1.2.3.4:1-5.6.7.8:2"})
    assert reponse.status_code == 404
    assert "existe plus" in reponse.json()["error"]
