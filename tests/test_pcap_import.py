"""Tests de l'import d'un fichier PCAP (ouverture d'une capture enregistree).

Le point important : un fichier etranger arrive du dehors. Il doit etre refuse
avec un message clair s'il est illisible, et ne jamais faire tomber le serveur.
Un fichier abime ne doit pas non plus empecher l'analyse des trames valides.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from app.analysis.pcap import Enregistrement, ecrire_pcap
from app.config import Settings
from app.web.app import create_app


@pytest.fixture
def client(tmp_path):
    """Client en mode LOCAL : l'import d'un fichier ecrit dans le moteur, et le
    mode consultation est justement en lecture seule (voir le test dedie)."""
    reglages = Settings(
        env="test",
        mode="local",
        secret_key="x" * 48,
        sqlite_path=tmp_path / "import.db",
        enrich_enabled=False,
        supabase_enabled=False,
        ai_enabled=False,
    )
    with TestClient(create_app(reglages)) as test_client:
        yield test_client


def get_csrf(client) -> str:
    page = client.get("/packets").text
    trouve = re.search(r'name="csrf-token" content="([^"]+)"', page)
    assert trouve, "jeton CSRF absent de la page"
    return trouve.group(1)


def trame(payload: bytes = b"salut") -> bytes:
    """Trame Ethernet minimale credible (EtherType IPv4 + en-tete IP)."""
    return (b"\x94\x08\x53\x96\x90\x9b" b"\x02\x95\x89\xb7\x46\xc0" b"\x08\x00"
            b"\x45\x00\x00\x14\x00\x00\x00\x00\x40\x06\x00\x00"
            b"\xc0\xa8\x01\x0a" b"\x08\x08\x08\x08" + payload)


def pcap_de(nombre: int) -> bytes:
    return ecrire_pcap([
        Enregistrement(ts=1759000000.0 + i, donnees=trame(bytes([65 + i])))
        for i in range(nombre)
    ])


def envoyer(client, contenu: bytes):
    jeton = get_csrf(client)
    return client.post("/api/pcap/open", content=contenu,
                       headers={"X-CSRF-Token": jeton,
                                "Content-Type": "application/octet-stream"})


# ------------------------------------------------------------------ nominal

def test_un_fichier_valide_est_analyse(client):
    reponse = envoyer(client, pcap_de(5))
    assert reponse.status_code == 200
    corps = reponse.json()
    assert corps["ok"] is True
    assert corps["read"] == 5
    assert corps["loaded"] == 5
    assert corps["unreadable"] == 0
    assert corps["link_type_label"] == "Ethernet"


def test_les_paquets_importes_sont_visibles_ensuite(client):
    """Importer ne sert a rien si la liste reste vide."""
    envoyer(client, pcap_de(4))
    donnees = client.get("/api/packets?limit=100").json()
    assert len(donnees["packets"]) == 4
    assert client.get("/api/stats").json()["packets"] == 4


def test_les_statistiques_suivent_le_fichier_importe(client):
    """Le fichier doit alimenter les memes compteurs qu'une capture en direct."""
    envoyer(client, pcap_de(3))
    stats = client.get("/api/stats").json()
    total_tranches = sum(t["count"] for t in stats["size_distribution"])
    assert total_tranches == 3


def test_l_horodatage_du_fichier_est_conserve(client):
    """Sinon la chronologie du fichier serait remplacee par l'heure d'import."""
    contenu = ecrire_pcap([Enregistrement(ts=1759000000.0, donnees=trame())])
    envoyer(client, contenu)
    paquets = client.get("/api/packets").json()["packets"]
    assert paquets
    assert paquets[0]["ts"] == pytest.approx(1759000000.0, abs=1.0)


def test_un_second_import_remplace_le_premier(client):
    """Melanger deux fichiers donnerait une liste ou l'on ne saurait plus ce
    qui vient d'ou."""
    envoyer(client, pcap_de(6))
    envoyer(client, pcap_de(2))
    assert client.get("/api/stats").json()["packets"] == 2


# --------------------------------------------------------------- refus net

def test_un_fichier_vide_est_refuse(client):
    reponse = envoyer(client, b"")
    assert reponse.status_code == 400
    assert "Aucun fichier" in reponse.json()["error"]


def test_un_fichier_etranger_est_refuse_avec_un_message(client):
    reponse = envoyer(client, b"ceci n'est pas un fichier pcap" * 4)
    assert reponse.status_code == 400
    assert reponse.json()["ok"] is False
    assert "PCAP" in reponse.json()["error"]


def test_un_fichier_tronque_est_refuse(client):
    reponse = envoyer(client, pcap_de(3)[:-9])
    assert reponse.status_code == 400
    assert "tronqu" in reponse.json()["error"]


def test_un_fichier_sans_paquet_est_refuse(client):
    reponse = envoyer(client, ecrire_pcap([]))
    assert reponse.status_code == 400
    assert "aucun paquet" in reponse.json()["error"].lower()


def test_un_fichier_pcapng_est_signale(client):
    """PCAPNG est le format recent de Wireshark : le dire clairement vaut mieux
    qu'un « format invalide » qui laisserait l'utilisateur chercher."""
    contenu = b"\x0a\x0d\x0d\x0a" + b"\x00" * 40
    reponse = envoyer(client, contenu)
    assert reponse.status_code == 400
    assert "PCAPNG" in reponse.json()["error"]


# ------------------------------------------------------------ sans le jeton

def test_l_import_exige_le_jeton_de_securite(client):
    reponse = client.post("/api/pcap/open", content=pcap_de(2))
    assert reponse.status_code == 400
    assert "Jeton de securite" in reponse.json()["error"]


def test_l_import_est_refuse_en_mode_consultation(tmp_path):
    """Une instance hebergee est en lecture seule : laisser un visiteur
    remplacer l'etat du moteur serait une atteinte a l'integrite des donnees."""
    from fastapi.testclient import TestClient

    from app.config import Settings
    from app.web.app import create_app

    reglages = Settings(env="test", mode="cloud", secret_key="x" * 48,
                        sqlite_path=tmp_path / "cloud.db", enrich_enabled=False)
    with TestClient(create_app(reglages)) as client_cloud:
        jeton = get_csrf(client_cloud)
        reponse = client_cloud.post(
            "/api/pcap/open", content=pcap_de(2),
            headers={"X-CSRF-Token": jeton,
                     "Content-Type": "application/octet-stream"})
        # 409 : l'application signale deja ce cas ainsi (« action impossible
        # dans ce mode »), on s'aligne sur sa convention.
        assert reponse.status_code == 409
        assert reponse.json()["ok"] is False
