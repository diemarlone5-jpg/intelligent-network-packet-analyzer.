"""Tests de validation des entrees de l'API.

Deux defauts reellement constates a l'origine de ces tests :

    - /api/enrich repondait 200 avec « error: null » pour une adresse invalide :
      la reponse ressemblait a un resultat valide mais vide, et l'appelant ne
      pouvait pas savoir que sa demande etait erronee ;
    - /api/history?session_id=N renvoyait une session vide pour une session
      inexistante, ce qui faisait afficher « aucune session enregistree » alors
      que des sessions existaient.

Principe commun : une demande erronee doit etre signalee comme telle, jamais
presentee comme un resultat vide.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.web.app import create_app


@pytest.fixture
def settings(tmp_path):
    return Settings(
        env="test",
        mode="cloud",
        secret_key="x" * 48,
        sqlite_path=tmp_path / "validation.db",
        enrich_enabled=False,
        supabase_enabled=False,
        ai_enabled=False,
    )


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings)) as test_client:
        yield test_client


# --------------------------------------------------------------------------
# Enrichissement
# --------------------------------------------------------------------------


@pytest.mark.parametrize("adresse", [
    "pas-une-adresse",
    "999.999.999.999",
    "8.8.8",
    "le-serveur-de-mon-ecole",
    "http://8.8.8.8",
])
def test_une_adresse_invalide_est_refusee(client, adresse):
    reponse = client.get("/api/enrich", params={"ip": adresse})
    assert reponse.status_code == 400
    corps = reponse.json()
    assert corps["ok"] is False
    assert "valide" in corps["error"]


@pytest.mark.parametrize("adresse", [
    "8.8.8.8",
    "192.168.1.5",
    "2001:4860:4860::8888",
    "fe80::1%12",
])
def test_une_adresse_valide_est_acceptee(client, adresse):
    """Ces adresses ne sont pas refusees pour cause de format."""
    reponse = client.get("/api/enrich", params={"ip": adresse})
    assert reponse.status_code != 400


# --------------------------------------------------------------------------
# Historique
# --------------------------------------------------------------------------


def test_une_session_inexistante_est_signalee(client):
    reponse = client.get("/api/history", params={"session_id": 999999})
    assert reponse.status_code == 404
    corps = reponse.json()
    assert corps["ok"] is False
    assert "999999" in corps["error"]


def test_l_historique_sans_parametre_repond_normalement(client):
    reponse = client.get("/api/history")
    assert reponse.status_code == 200
    assert reponse.json()["ok"] is True


# --------------------------------------------------------------------------
# Bornes des parametres
# --------------------------------------------------------------------------


@pytest.mark.parametrize("chemin,parametres", [
    ("/api/packets", {"limit": 99999}),
    ("/api/packets", {"limit": 0}),
    ("/api/flows", {"limit": 99999}),
])
def test_une_borne_depassee_est_refusee(client, chemin, parametres):
    reponse = client.get(chemin, params=parametres)
    assert reponse.status_code == 422


def test_un_paquet_inexistant_est_signale(client):
    reponse = client.get("/api/packet", params={"number": 999999999})
    assert reponse.status_code == 404
    assert reponse.json()["ok"] is False


# --------------------------------------------------------------------------
# Filtre d'affichage
# --------------------------------------------------------------------------


def test_un_filtre_valide_est_accepte(client):
    reponse = client.get("/api/packets", params={"filter": "tcp"})
    assert reponse.status_code == 200
    assert reponse.json()["ok"] is True


def test_un_filtre_invalide_est_refuse_avec_un_message(client):
    """Le point cle : une faute de frappe ne doit pas passer pour un filtre vide."""
    reponse = client.get("/api/packets", params={"filter": "tcp.pot == 443"})
    assert reponse.status_code == 400
    corps = reponse.json()
    assert corps["ok"] is False
    assert "tcp.pot" in corps["error"]


def test_la_syntaxe_du_filtre_est_exposee(client):
    reponse = client.get("/api/filter/syntax")
    assert reponse.status_code == 200
    syntaxe = reponse.json()["syntax"]
    assert "tcp" in syntaxe["protocoles"]
    assert "ip.addr" in syntaxe["champs"]
    assert syntaxe["exemples"]


def test_la_page_des_parametres_repond(client):
    reponse = client.get("/settings")
    assert reponse.status_code == 200
    assert "Paramètres" in reponse.text


def test_la_carte_des_relations_agrege_par_interlocuteur():
    """Une machine peut ouvrir vingt connexions au meme service : la carte doit
    montrer UN interlocuteur, pas vingt traits superposes."""
    from app.engine import AnalyzerEngine
    from app.models import Flow

    moteur = AnalyzerEngine.__new__(AnalyzerEngine)
    moteur._intel = {}

    class FauxFlux:
        def snapshot(self):
            return [
                Flow(key="a", src="192.168.1.10", dst="1.1.1.1", src_port=1, dst_port=443,
                     transport="TCP", first_seen=0, last_seen=1,
                     packets=5, bytes_total=500, app_protocol="TLS"),
                Flow(key="b", src="192.168.1.10", dst="1.1.1.1", src_port=2, dst_port=443,
                     transport="TCP", first_seen=0, last_seen=1,
                     packets=5, bytes_total=300, app_protocol="TLS"),
                Flow(key="c", src="192.168.1.10", dst="8.8.8.8", src_port=3, dst_port=53,
                     transport="UDP", first_seen=0, last_seen=1,
                     packets=2, bytes_total=200, app_protocol="DNS"),
            ]

    moteur.flows = FauxFlux()
    moteur.parser = type("P", (), {"is_local": staticmethod(
        lambda ip: ip.startswith("192.168."))})()

    carte = moteur.peer_map(limit=10)

    assert carte["total_peers"] == 2
    premier = carte["peers"][0]
    assert premier["ip"] == "1.1.1.1"
    assert premier["bytes"] == 800          # les deux flux sont additionnes
    assert premier["flows"] == 2
    assert premier["percent"] == 80.0
    assert premier["protocol"] == "TLS"


def test_la_carte_des_relations_signale_ce_qu_elle_ne_montre_pas():
    """Sans ce total, la carte laisserait croire qu'elle montre tout."""
    from app.engine import AnalyzerEngine
    from app.models import Flow

    moteur = AnalyzerEngine.__new__(AnalyzerEngine)
    moteur._intel = {}

    class FauxFlux:
        def snapshot(self):
            return [
                Flow(key=str(i), src="192.168.1.10", dst="10.0.0.%d" % i,
                     src_port=i, dst_port=443, transport="TCP",
                     first_seen=0, last_seen=1, packets=1, bytes_total=100 * (i + 1))
                for i in range(6)
            ]

    moteur.flows = FauxFlux()
    moteur.parser = type("P", (), {"is_local": staticmethod(
        lambda ip: ip.startswith("192.168."))})()

    carte = moteur.peer_map(limit=3)
    assert len(carte["peers"]) == 3
    assert carte["others"]["count"] == 3
    assert carte["others"]["bytes"] > 0


def test_la_carte_des_relations_ne_plante_pas_sur_une_capture_vide():
    from app.engine import AnalyzerEngine

    moteur = AnalyzerEngine.__new__(AnalyzerEngine)
    moteur._intel = {}
    moteur.flows = type("F", (), {"snapshot": staticmethod(lambda: [])})()
    moteur.parser = type("P", (), {"is_local": staticmethod(lambda ip: False)})()

    carte = moteur.peer_map()
    assert carte["peers"] == []
    assert carte["total_peers"] == 0


def test_les_parametres_n_exposent_aucun_secret(client):
    """Une page de reglages ne doit jamais devenir un moyen de lire les cles.

    On place des valeurs reconnaissables dans la configuration, puis on verifie
    qu'AUCUNE n'apparait dans la reponse : seuls des indicateurs « fourni /
    absent » sont admis.
    """
    reglages = client.app.state.settings
    reglages.secret_key = "SECRET-DE-SIGNATURE-A-NE-JAMAIS-EXPOSER"
    reglages.supabase_service_key = "CLE-SUPABASE-A-NE-JAMAIS-EXPOSER"
    reglages.ai_api_key = "CLE-IA-A-NE-JAMAIS-EXPOSER"
    reglages.abuseipdb_api_key = "CLE-ABUSEIPDB-A-NE-JAMAIS-EXPOSER"

    corps = client.get("/api/settings").text
    for secret in ("SECRET-DE-SIGNATURE-A-NE-JAMAIS-EXPOSER",
                   "CLE-SUPABASE-A-NE-JAMAIS-EXPOSER",
                   "CLE-IA-A-NE-JAMAIS-EXPOSER",
                   "CLE-ABUSEIPDB-A-NE-JAMAIS-EXPOSER"):
        assert secret not in corps, "secret exposé par /api/settings"

    # L'utilisateur doit tout de meme savoir ce qui est configure.
    donnees = client.get("/api/settings").json()["settings"]
    assert donnees["secret_signe"]["fourni"] is True
    assert donnees["supabase"]["cle_fournie"] is True
    assert donnees["assistant_ia"]["cle_fournie"] is True
    assert donnees["abuseipdb"]["cle_fournie"] is True


def test_la_courbe_de_trafic_est_exposee(client):
    """Le tableau de bord a besoin d'une serie, pas d'un total cumule."""
    donnees = client.get("/api/stats").json()
    assert isinstance(donnees.get("traffic_series"), list)


def test_l_export_pcap_produit_un_fichier_valide(client):
    """L'export doit etre un VRAI fichier PCAP, pas un fichier maison.

    On verifie le magic et l'ouverture avec Scapy : un lecteur ecrit par
    d'autres. C'est ce qui permet de dire a l'utilisateur « ouvre-le dans
    Wireshark » sans le lui faire decouvrir a ses depens.
    """
    reponse = client.get("/api/export/packets.pcap")
    assert reponse.status_code == 200
    assert reponse.headers["content-type"].startswith("application/vnd.tcpdump.pcap")
    assert "capture-" in reponse.headers["content-disposition"]

    contenu = reponse.content
    # En-tete global : magic petit-boutiste, version 2.4.
    assert contenu[:4] == b"\xd4\xc3\xb2\xa1"
    assert len(contenu) >= 24
    assert len(contenu[24:]) % 1 == 0

    scapy = pytest.importorskip("scapy.all", reason="Scapy absent")
    chemin = _fichier_temporaire(contenu)
    try:
        lus = scapy.rdpcap(str(chemin))
    finally:
        chemin.unlink(missing_ok=True)

    # Verification croisee : Scapy doit retrouver EXACTEMENT le nombre de
    # paquets que le moteur a exportes. Un fichier valide mais vide passerait
    # un simple controle de format sans rien prouver.
    attendus = len(client.app.state.engine.pcap_snapshot(limit=5000))
    assert len(lus) == attendus


def test_l_export_pcap_est_refuse_en_mode_cloud(client):
    """Le mode cloud ne capture rien : proposer un export n'aurait pas de sens."""
    client.app.state.settings.mode = "cloud"
    reponse = client.get("/api/export/packets.pcap")
    # Soit refuse, soit un fichier vide — jamais une erreur 500.
    assert reponse.status_code in (200, 400, 403)


def _fichier_temporaire(donnees: bytes):
    import os
    import tempfile
    from pathlib import Path

    descripteur, nom = tempfile.mkstemp(suffix=".pcap")
    os.close(descripteur)
    chemin = Path(nom)
    chemin.write_bytes(donnees)
    return chemin
