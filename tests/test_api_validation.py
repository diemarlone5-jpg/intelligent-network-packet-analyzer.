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
