"""Tests de l'interface web : pages, securite, API.

Ces tests contiennent deux tests de NON-REGRESSION qui reproduisent des bugs
reellement rencontres pendant le developpement :

    - l'ordre des intergiciels ASGI, qui rendait toutes les pages en erreur 500 ;
    - la serialisation JSON, qu'un objet Scapy non converti faisait echouer.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.web.app import create_app

CSRF_PATTERN = re.compile(r'name="csrf-token" content="([^"]+)"')

PAGES_ATTENDUES = [
    ("/", "Tableau de bord"),
    ("/packets", "Paquets capturés"),
    ("/flows", "Communications"),
    ("/events", "Événements détectés"),
    ("/protocols", "Base de connaissance réseau"),
    ("/history", "Historique"),
    ("/about", "Comprendre l'application"),
]


@pytest.fixture
def settings(tmp_path):
    """Configuration de test : mode consultation, aucune capture, aucun reseau."""
    return Settings(
        env="test",
        mode="cloud",
        secret_key="x" * 48,
        sqlite_path=tmp_path / "web-test.db",
        enrich_enabled=False,
        supabase_enabled=False,
        ai_enabled=False,
    )


@pytest.fixture
def client(settings):
    application = create_app(settings)
    with TestClient(application) as test_client:
        yield test_client


def get_csrf(client: TestClient) -> str:
    reponse = client.get("/")
    match = CSRF_PATTERN.search(reponse.text)
    assert match, "le jeton anti-CSRF doit etre present dans la page"
    return match.group(1)


# ==========================================================================
# Pages
# ==========================================================================


class TestPages:
    @pytest.mark.parametrize("chemin,titre", PAGES_ATTENDUES)
    def test_page_rendue(self, client, chemin, titre):
        """Regression : toutes les pages renvoyaient 500 a cause de l'ordre des
        intergiciels. Ce test echoue immediatement si l'ordre est casse."""
        reponse = client.get(chemin)
        assert reponse.status_code == 200
        assert titre in reponse.text
        assert 'lang="fr"' in reponse.text

    @pytest.mark.parametrize("chemin,_", PAGES_ATTENDUES)
    def test_aucun_gabarit_non_resolu(self, client, chemin, _):
        texte = client.get(chemin).text
        assert "{{" not in texte
        assert "{%" not in texte
        assert "None" not in texte

    def test_page_inconnue(self, client):
        reponse = client.get("/cette-page-nexiste-pas")
        assert reponse.status_code == 404
        assert "Page introuvable" in reponse.text
        # Aucune trace technique ne doit apparaitre
        assert "Traceback" not in reponse.text

    def test_assets_static_servis(self, client):
        assert client.get("/static/css/style.css").status_code == 200
        assert client.get("/static/js/app.js").status_code == 200
        assert client.get("/static/img/favicon.svg").status_code == 200

    def test_empreinte_de_version_sur_les_ressources(self, client):
        """Sans empreinte, le navigateur sert l'ancien script apres une
        modification et l'on croit avoir corrige un bug toujours actif."""
        texte = client.get("/").text
        assert "style.css?v=" in texte
        assert "app.js?v=" in texte

    def test_documentation_api_disponible(self, client):
        assert client.get("/api/docs").status_code == 200
        assert client.get("/api/openapi.json").status_code == 200


# ==========================================================================
# Securite
# ==========================================================================


class TestSecurite:
    def test_entetes_de_securite(self, client):
        entetes = client.get("/").headers
        assert entetes["x-content-type-options"] == "nosniff"
        assert entetes["x-frame-options"] == "DENY"
        assert entetes["referrer-policy"] == "same-origin"
        assert "content-security-policy" in entetes

    def test_politique_de_securite_interdit_le_script_en_ligne(self, client):
        csp = client.get("/").headers["content-security-policy"]
        assert "script-src 'self'" in csp
        assert "unsafe-inline" not in csp
        assert "frame-ancestors 'none'" in csp

    def test_aucun_gestionnaire_en_ligne_dans_les_gabarits(self, client):
        """Avec une politique stricte, un onclick= en ligne ne fonctionnerait pas."""
        for chemin, _ in PAGES_ATTENDUES:
            texte = client.get(chemin).text
            assert "onclick=" not in texte
            assert "onchange=" not in texte
            assert "<script>" not in texte

    def test_action_sans_jeton_refusee(self, client):
        reponse = client.post("/api/capture/start", json={})
        assert reponse.status_code == 400
        assert "Jeton de securite" in reponse.json()["error"]

    def test_jeton_invalide_refuse(self, client):
        get_csrf(client)
        reponse = client.post("/api/capture/start", json={},
                              headers={"X-CSRF-Token": "faux-jeton"})
        assert reponse.status_code == 400

    def test_jeton_valide_accepte(self, client):
        jeton = get_csrf(client)
        reponse = client.post("/api/reset", headers={"X-CSRF-Token": jeton})
        assert reponse.status_code == 200
        assert reponse.json()["ok"] is True

    def test_capture_refusee_en_mode_consultation(self, client):
        """Une instance deployee en ligne ne doit pas pretendre capturer."""
        jeton = get_csrf(client)
        reponse = client.post("/api/capture/start", json={},
                              headers={"X-CSRF-Token": jeton})
        assert reponse.status_code == 409
        assert "mode consultation" in reponse.json()["error"]


# ==========================================================================
# API
# ==========================================================================


class TestAPI:
    def test_status(self, client):
        donnees = client.get("/api/status").json()
        assert donnees["ok"] is True
        assert donnees["mode"] == "cloud"
        assert donnees["capture_available"] is False

    def test_stats_serialisables(self, client):
        """Regression : un objet d'interface Scapy non converti en chaine
        faisait echouer la serialisation JSON et renvoyait une erreur 500."""
        reponse = client.get("/api/stats")
        assert reponse.status_code == 200
        donnees = reponse.json()
        json.dumps(donnees)          # ne doit pas lever
        assert donnees["packets"] == 0
        assert "capture" in donnees
        assert donnees["capture"]["running"] is False

    def test_paquets_vides(self, client):
        donnees = client.get("/api/packets").json()
        assert donnees["ok"] is True
        assert donnees["packets"] == []

    def test_flux_vides(self, client):
        donnees = client.get("/api/flows").json()
        assert donnees["ok"] is True
        assert donnees["flows"] == []

    def test_evenements_vides(self, client):
        donnees = client.get("/api/events").json()
        assert donnees["ok"] is True
        assert donnees["events"] == []

    def test_communication_inconnue(self, client):
        reponse = client.get("/api/flow", params={"key": "TCP|1.1.1.1:1|2.2.2.2:2"})
        assert reponse.status_code == 404
        assert reponse.json()["ok"] is False

    def test_communication_sans_cle(self, client):
        assert client.get("/api/flow").status_code == 422

    def test_enrichissement_desactive(self, client):
        reponse = client.get("/api/enrich", params={"ip": "8.8.8.8"})
        assert reponse.status_code == 409

    def test_interfaces_listees(self, client):
        donnees = client.get("/api/interfaces").json()
        assert donnees["ok"] is True
        assert isinstance(donnees["interfaces"], list)

    def test_historique_vide(self, client):
        donnees = client.get("/api/history").json()
        assert donnees["ok"] is True
        assert donnees["sessions"] == []
        assert donnees["session"] is None

    def test_base_de_connaissance_exposee(self, client):
        """La page Protocoles doit pouvoir etre verifiee sans lire le code."""
        donnees = client.get("/api/protocols").json()
        assert donnees["ok"] is True
        services = {entree["service"] for entree in donnees["ports"]}
        assert "HTTPS" in services
        assert "DNS" in services
        # Chaque entree porte sa justification et son niveau de confiance
        for entree in donnees["ports"]:
            assert entree["why"]
            assert entree["confidence"] in ("haute", "moyenne", "faible")
        assert donnees["transports"]
        assert donnees["tcp_flags"]
        assert donnees["scopes"]

    def test_etat_des_dependances(self, client):
        donnees = client.get("/api/dependencies").json()
        assert donnees["ok"] is True
        assert donnees["base_locale"]["disponible"] is True
        assert donnees["supabase"]["active"] is False
        assert donnees["capture"]["disponible"] is False   # mode consultation
        assert "role" in donnees["supabase"]

    def test_resume_de_session(self, client):
        """Le resume doit fonctionner sans aucune cle d'API configuree."""
        donnees = client.get("/api/summary").json()
        assert donnees["ok"] is True
        resume = donnees["summary"]
        assert resume["provider"] == "regles"
        assert resume["guardrails"]["verifie"] is True
        assert resume["text"]
        assert resume["fallback"] is False

    def test_limites_de_pagination_validees(self, client):
        """Les entrees invalides doivent etre refusees, pas ignorees."""
        assert client.get("/api/packets", params={"limit": 0}).status_code == 422
        assert client.get("/api/packets", params={"limit": 99999}).status_code == 422
        assert client.get("/api/packets", params={"limit": "abc"}).status_code == 422


# ==========================================================================
# Enrichissement (sans appel reseau)
# ==========================================================================


class TestEnrichissement:
    def test_adresse_privee_sans_appel_externe(self, tmp_path):
        """Une adresse locale s'explique seule : aucun appel a une API externe."""
        settings = Settings(env="test", mode="cloud", secret_key="y" * 48,
                            sqlite_path=tmp_path / "enrich.db", enrich_enabled=True)
        application = create_app(settings)
        with TestClient(application) as client:
            donnees = client.get("/api/enrich", params={"ip": "192.168.1.42"}).json()
            assert donnees["ok"] is True
            assert donnees["intel"]["scope"] == "prive"
            assert donnees["intel"]["source"] == "classification locale"

    def test_adresse_invalide_geree(self, tmp_path):
        """Comportement corrige : une adresse invalide est refusee.

        Ce test verifiait auparavant un code 200 avec « scope: inconnu ». Cette
        reponse etait trompeuse : elle ressemblait a un resultat valide mais
        vide, et rien n'indiquait que la demande etait erronee.
        """
        settings = Settings(env="test", mode="cloud", secret_key="z" * 48,
                            sqlite_path=tmp_path / "enrich2.db", enrich_enabled=True)
        application = create_app(settings)
        with TestClient(application) as client:
            reponse = client.get("/api/enrich", params={"ip": "pas-une-adresse"})
            assert reponse.status_code == 400
            donnees = reponse.json()
            assert donnees["ok"] is False
            assert "valide" in donnees["error"]


# ==========================================================================
# Configuration
# ==========================================================================


class TestConfiguration:
    def test_production_refuse_une_configuration_incomplete(self, tmp_path):
        """En production, demarrer avec une configuration bancale doit echouer
        bruyamment plutot que produire une application insuffisante."""
        mauvaise = Settings(env="prod", mode="cloud", secret_key="court",
                            sqlite_path=tmp_path / "prod.db", ai_enabled=True)
        with pytest.raises(RuntimeError) as erreur:
            create_app(mauvaise)
        message = str(erreur.value)
        assert "SECRET_KEY" in message
        assert "AI_API_KEY" in message

    def test_mode_invalide_signale(self, tmp_path):
        settings = Settings(env="test", mode="n_importe_quoi", secret_key="a" * 48,
                            sqlite_path=tmp_path / "modes.db")
        assert any("APP_MODE" in p for p in settings.validate())

    def test_supabase_active_sans_cle_signalee(self, tmp_path):
        settings = Settings(env="test", mode="cloud", secret_key="a" * 48,
                            sqlite_path=tmp_path / "sb.db", supabase_enabled=True)
        assert any("SUPABASE" in p for p in settings.validate())

    def test_cle_secrete_genereree_en_developpement(self, tmp_path, monkeypatch):
        """Sans SECRET_KEY, l'application reste utilisable en developpement."""
        monkeypatch.delenv("SECRET_KEY", raising=False)
        from app.config import load_settings
        configuration = load_settings()
        assert len(configuration.secret_key) >= 32


# ==========================================================================
# Compatibilite avec la politique de securite (CSP)
# ==========================================================================


class TestScriptsEnLigne:
    """La CSP du serveur interdit les scripts en ligne.

    Un script en ligne ne provoque pas d'erreur visible : le navigateur le
    bloque en silence, et la fonctionnalite qu'il portait disparait. C'est
    exactement ce qui est arrive : la page de detail d'un paquet transmettait le
    numero par un script en ligne, donc le numero n'arrivait jamais et la page
    affichait « aucun paquet n'a ete designe ». Ces tests empechent le retour du
    probleme.
    """

    GABARITS = Path(__file__).resolve().parent.parent / "app" / "web" / "templates"

    def test_aucun_script_en_ligne_dans_les_gabarits(self):
        fautifs = []
        for gabarit in sorted(self.GABARITS.glob("*.html")):
            contenu = gabarit.read_text(encoding="utf-8")
            for balise in re.finditer(r"<script\b[^>]*>", contenu):
                if "src=" not in balise.group(0):
                    fautifs.append(f"{gabarit.name}: {balise.group(0)}")
        assert not fautifs, (
            "Ces balises <script> sont en ligne et seront bloquees par la CSP "
            "(script-src 'self') : " + " | ".join(fautifs)
            + " — utilisez un attribut data- lu par app.js."
        )

    def test_la_csp_interdit_bien_les_scripts_en_ligne(self, client):
        entete = client.get("/").headers.get("content-security-policy", "")
        assert "script-src 'self'" in entete
        assert "unsafe-inline" not in entete

    def test_la_page_paquet_transmet_le_numero_par_attribut(self, client):
        reponse = client.get("/packet", params={"number": 42})
        assert reponse.status_code == 200
        assert 'data-packet-number="42"' in reponse.text
        assert "window.PACKET_NUMBER" not in reponse.text

    def test_aucun_style_en_ligne_dans_les_gabarits(self):
        fautifs = []
        for gabarit in sorted(self.GABARITS.glob("*.html")):
            contenu = gabarit.read_text(encoding="utf-8")
            if re.search(r'\sstyle="', contenu):
                fautifs.append(gabarit.name)
        assert not fautifs, (
            "Ces gabarits posent un attribut style=\"...\", bloque par la CSP "
            "(style-src 'self' : " + ", ".join(fautifs) + ")"
        )

    def test_le_script_ne_pose_pas_d_attribut_style(self):
        """Le CSSOM est autorise, l'attribut style ne l'est pas.

        Les graphiques a barres posaient leur largeur par un attribut style :
        la CSP le bloquait, les barres se retrouvaient sans largeur et le
        tableau de bord paraissait vide. La largeur doit passer par
        `element.style.propriete = valeur`.
        """
        source = (Path(__file__).resolve().parent.parent
                  / "app" / "web" / "static" / "js" / "app.js").read_text(encoding="utf-8")
        assert "style:" not in source, (
            "app.js pose un attribut style dans une balise : utilisez le CSSOM "
            "(element.style.propriete = valeur), sinon la CSP le bloque en silence."
        )


