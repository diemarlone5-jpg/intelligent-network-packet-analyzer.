"""Tests du moteur de risque et de la couche d'intelligence.

Le point le plus important teste ici est la GARANTIE contre l'invention de
faits : la consigne donnee a un modele ne suffit pas, il faut un controle
applique a sa reponse. Ces tests verifient que ce controle fonctionne.
"""

from __future__ import annotations

import pytest

from app.analysis.flows import FlowTable, resolve_service_port
from app.analysis.parser import PacketParser
from app.analysis.risk import assess_flow
from app.config import Settings
from app.intelligence.context import SessionContext, build_session_context
from app.intelligence.summarizer import GuardrailViolation, Summarizer
from tests.conftest import LOCAL_IP, tcp_packet


def build_flows(packets):
    table = FlowTable(is_local=lambda ip: ip == LOCAL_IP)
    parser = PacketParser(local_ips={LOCAL_IP})
    flow = None
    for index, packet in enumerate(packets, start=1):
        flow = table.observe(parser.parse(packet, index))
    return flow


IS_LOCAL = lambda ip: ip == LOCAL_IP  # noqa: E731


# ==========================================================================
# Risque
# ==========================================================================


class TestMoteurDeRisque:
    def test_resume_coherent_avec_les_raisons(self):
        """Ne jamais annoncer 'aucun element' alors qu'une raison est listee."""
        flow = build_flows([
            tcp_packet(src="203.0.113.9", dst=LOCAL_IP, sport=51000,
                       dport=4444, flags="S", ts=1000.0),
        ])
        risk = assess_flow(flow, IS_LOCAL)
        if risk.reasons:
            assert "Aucun element particulier" not in risk.summary
        else:
            assert risk.summary

    def test_flux_ordinaire_est_de_risque_faible(self):
        flow = build_flows([
            tcp_packet(sport=51000, dport=443, flags="S", ts=1000.0),
            tcp_packet(src="93.184.216.34", dst=LOCAL_IP, sport=443,
                       dport=51000, flags="SA", ts=1000.1),
            tcp_packet(sport=51000, dport=443, flags="PA", ts=1000.2),
        ])
        risk = assess_flow(flow, IS_LOCAL)
        assert risk.label == "faible"
        assert risk.score == 0
        assert risk.reasons == []

    def test_service_sensible_entrant_eleve_le_risque(self):
        flow = build_flows([
            tcp_packet(src="203.0.113.7", dst=LOCAL_IP, sport=51000,
                       dport=23, flags="S", ts=1000.0),
        ])
        risk = assess_flow(flow, IS_LOCAL)
        assert risk.score >= 25
        assert any("sensible" in r.fact for r in risk.reasons)

    def test_connexion_refusee_compte_comme_risque(self):
        flow = build_flows([
            tcp_packet(sport=51000, dport=8080, flags="S", ts=1000.0),
            tcp_packet(src="93.184.216.34", dst=LOCAL_IP, sport=8080,
                       dport=51000, flags="RA", ts=1000.1),
        ])
        risk = assess_flow(flow, IS_LOCAL)
        assert any("reinitialisee" in r.fact for r in risk.reasons)

    def test_protocole_en_clair_est_signale(self):
        flow = build_flows([
            tcp_packet(sport=51000, dport=21, flags="S", ts=1000.0),
            tcp_packet(src="93.184.216.34", dst=LOCAL_IP, sport=21,
                       dport=51000, flags="SA", ts=1000.1),
            tcp_packet(sport=51000, dport=21, flags="A", ts=1000.2),
            tcp_packet(sport=51000, dport=21, flags="PA", ts=1000.3),
        ])
        risk = assess_flow(flow, IS_LOCAL)
        assert any("non chiffres" in r.fact for r in risk.reasons)

    def test_chaque_raison_porte_sa_justification(self):
        """Regle du projet : aucune deduction sans justification affichee."""
        flow = build_flows([
            tcp_packet(src="203.0.113.7", dst=LOCAL_IP, sport=51000,
                       dport=3389, flags="S", ts=1000.0),
        ])
        risk = assess_flow(flow, IS_LOCAL)
        assert risk.reasons
        for raison in risk.reasons:
            assert raison.fact
            assert raison.basis
            assert raison.points > 0

    def test_score_plafonne_a_cent(self):
        """Le total ne doit jamais sortir de l'echelle annoncee."""
        flow = build_flows([
            tcp_packet(src="203.0.113.7", dst=LOCAL_IP, sport=51000,
                       dport=23, flags="S", ts=1000.0),
            tcp_packet(src="203.0.113.7", dst=LOCAL_IP, sport=51000,
                       dport=23, flags="RA", ts=1000.1),
            tcp_packet(src="203.0.113.7", dst=LOCAL_IP, sport=51000,
                       dport=23, flags="RA", ts=1000.2),
        ])
        risk = assess_flow(flow, IS_LOCAL)
        assert 0 <= risk.score <= 100
        assert risk.label in ("faible", "modere", "eleve", "critique")

    def test_propriete_to_dict_serialisable(self):
        import json
        flow = build_flows([
            tcp_packet(src="203.0.113.7", dst=LOCAL_IP, sport=51000,
                       dport=445, flags="S", ts=1000.0),
        ])
        json.dumps(assess_flow(flow, IS_LOCAL).to_dict())


# ==========================================================================
# Contexte fourni a la couche d'intelligence
# ==========================================================================


class TestContexte:
    def test_recense_les_entites_autorisees(self):
        context = SessionContext(
            packets=10, flows=2,
            top_sources=[{"ip": LOCAL_IP, "count": 5}],
            top_destinations=[{"ip": "93.184.216.34", "count": 5}],
            domains=["example.com"],
            key_flows=[{"observer": LOCAL_IP, "distant": "93.184.216.34",
                        "service": "HTTPS", "domain": "example.com"}],
        )
        allowed = context.allowed_entities()
        assert LOCAL_IP in allowed["ips"]
        assert "93.184.216.34" in allowed["ips"]
        assert "example.com" in allowed["domains"]
        assert "https" in allowed["services"]

    def test_contexte_vide_ne_leve_pas(self):
        allowed = SessionContext().allowed_entities()
        assert allowed == {"ips": set(), "domains": set(), "services": set()}


# ==========================================================================
# Verificateur anti-invention
# ==========================================================================


class TestGardeFous:
    def build_summarizer(self, tmp_path, ai_enabled=False):
        settings = Settings(env="test", mode="cloud", secret_key="k" * 48,
                            sqlite_path=tmp_path / "ai.db",
                            ai_enabled=ai_enabled, ai_api_key="")
        return Summarizer(settings)

    def test_adresse_inconnue_rejetee(self, tmp_path):
        """Le coeur du dispositif : une entite inventee fait echouer la generation."""
        summarizer = self.build_summarizer(tmp_path)
        allowed = {"ips": {LOCAL_IP}, "domains": {"example.com"}, "services": set()}
        with pytest.raises(GuardrailViolation) as erreur:
            summarizer._validate("Le poste a contacte 8.8.8.8 sur le port 53.", allowed)
        assert "8.8.8.8" in erreur.value.entities

    def test_domaine_inconnu_rejete(self, tmp_path):
        summarizer = self.build_summarizer(tmp_path)
        allowed = {"ips": {LOCAL_IP}, "domains": {"example.com"}, "services": set()}
        with pytest.raises(GuardrailViolation):
            summarizer._validate("Le trafic va vers pirate-malveillant.com.", allowed)

    def test_entites_connues_acceptees(self, tmp_path):
        summarizer = self.build_summarizer(tmp_path)
        allowed = {"ips": {LOCAL_IP}, "domains": {"example.com"}, "services": set()}
        summarizer._validate(
            f"La machine {LOCAL_IP} a contacte example.com.", allowed
        )

    def test_adresse_reseau_du_meme_prefixe_acceptee(self, tmp_path):
        """192.168.1.0 est une designation de reseau, pas une invention."""
        summarizer = self.build_summarizer(tmp_path)
        allowed = {"ips": {"192.168.1.22"}, "domains": set(), "services": set()}
        summarizer._validate("Le reseau 192.168.1.0 est concerne.", allowed)

    def test_mot_ordinaire_sans_extension_accepte(self, tmp_path):
        """Un mot courant ne doit pas etre pris pour un nom de domaine."""
        summarizer = self.build_summarizer(tmp_path)
        allowed = {"ips": set(), "domains": set(), "services": set()}
        summarizer._validate("Le trafic semble normal et habituel.", allowed)


# ==========================================================================
# Resume
# ==========================================================================


class TestResume:
    def settings_for(self, tmp_path, **kwargs):
        defaults = dict(env="test", mode="cloud", secret_key="k" * 48,
                        sqlite_path=tmp_path / "resume.db")
        defaults.update(kwargs)
        return Settings(**defaults)

    def test_resume_par_regles_sans_aucune_configuration(self, tmp_path):
        """Le resume doit fonctionner sans cle d'API : c'est le mode par defaut."""
        summarizer = Summarizer(self.settings_for(tmp_path))
        context = SessionContext(
            packets=1200, flows=45, active_flows=7, bytes_total=2_500_000,
            protocols=[{"name": "TCP", "count": 900}, {"name": "TLS", "count": 300}],
            domains=["example.com"],
            events=[{"type": "OBSERVATION", "titre": "Volume dominant",
                     "regle": "volume_dominant", "gravite": "info"}],
            sensitive_services=["Telnet"],
        )
        result = summarizer.summarize(context)
        assert result.provider == "regles"
        assert result.fallback is False
        assert "1200 paquets" in result.text
        assert "Telnet" in result.text
        assert "conclure" in result.text.lower()   # la reserve est toujours la

    def test_resume_sur_capture_vide(self, tmp_path):
        summarizer = Summarizer(self.settings_for(tmp_path))
        result = summarizer.summarize(SessionContext())
        assert "Aucun paquet" in result.text
        assert result.guardrails["verifie"] is True
        # Le rapport de garde-fou garde la meme forme dans tous les cas :
        # l'interface peut donc toujours l'afficher sans test conditionnel.
        assert set(result.guardrails) == {
            "verifie", "entites_autorisees", "inventions_detectees", "regle"
        }

    def test_bascule_sur_les_regles_si_ia_active_sans_cle(self, tmp_path):
        """Sans cle, on ne tente aucun appel : on reste sur le resume local."""
        summarizer = Summarizer(self.settings_for(tmp_path, ai_enabled=True))
        result = summarizer.summarize(SessionContext(packets=10, flows=1))
        assert result.provider == "regles"
        assert result.fallback is False

    def test_rapport_de_garde_fou_present(self, tmp_path):
        summarizer = Summarizer(self.settings_for(tmp_path))
        result = summarizer.summarize(SessionContext(packets=10, flows=1))
        rapport = result.guardrails
        assert rapport["verifie"] is True
        assert rapport["inventions_detectees"] == []
        assert rapport["regle"]
