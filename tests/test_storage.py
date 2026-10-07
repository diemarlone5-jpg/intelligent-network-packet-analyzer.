"""Tests de la couche de persistance (SQLite)."""

from __future__ import annotations

import time

import pytest

from app.analysis.flows import FlowTable
from app.models import Event, Flow, IPIntel, PacketRecord
from app.storage.sqlite_repo import SqliteRepository
from tests.conftest import LOCAL_IP, tcp_packet


@pytest.fixture
def repo(tmp_path):
    repository = SqliteRepository(tmp_path / "test.db")
    repository.init_schema()
    return repository


def make_flow():
    table = FlowTable(is_local=lambda ip: ip == LOCAL_IP)
    from app.analysis.parser import PacketParser
    parser = PacketParser(local_ips={LOCAL_IP})
    flow = None
    for index, packet in enumerate([
        tcp_packet(sport=51000, dport=443, flags="S", ts=1000.0),
        tcp_packet(src="93.184.216.34", dst=LOCAL_IP, sport=443, dport=51000,
                   flags="SA", ts=1000.1),
    ], start=1):
        flow = table.observe(parser.parse(packet, index))
    return flow


class TestSessions:
    def test_creation_et_cloture(self, repo):
        session_id = repo.create_session(mode="local", interface="npf_x",
                                         interface_name="Wi-Fi", filter="tcp")
        assert session_id > 0

        sessions = repo.list_sessions()
        assert len(sessions) == 1
        assert sessions[0]["interface_name"] == "Wi-Fi"
        assert sessions[0]["stopped_at"] is None

        repo.close_session(session_id, packets=120, bytes_total=4096,
                           flows=8, events=2)
        cloturee = repo.get_session(session_id)
        assert cloturee["packets"] == 120
        assert cloturee["stopped_at"] is not None

    def test_session_inexistante(self, repo):
        assert repo.get_session(9999) is None

    def test_liste_vide_au_depart(self, repo):
        assert repo.list_sessions() == []


class TestFlux:
    def test_enregistrement_et_relecture(self, repo):
        session_id = repo.create_session(mode="local", interface="x",
                                         interface_name="Wi-Fi")
        flow = make_flow()
        flow.explanation_text = "Communication chiffree (TLS/HTTPS) probable"
        repo.save_flows(session_id, [flow])

        enregistres = repo.list_flows(session_id)
        assert len(enregistres) == 1
        assert enregistres[0]["flow_key"] == flow.key
        assert enregistres[0]["dst_port"] == 443
        assert "TLS" in enregistres[0]["explanation"]

    def test_mise_a_jour_sans_doublon(self, repo):
        """La cle de flux est unique par session : on met a jour, on ne duplique pas."""
        session_id = repo.create_session(mode="local", interface="x",
                                         interface_name="Wi-Fi")
        flow = make_flow()
        repo.save_flows(session_id, [flow])
        flow.packets = 99
        flow.bytes_total = 12345
        repo.save_flows(session_id, [flow])

        enregistres = repo.list_flows(session_id)
        assert len(enregistres) == 1
        assert enregistres[0]["packets"] == 99
        assert enregistres[0]["bytes_total"] == 12345

    def test_liste_vide_sans_erreur(self, repo):
        assert repo.list_flows(999) == []


class TestEvenements:
    def test_enregistrement_avec_preuves(self, repo):
        session_id = repo.create_session(mode="local", interface="x",
                                         interface_name="Wi-Fi")
        evenement = Event(
            ts=time.time(), kind="HYPOTHESE", rule="test_regle",
            title="Titre", explanation="Explication", severity="moyen",
            evidence={"nb": 20, "seuil": 15}, actor="192.168.1.10",
        )
        repo.save_events(session_id, [evenement])

        relus = repo.list_events(session_id)
        assert len(relus) == 1
        assert relus[0]["kind"] == "HYPOTHESE"
        assert relus[0]["evidence"]["nb"] == 20   # preuves restituees en dict

    def test_liste_vide(self, repo):
        assert repo.list_events(999) == []


class TestPaquets:
    def test_echantillon_enregistre(self, repo):
        session_id = repo.create_session(mode="local", interface="x",
                                         interface_name="Wi-Fi")
        record = PacketRecord(number=1, ts=1000.0, src=LOCAL_IP,
                              dst="93.184.216.34", protocol="TCP", size=54,
                              transport="TCP", src_port=51000, dst_port=443,
                              tcp_flags="S", ttl=64, info="TCP ...")
        repo.save_packets(session_id, [record])
        relus = repo.list_packets(session_id)
        assert len(relus) == 1
        assert relus[0]["dst_port"] == 443
        assert relus[0]["tcp_flags"] == "S"


class TestCacheEnrichissement:
    def test_ecriture_et_lecture(self, repo):
        intel = IPIntel(ip="8.8.8.8", scope="public", country="United States",
                        city="San Jose", org="Google LLC", asn="AS15169",
                        source="ipwho.is", fetched_at=time.time())
        repo.save_intel(intel)

        relu = repo.get_intel("8.8.8.8", max_age_hours=24)
        assert relu is not None
        assert relu.country == "United States"
        assert relu.asn == "AS15169"

    def test_cache_expire_est_ignore(self, repo):
        intel = IPIntel(ip="1.1.1.1", scope="public", source="test",
                        fetched_at=time.time() - 3600 * 48)
        repo.save_intel(intel)
        assert repo.get_intel("1.1.1.1", max_age_hours=24) is None

    def test_mise_a_jour_du_cache(self, repo):
        repo.save_intel(IPIntel(ip="1.1.1.1", scope="public", country="A",
                                source="test", fetched_at=time.time()))
        repo.save_intel(IPIntel(ip="1.1.1.1", scope="public", country="B",
                                source="test", fetched_at=time.time()))
        assert repo.get_intel("1.1.1.1", 24).country == "B"

    def test_adresse_absente(self, repo):
        assert repo.get_intel("10.0.0.1", 24) is None


class TestRobustesse:
    def test_ping(self, repo):
        assert repo.ping() is True

    def test_initialisation_idempotente(self, repo):
        repo.init_schema()
        repo.init_schema()
        assert repo.ping() is True

    def test_sauvegarde_de_listes_vides(self, repo):
        """Les cas vides ne doivent jamais lever."""
        session_id = repo.create_session(mode="local", interface="x",
                                         interface_name="Wi-Fi")
        repo.save_flows(session_id, [])
        repo.save_events(session_id, [])
        repo.save_packets(session_id, [])

    def test_avertissement_consigne(self, repo):
        repo.record_warning("Supabase injoignable")
        assert len(repo.list_warnings()) == 1
