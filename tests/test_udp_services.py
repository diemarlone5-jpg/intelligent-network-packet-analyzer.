"""Tests de l'identification des services portes par UDP.

Cas concret a l'origine de ces tests : un flux video YouTube passe par QUIC, sur
UDP/443. Le paquet etait etiquete « UDP » avec une adresse brute, donc invisible
pour l'utilisateur qui cherchait YouTube. La base de connaissance savait pourtant
deja que UDP/443 est QUIC.
"""

from __future__ import annotations

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from app.analysis.parser import PacketParser


def paquet_udp(sport: int, dport: int, charge: bytes = b"\x00" * 24):
    return Ether()/IP(src="192.168.1.5", dst="142.250.75.238")/UDP(sport=sport, dport=dport)/charge


def analyser(pkt):
    parser = PacketParser({"192.168.1.5"})
    return parser.parse(pkt, 1)


def test_udp_443_est_identifie_comme_quic():
    """Sans cela, une video YouTube reste un « UDP » anonyme."""
    record = analyser(paquet_udp(50000, 443))
    assert record.protocol == "QUIC"
    assert record.transport == "UDP"


def test_udp_443_en_reponse_est_aussi_quic():
    """Le port de destination est alors ephemere : c'est le port source qui compte."""
    record = analyser(paquet_udp(443, 50000))
    assert record.protocol == "QUIC"


def test_udp_123_est_identifie_comme_ntp():
    record = analyser(paquet_udp(50000, 123))
    assert record.protocol == "NTP"


def test_udp_1900_est_identifie_comme_ssdp():
    record = analyser(paquet_udp(50000, 1900))
    assert record.protocol == "SSDP"


def test_udp_53_reste_identifie_comme_dns():
    """Le cas DNS est traite avant : il ne doit pas etre ecrase."""
    record = analyser(paquet_udp(50000, 53))
    assert record.protocol == "DNS"


def test_un_port_udp_inconnu_reste_udp():
    """Un port non reference garde son nom generique : aucun nom invente."""
    record = analyser(paquet_udp(50000, 45678))
    assert record.protocol == "UDP"


def test_un_port_udp_inconnu_en_source_reste_udp():
    record = analyser(paquet_udp(45678, 50001))
    assert record.protocol == "UDP"


def test_le_port_de_destination_prime_sur_le_port_source():
    """Une demande sortante est nommee par le port vise."""
    record = analyser(paquet_udp(60000, 443))
    assert record.protocol == "QUIC"


def test_un_paquet_de_reponse_est_nomme_par_son_port_source():
    """Une reponse part du port du service vers le port ephemere du client.

    Le port de destination est alors inconnu de la base ; c'est le port source
    qui identifie le service. C'est le cas d'une reponse SSDP envoyee depuis le
    port 1900 vers le port ephemere du client.
    """
    record = analyser(paquet_udp(1900, 50001))
    assert record.protocol == "SSDP"


def test_aucun_port_reconnu_laisse_le_paquet_en_udp():
    record = analyser(paquet_udp(51234, 51235))
    assert record.protocol == "UDP"
