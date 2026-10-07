"""Fixtures partagees par les tests.

Aucun test ne depend du reseau ni d'une capture reelle : les paquets sont
construits a la main. C'est ce qui rend la suite reproductible sur n'importe
quelle machine, y compris celle d'un correcteur qui n'a pas Npcap installe.
"""

from __future__ import annotations

import struct

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from app.analysis.parser import PacketParser

# Adresses utilisees dans les tests : une locale, plusieurs distantes
LOCAL_IP = "192.168.1.10"
REMOTE_IP = "93.184.216.34"


@pytest.fixture
def parser() -> PacketParser:
    return PacketParser(local_ips={LOCAL_IP})


# --------------------------------------------------------------------------
# Fabriques de paquets
# --------------------------------------------------------------------------


def tcp_packet(src=LOCAL_IP, dst=REMOTE_IP, sport=50000, dport=443,
               flags="S", payload=b"", ts=1000.0, seq=1):
    """Construit un paquet TCP complet (Ethernet + IP + TCP + charge)."""
    packet = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                                                  flags=flags, seq=seq)
    if payload:
        packet = packet / payload
    packet.time = ts
    return packet


def udp_packet(src=LOCAL_IP, dst="8.8.8.8", sport=51000, dport=53,
               payload=b"", ts=1000.0):
    packet = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    if payload:
        packet = packet / payload
    packet.time = ts
    return packet


def dns_query(name="example.com", src=LOCAL_IP, dst="8.8.8.8", ts=1000.0):
    packet = (Ether() / IP(src=src, dst=dst) / UDP(sport=51000, dport=53)
              / DNS(rd=1, qd=DNSQR(qname=name)))
    packet.time = ts
    return packet


def arp_request(src="192.168.1.1", dst="192.168.1.99", ts=1000.0):
    packet = Ether() / ARP(op=1, psrc=src, pdst=dst)
    packet.time = ts
    return packet


def tls_client_hello(server_name: str = "example.com") -> bytes:
    """Construit un ClientHello TLS minimal mais structurellement valide.

    Le but est de verifier l'extraction du SNI, c'est-a-dire du nom de serveur
    que le client annonce en clair avant tout chiffrement.
    """
    name = server_name.encode("ascii")
    # Extension server_name : type 0x0000, puis liste (longueur 2), type 0x00,
    # puis longueur du nom (2) et le nom lui-meme
    server_name_ext = (b"\x00\x00" + struct.pack(">H", len(name) + 5)
                       + struct.pack(">H", len(name) + 3) + b"\x00"
                       + struct.pack(">H", len(name)) + name)

    # Corps du ClientHello : version + random + session_id + ciphers + compression
    body = (b"\x03\x03" + b"\x11" * 32          # version TLS 1.2 + random
            + b"\x00"                            # session_id vide
            + struct.pack(">H", 2) + b"\x00\x2f"  # une suite de chiffrement
            + b"\x01\x00"                        # une methode de compression
            + struct.pack(">H", len(server_name_ext)) + server_name_ext)

    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
    return record


def http_get(host: str = "example.com", path: str = "/") -> bytes:
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"User-Agent: test\r\n\r\n").encode("ascii")
