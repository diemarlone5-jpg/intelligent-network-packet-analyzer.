"""Traduction d'un paquet Scapy en enregistrement plat et exploitable.

Cette couche est volontairement *sans interpretation* : elle decrit ce que
contient le paquet, rien de plus. Les deductions (a quoi sert ce port, que
signifie ce drapeau) appartiennent au moteur d'explication.

Trois extractions apportent une vraie valeur a l'analyse et sont realisees
ici, car elles portent sur les octets bruts :

    - SNI du ClientHello TLS : le nom du serveur visite, visible meme si la
      session est chiffree ;
    - en-tete Host d'une requete HTTP non chiffree ;
    - nom interroge dans une requete DNS.

Aucune de ces extractions ne dechiffre quoi que ce soit : on lit uniquement
des informations que le client transmet volontairement en clair.
"""

from __future__ import annotations

import struct
from typing import Any

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.packet import Packet, Raw

from app.analysis.protocols import APP_PROTOCOLS, classify_address
from app.models import PacketRecord

# Ports sur lesquels on cherche un en-tete HTTP en clair
_HTTP_PORTS = {80, 8000, 8080, 8888, 3000, 5000, 591}
# Ports susceptibles de porter un ClientHello TLS
_TLS_PORTS = {443, 8443, 993, 995, 465, 636, 853, 5061, 8883}

_HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ",
                 b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")


def _safe_bytes(pkt: Packet) -> bytes:
    """Recupere la charge utile brute, sans lever d'exception."""
    try:
        layer = pkt.getlayer(Raw)
        if layer is None:
            return b""
        payload = layer.load
        return payload if isinstance(payload, (bytes, bytearray)) else bytes(payload)
    except Exception:
        return b""


# --------------------------------------------------------------------------
# Extraction du SNI (nom du serveur) dans un ClientHello TLS
# --------------------------------------------------------------------------


def extract_tls_sni(payload: bytes) -> str | None:
    """Lit le nom de domaine dans une poignee de main TLS, si presente.

    Structure lue (RFC 8446 / 5246) :
        [0]     0x16        -> type "Handshake"
        [1:3]   version TLS
        [3:5]   longueur de l'enregistrement
        [5]     0x01        -> type "ClientHello"
        [43:..] extensions  -> dont l'extension 0x0000 "server_name"

    Retourne None des que la structure ne correspond pas : un paquet qui
    n'est pas un ClientHello ne doit jamais produire de faux domaine.
    """
    try:
        if len(payload) < 44 or payload[0] != 0x16:
            return None
        if payload[5] != 0x01:  # pas un ClientHello
            return None

        # Position des extensions : apres session_id, cipher_suites, compression
        pos = 43  # 5 (enregistrement) + 2 (version) + 32 (random) + 1 + 1 + 2
        if pos >= len(payload):
            return None

        session_id_len = payload[43]
        pos = 44 + session_id_len
        if pos + 2 > len(payload):
            return None
        cipher_len = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2 + cipher_len
        if pos + 1 > len(payload):
            return None
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return None

        ext_total = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2
        end = min(len(payload), pos + ext_total)

        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack(">HH", payload[pos:pos + 4])
            pos += 4
            if pos + ext_len > end:
                break
            if ext_type == 0x0000:  # server_name
                # structure : liste de serveurs (2 octets) puis type (1) + nom
                server_list = payload[pos:pos + ext_len]
                if len(server_list) >= 5 and server_list[2] == 0x00:
                    name_len = struct.unpack(">H", server_list[3:5])[0]
                    raw_name = server_list[5:5 + name_len]
                    return raw_name.decode("ascii", errors="replace").lower() or None
                break
            pos += ext_len
    except Exception:
        return None
    return None


def extract_http_host(payload: bytes) -> str | None:
    """Lit l'en-tete `Host` d'une requete HTTP non chiffree."""
    try:
        if not payload.startswith(_HTTP_METHODS):
            return None
        head = payload.split(b"\r\n\r\n", 1)[0][:4096]
        for line in head.split(b"\r\n")[1:]:
            if line[:5].lower() == b"host:":
                return line[5:].decode("ascii", errors="replace").strip().lower() or None
    except Exception:
        return None
    return None


# --------------------------------------------------------------------------
# Parseur
# --------------------------------------------------------------------------


class PacketParser:
    """Transforme un paquet Scapy en PacketRecord.

    Le parseur conserve la liste des adresses locales de la machine pour
    qualifier le sens de la communication (sortant, entrant, interne).
    Les adresses sont injectables pour rendre les tests deterministes.
    """

    def __init__(self, local_ips: set[str] | None = None) -> None:
        from app.capture.interfaces import _normalize_ip

        self._normalize = _normalize_ip
        self.local_ips: set[str] = set()
        self.set_local_ips(local_ips or set())

    def set_local_ips(self, ips: set[str]) -> None:
        """Remplace la liste des adresses locales, en forme canonique."""
        normalized = {self._normalize(ip) for ip in ips if ip}
        normalized.update({"127.0.0.1", "::1", "0.0.0.0"})
        self.local_ips = {value for value in normalized if value}

    def is_local(self, ip: str | None) -> bool:
        """L'adresse appartient-elle a cette machine ?

        La comparaison est faite apres normalisation : une adresse IPv6 peut
        s'ecrire de plusieurs facons equivalentes, et une comparaison de chaines
        brutes echouerait selon la forme utilisee par le paquet.
        """
        if not ip:
            return False
        if ip in self.local_ips:
            return True
        import ipaddress

        try:
            return ipaddress.ip_address(ip.split("%")[0]).compressed in self.local_ips
        except ValueError:
            return False

    # ------------------------------------------------------------------
    def parse(self, pkt: Packet, number: int) -> PacketRecord:
        """Point d'entree : ne doit jamais lever d'exception."""
        record = PacketRecord(
            number=number,
            ts=float(getattr(pkt, "time", 0.0)),
            src="?",
            dst="?",
            protocol="Inconnu",
            size=len(pkt),
            info="",
        )

        try:
            record.layers = self._layer_names(pkt)
            self._parse_link_layer(pkt, record)
            self._parse_l3_l4(pkt, record)
            self._infer_application(pkt, record)
            record.direction = self._direction(record)
            record.info = self._summary(record)
        except Exception as exc:  # pragma: no cover - filet de securite
            record.malformed = True
            record.info = f"Paquet non analysable ({type(exc).__name__})"
        return record

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_link_layer(pkt: Packet, r: PacketRecord) -> None:
        """Recupere les adresses materielles de la couche Ethernet.

        C'est la seule information qui identifie un appareil independamment de
        son adresse IP : une meme machine peut en changer, son adresse
        materielle ne change pas. Elle sert a la page « Reseau local ».
        """
        try:
            if Ether in pkt:
                ether = pkt[Ether]
                r.src_mac = str(ether.src).lower() or None
                r.dst_mac = str(ether.dst).lower() or None
        except Exception:
            pass

    # ------------------------------------------------------------------
    @staticmethod
    def _layer_names(pkt: Packet) -> list[str]:
        """Liste les couches empilees, de la plus basse a la plus haute."""
        names: list[str] = []
        current: Any = pkt
        seen: set[str] = set()
        while current is not None:
            name = current.__class__.__name__
            if name in seen:  # protege contre les boucles de dissection
                break
            seen.add(name)
            names.append(name)
            current = current.payload if current.payload and current.payload.__class__ is not type(None) else None
            if getattr(current, "name", "") == "NoPayload":
                break
        return names[:12]

    # ------------------------------------------------------------------
    def _parse_l3_l4(self, pkt: Packet, r: PacketRecord) -> None:
        """Remplit les couches reseau et transport."""
        if ARP in pkt:
            arp = pkt[ARP]
            r.protocol, r.transport = "ARP", "ARP"
            r.src = str(arp.psrc)
            r.dst = str(arp.pdst)
            op = "requete" if arp.op == 1 else "reponse"
            r.info = f"ARP {op} : qui possede {arp.pdst} ? dit {arp.psrc}"
            return

        if IP in pkt:
            ip = pkt[IP]
            r.src, r.dst = str(ip.src), str(ip.dst)
            r.ttl = int(ip.ttl)
            r.protocol = "IP"
        elif IPv6 in pkt:
            ip6 = pkt[IPv6]
            r.src, r.dst = str(ip6.src), str(ip6.dst)
            r.ttl = int(ip6.hlim)
            r.protocol = "IPv6"
        elif Ether in pkt:
            eth = pkt[Ether]
            r.src, r.dst = str(eth.src), str(eth.dst)
            r.protocol = "Ethernet"
            return
        else:
            r.protocol = "Non IP"
            return

        if TCP in pkt:
            tcp = pkt[TCP]
            r.transport = "TCP"
            r.protocol = "TCP"
            r.src_port, r.dst_port = int(tcp.sport), int(tcp.dport)
            r.tcp_flags = str(tcp.flags)
            r.tcp_seq = int(tcp.seq)
            payload = _safe_bytes(pkt)
            r.payload_len = len(payload)
        elif UDP in pkt:
            udp = pkt[UDP]
            r.transport = "UDP"
            r.protocol = "UDP"
            r.src_port, r.dst_port = int(udp.sport), int(udp.dport)
            r.payload_len = max(0, len(udp.payload))
        elif ICMP in pkt:
            icmp = pkt[ICMP]
            r.transport, r.protocol = "ICMP", "ICMP"
            types = {0: "echo reply", 3: "destination injoignable",
                     8: "echo request (ping)", 11: "TTL depasse"}
            r.info = types.get(int(icmp.type), f"ICMP type {icmp.type}")
        else:
            r.transport = None

    # ------------------------------------------------------------------
    def _infer_application(self, pkt: Packet, r: PacketRecord) -> None:
        """Determine le protocole applicatif a partir de la structure reelle."""
        # --- DNS ---
        # ATTENTION : dans Scapy 2.8, `dns.qd` n'est PAS une instance de DNSQR
        # mais un objet liste interne. Un test `isinstance` rejetterait donc
        # silencieusement toutes les requetes. On interroge donc la structure
        # par ses attributs, ce qui reste valable quelle que soit la version.
        if DNS in pkt:
            dns = pkt[DNS]
            r.protocol = "DNS"
            # qr = 0 pour une question, 1 pour une reponse. Cette distinction
            # compte : demander « qui propose Spotify ? » n'a pas le meme sens
            # que repondre « moi, je propose Spotify ».
            try:
                r.dns_is_query = int(getattr(dns, "qr", 0)) == 0
            except Exception:
                r.dns_is_query = None
            try:
                question = dns.qd
                if question is not None and hasattr(question, "qname"):
                    raw_name = question.qname
                    if isinstance(raw_name, (bytes, bytearray)):
                        raw_name = raw_name.decode("ascii", errors="replace")
                    r.dns_query = str(raw_name).rstrip(".").lower() or None
            except Exception:
                r.dns_query = None
            return

        # --- DHCP ---
        if DHCP in pkt:
            r.protocol = "DHCP"
            return
        if BOOTP in pkt and r.transport == "UDP":
            r.protocol = "DHCP"
            return

        if r.transport != "TCP":
            return

        payload = _safe_bytes(pkt)
        if not payload:
            return

        # --- TLS ---
        # Un enregistrement TLS commence par un octet de type (0x14 a 0x17)
        # suivi de la version majeure 0x03. On ne se fie donc pas au seul port,
        # ce qui autorise la detection meme sur un port inhabituel, et on ne
        # l'exige pas non plus, ce qui autorise la detection du trafic chiffre
        # sur les ports standards d'autres services.
        looks_like_tls = (
            len(payload) >= 5
            and payload[0] in (0x14, 0x15, 0x16, 0x17)
            and payload[1] == 0x03
        )
        on_tls_port = r.dst_port in _TLS_PORTS or r.src_port in _TLS_PORTS

        if looks_like_tls and (on_tls_port or payload[0] == 0x16):
            r.protocol = "TLS"
            if payload[0] == 0x16:
                r.tls_sni = extract_tls_sni(payload)
            return

        # --- HTTP en clair ---
        if r.dst_port in _HTTP_PORTS or payload.startswith(_HTTP_METHODS):
            host = extract_http_host(payload)
            if host:
                r.protocol = "HTTP"
                r.http_host = host
                return

    # ------------------------------------------------------------------
    def _direction(self, r: PacketRecord) -> str:
        """Qualifie le sens du paquet vu depuis la machine locale."""
        src_local, dst_local = self.is_local(r.src), self.is_local(r.dst)
        if src_local and dst_local:
            return "interne"
        if src_local:
            return "sortant"
        if dst_local:
            return "entrant"
        return "traverse" if classify_address(r.src) == "public" else "inconnu"

    # ------------------------------------------------------------------
    @staticmethod
    def _summary(r: PacketRecord) -> str:
        """Resume lisible d'un paquet, dans l'esprit d'un outil d'analyse."""
        if r.info:
            return r.info

        left = f"{r.src}" + (f":{r.src_port}" if r.src_port else "")
        right = f"{r.dst}" + (f":{r.dst_port}" if r.dst_port else "")

        detail = ""
        if r.protocol == "TLS":
            detail = f" ClientHello pour {r.tls_sni}" if r.tls_sni else " en-tete TLS"
        elif r.protocol == "HTTP":
            detail = f" hote {r.http_host}" if r.http_host else ""
        elif r.protocol == "DNS" and r.dns_query:
            detail = f" requete {r.dns_query}"
        elif r.tcp_flags:
            detail = f" [{r.tcp_flags}]"

        return f"{r.protocol} {left} > {right}{detail}"


def app_protocol_info(name: str | None):
    """Retourne la fiche descriptive d'un protocole applicatif."""
    if not name:
        return None
    return APP_PROTOCOLS.get(name)
