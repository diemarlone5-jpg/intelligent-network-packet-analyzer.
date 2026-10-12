"""Tests du filtre d'affichage (« Apply a display filter » de Wireshark).

Le point le plus important : une expression invalide doit etre REFUSEE avec un
message clair, jamais donnee pour un filtre qui ne trouve rien. Un utilisateur
qui ecrit « tcp.pot == 443 » doit savoir qu'il s'est trompe, pas croire que le
reseau est vide.
"""

from __future__ import annotations

import pytest

from app.analysis.display_filter import (
    FilterSyntaxError,
    compile_filter,
    describe_syntax,
)
from app.models import PacketRecord


def pkt(**kwargs) -> PacketRecord:
    base = dict(number=1, ts=1000.0, src="192.168.1.5", dst="149.154.166.110",
                protocol="TCP", size=100, info="TCP 192.168.1.5:5000 > 149.154.166.110:443 [A]")
    base.update(kwargs)
    return PacketRecord(**base)


def accepte(expression: str, record: PacketRecord) -> bool:
    return compile_filter(expression)(record)


# --------------------------------------------------------------------------
# Expression vide
# --------------------------------------------------------------------------


@pytest.mark.parametrize("expression", [None, "", "   "])
def test_expression_vide_accepte_tout(expression):
    assert accepte(expression, pkt()) is True


# --------------------------------------------------------------------------
# Protocoles
# --------------------------------------------------------------------------


def test_un_protocole_simple():
    assert accepte("tcp", pkt(protocol="TCP")) is True
    assert accepte("tcp", pkt(protocol="DNS", transport="UDP")) is False


def test_le_transport_est_pris_en_compte():
    """Un paquet TLS reste du TCP : c'est la couche qui le porte."""
    assert accepte("tcp", pkt(protocol="TLS", transport="TCP")) is True
    assert accepte("udp", pkt(protocol="QUIC", transport="UDP")) is True


def test_insensible_a_la_casse():
    assert accepte("TCP", pkt(protocol="TCP")) is True
    assert accepte("Tcp", pkt(protocol="TCP")) is True


def test_quic_est_filtrable():
    """Le cas YouTube : sans cela, on ne peut pas isoler le flux video."""
    assert accepte("quic", pkt(protocol="QUIC", transport="UDP")) is True


# --------------------------------------------------------------------------
# Operateurs logiques
# --------------------------------------------------------------------------


def test_negation():
    assert accepte("not arp", pkt(protocol="TCP")) is True
    assert accepte("not arp", pkt(protocol="ARP")) is False


def test_et():
    a = pkt(protocol="TCP", dst_port=443)
    assert accepte("tcp and port == 443", a) is True
    assert accepte("tcp and port == 80", a) is False


def test_ou():
    assert accepte("dns or arp", pkt(protocol="DNS")) is True
    assert accepte("dns or arp", pkt(protocol="ARP")) is True
    assert accepte("dns or arp", pkt(protocol="TCP")) is False


def test_parentheses():
    a = pkt(protocol="TCP", size=2000)
    assert accepte("(tcp or udp) and size > 1000", a) is True
    assert accepte("(dns or arp) and size > 1000", a) is False


def test_symboles_logiques():
    a = pkt(protocol="TCP", dst_port=443)
    assert accepte("tcp && port == 443", a) is True
    assert accepte("dns || arp", pkt(protocol="DNS")) is True
    assert accepte("! arp", pkt(protocol="TCP")) is True


# --------------------------------------------------------------------------
# Champs
# --------------------------------------------------------------------------


def test_adresse_source_ou_destination():
    a = pkt(src="192.168.1.5", dst="8.8.8.8")
    assert accepte("ip.addr == 8.8.8.8", a) is True
    assert accepte("ip.addr == 192.168.1.5", a) is True
    assert accepte("ip.addr == 1.1.1.1", a) is False


def test_adresse_source_seulement():
    a = pkt(src="192.168.1.5", dst="8.8.8.8")
    assert accepte("ip.src == 192.168.1.5", a) is True
    assert accepte("ip.src == 8.8.8.8", a) is False


def test_adresse_destination_seulement():
    a = pkt(src="192.168.1.5", dst="8.8.8.8")
    assert accepte("ip.dst == 8.8.8.8", a) is True
    assert accepte("ip.dst == 192.168.1.5", a) is False


def test_port_dans_les_deux_sens():
    """Sinon la moitie d'une conversation disparaitrait du resultat."""
    demande = pkt(src_port=50000, dst_port=443)
    reponse = pkt(src_port=443, dst_port=50000)
    assert accepte("port == 443", demande) is True
    assert accepte("port == 443", reponse) is True


def test_port_tcp_ne_prend_pas_udp():
    assert accepte("tcp.port == 443", pkt(transport="TCP", dst_port=443)) is True
    assert accepte("tcp.port == 443", pkt(transport="UDP", dst_port=443)) is False


def test_taille():
    assert accepte("size > 500", pkt(size=1000)) is True
    assert accepte("size > 500", pkt(size=100)) is False
    assert accepte("size >= 100", pkt(size=100)) is True
    assert accepte("size <= 100", pkt(size=100)) is True


def test_contient_du_texte():
    assert accepte('contains "telegram"', pkt(info="TLS vers api.telegram.org")) is True
    assert accepte('contains "telegram"', pkt(info="TLS vers wikipedia.org")) is False


def test_domaine():
    a = pkt(tls_sni="api.telegram.org")
    assert accepte("domain == api.telegram.org", a) is True
    assert accepte("domain == youtube.com", a) is False


# --------------------------------------------------------------------------
# Expressions invalides : doivent etre refusees, jamais ignorees
# --------------------------------------------------------------------------


@pytest.mark.parametrize("expression", [
    "tcp.pot == 443",          # champ inexistant
    "cafe",                    # protocole inexistant
    "tcp and",                 # condition manquante
    "ip.addr ==",              # valeur manquante
    "(tcp or udp",             # parenthese non fermee
    "size > abc",              # nombre attendu
    "and tcp",                 # commence par un operateur
])
def test_expression_invalide_refusee(expression):
    with pytest.raises(FilterSyntaxError):
        compile_filter(expression)


def test_le_message_d_erreur_est_utile():
    with pytest.raises(FilterSyntaxError) as erreur:
        compile_filter("tcp.pot == 443")
    message = str(erreur.value)
    assert "tcp.pot" in message
    assert "ip.addr" in message  # propose des champs valides


def test_un_protocole_inconnu_propose_des_pistes():
    with pytest.raises(FilterSyntaxError) as erreur:
        compile_filter("tcpp")
    assert "tcp" in str(erreur.value)


# --------------------------------------------------------------------------
# Robustesse
# --------------------------------------------------------------------------


def test_un_paquet_sans_ports_ne_fait_pas_echouer():
    a = pkt(protocol="ARP", transport="ARP", src_port=None, dst_port=None)
    assert accepte("port == 443", a) is False
    assert accepte("not arp", a) is False


def test_un_resume_absent_ne_fait_pas_echouer():
    a = pkt(info="")
    assert accepte('contains "x"', a) is False


def test_les_champs_absents_sont_traites_comme_vides():
    a = pkt(tls_sni=None, dns_query=None, http_host=None)
    assert accepte("domain == x", a) is False


def test_la_description_de_syntaxe_est_complete():
    description = describe_syntax()
    assert "tcp" in description["protocoles"]
    assert "ip.addr" in description["champs"]
    assert description["exemples"]
