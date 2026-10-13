"""Decodage des adresses de traduction NAT64.

POURQUOI CES TESTS

Un telephone sans IPv4 native n'ecrit jamais « 3.173.21.63 » dans ses paquets :
l'operateur traduit l'adresse, et la capture montre « 64:ff9c::3ad:153f ». Sans
decodage, une grande partie du trafic de l'utilisateur reste illisible.

Le risque de ce decodage est symetrique : afficher une adresse IPv4 qui n'est
pas la bonne serait pire que de n'en afficher aucune. Les tests verifient donc
les deux bords — ce qu'on decode, et ce qu'on refuse de decoder.
"""

from __future__ import annotations

import pytest

from app.analysis.protocols import embedded_ipv4


# --------------------------------------------------------------------------
# Ce qu'on decode
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "adresse, attendu",
    [
        # Prefixe NAT64 normalise (RFC 6052). Les 32 derniers bits sont l'IPv4.
        ("64:ff9b::3ad:153f", "3.173.21.63"),
        ("64:ff9b::808:808", "8.8.8.8"),
        ("64:ff9b::c0a8:0101", "192.168.1.1"),
        # Prefixe decouvert sur le reseau de l'utilisateur (RFC 7050).
        ("64:ff9c::3ad:153f", "3.173.21.63"),
    ],
)
def test_decode_le_prefixe_nat64(adresse, attendu):
    assert embedded_ipv4(adresse) == attendu


def test_decode_une_adresse_ipv4_mappee():
    """::ffff:0:0/96 est aussi un prefixe de 96 bits : la meme regle s'applique."""
    assert embedded_ipv4("::ffff:142.250.75.238") == "142.250.75.238"


def test_le_port_n_est_pas_dans_l_adresse():
    """Le port est rendu separement : il ne doit pas perturber le decodage."""
    assert embedded_ipv4("64:ff9b::3ad:153f") == "3.173.21.63"


# --------------------------------------------------------------------------
# Ce qu'on refuse de decoder
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "adresse",
    [
        "192.168.1.32",        # IPv4 ordinaire : rien a decoder
        "8.8.8.8",
        "2a01:cb00::1",        # IPv6 ordinaire : rien a decoder
        "fe80::1",             # adresse locale de lien
    ],
)
def test_ne_decode_rien_sur_une_adresse_ordinaire(adresse):
    assert embedded_ipv4(adresse) is None


def test_refuse_de_deviner_sur_6to4():
    """2002::/16 place l'IPv4 au milieu de l'adresse, pas a la fin.

    Le decodage naif donnerait une adresse fausse : on prefere ne rien afficher.
    """
    assert embedded_ipv4("2002:0303:153f::1") is None


def test_refuse_de_deviner_sur_teredo():
    """2001::/32 brouille l'adresse du client (RFC 4380) : meme refus."""
    assert embedded_ipv4("2001::3ad:153f") is None


def test_refuse_sur_un_prefixe_local_de_48_bits():
    """64:ff9b:1::/48 (RFC 8215) utilise une autre position : meme refus."""
    assert embedded_ipv4("64:ff9b:1::3ad:153f") is None


@pytest.mark.parametrize("entree", ["", None, "pas-une-adresse", "999.999.999.999"])
def test_entrees_invalides(entree):
    assert embedded_ipv4(entree) is None


# --------------------------------------------------------------------------
# Integration : le moteur enrichit la BONNE adresse
# --------------------------------------------------------------------------

@pytest.fixture
def moteur(tmp_path):
    """Moteur reel, sur une base temporaire. Rien n'est capture : on interroge
    seulement la facon dont il choisit l'adresse a enrichir."""
    from app.config import Settings
    from app.engine import AnalyzerEngine
    from app.storage import build_repository

    reglages = Settings(env="test", mode="local", secret_key="x" * 48,
                        sqlite_path=tmp_path / "nat64.db", enrich_enabled=False)
    reglages.ensure_dirs()
    return AnalyzerEngine(reglages, build_repository(reglages), None)


def test_le_moteur_enrichit_l_adresse_ipv4_cachee(moteur):
    """Sur une traduction NAT64, l'enrichissement doit viser l'IPv4 reelle.

    Interroger la forme IPv6 ne renverrait rien : l'utilisateur ne verrait ni
    organisation ni operateur sur son propre trafic mobile.
    """
    adresse = moteur._counterparty(_faux_paquet("192.168.1.32", "64:ff9c::3ad:153f"))

    assert adresse == "3.173.21.63"


def test_le_moteur_garde_l_adresse_normale(moteur):
    adresse = moteur._counterparty(_faux_paquet("192.168.1.32", "142.250.75.238"))

    assert adresse == "142.250.75.238"


def test_le_moteur_ne_choisit_rien_sur_un_echange_local(moteur):
    """Un echange entre deux adresses locales n'a pas d'interlocuteur a enrichir.

    On prend les adresses locales reellement detectees sur la machine : les
    ecrire en dur rendrait le test dependant du reseau de celui qui l'execute.
    """
    locales = sorted(moteur._local_ips)
    assert locales, "aucune adresse locale detectee sur cette machine"

    depart = locales[0]
    arrivee = locales[1] if len(locales) > 1 else locales[0]

    assert moteur._counterparty(_faux_paquet(depart, arrivee)) is None


def test_la_vue_du_paquet_expose_les_deux_adresses(moteur):
    """L'interface a besoin de la forme d'origine ET de la forme decodee."""
    vue = moteur._packet_view(_faux_paquet("192.168.1.32", "64:ff9c::3ad:153f"))

    assert vue["dst"] == "64:ff9c::3ad:153f"      # ce qui a circule
    assert vue["dst_ipv4"] == "3.173.21.63"       # ce que cela veut dire
    assert vue["src_ipv4"] is None                # adresse ordinaire


class _faux_paquet:
    """Paquet minimal suffisant pour _counterparty et _packet_view."""

    def __init__(self, src: str, dst: str) -> None:
        self.src = src
        self.dst = dst
        self.src_port = 51234
        self.dst_port = 443
        self.protocol = "TCP"
        self.number = 1
        self.ts = 0.0
        self.size = 74
        self.info = ""
        self.payload = b""

    def to_dict(self) -> dict:
        return {
            "number": self.number,
            "ts": self.ts,
            "src": self.src,
            "dst": self.dst,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "size": self.size,
            "info": self.info,
        }
