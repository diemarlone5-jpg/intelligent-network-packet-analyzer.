"""Tests du format PCAP.

Le risque, avec un format binaire, est de produire un fichier qui « a l'air »
correct : bonne taille, bon magic, mais que Wireshark refuse ou interprete de
travers. On verifie donc aussi le fichier avec un lecteur ecrit par d'autres
(Scapy), pas seulement avec notre propre code.
"""

from __future__ import annotations

import struct

import pytest

from app.analysis.pcap import (
    LINKTYPE_ETHERNET,
    LINKTYPE_IP,
    Enregistrement,
    PcapErreur,
    deviner_type_lien,
    ecrire_pcap,
    horodatage_lisible,
    lire_pcap,
)


# --------------------------------------------------------------- fabriques

def trame_ethernet(payload: bytes = b"salut") -> bytes:
    """Une trame Ethernet minimale et credible (EtherType IPv4)."""
    return (b"\x94\x08\x53\x96\x90\x9b"      # destination
            b"\x02\x95\x89\xb7\x46\xc0"      # source
            b"\x08\x00"                      # EtherType : IPv4
            + payload)


def paquet_ip(protocole: int = 6) -> bytes:
    """Un en-tete IPv4 minimal (version 4, longueur 20, protocole donne)."""
    return bytes([0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
                  0x40, protocole, 0x00, 0x00,
                  0xC0, 0xA8, 0x01, 0x0A,      # 192.168.1.10
                  0x08, 0x08, 0x08, 0x08])     # 8.8.8.8


# --------------------------------------------------- detection du type lien

def test_une_trame_ethernet_est_reconnue():
    assert deviner_type_lien([trame_ethernet()]) == LINKTYPE_ETHERNET


def test_un_paquet_ip_brut_est_reconnu():
    assert deviner_type_lien([paquet_ip()]) == LINKTYPE_IP


def test_le_type_de_lien_regarde_plusieurs_paquets():
    """Le premier paquet peut etre trop court ; on ne conclut pas trop vite."""
    assert deviner_type_lien([b"\x00\x01", trame_ethernet()]) == LINKTYPE_ETHERNET


def test_une_liste_vide_ne_plante_pas():
    assert deviner_type_lien([]) == LINKTYPE_IP


# ---------------------------------------------------------------- aller-retour

def test_aller_retour_conserve_les_octets_et_les_instants():
    originaux = [
        Enregistrement(ts=1759000000.123456, donnees=trame_ethernet(b"un")),
        Enregistrement(ts=1759000001.654321, donnees=trame_ethernet(b"deux")),
    ]
    type_lien, relus = lire_pcap(ecrire_pcap(originaux))

    assert type_lien == LINKTYPE_ETHERNET
    assert len(relus) == 2
    for attendu, obtenu in zip(originaux, relus):
        assert obtenu.donnees == attendu.donnees
        assert obtenu.ts == pytest.approx(attendu.ts, abs=1e-6)


def test_le_fichier_produit_est_un_vrai_pcap():
    donnees = ecrire_pcap([Enregistrement(ts=1759000000.0, donnees=trame_ethernet())])

    magic, majeur, mineur, _, _, snaplen, type_lien = struct.unpack("<IHHiIII", donnees[:24])
    assert magic == 0xA1B2C3D4        # magic attendu par libpcap
    assert (majeur, mineur) == (2, 4)
    assert snaplen == 65535
    assert type_lien == LINKTYPE_ETHERNET
    # En-tete global + en-tete de paquet + octets.
    assert len(donnees) == 24 + 16 + len(trame_ethernet())


def test_le_fichier_est_lisible_par_un_lecteur_independant():
    """Verification par Scapy, qui n'est pas notre code.

    C'est la preuve qui compte : un fichier lu par un autre outil ne peut pas
    etre un format « maison » qui se contente de se relire lui-meme.
    """
    scapy = pytest.importorskip("scapy.all", reason="Scapy absent de cet environnement")

    originaux = [
        Enregistrement(ts=1759000000.5, donnees=trame_ethernet(b"alpha")),
        Enregistrement(ts=1759000001.25, donnees=trame_ethernet(b"beta")),
    ]
    chemin = _fichier_temporaire(ecrire_pcap(originaux))

    try:
        lus = scapy.rdpcap(str(chemin))
    finally:
        chemin.unlink(missing_ok=True)

    assert len(lus) == 2
    for attendu, obtenu in zip(originaux, lus):
        assert bytes(obtenu) == attendu.donnees
        assert float(obtenu.time) == pytest.approx(attendu.ts, abs=1e-6)


def _fichier_temporaire(donnees: bytes):
    """Ecrit les octets dans un fichier temporaire et rend son chemin.

    mkstemp ouvre le fichier et rend un descripteur : sur Windows, tant qu'il
    n'est pas ferme, le fichier reste verrouille et personne ne peut le rouvrir.
    """
    import os
    import tempfile
    from pathlib import Path

    descripteur, nom = tempfile.mkstemp(suffix=".pcap")
    os.close(descripteur)
    chemin = Path(nom)
    chemin.write_bytes(donnees)
    return chemin


def test_la_taille_d_origine_est_conservee():
    """Un paquet tronque a la capture doit garder sa taille reelle sur le fil."""
    entree = Enregistrement(ts=1.0, donnees=trame_ethernet()[:16], taille_origine=1500)
    _, relus = lire_pcap(ecrire_pcap([entree]))
    assert relus[0].taille_origine == 1500
    assert len(relus[0].donnees) == 16


def test_la_taille_d_origine_se_deduit_quand_on_ne_la_donne_pas():
    """L'appelant ne doit pas avoir a calculer une evidence."""
    _, relus = lire_pcap(ecrire_pcap([Enregistrement(ts=1.0, donnees=trame_ethernet())]))
    assert relus[0].taille_origine == len(trame_ethernet())


def test_un_arrondi_de_microsecondes_ne_deborde_pas():
    """0.9999999 s arrondi ne doit pas produire 1 000 000 microsecondes."""
    _, relus = lire_pcap(ecrire_pcap([Enregistrement(ts=1759000000.9999999,
                                                    donnees=trame_ethernet())]))
    assert relus[0].ts == pytest.approx(1759000001.0, abs=1e-6)


def test_une_liste_vide_produit_un_fichier_valide():
    _, relus = lire_pcap(ecrire_pcap([]))
    assert relus == []


# ------------------------------------------------------------------ lecture

def test_un_fichier_trop_court_est_refuse():
    with pytest.raises(PcapErreur, match="trop court"):
        lire_pcap(b"\x00" * 10)


def test_un_fichier_etranger_est_refuse_avec_un_message_clair():
    with pytest.raises(PcapErreur, match="pas au format PCAP"):
        lire_pcap(b"GET / HTTP/1.1\r\nHost: exemple.fr\r\n\r\n" + b"\x00" * 40)


def test_un_fichier_tronque_est_signale():
    complet = ecrire_pcap([Enregistrement(ts=1.0, donnees=trame_ethernet())])
    with pytest.raises(PcapErreur, match="tronqu"):
        lire_pcap(complet[:-5])


def test_un_fichier_en_gros_boutiste_est_lu():
    """Le format autorise les deux ordres d'octets : on doit lire les deux."""
    donnees = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)
    donnees += struct.pack(">IIII", 1759000000, 500000,
                           len(trame_ethernet()), len(trame_ethernet()))
    donnees += trame_ethernet()

    type_lien, relus = lire_pcap(donnees)
    assert type_lien == LINKTYPE_ETHERNET
    assert len(relus) == 1
    assert relus[0].ts == pytest.approx(1759000000.5, abs=1e-6)


def test_un_fichier_en_nanosecondes_est_lu():
    """Variante en nanosecondes, ecrite par certaines versions de libpcap."""
    donnees = struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)
    donnees += struct.pack("<IIII", 1759000000, 500_000_000,
                           len(trame_ethernet()), len(trame_ethernet()))
    donnees += trame_ethernet()

    _, relus = lire_pcap(donnees)
    assert relus[0].ts == pytest.approx(1759000000.5, abs=1e-6)


def test_le_magic_ecrit_est_celui_attendu_pour_un_fichier_petit_boutiste():
    """Le magic doit etre la VALEUR 0xA1B2C3D4 ecrite en petit-boutiste, soit
    les octets D4 C3 B2 A1. Se tromper ici produit un fichier dont l'en-tete
    annonce un ordre et dont le contenu en utilise un autre."""
    donnees = ecrire_pcap([Enregistrement(ts=1.0, donnees=trame_ethernet())])
    assert donnees[:4] == b"\xd4\xc3\xb2\xa1"


def test_un_fichier_pcapng_est_signale_comme_tel():
    """PCAPNG est le format recent de Wireshark : dire « magic invalide » ne
    rendrait pas service a l'utilisateur."""
    with pytest.raises(PcapErreur, match="PCAPNG"):
        lire_pcap(struct.pack("<I", 0x0A1A2B3C) + b"\x00" * 24)


# -------------------------------------------------------------- horodatage

def test_l_horodatage_est_en_utc_et_comparable():
    """On s'appuie sur des instants dont la date est connue et verifiable,
    plutot que sur une conversion que j'aurais calculee de tete."""
    assert horodatage_lisible(0) == "1970-01-01 00:00:00.000"
    assert horodatage_lisible(1_000_000_000) == "2001-09-09 01:46:40.000"
    assert horodatage_lisible(1_000_000_000.5) == "2001-09-09 01:46:40.500"
