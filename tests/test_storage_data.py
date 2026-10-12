"""Tests de la gestion des donnees conservees (taille, purge, compactage).

Le risque, avec une purge, n'est pas de mal calculer : c'est de supprimer plus
que demande. Ces tests verifient donc surtout ce qui RESTE, pas seulement ce qui
disparait. Une suppression qui laisse des lignes orphelines ferait grossir la
base au lieu de la vider, sans que personne ne s'en apercoive.
"""

from __future__ import annotations

import pytest

from app.models import Flow, PacketRecord
from app.storage.sqlite_repo import SqliteRepository


@pytest.fixture
def depot(tmp_path):
    entonnoir = SqliteRepository(tmp_path / "donnees.db")
    entonnoir.init_schema()
    return entonnoir


def remplir(depot, nombre_sessions: int, paquets_par_session: int = 5) -> list[int]:
    """Cree des sessions, chacune avec des paquets et une communication."""
    identifiants = []
    for i in range(nombre_sessions):
        session = depot.create_session(mode="local", interface="iface",
                                       interface_name="Wi-Fi", filter="")
        identifiants.append(session)
        depot.save_packets(session, [
            PacketRecord(number=n, ts=1000.0 + n, src="192.168.1.10",
                         dst="1.1.1.1", protocol="TCP", size=100 + n)
            for n in range(paquets_par_session)
        ])
        depot.save_flows(session, [
            Flow(key="f%d" % i, src="192.168.1.10", dst="1.1.1.1", src_port=1000,
                 dst_port=443, transport="TCP", first_seen=1000.0, last_seen=1001.0,
                 packets=paquets_par_session, bytes_total=500)
        ])
        depot.close_session(session, packets=paquets_par_session, bytes_total=500,
                            flows=1, events=0)
    return identifiants


# ------------------------------------------------------------------- rapport

def test_le_rapport_indique_la_taille_et_les_lignes(depot):
    remplir(depot, 3, paquets_par_session=4)
    rapport = depot.storage_report()

    assert rapport["bytes"] > 0
    assert rapport["rows"]["capture_sessions"] == 3
    assert rapport["rows"]["packets"] == 12
    assert rapport["rows"]["flows"] == 3


def test_une_base_neuve_n_a_aucune_ligne_orpheline(depot):
    assert depot.count_orphans() == 0


def test_l_insertion_normale_ne_cree_pas_d_orphelines(depot):
    remplir(depot, 2, paquets_par_session=3)
    assert depot.count_orphans() == 0


# --------------------------------------------------------------------- purge

def test_la_purge_garde_les_sessions_les_plus_recentes(depot):
    identifiants = remplir(depot, 6)
    resultat = depot.purge_old_sessions(keep=2)

    assert resultat["removed"] == 4
    assert resultat["kept"] == 2
    assert resultat["total_before"] == 6

    restantes = [ligne["id"] for ligne in depot.list_sessions(limit=50)]
    assert sorted(restantes) == sorted(identifiants[-2:])


def test_la_purge_supprime_les_paquets_et_communications_associes(depot):
    """Ce qui compte n'est pas que la session disparaisse, mais que TOUT ce qui
    s'y rattache disparaisse : sinon la base grossit au lieu de se vider."""
    remplir(depot, 5, paquets_par_session=4)
    depot.purge_old_sessions(keep=1)

    rapport = depot.storage_report()
    assert rapport["rows"]["capture_sessions"] == 1
    assert rapport["rows"]["packets"] == 4
    assert rapport["rows"]["flows"] == 1
    assert depot.count_orphans() == 0


def test_la_purge_ne_supprime_rien_si_le_nombre_demande_est_superieur(depot):
    identifiants = remplir(depot, 3)
    resultat = depot.purge_old_sessions(keep=10)

    assert resultat["removed"] == 0
    assert resultat["kept"] == 3
    assert len(depot.list_sessions(limit=50)) == 3


def test_la_purge_avec_garde_zero_ne_laisse_aucune_session(depot):
    remplir(depot, 3)
    resultat = depot.purge_old_sessions(keep=0)

    assert resultat["removed"] == 3
    assert depot.list_sessions(limit=50) == []
    assert depot.count_orphans() == 0


def test_une_garde_negative_est_traitee_comme_zero(depot):
    """Une valeur absurde ne doit pas tout emporter ni lever : on la ramene a
    zero, ce qui est explicite."""
    remplir(depot, 2)
    resultat = depot.purge_old_sessions(keep=-5)
    assert resultat["removed"] == 2
    assert depot.list_sessions(limit=50) == []


def test_la_purge_sur_une_base_vide_ne_plante_pas(depot):
    resultat = depot.purge_old_sessions(keep=5)
    assert resultat["removed"] == 0
    assert resultat["kept"] == 0


# ---------------------------------------------------------------- compactage

def test_le_compactage_reduit_la_taille_apres_une_purge(depot):
    """Supprimer des lignes ne reduit pas le fichier : SQLite reutilise les pages
    liberees. Sans compactage, l'utilisateur supprimerait ses donnees sans voir
    la taille diminuer, et croirait que rien ne s'est passe."""
    remplir(depot, 8, paquets_par_session=200)
    avant = depot.storage_report()["bytes"]

    depot.purge_old_sessions(keep=1)
    apres_purge = depot.storage_report()
    assert apres_purge["free_bytes"] > 0, "aucune page liberee : test sans objet"

    depot.vacuum()
    apres_compactage = depot.storage_report()["bytes"]

    assert apres_compactage < avant
    assert apres_compactage <= apres_purge["bytes"]


def test_les_donnees_survivent_au_compactage(depot):
    remplir(depot, 3, paquets_par_session=4)
    depot.purge_old_sessions(keep=1)
    depot.vacuum()

    rapport = depot.storage_report()
    assert rapport["rows"]["capture_sessions"] == 1
    assert rapport["rows"]["packets"] == 4
    assert depot.count_orphans() == 0
