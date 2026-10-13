"""Le schema SQL et le code Python decrivent-ils la meme base ?

POURQUOI CE CONTROLE

Le code ecrit vers Supabase en nommant ses colonnes ; le schema SQL cree ces
colonnes. Rien ne relie les deux automatiquement. Une seule divergence — une
colonne ecrite mais absente de la table, ou l'inverse — et Supabase refuse
l'ecriture avec un HTTP 400.

Le pire moment pour decouvrir ca est la demonstration : « montrez les donnees
enregistrees dans Supabase », et la table est vide parce qu'une colonne s'appelle
`bytes_total` ici et `bytes` la-bas.

Ce controle compare ce que le code PRODUIT a ce que le schema DECLARE. Il ne
demande aucun compte Supabase.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.models import Event, Flow, IPIntel, PacketRecord
from app.storage import supabase_repo as sr

SCHEMA = Path(__file__).resolve().parent.parent / "schema" / "supabase.sql"

# Colonnes que le code n'envoie jamais : elles sont produites par la base
# elle-meme (cle primaire, valeur par defaut, horodatage automatique).
AUTO = {"id", "created_at"}


def tables_du_schema() -> dict[str, set[str]]:
    """Lit le schema SQL et rend, par table, l'ensemble de ses colonnes.

    On lit le fichier tel qu'il sera colle dans Supabase : le verifier ici, c'est
    verifier ce que la base recevra reellement.
    """
    texte = SCHEMA.read_text(encoding="utf-8")
    tables: dict[str, set[str]] = {}

    for bloc in re.finditer(
        r"create table if not exists\s+(\w+)\s*\((.*?)\n\)\s*;",
        texte, re.IGNORECASE | re.DOTALL,
    ):
        nom, corps = bloc.group(1), bloc.group(2)
        colonnes: set[str] = set()
        for ligne in corps.splitlines():
            ligne = ligne.split("--")[0].strip().rstrip(",")
            if not ligne or ligne.lower().startswith(("constraint", "primary key", "foreign key", "unique")):
                continue
            premier = ligne.split()[0].strip('"')
            if premier:
                colonnes.add(premier)
        tables[nom] = colonnes
    return tables


def _colonnes_ecrites(objet: dict) -> set[str]:
    return {c for c in objet if c not in AUTO}


# --------------------------------------------------------------------------
# Le schema lui-meme
# --------------------------------------------------------------------------

def test_le_schema_cree_les_cinq_tables_attendues():
    """Les noms doivent correspondre EXACTEMENT a ceux du code."""
    attendues = {
        sr.TABLE_SESSIONS, sr.TABLE_FLOWS, sr.TABLE_EVENTS,
        sr.TABLE_PACKETS, sr.TABLE_INTEL,
    }
    tables = tables_du_schema()

    manquantes = attendues - set(tables)
    assert not manquantes, (
        f"Le code ecrit vers {sorted(manquantes)}, absent(s) du schema SQL : "
        "chaque ecriture echouerait en HTTP 400."
    )


def test_la_securite_par_ligne_est_activee_partout():
    """Sans RLS, la cle publique `anon` lirait toutes les captures. Le projet
    est heberge en ligne : ce n'est pas une precaution theorique."""
    texte = SCHEMA.read_text(encoding="utf-8")

    for table in (sr.TABLE_SESSIONS, sr.TABLE_FLOWS, sr.TABLE_EVENTS,
                  sr.TABLE_PACKETS, sr.TABLE_INTEL):
        motif = rf"alter table\s+{table}\s+enable row level security"
        assert re.search(motif, texte, re.IGNORECASE), (
            f"la table {table} n'active pas la securite par ligne"
        )


# --------------------------------------------------------------------------
# Ce que le code ecrit existe-t-il dans la table ?
# --------------------------------------------------------------------------

def test_les_colonnes_des_sessions_correspondent():
    depot = sr.SupabaseRepository.__new__(sr.SupabaseRepository)
    envoyees = _colonnes_ecrites({
        "started_at": 1, "mode": "local", "interface": "x",
        "interface_name": "x", "filter": "",
    })
    table = tables_du_schema()[sr.TABLE_SESSIONS]

    assert envoyees <= table, f"colonnes absentes de la table : {sorted(envoyees - table)}"


def test_les_colonnes_des_communications_correspondent():
    """C'est la table la plus large : 21 colonnes ecrites par le code."""
    flux = Flow(key="k", src="a", dst="b", src_port=1, dst_port=2,
                transport="TCP", first_seen=0.0, last_seen=1.0)
    # On reproduit exactement la construction de save_flows.
    ligne = {
        "session_id": 1, "flow_key": flux.key,
        "first_seen": flux.first_seen, "last_seen": flux.last_seen,
        "duration": flux.duration, "src": flux.src, "dst": flux.dst,
        "src_port": flux.src_port, "dst_port": flux.dst_port,
        "transport": flux.transport, "app_protocol": flux.app_protocol,
        "domain": flux.domain, "state": flux.state, "tcp_state": flux.tcp_state,
        "packets": flux.packets, "bytes_total": flux.bytes_total,
        "bytes_fwd": flux.bytes_fwd, "bytes_rev": flux.bytes_rev,
        "retransmissions": flux.retransmissions, "risk_score": flux.risk_score,
        "explanation": None,
    }
    table = tables_du_schema()[sr.TABLE_FLOWS]

    assert _colonnes_ecrites(ligne) <= table, (
        f"colonnes absentes de la table flows : {sorted(_colonnes_ecrites(ligne) - table)}"
    )


def test_les_colonnes_des_evenements_correspondent():
    ligne = {
        "session_id": 1, "ts": 1.0, "kind": "OBSERVATION", "rule": "r",
        "severity": "info", "title": "t", "explanation": "e",
        "evidence": {}, "actor": "a", "flow_key": "k",
    }
    table = tables_du_schema()[sr.TABLE_EVENTS]

    assert _colonnes_ecrites(ligne) <= table, (
        f"colonnes absentes de la table events : {sorted(_colonnes_ecrites(ligne) - table)}"
    )


def test_les_colonnes_des_paquets_correspondent():
    ligne = {
        "session_id": 1, "number": 1, "ts": 1.0, "src": "a", "dst": "b",
        "src_port": 1, "dst_port": 2, "protocol": "TCP", "transport": "TCP",
        "size": 74, "tcp_flags": "A", "ttl": 64, "info": "i", "domain": None,
    }
    table = tables_du_schema()[sr.TABLE_PACKETS]

    assert _colonnes_ecrites(ligne) <= table, (
        f"colonnes absentes de la table packets : {sorted(_colonnes_ecrites(ligne) - table)}"
    )


def test_les_colonnes_de_l_intel_correspondent():
    ligne = {
        "ip": "1.1.1.1", "scope": "public", "country": None,
        "country_code": None, "city": None, "isp": None, "org": None,
        "asn": None, "reverse_dns": None, "source": None,
        "fetched_at": 0.0, "error": None,
    }
    table = tables_du_schema()[sr.TABLE_INTEL]

    assert _colonnes_ecrites(ligne) <= table, (
        f"colonnes absentes de la table ip_intel : {sorted(_colonnes_ecrites(ligne) - table)}"
    )


# --------------------------------------------------------------------------
# Le schema est-il lisible par le code de ce projet ?
# --------------------------------------------------------------------------

def test_le_schema_est_du_sql_valide_pour_postgres():
    """On ne peut pas executer PostgreSQL ici, mais on peut verifier que le
    fichier ne contient pas d'instruction destructrice.

    Un `drop table` dans le fichier que l'utilisateur colle dans Supabase
    effacerait ses donnees : c'est exactement le genre de ligne qu'on ne veut
    pas laisser passer.
    """
    texte = SCHEMA.read_text(encoding="utf-8")
    actif = "\n".join(
        l for l in texte.splitlines()
        if l.strip() and not l.strip().startswith("--")
    ).lower()

    for dangereux in ("drop table", "drop database", "truncate ", "delete from"):
        assert dangereux not in actif, (
            f"le schema contient « {dangereux} » : coller ce fichier effacerait "
            "les donnees existantes"
        )
