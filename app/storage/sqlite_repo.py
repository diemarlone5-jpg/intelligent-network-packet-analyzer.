"""Stockage local SQLite : toujours disponible, meme sans reseau.

Chaque operation ouvre sa propre connexion : c'est le choix le plus simple qui
reste correct avec une capture qui s'execute dans un fil separe. Le volume de
donnees du projet (des milliers de lignes, pas des millions) rend ce compromis
sans consequence mesurable.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from app.models import Event, Flow, IPIntel, PacketRecord
from app.storage.base import Repository

SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS capture_sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      REAL    NOT NULL,
    stopped_at      REAL,
    mode            TEXT    NOT NULL DEFAULT 'local',
    interface       TEXT,
    interface_name  TEXT,
    filter          TEXT,
    packets         INTEGER NOT NULL DEFAULT 0,
    bytes_total     INTEGER NOT NULL DEFAULT 0,
    flows_count     INTEGER NOT NULL DEFAULT 0,
    events_count    INTEGER NOT NULL DEFAULT 0,
    note            TEXT
);

CREATE TABLE IF NOT EXISTS flows (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
    flow_key        TEXT    NOT NULL,
    first_seen      REAL    NOT NULL,
    last_seen       REAL    NOT NULL,
    duration        REAL    NOT NULL DEFAULT 0,
    src             TEXT    NOT NULL,
    dst             TEXT    NOT NULL,
    src_port        INTEGER,
    dst_port        INTEGER,
    transport       TEXT,
    app_protocol    TEXT,
    domain          TEXT,
    state           TEXT,
    tcp_state       TEXT,
    packets         INTEGER NOT NULL DEFAULT 0,
    bytes_total     INTEGER NOT NULL DEFAULT 0,
    bytes_fwd       INTEGER NOT NULL DEFAULT 0,
    bytes_rev       INTEGER NOT NULL DEFAULT 0,
    retransmissions INTEGER NOT NULL DEFAULT 0,
    risk_score      INTEGER NOT NULL DEFAULT 0,
    explanation     TEXT,
    UNIQUE(session_id, flow_key)
);

CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
    ts              REAL    NOT NULL,
    kind            TEXT    NOT NULL,
    rule            TEXT    NOT NULL,
    severity        TEXT    NOT NULL DEFAULT 'info',
    title           TEXT    NOT NULL,
    explanation     TEXT    NOT NULL,
    evidence        TEXT,
    actor           TEXT,
    flow_key        TEXT
);

CREATE TABLE IF NOT EXISTS packets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
    number          INTEGER NOT NULL,
    ts              REAL    NOT NULL,
    src             TEXT,
    dst             TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT,
    transport       TEXT,
    size            INTEGER,
    tcp_flags       TEXT,
    ttl             INTEGER,
    info            TEXT,
    domain          TEXT
);

CREATE TABLE IF NOT EXISTS ip_intel (
    ip              TEXT PRIMARY KEY,
    scope           TEXT,
    country         TEXT,
    country_code    TEXT,
    city            TEXT,
    isp             TEXT,
    org             TEXT,
    asn             TEXT,
    reverse_dns     TEXT,
    source          TEXT,
    fetched_at      REAL NOT NULL DEFAULT 0,
    error           TEXT
);

CREATE TABLE IF NOT EXISTS warnings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL NOT NULL,
    message         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_flows_session ON flows(session_id);
CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows(session_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id, number);
"""


class SqliteRepository(Repository):
    """Implementation locale du contrat de stockage."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _execute(self, sql: str, params: tuple = ()) -> None:
        with self._lock:
            with self._connect() as connection:
                connection.execute(sql, params)

    def _query(self, sql: str, params: tuple = ()) -> list[dict]:
        with self._lock:
            with self._connect() as connection:
                rows = connection.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------------
    def init_schema(self) -> None:
        with self._lock:
            with self._connect() as connection:
                connection.executescript(SCHEMA)

    def ping(self) -> bool:
        try:
            self._query("SELECT 1")
            return True
        except Exception:
            return False

    def record_warning(self, message: str) -> None:
        try:
            self._execute("INSERT INTO warnings (ts, message) VALUES (?, ?)",
                          (time.time(), message))
        except Exception:
            pass

    def list_warnings(self, limit: int = 20) -> list[dict]:
        return self._query("SELECT * FROM warnings ORDER BY ts DESC LIMIT ?", (limit,))

    # ------------------------------------------------------------------
    def create_session(self, *, mode: str, interface: str, interface_name: str,
                       filter: str = "") -> int:
        with self._lock:
            with self._connect() as connection:
                cursor = connection.execute(
                    "INSERT INTO capture_sessions "
                    "(started_at, mode, interface, interface_name, filter) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (time.time(), mode, interface, interface_name, filter),
                )
                return int(cursor.lastrowid)

    def close_session(self, session_id: int, *, packets: int, bytes_total: int,
                      flows: int, events: int, note: str | None = None) -> None:
        self._execute(
            "UPDATE capture_sessions SET stopped_at = ?, packets = ?, "
            "bytes_total = ?, flows_count = ?, events_count = ?, note = ? "
            "WHERE id = ?",
            (time.time(), packets, bytes_total, flows, events, note, session_id),
        )

    def list_sessions(self, limit: int = 50) -> list[dict]:
        return self._query(
            "SELECT * FROM capture_sessions ORDER BY started_at DESC LIMIT ?", (limit,)
        )

    def close_orphan_sessions(self, note: str) -> int:
        """Cloture les sessions laissees ouvertes par un arret non propre."""
        with self._lock:
            with self._connect() as connection:
                cursor = connection.execute(
                    "UPDATE capture_sessions SET stopped_at = ?, note = ? "
                    "WHERE stopped_at IS NULL",
                    (time.time(), note),
                )
                return int(cursor.rowcount)

    def get_session(self, session_id: int) -> dict | None:
        rows = self._query("SELECT * FROM capture_sessions WHERE id = ?", (session_id,))
        return rows[0] if rows else None

    # ------------------------------------------------------------------
    def save_flows(self, session_id: int, flows: list[Flow]) -> None:
        if not flows:
            return
        payload = [
            (
                session_id, f.key, f.first_seen, f.last_seen, f.duration,
                f.src, f.dst, f.src_port, f.dst_port, f.transport,
                f.app_protocol, f.domain, f.state, f.tcp_state,
                f.packets, f.bytes_total, f.bytes_fwd, f.bytes_rev,
                f.retransmissions, f.risk_score, getattr(f, "explanation_text", None),
            )
            for f in flows
        ]
        with self._lock:
            with self._connect() as connection:
                connection.executemany(
                    "INSERT INTO flows (session_id, flow_key, first_seen, last_seen, "
                    "duration, src, dst, src_port, dst_port, transport, app_protocol, "
                    "domain, state, tcp_state, packets, bytes_total, bytes_fwd, "
                    "bytes_rev, retransmissions, risk_score, explanation) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(session_id, flow_key) DO UPDATE SET "
                    "last_seen=excluded.last_seen, duration=excluded.duration, "
                    "state=excluded.state, tcp_state=excluded.tcp_state, "
                    "packets=excluded.packets, bytes_total=excluded.bytes_total, "
                    "bytes_fwd=excluded.bytes_fwd, bytes_rev=excluded.bytes_rev, "
                    "retransmissions=excluded.retransmissions, "
                    "app_protocol=excluded.app_protocol, domain=excluded.domain, "
                    "explanation=excluded.explanation",
                    payload,
                )

    def list_flows(self, session_id: int | None = None, limit: int = 500) -> list[dict]:
        if session_id is None:
            return self._query(
                "SELECT * FROM flows ORDER BY last_seen DESC LIMIT ?", (limit,)
            )
        return self._query(
            "SELECT * FROM flows WHERE session_id = ? ORDER BY last_seen DESC LIMIT ?",
            (session_id, limit),
        )

    # ------------------------------------------------------------------
    def save_events(self, session_id: int, events: list[Event]) -> None:
        if not events:
            return
        payload = [
            (session_id, e.ts, e.kind, e.rule, e.severity, e.title,
             e.explanation, json.dumps(e.evidence, ensure_ascii=False), e.actor, e.flow_key)
            for e in events
        ]
        with self._lock:
            with self._connect() as connection:
                connection.executemany(
                    "INSERT INTO events (session_id, ts, kind, rule, severity, title, "
                    "explanation, evidence, actor, flow_key) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    payload,
                )

    def list_events(self, session_id: int | None = None, limit: int = 300) -> list[dict]:
        if session_id is None:
            rows = self._query(
                "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)
            )
        else:
            rows = self._query(
                "SELECT * FROM events WHERE session_id = ? ORDER BY ts DESC LIMIT ?",
                (session_id, limit),
            )
        for row in rows:
            try:
                row["evidence"] = json.loads(row["evidence"]) if row["evidence"] else {}
            except (TypeError, json.JSONDecodeError):
                row["evidence"] = {}
        return rows

    # ------------------------------------------------------------------
    def save_packets(self, session_id: int, records: list[PacketRecord]) -> None:
        if not records:
            return
        payload = [
            (session_id, r.number, r.ts, r.src, r.dst, r.src_port, r.dst_port,
             r.protocol, r.transport, r.size, r.tcp_flags, r.ttl, r.info, r.domain)
            for r in records
        ]
        with self._lock:
            with self._connect() as connection:
                connection.executemany(
                    "INSERT INTO packets (session_id, number, ts, src, dst, src_port, "
                    "dst_port, protocol, transport, size, tcp_flags, ttl, info, domain) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    payload,
                )

    def list_packets(self, session_id: int | None = None, limit: int = 200) -> list[dict]:
        if session_id is None:
            return self._query(
                "SELECT * FROM packets ORDER BY ts DESC LIMIT ?", (limit,)
            )
        return self._query(
            "SELECT * FROM packets WHERE session_id = ? ORDER BY number ASC LIMIT ?",
            (session_id, limit),
        )

    # ------------------------------------------------------------------
    def get_intel(self, ip: str, max_age_hours: float) -> IPIntel | None:
        rows = self._query("SELECT * FROM ip_intel WHERE ip = ?", (ip,))
        if not rows:
            return None
        row = rows[0]
        age_hours = (time.time() - (row["fetched_at"] or 0)) / 3600.0
        if age_hours > max_age_hours:
            return None
        return IPIntel(
            ip=row["ip"], scope=row["scope"] or "inconnu", country=row["country"],
            country_code=row["country_code"], city=row["city"], isp=row["isp"],
            org=row["org"], asn=row["asn"], reverse_dns=row["reverse_dns"],
            source=row["source"], fetched_at=row["fetched_at"] or 0.0,
            error=row["error"],
        )

    def save_intel(self, intel: IPIntel) -> None:
        self._execute(
            "INSERT INTO ip_intel (ip, scope, country, country_code, city, isp, org, "
            "asn, reverse_dns, source, fetched_at, error) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(ip) DO UPDATE SET scope=excluded.scope, country=excluded.country, "
            "country_code=excluded.country_code, city=excluded.city, isp=excluded.isp, "
            "org=excluded.org, asn=excluded.asn, reverse_dns=excluded.reverse_dns, "
            "source=excluded.source, fetched_at=excluded.fetched_at, error=excluded.error",
            (intel.ip, intel.scope, intel.country, intel.country_code, intel.city,
             intel.isp, intel.org, intel.asn, intel.reverse_dns, intel.source,
             intel.fetched_at, intel.error),
        )

    # ------------------------------------------------------------------
    def list_intel(self, limit: int = 200) -> list[dict]:
        return self._query("SELECT * FROM ip_intel ORDER BY fetched_at DESC LIMIT ?", (limit,))

    def delete_session(self, session_id: int) -> None:
        self._execute("DELETE FROM capture_sessions WHERE id = ?", (session_id,))

    # ------------------------------------------------------ gestion des donnees

    def storage_report(self) -> dict:
        """Taille de la base et nombre de lignes par table.

        Une capture qui tourne grossit sans fin : sans ce rapport, l'utilisateur
        ne peut pas savoir que sa base occupe des centaines de megaoctets, ni
        pourquoi l'application ralentit au demarrage.
        """
        with self._lock:
            with self._connect() as connection:
                taille_page = connection.execute("PRAGMA page_size").fetchone()[0]
                nb_pages = connection.execute("PRAGMA page_count").fetchone()[0]
                libres = connection.execute("PRAGMA freelist_count").fetchone()[0]
                lignes = {}
                for table in ("capture_sessions", "flows", "events", "packets",
                              "ip_intel", "warnings"):
                    try:
                        lignes[table] = connection.execute(
                            "SELECT COUNT(*) FROM %s" % table).fetchone()[0]
                    except sqlite3.Error:
                        lignes[table] = 0

        return {
            "bytes": nb_pages * taille_page,
            "free_bytes": libres * taille_page,
            "rows": lignes,
        }

    def count_orphans(self) -> int:
        """Lignes rattachees a aucune session.

        Les tables portent « ON DELETE CASCADE » et le mode SQLite est configure
        pour l'appliquer, donc il ne devrait jamais y en avoir. On le verifie
        quand meme : une suppression qui laisse des lignes derriere elle ferait
        grossir la base au lieu de la vider, et personne ne s'en apercevrait.
        """
        total = 0
        for table in ("flows", "events", "packets"):
            resultat = self._query(
                "SELECT COUNT(*) AS n FROM %s "
                "WHERE session_id NOT IN (SELECT id FROM capture_sessions)" % table)
            total += resultat[0]["n"] if resultat else 0
        return total

    def purge_old_sessions(self, keep: int) -> dict:
        """Supprime les sessions les plus anciennes et garde les `keep` recentes.

        On ne supprime jamais « tout ce qui est vieux » d'apres un delai : une
        session ancienne peut etre celle que l'utilisateur doit montrer. Le
        nombre est donc explicite, et connu a l'avance.
        """
        if keep < 0:
            keep = 0

        sessions = self._query("SELECT id FROM capture_sessions ORDER BY id DESC")
        a_supprimer = [ligne["id"] for ligne in sessions[keep:]]

        avant = self.count_orphans()
        for session_id in a_supprimer:
            self._execute("DELETE FROM capture_sessions WHERE id = ?", (session_id,))
        apres = self.count_orphans()

        return {
            "removed": len(a_supprimer),
            "kept": min(keep, len(sessions)),
            "total_before": len(sessions),
            "orphans_before": avant,
            "orphans_after": apres,
        }

    def vacuum(self) -> None:
        """Recupere l'espace des pages liberees.

        Supprimer des lignes ne reduit PAS le fichier : SQLite marque les pages
        comme libres et les reutilise. Sans compactage, la base reste aussi
        grosse alors qu'elle est vide.
        """
        with self._lock:
            connection = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
            try:
                connection.execute("VACUUM")
            finally:
                connection.close()
