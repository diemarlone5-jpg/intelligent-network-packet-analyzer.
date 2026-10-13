"""Depot combine : ecrit en local ET dans Supabase, lit la source disponible.

Pourquoi cette couche existe :
    - la capture doit continuer a fonctionner meme si Internet tombe ou si le
      quota de Supabase est atteint ;
    - une donnee ecrite en local est immediatement exploitable, sans attendre
      le reseau ;
    - le mode en ligne alimente la demonstration depuis Supabase.

Regle de lecture : Supabase est prioritaire s'il repond, sinon SQLite. Le
fichier local reste ainsi la source de secours, jamais une source perimee.
"""

from __future__ import annotations

import time

from app.models import Event, Flow, IPIntel, PacketRecord
from app.storage.base import Repository


class CompositeRepository(Repository):
    """Ecrit dans les deux depots, lit celui qui est disponible."""

    def __init__(self, local: Repository, remote: Repository) -> None:
        self.local = local
        self.remote = remote
        self.remote_available = True
        self.last_error: str | None = None
        # Correspondance identifiant LOCAL -> identifiant DISTANT.
        #
        # Les deux bases numerotent leurs lignes independamment : la 45e session
        # locale peut tres bien etre la 2e en ligne, surtout apres avoir vide la
        # base distante ou teste plusieurs fois. Le moteur, lui, ne connait que
        # l'identifiant local et s'en sert pour tout ecrire.
        #
        # Sans cette table, chaque ecriture partait avec l'identifiant local :
        # la cle etrangere ne correspondait a aucune session distante, et
        # Supabase refusait en HTTP 409. Aucune erreur ne remontait a l'ecran —
        # les tables distantes restaient simplement vides, ce qui est le pire
        # des cas pour une demonstration.
        self._sessions_distantes: dict[int, int] = {}

    def _id_distant(self, session_id: int | None) -> int | None:
        """Traduit un identifiant local en identifiant distant.

        On ne traduit que les ECRITURES. En lecture, l'identifiant vient de
        `list_sessions()`, qui renvoie deja les sessions distantes quand elles
        sont joignables : c'est donc deja un identifiant distant, et le traduire
        une seconde fois viserait la mauvaise session.
        """
        if session_id is None:
            return None
        return self._sessions_distantes.get(session_id, session_id)

    # ------------------------------------------------------------------
    def _try_remote(self, action, *args, **kwargs):
        """Execute une operation distante sans jamais propager d'erreur."""
        if not self.remote_available:
            return None
        try:
            return action(*args, **kwargs)
        except Exception as exc:
            self.remote_available = False
            self.last_error = (
                f"Supabase n'est plus joignable ({type(exc).__name__}) : "
                f"l'application continue uniquement en local."
            )
            return None

    def _recheck_remote(self) -> None:
        """Reessaie le distant toutes les 60 secondes apres un echec."""
        if self.remote_available:
            return
        now = time.time()
        if now - getattr(self, "_last_recheck", 0.0) < 60.0:
            return
        self._last_recheck = now
        try:
            if self.remote.ping():  # type: ignore[attr-defined]
                self.remote_available = True
                self.last_error = None
        except Exception:
            pass

    # ------------------------------------------------------------------
    def init_schema(self) -> None:
        self.local.init_schema()
        self._try_remote(self.remote.init_schema)

    def ping(self) -> bool:
        return self.local.ping()

    def record_warning(self, message: str) -> None:
        self.local.record_warning(message)

    # ------------------------------------------------------------------
    def create_session(self, **kwargs) -> int:
        """Cree la session des deux cotes et retient la correspondance.

        On rend l'identifiant LOCAL : c'est celui que le moteur utilisera partout
        ensuite. L'identifiant distant est conserve a part, pour traduire les
        ecritures (voir `_id_distant`).
        """
        session_id = self.local.create_session(**kwargs)
        distant = self._try_remote(self.remote.create_session, **kwargs)
        if isinstance(distant, int) and distant != session_id:
            self._sessions_distantes[session_id] = distant
        return session_id

    def close_session(self, session_id: int, **kwargs) -> None:
        self.local.close_session(session_id, **kwargs)
        self._try_remote(self.remote.close_session, self._id_distant(session_id), **kwargs)

    def list_sessions(self, limit: int = 50) -> list[dict]:
        self._recheck_remote()
        remote = self._try_remote(self.remote.list_sessions, limit) if self.remote_available else None
        return remote if remote else self.local.list_sessions(limit)

    def close_orphan_sessions(self, note: str) -> int:
        fermees = self.local.close_orphan_sessions(note)
        self._try_remote(self.remote.close_orphan_sessions, note)
        return fermees

    def get_session(self, session_id: int) -> dict | None:
        self._recheck_remote()
        remote = self._try_remote(self.remote.get_session, session_id) if self.remote_available else None
        return remote if remote else self.local.get_session(session_id)

    # ------------------------------------------------------------------
    def save_flows(self, session_id: int, flows: list[Flow]) -> None:
        self.local.save_flows(session_id, flows)
        self._try_remote(self.remote.save_flows, self._id_distant(session_id), flows)

    def list_flows(self, session_id: int | None = None, limit: int = 500) -> list[dict]:
        self._recheck_remote()
        remote = self._try_remote(self.remote.list_flows, session_id, limit) if self.remote_available else None
        return remote if remote else self.local.list_flows(session_id, limit)

    def save_events(self, session_id: int, events: list[Event]) -> None:
        self.local.save_events(session_id, events)
        self._try_remote(self.remote.save_events, self._id_distant(session_id), events)

    def list_events(self, session_id: int | None = None, limit: int = 300) -> list[dict]:
        self._recheck_remote()
        remote = self._try_remote(self.remote.list_events, session_id, limit) if self.remote_available else None
        return remote if remote else self.local.list_events(session_id, limit)

    def save_packets(self, session_id: int, records: list[PacketRecord]) -> None:
        self.local.save_packets(session_id, records)
        self._try_remote(self.remote.save_packets, self._id_distant(session_id), records)

    def list_packets(self, session_id: int | None = None, limit: int = 200) -> list[dict]:
        self._recheck_remote()
        remote = self._try_remote(self.remote.list_packets, session_id, limit) if self.remote_available else None
        return remote if remote else self.local.list_packets(session_id, limit)

    # ------------------------------------------------------------------
    def get_intel(self, ip: str, max_age_hours: float) -> IPIntel | None:
        local = self.local.get_intel(ip, max_age_hours)
        if local is not None:
            return local
        return self._try_remote(self.remote.get_intel, ip, max_age_hours) if self.remote_available else None

    def save_intel(self, intel: IPIntel) -> None:
        self.local.save_intel(intel)
        self._try_remote(self.remote.save_intel, intel)

    # ------------------------------------------------- gestion des donnees
    #
    # Ces operations ne concernent QUE la base locale. Le depot distant est une
    # archive : on n'y supprime rien depuis l'application, car une suppression
    # a distance est irreversible et ne se voit pas depuis l'interface.

    def storage_report(self) -> dict:
        return self.local.storage_report()

    def count_orphans(self) -> int:
        return self.local.count_orphans()

    def purge_old_sessions(self, keep: int) -> dict:
        return self.local.purge_old_sessions(keep)

    def vacuum(self) -> None:
        self.local.vacuum()
