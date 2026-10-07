"""Interface de persistance, commune a SQLite et a Supabase.

Le reste de l'application ne connait que cette interface : changer de base ne
doit jamais obliger a modifier la couche d'analyse ni l'interface web.

Conception du modele de donnees (justification demandee au cahier des charges) :

    capture_sessions  une ligne par campagne d'observation. Sans elle, aucune
                      comparaison entre deux analyses n'est possible : on ne
                      saurait pas quel trafic appartenait a quelle session.

    flows             une ligne par communication (et non par paquet). C'est
                      l'unite qui a du sens pour un analyste, et cela divise
                      par plusieurs milliers le volume stocke.

    events            une ligne par fait remarquable detecte, rattachee a sa
                      session et, quand elle existe, a la communication
                      concernee. C'est ce qui permet de rejouer une analyse.

    packets           un echantillon de paquets bruts, volontairement plafonne
                      par session. Le paquet brut sert a la verification et a la
                      demonstration, pas a l'analyse de masse.

    ip_intel          cache de l'enrichissement externe. Une IP n'est
                      interrogee qu'une fois par periode de validite : cela
                      respecte les quotas de l'API et rend l'application
                      utilisable hors ligne grace au cache.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.models import Event, Flow, IPIntel, PacketRecord


class Repository(ABC):
    """Contrat de stockage. Toute implementation doit respecter ces signatures."""

    # --- cycle de vie -------------------------------------------------
    @abstractmethod
    def init_schema(self) -> None:
        """Cree les tables si elles n'existent pas. Doit etre idempotent."""

    @abstractmethod
    def ping(self) -> bool:
        """Verifie que la base repond. Ne doit jamais lever."""

    # --- sessions -----------------------------------------------------
    @abstractmethod
    def create_session(self, *, mode: str, interface: str, interface_name: str,
                       filter: str = "") -> int:
        """Ouvre une session de capture et retourne son identifiant."""

    @abstractmethod
    def close_session(self, session_id: int, *, packets: int, bytes_total: int,
                      flows: int, events: int, note: str | None = None) -> None:
        """Cloture une session en y inscrivant ses totaux."""

    @abstractmethod
    def close_orphan_sessions(self, note: str) -> int:
        """Cloture les sessions restees ouvertes apres un arret non propre.

        Sans cela, une session interrompue par une coupure de courant ou un
        arret force reste eternellement « en cours » dans l'historique, et
        affiche des totaux a zero qui laissent croire qu'aucun paquet n'a ete
        capture. Retourne le nombre de sessions cloturees.
        """

    @abstractmethod
    def list_sessions(self, limit: int = 50) -> list[dict]:
        """Historique des sessions, la plus recente en premier."""

    @abstractmethod
    def get_session(self, session_id: int) -> dict | None:
        ...

    # --- donnees analysees --------------------------------------------
    @abstractmethod
    def save_flows(self, session_id: int, flows: list[Flow]) -> None:
        """Enregistre ou met a jour des communications (upsert par cle de flux)."""

    @abstractmethod
    def list_flows(self, session_id: int | None = None, limit: int = 500) -> list[dict]:
        ...

    @abstractmethod
    def save_events(self, session_id: int, events: list[Event]) -> None:
        ...

    @abstractmethod
    def list_events(self, session_id: int | None = None, limit: int = 300) -> list[dict]:
        ...

    @abstractmethod
    def save_packets(self, session_id: int, records: list[PacketRecord]) -> None:
        """Conserve un echantillon de paquets bruts (plafonne par la session)."""

    @abstractmethod
    def list_packets(self, session_id: int | None = None, limit: int = 200) -> list[dict]:
        ...

    # --- enrichissement -----------------------------------------------
    @abstractmethod
    def get_intel(self, ip: str, max_age_hours: float) -> IPIntel | None:
        """Retourne les informations en cache si elles sont encore valides."""

    @abstractmethod
    def save_intel(self, intel: IPIntel) -> None:
        ...

    # --- divers -------------------------------------------------------
    def record_warning(self, message: str) -> None:
        """Consigne un avertissement non bloquant (implementation libre)."""
        return None
