"""Le depot combine ecrit-il dans la bonne session distante ?

LE BUG QUE CES TESTS EMPECHENT DE REINTRODUIRE

Les deux bases numerotent leurs lignes independamment. Apres plusieurs essais,
la 46e session locale correspondait a la 2e session distante.

Le moteur ne connait que l'identifiant local — c'est celui que `create_session`
lui rend — et s'en sert pour tout ecrire. Le depot combine le transmettait tel
quel a Supabase, ou aucune session ne portait ce numero : la cle etrangere ne
correspondait a rien, et CHAQUE ecriture repartait avec un HTTP 409.

Le defaut etait invisible : aucune exception, aucune erreur a l'ecran. Les tables
distantes restaient simplement vides. C'est le pire cas possible pour une
demonstration qui doit montrer « les donnees enregistrees dans Supabase ».
"""

from __future__ import annotations

import pytest

from app.models import Event, Flow, PacketRecord
from app.storage.composite_repo import CompositeRepository


class FauxDepot:
    """Depot de test : retient ce qu'on lui demande, rend ce qu'on lui dit."""

    def __init__(self, id_session: int = 1) -> None:
        self.id_session = id_session
        self.appels: list[tuple] = []

    def create_session(self, **kwargs) -> int:
        self.appels.append(("create_session",))
        return self.id_session

    def close_session(self, session_id, **kwargs) -> None:
        self.appels.append(("close_session", session_id))

    def save_flows(self, session_id, flows) -> None:
        self.appels.append(("save_flows", session_id))

    def save_events(self, session_id, events) -> None:
        self.appels.append(("save_events", session_id))

    def save_packets(self, session_id, records) -> None:
        self.appels.append(("save_packets", session_id))

    def list_sessions(self, limit: int = 50) -> list[dict]:
        return [{"id": self.id_session}]

    def list_flows(self, session_id=None, limit: int = 500) -> list[dict]:
        self.appels.append(("list_flows", session_id))
        return []

    def init_schema(self) -> None:
        pass

    def ping(self) -> bool:
        return True

    def record_warning(self, message: str) -> None:
        pass

    def get_intel(self, ip, max_age_hours):
        return None

    def save_intel(self, intel) -> None:
        pass


@pytest.fixture
def composite():
    """Local numero 45, distant numero 2 : le cas qui echouait."""
    local = FauxDepot(id_session=45)
    distant = FauxDepot(id_session=2)
    return CompositeRepository(local, distant), local, distant


def _flux() -> Flow:
    return Flow(key="k", src="a", dst="b", src_port=1, dst_port=2,
                transport="TCP", first_seen=0.0, last_seen=1.0)


# --------------------------------------------------------------------------
# Le coeur du probleme
# --------------------------------------------------------------------------

def test_la_session_distante_est_creee(composite):
    depot, local, distant = composite
    identifiant = depot.create_session(mode="local", interface="Wi-Fi",
                                       interface_name="Wi-Fi", filter="")

    assert identifiant == 45, "le moteur doit recevoir l'identifiant LOCAL"
    assert ("create_session",) in distant.appels


def test_les_communications_partent_avec_l_identifiant_distant(composite):
    depot, local, distant = composite
    depot.create_session(mode="local", interface="Wi-Fi",
                         interface_name="Wi-Fi", filter="")

    depot.save_flows(45, [_flux()])

    assert ("save_flows", 2) in distant.appels, (
        "Supabase a recu l'identifiant local : la cle etrangere ne correspond "
        "a aucune session et l'ecriture est refusee en HTTP 409."
    )
    assert ("save_flows", 45) in local.appels, "le local garde son propre numero"


def test_les_paquets_partent_avec_l_identifiant_distant(composite):
    depot, local, distant = composite
    depot.create_session(mode="local", interface="Wi-Fi",
                         interface_name="Wi-Fi", filter="")

    depot.save_packets(45, [PacketRecord(number=1, ts=0.0, src="a", dst="b",
                                         protocol="TCP", size=74)])

    assert ("save_packets", 2) in distant.appels


def test_les_evenements_partent_avec_l_identifiant_distant(composite):
    depot, local, distant = composite
    depot.create_session(mode="local", interface="Wi-Fi",
                         interface_name="Wi-Fi", filter="")

    depot.save_events(45, [Event(ts=0.0, kind="OBSERVATION", rule="r",
                                 title="t", explanation="e")])

    assert ("save_events", 2) in distant.appels


def test_la_cloture_vise_la_bonne_session_distante(composite):
    depot, local, distant = composite
    depot.create_session(mode="local", interface="Wi-Fi",
                         interface_name="Wi-Fi", filter="")

    depot.close_session(45, packets=1, bytes_total=1, flows=1, events=1)

    assert ("close_session", 2) in distant.appels


# --------------------------------------------------------------------------
# Les cas ou il ne faut PAS traduire
# --------------------------------------------------------------------------

def test_une_ecriture_hors_session_n_est_pas_traduite(composite):
    """L'intel n'appartient a aucune session : elle ne doit pas etre traduite."""
    depot, local, distant = composite
    depot.create_session(mode="local", interface="Wi-Fi",
                         interface_name="Wi-Fi", filter="")

    assert depot._id_distant(None) is None
    assert depot._id_distant(999) == 999


def test_les_lectures_ne_sont_pas_traduites(composite):
    """En lecture, l'identifiant vient de la liste des sessions : il est DEJA
    distant. Le traduire une seconde fois viserait la mauvaise session."""
    depot, local, distant = composite
    depot.create_session(mode="local", interface="Wi-Fi",
                         interface_name="Wi-Fi", filter="")

    depot.list_flows(2, limit=10)

    assert ("list_flows", 2) in distant.appels, (
        "l'identifiant 2 est deja distant : il ne doit pas devenir 45"
    )


def test_sans_distant_disponible_le_local_fonctionne(composite):
    """Si Supabase tombe, la capture doit continuer en local."""
    depot, local, distant = composite
    depot.create_session(mode="local", interface="Wi-Fi",
                         interface_name="Wi-Fi", filter="")
    depot.remote_available = False

    depot.save_flows(45, [_flux()])

    assert ("save_flows", 45) in local.appels


def test_un_meme_identifiant_ne_creer_pas_de_correspondance(composite):
    """Quand les deux bases donnent le meme numero, inutile de traduire."""
    local = FauxDepot(id_session=7)
    distant = FauxDepot(id_session=7)
    depot = CompositeRepository(local, distant)

    assert depot.create_session(mode="local", interface="x",
                                interface_name="x", filter="") == 7
    assert depot._id_distant(7) == 7
