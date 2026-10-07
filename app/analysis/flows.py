"""Regroupement des paquets en communications, et suivi de leur etat.

Un paquet isole ne raconte rien. Le role de ce module est de repondre aux
questions du cahier des charges :

    Qui communique avec qui ?  Depuis combien de temps ?  Sur quel protocole ?
    Combien de paquets echanges ?  Combien de donnees ?  Est-ce encore actif ?

L'identite d'une communication est le quintuplet (transport, ip, port, ip,
port) rendu BIDIRECTIONNEL : une conversation appartient aux deux machines.
Le premier paquet observe fixe l'initiateur, ce qui permet ensuite de dire
qui a appele qui et de compter separement les octets dans chaque sens.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict

from app.models import (
    STATE_CLOSED,
    STATE_ESTABLISHED,
    STATE_FAILED,
    STATE_IDLE,
    STATE_NEW,
    STATE_ONGOING,
    STATE_UNKNOWN,
    Flow,
    PacketRecord,
)

# Duree sans paquet a partir de laquelle une communication non fermee est
# consideree comme inactive (et non plus "en cours").
IDLE_TIMEOUT_SECONDS = 60.0

# Etats internes de la machine a etats TCP
TCP_OPEN_SENT = "ouverture demandee"
TCP_OPEN_ACCEPTED = "ouverture acceptee"
TCP_ESTABLISHED = "etablie"
TCP_DATA = "echange de donnees"
TCP_CLOSING = "fermeture demandee"
TCP_CLOSED = "fermee normalement"
TCP_REFUSED = "refusee par le destinataire"
TCP_RESET = "interrompue (reinitialisation)"


def _canonical_key(transport: str, a_ip: str, a_port: int | None,
                   b_ip: str, b_port: int | None) -> str:
    """Construit une cle identique pour les deux sens de la conversation."""
    a = f"{a_ip}:{a_port if a_port is not None else '-'}"
    b = f"{b_ip}:{b_port if b_port is not None else '-'}"
    first, second = sorted((a, b))
    return f"{transport}|{first}|{second}"


class FlowTable:
    """Table des communications en cours, alimentee paquet par paquet.

    La classe est protegee par un verrou car la capture s'execute dans un
    fil d'execution separe de l'interface web.
    """

    def __init__(self, max_flows: int = 20000, is_local=None) -> None:
        self._flows: OrderedDict[str, Flow] = OrderedDict()
        self._lock = threading.RLock()
        self.max_flows = max_flows
        # Predicat permettant de savoir si une adresse appartient a la machine.
        # Injecte, jamais suppose : les tests peuvent ainsi le rendre deterministe.
        self.is_local = is_local or (lambda ip: False)
        # suivi des numeros de sequence par sens, pour reperer les retransmissions
        self._seen_seq: dict[tuple[str, str], set[int]] = {}

    # ------------------------------------------------------------------
    def observe(self, record: PacketRecord) -> Flow:
        """Integre un paquet et retourne la communication a laquelle il appartient."""
        transport = record.transport or record.protocol
        key = _canonical_key(transport, record.src, record.src_port,
                             record.dst, record.dst_port)

        with self._lock:
            flow = self._flows.get(key)
            if flow is None:
                if len(self._flows) >= self.max_flows:
                    self._flows.popitem(last=False)  # retire la plus ancienne
                flow = self._create(record, key, transport)
                self._flows[key] = flow
            else:
                self._flows.move_to_end(key)
                self._update(flow, record)
            return flow

    # ------------------------------------------------------------------
    def _create(self, record: PacketRecord, key: str, transport: str) -> Flow:
        ts = record.ts or time.time()
        if self.is_local(record.src) and not self.is_local(record.dst):
            local_side = "src"
        elif self.is_local(record.dst) and not self.is_local(record.src):
            local_side = "dst"
        else:
            local_side = None
        return Flow(
            key=key,
            src=record.src,
            dst=record.dst,
            src_port=record.src_port,
            dst_port=record.dst_port,
            transport=transport,
            first_seen=ts,
            last_seen=ts,
            packets=1,
            bytes_total=record.size,
            bytes_fwd=record.size,
            state=STATE_NEW,
            initiator=record.src,
            local_side=local_side,
            app_protocol=record.protocol if record.protocol in ("DNS", "HTTP", "TLS", "DHCP", "ARP", "ICMP") else None,
            domain=record.domain if record.protocol in ("DNS", "HTTP", "TLS") else None,
            tcp_state=TCP_OPEN_SENT if record.tcp_flags == "S" else None,
            syn_count=1 if record.tcp_flags == "S" else 0,
            handshake_seen=record.tcp_flags == "S",
            service_port=record.dst_port if record.tcp_flags == "S" else None,
        )

    # ------------------------------------------------------------------
    def _update(self, flow: Flow, record: PacketRecord) -> None:
        """Met a jour les compteurs, le protocole applicatif et l'etat."""
        flow.last_seen = max(flow.last_seen, record.ts or flow.last_seen)
        flow.packets += 1
        flow.bytes_total += record.size

        forward = (record.src, record.src_port) == (flow.src, flow.src_port)
        if forward:
            flow.bytes_fwd += record.size
        else:
            flow.bytes_rev += record.size

        # Le protocole applicatif le plus precis l'emporte : TLS > HTTP > DNS
        precedence = {None: 0, "DHCP": 1, "DNS": 1, "HTTP": 2, "TLS": 3}
        if record.protocol in precedence:
            if precedence[record.protocol] > precedence.get(flow.app_protocol, 0):
                flow.app_protocol = record.protocol
        # Un domaine connu ne doit jamais etre ecrase par une valeur vide
        if record.domain and not flow.domain:
            flow.domain = record.domain

        if record.transport == "TCP":
            self._advance_tcp_state(flow, record, forward)

    # ------------------------------------------------------------------
    def _advance_tcp_state(self, flow: Flow, record: PacketRecord, forward: bool) -> None:
        """Suit les etapes successives d'une connexion TCP.

        On ne devine pas : chaque transition correspond a un drapeau reellement
        observe. Un etat reste inchange tant qu'aucun paquet ne le confirme.
        """
        flags = record.tcp_flags or ""

        if "S" in flags and "A" not in flags:
            # SYN pur : c'est le tout premier paquet de la connexion. Le port
            # de destination de CE paquet est, par definition, le port du
            # service contacte. C'est la seule source fiable pour le savoir.
            flow.syn_count += 1
            flow.handshake_seen = True
            flow.service_port = record.dst_port
            if flow.tcp_state in (None, TCP_OPEN_SENT):
                flow.tcp_state = TCP_OPEN_SENT
                flow.state = STATE_NEW
            return

        if "S" in flags and "A" in flags:
            flow.tcp_state = TCP_OPEN_ACCEPTED
            flow.state = STATE_ONGOING
            return

        if "R" in flags:
            flow.rst_count += 1
            # Un RST juste apres un SYN signifie un refus de connexion
            if flow.tcp_state in (TCP_OPEN_SENT, TCP_OPEN_ACCEPTED):
                flow.tcp_state = TCP_REFUSED
                flow.state = STATE_FAILED
            else:
                flow.tcp_state = TCP_RESET
                flow.state = STATE_CLOSED
            return

        if "F" in flags:
            flow.fin_count += 1
            if flow.fin_count >= 2:
                flow.tcp_state = TCP_CLOSED
                flow.state = STATE_CLOSED
            else:
                flow.tcp_state = TCP_CLOSING
                flow.state = STATE_ONGOING
            return

        if flow.tcp_state in (TCP_OPEN_ACCEPTED, None, TCP_OPEN_SENT):
            flow.tcp_state = TCP_ESTABLISHED
            flow.state = STATE_ESTABLISHED

        if record.payload_len > 0:
            flow.tcp_state = TCP_DATA
            flow.state = STATE_ONGOING
            self._count_retransmission(flow, record, forward)

    # ------------------------------------------------------------------
    def _count_retransmission(self, flow: Flow, record: PacketRecord,
                              forward: bool) -> None:
        """Repere grossierement une retransmission.

        Deux paquets portant le meme numero de sequence et la meme quantite de
        donnees dans le meme sens sont, en pratique, une retransmission. On ne
        compare que le numero de sequence, sans lire l'en-tete au-dela : c'est
        une approximation assumee, documentee dans le README.
        """
        seq = record.tcp_seq
        if seq is None:
            return
        track = (flow.key, "fwd" if forward else "rev")
        bucket = self._seen_seq.setdefault(track, set())
        if seq in bucket:
            flow.retransmissions += 1
        else:
            bucket.add(seq)
            if len(bucket) > 5000:
                bucket.clear()

    # ------------------------------------------------------------------
    def tick(self, now: float | None = None) -> None:
        """Reevalue les etats : une connexion sans paquet devient inactive."""
        now = now or time.time()
        with self._lock:
            for flow in self._flows.values():
                if flow.state in (STATE_CLOSED, STATE_FAILED, STATE_IDLE):
                    continue
                if now - flow.last_seen > IDLE_TIMEOUT_SECONDS:
                    flow.state = STATE_IDLE
                    if flow.tcp_state in (TCP_ESTABLISHED, TCP_DATA):
                        flow.tcp_state = "inactive (aucun paquet depuis un moment)"

    # ------------------------------------------------------------------
    def snapshot(self, limit: int | None = None) -> list[Flow]:
        """Copie des communications, les plus recentes en premier."""
        with self._lock:
            flows = list(self._flows.values())
        flows.sort(key=lambda f: f.last_seen, reverse=True)
        return flows[:limit] if limit else flows

    def get(self, key: str) -> Flow | None:
        with self._lock:
            return self._flows.get(key)

    def count(self) -> int:
        with self._lock:
            return len(self._flows)

    def clear(self) -> None:
        with self._lock:
            self._flows.clear()
            self._seen_seq.clear()


# --------------------------------------------------------------------------
# Decodage des drapeaux, pour l'affichage
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# Interpretation de la communication
# --------------------------------------------------------------------------


def resolve_service_port(flow: Flow) -> int | None:
    """Determine le port du service discute, meme si le debut a ete manque.

    Cas fiable : un SYN a ete observe, son port de destination est le port du
    service. Cas deguise : la capture a commence en cours de connexion, aucun
    SYN n'est disponible. On retombe alors sur un raisonnement explicite :

        1. si un seul des deux ports est un service documente, c'est lui ;
        2. sinon, le plus petit des deux (convention : les services ecoutent
           sur les ports bas, les clients utilisent des ports ephemeres hauts) ;
        3. sinon, indetermine.

    Cette deduction est presentee comme telle dans l'explication : elle ne
    prend jamais la place d'un fait.
    """
    from app.analysis.protocols import lookup_port

    if flow.handshake_seen and flow.service_port is not None:
        return flow.service_port

    candidates = [p for p in (flow.src_port, flow.dst_port) if p is not None]
    if not candidates:
        return None

    documented = [p for p in candidates if lookup_port(p, flow.transport)]
    if len(documented) == 1:
        return documented[0]

    return min(candidates)


def infer_direction(flow: Flow, is_local) -> str:
    """Qui a pris l'initiative ? "local", "distant" ou "inconnu".

    Repose d'abord sur le SYN reellement observe. En son absence, sur la
    position des ports : un client utilise un port ephemeral (eleve) face a
    un service (port bas), et ce rapport suffit generalement a trancher.
    """
    from app.analysis.protocols import lookup_port

    if flow.handshake_seen and flow.initiator:
        return "local" if is_local(flow.initiator) else "distant"

    local_is_src = is_local(flow.src)
    local_port = flow.src_port if local_is_src else flow.dst_port
    remote_port = flow.dst_port if local_is_src else flow.src_port

    local_known = bool(local_port is not None and lookup_port(local_port, flow.transport))
    remote_known = bool(remote_port is not None and lookup_port(remote_port, flow.transport))

    if remote_known and not local_known:
        return "local"       # nous contactons un service connu
    if local_known and not remote_known:
        return "distant"     # un service connu chez nous est contacte
    if local_port and remote_port:
        if local_port > 1024 >= remote_port:
            return "local"
        if remote_port > 1024 >= local_port:
            return "distant"
    return "inconnu"


def state_label(flow: Flow) -> str:
    """Etat de la communication en langage courant."""
    if flow.state == STATE_FAILED:
        return f"connexion {flow.tcp_state or 'echouee'}"
    if flow.state == STATE_CLOSED:
        return flow.tcp_state or "fermee"
    if flow.state == STATE_IDLE:
        return "inactive (aucun paquet recent)"
    if flow.state == STATE_ESTABLISHED:
        return "etablie"
    if flow.state == STATE_ONGOING:
        return flow.tcp_state or "en cours"
    if flow.state == STATE_NEW:
        return flow.tcp_state or "nouvelle"
    return STATE_UNKNOWN


def human_bytes(n: int) -> str:
    """Formate un volume de donnees de facon lisible."""
    size = float(n)
    for unit in ("o", "Ko", "Mo", "Go"):
        if size < 1024 or unit == "Go":
            return f"{size:.0f} {unit}" if unit == "o" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} Go"


def human_duration(seconds: float) -> str:
    """Formate une duree de facon lisible."""
    if seconds < 1:
        return "moins d'une seconde"
    if seconds < 60:
        return f"{seconds:.0f} s"
    if seconds < 3600:
        return f"{seconds / 60:.0f} min"
    return f"{seconds / 3600:.1f} h"
