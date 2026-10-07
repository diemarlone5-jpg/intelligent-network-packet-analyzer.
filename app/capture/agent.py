"""Agent de capture : ouvre l'interface reseau et livre les paquets observes.

La capture s'execute dans un fil d'execution distinct de l'interface web.
Aucune exception remontee par le traitement d'un paquet ne doit arreter la
capture : un paquet illisible est compte comme erreur, puis on continue.
"""

from __future__ import annotations

import threading
import time
from typing import Callable

from scapy.all import AsyncSniffer, conf

from app.capture.interfaces import capture_available, find_interface, pick_default_interface


class CaptureAgent:
    """Pilote une capture Scapy demarrable et arretable a tout moment."""

    def __init__(self, on_packet: Callable, on_error: Callable[[str], None] | None = None) -> None:
        self.on_packet = on_packet
        self.on_error = on_error
        self._sniffer: AsyncSniffer | None = None
        self._lock = threading.RLock()
        self._stop_requested = False

        # Statistiques de capture, exposees a l'interface
        self.packets_seen = 0
        self.bytes_seen = 0
        self.handler_errors = 0
        self.started_at: float | None = None
        self.iface_id: str | None = None
        self.iface_name: str | None = None
        self.bpf_filter: str = ""
        self.last_error: str | None = None

    # ------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return bool(self._sniffer and self._sniffer.running)

    # ------------------------------------------------------------------
    def start(self, iface_id: str | None = None, iface_name: str | None = None,
              bpf_filter: str = "") -> tuple[bool, str]:
        """Demarre la capture. Retourne (succes, message en langage clair)."""
        with self._lock:
            if self.running:
                return False, "Une capture est deja en cours."

            available, message = capture_available()
            if not available:
                self.last_error = message
                return False, message

            if iface_id:
                target = find_interface(iface_id)
            else:
                # Aucune interface imposee : on utilise la meme logique de choix
                # que le reste de l'application (carte portant la route par
                # defaut). Se fier au defaut de Scapy peut mener a capturer sur
                # un adaptateur virtuel ou deconnecte.
                target = pick_default_interface()

            # `conf.iface` peut renvoyer un OBJET interface Scapy et non une
            # chaine, et un identifiant technique n'est pas un nom lisible.
            # On resout donc toujours vers un identifiant ET un nom d'affichage.
            if target is not None:
                target_id, target_name = str(target.id), str(target.name)
            else:
                target_id = str(iface_id or conf.iface)
                target_name = str(iface_name or target_id)

            if not target_id:
                self.last_error = "Aucune interface de capture n'a pu etre determinee."
                return False, self.last_error

            # On ouvre d'abord un socket de test : si le droit d'ouvrir le pilote
            # manque, l'erreur apparait ici, de facon synchrone et explicite,
            # au lieu d'echouer silencieusement dans le fil de capture.
            try:
                probe = conf.L2listen(iface=target_id, filter=bpf_filter or None)
                probe.close()
            except Exception as exc:
                self.last_error = self._explain_open_error(exc, bpf_filter)
                return False, self.last_error

            try:
                self._sniffer = AsyncSniffer(
                    iface=target_id,
                    prn=self._dispatch,
                    store=False,
                    filter=bpf_filter or None,
                )
                self._sniffer.start()
            except Exception as exc:
                self.last_error = f"Le demarrage de la capture a echoue : {exc}"
                self._sniffer = None
                return False, self.last_error

            # Laisse au fil de capture le temps d'ouvrir reellement le socket
            time.sleep(0.7)
            if not self._sniffer.running:
                detail = getattr(self._sniffer, "exception", None)
                self._sniffer = None
                self.last_error = (
                    f"La capture s'est arretee immediatement"
                    + (f" ({detail})" if detail else "")
                    + ". Verifiez l'interface choisie et les droits d'acces au pilote."
                )
                return False, self.last_error

            self.started_at = time.time()
            self.iface_id = target_id
            self.iface_name = target_name
            self.bpf_filter = bpf_filter
            self.last_error = None
            return True, f"Capture demarree sur {target_name}."

    # ------------------------------------------------------------------
    @staticmethod
    def _explain_open_error(exc: Exception, bpf_filter: str) -> str:
        """Traduit une erreur technique d'ouverture en conseil actionnable."""
        text = str(exc)
        if bpf_filter and ("syntax" in text.lower() or "filter" in text.lower()):
            return (
                f"Le filtre de capture est invalide : {bpf_filter!r}. "
                "Exemple de syntaxe correcte : « tcp and port 443 »."
            )
        if "permission" in text.lower() or "access" in text.lower() or "denied" in text.lower():
            return (
                "Acces refuse a l'interface. Le pilote de capture (Npcap) doit "
                "etre installe en autorisant les utilisateurs non administrateurs, "
                "ou l'application doit etre lancee avec des droits suffisants."
            )
        return f"Ouverture de l'interface impossible : {type(exc).__name__} - {text}"

    # ------------------------------------------------------------------
    def _dispatch(self, packet) -> None:
        """Recoit un paquet du fil de capture. Ne doit jamais lever."""
        try:
            self.packets_seen += 1
            self.bytes_seen += len(packet)
            self.on_packet(packet)
        except Exception as exc:  # pragma: no cover - depend de paquets reels
            self.handler_errors += 1
            if self.handler_errors <= 5:
                # On signale les premieres erreurs, puis on reste silencieux
                # pour ne pas noyer les journaux.
                message = f"Paquet {self.packets_seen} non traite : {type(exc).__name__} - {exc}"
                if self.on_error:
                    self.on_error(message)

    # ------------------------------------------------------------------
    def stop(self) -> tuple[bool, str]:
        """Arrete la capture. Sans capture en cours, ne fait rien."""
        with self._lock:
            if not self._sniffer:
                return False, "Aucune capture en cours."
            try:
                self._sniffer.stop()
            except Exception as exc:
                self.last_error = f"Arret difficile : {exc}"
            finally:
                self._sniffer = None
            return True, "Capture arretee."

    # ------------------------------------------------------------------
    def stats(self) -> dict:
        """Etat de la capture, pour l'interface."""
        return {
            "running": self.running,
            "interface": self.iface_name,
            "interface_id": self.iface_id,
            "filter": self.bpf_filter,
            "packets": self.packets_seen,
            "bytes": self.bytes_seen,
            "errors": self.handler_errors,
            "started_at": self.started_at,
            "uptime": (time.time() - self.started_at) if self.started_at and self.running else 0.0,
            "last_error": self.last_error,
        }

    def reset_counters(self) -> None:
        self.packets_seen = 0
        self.bytes_seen = 0
        self.handler_errors = 0
