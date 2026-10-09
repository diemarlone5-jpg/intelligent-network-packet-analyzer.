"""Detection de comportements qui meritent l'attention d'un analyste.

Le cahier des charges insiste sur un point : un comportement inhabituel n'est
pas automatiquement une attaque. Ce module respecte donc un contrat strict :

    OBSERVATION  ce qui est compte, mesure, indiscutable
    HYPOTHESE    la lecture possible de cette observation, jamais affirmee
    ALERTE       une exposition documentee et verifiable (service sensible
                 joignable, protocole en clair transportant des identifiants)

Chaque regle produit un evenement qui contient sa `evidence` : les valeurs
reellement mesurees. C'est ce qui permet, a l'oral, de repondre a la question
"quelle information est observee, et laquelle est deduite ?".

Aucune regle ne s'appuie sur une liste noire externe : les seuils sont des
parametres visibles et modifiables, jamais des verites cachees.
"""

from __future__ import annotations

import math
import time
from collections import Counter, defaultdict
from dataclasses import dataclass

from app.analysis.flows import infer_direction, resolve_service_port
from app.analysis.protocols import classify_address, is_translation_prefix, lookup_port
from app.models import (
    KIND_ALERTE,
    KIND_HYPOTHESE,
    KIND_OBSERVATION,
    Event,
    Flow,
)


@dataclass
class DetectionConfig:
    """Seuils des regles. Tous modifiables, aucun n'est une evidence."""

    window_seconds: float = 60.0
    # Une balise emet a intervalle regulier : detecter ce rythme exige une
    # fenetre bien plus longue que celle des regles de volume ou de balayage.
    beacon_window_seconds: float = 900.0
    many_destinations: int = 15        # destinations distinctes = balayage possible
    many_local_ports: int = 20         # ports locaux distincts = balayage entrant
    refused_connections: int = 8       # connexions refusees repetees
    unanswered_syn: int = 15           # SYN sans reponse
    dns_queries: int = 40              # volume de requetes DNS
    dns_entropy_threshold: float = 3.4  # entropie d'un nom = tunnel/DGA possible
    volume_share: float = 0.75         # part du volume total d'un seul hote
    # Un echantillon trop maigre rend le pourcentage trompeur : avec un seul
    # flux, l'hote concentre 100 % du trafic sans que cela signifie quoi que
    # ce soit. On exige donc un minimum de matiere avant de comparer.
    volume_min_flows: int = 5
    volume_min_bytes: int = 1_000_000
    # Avec peu d'interlocuteurs, "concentre 90 % du volume" n'apprend rien :
    # c'est le cas normal d'une conversation unique et volumineuse. La regle
    # n'a de sens que s'il y a une vraie diversite de destinations.
    volume_min_remote_hosts: int = 6
    beacon_min_series: int = 5         # connexions regulieres = balise possible
    beacon_jitter: float = 0.30        # dispersion relative toleree
    baseline_factor: float = 3.0       # ecart au comportement habituel
    cooldown_seconds: float = 45.0     # anti-repetition d'une meme alerte
    # Les regles purement informatives derivent naturellement avec le temps
    # (une part de volume change a chaque fenetre) : sans delai plus long,
    # elles finissent par saturer la liste et masquer les vraies detections.
    cooldown_info_seconds: float = 300.0


def shannon_entropy(text: str) -> float:
    """Entropie de Shannon d'une chaine, en bits par caractere.

    Sert a reperer les noms de domaine generes aleatoirement, typiques des
    algorithmes de generation de domaines (DGA) et des tunnels DNS. Une chaine
    aleatoire a une entropie elevee ; un mot francais, faible.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class BehaviorAnalyzer:
    """Analyse par fenetre glissante, avec memoire pour eviter le bruit."""

    def __init__(self, config: DetectionConfig | None = None, is_local=None) -> None:
        self.config = config or DetectionConfig()
        self.is_local = is_local or (lambda ip: False)
        self._last_emitted: dict[str, float] = {}
        self._known_remotes: set[str] = set()
        self._baseline_remotes: float | None = None
        self._windows_seen = 0

    # ------------------------------------------------------------------
    def analyze(self, flows: list[Flow], now: float | None = None) -> list[Event]:
        """Analyse un instantane des communications et retourne les evenements."""
        now = now or time.time()
        if not flows:
            return []
        # Fenetre courte : regles de volume, de balayage et d'exposition.
        # La detection de balise utilise sa propre fenetre, plus longue, et
        # doit donc pouvoir s'executer meme si la fenetre courte est vide.
        window = self._recent(flows, now)

        events: list[Event] = []
        events += self._r1_many_destinations(window, now)
        events += self._r2_inbound_scan(window, now)
        events += self._r3_sensitive_ports(window, now)
        events += self._r4_refused(window, now)
        events += self._r5_unanswered(window, now)
        events += self._r6_dns(window, now)
        events += self._r7_volume(window, now)
        # Le rythme d'une balise ne se lit que sur une duree longue : on
        # n'utilise pas la meme fenetre que les regles de volume.
        events += self._r8_beaconing(
            self._recent(flows, now, self.config.beacon_window_seconds), now
        )
        events += self._r9_baseline(window, now)
        events += self._r10_cleartext(window, now)

        # Tri par gravite decroissante pour l'affichage
        order = {"eleve": 0, "moyen": 1, "faible": 2, "info": 3}
        events.sort(key=lambda e: order.get(e.severity, 9))
        return events

    # ------------------------------------------------------------------
    def _recent(self, flows: list[Flow], now: float,
                window: float | None = None) -> list[Flow]:
        """Communications vues pendant la fenetre d'observation demandee."""
        cutoff = now - (window if window is not None else self.config.window_seconds)
        return [f for f in flows if f.last_seen >= cutoff]

    # ------------------------------------------------------------------
    def _emit(self, event: Event) -> bool:
        """Applique le delai anti-repetition. Retourne True si l'evenement passe."""
        signature = f"{event.rule}:{event.actor or ''}"
        delai = (self.config.cooldown_info_seconds if event.severity == "info"
                 else self.config.cooldown_seconds)
        last = self._last_emitted.get(signature, 0.0)
        if event.ts - last < delai:
            return False
        self._last_emitted[signature] = event.ts
        return True

    # ------------------------------------------------------------------
    # R1 - une machine contacte de nombreuses destinations distinctes
    # ------------------------------------------------------------------
    def _r1_many_destinations(self, flows: list[Flow], now: float) -> list[Event]:
        by_actor: dict[str, set[str]] = defaultdict(set)
        for f in flows:
            if f.local_side == "src":          # c'est nous qui appelons
                by_actor[f.src].add(f.dst)

        events = []
        for actor, destinations in by_actor.items():
            if len(destinations) < self.config.many_destinations:
                continue
            event = Event(
                ts=now,
                kind=KIND_HYPOTHESE,
                rule="destinations_multiples",
                title=f"{len(destinations)} destinations distinctes contactees en "
                      f"{int(self.config.window_seconds)} secondes",
                severity="moyen",
                actor=actor,
                evidence={
                    "nb_destinations": len(destinations),
                    "seuil": self.config.many_destinations,
                    "fenetre_secondes": self.config.window_seconds,
                    "exemples": sorted(destinations)[:10],
                },
                explanation=(
                    f"OBSERVATION : la machine {actor} a ouvert des communications "
                    f"vers {len(destinations)} adresses distinctes pendant la fenetre "
                    f"d'observation, pour un seuil fixe a {self.config.many_destinations}. "
                    f"Les exemples sont listes dans les preuves. "
                    f"HYPOTHESE : ce comportement est compatible avec un balayage de "
                    f"reseau, mais aussi avec un simple usage normal et intense "
                    f"(navigation, mises a jour, synchronisation). Cette regle compte "
                    f"un fait, elle ne conclut pas a une intention. Pour trancher, il "
                    f"faut regarder le rythme, la variete des ports et le taux d'echec."
                ),
            )
            if self._emit(event):
                events.append(event)
        return events

    # ------------------------------------------------------------------
    # R2 - de nombreuses tentatives entrantes vers des ports locaux distincts
    # ------------------------------------------------------------------
    def _r2_inbound_scan(self, flows: list[Flow], now: float) -> list[Event]:
        by_source: dict[str, set[int]] = defaultdict(set)
        for f in flows:
            if f.local_side == "dst" and f.tcp_state in ("ouverture demandee", "ouverture acceptee"):
                if f.dst_port is not None:
                    by_source[f.src].add(f.dst_port)

        events = []
        for source, ports in by_source.items():
            if len(ports) < self.config.many_local_ports:
                continue
            event = Event(
                ts=now,
                kind=KIND_HYPOTHESE,
                rule="balayage_entrant",
                title=f"{source} a tente d'atteindre {len(ports)} ports differents "
                      f"sur cette machine",
                severity="eleve",
                actor=source,
                evidence={
                    "source": source,
                    "nb_ports_distincts": len(ports),
                    "seuil": self.config.many_local_ports,
                    "ports": sorted(ports)[:25],
                },
                explanation=(
                    f"OBSERVATION : {source} a envoye des demandes d'ouverture vers "
                    f"{len(ports)} ports distincts de cette machine pendant la fenetre. "
                    f"HYPOTHESE : une tentative de cartographie des services "
                    f"accessibles (balayage de ports). C'est la lecture la plus "
                    f"probable au vu du volume, sans etre une certitude : un outil de "
                    f"supervision mal configure produit le meme motif."
                ),
            )
            if self._emit(event):
                events.append(event)
        return events

    # ------------------------------------------------------------------
    # R3 - ports sensibles
    # ------------------------------------------------------------------
    def _r3_sensitive_ports(self, flows: list[Flow], now: float) -> list[Event]:
        events = []
        for f in flows:
            port = resolve_service_port(f)
            info = lookup_port(port, f.transport)
            if not info or not info.sensitive:
                continue

            # Un service contacte en diffusion (SSDP, mDNS, LLMNR, NetBIOS) n'est
            # pas un service expose : c'est un mecanisme de decouverte, present
            # sur presque tous les reseaux domestiques. Le presenter comme une
            # alerte serait un cri au loup, exactement ce que le cahier des
            # charges interdit. On ignore donc ces cas ici.
            portee_destination = classify_address(f.dst)
            if portee_destination in ("multicast", "diffusion"):
                continue
            if classify_address(f.src) in ("multicast", "diffusion"):
                continue

            inbound = infer_direction(f, self.is_local) == "distant"
            if inbound:
                event = Event(
                    ts=now,
                    kind=KIND_ALERTE,
                    rule="service_sensible_joignable",
                    title=f"Un service sensible ({info.service}) accepte des connexions "
                          f"sur le port {port}",
                    severity="eleve",
                    actor=f.src,
                    flow_key=f.key,
                    evidence={
                        "port": port, "service": info.service,
                        "provenance": f.src, "etat": f.state,
                        "paquets": f.packets,
                    },
                    explanation=(
                        f"OBSERVATION : une connexion entrante depuis {f.src} vers le "
                        f"port local {port} a ete observee, avec {f.packets} paquet(s) "
                        f"et un etat « {f.state} ». "
                        f"ALERTE : le port {port} est documente comme celui de "
                        f"{info.service} ({info.meaning}). {info.why} "
                        f"Exposer ce service sur le reseau elargit inutilement la "
                        f"surface d'attaque. A verifier : ce service doit-il vraiment "
                        f"etre joignable depuis cette machine ?"
                    ),
                )
            else:
                event = Event(
                    ts=now,
                    kind=KIND_OBSERVATION,
                    rule="contact_port_sensible",
                    title=f"Communication sortante vers {info.service} (port {port})",
                    severity="moyen",
                    actor=f.observer(),
                    flow_key=f.key,
                    evidence={
                        "port": port, "service": info.service,
                        "destination": f.distant(), "etat": f.state,
                    },
                    explanation=(
                        f"OBSERVATION : la machine locale ({f.observer()}) a contacte "
                        f"{f.distant()} sur le port {port}, generalement associe a "
                        f"{info.service}. "
                        f"HYPOTHESE : cet usage peut etre legitime (administration a "
                        f"distance volontaire, client de base de donnees) ou signaler "
                        f"une activite non autorisee. Le port seul ne permet pas de "
                        f"trancher : il faut connaitre l'usage attendu de ce poste."
                    ),
                )
            if self._emit(event):
                events.append(event)
        return events

    # ------------------------------------------------------------------
    # R4 - tentatives repetees sur des services fermes
    # ------------------------------------------------------------------
    def _r4_refused(self, flows: list[Flow], now: float) -> list[Event]:
        by_target: dict[tuple[str, int | None], int] = Counter()
        for f in flows:
            if f.tcp_state == "refusee par le destinataire":
                by_target[(f.distant(), f.dst_port)] += 1

        events = []
        for (target, port), count in by_target.items():
            if count < self.config.refused_connections:
                continue
            event = Event(
                ts=now,
                kind=KIND_HYPOTHESE,
                rule="connexions_refusees_repetees",
                title=f"{count} connexions refusees vers {target}:{port}",
                severity="moyen",
                actor=target,
                evidence={"destination": target, "port": port,
                          "nb_echecs": count, "seuil": self.config.refused_connections},
                explanation=(
                    f"OBSERVATION : {count} tentatives de connexion vers {target} sur "
                    f"le port {port} ont ete rejetees par le destinataire (reponse RST). "
                    f"HYPOTHESE : soit un service attendu qui ne repond pas, soit une "
                    f"recherche volontaire de services ouverts. Les deux cas produisent "
                    f"exactement le meme motif sur le reseau."
                ),
            )
            if self._emit(event):
                events.append(event)
        return events

    # ------------------------------------------------------------------
    # R5 - demandes d'ouverture restees sans reponse
    # ------------------------------------------------------------------
    def _r5_unanswered(self, flows: list[Flow], now: float) -> list[Event]:
        unanswered = [f for f in flows
                      if f.local_side == "src"
                      and f.tcp_state == "ouverture demandee"
                      and f.syn_count >= 2]
        if len(unanswered) < self.config.unanswered_syn:
            return []

        event = Event(
            ts=now,
            kind=KIND_HYPOTHESE,
            rule="ouvertures_sans_reponse",
            title=f"{len(unanswered)} communications sans reponse du destinataire",
            severity="moyen",
            evidence={
                "nb_flux": len(unanswered),
                "seuil": self.config.unanswered_syn,
                "exemples": [f"{f.dst}:{f.dst_port}" for f in unanswered[:10]],
            },
            explanation=(
                f"OBSERVATION : {len(unanswered)} communications ont ete ouvertes "
                f"sans recevoir de reponse, et certaines ont ete retentees "
                f"(plusieurs SYN observes). "
                f"HYPOTHESE : un filtrage silencieux (pare-feu qui jette les paquets "
                f"au lieu de les refuser) ou un destinataire injoignable. Ce n'est pas "
                f"en soi un signe d'attaque, mais cela peut aussi accompagner une "
                f"tentative de decouverte de services."
            ),
        )
        return [event] if self._emit(event) else []

    # ------------------------------------------------------------------
    # R6 - volume DNS et noms a forte entropie
    # ------------------------------------------------------------------
    def _r6_dns(self, flows: list[Flow], now: float) -> list[Event]:
        queries = [f.domain for f in flows
                   if f.transport in ("UDP", "TCP") and f.dst_port == 53 and f.domain]
        if len(queries) < self.config.dns_queries:
            return []

        suspicious = []
        for name in queries:
            label = name.split(".")[0] if "." in name else name
            if len(label) >= 12 and shannon_entropy(label) >= self.config.dns_entropy_threshold:
                suspicious.append((name, round(shannon_entropy(label), 2)))

        event = Event(
            ts=now,
            kind=KIND_HYPOTHESE if suspicious else KIND_OBSERVATION,
            rule="volume_dns",
            title=f"{len(queries)} requetes DNS distinctes en "
                  f"{int(self.config.window_seconds)} s"
                  + (f", dont {len(suspicious)} a nom aleatoire" if suspicious else ""),
            severity="moyen" if suspicious else "faible",
            evidence={
                "nb_requetes": len(queries),
                "seuil": self.config.dns_queries,
                "entropie_seuil": self.config.dns_entropy_threshold,
                "noms_suspects": suspicious[:10],
                "exemples": sorted(set(queries))[:10],
            },
            explanation=(
                f"OBSERVATION : {len(queries)} requetes DNS ont ete observees. "
                + (
                    f"{len(suspicious)} d'entre elles portent un nom dont l'entropie "
                    f"depasse {self.config.dns_entropy_threshold} bits par caractere, "
                    f"ce qui est caracteristique d'une chaine generee par programme "
                    f"plutot que choisie par un humain. "
                    f"HYPOTHESE : un tunnel DNS (exfiltration de donnees deguisee en "
                    f"requetes de noms) ou un logiciel dont les domaines sont generes "
                    f"automatiquement. Beaucoup d'autres explications benignes "
                    f"existent : reseaux de diffusion de contenu, telemetrie, "
                    f"protocoles de pair a pair."
                    if suspicious else
                    "Aucun nom a entropie elevee n'a ete detecte parmi eux."
                )
            ),
        )
        return [event] if self._emit(event) else []

    # ------------------------------------------------------------------
    # R7 - un hote concentre la majorite du volume
    # ------------------------------------------------------------------
    def _r7_volume(self, flows: list[Flow], now: float) -> list[Event]:
        total = sum(f.bytes_total for f in flows)
        if total <= 0:
            return []
        # Sans assez de matiere, un pourcentage ne veut rien dire : un seul flux
        # represente mecaniquement 100 % du trafic observe.
        if len(flows) < self.config.volume_min_flows or total < self.config.volume_min_bytes:
            return []

        by_remote: dict[str, int] = Counter()
        for f in flows:
            by_remote[f.distant()] += f.bytes_total

        if len(by_remote) < self.config.volume_min_remote_hosts:
            return []

        top, top_bytes = by_remote.most_common(1)[0]

        # Un prefixe de traduction (NAT64, 6to4) represente des dizaines de
        # destinations reelles : dire « cet hote concentre 97 % du trafic »
        # serait faux et trompeur pour l'utilisateur.
        if is_translation_prefix(top):
            return []

        share = top_bytes / total
        if share < self.config.volume_share:
            return []

        event = Event(
            ts=now,
            kind=KIND_OBSERVATION,
            rule="volume_dominant",
            title=f"{top} concentre {share:.0%} du volume observe",
            severity="info",
            actor=top,
            evidence={"hote": top, "octets": top_bytes, "total_octets": total,
                      "part": round(share, 3), "seuil": self.config.volume_share,
                      "nb_flux_analyses": len(flows)},
            explanation=(
                f"OBSERVATION : {top} represente {share:.0%} des {total} octets "
                f"observes pendant la fenetre. C'est un fait de mesure. "
                f"HYPOTHESE : rien en soi. Un service de diffusion video ou de "
                f"sauvegarde en ligne produit legitimement ce profil. Cette mesure "
                f"sert de repere pour reperer un transfert inhabituel, pas de preuve."
            ),
        )
        return [event] if self._emit(event) else []

    # ------------------------------------------------------------------
    # R8 - connexions regulieres vers la meme destination (balise)
    # ------------------------------------------------------------------
    def _r8_beaconing(self, flows: list[Flow], now: float) -> list[Event]:
        series: dict[tuple[str, int | None], list[float]] = defaultdict(list)
        for f in flows:
            if f.local_side == "src" and f.transport == "TCP":
                series[(f.distant(), f.dst_port)].append(f.first_seen)

        events = []
        for (target, port), times in series.items():
            if len(times) < self.config.beacon_min_series:
                continue
            times.sort()
            gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
            if len(gaps) < 2:
                continue
            mean = sum(gaps) / len(gaps)
            if mean <= 0:
                continue
            variance = sum((g - mean) ** 2 for g in gaps) / len(gaps)
            jitter = math.sqrt(variance) / mean
            if jitter > self.config.beacon_jitter:
                continue

            event = Event(
                ts=now,
                kind=KIND_HYPOTHESE,
                rule="connexions_regulieres",
                title=f"Connexions regulieres vers {target}:{port} "
                      f"(toutes les {mean:.0f} s)",
                severity="moyen",
                actor=target,
                evidence={
                    "destination": target, "port": port, "nb_connexions": len(times),
                    "intervalle_moyen_s": round(mean, 2),
                    "dispersion_relative": round(jitter, 3),
                    "seuil_dispersion": self.config.beacon_jitter,
                },
                explanation=(
                    f"OBSERVATION : {len(times)} connexions vers {target} sur le port "
                    f"{port} se sont produites a intervalles reguliers (en moyenne "
                    f"{mean:.0f} secondes, dispersion {jitter:.0%}). "
                    f"HYPOTHESE : ce rythme mecanique evoque une balise informatique "
                    f"qui signale sa presence a intervalle fixe, procede classique "
                    f"d'un logiciel de controle a distance. Il faut toutefois noter "
                    f"que la plupart des logiciels modernes se comportent exactement "
                    f"ainsi : messagerie, client de messagerie d'entreprise, agent de "
                    f"supervision, mises a jour. Cette regle signale un rythme, pas "
                    f"une compromission."
                ),
            )
            if self._emit(event):
                events.append(event)
        return events

    # ------------------------------------------------------------------
    # R9 - ecart par rapport au comportement habituel observe
    # ------------------------------------------------------------------
    def _r9_baseline(self, flows: list[Flow], now: float) -> list[Event]:
        remotes = {f.distant() for f in flows
                   if f.local_side == "src" and classify_address(f.distant()) == "public"}
        self._windows_seen += 1
        current = float(len(remotes))

        if self._baseline_remotes is None:
            self._baseline_remotes = current
            self._known_remotes |= remotes
            return []

        baseline = self._baseline_remotes
        # Moyenne glissante : la reference s'adapte progressivement
        self._baseline_remotes = (baseline * 0.7) + (current * 0.3)
        self._known_remotes |= remotes

        if baseline < 3 or current < baseline * self.config.baseline_factor:
            return []

        event = Event(
            ts=now,
            kind=KIND_OBSERVATION,
            rule="ecart_comportement",
            title=f"{int(current)} destinations publiques contactees, contre "
                  f"{baseline:.0f} en moyenne",
            severity="faible",
            evidence={
                "destinations_actuelles": int(current),
                "moyenne_reference": round(baseline, 2),
                "facteur": round(current / baseline, 2),
                "seuil_facteur": self.config.baseline_factor,
            },
            explanation=(
                f"OBSERVATION : le nombre de destinations publiques contactees "
                f"({int(current)}) depasse {self.config.baseline_factor} fois la "
                f"moyenne observee jusqu'ici sur cette session ({baseline:.1f}). "
                f"C'est un ecart statistique mesure sur le trafic reel de cette "
                f"machine, pas une regle theorique. "
                f"HYPOTHESE : un changement d'usage (mise a jour, telechargement), ou "
                f"une activite inhabituelle. La reference est une moyenne glissante : "
                f"elle s'adapte, donc un pic durable devient la nouvelle normale."
            ),
        )
        return [event] if self._emit(event) else []

    # ------------------------------------------------------------------
    # R10 - protocole en clair transportant des informations sensibles
    # ------------------------------------------------------------------
    def _r10_cleartext(self, flows: list[Flow], now: float) -> list[Event]:
        events = []
        for f in flows:
            info = lookup_port(resolve_service_port(f), f.transport)
            # On ne signale que si le service transmet des identifiants en clair
            if not info or not info.cleartext:
                continue
            if info.service not in ("Telnet", "FTP (controle)", "HTTP", "POP3", "IMAP",
                                    "SMTP", "LDAP", "SNMP"):
                continue
            if f.packets < 4:      # simple poignee de main : pas encore de donnees
                continue

            event = Event(
                ts=now,
                kind=KIND_OBSERVATION,
                rule="protocole_en_clair",
                title=f"Echanges {info.service} non chiffres avec {f.distant()}",
                severity="faible",
                actor=f.observer(),
                flow_key=f.key,
                evidence={
                    "service": info.service, "port": f.dst_port,
                    "destination": f.distant(), "paquets": f.packets,
                    "octets": f.bytes_total,
                },
                explanation=(
                    f"OBSERVATION : {f.packets} paquets ont ete echanges en {info.service} "
                    f"avec {f.distant()}, protocole qui ne chiffre pas ses echanges. "
                    f"HYPOTHESE : si des identifiants ou des donnees personnelles "
                    f"circulent par ce canal, ils sont lisibles par toute personne "
                    f"placee sur le chemin. Nous ne pouvons pas l'affirmer : nous ne "
                    f"stockons ni n'analysons le contenu des paquets."
                ),
            )
            if self._emit(event):
                events.append(event)
        return events
