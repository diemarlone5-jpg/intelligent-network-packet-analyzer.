"""Moteur d'explication : transformer des faits techniques en texte humain.

C'est la piece centrale du projet. Sa regle de conception tient en une phrase,
reprise du cahier des charges :

    NE JAMAIS PRESENTER UNE HYPOTHESE COMME UNE CERTITUDE.

Pour rendre cette regle verifiable, chaque explication est decoupee en trois
zones distinctes :

    FAITS            ce qui a ete mesure dans les paquets (date, port, drapeaux)
    INTERPRETATIONS  ce que cela signifie habituellement, avec sa justification
                     et un niveau de confiance
    RESERVES         ce que l'observation ne permet PAS de conclure

Le texte final (`plain_text`) est construit a partir de ces trois zones : il
n'est jamais produit a partir d'autre chose, et notamment jamais par une IA.
Une couche d'IA peut ensuite reformuler ce texte, mais elle ne peut pas
introduire un fait absent d'ici.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.analysis.flows import (
    human_bytes,
    human_duration,
    infer_direction,
    resolve_service_port,
    state_label,
)
from app.analysis.protocols import (
    APP_PROTOCOLS,
    TRANSPORT_KNOWLEDGE,
    describe_scope,
    lookup_port,
)
from app.models import Event, Flow, PacketRecord

CONF_HAUTE, CONF_MOYENNE, CONF_FAIBLE = "haute", "moyenne", "faible"


@dataclass
class Fact:
    """Un element mesure, non discutable."""

    label: str
    value: str
    origin: str = "observation directe du paquet"


@dataclass
class Interpretation:
    """Une lecture probable d'un fait, toujours rattachee a sa justification."""

    statement: str
    basis: str
    confidence: str = CONF_MOYENNE


@dataclass
class Explanation:
    headline: str
    confidence: str
    facts: list[Fact] = field(default_factory=list)
    interpretations: list[Interpretation] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)
    plain_text: str = ""

    def to_dict(self) -> dict:
        return {
            "headline": self.headline,
            "confidence": self.confidence,
            "facts": [f.__dict__ for f in self.facts],
            "interpretations": [i.__dict__ for i in self.interpretations],
            "caveats": self.caveats,
            "plain_text": self.plain_text,
        }


# --------------------------------------------------------------------------
# Titre de l'explication
# --------------------------------------------------------------------------


def _headline(flow: Flow, service_name: str | None, app: str | None) -> str:
    """Phrase de titre, volontairement prudente ('probable', 'compatible')."""
    if app == "ARP":
        return "Echange local : resolution d'adresse materielle (ARP)"
    if app == "ICMP":
        return "Message de controle reseau (ICMP)"
    if app == "DNS":
        return "Resolution de nom de domaine (DNS)"
    if app == "DHCP":
        return "Configuration automatique de reseau (DHCP)"

    if app == "TLS" or service_name in ("HTTPS", "HTTPS alternatif"):
        domain = f" vers {flow.domain}" if flow.domain else ""
        return f"Communication chiffree (TLS/HTTPS) probable{domain}"
    if service_name in ("HTTP", "HTTP alternatif", "HTTP de developpement"):
        return "Echange web en clair probable (HTTP)"
    if service_name:
        return f"Communication {service_name} probable"
    return "Communication vers un service non documente"


# --------------------------------------------------------------------------
# Moteur
# --------------------------------------------------------------------------


class Explainer:
    """Produit l'explication d'une communication, d'un paquet ou d'un evenement."""

    def __init__(self, is_local=None) -> None:
        # `is_local` permet de qualifier les adresses sans dependre du parseur
        self.is_local = is_local or (lambda ip: False)

    # ------------------------------------------------------------------
    def explain_flow(self, flow: Flow, intel=None) -> Explanation:
        """Explication complete d'une communication."""
        app = flow.app_protocol
        service_port = resolve_service_port(flow)
        port_info = lookup_port(service_port, flow.transport)
        service_name = port_info.service if port_info else None

        facts: list[Fact] = []
        interps: list[Interpretation] = []
        caveats: list[str] = []

        # ---------------- FAITS ----------------
        facts.append(Fact("Adresse locale", flow.observer()))
        facts.append(Fact("Adresse distante", flow.distant()))
        facts.append(Fact("Protocole de transport", flow.transport or "non determine"))
        if service_port is not None:
            if flow.handshake_seen:
                origin = "port de destination du SYN initiateur"
            elif flow.transport == "TCP":
                origin = ("port deduit, le debut de la connexion n'a pas ete observe")
            else:
                origin = ("port deduit de la position des ports : ce protocole "
                          "n'etablit pas de connexion, il n'y a donc pas de SYN")
            facts.append(Fact("Port du service contacte", str(service_port), origin))
        if flow.src_port is not None and flow.dst_port is not None:
            facts.append(Fact("Ports observes",
                              f"{flow.src_port} -> {flow.dst_port}"))
        facts.append(Fact("Nombre de paquets", str(flow.packets), "compteur du flux"))
        facts.append(Fact("Volume echange", human_bytes(flow.bytes_total),
                          "compteur du flux"))
        facts.append(Fact("Duree observee", human_duration(flow.duration),
                          "compteur du flux"))
        facts.append(Fact("Etat", state_label(flow), "machine a etats TCP"))
        if app:
            facts.append(Fact("Protocole applicatif reconnu", app,
                              "structure du paquet"))
        if flow.domain:
            facts.append(Fact("Nom de domaine observe", flow.domain,
                              "SNI TLS ou en-tete HTTP ou requete DNS"))
        if flow.rst_count:
            facts.append(Fact("Reinitialisations (RST)", str(flow.rst_count),
                              "compteur du flux"))
        if flow.retransmissions:
            facts.append(Fact("Retransmissions estimees", str(flow.retransmissions),
                              "compteur du flux"))

        # Enrichissement externe
        if intel is not None and getattr(intel, "source", None):
            if intel.country:
                facts.append(Fact("Pays du destinataire distant", intel.country,
                                  f"API externe ({intel.source})"))
            if intel.org or intel.isp:
                facts.append(Fact("Operateur / organisation", intel.org or intel.isp,
                                  f"API externe ({intel.source})"))
            if intel.asn:
                facts.append(Fact("Systeme autonome", str(intel.asn),
                                  f"API externe ({intel.source})"))
            if intel.reverse_dns:
                facts.append(Fact("Nom DNS inverse", intel.reverse_dns,
                                  f"API externe ({intel.source})"))

        # ---------------- INTERPRETATIONS ----------------
        local_addr, remote_addr = flow.observer(), flow.distant()
        local_kind = describe_scope(local_addr)
        remote_kind = describe_scope(remote_addr)

        interps.append(Interpretation(
            statement=(
                f"{remote_addr} est une {remote_kind}."
                if remote_kind != "inconnu" else
                "La nature de l'adresse distante n'a pas pu etre determinee."
            ),
            basis="classification de l'adresse selon les plages normalisees (RFC 1918 / 6890)",
            confidence=CONF_HAUTE if remote_kind != "inconnu" else CONF_FAIBLE,
        ))

        if flow.transport in TRANSPORT_KNOWLEDGE:
            tinfo = TRANSPORT_KNOWLEDGE[flow.transport]
            interps.append(Interpretation(
                statement=(
                    f"Le transport {flow.transport} {tinfo.role}. "
                    f"On l'utilise typiquement pour : {tinfo.example}."
                ),
                basis=f"protocole de transport reellement observe dans le paquet",
                confidence=CONF_HAUTE,
            ))

        if port_info:
            interps.append(Interpretation(
                statement=(
                    f"Le port {port_info.port}/{port_info.transport} est "
                    f"habituellement associe au service {port_info.service}, "
                    f"qui sert a {port_info.meaning}. {port_info.why}"
                ),
                basis=(
                    "table de connaissance des ports ; c'est une convention "
                    "d'usage et non une preuve du service reellement utilise"
                ),
                confidence=port_info.confidence,
            ))
        else:
            interps.append(Interpretation(
                statement=(
                    f"Le port {service_port} ne correspond a aucun service "
                    "standard documente dans notre base. Cela signifie "
                    "seulement que nous ne pouvons pas l'interpreter."
                ),
                basis="absence d'entree correspondante dans la table des ports",
                confidence=CONF_HAUTE,
            ))

        # Sens de la communication
        direction = infer_direction(flow, self.is_local)
        sans_connexion = flow.transport != "TCP"
        if direction == "local":
            direction_text = (
                "C'est la machine locale qui a pris l'initiative de la communication."
            )
            if flow.handshake_seen:
                direction_basis = "SYN observe en provenance de la machine locale"
                direction_confidence = CONF_HAUTE
            elif sans_connexion:
                direction_basis = (
                    f"aucun etablissement de connexion en {flow.transport} : le sens "
                    f"est deduit de la position des ports (le service ecoute sur un "
                    f"port bas, le client utilise un port eleve)"
                )
                direction_confidence = CONF_MOYENNE
            else:
                direction_basis = (
                    "aucun SYN observe : deduit de la position des ports "
                    "(le service connait un port bas, le client un port eleve)"
                )
                direction_confidence = CONF_MOYENNE
        elif direction == "distant":
            direction_text = (
                "C'est la machine locale qui a ete contactee : une autre machine a "
                "pris l'initiative de la communication."
            )
            if flow.handshake_seen:
                direction_basis = "SYN observe en provenance de l'hote distant"
                direction_confidence = CONF_HAUTE
            elif sans_connexion:
                direction_basis = (
                    f"aucun etablissement de connexion en {flow.transport} : le sens "
                    f"est deduit de la position des ports"
                )
                direction_confidence = CONF_MOYENNE
            else:
                direction_basis = "aucun SYN observe : deduit de la position des ports"
                direction_confidence = CONF_MOYENNE
        else:
            direction_text = (
                "Le sens de l'initiative n'a pas pu etre determine : "
                + ("les deux ports jouent ici le meme role (diffusion locale)."
                   if sans_connexion else
                   "le debut de la connexion n'a pas ete observe.")
            )
            direction_basis = (
                "aucun etablissement de connexion et ports de meme nature"
                if sans_connexion
                else "aucun SYN observe et les ports ne permettent pas de trancher"
            )
            direction_confidence = CONF_FAIBLE

        interps.append(Interpretation(
            statement=direction_text,
            basis=direction_basis,
            confidence=direction_confidence,
        ))

        # Chiffrement
        if app == "TLS":
            interps.append(Interpretation(
                statement=(
                    "Le contenu de cette communication est chiffre. Il n'est pas "
                    "possible de savoir quelles donnees circulent, seulement leur "
                    "volume et leur rythme."
                    + (f" En revanche, le client a annonce vouloir joindre "
                       f"« {flow.domain} » lors de la negociation : ce nom est "
                       f"visible car il circule en clair." if flow.domain else "")
                ),
                basis="presence d'une en-tete de negociation TLS (octet 0x16) et "
                      "eventuellement du champ SNI",
                confidence=CONF_HAUTE,
            ))
        elif app == "HTTP" or (port_info and port_info.cleartext is True):
            interps.append(Interpretation(
                statement=(
                    "Cette communication n'est pas chiffree : son contenu circule "
                    "en clair et peut etre lu par quiconque se trouve sur le chemin."
                ),
                basis="absence de negociation TLS et port associe a un service en clair",
                confidence=CONF_MOYENNE,
            ))

        # Etat
        state = state_label(flow)
        if flow.state == "echec":
            interps.append(Interpretation(
                statement=(
                    "La connexion a ete refusee : le destinataire a repondu par une "
                    "reinitialisation (RST). Cela signifie generalement qu'aucun "
                    "service n'ecoute sur ce port, ou qu'un pare-feu a bloque l'acces."
                ),
                basis=f"compteur de reinitialisations = {flow.rst_count}",
                confidence=CONF_MOYENNE,
            ))
        elif flow.state == "fermee":
            interps.append(Interpretation(
                statement=(
                    "La connexion s'est terminee normalement : les deux parties ont "
                    "echange leurs demandes de fermeture (FIN)."
                ),
                basis=f"compteur de fermetures (FIN) = {flow.fin_count}",
                confidence=CONF_HAUTE,
            ))
        elif flow.state == "inactive":
            interps.append(Interpretation(
                statement=(
                    "La communication est etablie mais plus aucun paquet n'est "
                    "observe depuis un moment."
                ),
                basis="delai ecoule depuis le dernier paquet superieur au seuil d'inactivite",
                confidence=CONF_MOYENNE,
            ))
        elif flow.state in ("etablie", "en cours"):
            interps.append(Interpretation(
                statement="La communication est active pendant la fenetre d'observation.",
                basis=f"etat TCP deduit des drapeaux observes ({state})",
                confidence=CONF_MOYENNE,
            ))

        # ---------------- RESERVES ----------------
        caveats.append(
            "Un port est une convention : un service peut parfaitement ecouter "
            "sur un port inhabituel, et un autre service peut occuper un port "
            "standard."
        )
        caveats.append(
            "L'analyse porte uniquement sur les paquets captures pendant la "
            "fenetre d'observation. Un silence n'est pas une absence d'activite."
        )
        if not flow.handshake_seen and flow.transport == "TCP":
            caveats.append(
                "Le debut de cette communication n'a pas ete observe : le port du "
                "service et le sens de l'initiative sont deduits, pas mesures."
            )
        elif flow.transport != "TCP":
            caveats.append(
                f"{flow.transport} n'etablit pas de connexion : il n'existe ni "
                f"ouverture ni fermeture a observer, seulement des datagrammes."
            )
        if flow.state == "nouvelle":
            caveats.append(
                "La connexion vient d'etre observee : son issue n'est pas encore "
                "connue."
            )
        if app != "TLS" and port_info is None:
            caveats.append(
                "Aucun protocole applicatif n'a pu etre identifie dans le contenu."
            )

        confidence = self._overall_confidence(port_info, app, flow)
        if not flow.handshake_seen and confidence == CONF_HAUTE:
            # Sans le debut de la connexion, on ne s'autorise pas la confiance
            # maximale : le port du service lui-meme est deduit.
            confidence = CONF_MOYENNE
        explanation = Explanation(
            headline=_headline(flow, service_name, app),
            confidence=confidence,
            facts=facts,
            interpretations=interps,
            caveats=caveats,
        )
        explanation.plain_text = self._compose(explanation, flow, port_info,
                                               direction, service_port)
        return explanation

    # ------------------------------------------------------------------
    @staticmethod
    def _overall_confidence(port_info, app, flow: Flow) -> str:
        """Confiance globale : jamais "haute" sans fait solide a l'appui."""
        if app in ("TLS", "DNS", "ARP", "DHCP") and flow.packets >= 3:
            return CONF_HAUTE
        if port_info and port_info.confidence == "haute" and flow.packets >= 3:
            return CONF_HAUTE
        if port_info or app:
            return CONF_MOYENNE
        return CONF_FAIBLE

    # ------------------------------------------------------------------
    @staticmethod
    def _compose(exp: Explanation, flow: Flow, port_info,
                 direction: str = "inconnu", service_port: int | None = None) -> str:
        """Assemble le texte humain a partir des faits et interpretations."""
        parts: list[str] = []

        # 1. Qui parle a qui
        if flow.transport == "ARP":
            parts.append(
                f"Un appareil du reseau local demande a qui appartient l'adresse "
                f"{flow.dst}. Ce n'est pas une communication vers Internet : il "
                f"s'agit d'un echange purement local."
            )
        else:
            if direction == "local":
                sens = "a pris l'initiative d'etablir une communication avec"
            elif direction == "distant":
                sens = "a ete contacte par"
            else:
                sens = "echange des donnees avec"
            parts.append(
                f"La machine locale ({flow.observer()}) {sens} {flow.distant()}"
                + (f", sur le port {service_port}." if service_port is not None else ".")
            )

        # 2. Sens du port
        if port_info:
            parts.append(
                f"Ce port est generalement utilise par le service "
                f"{port_info.service}, dont le role est de {port_info.meaning}."
            )
        elif service_port is not None:
            parts.append(
                f"Le port {service_port} n'est pas un port standard documente : "
                f"nous ne pouvons pas en deduire le service."
            )

        # 3. Chiffrement
        if flow.app_protocol == "TLS":
            parts.append(
                "Le contenu echange est chiffre : on peut mesurer le volume, mais "
                "pas lire les donnees."
                + (f" Le nom de domaine « {flow.domain} » a toutefois ete observe "
                   f"en clair lors de la negociation." if flow.domain else "")
            )
        elif flow.app_protocol == "HTTP":
            parts.append(
                "Le contenu circule en clair : il est lisible par un observateur "
                "place sur le chemin."
            )
        elif port_info and port_info.cleartext:
            parts.append(
                f"Le service {port_info.service} ne chiffre pas ses echanges par "
                f"defaut."
            )

        # 4. Deroulement
        parts.append(
            f"Cette communication a ete observee pendant {human_duration(flow.duration)}, "
            f"avec {flow.packets} paquet(s) pour {human_bytes(flow.bytes_total)} "
            f"de donnees. Etat : {state_label(flow)}."
        )

        # 5. Conclusion prudente
        if exp.confidence == "haute":
            parts.append(
                "Les elements observes convergent, ce qui rend cette lecture "
                "probable sans pour autant la rendre certaine."
            )
        elif exp.confidence == "moyenne":
            parts.append(
                "Cette lecture est probable mais repose sur peu d'elements : "
                "elle doit etre confirmee par d'autres observations."
            )
        else:
            parts.append(
                "Trop peu d'elements sont disponibles pour proposer autre chose "
                "qu'une hypothese prudente."
            )

        return " ".join(parts)

    # ------------------------------------------------------------------
    def explain_packet(self, record: PacketRecord) -> Explanation:
        """Explication courte, au niveau d'un paquet unique."""
        port_info = lookup_port(record.dst_port, record.transport)
        app = record.protocol if record.protocol in APP_PROTOCOLS else None

        facts = [
            Fact("Instant", f"{record.ts:.3f} (horodatage de capture)"),
            Fact("Source", f"{record.src}" + (f":{record.src_port}" if record.src_port else "")),
            Fact("Destination", f"{record.dst}" + (f":{record.dst_port}" if record.dst_port else "")),
            Fact("Taille", f"{record.size} octets"),
        ]
        if record.tcp_flags:
            from app.analysis.protocols import TCP_FLAG_MEANING
            facts.append(Fact("Drapeaux TCP", record.tcp_flags))
        if record.ttl is not None:
            facts.append(Fact("TTL", str(record.ttl)))

        interps: list[Interpretation] = []
        if record.tcp_flags:
            from app.analysis.protocols import TCP_FLAG_MEANING
            meaning = TCP_FLAG_MEANING.get(record.tcp_flags)
            if meaning:
                interps.append(Interpretation(
                    statement=f"Signification habituelle des drapeaux {record.tcp_flags} : {meaning}.",
                    basis="table de signification des drapeaux TCP",
                    confidence=CONF_HAUTE,
                ))
        if port_info:
            interps.append(Interpretation(
                statement=f"Le port de destination renvoie au service {port_info.service} : {port_info.meaning}.",
                basis="table de connaissance des ports",
                confidence=port_info.confidence,
            ))
        if app:
            info = APP_PROTOCOLS[app]
            interps.append(Interpretation(
                statement=f"{info.name} sert a {info.what} On le reconnait a : {info.clues}.",
                basis="structure du paquet reellement observe",
                confidence=CONF_MOYENNE,
            ))

        text = (
            f"Paquet {record.protocol} de {record.src} vers {record.dst}, "
            f"d'une taille de {record.size} octets."
        )
        if port_info:
            text += f" Le port de destination est generalement lie au service {port_info.service}."
        if record.domain:
            text += f" Le nom de domaine observe est « {record.domain} »."
        if record.tcp_flags and record.tcp_flags in TCP_FLAG_MEANING:
            text += f" {TCP_FLAG_MEANING[record.tcp_flags]}."

        return Explanation(
            headline=_headline_for_packet(record, port_info),
            confidence=CONF_HAUTE if (app or port_info) else CONF_FAIBLE,
            facts=facts,
            interpretations=interps,
            caveats=["Un paquet isole ne represente qu'une partie d'une conversation."],
            plain_text=text,
        )

    # ------------------------------------------------------------------
    def explain_event(self, event: Event) -> str:
        """Texte d'explication d'un evenement detecte."""
        return event.explanation


# --------------------------------------------------------------------------


def _headline_for_packet(record: PacketRecord, port_info) -> str:
    if record.protocol == "ARP":
        return "Paquet ARP : resolution d'adresse locale"
    if record.protocol == "DNS":
        return "Requete ou reponse DNS"
    if record.protocol == "TLS":
        return "Etape de negociation TLS (contenu chiffre)"
    if record.protocol == "HTTP":
        return "Requete ou reponse HTTP en clair"
    if record.protocol == "ICMP":
        return "Message de controle ICMP"
    if port_info:
        return f"Paquet vers le service {port_info.service} probable"
    return f"Paquet {record.protocol}"
