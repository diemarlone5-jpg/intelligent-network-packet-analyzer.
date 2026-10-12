"""Filtre d'affichage : la barre « Apply a display filter » de Wireshark.

POURQUOI CE MODULE

La recherche par sous-chaine ne suffit pas a analyser du trafic : on veut
pouvoir demander « les paquets DNS vers 8.8.8.8 », « le trafic TCP sur le port
443 » ou « ce qui n'est ni ARP ni mDNS ». C'est ce que fait le filtre
d'affichage de Wireshark, et c'est la fonction la plus utilisee de cet outil.

SYNTAXE ACCEPTEE

    tcp                          un protocole
    dns or arp                   l'un ou l'autre
    not arp                      tout sauf ARP
    tcp and port == 443          combinaison
    ip.addr == 8.8.8.8           une adresse, source ou destination
    ip.src == 192.168.1.5        l'emetteur seulement
    ip.dst == 1.1.1.1            le destinataire seulement
    tcp.port == 443              port de destination ou source
    udp.port == 53
    size > 500                   taille en octets
    contains "telegram"          sous-chaine dans le resume
    (tcp or udp) and size > 100  parentheses

CE QUE CE MODULE NE FAIT PAS

Il ne couvre qu'un sous-ensemble de la syntaxe de Wireshark. Une expression
hors de ce sous-ensemble est REFUSEE avec un message explicite, plutot
qu'interpretation approximative : mieux vaut dire « je ne sais pas faire » que
renvoyer un resultat faux. C'est aussi pour cela que la compilation est faite
cote serveur et testee : une erreur de syntaxe ne doit jamais passer pour un
filtre qui ne trouve rien.
"""

from __future__ import annotations

import re
from typing import Any, Callable

# --------------------------------------------------------------------------
# Grammaire
# --------------------------------------------------------------------------

# Jetons : parentheses, operateurs, mots, chaines, nombres
_TOKEN = re.compile(r"""
    \s*(?:
        (?P<lparen>\() |
        (?P<rparen>\)) |
        (?P<op>>=|<=|==|!=|>|<|=|!) |
        (?P<chaine>"[^"]*"|'[^']*') |
        (?P<mot>[A-Za-z_][A-Za-z0-9_.:\[\]-]*) |
        (?P<ip>[0-9A-Fa-f:.]+) |
        (?P<nombre>[0-9]+)
    )
""", re.VERBOSE)

# Un nom d'hote ou d'adresse peut contenir des caracteres que le motif « mot »
# n'accepte pas : on tolere tout ce qui n'est ni espace ni operateur.
_LIBRE = re.compile(r"\s*([^\s()=!<>]+)")

_MOTS_VIDES = {"and", "or", "not"}


class FilterSyntaxError(ValueError):
    """Expression de filtre invalide. Le message est destine a l'utilisateur."""


# --------------------------------------------------------------------------
# Champs reconnus
# --------------------------------------------------------------------------

# Protocoles filtrables, en minuscules. La correspondance se fait sur le
# protocole identifie ET sur le transport (un paquet « TLS » reste du « tcp »).
PROTOCOLES = {
    "tcp", "udp", "dns", "tls", "http", "quic", "arp", "icmp", "ipv6", "ip",
    "ssdp", "mdns", "ntp", "netbios", "dhcp", "igmp", "tlsv1", "https",
}

_CHAMPS_ADRESSE = {"ip.addr", "addr", "ip"}
_CHAMPS_SOURCE = {"ip.src", "src"}
_CHAMPS_DEST = {"ip.dst", "dst"}
_CHAMPS_PORT = {"port", "ip.port", "tcp.port", "udp.port"}
_CHAMPS_PORT_TCP = {"tcp.port"}
_CHAMPS_PORT_UDP = {"udp.port"}
_CHAMPS_TAILLE = {"size", "length", "len", "frame.len"}
_CHAMPS_RESUME = {"info", "contains"}
_CHAMPS_DOMAINE = {"domain", "dns.qry.name", "tls.handshake.extensions_server_name"}
_CHAMPS_DRAPEAUX = {"tcp.flags", "flags"}

_TOUS_LES_CHAMPS = (_CHAMPS_ADRESSE | _CHAMPS_SOURCE | _CHAMPS_DEST | _CHAMPS_PORT
                    | _CHAMPS_TAILLE | _CHAMPS_RESUME | _CHAMPS_DOMAINE
                    | _CHAMPS_DRAPEAUX)


# --------------------------------------------------------------------------
# Compilation
# --------------------------------------------------------------------------


def compile_filter(expression: str | None) -> Callable[[Any], bool]:
    """Transforme une expression en fonction de test. Leve FilterSyntaxError.

    Une expression vide ou absente accepte tout.
    """
    if expression is None or not str(expression).strip():
        return lambda record: True

    jetons = _tokeniser(str(expression))
    if not jetons:
        return lambda record: True

    parseur = _Parseur(jetons, str(expression))
    predicat = parseur.analyser()
    if not parseur.fini():
        reste = parseur.reste()
        raise FilterSyntaxError(
            f"Expression invalide : element inattendu « {reste} ». "
            "Verifiez les operateurs (et, ou, non) et les parentheses."
        )
    return predicat


def _tokeniser(expression: str) -> list[tuple[str, str]]:
    jetons: list[tuple[str, str]] = []
    position = 0
    longueur = len(expression)

    while position < longueur:
        if expression[position].isspace():
            position += 1
            continue

        correspondance = _TOKEN.match(expression, position)
        if not correspondance:
            # Dernier recours : tout ce qui n'est ni espace ni operateur
            libre = _LIBRE.match(expression, position)
            if not libre:
                raise FilterSyntaxError(
                    f"Expression invalide a la position {position} : "
                    f"« {expression[position:position + 12]} »."
                )
            texte = libre.group(1)
            jetons.append(("mot", texte))
            position = libre.end()
            continue

        position = correspondance.end()
        for nom in ("lparen", "rparen", "op", "chaine", "mot", "ip", "nombre"):
            valeur = correspondance.group(nom)
            if valeur is None:
                continue
            jetons.append((nom, valeur))
            break

    return jetons


class _Parseur:
    """Analyseur descendant recursif : ou / et / non / atome."""

    def __init__(self, jetons: list[tuple[str, str]], expression: str) -> None:
        self.jetons = jetons
        self.expression = expression
        self.index = 0

    # -- utilitaires ---------------------------------------------------
    def fini(self) -> bool:
        return self.index >= len(self.jetons)

    def reste(self) -> str:
        return " ".join(valeur for _, valeur in self.jetons[self.index:self.index + 4])

    def _courant(self) -> tuple[str, str] | None:
        if self.index >= len(self.jetons):
            return None
        return self.jetons[self.index]

    def _valeur_courante(self) -> str:
        courant = self._courant()
        return courant[1].lower() if courant else ""

    def _avancer(self) -> tuple[str, str]:
        courant = self.jetons[self.index]
        self.index += 1
        return courant

    # -- grammaire -----------------------------------------------------
    def analyser(self) -> Callable[[Any], bool]:
        return self._ou()

    def _ou(self) -> Callable[[Any], bool]:
        gauche = self._et()
        while self._valeur_courante() in ("or", "||"):
            self._avancer()
            droite = self._et()
            gauche = _combiner_ou(gauche, droite)
        return gauche

    def _et(self) -> Callable[[Any], bool]:
        gauche = self._non()
        while self._valeur_courante() in ("and", "&&"):
            self._avancer()
            droite = self._non()
            gauche = _combiner_et(gauche, droite)
        return gauche

    def _non(self) -> Callable[[Any], bool]:
        if self._valeur_courante() in ("not", "!"):
            self._avancer()
            interne = self._non()
            return lambda record: not interne(record)
        return self._atome()

    def _atome(self) -> Callable[[Any], bool]:
        courant = self._courant()
        if courant is None:
            raise FilterSyntaxError(
                "Expression incomplete : il manque une condition apres l'operateur."
            )

        if courant[0] == "lparen":
            self._avancer()
            interne = self._ou()
            suivant = self._courant()
            if suivant is None or suivant[0] != "rparen":
                raise FilterSyntaxError("Parenthese fermante manquante.")
            self._avancer()
            return interne

        # « contains "texte" »
        if courant[0] == "mot" and courant[1].lower() == "contains":
            self._avancer()
            suivant = self._courant()
            if suivant is None:
                raise FilterSyntaxError("« contains » doit etre suivi d'un texte.")
            # Le texte peut etre entre guillemets : on les retire. Sans cela, le
            # filtre chercherait « "telegram" » guillemets compris et ne
            # trouverait jamais rien.
            valeur = suivant[1].strip().strip('"').strip("'").lower()
            self._avancer()
            if not valeur:
                raise FilterSyntaxError("« contains » doit etre suivi d'un texte non vide.")

            def test_contient(record) -> bool:
                return valeur in (getattr(record, "info", "") or "").lower()

            return test_contient

        # « champ operateur valeur » ou « protocole »
        if courant[0] in ("mot", "ip", "nombre"):
            self._avancer()
            premier = courant[1]
            suivant = self._courant()

            # Un operateur suit : c'est un champ.
            if suivant is not None and suivant[0] == "op":
                self._avancer()
                operateur = suivant[1]
                valeur = self._courant()
                if valeur is None:
                    raise FilterSyntaxError(
                        f"« {premier} {operateur} » doit etre suivi d'une valeur."
                    )
                self._avancer()
                return _champ(premier, operateur, valeur[1])

            # Sinon : un protocole, ou un champ compare a vrai.
            return _protocole(premier)

        raise FilterSyntaxError(
            f"Element inattendu « {courant[1]} » dans l'expression."
        )


def _combiner_ou(gauche, droite):
    return lambda record: gauche(record) or droite(record)


def _combiner_et(gauche, droite):
    return lambda record: gauche(record) and droite(record)


# --------------------------------------------------------------------------
# Conditions elementaires
# --------------------------------------------------------------------------


def _protocole(nom: str) -> Callable[[Any], bool]:
    """Test sur un nom de protocole : « tcp », « dns », « quic »…"""
    cible = nom.strip().lower().rstrip(":")

    if cible not in PROTOCOLES:
        proches = sorted(p for p in PROTOCOLES if p.startswith(cible[:3]))
        suggestion = f" Essayez peut-etre : {', '.join(proches[:4])}." if proches else ""
        raise FilterSyntaxError(
            f"« {nom} » n'est pas un protocole filtre reconnu.{suggestion} "
            "Pour un champ, utilisez un operateur, par exemple ip.addr == 8.8.8.8."
        )

    def test(record) -> bool:
        protocole = (getattr(record, "protocol", "") or "").lower()
        transport = (getattr(record, "transport", "") or "").lower()
        return protocole == cible or transport == cible

    return test


def _champ(nom: str, operateur: str, valeur: str) -> Callable[[Any], bool]:
    """Construit le test d'un champ compare a une valeur."""
    champ = nom.strip().lower()
    brut = valeur.strip()
    texte = brut.strip('"').strip("'").lower()

    if champ not in _TOUS_LES_CHAMPS and champ not in PROTOCOLES:
        raise FilterSyntaxError(
            f"Le champ « {nom} » n'est pas reconnu. Champs disponibles : "
            "ip.addr, ip.src, ip.dst, tcp.port, udp.port, size, contains, domain."
        )

    # --- taille ---
    if champ in _CHAMPS_TAILLE:
        nombre = _nombre(brut, nom)
        return _comparer_nombre(lambda r: getattr(r, "size", 0) or 0, operateur, nombre)

    # --- adresse (source ou destination) ---
    if champ in _CHAMPS_ADRESSE:
        return lambda record: _comparer_texte(
            (getattr(record, "src", "") or "", getattr(record, "dst", "") or ""),
            operateur, texte, plusieurs=True,
        )

    if champ in _CHAMPS_SOURCE:
        return lambda record: _comparer_texte(
            (getattr(record, "src", "") or "",), operateur, texte,
        )

    if champ in _CHAMPS_DEST:
        return lambda record: _comparer_texte(
            (getattr(record, "dst", "") or "",), operateur, texte,
        )

    # --- ports ---
    if champ in _CHAMPS_PORT:
        nombre = _nombre(brut, nom)
        transports = None
        if champ in _CHAMPS_PORT_TCP:
            transports = ("tcp",)
        elif champ in _CHAMPS_PORT_UDP:
            transports = ("udp",)

        def test(record) -> bool:
            """Vrai si le port de destination OU de source satisfait la condition.

            Un filtre de port doit repondre dans les deux sens : « port == 443 »
            doit trouver aussi bien la demande que la reponse, sans quoi la
            moitie de la conversation disparaitrait du resultat.
            """
            if transports is not None:
                if (getattr(record, "transport", "") or "").lower() not in transports:
                    return False
            for port in (getattr(record, "dst_port", None),
                         getattr(record, "src_port", None)):
                if port is None:
                    continue
                if _comparer_nombre(lambda r, v=port: v, operateur, nombre)(record):
                    return True
            return False

        return test

    # --- domaine ---
    if champ in _CHAMPS_DOMAINE:
        return lambda record: _comparer_texte(
            ((getattr(record, "domain", None) or ""),), operateur, texte,
        )

    # --- drapeaux TCP ---
    if champ in _CHAMPS_DRAPEAUX:
        return lambda record: _comparer_texte(
            ((getattr(record, "tcp_flags", None) or ""),), operateur, texte,
        )

    # --- resume ---
    return lambda record: _comparer_texte(
        ((getattr(record, "info", "") or ""),), operateur, texte,
    )


def _nombre(texte: str, nom_champ: str) -> int:
    try:
        return int(texte)
    except (TypeError, ValueError):
        raise FilterSyntaxError(
            f"Le champ « {nom_champ} » attend un nombre, or « {texte} » n'en est pas un."
        ) from None


def _comparer_nombre(lecteur, operateur: str, attendu: int):
    def test(record) -> bool:
        valeur = lecteur(record)
        if valeur is None:
            return False
        try:
            valeur = int(valeur)
        except (TypeError, ValueError):
            return False
        if operateur in ("==", "="):
            return valeur == attendu
        if operateur == "!=":
            return valeur != attendu
        if operateur == ">":
            return valeur > attendu
        if operateur == "<":
            return valeur < attendu
        if operateur == ">=":
            return valeur >= attendu
        if operateur == "<=":
            return valeur <= attendu
        return False

    return test


def _comparer_texte(valeurs: tuple, operateur: str, texte: str, plusieurs: bool = False):
    """Compare une ou plusieurs chaines a la valeur demandee."""
    if operateur in ("==", "="):
        return any((v or "").lower() == texte for v in valeurs)
    if operateur == "!=":
        return all((v or "").lower() != texte for v in valeurs)
    if operateur == ">":
        return any((v or "").lower() > texte for v in valeurs)
    if operateur == "<":
        return any((v or "").lower() < texte for v in valeurs)
    if operateur == ">=":
        return any((v or "").lower() >= texte for v in valeurs)
    if operateur == "<=":
        return any((v or "").lower() <= texte for v in valeurs)
    return False


def describe_syntax() -> dict[str, Any]:
    """Description de la syntaxe acceptee, pour l'aide et l'API."""
    return {
        "protocoles": sorted(PROTOCOLES),
        "champs": {
            "ip.addr": "adresse source ou destination",
            "ip.src": "adresse de l'emetteur",
            "ip.dst": "adresse du destinataire",
            "tcp.port": "port TCP (source ou destination)",
            "udp.port": "port UDP (source ou destination)",
            "size": "taille du paquet en octets",
            "domain": "nom de domaine associe",
            "contains": "sous-chaine dans le resume du paquet",
        },
        "operateurs": ["==", "!=", ">", "<", ">=", "<="],
        "logiques": ["and", "or", "not", "&&", "||", "!", "(", ")"],
        "exemples": [
            "tcp",
            "dns and ip.addr == 8.8.8.8",
            "not arp and size > 500",
            "tcp.port == 443",
            "(tcp or udp) and size > 1000",
            "contains \"telegram\"",
        ],
    }
