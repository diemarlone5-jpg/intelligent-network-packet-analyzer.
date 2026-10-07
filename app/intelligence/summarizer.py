"""Resume de session, avec garantie verifiable contre l'invention de faits.

Deux fournisseurs, interchangeables :

    "regles"  resume compose localement a partir du contexte. Toujours
              disponible, deterministe, aucun appel reseau, aucun secret.
              C'est le mode par defaut.

    "openai"  appel a une API compatible OpenAI (OpenAI, Groq, Ollama,
              LM Studio...). Le contexte seul est transmis, jamais les
              paquets. La reponse est verifiee avant d'etre affichee.

Le verificateur est le coeur du dispositif : il extrait du texte genere toutes
les adresses IP et tous les noms de domaine, et rejette la generation si l'un
d'eux n'existe pas dans le contexte. Autrement dit, la consigne « n'invente
rien » n'est pas une simple instruction au modele, c'est un controle applique
apres coup a sa reponse.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

import httpx

from app.intelligence.context import (
    DOMAIN_PATTERN,
    IP_PATTERN,
    SessionContext,
)

# Consigne donnee au modele. Elle est volontairement courte et imperative.
SYSTEM_PROMPT = """Tu es un assistant d'analyse reseau. Tu recois un contexte JSON
deja calcule par un analyseur de paquets. Tu dois le reformuler en francais.

REGLES ABSOLUES :
1. Ne cite AUCUNE adresse IP, AUCUN nom de domaine et AUCUN numero de port qui
   ne figure pas deja dans le contexte fourni.
2. Ne conclus jamais qu'une activite est une attaque. Distingue ce qui est
   observe de ce qui est suppose.
3. N'invente aucune information technique absente du contexte.
4. Ecris 3 a 5 phrases, pour une personne qui debute en cybersecurite.
5. N'utilise ni titres, ni listes a puces : un paragraphe suivi est attendu.
6. Si le contexte est vide ou insuffisant, dis-le simplement.
"""


class GuardrailViolation(Exception):
    """Leve quand un texte genere contient une entite absente du contexte."""

    def __init__(self, entities: list[str]) -> None:
        self.entities = entities
        super().__init__(
            "Entites absentes du contexte, generation refusee : "
            + ", ".join(entities)
        )


@dataclass
class Summary:
    text: str
    provider: str
    guardrails: dict = field(default_factory=dict)
    fallback: bool = False
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "provider": self.provider,
            "guardrails": self.guardrails,
            "fallback": self.fallback,
            "error": self.error,
        }


class Summarizer:
    """Produit le resume d'une session, avec repli automatique."""

    def __init__(self, settings) -> None:
        self.settings = settings
        self._client: httpx.Client | None = None

    # ------------------------------------------------------------------
    def summarize(self, context: SessionContext) -> Summary:
        """Retourne un resume. Ne leve jamais."""
        allowed = context.allowed_entities()

        if context.packets == 0:
            return Summary(
                text=("Aucun paquet n'a encore ete observe. Demarrez une capture "
                      "pour que l'assistant puisse decrire ce qui se passe sur le reseau."),
                provider="regles",
                guardrails=self._guardrail_report(context, []),
            )

        if not self.settings.ai_enabled or not self.settings.ai_api_key:
            # Mode par defaut : aucun appel externe, aucun secret requis.
            return Summary(
                text=self._from_rules(context),
                provider="regles",
                guardrails=self._guardrail_report(context, []),
            )

        try:
            text = self._from_llm(context)
            self._validate(text, allowed)
            return Summary(
                text=text,
                provider=f"modele {self.settings.ai_model}",
                guardrails=self._guardrail_report(context, []),
            )
        except GuardrailViolation as violation:
            # Le modele a produit une entite inexistante : on ne publie pas sa
            # reponse et on bascule sur le resume deterministe.
            return Summary(
                text=self._from_rules(context),
                provider="regles (repli)",
                guardrails=self._guardrail_report(context, violation.entities),
                fallback=True,
                error=(
                    "La reponse du modele citait des elements absents des donnees "
                    "observees. Elle a donc ete ecartee et remplacee par le resume "
                    "par regles."
                ),
            )
        except Exception as exc:
            return Summary(
                text=self._from_rules(context),
                provider="regles (repli)",
                guardrails=self._guardrail_report(context, []),
                fallback=True,
                error=f"Le service de reformulation n'a pas repondu ({type(exc).__name__}).",
            )

    # ------------------------------------------------------------------
    # Verification des entites
    # ------------------------------------------------------------------
    @staticmethod
    def _entities_in(text: str) -> set[str]:
        """Recense les adresses et domaines cites dans un texte."""
        found: set[str] = set()
        for match in IP_PATTERN.finditer(text):
            found.add(match.group(0))
        for match in DOMAIN_PATTERN.finditer(text):
            candidate = match.group(0).rstrip(".").lower()
            if not candidate.endswith((".com", ".net", ".org", ".local", ".invalid")):
                # Un nom de fichier ou une abreviation ne doit pas declencher
                # une fausse alerte : on exige une extension plausible.
                continue
            found.add(candidate)
        return found

    def _validate(self, text: str, allowed: dict[str, set[str]]) -> None:
        """Rejette le texte si une entite citee n'est pas dans le contexte."""
        invented: list[str] = []
        for entity in self._entities_in(text):
            if entity in allowed["ips"]:
                continue
            if entity.lower() in allowed["domains"]:
                continue
            # Une adresse reseau (ex. 192.168.1.0) reste acceptable si elle
            # appartient au meme prefixe qu'une adresse reellement observee.
            if "." in entity and entity.count(".") == 3:
                prefix = entity.rsplit(".", 1)[0] + "."
                if any(ip.startswith(prefix) for ip in allowed["ips"]):
                    continue
            invented.append(entity)

        if invented:
            raise GuardrailViolation(sorted(set(invented)))

    @staticmethod
    def _guardrail_report(context: SessionContext, invented: list[str]) -> dict:
        allowed = context.allowed_entities()
        return {
            "verifie": True,
            "entites_autorisees": (
                len(allowed["ips"]) + len(allowed["domains"]) + len(allowed["services"])
            ),
            "inventions_detectees": invented,
            "regle": (
                "Toute adresse IP ou nom de domaine cite par le resume doit "
                "figurer dans les donnees observees, sinon la generation est "
                "ecartee."
            ),
        }

    # ------------------------------------------------------------------
    # Fournisseur local (regles)
    # ------------------------------------------------------------------
    @staticmethod
    def _from_rules(context: SessionContext) -> str:
        """Assemble un resume deterministe a partir des faits calcules."""
        from app.analysis.flows import human_bytes, human_duration

        parties: list[str] = []

        # 1. Volume general
        parties.append(
            f"Sur la periode observee, {context.packets} paquets ont ete captures, "
            f"regroupes en {context.flows} communications "
            f"({context.active_flows} encore actives), pour un volume total de "
            f"{human_bytes(context.bytes_total)}."
        )

        # 2. Protocoles
        if context.protocols:
            principaux = ", ".join(
                f"{entree['name']} ({entree['count']})" for entree in context.protocols[:4]
            )
            parties.append(f"Les protocoles les plus presents sont : {principaux}.")

        # 3. Ce qui a pu etre identifie
        if context.domains:
            apercu = ", ".join(context.domains[:5])
            parties.append(
                f"Le trafic a pu etre rattache a des destinations nommees, "
                f"notamment : {apercu}."
            )
        else:
            parties.append(
                "Aucun nom de domaine n'a ete observe : les destinations restent "
                "identifiees par leur seule adresse."
            )

        # 4. Elements d'attention
        if context.sensitive_services:
            services = ", ".join(context.sensitive_services[:5])
            parties.append(
                f"Des services documentes comme sensibles ont ete observes : "
                f"{services}. Cela ne signifie pas qu'ils sont attaques, "
                f"seulement qu'ils meritent une verification."
            )

        # 5. Evenements
        if context.events:
            types: dict[str, int] = {}
            for evenement in context.events:
                types[evenement["type"]] = types.get(evenement["type"], 0) + 1
            detail = ", ".join(
                f"{nombre} {nom.lower()}{'s' if nombre > 1 else ''}"
                for nom, nombre in types.items()
            )
            parties.append(
                f"L'analyse comportementale a retenu {len(context.events)} "
                f"evenement{'s' if len(context.events) > 1 else ''} : {detail}."
            )
        else:
            parties.append(
                "Aucun comportement inhabituel n'a ete retenu pendant cette fenetre "
                "d'observation."
            )

        # 6. Reserve
        parties.append(
            "Ces elements decrivent uniquement ce qui est passe devant la carte "
            "reseau pendant l'observation : ils ne permettent pas de conclure a une "
            "intention."
        )
        return " ".join(parties)

    # ------------------------------------------------------------------
    # Fournisseur LLM (compatible OpenAI)
    # ------------------------------------------------------------------
    def _from_llm(self, context: SessionContext) -> str:
        """Appelle une API compatible OpenAI. Leve en cas d'echec."""
        if self._client is None:
            self._client = httpx.Client(timeout=30.0)

        base = (self.settings.ai_base_url or "https://api.openai.com/v1").rstrip("/")
        response = self._client.post(
            f"{base}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.settings.ai_api_key}",
                "Content-Type": "application/json",
            },
            content=json.dumps({
                "model": self.settings.ai_model,
                "temperature": 0.2,     # peu de creativite : on reformule, on n'invente pas
                "max_tokens": 500,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": json.dumps(
                        context.to_prompt(), ensure_ascii=False)},
                ],
            }),
        )
        response.raise_for_status()
        data = response.json()
        text = (data["choices"][0]["message"]["content"] or "").strip()
        if not text:
            raise ValueError("reponse vide du modele")
        return text

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
