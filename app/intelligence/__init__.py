"""Couche d'intelligence : resumer et reformuler, jamais inventer.

Principe de conception (exigence explicite du cahier des charges) :

    Le programme produit d'abord des donnees STRUCTUREES ET VERIFIABLES.
    Une couche d'intelligence peut ensuite les reformuler, les resumer,
    les contextualiser. Elle ne doit JAMAIS introduire un fait absent.

Ce module applique cette regle par trois mecanismes concrets :

    1. La couche d'intelligence ne recoit QUE le contexte calcule par le
       moteur (adresses, ports, etats, evenements). Elle n'a aucun acces aux
       paquets bruts et ne peut donc rien observer d'autre.

    2. La consigne donnee au modele lui interdit explicitement d'ajouter une
       adresse, un domaine ou un numero qui ne figure pas dans le contexte.

    3. La reponse est VERIFIEE apres coup : toute adresse IP ou nom de domaine
       cite qui n'apparait pas dans le contexte fait echouer la generation, et
       le resume par regles est utilise a la place.

Le troisieme point est le plus important : il transforme une consigne en
controle verifiable. Un modele qui hallucine est detecte, pas publie.
"""

from app.intelligence.context import SessionContext, build_session_context
from app.intelligence.summarizer import GuardrailViolation, Summarizer, Summary

__all__ = [
    "SessionContext",
    "build_session_context",
    "Summarizer",
    "Summary",
    "GuardrailViolation",
]
