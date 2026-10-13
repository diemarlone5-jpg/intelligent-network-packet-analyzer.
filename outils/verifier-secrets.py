"""Cherche des secrets commites par erreur dans le depot.

Le depot est PUBLIC : un jeton commite est un jeton rendu public. Ce controle
doit pouvoir etre relance a tout moment, y compris par le correcteur.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent

# Motifs de secrets reconnaissables. On cherche large : un faux positif coute
# une ligne a relire, un faux negatif coute un jeton brule.
MOTIFS = [
    (r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", "jeton JWT"),
    (r"sk-[A-Za-z0-9]{20,}", "cle OpenAI"),
    (r"ghp_[A-Za-z0-9]{20,}", "jeton GitHub"),
    (r"gho_[A-Za-z0-9]{20,}", "jeton GitHub OAuth"),
    (r"github_pat_[A-Za-z0-9_]{20,}", "jeton GitHub fin"),
    (r"sbp_[A-Za-z0-9]{20,}", "cle Supabase"),
    (r"AIza[A-Za-z0-9_-]{30,}", "cle Google"),
    (r"postgres(?:ql)?://[^\s\"']*:[^\s\"'@]+@", "URL de base avec mot de passe"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "cle privee"),
]

# Pourquoi il n'y a pas de motif sur le simple mot « service_role » : une cle
# Supabase EST un JWT, deja couvert par le premier motif. Chercher le mot seul
# ne remontait que des commentaires qui EXPLIQUENT la regle de securite — trois
# fausses alertes qui noient les vraies. Un controle qui crie au loup finit
# qu'on ne le lance plus.

# Fichiers a ignorer : ce sont des exemples, des tests, ou de la documentation.
EXCLUS = ("tests/", "GUIDE-", "SOUTENANCE", "README", ".env.example")


def fichiers_suivis() -> list[str]:
    sortie = subprocess.run(
        ["git", "ls-files"], cwd=RACINE, capture_output=True, text=True, check=True
    )
    return [l.strip() for l in sortie.stdout.splitlines() if l.strip()]


def main() -> int:
    trouves = 0
    examines = 0

    for nom in fichiers_suivis():
        if any(nom.startswith(e) or e in nom for e in EXCLUS):
            continue
        chemin = RACINE / nom
        if not chemin.is_file() or chemin.stat().st_size > 400_000:
            continue
        try:
            texte = chemin.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        examines += 1

        for motif, etiquette in MOTIFS:
            for m in re.finditer(motif, texte):
                ligne = texte[: m.start()].count("\n") + 1
                extrait = m.group(0)[:40]
                print(f"  ALERTE  {nom}:{ligne}  {etiquette}  -> {extrait}")
                trouves += 1

    print()
    print(f"  fichiers examines : {examines}")
    if trouves:
        print(f"  PROBLEMES         : {trouves}  (le depot est public !)")
        return 1
    print("  PROBLEMES         : 0 — aucun secret dans le depot")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
