"""Aucun secret ne doit se retrouver dans le depot.

POURQUOI CE TEST EXISTE

Le depot est PUBLIC. Un jeton commite est un jeton donne au monde entier, et le
retirer plus tard ne suffit pas : il reste dans l'historique Git, ou n'importe
qui peut le relire.

Ce test ne remplace pas la vigilance, il la rend automatique : il tourne a
chaque `pytest`, donc un secret ne peut plus partir par inadvertance dans un
commit.

Ce qu'il cherche, ce sont des FORMES de secrets (JWT, cles prefixees), pas des
mots. Chercher le mot « service_role » remontait trois commentaires qui
expliquent la regle de securite : un controle qui crie au loup finit par ne plus
etre lance.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent

MOTIFS = [
    (r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", "jeton JWT"),
    (r"sk-[A-Za-z0-9]{20,}", "cle OpenAI"),
    (r"ghp_[A-Za-z0-9]{20,}", "jeton GitHub"),
    (r"github_pat_[A-Za-z0-9_]{20,}", "jeton GitHub fin"),
    (r"sbp_[A-Za-z0-9]{20,}", "cle Supabase"),
    (r"AIza[A-Za-z0-9_-]{30,}", "cle Google"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "cle privee"),
]

# Documentation et exemples : ils decrivent la regle, ils ne l'enfreignent pas.
EXCLUS = ("tests/", "GUIDE-", "SOUTENANCE", "README", ".env.example", "outils/")


def fichiers_suivis() -> list[str]:
    try:
        sortie = subprocess.run(
            ["git", "ls-files"], cwd=RACINE,
            capture_output=True, text=True, check=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as erreur:
        pytest.skip(f"git indisponible : {erreur}")
    return [l.strip() for l in sortie.stdout.splitlines() if l.strip()]


def test_aucun_secret_dans_les_fichiers_suivis():
    suivis = fichiers_suivis()
    if not suivis:
        pytest.skip("depot Git vide ou absent")

    trouves = []
    for nom in suivis:
        if any(nom.startswith(e) or e in nom for e in EXCLUS):
            continue
        chemin = RACINE / nom
        if not chemin.is_file() or chemin.stat().st_size > 400_000:
            continue
        texte = chemin.read_text(encoding="utf-8", errors="ignore")
        for motif, etiquette in MOTIFS:
            for m in re.finditer(motif, texte):
                ligne = texte[: m.start()].count("\n") + 1
                trouves.append(f"{nom}:{ligne} — {etiquette}")

    assert not trouves, (
        "Secret(s) present(s) dans un depot PUBLIC :\n- " + "\n- ".join(trouves)
    )


def test_le_fichier_env_n_est_pas_suivi():
    """Le .env contient les vrais secrets : il ne doit jamais etre commite."""
    suivis = fichiers_suivis()
    if not suivis:
        pytest.skip("depot Git vide ou absent")

    interdits = [n for n in suivis if Path(n).name == ".env"]
    assert not interdits, f"Le fichier .env est suivi par Git : {interdits}"


def test_le_controle_detecte_vraiment_un_secret():
    """Un controle qui ne detecte rien ne prouve rien.

    On lui presente un JWT de forme realiste : s'il ne le voit pas, c'est le
    controle qui est casse, pas le depot qui est propre.
    """
    faux = (
        "SUPABASE_SERVICE_KEY="
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UifQ"
        ".abcdefghijklmnopqrstuvwxyz123456"
    )

    detecte = any(re.search(motif, faux) for motif, _ in MOTIFS)

    assert detecte, "le controle ne detecte meme pas un JWT evident"


def test_le_controle_ne_signale_pas_la_documentation():
    """Un commentaire qui EXPLIQUE la regle n'est pas une fuite.

    Sans ce garde-fou, les trois commentaires de securite du projet remontaient
    comme des alertes, et noyaient les vraies.
    """
    commentaire = "L'application serveur utilise la cle `service_role`, qui contourne RLS."

    detecte = any(re.search(motif, commentaire) for motif, _ in MOTIFS)

    assert not detecte, "la documentation sur la securite est prise pour une fuite"
