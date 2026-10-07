#!/usr/bin/env python3
"""Point d'entree de l'application.

Trois facons de lancer le projet :

    python run.py                      serveur de developpement (rechargement auto)
    python run.py --mode cloud         consultation d'historique seulement
    gunicorn -k uvicorn.workers.UvicornWorker app.web.app:create_app   production

La capture reseau n'est possible qu'en mode local : elle necessite le pilote
Npcap (Windows) ou libpcap (Linux/macOS) sur la machine qui execute le
processus.
"""

from __future__ import annotations

import argparse
import logging
import sys

import uvicorn

from app.config import load_settings
from app.web.app import create_app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Intelligent Network Packet Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="adresse d'ecoute (defaut : 127.0.0.1, accessible depuis ce poste seulement)")
    parser.add_argument("--port", type=int, default=8000, help="port d'ecoute (defaut : 8000)")
    parser.add_argument("--mode", choices=["local", "cloud"],
                        help="force le mode : local (capture) ou cloud (consultation)")
    parser.add_argument("--reload", action="store_true", help="rechargement automatique en developpement")
    parser.add_argument("--log-level", default="info",
                        choices=["critical", "error", "warning", "info", "debug"])
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    settings = load_settings()
    if args.mode:
        settings.mode = args.mode

    problems = settings.validate()
    if problems:
        for problem in problems:
            print(f"ATTENTION : {problem}", file=sys.stderr)

    app = create_app(settings)

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )

    print("=" * 62)
    print("  Intelligent Network Packet Analyzer")
    print("=" * 62)
    print(f"  Mode              : {settings.mode}"
          + ("  (capture reseau active)" if settings.is_local else "  (consultation seule)"))
    print(f"  Interface web     : http://{args.host}:{args.port}")
    print(f"  Documentation API : http://{args.host}:{args.port}/api/docs")
    print(f"  Base locale       : {settings.sqlite_path}")
    print(f"  Supabase          : {'active' if settings.supabase_enabled else 'desactive'}")
    print(f"  Enrichissement    : {'active' if settings.enrich_enabled else 'desactive'}")
    print("=" * 62)

    # Sur une plateforme d'hebergement, le port est impose par l'environnement
    import os
    port = int(os.getenv("PORT", args.port))
    host = os.getenv("HOST", args.host)

    if args.reload:
        uvicorn.run("app.web.app:create_app", factory=True, host=host, port=port,
                    reload=True, log_level=args.log_level)
    else:
        uvicorn.run(app, host=host, port=port, log_level=args.log_level)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
