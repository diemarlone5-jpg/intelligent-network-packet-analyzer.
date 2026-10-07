"""Application web : assemble le moteur d'analyse et l'expose en HTTP.

Cette couche ne contient AUCUNE logique d'analyse. Elle se contente de piloter
le moteur (demarrer, arreter, lire des instantanes) et de les rendre. Cette
separation est ce qui permet de tester l'analyse sans lancer de serveur.
"""

from __future__ import annotations

import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.config import BASE_DIR, settings as global_settings
from app.engine import AnalyzerEngine
from app.enrichment import IPEnricher
from app.storage import build_repository

from app.web import routes
from app.web.api import router as api_router

STATIC_DIR = BASE_DIR / "app" / "web" / "static"


def create_app(settings_object=None) -> FastAPI:
    """Construit l'application. Accepte une configuration injectee (tests)."""
    cfg = settings_object or global_settings
    cfg.ensure_dirs()

    problems = cfg.validate()
    if cfg.is_production and problems:
        # En production, une configuration bancale doit empecher le demarrage
        # plutot que produire une application silencieusement insuffisante.
        raise RuntimeError(
            "Configuration invalide, demarrage refuse :\n- " + "\n- ".join(problems)
        )

    repository = build_repository(cfg)
    enricher = IPEnricher(repository, cfg)
    engine = AnalyzerEngine(cfg, repository, enricher)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        engine.start()
        try:
            yield
        finally:
            engine.shutdown()
            enricher.close()

    application = FastAPI(
        title="Intelligent Network Packet Analyzer",
        description=(
            "Capturer, analyser, comprendre et expliquer le trafic reseau. "
            "Chaque conclusion est separee en fait observe et interpretation."
        ),
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )

    application.state.settings = cfg
    application.state.engine = engine
    application.state.repository = repository
    application.state.enricher = enricher
    application.state.config_problems = problems

    application.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    # ------------------------------------------------------------------
    @application.middleware("http")
    async def security_and_csrf(request: Request, call_next):
        """En-tetes de securite, jeton anti-CSRF et page d'erreur lisible."""
        session = request.session
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        request.state.csrf = session["csrf"]

        # Toute action modifiant l'etat exige le jeton de session : une page
        # tierce ne peut donc pas commander l'arret ou le demarrage d'une
        # capture a l'insu de l'utilisateur.
        state_changing = request.method in ("POST", "PUT", "PATCH", "DELETE")
        if state_changing and request.url.path.startswith("/api/"):
            sent = request.headers.get("x-csrf-token", "")
            if not sent or not secrets.compare_digest(sent, session["csrf"]):
                return JSONResponse(
                    {"ok": False, "error": "Jeton de securite invalide ou absent."},
                    status_code=400,
                )

        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; "
            "style-src 'self'; script-src 'self'; connect-src 'self' ws: wss:; "
            "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
        )
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # ATTENTION A L'ORDRE : dans Starlette, le dernier intergiciel enregistre
    # est le plus EXTERIEUR, donc le premier a s'executer. `security_and_csrf`
    # lit `request.session` : il faut donc que SessionMiddleware soit ajoute
    # APRES lui, sans quoi la session n'existe pas encore et chaque requete
    # echoue en 500. Ce point est verifie par un test dedie.
    application.add_middleware(
        SessionMiddleware,
        secret_key=cfg.secret_key,
        session_cookie="pka_session",
        max_age=8 * 3600,
        same_site="lax",
        https_only=cfg.is_production,
    )

    # ------------------------------------------------------------------
    @application.exception_handler(404)
    async def not_found(request: Request, exc):
        return routes.render_error(request, 404, "Page introuvable",
                                   "L'adresse demandee ne correspond a aucune page de l'application.")

    @application.exception_handler(Exception)
    async def server_error(request: Request, exc):
        # Aucune trace technique n'est montree a l'utilisateur : le detail va
        # dans le journal du serveur, la page affiche un message comprehensible.
        import logging
        logging.getLogger("packet-analyzer").exception("Erreur non geree : %s", exc)
        return routes.render_error(
            request, 500, "Erreur interne",
            "Une erreur inattendue s'est produite. L'analyse en cours n'a pas ete "
            "interrompue ; vous pouvez revenir au tableau de bord.",
        )

    application.include_router(routes.router)
    application.include_router(api_router)
    return application
