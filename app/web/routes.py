"""Pages HTML de l'application."""

from __future__ import annotations

import time

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.analysis.flows import human_bytes, human_duration
from app.analysis.protocols import describe_scope
from app.config import BASE_DIR
from app.models import KIND_ALERTE, KIND_HYPOTHESE, KIND_OBSERVATION
from app.capture.interfaces import list_interfaces, primary_address

TEMPLATES_DIR = BASE_DIR / "app" / "web" / "templates"
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Filtres exposes aux gabarits : la mise en forme reste dans la couche web,
# jamais dans les modeles.
templates.env.filters["human_bytes"] = human_bytes
templates.env.filters["human_duration"] = human_duration
templates.env.filters["scope"] = describe_scope

router = APIRouter()


def base_context(request: Request) -> dict:
    """Contexte commun a toutes les pages."""
    settings = request.app.state.settings
    theme = request.cookies.get("pka_theme", "dark")
    return {
        "request": request,
        "csrf_token": getattr(request.state, "csrf", ""),
        "app_mode": settings.mode,
        "is_local_mode": settings.is_local,
        "theme": theme if theme in ("dark", "light") else "dark",
        "config_problems": request.app.state.config_problems,
        "now": time.time(),
    }


def render_error(request: Request, code: int, title: str, message: str,
                 detail: str | None = None) -> HTMLResponse:
    context = base_context(request)
    context.update({"code": code, "title": title, "message": message, "detail": detail})
    return HTMLResponse(
        templates.get_template("error.html").render(**context),
        status_code=code,
    )


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    context = base_context(request)
    context["active"] = "dashboard"
    return templates.TemplateResponse(request, "dashboard.html", context)


@router.get("/packets", response_class=HTMLResponse)
async def packets(request: Request):
    context = base_context(request)
    context["active"] = "packets"
    return templates.TemplateResponse(request, "packets.html", context)


@router.get("/flows", response_class=HTMLResponse)
async def flows(request: Request):
    context = base_context(request)
    context["active"] = "flows"
    return templates.TemplateResponse(request, "flows.html", context)


@router.get("/flow", response_class=HTMLResponse)
async def flow_detail(request: Request, key: str = ""):
    context = base_context(request)
    context["active"] = "flows"
    context["flow_key"] = key
    return templates.TemplateResponse(request, "flow_detail.html", context)


@router.get("/events", response_class=HTMLResponse)
async def events(request: Request):
    context = base_context(request)
    context["active"] = "events"
    context["kinds"] = {
        "observation": KIND_OBSERVATION,
        "hypothese": KIND_HYPOTHESE,
        "alerte": KIND_ALERTE,
    }
    return templates.TemplateResponse(request, "events.html", context)


@router.get("/history", response_class=HTMLResponse)
async def history(request: Request):
    context = base_context(request)
    context["active"] = "history"
    return templates.TemplateResponse(request, "history.html", context)


@router.get("/about", response_class=HTMLResponse)
async def about(request: Request):
    """Page de comprehension : elle explique le fonctionnement du systeme.

    Elle sert aussi de support direct a la defense technique du projet.
    """
    context = base_context(request)
    context["active"] = "about"
    context["interfaces"] = [i.to_dict() for i in list_interfaces()]
    context["primary_address"] = primary_address()
    return templates.TemplateResponse(request, "about.html", context)
