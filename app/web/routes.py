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


def _asset_fingerprint() -> str:
    """Empreinte des fichiers statiques, pour forcer leur rechargement.

    Sans cela, le navigateur continue de servir l'ancienne feuille de style ou
    l'ancien script apres une modification : on croit avoir corrige un bug qui
    est toujours actif a l'ecran. L'empreinte change des qu'un fichier change.
    """
    newest = 0.0
    for relative in ("static/css/style.css", "static/js/app.js"):
        try:
            newest = max(newest, (BASE_DIR / "app" / "web" / relative).stat().st_mtime)
        except OSError:
            continue
    return str(int(newest)) or "1"


ASSET_VERSION = _asset_fingerprint()


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
        "asset_version": ASSET_VERSION,
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


@router.get("/packet", response_class=HTMLResponse)
async def packet_detail(request: Request, number: int = 0):
    """Vue detaillee d'un paquet : arbre des couches et contenu brut.

    Reproduction des deux panneaux du bas de Wireshark. Le contenu est charge
    par le navigateur depuis /api/packet, la page ne fait que le presenter.
    """
    context = base_context(request)
    context["active"] = "packets"
    context["packet_number"] = number
    return templates.TemplateResponse(request, "packet.html", context)


@router.get("/network", response_class=HTMLResponse)
async def network(request: Request):
    """Qui d'autre est sur le reseau, et qu'est-ce que chacun annonce ?

    Page construite uniquement sur des diffusions publiques (ARP, mDNS). Elle
    repond a une question que la liste des paquets ne permet pas de se poser, et
    elle explique aussi pourquoi le contenu prive des autres appareils reste
    hors de portee : c'est une limite du reseau, pas de l'outil.
    """
    context = base_context(request)
    context["active"] = "network"
    context["local_addresses"] = _useful_local_addresses(
        request.app.state.engine.parser.local_ips
    )
    return templates.TemplateResponse(request, "network.html", context)


def _useful_local_addresses(adresses) -> list[str]:
    """Adresses de cette machine qui meritent d'etre affichees.

    La liste brute contient des adresses techniques (boucle locale, adresses de
    lien local, adaptateurs virtuels) qui noient l'information utile. On ne
    garde que ce qui identifie la machine sur le reseau.
    """
    utiles = [
        adresse for adresse in adresses
        if not adresse.startswith(("127.", "169.254.", "0.0.0.0", "::1"))
        and not adresse.startswith("fe80:")
        and not adresse.startswith("172.26.")   # adaptateur virtuel Windows
    ]
    return sorted(utiles)


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


@router.get("/protocols", response_class=HTMLResponse)
async def protocols(request: Request):
    """Referentiel consultable : ce que l'application sait interpreter.

    Cette page rend le raisonnement verifiable : l'utilisateur peut comparer ce
    qui est documente avec ce que l'application affirme.
    """
    context = base_context(request)
    context["active"] = "protocols"
    return templates.TemplateResponse(request, "protocols.html", context)


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Configuration en vigueur, etat des services, donnees conservees.

    La page est en lecture seule : les reglages se modifient dans .env. Une
    interface web qui piloterait la configuration du moteur serait une prise
    supplementaire pour un attaquant, et le reglage disparaitrait du projet.
    """
    context = base_context(request)
    context["active"] = "settings"
    return templates.TemplateResponse(request, "settings.html", context)


@router.get("/api/docs", response_class=HTMLResponse)
async def api_docs(request: Request):
    """Documentation de l'API, generee a partir du schema de l'application.

    Elle remplace la documentation integree de FastAPI, dont les ressources
    viennent d'un CDN : la politique de securite de l'application les bloque, et
    la page s'affichait entierement blanche. On la reproduit ici plutot que
    d'assouplir la securite pour afficher une page.
    """
    schema = request.app.openapi()
    groupes: dict[str, list[dict]] = {}

    for chemin, operations in sorted(schema.get("paths", {}).items()):
        if not chemin.startswith("/api/"):
            continue
        for methode, operation in operations.items():
            if methode.upper() not in ("GET", "POST"):
                continue

            parametres = []
            for parametre in operation.get("parameters", []) or []:
                parametres.append({
                    "nom": parametre.get("name", ""),
                    "obligatoire": bool(parametre.get("required")),
                    "description": parametre.get("description")
                                   or parametre.get("schema", {}).get("title", ""),
                })

            # Un exemple cliquable seulement s'il n'y a rien a renseigner : un
            # lien qui repond une erreur ferait paraitre la route cassee.
            exemple = None
            if methode.upper() == "GET" and not any(p["obligatoire"] for p in parametres):
                exemple = chemin

            route = {
                "methode": methode.upper(),
                "chemin": chemin,
                "resume": operation.get("summary") or operation.get("description", ""),
                "parametres": parametres,
                "exemple": exemple,
            }
            groupes.setdefault(_groupe_api(chemin, methode.upper()), []).append(route)

    ordre = ("État et statistiques", "Données capturées", "Export de la capture",
             "Référentiels et configuration", "Actions (modification)")
    liste = [{"titre": titre, "routes": groupes[titre]}
             for titre in ordre if titre in groupes]

    context = base_context(request)
    context["active"] = "api"
    context["groupes"] = liste
    context["total"] = sum(len(g["routes"]) for g in liste)
    return templates.TemplateResponse(request, "api_docs.html", context)


def _groupe_api(chemin: str, methode: str) -> str:
    """Range une route dans le groupe qui correspond a ce qu'elle sert."""
    if methode != "GET":
        return "Actions (modification)"
    if chemin.startswith("/api/export/"):
        return "Export de la capture"
    if chemin in ("/api/stats", "/api/status", "/api/dependencies", "/api/summary"):
        return "État et statistiques"
    if chemin in ("/api/protocols", "/api/filter/syntax", "/api/interfaces",
                  "/api/settings"):
        return "Référentiels et configuration"
    return "Données capturées"


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
