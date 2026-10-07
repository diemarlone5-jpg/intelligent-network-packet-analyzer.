"""Points d'entree JSON et flux temps reel.

L'interface web ne recalcule rien : elle affiche ce que le moteur lui donne.
Ces points d'entree sont aussi la surface d'API documentee du projet
(/api/docs), ce qui permet de verifier le systeme sans passer par l'ecran.
"""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from app.capture.interfaces import capture_available, list_interfaces, pick_default_interface

router = APIRouter(prefix="/api", tags=["analyse"])


def engine_of(request: Request):
    return request.app.state.engine


def _guard_local(request: Request) -> JSONResponse | None:
    """En mode consultation, la capture est refusee avec un message clair."""
    if not request.app.state.settings.is_local:
        return JSONResponse(
            {"ok": False, "error": "Instance en mode consultation : la capture "
                                   "reseau n'est disponible que sur la machine locale."},
            status_code=409,
        )
    return None


# --------------------------------------------------------------------------
# Etat et pilotage
# --------------------------------------------------------------------------


@router.get("/status", summary="Etat general de l'application")
async def status(request: Request):
    settings = request.app.state.settings
    available, message = capture_available() if settings.is_local else (False, "mode consultation")
    default = pick_default_interface()
    return {
        "ok": True,
        "mode": settings.mode,
        "capture_available": available,
        "capture_message": message,
        "default_interface": default.to_dict() if default else None,
        "config_problems": request.app.state.config_problems,
        "enrichment_enabled": settings.enrich_enabled,
    }


@router.get("/interfaces", summary="Interfaces reseau capturables")
async def interfaces():
    default = pick_default_interface()
    return {
        "ok": True,
        "interfaces": [i.to_dict() for i in list_interfaces()],
        "default": default.id if default else None,
    }


@router.post("/capture/start", summary="Demarrer une capture")
async def capture_start(request: Request):
    guard = _guard_local(request)
    if guard:
        return guard
    body = await _json_body(request)
    ok, message = engine_of(request).start_capture(
        iface_id=body.get("interface") or None,
        bpf_filter=(body.get("filter") or "").strip(),
    )
    return JSONResponse({"ok": ok, "message": message}, status_code=200 if ok else 400)


@router.post("/capture/stop", summary="Arreter la capture")
async def capture_stop(request: Request):
    ok, message = engine_of(request).stop_capture()
    return JSONResponse({"ok": ok, "message": message}, status_code=200 if ok else 400)


@router.post("/reset", summary="Vider les tampons d'analyse")
async def reset(request: Request):
    engine_of(request).reset()
    return {"ok": True, "message": "Tampons d'analyse vides."}


async def _json_body(request: Request) -> dict:
    """Lit un corps JSON en tolerant un corps vide ou invalide."""
    try:
        raw = await request.body()
        if not raw:
            return {}
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}


# --------------------------------------------------------------------------
# Donnees
# --------------------------------------------------------------------------


@router.get("/stats", summary="Statistiques du tableau de bord")
async def stats(request: Request):
    return engine_of(request).stats()


@router.get("/packets", summary="Paquets captures")
async def packets(request: Request, limit: int = Query(200, ge=1, le=2000),
                  protocol: str = "", search: str = ""):
    return {
        "ok": True,
        "packets": engine_of(request).packet_snapshot(
            limit=limit, protocol=protocol or None, search=search or None
        ),
    }


@router.get("/flows", summary="Communications observees")
async def flows(request: Request, limit: int = Query(200, ge=1, le=2000),
                active_only: bool = False):
    return {
        "ok": True,
        "flows": engine_of(request).flow_snapshot(limit=limit, only_active=active_only),
    }


@router.get("/flow", summary="Explication detaillee d'une communication")
async def flow_detail(request: Request, key: str = Query(..., min_length=3)):
    result = engine_of(request).explain_flow(key)
    if result is None:
        return JSONResponse(
            {"ok": False, "error": "Cette communication n'est plus dans la memoire "
                                   "d'analyse. Elle peut avoir ete evincee par un "
                                   "trafic plus recent."},
            status_code=404,
        )
    return {"ok": True, **result}


@router.get("/events", summary="Evenements detectes")
async def events(request: Request, limit: int = Query(100, ge=1, le=1000)):
    return {"ok": True, "events": engine_of(request).event_snapshot(limit=limit)}


@router.get("/enrich", summary="Enrichir une adresse IP")
async def enrich(request: Request, ip: str = Query(..., min_length=3)):
    """Interroge la source externe pour une adresse, avec cache."""
    enricher = request.app.state.enricher
    if enricher is None or not request.app.state.settings.enrich_enabled:
        return JSONResponse(
            {"ok": False, "error": "L'enrichissement externe est desactive "
                                   "(ENRICH_ENABLED=false)."},
            status_code=409,
        )
    intel = enricher.lookup(ip)
    return {"ok": True, "intel": intel.to_dict()}


@router.get("/history", summary="Historique des sessions enregistrees")
async def history(request: Request, session_id: int | None = None):
    return {"ok": True, **engine_of(request).history(session_id)}


# --------------------------------------------------------------------------
# Flux temps reel
# --------------------------------------------------------------------------


@router.websocket("/ws/live")
async def live(websocket: WebSocket):
    """Pousse l'etat courant vers le navigateur, deux fois par seconde.

    Le navigateur ne fait aucune boucle de requetes : c'est le serveur qui
    cadence, ce qui evite de solliciter l'analyse pour rien.
    """
    await websocket.accept()
    engine = websocket.app.state.engine
    try:
        while True:
            stats = engine.stats()
            payload = {
                "type": "stats",
                "stats": stats,
                "recent_packets": engine.packet_snapshot(limit=40),
                "recent_events": engine.event_snapshot(limit=8),
            }
            await websocket.send_text(json.dumps(payload, default=str))
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        return
    except Exception:
        # Une connexion interrompue est un evenement normal : on ferme proprement
        # sans polluer les journaux.
        try:
            await websocket.close()
        except Exception:
            pass
