"""Points d'entree JSON et flux temps reel.

L'interface web ne recalcule rien : elle affiche ce que le moteur lui donne.
Ces points d'entree sont aussi la surface d'API documentee du projet
(/api/docs), ce qui permet de verifier le systeme sans passer par l'ecran.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json

from fastapi import APIRouter, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, Response

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


@router.get("/packet", summary="Detail d'un paquet : couches et contenu brut")
async def packet_detail(request: Request, number: int = Query(..., ge=1)):
    """Equivalent des panneaux « arbre des protocoles » et « vidage » de Wireshark."""
    result = engine_of(request).packet_detail(number)
    if result is None:
        return JSONResponse(
            {"ok": False, "error": "Ce paquet n'est plus dans la memoire d'analyse. "
                                   "Seuls les paquets recents conservent leur contenu."},
            status_code=404,
        )
    return {"ok": True, "packet": result}


@router.get("/devices", summary="Appareils du reseau local et services diffuses")
async def devices(request: Request):
    """Ce que les appareils du reseau diffusent a tout le monde.

    Alimente par ARP et mDNS uniquement : des informations que chaque appareil
    envoie volontairement a l'ensemble du reseau. Aucune lecture de trafic
    prive, aucun dechiffrement.
    """
    return {"ok": True, **engine_of(request).devices_snapshot()}


def _csv_safe(value) -> str:
    """Neutralise les valeurs qu'un tableur interpreterait comme une formule.

    Un nom de domaine peut commencer par « = » ou « + » : ouvert dans Excel, il
    serait execute comme une formule. On prefixe par une apostrophe pour forcer
    le texte brut. C'est la recommandation OWASP et cela protege l'utilisateur
    qui ouvre l'export.
    """
    texte = "" if value is None else str(value)
    if texte[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + texte
    return texte


@router.get("/export/packets.csv", summary="Export CSV des paquets")
async def export_packets(request: Request, limit: int = Query(5000, ge=1, le=50000)):
    return _csv_response(
        "paquets.csv",
        ["numero", "horodatage", "protocole", "source", "port_source",
         "destination", "port_destination", "taille_octets", "drapeaux_tcp",
         "ttl", "domaine", "pays", "organisation", "resume"],
        _packet_rows(engine_of(request).packet_snapshot(limit=limit)),
    )


@router.get("/export/flows.csv", summary="Export CSV des communications")
async def export_flows(request: Request, limit: int = Query(5000, ge=1, le=50000)):
    return _csv_response(
        "communications.csv",
        ["debut", "fin", "source", "port_source", "destination", "port_destination",
         "transport", "protocole", "service", "etat", "sens", "paquets", "octets"],
        _flow_rows(engine_of(request).flow_snapshot(limit=limit)),
    )


def _packet_rows(paquets: list[dict]):
    for paquet in paquets:
        geo = paquet.get("geo") or {}
        yield [
            paquet.get("number"),
            paquet.get("ts"),
            paquet.get("protocol"),
            paquet.get("src"),
            paquet.get("src_port"),
            paquet.get("dst"),
            paquet.get("dst_port"),
            paquet.get("size"),
            paquet.get("tcp_flags"),
            paquet.get("ttl"),
            paquet.get("domain"),
            geo.get("country"),
            geo.get("org"),
            paquet.get("info"),
        ]


def _flow_rows(communications: list[dict]):
    for flux in communications:
        yield [
            flux.get("first_seen"),
            flux.get("last_seen"),
            flux.get("src"),
            flux.get("src_port"),
            flux.get("dst"),
            flux.get("dst_port"),
            flux.get("transport"),
            flux.get("protocol"),
            flux.get("service"),
            flux.get("state_label") or flux.get("state"),
            flux.get("direction"),
            flux.get("packets"),
            flux.get("bytes"),
        ]


def _csv_response(nom: str, entetes: list[str], lignes) -> Response:
    """Fabrique une reponse CSV telechargeable.

    Le point-virgule est le separateur attendu par Excel en configuration
    francaise ; l'encodage UTF-8 avec BOM garantit l'affichage correct des
    accents.
    """
    tampon = io.StringIO()
    ecrivain = csv.writer(tampon, delimiter=";", lineterminator="\r\n")
    ecrivain.writerow(entetes)
    for ligne in lignes:
        ecrivain.writerow([_csv_safe(valeur) for valeur in ligne])

    contenu = "\ufeff" + tampon.getvalue()
    return Response(
        content=contenu,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{nom}"'},
    )


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
    # Une adresse invalide doit etre refusee clairement. La traiter comme une
    # adresse sans information produirait une reponse « valide mais vide », dont
    # l'appelant ne pourrait pas deduire que sa demande etait erronee.
    if not _is_valid_ip(ip):
        return JSONResponse(
            {"ok": False, "error": f"« {ip} » n'est pas une adresse IP valide."},
            status_code=400,
        )

    enricher = request.app.state.enricher
    if enricher is None or not request.app.state.settings.enrich_enabled:
        return JSONResponse(
            {"ok": False, "error": "L'enrichissement externe est desactive "
                                   "(ENRICH_ENABLED=false)."},
            status_code=409,
        )
    intel = enricher.lookup(ip)
    return {"ok": True, "intel": intel.to_dict()}


def _is_valid_ip(adresse: str) -> bool:
    """Verifie qu'une chaine est bien une adresse IP.

    La partie apres « % » est retiree : sur Windows, une adresse de lien local
    s'ecrit « fe80::1%12 », ou 12 designe l'interface.
    """
    import ipaddress

    texte = str(adresse or "").split("%")[0].strip()
    if not texte:
        return False
    try:
        ipaddress.ip_address(texte)
    except ValueError:
        return False
    return True


@router.get("/history", summary="Historique des sessions enregistrees")
async def history(request: Request, session_id: int | None = None):
    resultat = engine_of(request).history(session_id)
    # Demander une session precise qui n'existe pas doit etre signale comme tel.
    # Renvoyer une session vide ferait afficher « aucune session enregistree »
    # alors que des sessions existent bel et bien : le message serait faux.
    if session_id is not None and resultat.get("session") is None:
        return JSONResponse(
            {"ok": False, "error": f"La session #{session_id} n'existe pas.",
             "sessions": resultat.get("sessions") or []},
            status_code=404,
        )
    return {"ok": True, **resultat}


@router.get("/protocols", summary="Base de connaissance reseau")
async def protocols():
    """Expose la table des ports et des protocoles utilisee par l'explication.

    Permet de verifier, sans lire le code, sur quelles conventions s'appuie
    l'application et a quel niveau de confiance.
    """
    from app.analysis.protocols import knowledge_base_export
    return {"ok": True, **knowledge_base_export()}


@router.get("/dependencies", summary="Etat des services dont depend l'application")
async def dependencies(request: Request):
    """Indique ce qui fonctionne et ce qui ne repond pas.

    Repond directement a l'exigence de gestion des erreurs : l'utilisateur doit
    voir qu'une dependance est tombee, et savoir que l'analyse continue malgre
    tout, plutot que de decouvrir une panne silencieuse.
    """
    from app.capture.interfaces import capture_available, list_interfaces
    from app.storage.composite_repo import CompositeRepository

    settings = request.app.state.settings
    repository = request.app.state.repository
    enricher = request.app.state.enricher

    # --- base locale ---
    try:
        local_ok = repository.ping()
    except Exception:
        local_ok = False

    # --- base distante ---
    if isinstance(repository, CompositeRepository):
        remote = repository.remote
        remote_ok = bool(repository.remote_available)
        remote_error = repository.last_error or getattr(remote, "last_error", None)
    elif settings.supabase_enabled:
        remote_ok = False
        remote_error = (
            "Supabase est active mais l'application n'a pas pu s'y connecter au "
            "demarrage : les donnees sont conservees en local."
        )
    else:
        remote_ok = None
        remote_error = None

    # --- pilote de capture ---
    if settings.is_local:
        capture_ok, capture_message = capture_available()
        interface_count = len(list_interfaces())
    else:
        capture_ok, capture_message = False, "mode consultation"
        interface_count = 0

    return {
        "ok": True,
        "base_locale": {
            "disponible": local_ok,
            "chemin": str(settings.sqlite_path),
            "role": "historique local, toujours actif",
        },
        "supabase": {
            "active": settings.supabase_enabled,
            "disponible": remote_ok,
            "erreur": remote_error,
            "role": "historique consultable en ligne",
        },
        "capture": {
            "mode": settings.mode,
            "disponible": capture_ok,
            "message": capture_message,
            "interfaces": interface_count,
        },
        "enrichissement": {
            "active": settings.enrich_enabled,
            "appels_externes": getattr(enricher, "calls_made", 0) if enricher else 0,
            "reponses_en_cache": getattr(enricher, "cache_hits", 0) if enricher else 0,
            "source": "ipwho.is (secours : ip-api.com)",
        },
        "reformulation": {
            "modele_actif": bool(settings.ai_enabled and settings.ai_api_key),
            "fournisseur": settings.ai_model if settings.ai_enabled else "regles (local)",
        },
        "traduction": {
            "prefixes_nat64": list(engine_of(request).nat64_prefixes),
            "methode": ("decouverts par la methode RFC 7050 (interrogation de "
                        "ipv4only.arpa), car chaque reseau choisit ses propres "
                        "prefixes de traduction"),
            "effet": ("les adresses de ces prefixes ne sont pas presentees comme un "
                      "hote unique : elles representent plusieurs destinations"),
        },
    }


@router.get("/summary", summary="Resume de la session en langage humain")
async def summary(request: Request):
    """Resume ce qui a ete observe, en insistant sur ce qui n'est pas conclu.

    Le resume par regles fonctionne sans aucune configuration. Si une couche IA
    est activee, elle reformule ce resume, et sa reponse est verifiee : toute
    adresse ou domaine cite qui n'existe pas dans les observations fait rejeter
    la generation au profit du resume deterministe.
    """
    from app.intelligence import Summarizer, build_session_context

    engine = engine_of(request)
    context = build_session_context(engine)
    summarizer = Summarizer(request.app.state.settings)
    try:
        result = summarizer.summarize(context)
    finally:
        summarizer.close()
    return {"ok": True, "summary": result.to_dict()}


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
