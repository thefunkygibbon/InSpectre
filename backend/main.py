from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import CORS_ORIGINS
from auth_utils import _decode_token, _seed_default_user
from database import SessionLocal, _migrate, _seed_settings
from database import _migrate_legacy_docker_host, _migrate_legacy_notifications, _migrate_legacy_ha_mqtt
from ha_mqtt import _ha_startup_connect
from sse import _sse_publish, _sse_event_watcher
from vuln_utils import _scheduled_vuln_scan_loop
from notifications_core import _notification_loop
from fingerprint_utils import _fingerbank_loop
from background_loops import (
    _trivy_db_update_loop, _docker_event_loop,
    _traffic_flush_loop, _speedtest_schedule_loop, _auto_update_schedule_loop,
    _block_schedule_loop, _device_lifecycle_loop,
)
import state
import container_updates as _cu
import asyncio

from routes.auth import router as auth_router
from routes.setup import router as setup_router
from routes.system import router as system_router
from routes.devices import router as devices_router
from routes.vuln import router as vuln_router
from routes.services import router as services_router
from routes.zones import router as zones_router
from routes.saved_views import router as saved_views_router
from routes.suppressions import router as suppressions_router
from routes.events import router as events_router
from routes.settings import router as settings_router
from routes.notifications import router as notifications_router
from routes.plugins import router as plugins_router
from routes.fingerprints import router as fingerprints_router
from routes.export import router as export_router
from routes.tools import router as tools_router
from routes.schedules import router as schedules_router
from routes.persons import router as persons_router
from routes.network import router as network_router
from routes.timeline import router as timeline_router
from routes.traffic import router as traffic_router
from routes.docker import router as docker_router

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = FastAPI(title="InSpectre API", version="1.0.0")
app.include_router(_cu.router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
)

# ---------------------------------------------------------------------------
# Auth middleware
# ---------------------------------------------------------------------------
_PUBLIC_PATHS = frozenset([
    "/",
    "/health",
    "/auth/login",
    "/setup/status",
    "/setup/create-user",
    "/setup/network-info",
    "/setup/apply-network",
    "/setup/complete",
    "/setup/restore-from-backup",
    "/docs",
    "/redoc",
    "/openapi.json",
])


@app.middleware("http")
async def _auth_middleware(request: Request, call_next):
    if request.method == "OPTIONS" or request.url.path in _PUBLIC_PATHS:
        return await call_next(request)

    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:] if auth_header.startswith("Bearer ") else ""
    if not token:
        token = request.query_params.get("token", "")
    if not token:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)

    username = _decode_token(token)
    if not username:
        return JSONResponse({"detail": "Invalid or expired token"}, status_code=401)

    return await call_next(request)


@app.middleware("http")
async def _sse_mutation_notifier(request: Request, call_next):
    response = await call_next(request)
    try:
        if (request.method in ("POST", "PUT", "PATCH", "DELETE")
                and 200 <= response.status_code < 300):
            path = request.url.path
            if "/block-schedules" in path:
                _sse_publish("schedules", {})
                _sse_publish("devices", {})
            elif "/persons" in path:
                _sse_publish("persons", {})
                _sse_publish("devices", {})
            elif "/group" in path:
                _sse_publish("devices", {})
            elif "/metadata" in path or path.startswith("/devices/"):
                _sse_publish("devices", {})
    except Exception:
        pass
    return response


# ---------------------------------------------------------------------------
# Include all routers
# ---------------------------------------------------------------------------
for router in [
    auth_router, setup_router, system_router, devices_router,
    vuln_router, services_router, zones_router, saved_views_router,
    suppressions_router, events_router, settings_router, notifications_router,
    plugins_router, fingerprints_router, export_router, tools_router,
    schedules_router, persons_router, network_router, timeline_router,
    traffic_router, docker_router,
]:
    app.include_router(router)


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def on_startup():
    state._main_loop = asyncio.get_event_loop()
    db = SessionLocal()
    try:
        _migrate(db)
        _seed_settings(db)
        _seed_default_user(db)
        _migrate_legacy_docker_host(db)
        try:
            _migrate_legacy_notifications(db)
        except Exception as exc:
            print(f"[startup] notifications migration failed (non-fatal): {exc}", flush=True)
            db.rollback()
        _migrate_legacy_ha_mqtt(db)
        state._plugin_registry.load_all(db)
        _ha_startup_connect(db)
    except Exception as exc:
        print(f"[startup] CRITICAL startup error: {exc}", flush=True)
    finally:
        db.close()

    asyncio.ensure_future(_scheduled_vuln_scan_loop())
    asyncio.ensure_future(_notification_loop())
    asyncio.ensure_future(_sse_event_watcher())
    asyncio.ensure_future(_block_schedule_loop())
    asyncio.ensure_future(_traffic_flush_loop())
    asyncio.ensure_future(_speedtest_schedule_loop())
    asyncio.ensure_future(_trivy_db_update_loop())
    asyncio.ensure_future(_docker_event_loop())
    asyncio.ensure_future(_fingerbank_loop())
    asyncio.ensure_future(state._plugin_scheduler.run())
    asyncio.ensure_future(_auto_update_schedule_loop())
    asyncio.ensure_future(_device_lifecycle_loop())

    from routes.docker import (
        _get_enabled_hosts, _make_docker_client, _fmt_container,
        _add_docker_host_meta, _generate_compose_yaml, _parse_proxmox_id,
    )
    _cu.init(
        session_local         = SessionLocal,
        get_enabled_hosts     = _get_enabled_hosts,
        make_docker_client    = _make_docker_client,
        fmt_container         = _fmt_container,
        add_host_meta         = _add_docker_host_meta,
        gen_compose_yaml      = _generate_compose_yaml,
        parse_proxmox_id      = _parse_proxmox_id,
        notification_dispatch = _notification_dispatch_ref,
        main_loop_getter      = lambda: state._main_loop,
    )
    asyncio.ensure_future(_cu.container_update_check_loop())


def _notification_dispatch_ref(event_type, title, body, device_mac=None):
    from notifications_core import _notification_dispatch
    return _notification_dispatch(event_type, title, body, device_mac)
