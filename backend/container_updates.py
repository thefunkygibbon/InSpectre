"""
container_updates.py — Container image update management for InSpectre.

Self-contained FastAPI router module providing:
  - Registry digest comparison (lightweight — no unnecessary pulls)
  - Pre-update config backup to DB and filesystem
  - Optional Trivy pre-scan gate (blocks updates with critical CVEs)
  - Blue/green update flow with automatic rollback on failure
  - Scheduled background update checks and optional auto-update
  - Notification dispatch for all update lifecycle events

Wired into main.py via:
    from container_updates import (
        router as _update_router,
        init   as _init_container_updates,
        migrate as _update_migrate,
        container_update_check_loop as _container_update_check_loop,
    )
"""

import asyncio
import json
import os
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from typing import Optional

import docker as docker_sdk
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import text

# ── Auth ───────────────────────────────────────────────────────────────────────
# Replicated from main.py to avoid circular imports — only needs env vars.

_SECRET_KEY = os.environ.get("SECRET_KEY", "")
_ALGORITHM  = "HS256"


def _verify_token(request: Request) -> str:
    """Validate Bearer JWT; return username or raise 401."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Not authenticated")
    token = auth[7:]
    try:
        payload = jwt.decode(token, _SECRET_KEY, algorithms=[_ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(401, "Invalid token")
        return username
    except JWTError:
        raise HTTPException(401, "Invalid token")


# ── Dependency injection ───────────────────────────────────────────────────────
# Populated once at startup by init(). Never imported from main.py directly.

_SessionLocal           = None
_get_enabled_hosts      = None
_make_docker_client     = None
_fmt_container          = None
_add_host_meta          = None
_gen_compose_yaml       = None
_parse_proxmox_id       = None
_notification_dispatch  = None
_main_loop_getter       = None   # callable → AbstractEventLoop | None


def init(
    session_local,
    get_enabled_hosts,
    make_docker_client,
    fmt_container,
    add_host_meta,
    gen_compose_yaml,
    parse_proxmox_id,
    notification_dispatch,
    main_loop_getter,
):
    """Called once from main.py on_startup to inject shared dependencies."""
    global _SessionLocal, _get_enabled_hosts, _make_docker_client, _fmt_container
    global _add_host_meta, _gen_compose_yaml, _parse_proxmox_id
    global _notification_dispatch, _main_loop_getter
    _SessionLocal          = session_local
    _get_enabled_hosts     = get_enabled_hosts
    _make_docker_client    = make_docker_client
    _fmt_container         = fmt_container
    _add_host_meta         = add_host_meta
    _gen_compose_yaml      = gen_compose_yaml
    _parse_proxmox_id      = parse_proxmox_id
    _notification_dispatch = notification_dispatch
    _main_loop_getter      = main_loop_getter


# ── Constants ──────────────────────────────────────────────────────────────────

BACKUP_DIR = "/app/backups"

INTERVAL_MAP = {
    "1h":  3600,
    "6h":  21600,
    "12h": 43200,
    "24h": 86400,
}

# JSONB columns in container_update_status that need explicit casting
_JSONB_COLS_STATUS = {"new_image_vulns"}

# Per-container update locks (created lazily on first use)
_update_locks: dict[str, asyncio.Lock] = {}

router = APIRouter()


def _resolve_net_mode_parent(client, container, raw_net_mode: str) -> str:
    """
    Given a raw NetworkMode like 'container:SOME_ID_OR_NAME', return a
    resolved 'container:CURRENT_NAME' string via direct Docker API lookup.

    Returns the original raw_net_mode unchanged if the parent can't be found
    (e.g. stale ID from a compose-managed parent that was recreated).
    """
    if not raw_net_mode or not raw_net_mode.lower().startswith("container:"):
        return raw_net_mode
    parent_ref = raw_net_mode.split(":", 1)[1]
    try:
        parent = client.containers.get(parent_ref)
        return f"container:{parent.name.lstrip('/')}"
    except Exception:
        return raw_net_mode

# ── Self-update helper script ──────────────────────────────────────────────────
# Written to the backups volume and executed by a short-lived sidecar container
# that has Docker socket access.  This lets inspectre-web update itself without
# killing the running SSE coroutine mid-update.

_SELF_UPDATE_HELPER_SCRIPT = r'''#!/usr/bin/env python3
"""
InSpectre self-update helper — runs in a short-lived sidecar container.
Performs stop/rename/recreate/health-check/rollback for the main backend.
"""
import os, sys, time
import docker as docker_sdk

TARGET_ID      = os.environ.get("INSPECTRE_CONTAINER_ID", "")
TARGET_NAME    = os.environ["INSPECTRE_CONTAINER_NAME"]
NEW_IMAGE      = os.environ["NEW_IMAGE"]
BACKUP_SUFFIX  = os.environ.get("BACKUP_SUFFIX", "bak")
HEALTH_TIMEOUT = int(os.environ.get("HEALTH_TIMEOUT", "60"))
DB_URL         = os.environ.get("DATABASE_URL", "")

backup_name   = f"{TARGET_NAME}_inspectre_bak_{BACKUP_SUFFIX}"
new_container = None
client        = docker_sdk.from_env()


def log(msg):
    print(f"[helper] {msg}", flush=True)


def update_db_status(success, error_msg=""):
    if not DB_URL:
        return
    try:
        import psycopg2
        conn = psycopg2.connect(DB_URL)
        cur  = conn.cursor()
        if success:
            cur.execute(
                """UPDATE container_update_status
                   SET update_in_progress=FALSE, last_update_status='success',
                       last_updated_at=NOW(), has_update=FALSE,
                       current_digest=latest_digest, last_update_error=NULL
                   WHERE container_name=%s""",
                (TARGET_NAME,),
            )
        else:
            cur.execute(
                """UPDATE container_update_status
                   SET update_in_progress=FALSE, last_update_status='failed',
                       last_update_error=%s
                   WHERE container_name=%s""",
                (error_msg[:500], TARGET_NAME),
            )
        conn.commit(); cur.close(); conn.close()
        log("DB status updated.")
    except Exception as e:
        log(f"DB update failed (non-fatal): {e}")


log(f"Helper started. Target: {TARGET_NAME} → backup: {backup_name}")
log("Waiting 5 s for SSE stream to drain…")
time.sleep(5)

try:
    # ── Stop + rename ────────────────────────────────────────────────────────
    log(f"Stopping {TARGET_NAME}…")
    try:
        c = client.containers.get(TARGET_ID) if TARGET_ID else client.containers.get(TARGET_NAME)
    except docker_sdk.errors.NotFound:
        c = client.containers.get(TARGET_NAME)

    if c.status not in ("exited", "created"):
        c.stop(timeout=30)
        c.reload()

    c.rename(backup_name)
    c.reload()
    log(f"Renamed to {backup_name}")

    # ── Read config from the renamed container ───────────────────────────────
    attrs   = c.attrs or {}
    config  = attrs.get("Config", {})
    hcfg    = attrs.get("HostConfig", {})
    net_cfg = attrs.get("NetworkSettings", {})
    all_nets = list((net_cfg.get("Networks") or {}).keys())

    # Port bindings
    port_bindings = {}
    for port_proto, bindings in (net_cfg.get("Ports") or {}).items():
        if bindings:
            for b in bindings:
                hp = b.get("HostPort")
                if hp:
                    port_bindings[port_proto] = int(hp)

    # Bind mounts + named volumes
    binds = {}
    for m in (attrs.get("Mounts") or []):
        if m.get("Type") == "bind":
            src, dst, mode = m.get("Source", ""), m.get("Destination", ""), m.get("Mode", "rw")
            if src and dst:
                binds[src] = {"bind": dst, "mode": mode}

    vol_binds = {
        m["Name"]: {"bind": m["Destination"], "mode": m.get("Mode", "rw")}
        for m in (attrs.get("Mounts") or [])
        if m.get("Type") == "volume" and m.get("Name") and m.get("Destination")
    }
    all_binds = {**binds, **vol_binds} or None

    rp_raw = hcfg.get("RestartPolicy") or {"Name": "no"}
    rp = {
        "Name":              rp_raw.get("Name", "no") if isinstance(rp_raw, dict) else "no",
        "MaximumRetryCount": rp_raw.get("MaximumRetryCount", 0) if isinstance(rp_raw, dict) else 0,
    }

    # ── Create new container ─────────────────────────────────────────────────
    log(f"Creating new container from {NEW_IMAGE}…")
    primary_mode = hcfg.get("NetworkMode") or None
    # Resolve container:ID → container:NAME
    if primary_mode and primary_mode.lower().startswith("container:"):
        _parent_ref = primary_mode.split(":", 1)[1]
        try:
            _parent = client.containers.get(_parent_ref)
            primary_mode = f"container:{_parent.name.lstrip('/')}"
        except Exception:
            pass  # stale ID — pre-flight check should have caught this
    _host_mode = (primary_mode or "").lower()
    _custom_hostname = (
        None if _host_mode in ("host", "none") or _host_mode.startswith("container:")
        else (config.get("Hostname") or TARGET_NAME)
    )
    _result = client.api.create_container(
        image          = NEW_IMAGE,
        name           = TARGET_NAME,
        command        = config.get("Cmd"),
        environment    = config.get("Env"),
        labels         = config.get("Labels"),
        hostname       = _custom_hostname,
        working_dir    = config.get("WorkingDir") or None,
        entrypoint     = config.get("Entrypoint"),
        user           = config.get("User") or None,
        tty            = config.get("Tty", False),
        stdin_open     = config.get("OpenStdin", False),
        host_config    = client.api.create_host_config(
            port_bindings = port_bindings or None,
            binds         = all_binds,
            volumes_from  = hcfg.get("VolumesFrom") or None,
            network_mode  = primary_mode,
            privileged    = hcfg.get("Privileged", False),
            cap_add       = hcfg.get("CapAdd") or None,
            cap_drop      = hcfg.get("CapDrop") or None,
            devices       = hcfg.get("Devices") or None,
            dns           = hcfg.get("Dns") or None,
            dns_search    = hcfg.get("DnsSearch") or None,
            extra_hosts   = hcfg.get("ExtraHosts") or None,
            sysctls       = hcfg.get("Sysctls") or None,
            mem_limit     = hcfg.get("Memory") or None,
            nano_cpus     = hcfg.get("NanoCpus") or None,
            log_config    = hcfg.get("LogConfig") or None,
            pid_mode      = hcfg.get("PidMode") or None,
            userns_mode   = hcfg.get("UsernsMode") or None,
            security_opt  = hcfg.get("SecurityOpt") or None,
            tmpfs         = hcfg.get("Tmpfs") or None,
            shm_size      = hcfg.get("ShmSize") or None,
            ipc_mode      = hcfg.get("IpcMode") or None,
            read_only     = hcfg.get("ReadonlyRootfs", False),
            restart_policy = rp,
        ),
    )
    new_container = client.containers.get(_result["Id"])

    # Connect to extra networks (docker-compose projects often use multiple)
    primary_net_key = (primary_mode or "").split(":")[0]
    for net_name in all_nets:
        if net_name in ("host", "none", primary_net_key, ""):
            continue
        try:
            client.networks.get(net_name).connect(new_container)
            log(f"Connected to network: {net_name}")
        except Exception as ne:
            log(f"Could not connect to network {net_name}: {ne}")

    new_container.start()
    new_container.reload()
    log(f"New container started ({new_container.id[:12]}). Health checking for {HEALTH_TIMEOUT}s…")

    # ── Health check ─────────────────────────────────────────────────────────
    deadline, is_healthy, final_status = time.monotonic() + HEALTH_TIMEOUT, False, "unknown"
    while time.monotonic() < deadline:
        new_container.reload()
        st = new_container.status
        if st in ("exited", "dead"):
            final_status = st; break
        if st == "running":
            health = (new_container.attrs.get("State") or {}).get("Health")
            if health:
                hs = health.get("Status", "")
                if hs == "healthy":
                    is_healthy = True; final_status = "healthy"; break
                if hs == "unhealthy":
                    final_status = "unhealthy"; break
            else:
                is_healthy = True; final_status = "running"; break
        time.sleep(2)

    if not is_healthy:
        new_container.reload()
        if new_container.status == "running":
            is_healthy = True; final_status = new_container.status

    if is_healthy:
        log(f"Health check passed ({final_status}). Removing backup container…")
        try:
            client.containers.get(backup_name).remove(force=True)
        except Exception:
            pass
        update_db_status(True)
        log("Self-update complete!")
    else:
        log(f"Health check FAILED ({final_status}). Rolling back…")
        try:
            new_container.remove(force=True)
        except Exception:
            pass
        bak = client.containers.get(backup_name)
        bak.rename(TARGET_NAME)
        bak.start()
        log("Rolled back to previous version.")
        update_db_status(False, f"Health check failed: {final_status}")

except Exception as exc:
    log(f"FATAL: {exc}")
    update_db_status(False, str(exc))
    try:
        if new_container:
            try:
                new_container.remove(force=True)
            except Exception:
                pass
        bak = client.containers.get(backup_name)
        bak.rename(TARGET_NAME)
        bak.start()
        log("Emergency rollback succeeded.")
    except Exception as rb_err:
        log(f"Emergency rollback FAILED: {rb_err}")
        log(f"Backup container: {backup_name}")
        log(f"Manual recovery: docker rename {backup_name} {TARGET_NAME} && docker start {TARGET_NAME}")
    sys.exit(1)

sys.exit(0)
'''

# ── InSpectre stack self-protection ───────────────────────────────────────────

# Known container names used by the InSpectre Docker Compose stack.
# These are the default names from docker-compose.yml; users who rename them
# won't be protected, but that's an edge case.
_INSPECTRE_STACK: dict[str, str] = {
    "inspectre-web":      "self",   # the backend — updating kills this very process
    "inspectre-db":       "db",     # the database — stopping it severs all DB connections
    "inspectre-frontend": "stack",  # nginx — safe-ish but disrupts the browser session
    "inspectre-probe":    "stack",  # probe — independent, lowest risk
}


def _stack_role(container_name: str, container_id: str) -> str | None:
    """
    Return the role of a container within the InSpectre stack, or None if it
    is not an InSpectre container.

    Detection strategy:
      1. Compare the running process hostname (Docker sets it to the 12-char
         short container ID) with the target container ID — reliable self-detection.
      2. Fall back to name matching for the other known InSpectre containers.

    Roles:
      "self"  — this IS the backend container; stopping it kills this coroutine
      "db"    — the PostgreSQL container; stopping it breaks all DB connections
      "stack" — another InSpectre container (frontend/probe); lower risk
    """
    try:
        if socket.gethostname() == container_id[:12]:
            return "self"
    except Exception:
        pass
    return _INSPECTRE_STACK.get(container_name)


# ── DB helpers ─────────────────────────────────────────────────────────────────

def _setting(db, key: str, default: str = "") -> str:
    row = db.execute(
        text("SELECT value FROM settings WHERE key = :k"), {"k": key}
    ).fetchone()
    return row[0] if row else default


def migrate(db) -> None:
    """
    Create tables required by this module.
    Called from main.py's _migrate() so migrations run at startup alongside
    all other schema changes — no Alembic needed.
    """
    db.execute(text("""
        CREATE TABLE IF NOT EXISTS container_update_status (
            id                   SERIAL PRIMARY KEY,
            container_name       VARCHAR NOT NULL,
            host_id              INTEGER,
            image                VARCHAR,
            current_digest       VARCHAR,
            latest_digest        VARCHAR,
            has_update           BOOLEAN  DEFAULT FALSE,
            checked_at           TIMESTAMPTZ,
            last_updated_at      TIMESTAMPTZ,
            update_blocked       BOOLEAN  DEFAULT FALSE,
            blocked_reason       TEXT,
            new_image_vulns      JSONB,
            new_image_scanned_at TIMESTAMPTZ,
            update_in_progress   BOOLEAN  DEFAULT FALSE,
            last_update_status   VARCHAR,
            last_update_error    TEXT,
            pinned               BOOLEAN  DEFAULT FALSE
        )
    """))
    # Expression-based unique constraint requires a separate index in PostgreSQL
    # (inline UNIQUE in CREATE TABLE only accepts column references, not expressions)
    db.execute(text("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_container_update_status_name_host
        ON container_update_status (container_name, COALESCE(host_id, -1))
    """))
    db.execute(text("""
        CREATE TABLE IF NOT EXISTS container_backups (
            id               SERIAL PRIMARY KEY,
            container_name   VARCHAR NOT NULL,
            container_id_str VARCHAR,
            host_id          INTEGER,
            image            VARCHAR,
            image_id         VARCHAR,
            config_json      JSONB,
            compose_yaml     TEXT,
            networks         JSONB,
            mounts           JSONB,
            backed_up_at     TIMESTAMPTZ DEFAULT NOW(),
            reason           VARCHAR     DEFAULT 'pre_update'
        )
    """))
    # Safe no-op column additions for installations upgrading from a pre-update version
    for stmt in [
        "ALTER TABLE container_update_status ADD COLUMN IF NOT EXISTS pinned BOOLEAN DEFAULT FALSE",
        "ALTER TABLE container_update_status ADD COLUMN IF NOT EXISTS update_in_progress BOOLEAN DEFAULT FALSE",
        "ALTER TABLE container_update_status ADD COLUMN IF NOT EXISTS new_image_vulns JSONB",
        "ALTER TABLE container_update_status ADD COLUMN IF NOT EXISTS new_image_scanned_at TIMESTAMPTZ",
        "ALTER TABLE container_update_status ADD COLUMN IF NOT EXISTS last_update_error TEXT",
    ]:
        try:
            db.execute(text(stmt))
        except Exception:
            db.rollback()
    db.commit()


# ── Update status upsert ───────────────────────────────────────────────────────

def _upsert_update_status(db, container_name: str, host_id, **kwargs) -> None:
    """
    Insert or update a row in container_update_status for the given container.
    Only columns present in kwargs are written — others are untouched.
    JSONB columns listed in _JSONB_COLS_STATUS get an explicit ::jsonb cast.
    """
    existing = db.execute(
        text("""SELECT id FROM container_update_status
                WHERE container_name=:n AND COALESCE(host_id,-1)=COALESCE(:h,-1)"""),
        {"n": container_name, "h": host_id},
    ).fetchone()

    def _cast(k: str) -> str:
        # Use CAST() syntax — ":param::type" confuses SQLAlchemy's text() binder
        if k in _JSONB_COLS_STATUS and kwargs[k] is not None:
            return f"CAST(:{k} AS jsonb)"
        return f":{k}"

    if existing:
        set_parts = [f"{k}={_cast(k)}" for k in kwargs]
        db.execute(
            text(f"UPDATE container_update_status SET {', '.join(set_parts)} WHERE id=:_id"),
            {**kwargs, "_id": existing[0]},
        )
    else:
        col_parts = list(kwargs.keys())
        val_parts = [_cast(k) for k in col_parts]
        cols = "container_name, host_id, " + ", ".join(col_parts)
        vals = ":container_name, :host_id, " + ", ".join(val_parts)
        db.execute(
            text(f"INSERT INTO container_update_status ({cols}) VALUES ({vals})"),
            {"container_name": container_name, "host_id": host_id, **kwargs},
        )
    db.commit()


def _get_update_status_row(db, container_name: str, host_id=None) -> dict | None:
    row = db.execute(text("""
        SELECT id, container_name, host_id, image, current_digest, latest_digest,
               has_update, checked_at, last_updated_at, update_blocked, blocked_reason,
               new_image_vulns, new_image_scanned_at, update_in_progress,
               last_update_status, last_update_error, pinned
        FROM container_update_status
        WHERE container_name=:n AND COALESCE(host_id,-1)=COALESCE(:h,-1)
    """), {"n": container_name, "h": host_id}).fetchone()
    if not row:
        return None
    keys = [
        "id", "container_name", "host_id", "image", "current_digest", "latest_digest",
        "has_update", "checked_at", "last_updated_at", "update_blocked", "blocked_reason",
        "new_image_vulns", "new_image_scanned_at", "update_in_progress",
        "last_update_status", "last_update_error", "pinned",
    ]
    d = dict(zip(keys, row))
    for k in ("checked_at", "last_updated_at", "new_image_scanned_at"):
        if d[k]:
            d[k] = d[k].isoformat()
    return d


# ── Host resolution ────────────────────────────────────────────────────────────

def _resolve_host(db, container_id: str) -> tuple[str, dict, int | None]:
    """
    Return (host_url, host_meta_dict, host_id) for the first enabled Docker host.
    Raises 503 if no Docker hosts are configured.
    """
    hosts = _get_enabled_hosts(db)
    docker_hosts = [h for h in hosts if h.get("type") != "proxmox"]
    if not docker_hosts:
        raise HTTPException(503, "No Docker hosts configured.")
    meta     = docker_hosts[0]
    host_url = meta.get("url") or "unix:///var/run/docker.sock"
    return host_url, meta, meta.get("id")


# ── Image update detection ────────────────────────────────────────────────────

def _check_update_sync(image_name: str, host_url: str) -> dict:
    """
    Compare the locally-cached image digest with the remote registry manifest.
    Uses get_registry_data() which fetches only the manifest header — no pull needed.

    Returns: {current_digest, latest_digest, has_update, error?}
    """
    client = _make_docker_client(host_url)
    try:
        # Digest of the locally-cached image for this tag
        try:
            local_img = client.images.get(image_name)
            current_digest = local_img.id
        except docker_sdk.errors.ImageNotFound:
            current_digest = None

        # Digest of the latest manifest in the registry (no download)
        try:
            reg_data = client.images.get_registry_data(image_name)
            latest_digest = reg_data.id
        except Exception as exc:
            return {
                "current_digest": current_digest,
                "latest_digest":  None,
                "has_update":     False,
                "error": f"Registry check failed: {exc}",
            }

        has_update = bool(
            latest_digest and current_digest and latest_digest != current_digest
        )
        return {
            "current_digest": current_digest,
            "latest_digest":  latest_digest,
            "has_update":     has_update,
        }
    finally:
        client.close()


# ── Config backup ──────────────────────────────────────────────────────────────

def _backup_container_sync(
    container_name: str,
    container_id: str,
    host_url: str,
    host_id: Optional[int],
    reason: str = "pre_update",
) -> int:
    """
    Capture full container config (docker inspect JSON + compose YAML) and
    persist it to the database and to the backup filesystem directory.

    The filesystem copy provides a recovery path even if the DB is unavailable.
    Returns the DB backup row id.
    """
    client = _make_docker_client(host_url)
    try:
        c           = client.containers.get(container_id)
        attrs       = c.attrs or {}
        image_name  = (c.image.tags or [str(c.image.id)])[0]
        image_id    = c.image.id
        networks    = list((attrs.get("NetworkSettings") or {}).get("Networks", {}).keys())
        mounts      = attrs.get("Mounts") or []

        # Generate a compose YAML representation via the injected helper
        try:
            compose_yaml, _ = _gen_compose_yaml(c)
        except Exception as e:
            compose_yaml = f"# compose generation failed: {e}"
    finally:
        client.close()

    # Persist to DB
    db = _SessionLocal()
    try:
        row = db.execute(text("""
            INSERT INTO container_backups
                (container_name, container_id_str, host_id, image, image_id,
                 config_json, compose_yaml, networks, mounts, backed_up_at, reason)
            VALUES
                (:name, :cid, :hid, :img, :imgid,
                 CAST(:cfg AS jsonb), :yaml, CAST(:nets AS jsonb), CAST(:mts AS jsonb), NOW(), :reason)
            RETURNING id
        """), {
            "name":   container_name,
            "cid":    container_id,
            "hid":    host_id,
            "img":    image_name,
            "imgid":  image_id,
            "cfg":    json.dumps(attrs, default=str),
            "yaml":   compose_yaml,
            "nets":   json.dumps(networks),
            "mts":    json.dumps(mounts, default=str),
            "reason": reason,
        }).fetchone()
        db.commit()
        backup_id = row[0]
    finally:
        db.close()

    # Filesystem copy — survives DB loss
    try:
        ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        bdir = os.path.join(BACKUP_DIR, container_name, f"{ts}_{reason}")
        os.makedirs(bdir, exist_ok=True)
        with open(os.path.join(bdir, "config.json"), "w") as f:
            json.dump(attrs, f, indent=2, default=str)
        with open(os.path.join(bdir, "compose.yaml"), "w") as f:
            f.write(compose_yaml)
        with open(os.path.join(bdir, "metadata.json"), "w") as f:
            json.dump({
                "backup_id":      backup_id,
                "container_name": container_name,
                "image":          image_name,
                "image_id":       image_id,
                "reason":         reason,
                "backed_up_at":   datetime.now(timezone.utc).isoformat(),
                "networks":       networks,
                "bind_mounts":    [m.get("Source") for m in mounts if m.get("Type") == "bind"],
                "named_volumes":  [m.get("Name") for m in mounts if m.get("Type") == "volume"],
            }, f, indent=2)
    except Exception as fs_err:
        print(f"[backup] filesystem write failed (non-fatal): {fs_err}", flush=True)

    return backup_id


# ── Trivy scan for a specific image ───────────────────────────────────────────

def _trivy_scan_image(image_name: str) -> tuple[list, int, int]:
    """
    Run `trivy image` against image_name.
    Returns (vulns_list, critical_count, high_count).
    vulns_list follows the same shape as VulnTab in the frontend.
    """
    if not shutil.which("trivy"):
        return [], 0, 0
    try:
        result = subprocess.run(
            [
                "trivy", "image",
                "--quiet", "--no-progress",
                "--format", "json",
                image_name,
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            print(f"[trivy-image-scan] exited {result.returncode}: {result.stderr[:200]}", flush=True)
            return [], 0, 0

        data  = json.loads(result.stdout)
        vulns = []
        for res in (data.get("Results") or []):
            for v in (res.get("Vulnerabilities") or []):
                score = None
                cvss  = v.get("CVSS") or {}
                for source in ("nvd", "redhat", "ghsa"):
                    if cvss.get(source, {}).get("V3Score"):
                        score = cvss[source]["V3Score"]
                        break
                vulns.append({
                    "id":          v.get("VulnerabilityID", ""),
                    "severity":    v.get("Severity", "UNKNOWN").lower(),
                    "pkg":         v.get("PkgName", ""),
                    "installed":   v.get("InstalledVersion", ""),
                    "fixed":       v.get("FixedVersion", ""),
                    "title":       v.get("Title", ""),
                    "description": (v.get("Description") or "")[:400],
                    "score":       score,
                    "url": f"https://nvd.nist.gov/vuln/detail/{v.get('VulnerabilityID', '')}",
                })
        critical = sum(1 for v in vulns if v["severity"] == "critical")
        high     = sum(1 for v in vulns if v["severity"] == "high")
        return vulns, critical, high
    except Exception as e:
        print(f"[trivy-image-scan] {e}", flush=True)
        return [], 0, 0


# ── Notification helper ────────────────────────────────────────────────────────

def _fire_notification(event: str, title: str, body: str) -> None:
    """Thread-safe: schedule a notification dispatch on the main event loop."""
    loop = _main_loop_getter() if _main_loop_getter else None
    if loop and not loop.is_closed():
        asyncio.run_coroutine_threadsafe(
            _notification_dispatch(event, title, body), loop
        )


# ── Self-update via helper container ─────────────────────────────────────────

async def _self_update_via_helper_stream(
    container_id: str,
    container_name: str,
    image_name: str,
    host_url: str,
    host_id: Optional[int],
    force: bool = False,
    scan_first: bool = True,
):
    """
    Variant of _safe_update_stream for updating the InSpectre backend container.

    The problem: stopping inspectre-web kills this very coroutine, so the normal
    blue/green flow cannot safely update itself.

    The solution: stages 1-3 (backup, pull, optional Trivy scan) run normally while
    the backend is still up.  Then a short-lived sidecar container is created from
    the same image (Docker SDK already installed) with the Docker socket mounted.
    The sidecar performs the actual stop/rename/recreate/health-check/rollback cycle
    independently.  The SSE stream sends SELF_UPDATE_STARTED and ends — the frontend
    switches to a reconnect UI that polls GET /api/ping until the new backend answers.
    """
    def emit(msg: str) -> str:
        return f"data: {msg}\n\n"

    try:
        # Stage 1: Backup
        yield emit("LOG: [1/3] Backing up current container configuration…")
        backup_id = await asyncio.to_thread(
            _backup_container_sync,
            container_name, container_id, host_url, host_id, "pre_update",
        )
        yield emit(f"LOG: [1/3] ✓ Backup saved (ID {backup_id})")

        db = _SessionLocal()
        try:
            _upsert_update_status(db, container_name, host_id,
                                  update_in_progress=True,
                                  last_update_status=None,
                                  last_update_error=None)
        finally:
            db.close()

        # Stage 2: Pull latest image
        yield emit(f"LOG: [2/3] Pulling latest image: {image_name}…")

        def _pull():
            client = _make_docker_client(host_url)
            try:
                img = client.images.pull(image_name)
                return img.id
            finally:
                client.close()

        try:
            new_image_id = await asyncio.to_thread(_pull)
            yield emit(f"LOG: [2/3] ✓ Pull complete. Digest: {new_image_id[:19]}…")
        except Exception as pull_err:
            yield emit(f"LOG: [ERROR] Image pull failed: {pull_err}")
            yield emit("UPDATE_ERROR:Image pull failed — container unchanged.")
            db = _SessionLocal()
            try:
                _upsert_update_status(db, container_name, host_id,
                                      update_in_progress=False,
                                      last_update_status="failed",
                                      last_update_error=str(pull_err))
            finally:
                db.close()
            return

        # Stage 3: Optional Trivy scan
        if scan_first:
            db = _SessionLocal()
            try:
                block_on_critical = _setting(db, "container_update_block_critical", "true") == "true"
            finally:
                db.close()

            yield emit("LOG: [3/3] Running Trivy security scan on new image…")
            scan_vulns, critical_count, high_count = await asyncio.to_thread(
                _trivy_scan_image, image_name
            )
            yield emit(
                f"LOG: [3/3] ✓ Scan complete — "
                f"{critical_count} critical, {high_count} high, {len(scan_vulns)} total CVEs."
            )

            db = _SessionLocal()
            try:
                _upsert_update_status(db, container_name, host_id,
                                      new_image_vulns=json.dumps(scan_vulns),
                                      new_image_scanned_at=datetime.now(timezone.utc))
            finally:
                db.close()

            if critical_count > 0 and block_on_critical and not force:
                reason_str = f"{critical_count} critical CVE(s) found in new image"
                db = _SessionLocal()
                try:
                    _upsert_update_status(db, container_name, host_id,
                                          update_blocked=True,
                                          blocked_reason=reason_str,
                                          update_in_progress=False,
                                          last_update_status="blocked")
                finally:
                    db.close()
                yield emit(f"LOG: [BLOCKED] {reason_str} — update aborted for safety.")
                yield emit(f"UPDATE_BLOCKED:{critical_count}")
                return

            if critical_count > 0 and force:
                yield emit(
                    f"LOG: [WARNING] {critical_count} critical CVE(s) found "
                    "— proceeding anyway (force override active)."
                )
        else:
            yield emit("LOG: [3/3] Trivy pre-scan skipped.")

        # Stage 4: Launch helper container
        yield emit("LOG: Preparing self-update helper container…")

        ts     = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        db_url = os.environ.get("DATABASE_URL", "")

        db = _SessionLocal()
        try:
            health_timeout = int(_setting(db, "container_update_health_timeout", "60"))
        except (ValueError, Exception):
            health_timeout = 60
        finally:
            db.close()

        def _launch_helper():
            client = _make_docker_client(host_url)
            try:
                # Write the helper script to the backups volume so the sidecar can exec it
                os.makedirs(BACKUP_DIR, exist_ok=True)
                script_name = f"_self_update_helper_{ts}.py"
                script_path = os.path.join(BACKUP_DIR, script_name)
                with open(script_path, "w") as fh:
                    fh.write(_SELF_UPDATE_HELPER_SCRIPT)
                os.chmod(script_path, 0o755)

                target_c = client.containers.get(container_id)

                # Use the current inspectre-web image — it already has docker + psycopg2
                helper_img = (target_c.image.tags or [str(target_c.image.id)])[0]

                # Resolve actual host paths from the running container's mounts
                # (BACKUP_DIR is /app/backups inside the container, not on the host)
                host_backup_dir = BACKUP_DIR
                host_socket     = "/var/run/docker.sock"
                for m in (target_c.attrs.get("Mounts") or []):
                    if m.get("Destination") == "/app/backups":
                        host_backup_dir = m.get("Source", BACKUP_DIR)
                    if m.get("Destination") == "/var/run/docker.sock":
                        host_socket = m.get("Source", "/var/run/docker.sock")

                helper_name = f"inspectre_self_update_{ts}"
                primary_mode = (target_c.attrs.get("HostConfig") or {}).get("NetworkMode") or None

                _hres = client.api.create_container(
                    image       = helper_img,
                    name        = helper_name,
                    command     = ["python3", f"/app/backups/{script_name}"],
                    environment = {
                        "INSPECTRE_CONTAINER_ID":   container_id,
                        "INSPECTRE_CONTAINER_NAME": container_name,
                        "NEW_IMAGE":                image_name,
                        "BACKUP_SUFFIX":            ts,
                        "HEALTH_TIMEOUT":           str(health_timeout),
                        "DATABASE_URL":             db_url,
                    },
                    host_config = client.api.create_host_config(
                        binds        = {
                            host_socket:     {"bind": "/var/run/docker.sock", "mode": "rw"},
                            host_backup_dir: {"bind": "/app/backups",         "mode": "rw"},
                        },
                        network_mode = primary_mode,
                    ),
                )
                helper = client.containers.get(_hres["Id"])

                # Connect to any extra networks so the helper can reach inspectre-db
                all_nets = list(
                    (target_c.attrs.get("NetworkSettings") or {})
                    .get("Networks", {}).keys()
                )
                primary_key = (primary_mode or "").split(":")[0]
                for net_name in all_nets:
                    if net_name in ("host", "none", primary_key, ""):
                        continue
                    try:
                        client.networks.get(net_name).connect(helper)
                    except Exception:
                        pass

                helper.start()
                helper.reload()
                return helper.id[:12], helper_name
            finally:
                client.close()

        helper_short_id, helper_name = await asyncio.to_thread(_launch_helper)
        yield emit(f"LOG: ✓ Helper container '{helper_name}' started ({helper_short_id}).")
        yield emit("LOG: InSpectre is going offline momentarily to apply the update.")
        yield emit("LOG: The interface will reconnect automatically in ~30–60 seconds.")
        yield emit(f"LOG: To follow helper progress: docker logs -f {helper_name}")
        yield emit("SELF_UPDATE_STARTED")
        # Stream ends here — the helper runs independently

    except Exception as exc:
        yield emit(f"LOG: [FATAL] Failed to launch self-update helper: {exc}")
        yield emit(f"UPDATE_ERROR:{exc}")
        db = _SessionLocal()
        try:
            _upsert_update_status(db, container_name, host_id,
                                  update_in_progress=False,
                                  last_update_status="failed",
                                  last_update_error=str(exc))
        except Exception:
            pass
        finally:
            db.close()


# ── Network-dependent container cascade helpers ────────────────────────────────

def _find_network_dependents(client, container_id: str) -> list:
    """Return containers that use container_id as their network parent."""
    dependents = []
    for c in client.containers.list(all=True):
        nm = ((c.attrs.get("HostConfig") or {}).get("NetworkMode") or "").lower()
        if nm.startswith("container:") and container_id in nm:
            dependents.append(c)
    return dependents


def _recreate_container_with_net(client, dep, new_net_mode: str) -> None:
    """
    Recreate a container with a new network_mode, preserving all other config.
    Stop → rename to temp → create new → start → remove temp.
    Restores original on failure.
    """
    dep_name = dep.name.lstrip("/")
    attrs    = dep.attrs or {}
    config   = attrs.get("Config", {})
    hcfg     = attrs.get("HostConfig", {})
    net_sets = attrs.get("NetworkSettings", {})

    # Port bindings
    port_bindings = {}
    for port_proto, bindings in (net_sets.get("Ports") or {}).items():
        if bindings:
            for b in bindings:
                hp = b.get("HostPort")
                if hp:
                    port_bindings[port_proto] = int(hp)

    # Bind mounts + named volumes
    binds = {}
    for m in (attrs.get("Mounts") or []):
        if m.get("Type") == "bind":
            src, dst, mode = m.get("Source",""), m.get("Destination",""), m.get("Mode","rw")
            if src and dst:
                binds[src] = {"bind": dst, "mode": mode}
    vol_binds = {
        m["Name"]: {"bind": m["Destination"], "mode": m.get("Mode","rw")}
        for m in (attrs.get("Mounts") or [])
        if m.get("Type") == "volume" and m.get("Name") and m.get("Destination")
    }
    all_binds = {**binds, **vol_binds} or None

    rp_raw = hcfg.get("RestartPolicy") or {"Name": "no"}
    rp = {
        "Name": rp_raw.get("Name","no") if isinstance(rp_raw, dict) else "no",
        "MaximumRetryCount": rp_raw.get("MaximumRetryCount", 0) if isinstance(rp_raw, dict) else 0,
    }

    ts       = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    bak_name = f"{dep_name}_netupd_{ts}"

    if dep.status not in ("exited", "created"):
        dep.stop(timeout=15)
    dep.rename(bak_name)
    dep.reload()

    _net_lo = (new_net_mode or "").lower()
    _hostname = (
        None if _net_lo in ("host","none") or _net_lo.startswith("container:")
        else (config.get("Hostname") or dep_name)
    )

    try:
        _cres = client.api.create_container(
            image         = config.get("Image"),
            name          = dep_name,
            command       = config.get("Cmd"),
            environment   = config.get("Env"),
            labels        = config.get("Labels"),
            hostname      = _hostname,
            working_dir   = config.get("WorkingDir") or None,
            entrypoint    = config.get("Entrypoint"),
            user          = config.get("User") or None,
            tty           = config.get("Tty", False),
            stdin_open    = config.get("OpenStdin", False),
            host_config   = client.api.create_host_config(
                port_bindings = port_bindings or None,
                binds         = all_binds,
                volumes_from  = hcfg.get("VolumesFrom") or None,
                network_mode  = new_net_mode,
                privileged    = hcfg.get("Privileged", False),
                cap_add       = hcfg.get("CapAdd") or None,
                cap_drop      = hcfg.get("CapDrop") or None,
                devices       = hcfg.get("Devices") or None,
                dns           = hcfg.get("Dns") or None,
                dns_search    = hcfg.get("DnsSearch") or None,
                extra_hosts   = hcfg.get("ExtraHosts") or None,
                sysctls       = hcfg.get("Sysctls") or None,
                mem_limit     = hcfg.get("Memory") or None,
                nano_cpus     = hcfg.get("NanoCpus") or None,
                log_config    = hcfg.get("LogConfig") or None,
                pid_mode      = hcfg.get("PidMode") or None,
                userns_mode   = hcfg.get("UsernsMode") or None,
                security_opt  = hcfg.get("SecurityOpt") or None,
                tmpfs         = hcfg.get("Tmpfs") or None,
                shm_size      = hcfg.get("ShmSize") or None,
                ipc_mode      = hcfg.get("IpcMode") or None,
                read_only     = hcfg.get("ReadonlyRootfs", False),
                restart_policy= rp,
            ),
        )
        new_dep = client.containers.get(_cres["Id"])
        try:
            new_dep.start()
        except Exception:
            try: new_dep.remove(force=True)
            except Exception: pass
            raise
        try:
            client.containers.get(bak_name).remove(force=True)
        except Exception:
            pass
    except Exception:
        # Restore original
        try:
            b = client.containers.get(bak_name)
            b.rename(dep_name)
            b.start()
        except Exception:
            pass
        raise


# ── Safe update flow ───────────────────────────────────────────────────────────

async def _safe_update_stream(
    container_id: str,
    host_url: str,
    host_id: Optional[int],
    force: bool = False,
    scan_first: bool = True,
):
    """
    Async generator: yields SSE-formatted data lines for a waterproof container update.

    Safety guarantees:
      - Config is backed up BEFORE any change is made to the running container.
      - The old container is RENAMED (not deleted) before the new one is created.
      - The backup container is only deleted AFTER the new container passes the
        health check. Until then it can be restored with a single rename + start.
      - If the new container fails to start or passes the health check, the
        backup container is automatically renamed back and started (rollback).
      - Any unexpected exception leaves the backup container in place and reports
        its name so the operator can restore manually if needed.

    Update stages:
      1. Backup current config
      2. Pull latest image
      3. (Optional) Trivy-scan new image — abort if critical CVEs (unless force=True)
      4. Stop old container gracefully
      5. Rename old container to a timestamped backup name
      6. Create new container with identical configuration
      7. Start new container
      8. Health-check gate (waits up to health_timeout seconds)
         8a. Healthy  → remove backup container, record success, notify
         8b. Unhealthy → rollback: start backup, record failure, notify
    """

    def emit(msg: str) -> str:
        return f"data: {msg}\n\n"

    container_name: Optional[str] = None
    backup_cname:   Optional[str] = None
    new_container               = None

    # One lock per container — prevents concurrent updates
    if container_id not in _update_locks:
        _update_locks[container_id] = asyncio.Lock()
    lock = _update_locks[container_id]

    if lock.locked():
        yield emit("UPDATE_ERROR:Update already in progress for this container.")
        return

    async with lock:
        try:
            # ── Resolve container name and image ───────────────────────────
            def _get_info():
                client = _make_docker_client(host_url)
                try:
                    c = client.containers.get(container_id)
                    return (
                        c.name.lstrip("/"),
                        (c.image.tags or [str(c.image.id)])[0],
                    )
                finally:
                    client.close()

            container_name, image_name = await asyncio.to_thread(_get_info)

            # ── Pre-flight: verify container: network parent is resolvable ──
            def _check_network_parent():
                """
                Returns (parent_ref, is_compose) if the parent can't be found,
                or None if everything is fine.
                """
                client = _make_docker_client(host_url)
                try:
                    c = client.containers.get(container_id)
                    net_mode = (c.attrs.get("HostConfig") or {}).get("NetworkMode") or ""
                    if not net_mode.lower().startswith("container:"):
                        return None
                    parent_ref = net_mode.split(":", 1)[1]
                    try:
                        client.containers.get(parent_ref)
                        return None  # parent found, all good
                    except Exception:
                        pass
                    # Parent not found — check if this is a compose-managed container
                    labels = c.labels or {}
                    is_compose = bool(labels.get("com.docker.compose.project"))
                    return (parent_ref, is_compose)
                finally:
                    client.close()

            preflight = await asyncio.to_thread(_check_network_parent)
            if preflight is not None:
                missing_ref, is_compose = preflight
                short_ref = missing_ref[:16] + "…" if len(missing_ref) > 16 else missing_ref
                if is_compose:
                    err_msg = (
                        f"Cannot update '{container_name}' automatically — "
                        f"it shares another container's network namespace (container: mode) "
                        f"and the parent container ({short_ref}) no longer exists. "
                        f"This happens when the parent was recreated by docker compose, "
                        f"giving it a new ID. To fix: re-run 'docker compose up -d' in "
                        f"your original compose project directory to recreate the whole "
                        f"stack with correct references, then update from there."
                    )
                else:
                    err_msg = (
                        f"Cannot update '{container_name}' — it uses "
                        f"'container:' network mode but its parent container "
                        f"({short_ref}) no longer exists. "
                        f"Recreate the parent container first, then retry."
                    )
                db = _SessionLocal()
                try:
                    _upsert_update_status(db, container_name, host_id,
                                          update_in_progress=False,
                                          last_update_status="failed",
                                          last_update_error=err_msg)
                finally:
                    db.close()
                yield emit(f"UPDATE_ERROR:{err_msg}")
                return

            # ── InSpectre stack safety guard ───────────────────────────────
            role = _stack_role(container_name, container_id)
            if role == "self":
                # Route to helper-container self-update — the helper performs the
                # actual stop/rename/recreate after the SSE stream ends.
                async for chunk in _self_update_via_helper_stream(
                    container_id, container_name, image_name,
                    host_url, host_id, force=force, scan_first=scan_first,
                ):
                    yield chunk
                return
            if role == "db":
                yield emit(
                    "UPDATE_ERROR:INSPECTRE_DB — Cannot update the InSpectre database "
                    "container through this mechanism: stopping it severs all active "
                    "database connections and would corrupt the update flow. "
                    "Use Settings → About → Update InSpectre for a coordinated stack update."
                )
                return
            if role == "stack":
                yield emit(
                    f"LOG: [WARNING] {container_name} is part of the InSpectre stack. "
                    "Updating individual stack containers may disrupt the application. "
                    "Consider using Settings → About → Update InSpectre for a full "
                    "coordinated update instead. Proceeding…"
                )

            # ── Stage 1: Backup ────────────────────────────────────────────
            yield emit("LOG: [1/7] Backing up current container configuration…")

            backup_id = await asyncio.to_thread(
                _backup_container_sync,
                container_name, container_id, host_url, host_id, "pre_update",
            )
            yield emit(f"LOG: [1/7] ✓ Backup saved (ID {backup_id}) — config preserved at {BACKUP_DIR}/{container_name}/")

            db = _SessionLocal()
            try:
                _upsert_update_status(db, container_name, host_id,
                                      update_in_progress=True,
                                      last_update_status=None,
                                      last_update_error=None)
            finally:
                db.close()

            # ── Stage 2: Pull latest image ─────────────────────────────────
            yield emit(f"LOG: [2/7] Pulling latest image: {image_name}…")

            def _pull():
                client = _make_docker_client(host_url)
                try:
                    img = client.images.pull(image_name)
                    return img.id
                finally:
                    client.close()

            try:
                new_image_id = await asyncio.to_thread(_pull)
                yield emit(f"LOG: [2/7] ✓ Pull complete. Digest: {new_image_id[:19]}…")
            except Exception as pull_err:
                yield emit(f"LOG: [ERROR] Image pull failed: {pull_err}")
                yield emit("UPDATE_ERROR:Image pull failed — container unchanged.")
                db = _SessionLocal()
                try:
                    _upsert_update_status(db, container_name, host_id,
                                          update_in_progress=False,
                                          last_update_status="failed",
                                          last_update_error=str(pull_err))
                finally:
                    db.close()
                return

            # ── Stage 3: Optional Trivy pre-scan ──────────────────────────
            scan_vulns     = []
            critical_count = 0
            high_count     = 0

            if scan_first:
                db = _SessionLocal()
                try:
                    block_on_critical = _setting(db, "container_update_block_critical", "true") == "true"
                finally:
                    db.close()

                yield emit(f"LOG: [3/7] Running Trivy security scan on new image…")

                scan_vulns, critical_count, high_count = await asyncio.to_thread(
                    _trivy_scan_image, image_name
                )
                yield emit(
                    f"LOG: [3/7] ✓ Scan complete — "
                    f"{critical_count} critical, {high_count} high, {len(scan_vulns)} total CVEs."
                )

                db = _SessionLocal()
                try:
                    _upsert_update_status(db, container_name, host_id,
                                          new_image_vulns=json.dumps(scan_vulns),
                                          new_image_scanned_at=datetime.now(timezone.utc))
                finally:
                    db.close()

                if critical_count > 0 and block_on_critical and not force:
                    reason_str = f"{critical_count} critical CVE(s) found in new image"
                    db = _SessionLocal()
                    try:
                        _upsert_update_status(db, container_name, host_id,
                                              update_blocked=True,
                                              blocked_reason=reason_str,
                                              update_in_progress=False,
                                              last_update_status="blocked")
                    finally:
                        db.close()
                    yield emit(f"LOG: [BLOCKED] {reason_str} — update aborted for safety.")
                    yield emit(f"UPDATE_BLOCKED:{critical_count}")
                    _fire_notification(
                        "container.update_blocked",
                        "Container Update Blocked",
                        f"{container_name}: blocked — {critical_count} critical CVE(s) in new image",
                    )
                    return

                if critical_count > 0 and force:
                    yield emit(
                        f"LOG: [WARNING] {critical_count} critical CVE(s) found "
                        f"— proceeding anyway (force override active)."
                    )
            else:
                yield emit("LOG: [3/7] Trivy pre-scan skipped.")

            # ── Stage 4: Stop container gracefully ─────────────────────────
            yield emit("LOG: [4/7] Stopping current container (30 s grace period)…")

            def _stop_and_rename():
                client = _make_docker_client(host_url)
                try:
                    c         = client.containers.get(container_id)
                    orig_name = c.name.lstrip("/")
                    if c.status not in ("exited", "created"):
                        c.stop(timeout=30)
                        c.reload()
                    ts    = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
                    bname = f"{orig_name}_inspectre_bak_{ts}"
                    c.rename(bname)
                    c.reload()
                    return orig_name, bname, c.id
                finally:
                    client.close()

            orig_name, backup_cname, old_id = await asyncio.to_thread(_stop_and_rename)
            yield emit(f"LOG: [4/7] ✓ Stopped. Old container preserved as '{backup_cname}'.")

            # ── Stage 5+6: Create and start new container ──────────────────
            yield emit("LOG: [5/7] Creating new container with updated image…")

            def _create_and_start():
                client = _make_docker_client(host_url)
                try:
                    old_c    = client.containers.get(backup_cname)
                    attrs    = old_c.attrs or {}
                    config   = attrs.get("Config", {})
                    hcfg     = attrs.get("HostConfig", {})
                    net_cfg  = attrs.get("NetworkSettings", {})

                    # Reconstruct port bindings from NetworkSettings
                    port_bindings = {}
                    for port_proto, bindings in (net_cfg.get("Ports") or {}).items():
                        if bindings:
                            for b in bindings:
                                hp = b.get("HostPort")
                                if hp:
                                    port_bindings[port_proto] = int(hp)

                    # Reconstruct bind mounts
                    binds = {}
                    for m in (attrs.get("Mounts") or []):
                        if m.get("Type") == "bind":
                            src  = m.get("Source", "")
                            dst  = m.get("Destination", "")
                            mode = m.get("Mode", "rw")
                            if src and dst:
                                binds[src] = {"bind": dst, "mode": mode}

                    # Named volume binds
                    vol_binds = {
                        m["Name"]: {"bind": m["Destination"], "mode": m.get("Mode", "rw")}
                        for m in (attrs.get("Mounts") or [])
                        if m.get("Type") == "volume" and m.get("Name") and m.get("Destination")
                    }
                    all_binds = {**binds, **vol_binds} or None

                    restart_policy = hcfg.get("RestartPolicy") or {"Name": "no"}

                    # Normalise restart policy — docker SDK wants {"Name": ..., "MaximumRetryCount": ...}
                    if isinstance(restart_policy, dict):
                        rp = {
                            "Name": restart_policy.get("Name", "no"),
                            "MaximumRetryCount": restart_policy.get("MaximumRetryCount", 0),
                        }
                    else:
                        rp = {"Name": "no"}

                    _raw_net_mode = _resolve_net_mode_parent(
                        client, old_c, hcfg.get("NetworkMode") or ""
                    ) or None
                    _net_mode = (_raw_net_mode or "").lower()
                    _hostname = (
                        None if _net_mode in ("host", "none") or _net_mode.startswith("container:")
                        else (config.get("Hostname") or orig_name)
                    )
                    _cres = client.api.create_container(
                        image         = image_name,
                        name          = orig_name,
                        command       = config.get("Cmd"),
                        environment   = config.get("Env"),
                        labels        = config.get("Labels"),
                        hostname      = _hostname,
                        working_dir   = config.get("WorkingDir") or None,
                        entrypoint    = config.get("Entrypoint"),
                        user          = config.get("User") or None,
                        tty           = config.get("Tty", False),
                        stdin_open    = config.get("OpenStdin", False),
                        host_config   = client.api.create_host_config(
                            port_bindings  = port_bindings or None,
                            binds          = all_binds,
                            volumes_from   = hcfg.get("VolumesFrom") or None,
                            network_mode   = _raw_net_mode,
                            privileged     = hcfg.get("Privileged", False),
                            cap_add        = hcfg.get("CapAdd") or None,
                            cap_drop       = hcfg.get("CapDrop") or None,
                            devices        = hcfg.get("Devices") or None,
                            dns            = hcfg.get("Dns") or None,
                            dns_search     = hcfg.get("DnsSearch") or None,
                            extra_hosts    = hcfg.get("ExtraHosts") or None,
                            sysctls        = hcfg.get("Sysctls") or None,
                            mem_limit      = hcfg.get("Memory") or None,
                            nano_cpus      = hcfg.get("NanoCpus") or None,
                            log_config     = hcfg.get("LogConfig") or None,
                            pid_mode       = hcfg.get("PidMode") or None,
                            userns_mode    = hcfg.get("UsernsMode") or None,
                            security_opt   = hcfg.get("SecurityOpt") or None,
                            tmpfs          = hcfg.get("Tmpfs") or None,
                            shm_size       = hcfg.get("ShmSize") or None,
                            ipc_mode       = hcfg.get("IpcMode") or None,
                            read_only      = hcfg.get("ReadonlyRootfs", False),
                            restart_policy = rp,
                        ),
                    )
                    new_c = client.containers.get(_cres["Id"])
                    try:
                        new_c.start()
                    except Exception:
                        try:
                            new_c.remove(force=True)
                        except Exception:
                            pass
                        raise
                    new_c.reload()
                    return new_c
                finally:
                    client.close()

            try:
                new_container = await asyncio.to_thread(_create_and_start)
                yield emit(f"LOG: [5/7] ✓ New container '{orig_name}' created and started.")
            except Exception as create_err:
                yield emit(f"LOG: [ERROR] Container creation failed: {create_err}")
                yield emit("LOG: [ROLLBACK] Restoring original container…")
                try:
                    def _rollback_rename():
                        client = _make_docker_client(host_url)
                        try:
                            bak = client.containers.get(backup_cname)
                            bak.rename(orig_name)
                            bak.reload()
                            return bak
                        finally:
                            client.close()
                    bak_c = await asyncio.to_thread(_rollback_rename)
                    yield emit(f"LOG: [ROLLBACK] ✓ Renamed '{backup_cname}' back to '{orig_name}'.")
                    try:
                        def _rollback_start():
                            client = _make_docker_client(host_url)
                            try:
                                client.containers.get(orig_name).start()
                            finally:
                                client.close()
                        await asyncio.to_thread(_rollback_start)
                        yield emit("LOG: [ROLLBACK] ✓ Original container is running again.")
                    except Exception as start_err:
                        yield emit(
                            f"LOG: [ROLLBACK] Container renamed but could not auto-start "
                            f"(likely container-mode networking — start '{orig_name}' manually). Error: {start_err}"
                        )
                except Exception as rb_err:
                    yield emit(
                        f"LOG: [ROLLBACK FAILED] Could not rename backup — "
                        f"container is still '{backup_cname}'. Manual rename + start needed. Error: {rb_err}"
                    )
                yield emit("UPDATE_ERROR:Container creation failed. Original has been restored.")
                db = _SessionLocal()
                try:
                    _upsert_update_status(db, container_name, host_id,
                                          update_in_progress=False,
                                          last_update_status="failed",
                                          last_update_error=str(create_err))
                finally:
                    db.close()
                return

            # ── Stage 7: Health check ──────────────────────────────────────
            yield emit("LOG: [6/7] Running health check…")

            db = _SessionLocal()
            try:
                try:
                    health_timeout = int(_setting(db, "container_update_health_timeout", "30"))
                except ValueError:
                    health_timeout = 30
            finally:
                db.close()

            def _wait_healthy(timeout: int) -> tuple[bool, str]:
                """
                Poll container status for up to `timeout` seconds.
                Returns (is_healthy, final_status).
                Honours Docker-native HEALTHCHECK if configured.
                """
                client = _make_docker_client(host_url)
                try:
                    deadline = time.monotonic() + timeout
                    while time.monotonic() < deadline:
                        new_container.reload()
                        status = new_container.status

                        if status in ("exited", "dead"):
                            return False, status

                        if status == "running":
                            health = (new_container.attrs.get("State") or {}).get("Health")
                            if health:
                                hstatus = health.get("Status", "")
                                if hstatus == "healthy":
                                    return True, "healthy"
                                if hstatus == "unhealthy":
                                    return False, "unhealthy"
                                # "starting" — keep waiting
                            else:
                                # No HEALTHCHECK defined — running is enough
                                return True, "running"
                        time.sleep(2)

                    # Timeout — final status check
                    new_container.reload()
                    ok = new_container.status == "running"
                    return ok, new_container.status
                finally:
                    client.close()

            is_healthy, final_status = await asyncio.to_thread(_wait_healthy, health_timeout)

            if is_healthy:
                # ── Stage 8a: Success ──────────────────────────────────────
                yield emit(f"LOG: [7/7] Container is healthy (status: {final_status}). Cleaning up backup…")

                def _cleanup_backup():
                    client = _make_docker_client(host_url)
                    try:
                        bak = client.containers.get(backup_cname)
                        bak.remove(force=True)
                    except Exception:
                        pass   # non-fatal — backup can be cleaned up later
                    finally:
                        client.close()

                await asyncio.to_thread(_cleanup_backup)

                # ── Stage 7b: Cascade-restart containers sharing old container's network ──
                yield emit(f"LOG: [7/7] Checking for containers sharing network with old container…")
                def _find_and_cascade():
                    client = _make_docker_client(host_url)
                    try:
                        deps = _find_network_dependents(client, old_id)
                        results = []
                        for dep in deps:
                            dname = dep.name.lstrip("/")
                            try:
                                _recreate_container_with_net(client, dep, f"container:{orig_name}")
                                results.append((dname, None))
                            except Exception as de:
                                results.append((dname, str(de)))
                        return results
                    finally:
                        client.close()

                cascade_results = await asyncio.to_thread(_find_and_cascade)
                for dname, err in cascade_results:
                    if err:
                        yield emit(f"LOG: [CASCADE] ⚠ Could not restart '{dname}': {err}")
                    else:
                        yield emit(f"LOG: [CASCADE] ✓ Restarted '{dname}' with updated network reference.")

                new_container.reload()
                new_digest = new_container.image.id

                db = _SessionLocal()
                try:
                    _upsert_update_status(db, container_name, host_id,
                                          image               = image_name,
                                          current_digest      = new_digest,
                                          latest_digest       = new_digest,
                                          has_update          = False,
                                          update_blocked      = False,
                                          blocked_reason      = None,
                                          update_in_progress  = False,
                                          last_updated_at     = datetime.now(timezone.utc),
                                          last_update_status  = "success",
                                          last_update_error   = None)
                finally:
                    db.close()

                yield emit(f"LOG: ✓ Update complete! {container_name} is now running {image_name} ({new_digest[:19]}…)")
                yield emit("UPDATE_DONE:success")
                _fire_notification(
                    "container.updated",
                    "Container Updated",
                    f"{container_name} successfully updated to {image_name} ({new_digest[:19]}…)",
                )

            else:
                # ── Stage 8b: Rollback ─────────────────────────────────────
                yield emit(f"LOG: [FAIL] New container failed health check (status: {final_status}). Rolling back…")

                def _rollback():
                    client = _make_docker_client(host_url)
                    try:
                        # Remove the failed new container
                        try:
                            new_container.remove(force=True)
                        except Exception:
                            pass
                        # Restore backup
                        bak = client.containers.get(backup_cname)
                        bak.rename(orig_name)
                        bak.start()
                    finally:
                        client.close()

                try:
                    await asyncio.to_thread(_rollback)
                    yield emit(f"LOG: [ROLLBACK] ✓ '{orig_name}' restored to previous version and running.")
                    yield emit("UPDATE_DONE:rolled_back")
                    rollback_status = "rolled_back"
                except Exception as rb_err:
                    yield emit(
                        f"LOG: [ROLLBACK FAILED] Auto-restore failed: {rb_err}. "
                        f"Backup container '{backup_cname}' is preserved — rename it to '{orig_name}' and start it manually."
                    )
                    yield emit("UPDATE_DONE:rollback_failed")
                    rollback_status = "failed"

                db = _SessionLocal()
                try:
                    _upsert_update_status(db, container_name, host_id,
                                          update_in_progress=False,
                                          last_update_status=rollback_status,
                                          last_update_error=f"Health check failed (status: {final_status})")
                finally:
                    db.close()

                _fire_notification(
                    "container.update_failed",
                    "Container Update Failed — Rolled Back",
                    f"{container_name}: new image failed health check; original container restored",
                )

        except Exception as outer_err:
            # Catch-all: report the error and leave backup in place
            yield emit(f"LOG: [FATAL] Unexpected error during update: {outer_err}")
            yield emit(f"UPDATE_ERROR:{outer_err}")
            if backup_cname:
                yield emit(
                    f"LOG: Backup container '{backup_cname}' is preserved. "
                    f"Restore manually: docker rename {backup_cname} {container_name or 'ORIGINAL_NAME'} && docker start {container_name or backup_cname}"
                )
            if container_name:
                db = _SessionLocal()
                try:
                    _upsert_update_status(db, container_name, host_id,
                                          update_in_progress=False,
                                          last_update_status="failed",
                                          last_update_error=str(outer_err))
                except Exception:
                    pass
                finally:
                    db.close()


# ── Bulk update check (synchronous — runs in thread) ──────────────────────────

def _check_all_containers_for_host(
    host_url: str,
    host_id,
    auto_update: str = "disabled",
) -> None:
    """
    Iterate every running container on a host, compare image digests against
    the registry, persist results, and fire notifications when updates appear.
    Called from the background loop via asyncio.to_thread().
    """
    client = _make_docker_client(host_url)
    try:
        containers = client.containers.list(filters={"status": "running"})
    except Exception as e:
        print(f"[update-check] list failed on {host_url}: {e}", flush=True)
        return
    finally:
        client.close()

    for c in containers:
        cname      = c.name.lstrip("/")
        image_name = (c.image.tags or [str(c.image.id)])[0]

        # Never auto-update InSpectre's own critical containers
        role = _stack_role(cname, c.id)
        if role in ("self", "db"):
            continue

        # Respect label-level pin
        if (c.labels or {}).get("com.inspectre.update.pin") == "true":
            continue

        # Respect DB-level pin
        db = _SessionLocal()
        try:
            row = db.execute(
                text("""SELECT pinned, update_in_progress
                        FROM container_update_status
                        WHERE container_name=:n AND COALESCE(host_id,-1)=COALESCE(:h,-1)"""),
                {"n": cname, "h": host_id},
            ).fetchone()
            if row and (row[0] or row[1]):
                db.close()
                continue
        finally:
            db.close()

        try:
            result       = _check_update_sync(image_name, host_url)
            had_update   = False

            db = _SessionLocal()
            try:
                prev = db.execute(
                    text("""SELECT has_update FROM container_update_status
                            WHERE container_name=:n AND COALESCE(host_id,-1)=COALESCE(:h,-1)"""),
                    {"n": cname, "h": host_id},
                ).fetchone()
                had_update = bool(prev and prev[0])

                kw = dict(
                    image          = image_name,
                    current_digest = result.get("current_digest"),
                    latest_digest  = result.get("latest_digest"),
                    has_update     = result.get("has_update", False),
                    checked_at     = datetime.now(timezone.utc),
                )
                if not result.get("has_update"):
                    kw["update_blocked"] = False
                _upsert_update_status(db, cname, host_id, **kw)
            finally:
                db.close()

            # Notify once when an update first appears
            if result.get("has_update") and not had_update:
                _fire_notification(
                    "container.update_available",
                    "Container Update Available",
                    f"New image version available for {cname} ({image_name})",
                )

        except Exception as exc:
            print(f"[update-check] {cname}: {exc}", flush=True)

        time.sleep(1)   # small inter-container delay to respect rate limits


# ── Background update check loop ───────────────────────────────────────────────

async def container_update_check_loop() -> None:
    """
    Background asyncio loop: checks all containers for image updates on a schedule.
    Schedule is driven by the 'container_check_enabled', 'container_check_hour', and
    'container_check_days' settings (matching the VM image update schedule style).
    Registered in main.py's on_startup via asyncio.ensure_future().
    """
    # Clear any stale update_in_progress flags left by a previous crash/restart
    _db = _SessionLocal()
    try:
        _db.execute(text("""
            UPDATE container_update_status
            SET update_in_progress = FALSE,
                last_update_error = COALESCE(last_update_error, 'Update interrupted by process restart')
            WHERE update_in_progress = TRUE
        """))
        _db.commit()
    except Exception:
        pass
    finally:
        _db.close()

    await asyncio.sleep(90)   # startup grace — let Docker event loop settle first
    last_check_date = None
    while True:
        try:
            db = _SessionLocal()
            try:
                enabled     = _setting(db, "container_check_enabled", "false") == "true"
                hour        = int(_setting(db, "container_check_hour", "3"))
                days_raw    = _setting(db, "container_check_days", "[]")
                days        = json.loads(days_raw)
                auto_update = _setting(db, "container_auto_update", "disabled")
                hosts       = _get_enabled_hosts(db)
            finally:
                db.close()

            if enabled:
                now      = datetime.now(timezone.utc)
                js_dow   = (now.weekday() + 1) % 7
                right_hour = now.hour == hour
                right_day  = not days or js_dow in days
                already_ran = last_check_date == now.date()

                if right_hour and right_day and not already_ran:
                    last_check_date = now.date()
                    docker_hosts = [h for h in hosts if h.get("type") != "proxmox"]
                    for host in docker_hosts:
                        host_url = host.get("url") or "unix:///var/run/docker.sock"
                        host_id  = host.get("id")
                        try:
                            await asyncio.to_thread(
                                _check_all_containers_for_host, host_url, host_id, auto_update
                            )
                        except Exception as exc:
                            print(f"[update-check] host {host_url}: {exc}", flush=True)

        except Exception as exc:
            print(f"[update-check] loop error: {exc}", flush=True)

        await asyncio.sleep(300)


# ── API routes ─────────────────────────────────────────────────────────────────

@router.get("/docker/update-status")
async def get_all_update_statuses(request: Request):
    """Return update status for all tracked containers (used by ContainersPage for badges)."""
    _verify_token(request)
    db = _SessionLocal()
    try:
        rows = db.execute(text("""
            SELECT container_name, host_id, image, has_update, update_blocked,
                   blocked_reason, checked_at, last_updated_at, update_in_progress,
                   last_update_status, pinned, current_digest, latest_digest
            FROM container_update_status
            ORDER BY container_name
        """)).fetchall()
        return [
            {
                "container_name":     r[0],
                "host_id":            r[1],
                "image":              r[2],
                "has_update":         r[3],
                "update_blocked":     r[4],
                "blocked_reason":     r[5],
                "checked_at":         r[6].isoformat() if r[6] else None,
                "last_updated_at":    r[7].isoformat() if r[7] else None,
                "update_in_progress": r[8],
                "last_update_status": r[9],
                "pinned":             r[10],
                "current_digest":     r[11],
                "latest_digest":      r[12],
            }
            for r in rows
        ]
    finally:
        db.close()


@router.get("/docker/containers/{container_id}/update-status")
async def get_container_update_status(container_id: str, request: Request):
    """Detailed update status for a single container, including CVE scan results."""
    _verify_token(request)
    if _parse_proxmox_id(container_id):
        raise HTTPException(400, "Update management is not available for Proxmox containers.")
    db = _SessionLocal()
    try:
        host_url, _, host_id = _resolve_host(db, container_id)

        def _get_name():
            client = _make_docker_client(host_url)
            try:
                return client.containers.get(container_id).name.lstrip("/")
            finally:
                client.close()

        container_name = await asyncio.to_thread(_get_name)
        row = _get_update_status_row(db, container_name, host_id)
        if not row:
            return {"container_name": container_name, "has_update": False, "checked_at": None}
        return row
    finally:
        db.close()


@router.post("/docker/containers/{container_id}/check-update")
async def check_container_update(container_id: str, request: Request):
    """Trigger an immediate update check for one container. Synchronous — returns result."""
    _verify_token(request)
    if _parse_proxmox_id(container_id):
        raise HTTPException(400, "Update management is not available for Proxmox containers.")
    db = _SessionLocal()
    try:
        host_url, _, host_id = _resolve_host(db, container_id)

        def _get_info():
            client = _make_docker_client(host_url)
            try:
                c = client.containers.get(container_id)
                return c.name.lstrip("/"), (c.image.tags or [str(c.image.id)])[0]
            finally:
                client.close()

        container_name, image_name = await asyncio.to_thread(_get_info)
        result = await asyncio.to_thread(_check_update_sync, image_name, host_url)

        prev = _get_update_status_row(db, container_name, host_id)
        had_update = bool(prev and prev.get("has_update"))

        kw = dict(
            image          = image_name,
            current_digest = result.get("current_digest"),
            latest_digest  = result.get("latest_digest"),
            has_update     = result.get("has_update", False),
            checked_at     = datetime.now(timezone.utc),
        )
        if not result.get("has_update"):
            kw["update_blocked"] = False
        _upsert_update_status(db, container_name, host_id, **kw)

        if result.get("has_update") and not had_update:
            asyncio.ensure_future(_notification_dispatch(
                "container.update_available", "Container Update Available",
                f"New image available for {container_name} ({image_name})",
            ))

        return {**result, "container_name": container_name, "image": image_name}
    finally:
        db.close()


@router.post("/docker/containers/{container_id}/scan-new-image")
async def scan_new_image_endpoint(container_id: str, request: Request):
    """
    SSE: Pull and Trivy-scan the latest image version without deploying it.
    Saves results to DB so the Updates tab can display them without re-scanning.
    """
    _verify_token(request)
    if _parse_proxmox_id(container_id):
        raise HTTPException(400, "Not available for Proxmox containers.")

    db = _SessionLocal()
    try:
        host_url, _, host_id = _resolve_host(db, container_id)

        def _get_info():
            client = _make_docker_client(host_url)
            try:
                c = client.containers.get(container_id)
                return c.name.lstrip("/"), (c.image.tags or [str(c.image.id)])[0]
            finally:
                client.close()

        container_name, image_name = await asyncio.to_thread(_get_info)
    finally:
        db.close()

    async def _stream():
        yield f"data: LOG: Pulling latest image: {image_name}…\n\n"
        try:
            def _pull():
                client = _make_docker_client(host_url)
                try:
                    return client.images.pull(image_name).id
                finally:
                    client.close()
            new_id = await asyncio.to_thread(_pull)
            yield f"data: LOG: Pull complete ({new_id[:19]}…). Starting Trivy scan…\n\n"
        except Exception as e:
            yield f"data: LOG: Pull failed: {e}\n\n"
            yield "data: SCAN_DONE:error\n\n"
            return

        vulns, critical, high = await asyncio.to_thread(_trivy_scan_image, image_name)
        db2 = _SessionLocal()
        try:
            _upsert_update_status(db2, container_name, host_id,
                                  new_image_vulns=json.dumps(vulns),
                                  new_image_scanned_at=datetime.now(timezone.utc),
                                  update_blocked=critical > 0,
                                  blocked_reason=f"{critical} critical CVE(s) in new image" if critical > 0 else None)
        except Exception as _db_err:
            yield f"data: LOG: Warning: could not save scan result to DB: {_db_err}\n\n"
        finally:
            db2.close()

        yield f"data: LOG: Scan complete — {critical} critical, {high} high, {len(vulns)} total CVEs.\n\n"
        yield (
            f"data: SCAN_RESULT:{json.dumps({'vulns': vulns, 'critical': critical, 'high': high, 'image': image_name})}\n\n"
        )
        yield "data: SCAN_DONE:ok\n\n"

    return StreamingResponse(
        _stream(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


class SafeUpdateBody(BaseModel):
    force:      bool = False
    scan_first: bool = True


@router.post("/docker/containers/{container_id}/safe-update")
async def safe_update_endpoint(container_id: str, body: SafeUpdateBody, request: Request):
    """
    SSE: Run the full waterproof blue/green update flow.
    Accepts force=true to override a CVE block, scan_first=false to skip the Trivy gate.
    """
    _verify_token(request)
    if _parse_proxmox_id(container_id):
        raise HTTPException(400, "Update is not available for Proxmox containers.")

    db = _SessionLocal()
    try:
        host_url, _, host_id = _resolve_host(db, container_id)
    finally:
        db.close()

    async def _stream():
        async for line in _safe_update_stream(
            container_id, host_url, host_id,
            force=body.force, scan_first=body.scan_first,
        ):
            yield line

    return StreamingResponse(
        _stream(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/docker/containers/{container_id}/backup")
async def backup_container_endpoint(container_id: str, request: Request):
    """Manually trigger a config backup for a container."""
    _verify_token(request)
    if _parse_proxmox_id(container_id):
        raise HTTPException(400, "Not available for Proxmox containers.")
    db = _SessionLocal()
    try:
        host_url, _, host_id = _resolve_host(db, container_id)

        def _get_name():
            client = _make_docker_client(host_url)
            try:
                return client.containers.get(container_id).name.lstrip("/")
            finally:
                client.close()

        container_name = await asyncio.to_thread(_get_name)
    finally:
        db.close()

    backup_id = await asyncio.to_thread(
        _backup_container_sync, container_name, container_id, host_url, host_id, "manual"
    )
    return {"backup_id": backup_id, "container_name": container_name}


@router.get("/docker/containers/{container_id}/backups")
async def list_container_backups(container_id: str, request: Request):
    """List the 20 most recent backups for a container."""
    _verify_token(request)
    db = _SessionLocal()
    try:
        host_url, _, _ = _resolve_host(db, container_id)

        def _get_name():
            client = _make_docker_client(host_url)
            try:
                return client.containers.get(container_id).name.lstrip("/")
            finally:
                client.close()

        container_name = await asyncio.to_thread(_get_name)
        rows = db.execute(text("""
            SELECT id, container_name, image, image_id, backed_up_at, reason,
                   (compose_yaml IS NOT NULL AND compose_yaml != '') AS has_compose
            FROM container_backups
            WHERE container_name = :n
            ORDER BY backed_up_at DESC
            LIMIT 20
        """), {"n": container_name}).fetchall()
        return [
            {
                "id":             r[0],
                "container_name": r[1],
                "image":          r[2],
                "image_id":       (r[3] or "")[:19] + "…" if r[3] else None,
                "backed_up_at":   r[4].isoformat() if r[4] else None,
                "reason":         r[5],
                "has_compose":    bool(r[6]),
            }
            for r in rows
        ]
    finally:
        db.close()


@router.get("/docker/backups/{backup_id}/compose")
async def get_backup_compose(backup_id: int, request: Request):
    """Return the compose YAML stored for a specific backup."""
    _verify_token(request)
    db = _SessionLocal()
    try:
        row = db.execute(
            text("SELECT container_name, compose_yaml FROM container_backups WHERE id=:id"),
            {"id": backup_id},
        ).fetchone()
        if not row or not row[1]:
            raise HTTPException(404, "Backup not found or has no compose YAML.")
        return {"container_name": row[0], "compose_yaml": row[1]}
    finally:
        db.close()


class PinBody(BaseModel):
    pinned: bool


@router.post("/docker/containers/{container_id}/pin")
async def pin_container(container_id: str, body: PinBody, request: Request):
    """Pin or unpin a container from auto-updates."""
    _verify_token(request)
    db = _SessionLocal()
    try:
        host_url, _, host_id = _resolve_host(db, container_id)

        def _get_name():
            client = _make_docker_client(host_url)
            try:
                return client.containers.get(container_id).name.lstrip("/")
            finally:
                client.close()

        container_name = await asyncio.to_thread(_get_name)
        _upsert_update_status(db, container_name, host_id, pinned=body.pinned)
        return {"container_name": container_name, "pinned": body.pinned}
    finally:
        db.close()


@router.post("/docker/check-all-updates")
async def check_all_updates_endpoint(request: Request):
    """
    Trigger an immediate update check across all containers on all Docker hosts.
    Returns immediately — the check runs asynchronously in the background.
    """
    _verify_token(request)
    db = _SessionLocal()
    try:
        hosts = _get_enabled_hosts(db)
        docker_hosts = [h for h in hosts if h.get("type") != "proxmox"]
    finally:
        db.close()

    async def _run():
        for host in docker_hosts:
            host_url = host.get("url") or "unix:///var/run/docker.sock"
            host_id  = host.get("id")
            try:
                await asyncio.to_thread(_check_all_containers_for_host, host_url, host_id)
            except Exception as e:
                print(f"[check-all] {host_url}: {e}", flush=True)

    asyncio.ensure_future(_run())
    return {"status": "check_started", "hosts": len(docker_hosts)}


@router.post("/docker/update-all")
async def update_all_pending(request: Request):
    """
    Trigger safe-updates for all containers that have has_update=True and are
    not pinned, blocked, or already updating. Returns immediately; updates run
    as a background task with the configured stagger delay between containers.
    """
    _verify_token(request)
    db = _SessionLocal()
    try:
        pending = db.execute(text("""
            SELECT container_name, host_id FROM container_update_status
            WHERE has_update = TRUE
              AND NOT COALESCE(pinned, FALSE)
              AND NOT COALESCE(update_blocked, FALSE)
              AND NOT COALESCE(update_in_progress, FALSE)
        """)).fetchall()
        hosts = _get_enabled_hosts(db)
    finally:
        db.close()

    host_map = {h["id"]: h for h in hosts if h.get("type") != "proxmox"}

    async def _run_all():
        for i, row in enumerate(pending):
            cname, host_id = row[0], row[1]
            host = host_map.get(host_id)
            if not host:
                continue
            host_url = host.get("url") or "unix:///var/run/docker.sock"

            if i > 0:
                db2 = _SessionLocal()
                try:
                    stagger = int(_setting(db2, "container_update_stagger_seconds", "30"))
                except Exception:
                    stagger = 30
                finally:
                    db2.close()
                await asyncio.sleep(stagger)

            def _get_cid(cname=cname, hurl=host_url):
                client = _make_docker_client(hurl)
                try:
                    return client.containers.get(cname).id
                except Exception:
                    return None
                finally:
                    client.close()

            cid = await asyncio.to_thread(_get_cid)
            if not cid:
                continue
            try:
                async for _ in _safe_update_stream(cid, host_url, host_id):
                    pass
            except Exception as e:
                print(f"[update-all] {cname}: {e}", flush=True)

    asyncio.ensure_future(_run_all())
    return {
        "status": "updates_triggered",
        "count": len(pending),
        "containers": [r[0] for r in pending],
    }


@router.get("/docker/containers/{container_id}/networks")
async def get_container_networks(container_id: str, request: Request):
    """Return all host Docker networks and the container's current network mode."""
    _verify_token(request)
    db = _SessionLocal()
    try:
        host_url, _, _ = _resolve_host(db, container_id)
    finally:
        db.close()

    def _fetch():
        client = _make_docker_client(host_url)
        try:
            c        = client.containers.get(container_id)
            hcfg     = c.attrs.get("HostConfig") or {}
            net_mode = hcfg.get("NetworkMode") or "bridge"
            all_nets = [n.name for n in client.networks.list()]
            return all_nets, net_mode
        finally:
            client.close()

    all_nets, current = await asyncio.to_thread(_fetch)
    return {"networks": sorted(all_nets), "current": current}


class SetNetworkBody(BaseModel):
    network: str


@router.post("/docker/containers/{container_id}/network")
async def set_container_network(container_id: str, body: SetNetworkBody, request: Request):
    """
    Connect a container to a different Docker network.
    Named networks are switched live (disconnect old, connect new).
    Switching to/from host or none requires a container recreate and is not
    supported here — use the update flow instead.
    """
    _verify_token(request)
    db = _SessionLocal()
    try:
        host_url, _, _ = _resolve_host(db, container_id)
    finally:
        db.close()

    target_net = body.network.strip()
    if not target_net:
        raise HTTPException(status_code=400, detail="network is required")
    if target_net in ("host", "none"):
        raise HTTPException(
            status_code=400,
            detail="Switching to host/none requires recreating the container — not supported via this endpoint.",
        )

    def _switch():
        client = _make_docker_client(host_url)
        try:
            c    = client.containers.get(container_id)
            hcfg = c.attrs.get("HostConfig") or {}
            net_sets = c.attrs.get("NetworkSettings") or {}
            current_nets = list((net_sets.get("Networks") or {}).keys())

            new_net_obj = client.networks.get(target_net)
            # Connect to new network first so there's no connectivity gap
            new_net_obj.connect(c)
            # Disconnect from all previous non-target networks
            for n in current_nets:
                if n != target_net:
                    try:
                        client.networks.get(n).disconnect(c)
                    except Exception:
                        pass
            c.reload()
            return _fmt_container(c)
        finally:
            client.close()

    updated = await asyncio.to_thread(_switch)
    return updated


class RestartPolicyBody(BaseModel):
    name:                str
    maximum_retry_count: int = 0


@router.post("/docker/containers/{container_id}/restart-policy")
async def set_restart_policy(container_id: str, body: RestartPolicyBody, request: Request):
    """Update the restart policy on a running or stopped container."""
    _verify_token(request)
    valid = {"no", "always", "unless-stopped", "on-failure"}
    if body.name not in valid:
        raise HTTPException(status_code=400, detail=f"policy must be one of: {', '.join(sorted(valid))}")

    db = _SessionLocal()
    try:
        host_url, _, _ = _resolve_host(db, container_id)
    finally:
        db.close()

    def _apply():
        client = _make_docker_client(host_url)
        try:
            c = client.containers.get(container_id)
            client.api.update_container(
                container_id,
                restart_policy={
                    "Name":              body.name,
                    "MaximumRetryCount": body.maximum_retry_count if body.name == "on-failure" else 0,
                },
            )
            c.reload()
            return _fmt_container(c)
        finally:
            client.close()

    updated = await asyncio.to_thread(_apply)
    return updated


@router.get("/ping")
async def ping():
    """No-auth health probe used by the frontend reconnect UI after a self-update."""
    return {"pong": True}
