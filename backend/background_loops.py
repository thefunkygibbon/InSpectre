import asyncio
import json
import os
import shutil
import subprocess
import threading
from datetime import datetime, timezone, timedelta

import httpx
from sqlalchemy import text

from config import PROBE_URL
from database import SessionLocal
from models import Setting, TrafficStat
from probe_client import _probe_client
from trivy_utils import run_trivy_image_scan_sync


# ---------------------------------------------------------------------------
# Device lifecycle — auto-expire "new" status & auto-delete stale devices
# ---------------------------------------------------------------------------
def _lifecycle_threshold_seconds(value_key: str, unit_key: str, db) -> int:
    """Convert a value+unit setting pair into a total number of seconds."""
    try:
        value = int((db.get(Setting, value_key) or type('', (), {'value': '7'})()).value or 7)
    except (ValueError, AttributeError):
        value = 7
    unit_row = db.get(Setting, unit_key)
    unit = (unit_row.value or "day").strip().lower() if unit_row else "day"
    multipliers = {"day": 86400, "week": 604800, "month": 2592000, "year": 31536000}
    return value * multipliers.get(unit, 86400)


async def _device_lifecycle_loop():
    """Hourly loop that auto-acknowledges new devices and auto-deletes stale ones."""
    await asyncio.sleep(120)  # startup grace period
    while True:
        try:
            db = SessionLocal()
            try:
                def _flag(key):
                    row = db.get(Setting, key)
                    return row and row.value.strip().lower() == "true"

                now = datetime.now(timezone.utc)

                # ── Auto-acknowledge new devices past threshold ────────────
                if _flag("new_device_threshold_enabled"):
                    secs = _lifecycle_threshold_seconds(
                        "new_device_threshold_value", "new_device_threshold_unit", db)
                    cutoff = now - timedelta(seconds=secs)
                    result = db.execute(
                        text("""
                            UPDATE devices
                            SET is_acknowledged = true
                            WHERE is_acknowledged = false
                              AND first_seen < :cutoff
                        """),
                        {"cutoff": cutoff},
                    )
                    if result.rowcount:
                        db.commit()
                        print(f"[lifecycle] Auto-acknowledged {result.rowcount} device(s) "
                              f"older than threshold.", flush=True)

                # ── Auto-delete stale devices ──────────────────────────────
                if _flag("stale_device_auto_delete_enabled"):
                    secs = _lifecycle_threshold_seconds(
                        "stale_device_auto_delete_value", "stale_device_auto_delete_unit", db)
                    cutoff = now - timedelta(seconds=secs)
                    # Fetch candidates: not seen since cutoff, not important, not group primary
                    # when the group has other living members.
                    candidates = db.execute(
                        text("""
                            SELECT d.mac_address, d.group_id, d.group_primary
                            FROM devices d
                            WHERE d.last_seen < :cutoff
                              AND COALESCE(d.is_important, false) = false
                              AND (
                                -- ungrouped devices are eligible
                                d.group_id IS NULL
                                OR
                                -- grouped non-primary members are eligible
                                COALESCE(d.group_primary, false) = false
                                OR
                                -- primary is eligible only if ALL other group members are also stale
                                (
                                  COALESCE(d.group_primary, false) = true
                                  AND NOT EXISTS (
                                    SELECT 1 FROM devices d2
                                    WHERE d2.group_id = d.group_id
                                      AND d2.mac_address != d.mac_address
                                      AND d2.last_seen >= :cutoff
                                  )
                                )
                              )
                        """),
                        {"cutoff": cutoff},
                    ).fetchall()

                    for row in candidates:
                        mac = row[0]
                        gid = row[1]
                        is_primary = row[2]

                        # If deleting a primary with no surviving members, clean group refs
                        if gid and is_primary:
                            db.execute(
                                text("UPDATE devices SET group_id = NULL, group_primary = false "
                                     "WHERE group_id = :gid AND mac_address != :mac"),
                                {"gid": str(gid), "mac": mac},
                            )
                        # Promote a new primary if deleting a non-primary whose group now
                        # needs a new primary (rare edge case but safe to handle)
                        elif gid and not is_primary:
                            existing_primary = db.execute(
                                text("SELECT mac_address FROM devices "
                                     "WHERE group_id = :gid AND group_primary = true "
                                     "AND mac_address != :mac LIMIT 1"),
                                {"gid": str(gid), "mac": mac},
                            ).fetchone()
                            if not existing_primary:
                                new_primary = db.execute(
                                    text("SELECT mac_address FROM devices "
                                         "WHERE group_id = :gid AND mac_address != :mac "
                                         "AND last_seen >= :cutoff LIMIT 1"),
                                    {"gid": str(gid), "mac": mac, "cutoff": cutoff},
                                ).fetchone()
                                if new_primary:
                                    db.execute(
                                        text("UPDATE devices SET group_primary = true "
                                             "WHERE mac_address = :m"),
                                        {"m": new_primary[0]},
                                    )

                        db.execute(
                            text("DELETE FROM devices WHERE mac_address = :mac"),
                            {"mac": mac},
                        )
                        print(f"[lifecycle] Auto-deleted stale device {mac} "
                              f"(not seen since before {cutoff.date()})", flush=True)

                    if candidates:
                        db.commit()

            except Exception as exc:
                db.rollback()
                print(f"[lifecycle] Error in device lifecycle loop: {exc}", flush=True)
            finally:
                db.close()
        except Exception as outer:
            print(f"[lifecycle] Outer error: {outer}", flush=True)

        await asyncio.sleep(3600)  # run hourly


# ---------------------------------------------------------------------------
# Block schedule enforcement
# ---------------------------------------------------------------------------
_DAY_ABBREVS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def _schedule_active_now(days_of_week: str, start_time: str, end_time: str) -> bool:
    now_local = datetime.now()
    current_day = _DAY_ABBREVS[now_local.weekday()]
    allowed_days = [d.strip().lower() for d in days_of_week.split(",")]
    if current_day not in allowed_days:
        return False
    try:
        sh, sm = map(int, start_time.split(":"))
        eh, em = map(int, end_time.split(":"))
        start_mins = sh * 60 + sm
        end_mins   = eh * 60 + em
        now_mins   = now_local.hour * 60 + now_local.minute
        if end_mins > start_mins:
            return start_mins <= now_mins < end_mins
        else:
            return now_mins >= start_mins or now_mins < end_mins
    except Exception:
        return False


async def _block_schedule_loop():
    from probe_client import _execute_block_bg
    from device_utils import _add_event
    import state as _state

    await asyncio.sleep(15)
    while True:
        try:
            db = SessionLocal()
            try:
                try:
                    schedules = db.execute(text(
                        "SELECT id, mac_address, days_of_week, start_time, end_time, mac_addresses, tags, person_id, person_ids "
                        "FROM block_schedules WHERE enabled = TRUE"
                    )).fetchall()
                    has_person_ids_col = True
                except Exception:
                    schedules = db.execute(text(
                        "SELECT id, mac_address, days_of_week, start_time, end_time, mac_addresses, tags, person_id "
                        "FROM block_schedules WHERE enabled = TRUE"
                    )).fetchall()
                    has_person_ids_col = False

                device_should_block: dict = {}

                for sched in schedules:
                    try:
                        if has_person_ids_col:
                            sched_id, mac, days, start, end, mac_addresses, sched_tags, person_id, person_ids = sched
                        else:
                            sched_id, mac, days, start, end, mac_addresses, sched_tags, person_id = sched
                            person_ids = []
                        active = _schedule_active_now(days, start, end)

                        target_macs = None

                        effective_pids = [str(p) for p in (person_ids or [])] if person_ids else []
                        if person_id and str(person_id) not in effective_pids:
                            effective_pids.append(str(person_id))

                        if effective_pids:
                            target_macs = []
                            for pid in effective_pids:
                                person_macs = db.execute(text(
                                    "SELECT mac_address FROM person_devices WHERE person_id::text = :pid"
                                ), {"pid": pid}).scalars().all()
                                target_macs.extend(person_macs)
                            target_macs = list(set(target_macs))
                            print(f"[sched] id={sched_id} persons={effective_pids} active={active} macs={target_macs}", flush=True)
                        elif mac_addresses:
                            target_macs = list(mac_addresses)
                        elif sched_tags:
                            tag_list = [t.strip().lower() for t in sched_tags.split(',') if t.strip()]
                            all_devices = db.execute(text(
                                "SELECT mac_address, tags FROM devices WHERE is_ignored = FALSE AND tags IS NOT NULL"
                            )).fetchall()
                            target_macs = []
                            for dev_mac, dev_tags in all_devices:
                                if dev_tags:
                                    dev_tag_list = [t.strip().lower() for t in dev_tags.split(',') if t.strip()]
                                    if any(t in dev_tag_list for t in tag_list):
                                        target_macs.append(dev_mac)
                        elif mac:
                            target_macs = [mac]

                        if target_macs is not None:
                            for m in target_macs:
                                if m not in device_should_block:
                                    device_should_block[m] = False
                                if active:
                                    device_should_block[m] = True
                        else:
                            all_macs = db.execute(text(
                                "SELECT mac_address FROM devices WHERE is_ignored = FALSE"
                            )).scalars().all()
                            for m in all_macs:
                                if m not in device_should_block:
                                    device_should_block[m] = False
                                if active:
                                    device_should_block[m] = True
                    except Exception as sched_exc:
                        print(f"[block_schedule_loop] schedule error id={sched[0] if sched else '?'}: {sched_exc}", flush=True)

                for mac, should_block in device_should_block.items():
                    try:
                        dev = db.execute(text(
                            "SELECT is_blocked, is_schedule_blocked, ip_address FROM devices WHERE mac_address = :mac"
                        ), {"mac": mac}).fetchone()
                        if not dev:
                            continue
                        is_blocked, is_sched_blocked, ip = dev

                        if should_block and not is_sched_blocked:
                            print(f"[sched] blocking {mac} ({ip}) via schedule", flush=True)
                            await _execute_block_bg(mac, ip, "block")
                            db.execute(text(
                                "UPDATE devices SET is_blocked = TRUE, is_schedule_blocked = TRUE WHERE mac_address = :mac"
                            ), {"mac": mac})
                            _add_event(db, mac, "blocked", {"ip": ip, "reason": "schedule"})
                            asyncio.ensure_future(_state._plugin_event_bus.notify("device.blocked", {"mac": mac, "ip": ip or ""}))

                        elif not should_block and is_sched_blocked:
                            print(f"[sched] unblocking {mac} ({ip}) schedule ended", flush=True)
                            await _execute_block_bg(mac, ip, "unblock")
                            db.execute(text(
                                "UPDATE devices SET is_blocked = FALSE, is_schedule_blocked = FALSE WHERE mac_address = :mac"
                            ), {"mac": mac})
                            _add_event(db, mac, "unblocked", {"ip": ip, "reason": "schedule_end"})
                            asyncio.ensure_future(_state._plugin_event_bus.notify("device.unblocked", {"mac": mac, "ip": ip or ""}))
                    except Exception as mac_exc:
                        print(f"[block_schedule_loop] apply error {mac}: {mac_exc}", flush=True)

                db.commit()
            finally:
                db.close()
        except Exception as exc:
            print(f"[block_schedule_loop] outer error: {exc}", flush=True)

        await asyncio.sleep(60)


# ---------------------------------------------------------------------------
# Trivy DB helpers
# ---------------------------------------------------------------------------
_TRIVY_DB_META = "/root/.cache/trivy/db/metadata.json"
_TRIVY_FREQ_SECONDS = {"1d": 86400, "2d": 172800, "7d": 604800, "30d": 2592000}
_trivy_db_update_lock = asyncio.Lock()

_container_vuln_scans: dict = {}


def _trivy_db_status() -> dict:
    try:
        with open(_TRIVY_DB_META) as f:
            meta = json.load(f)
        return {
            "exists":        True,
            "updated_at":    meta.get("UpdatedAt"),
            "next_update":   meta.get("NextUpdate"),
            "downloaded_at": meta.get("DownloadedAt"),
        }
    except Exception:
        return {"exists": False, "updated_at": None, "next_update": None, "downloaded_at": None}


async def _run_trivy_db_download():
    if _trivy_db_update_lock.locked() or not shutil.which("trivy"):
        return
    async with _trivy_db_update_lock:
        try:
            proc = await asyncio.create_subprocess_exec(
                "trivy", "image", "--download-db-only",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            if proc.stdout:
                async for raw in proc.stdout:
                    line = raw.decode(errors="replace").rstrip()
                    if line:
                        print(f"[trivy_db] {line}", flush=True)
            await proc.wait()
            if proc.returncode == 0:
                print("[trivy_db] Vulnerability DB updated.", flush=True)
            else:
                print(f"[trivy_db] Update exited with code {proc.returncode}.", flush=True)
        except Exception as exc:
            print(f"[trivy_db] Update failed: {exc}", flush=True)


def _schedule_trivy_db_download_if_missing():
    if not _trivy_db_status()["exists"] and shutil.which("trivy"):
        asyncio.ensure_future(_run_trivy_db_download())


async def _trivy_db_update_loop():
    await asyncio.sleep(60)
    if not _trivy_db_status()["exists"] and shutil.which("trivy"):
        print("[trivy_db] DB not found — downloading now.", flush=True)
        await _run_trivy_db_download()
    while True:
        db = SessionLocal()
        try:
            s = db.get(Setting, "trivy_db_update_frequency")
            freq = s.value.strip() if s and s.value else "1d"
        except Exception:
            freq = "1d"
        finally:
            db.close()

        interval = _TRIVY_FREQ_SECONDS.get(freq, 0)
        if interval > 0 and shutil.which("trivy"):
            await _run_trivy_db_download()

        await asyncio.sleep(interval if interval > 0 else 86400)


# ---------------------------------------------------------------------------
# Container Trivy scanning helpers
# ---------------------------------------------------------------------------
def _save_trivy_result(name: str, image: str, vulns: list, scanned_at: str, image_id: str | None = None):
    from sqlalchemy import text
    try:
        db = SessionLocal()
        db.execute(text("""
            INSERT INTO container_vuln_results (name, image, image_id, vulns, scanned_at)
            VALUES (:name, :image, :image_id, cast(:vulns as jsonb), :scanned_at)
            ON CONFLICT (name) DO UPDATE
                SET image = EXCLUDED.image,
                    image_id = EXCLUDED.image_id,
                    vulns = EXCLUDED.vulns,
                    scanned_at = EXCLUDED.scanned_at
        """), {
            "name": name,
            "image": image,
            "image_id": image_id,
            "vulns": json.dumps(vulns),
            "scanned_at": scanned_at,
        })
        db.commit()
    except Exception as e:
        print(f"[trivy] DB save failed for {name}: {e}", flush=True)
    finally:
        db.close()


def _run_trivy_for_container(name: str, image: str, image_id: str | None = None):
    from notifications_core import _notification_dispatch
    import state as _state
    _container_vuln_scans[name] = {"scanning": True, "image": image}
    try:
        result = run_trivy_image_scan_sync(image)
        if not result.get("ok"):
            _container_vuln_scans[name]["error"] = result.get("error")
            print(f"[trivy] {name}: {result.get('error')}", flush=True)
            return
        vulns = result.get("vulns") or []
        _save_trivy_result(name, image, vulns, result["scanned_at"], image_id=image_id)
        if vulns and _state._main_loop and not _state._main_loop.is_closed():
            severities = {v.get("severity", "").upper() for v in vulns}
            if "CRITICAL" in severities:
                crit = sum(1 for v in vulns if v.get("severity", "").upper() == "CRITICAL")
                asyncio.run_coroutine_threadsafe(
                    _notification_dispatch("container.vuln_critical", "Container Critical Vulnerability",
                                           f"{name}: {crit} critical vulnerability/ies found"),
                    _state._main_loop,
                )
            elif "HIGH" in severities:
                high = sum(1 for v in vulns if v.get("severity", "").upper() == "HIGH")
                asyncio.run_coroutine_threadsafe(
                    _notification_dispatch("container.vuln_high", "Container High Vulnerability",
                                           f"{name}: {high} high-severity vulnerability/ies found"),
                    _state._main_loop,
                )
    except Exception as exc:
        print(f"[trivy] {name}: {exc}", flush=True)
    finally:
        _container_vuln_scans[name]["scanning"] = False


def _run_trivy_for_live_container(name: str, host_url: str):
    from container_updates import _container_image_ref
    from routes.docker import _make_docker_client

    client = _make_docker_client(host_url)
    try:
        container = client.containers.get(name)
        _run_trivy_for_container(
            container.name.lstrip("/"),
            _container_image_ref(container),
            image_id=getattr(container.image, "id", None),
        )
    finally:
        client.close()


def _record_container_event(name: str, status: str):
    from sqlalchemy import text
    try:
        db = SessionLocal()
        db.execute(text("INSERT INTO container_events (name, status) VALUES (:n, :s)"),
                   {"n": name, "s": status})
        db.commit()
    except Exception as e:
        print(f"[container_events] DB write failed: {e}", flush=True)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Docker event watcher
# ---------------------------------------------------------------------------
async def _docker_event_loop():
    await asyncio.sleep(45)
    while True:
        from routes.docker import (
            _docker_enabled, _get_enabled_hosts, _get_docker_host,
            _make_docker_client,
        )
        import state as _state
        from notifications_core import _notification_dispatch

        db = SessionLocal()
        try:
            enabled = _docker_enabled(db)
            scan_on_new    = db.get(Setting, "docker_scan_on_new")
            scan_on_update = db.get(Setting, "docker_scan_on_update")
            do_new    = enabled and scan_on_new    and scan_on_new.value    == "true"
            do_update = enabled and scan_on_update and scan_on_update.value == "true"
            if enabled:
                docker_hosts = [h for h in _get_enabled_hosts(db) if h["type"] != "proxmox"]
                host = docker_hosts[0]["url"] if docker_hosts else _get_docker_host(db)
            else:
                host = None
        except Exception:
            enabled = False
            host = None
            do_new = do_update = False
        finally:
            db.close()

        if not enabled:
            await asyncio.sleep(30)
            continue

        try:
            def _watch():
                client = _make_docker_client(host)
                seen_images: dict = {}
                try:
                    for c in client.containers.list(all=True):
                        cname = c.name.lstrip("/")
                        seen_images[cname] = c.image.tags[0] if c.image.tags else c.image.id
                except Exception:
                    pass

                try:
                    for event in client.events(decode=True):
                        action = event.get("Action", "")
                        actor  = event.get("Actor", {})
                        attrs  = actor.get("Attributes", {})
                        cname  = attrs.get("name", "")
                        image  = attrs.get("image", "")

                        if action == "start":
                            threading.Thread(target=_record_container_event,
                                             args=(cname, "running"), daemon=True).start()
                        elif action in ("die", "stop", "kill", "pause"):
                            status = "paused" if action == "pause" else "stopped"
                            threading.Thread(target=_record_container_event,
                                             args=(cname, status), daemon=True).start()
                            if action == "die":
                                exit_code = attrs.get("exitCode", "0")
                                if exit_code != "0" and _state._main_loop and not _state._main_loop.is_closed():
                                    asyncio.run_coroutine_threadsafe(
                                        _notification_dispatch(
                                            "container.crashed", "Container Crashed",
                                            f"Container {cname!r} exited with code {exit_code}",
                                        ),
                                        _state._main_loop,
                                    )

                        if action == "create" and do_new:
                            threading.Thread(target=_run_trivy_for_live_container,
                                             args=(cname, host), daemon=True).start()
                        elif action == "start" and do_update:
                            prev = seen_images.get(cname)
                            if prev and prev != image:
                                threading.Thread(target=_run_trivy_for_live_container,
                                                 args=(cname, host), daemon=True).start()

                        if action in ("create", "start"):
                            seen_images[cname] = image
                except Exception:
                    pass
                finally:
                    client.close()

            await asyncio.to_thread(_watch)
        except Exception as e:
            print(f"[docker_events] {e}", flush=True)

        await asyncio.sleep(10)


# ---------------------------------------------------------------------------
# Traffic flush + notifications
# ---------------------------------------------------------------------------
async def _check_traffic_notifications(sessions: list):
    from notifications_core import _notification_dispatch
    import state as _state
    db = SessionLocal()
    try:
        susp_s = db.get(Setting, "traffic_suspicious_countries")
        susp_countries = {c.strip().upper() for c in (susp_s.value or "").split(",") if c.strip()} if susp_s else set()
    finally:
        db.close()

    now = datetime.now(timezone.utc)
    COOLDOWN = 86400

    for session in sessions:
        mac = session.get("mac", "").lower()
        if not mac:
            continue
        for bucket in session.get("history", []):
            unusual_ports = bucket.get("unusual_ports") or []
            if unusual_ports:
                key = (mac, "traffic.unusual_port")
                last = _state._traffic_notif_cooldowns.get(key)
                if last is None or (now - last).total_seconds() > COOLDOWN:
                    _state._traffic_notif_cooldowns[key] = now
                    ports_str = ", ".join(str(p) for p in unusual_ports[:5])
                    asyncio.ensure_future(_notification_dispatch(
                        "traffic.unusual_port", "Unusual Traffic Pattern",
                        f"Device {mac}: traffic on unusual ports ({ports_str})",
                    ))
                break

            if susp_countries:
                top_countries = bucket.get("top_countries") or {}
                if isinstance(top_countries, str):
                    try:
                        top_countries = json.loads(top_countries)
                    except Exception:
                        top_countries = {}
                flagged = [c for c in top_countries if c.upper() in susp_countries]
                if flagged:
                    key = (mac, "traffic.suspicious_country")
                    last = _state._traffic_notif_cooldowns.get(key)
                    if last is None or (now - last).total_seconds() > COOLDOWN:
                        _state._traffic_notif_cooldowns[key] = now
                        asyncio.ensure_future(_notification_dispatch(
                            "traffic.suspicious_country", "Suspicious Country Traffic",
                            f"Device {mac}: traffic detected to {', '.join(flagged)}",
                        ))
                    break


def _flush_traffic_sessions(db, sessions: list) -> None:
    from sqlalchemy import text
    for s in sessions:
        mac = s.get("mac", "").lower()
        ip  = s.get("target_ip")
        if not mac:
            continue
        history = s.get("history", [])
        if not history:
            continue
        ts_candidates = []
        for bucket in history:
            ts_str = bucket.get("ts")
            if not ts_str:
                continue
            try:
                ts_candidates.append((datetime.fromisoformat(ts_str), bucket))
            except Exception:
                continue
        if not ts_candidates:
            continue
        existing_ts = set()
        try:
            rows = db.execute(
                text("SELECT bucket_ts FROM traffic_stats WHERE mac_address=:mac AND bucket_ts = ANY(:ts)"),
                {"mac": mac, "ts": [t for t, _ in ts_candidates]},
            ).fetchall()
            existing_ts = {r[0] for r in rows}
        except Exception:
            pass
        for bucket in history:
            ts_str = bucket.get("ts")
            if not ts_str:
                continue
            try:
                ts = datetime.fromisoformat(ts_str)
            except Exception:
                continue
            ts_key = ts.replace(tzinfo=None) if ts.tzinfo else ts
            if any(
                (e.replace(tzinfo=None) if hasattr(e, 'replace') else e) == ts_key
                for e in existing_ts
            ):
                continue
            row = TrafficStat(
                mac_address   = mac,
                ip_address    = ip,
                bucket_ts     = ts,
                bytes_in      = bucket.get("bytes_in", 0),
                bytes_out     = bucket.get("bytes_out", 0),
                packets_in    = bucket.get("packets_in", 0),
                packets_out   = bucket.get("packets_out", 0),
                lan_bytes     = bucket.get("lan_bytes", 0),
                wan_bytes     = bucket.get("wan_bytes", 0),
                dns_queries   = bucket.get("dns_queries"),
                tls_sni       = bucket.get("tls_sni"),
                http_hosts    = bucket.get("http_hosts"),
                top_ips       = bucket.get("top_ips"),
                top_ports     = bucket.get("top_ports"),
                top_countries = bucket.get("top_countries"),
                protocols     = bucket.get("protocols"),
                unusual_ports = bucket.get("unusual_ports"),
            )
            db.add(row)
    db.commit()


async def _traffic_flush_loop():
    from sqlalchemy import text
    await asyncio.sleep(60)
    while True:
        try:
            async with _probe_client(timeout=10.0) as client:
                resp = await client.get(f"{PROBE_URL}/traffic/stats")
                if resp.status_code == 200:
                    data = resp.json()
                    sessions = data.get("sessions", [])
                    if sessions:
                        db = SessionLocal()
                        try:
                            _flush_traffic_sessions(db, sessions)
                        finally:
                            db.close()
                        await _check_traffic_notifications(sessions)
        except httpx.ConnectError:
            pass
        except Exception as exc:
            print(f"[traffic_flush] error: {exc}", flush=True)

        try:
            db = SessionLocal()
            try:
                ret_s = db.get(Setting, "traffic_retention_days")
                days  = int(ret_s.value) if ret_s else 30
                cutoff = datetime.now(timezone.utc) - timedelta(days=days)
                db.execute(text("DELETE FROM traffic_stats WHERE created_at < :cutoff"), {"cutoff": cutoff})
                db.commit()
            finally:
                db.close()
        except Exception as exc:
            print(f"[traffic_flush] retention cleanup error: {exc}", flush=True)

        await asyncio.sleep(300)


# ---------------------------------------------------------------------------
# Speedtest schedule
# ---------------------------------------------------------------------------
_last_speedtest_slot: datetime | None = None
_SPEEDTEST_EPOCH = datetime(2020, 1, 1, tzinfo=timezone.utc)


def _speedtest_current_slot(interval_s: int) -> datetime:
    elapsed = (datetime.now(timezone.utc) - _SPEEDTEST_EPOCH).total_seconds()
    return _SPEEDTEST_EPOCH + timedelta(seconds=int(elapsed // interval_s) * interval_s)


async def _run_speedtest_and_save():
    from sqlalchemy import text
    from notifications_core import _notification_dispatch
    try:
        result: dict = {}
        raw_lines: list[str] = []
        async with _probe_client(timeout=180) as client:
            async with client.stream("GET", f"{PROBE_URL}/stream/tools/speedtest") as resp:
                async for line in resp.aiter_lines():
                    if line.startswith("data: RESULT:"):
                        result = json.loads(line[len("data: RESULT:"):])
                    elif line.startswith("data: "):
                        raw_lines.append(line[6:])
        if result.get("download_mbps") is not None or result.get("upload_mbps") is not None:
            db = SessionLocal()
            try:
                db.execute(text(
                    "INSERT INTO speedtest_results (server, ping_ms, download_mbps, upload_mbps, raw_output) "
                    "VALUES (:server, :ping, :dl, :ul, :raw)"
                ), {
                    "server": result.get("server"),
                    "ping":   result.get("ping_ms"),
                    "dl":     result.get("download_mbps"),
                    "ul":     result.get("upload_mbps"),
                    "raw":    "\n".join(raw_lines),
                })
                db.commit()
            finally:
                db.close()
            print(f"[speedtest] completed — DL: {result.get('download_mbps')} Mbps, UL: {result.get('upload_mbps')} Mbps", flush=True)
            dl = result.get("download_mbps")
            if dl is not None:
                db2 = SessionLocal()
                try:
                    exp_s = db2.get(Setting, "speedtest_expected_download")
                    thr_s = db2.get(Setting, "speedtest_alert_threshold")
                    exp_dl    = float(exp_s.value) if exp_s and exp_s.value else 0.0
                    threshold = float(thr_s.value) if thr_s and thr_s.value else 80.0
                finally:
                    db2.close()
                if exp_dl > 0 and dl < exp_dl * threshold / 100:
                    pct = int(dl / exp_dl * 100)
                    asyncio.ensure_future(_notification_dispatch(
                        "speedtest.degraded_download", "Download Speed Degraded",
                        f"Download {dl:.1f} Mbps is {pct}% of expected {exp_dl:.0f} Mbps",
                    ))
    except Exception as exc:
        print(f"[speedtest] scheduled run error: {exc}", flush=True)


async def _speedtest_schedule_loop():
    global _last_speedtest_slot
    await asyncio.sleep(120)
    INTERVALS = {"30m": 1800, "1h": 3600, "6h": 21600, "24h": 86400}
    while True:
        try:
            db = SessionLocal()
            try:
                sched_s = db.get(Setting, "speedtest_schedule")
                sched   = sched_s.value if sched_s else "disabled"
            finally:
                db.close()
            interval = INTERVALS.get(sched)
            if interval:
                slot = _speedtest_current_slot(interval)
                if _last_speedtest_slot is None:
                    _last_speedtest_slot = slot
                elif slot > _last_speedtest_slot:
                    await _run_speedtest_and_save()
                    _last_speedtest_slot = slot
        except Exception as exc:
            print(f"[speedtest] schedule loop error: {exc}", flush=True)
        await asyncio.sleep(300)


# ---------------------------------------------------------------------------
# Appliance auto-update
# ---------------------------------------------------------------------------
_auto_update_running = False
_APPLIANCE_JSON_PATH = "/opt/inspectre/appliance.json"


def _is_appliance() -> bool:
    return os.path.exists(_APPLIANCE_JSON_PATH)


def _read_appliance_meta() -> dict:
    try:
        with open(_APPLIANCE_JSON_PATH) as f:
            return json.loads(f.read())
    except Exception:
        return {}


def _do_appliance_update():
    try:
        import appliance_update as _au
        client  = _au.make_client()
        results = {}
        for name in _au.NON_SELF_CONTAINERS:
            try:
                results[name] = _au.update_container(client, name)
            except Exception as exc:
                results[name] = {"name": name, "error": str(exc)}
        try:
            updater_img = "thefunkygibbon/inspectre-web:latest"
            client.containers.run(
                updater_img,
                command=["python", "-m", "appliance_update"],
                name=_au.UPDATER_CONTAINER,
                detach=True,
                remove=True,
                volumes={"/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "rw"}},
                environment={"DATABASE_URL": os.environ.get("DATABASE_URL", "")},
            )
            results[_au.WEB_CONTAINER] = {"name": _au.WEB_CONTAINER, "triggered": True}
        except Exception as exc:
            results[_au.WEB_CONTAINER] = {"name": _au.WEB_CONTAINER, "self_update_error": str(exc)}
        _au.write_status("ok", results)
        print(f"[auto-update] complete: {results}", flush=True)
    except Exception as exc:
        print(f"[auto-update] FAILED: {exc}", flush=True)
        try:
            import appliance_update as _au
            _au.write_status("error", {"error": str(exc)})
        except Exception:
            pass


async def _run_appliance_update_task():
    global _auto_update_running
    if _auto_update_running:
        return
    _auto_update_running = True
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _do_appliance_update)
    finally:
        _auto_update_running = False


async def _auto_update_schedule_loop():
    await asyncio.sleep(60)
    last_run_date = None
    while True:
        try:
            if _is_appliance():
                db = SessionLocal()
                try:
                    def _s(key, default=""):
                        row = db.get(Setting, key)
                        return row.value if row else default
                    enabled  = _s("auto_update_enabled", "false") == "true"
                    hour     = int(_s("auto_update_hour", "3"))
                    days_raw = _s("auto_update_days", "[]")
                    try:
                        days = json.loads(days_raw)
                    except Exception:
                        days = []
                finally:
                    db.close()

                if enabled:
                    now      = datetime.now(timezone.utc)
                    today    = now.weekday()
                    js_dow   = (today + 1) % 7
                    right_hour  = now.hour == hour
                    right_day   = not days or js_dow in days
                    already_ran = last_run_date == now.date()
                    if right_hour and right_day and not already_ran and not _auto_update_running:
                        last_run_date = now.date()
                        asyncio.ensure_future(_run_appliance_update_task())
        except Exception as exc:
            print(f"[auto-update-scheduler] error: {exc}", flush=True)
        await asyncio.sleep(300)
