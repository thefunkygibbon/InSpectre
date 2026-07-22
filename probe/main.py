import signal
import sys
import threading
import time
import uuid as _uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

import probe_config as _cfg
import traffic_monitor as _tm
from probe_config import VERSION
from probe_models import Session, Device, _sniffer_seen_lock, _sniffer_seen_this_interval
from probe_db import wait_for_db, init_db
from probe_hostname import _load_mac_vendor_db, _detect_dns_server
from probe_fingerprint import _run_nerva_fingerprint, _nuclei_template_update_loop
from probe_grouping import _hostname_base, _is_generic_hostname, retroactive_auto_group
from probe_scanner import arp_scan, trigger_deep_scan
from probe_device import (
    refresh_missing_vendors, refresh_missing_hostnames,
    update_presence_from_sweep, upsert_seen_device,
)
from probe_sniffer import start_arp_sniffer
from probe_mdns import _mdns_loop, _mdns_passive_listener
from probe_ssdp import _ssdp_passive_listener
from probe_routes import start_probe_api


# ---------------------------------------------------------------------------
# Startup Nerva backfill
# ---------------------------------------------------------------------------
def _startup_nerva_backfill() -> None:
    """Re-fingerprint devices whose services are empty AND whose last deep scan
    was more than 24 hours ago (or never ran). Prevents re-running Nerva on
    every container restart for recently-scanned devices. Uses current
    ip_address, not historical primary_ip."""
    time.sleep(15)
    now = datetime.now(timezone.utc)
    backfill_threshold = now - timedelta(hours=24)
    active = {t.name for t in threading.enumerate()}
    _nerva_backfill_sem = threading.Semaphore(3)

    def _run_limited(scan_ip, mac, ports):
        with _nerva_backfill_sem:
            _run_nerva_fingerprint(scan_ip, mac, ports)

    session = Session()
    count = 0
    try:
        devices = session.query(Device).filter(Device.deep_scanned == True).all()
        for dev in devices:
            sr = dev.scan_results or {}
            pipeline_stage = sr.get("pipeline_stage")
            services = sr.get("services")

            needs_backfill = (
                pipeline_stage in ("services_done", "ports_done")
                and not services
                and sr.get("open_ports")
            )
            if not needs_backfill:
                continue

            last_run = dev.deep_scan_last_run
            if last_run is not None and last_run > backfill_threshold:
                print(
                    f"[nerva] Backfill skipped (cooldown): {dev.mac_address} "
                    f"last scanned {(now - last_run).total_seconds() / 3600:.1f}h ago",
                    flush=True,
                )
                continue

            if (f"nerva-{dev.mac_address}" in active or
                    f"nerva-backfill-{dev.mac_address}" in active):
                continue

            ports = [p["port"] for p in sr["open_ports"] if isinstance(p.get("port"), int)]
            if not ports:
                continue

            scan_ip = dev.ip_address or dev.primary_ip
            if not _cfg._is_valid_ip(scan_ip):
                continue

            threading.Thread(
                target=_run_limited,
                args=(scan_ip, dev.mac_address, ports),
                daemon=True,
                name=f"nerva-backfill-{dev.mac_address}",
            ).start()
            count += 1
            print(f"[nerva] Backfill queued: {scan_ip} ({dev.mac_address}), {len(ports)} port(s)", flush=True)
    except Exception as e:
        print(f"[nerva] Backfill query error: {e}", flush=True)
    finally:
        session.close()
    print(f"[nerva] Backfill: {count} device(s) queued for re-fingerprint", flush=True)


# ---------------------------------------------------------------------------
# Hostname group backfill (runs once at startup)
# ---------------------------------------------------------------------------
def _backfill_hostname_groups() -> None:
    """Group already-stored devices that share a base DNS hostname but have no
    group yet. Only matches on resolved DNS hostname (never DHCP hostname) to
    avoid merging unrelated devices."""
    if not _cfg.AUTO_GROUP_BY_HOSTNAME:
        return
    sess = Session()
    try:
        rows = sess.execute(text("""
            SELECT mac_address, hostname, dhcp_hostname, group_id, group_primary, is_online, last_seen, group_manual
            FROM devices
            WHERE hostname IS NOT NULL AND hostname != ''
        """)).fetchall()

        base_map: dict[str, list] = {}
        for row in rows:
            mac, hn, dhcp_hn, gid, gprimary, online, last_seen, gmanual = row
            if gmanual:
                continue
            base = _hostname_base(hn or '')
            if not base or _is_generic_hostname(base):
                continue
            base_map.setdefault(base, []).append({
                "mac": mac, "group_id": gid, "group_primary": bool(gprimary),
                "is_online": bool(online), "last_seen": last_seen,
            })

        assigned = 0
        for base, devs in base_map.items():
            if len(devs) < 2:
                continue
            gids = [str(d["group_id"]) for d in devs if d["group_id"]]
            if len(gids) == len(devs) and len(set(gids)) == 1:
                continue

            new_gid = gids[0] if gids else str(_uuid.uuid4())

            online_devs = [d for d in devs if d["is_online"]]
            if len(online_devs) == 1:
                primary_mac = online_devs[0]["mac"]
            else:
                primary_mac = max(
                    devs,
                    key=lambda d: d["last_seen"] or datetime.min.replace(tzinfo=timezone.utc),
                )["mac"]

            for d in devs:
                want_primary = (d["mac"] == primary_mac)
                if (d["group_id"] and str(d["group_id"]) == new_gid
                        and d["group_primary"] == want_primary):
                    continue
                sess.execute(
                    text("UPDATE devices SET group_id = :gid, group_primary = :pri WHERE mac_address = :mac"),
                    {"gid": new_gid, "pri": want_primary, "mac": d["mac"]},
                )
                assigned += 1

        if assigned:
            sess.commit()
            print(f"[grouping] Backfill: grouped {assigned} device(s) by base hostname", flush=True)
        else:
            print("[grouping] Backfill: no ungrouped hostname matches found", flush=True)
    except Exception as exc:
        sess.rollback()
        print(f"[grouping] Backfill error: {exc}", flush=True)
    finally:
        sess.close()


def _cleanup_bad_hostname_groups() -> None:
    """One-shot repair for groups created by over-eager grouping logic that
    merged devices on DHCP-hostname coincidence. Splits any group whose members
    have conflicting DNS hostnames; re-forms groups only where >=2 devices
    genuinely share a DNS base."""
    sess = Session()
    try:
        rows = sess.execute(text("""
            SELECT mac_address, hostname, group_id, group_manual
            FROM devices
            WHERE group_id IS NOT NULL
        """)).fetchall()

        groups: dict[str, list] = {}
        group_is_manual: dict[str, bool] = {}
        for mac, hn, gid, gmanual in rows:
            key = str(gid)
            groups.setdefault(key, []).append({"mac": mac, "hostname": hn})
            if gmanual:
                group_is_manual[key] = True

        repaired = 0
        for gid, members in groups.items():
            if len(members) < 2:
                continue
            if group_is_manual.get(gid):
                continue
            bases = {}
            for m in members:
                base = _hostname_base(m["hostname"] or "")
                if base and not _is_generic_hostname(base):
                    bases.setdefault(base, []).append(m["mac"])

            if len(bases) == 1:
                continue

            for m in members:
                sess.execute(text(
                    "UPDATE devices SET group_id = NULL, group_primary = false WHERE mac_address = :mac"
                ), {"mac": m["mac"]})
                repaired += 1

            for base, macs in bases.items():
                if len(macs) < 2:
                    continue
                new_gid = str(_uuid.uuid4())
                for i, mac in enumerate(macs):
                    sess.execute(text(
                        "UPDATE devices SET group_id = :gid, group_primary = :pri WHERE mac_address = :mac"
                    ), {"gid": new_gid, "pri": i == 0, "mac": mac})

        if repaired:
            sess.commit()
            print(f"[grouping] Cleanup: dissolved/repaired {repaired} mis-grouped device(s)", flush=True)
        else:
            print("[grouping] Cleanup: no bad hostname groups found", flush=True)
    except Exception as exc:
        sess.rollback()
        print(f"[grouping] Cleanup error: {exc}", flush=True)
    finally:
        sess.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def _graceful_shutdown(signum, frame) -> None:
    """SIGTERM/SIGINT handler. Stops all active traffic monitor sessions and
    waits for ARP restore threads before exit so monitored devices are not left
    with poisoned ARP caches. Docker sends SIGTERM and waits 10 s before SIGKILL."""
    print("[*] Received shutdown signal — restoring ARP tables for all active monitors...", flush=True)
    _tm.stop_all_and_wait(timeout=5.0)
    print("[*] All traffic monitors cleaned up — exiting.", flush=True)
    sys.exit(0)


def main() -> None:
    signal.signal(signal.SIGTERM, _graceful_shutdown)
    signal.signal(signal.SIGINT,  _graceful_shutdown)

    print(f"[*] InSpectre Probe v{VERSION} starting...", flush=True)
    _load_mac_vendor_db()
    wait_for_db()
    init_db()
    _cfg._load_settings_from_db()
    threading.Thread(target=refresh_missing_vendors, daemon=True, name="vendor-refresh").start()
    threading.Thread(target=_startup_nerva_backfill, daemon=True, name="nerva-backfill").start()

    def _group_maintenance():
        _cleanup_bad_hostname_groups()
        _backfill_hostname_groups()
    threading.Thread(target=_group_maintenance, daemon=True, name="group-backfill").start()

    print(
        f"[*] Scanning {_cfg.IP_RANGE} on {_cfg.INTERFACE} every {_cfg.SCAN_INTERVAL}s\n"
        f"[*] Offline threshold: {_cfg.OFFLINE_MISS_THRESHOLD} missed sweeps | "
        f"OS confidence: {_cfg.OS_CONFIDENCE_THRESHOLD}%",
        flush=True,
    )

    _cfg._DNS_SERVER   = _detect_dns_server()
    _cfg._DNS_DETECTED = True
    print(f"[*] DNS server: {_cfg._DNS_SERVER or 'NOT DETECTED — set LAN_DNS_SERVER in docker-compose!'}", flush=True)

    threading.Thread(target=start_probe_api,              daemon=True, name="probe-api").start()
    threading.Thread(target=_nuclei_template_update_loop, daemon=True, name="nuclei-updater").start()
    time.sleep(2)

    _background_started = False

    while True:
        _cfg._load_settings_from_db()

        try:
            _chk = Session()
            try:
                _sc = _chk.execute(text("SELECT value FROM settings WHERE key='setup_complete'")).fetchone()
                _setup_done = _sc and _sc[0] == "true"
            finally:
                _chk.close()
        except Exception:
            _setup_done = False

        if not _setup_done:
            print("[*] Waiting for setup wizard to complete before scanning…", flush=True)
            time.sleep(10)
            continue

        if not _background_started:
            if _cfg.ENABLE_PASSIVE_SNIFFER:
                threading.Thread(target=start_arp_sniffer, daemon=True, name="arp-sniffer").start()
            if _cfg.ENABLE_MDNS:
                threading.Thread(target=_mdns_loop,             daemon=True, name="mdns-loop").start()
                threading.Thread(target=_mdns_passive_listener,  daemon=True, name="mdns-passive").start()
                threading.Thread(target=_ssdp_passive_listener,  daemon=True, name="ssdp-passive").start()
            _background_started = True

        with _sniffer_seen_lock:
            _sniffer_seen_this_interval.clear()

        session = Session()
        try:
            if _cfg.ENABLE_ARP_SWEEP:
                found = arp_scan(_cfg.INTERFACE, _cfg.IP_RANGE)
                active_macs: set[str] = set()
                for entry in found:
                    if upsert_seen_device(entry["mac"], entry["ip"], "sweep"):
                        active_macs.add(entry["mac"])
                update_presence_from_sweep(session, active_macs)
                session.commit()
                print(f"[*] Sweep done -- {len(active_macs)} online", flush=True)
            else:
                print("[*] ARP sweep disabled — skipping active sweep", flush=True)

            retroactive_auto_group()

            if _cfg.ENABLE_UNSCANNED_RETRY:
                unscanned = session.query(Device).filter(
                    Device.is_online    == True,
                    Device.deep_scanned == False,
                ).all()
                for dev in unscanned:
                    scan_ip = dev.primary_ip or dev.ip_address
                    if _cfg._is_valid_ip(scan_ip):
                        print(f"[scan] Retrying unscanned device: {scan_ip} ({dev.mac_address})", flush=True)
                        trigger_deep_scan(scan_ip, dev.mac_address)

            threading.Thread(target=refresh_missing_hostnames, daemon=True).start()

            if _cfg.ENABLE_NIGHTLY_SCAN:
                now_hour = datetime.now().hour
                if _cfg.NIGHTLY_SCAN_START <= now_hour < _cfg.NIGHTLY_SCAN_END:
                    nightly_threshold = datetime.now(timezone.utc) - timedelta(hours=23)
                    nightly_q = session.query(Device).filter(
                        Device.is_online    == True,
                        Device.deep_scanned == True,
                    ).all()
                    nightly_count = 0
                    for dev in nightly_q:
                        last_run = dev.deep_scan_last_run
                        if last_run is None or last_run < nightly_threshold:
                            scan_ip = dev.primary_ip or dev.ip_address
                            if _cfg._is_valid_ip(scan_ip):
                                print(f"[scan] Nightly rescan: {scan_ip} ({dev.mac_address})", flush=True)
                                trigger_deep_scan(scan_ip, dev.mac_address)
                                nightly_count += 1
                    if nightly_count:
                        print(f"[scan] Nightly window queued {nightly_count} rescan(s)", flush=True)
        except Exception as e:
            session.rollback()
            print(f"[!] Sweep error: {e}", flush=True)
        finally:
            session.close()
        time.sleep(_cfg.SCAN_INTERVAL)


if __name__ == "__main__":
    main()
