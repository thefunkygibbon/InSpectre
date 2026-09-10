import time
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm.attributes import flag_modified

import probe_config as _cfg
import dhcp_classify as _dhcp_cls
from probe_models import (
    Session, Device,
    _sniffer_seen_this_interval, _sniffer_seen_lock,
    _confirmed_offline_macs, _confirmed_offline_lock,
    _offline_at, _offline_lock,
    _pending_offline_events, _pending_offline_lock,
    _get_mac_lock,
    _store_pending_dhcp, _pop_pending_dhcp,
    _remember_name_source,
)
from probe_ip import record_ip, _primary_ip_is_stale, _write_event
from probe_hostname import resolve_hostname, lookup_vendor
from probe_grouping import _try_auto_group_by_hostname, _get_host_ipv4s, _is_generic_hostname
from probe_scanner import trigger_deep_scan
from presence_guard import is_locked_secondary_sighting, apply_secondary_ip_sighting


def _upsert_dhcp_info(
    mac: str,
    hostname: str | None,
    vendor_class: str | None,
    opt55: list[int] | None,
) -> None:
    """Write DHCP fingerprint data to the device row and optionally refine device_type."""
    fingerprint_str = ",".join(str(x) for x in opt55) if opt55 else None
    dtype, conf = _dhcp_cls.classify_from_dhcp(vendor_class, opt55)

    session = Session()
    try:
        device = session.get(Device, mac)
        if device is None:
            _store_pending_dhcp(mac, hostname, vendor_class, opt55)
            return

        changed = False
        hostname_updated = False

        if hostname:
            prior_dhcp_hostname = device.dhcp_hostname
            if device.dhcp_hostname != hostname:
                device.dhcp_hostname = hostname
                changed = True

            # Naming priority: manual name > non-generic DNS/mDNS name > DHCP-reported
            # hostname > other discovery methods > generic DNS name as a last resort.
            # DHCP hostnames are frequently auto-generated/generic (e.g. "android-1a2b3c")
            # and must never clobber a meaningful name already resolved from a
            # higher-priority source (rDNS, mDNS, a plugin, etc). Only let DHCP claim
            # the display hostname when there's nothing better in place yet, or when
            # the current name was itself only ever a DHCP-sourced/generic value.
            current_hn = device.hostname or ""
            should_replace = (
                not device.custom_name
                and hostname != current_hn
                and (
                    not current_hn
                    or _is_generic_hostname(current_hn)
                    or _cfg._is_ip_derived_hostname(current_hn)
                    or current_hn == prior_dhcp_hostname
                )
            )
            if should_replace:
                conflict = session.query(Device).filter(
                    Device.hostname == hostname,
                    Device.mac_address != mac,
                ).first()
                if not conflict:
                    device.hostname = hostname
                    changed = True
                    hostname_updated = True
                    if current_hn:
                        print(f"[dhcp] {mac}: hostname {current_hn!r} → {hostname!r} (DHCP name applied — no stronger name available)", flush=True)

        if vendor_class and device.dhcp_vendor_class != vendor_class:
            device.dhcp_vendor_class = vendor_class
            changed = True

        if fingerprint_str and device.dhcp_fingerprint != fingerprint_str:
            device.dhcp_fingerprint = fingerprint_str
            changed = True

        if dtype != "unknown" and conf >= 0.75 and not device.device_type_override:
            current_sr_type = (device.scan_results or {}).get("device_type")
            if current_sr_type != dtype:
                sr = dict(device.scan_results or {})
                sr["device_type"]        = dtype
                sr["device_type_source"] = "dhcp"
                sr["device_type_conf"]   = conf
                device.scan_results = sr
                flag_modified(device, "scan_results")
                changed = True

        if changed:
            session.commit()
            dtype_msg = f"  → type={dtype}({conf:.0%})" if dtype != "unknown" else ""
            print(f"[dhcp] saved {mac}  vc={vendor_class!r}  host={hostname!r}{dtype_msg}", flush=True)
            if hostname_updated and hostname and not _is_generic_hostname(hostname):
                _try_auto_group_by_hostname(mac, hostname)
    except Exception as exc:
        session.rollback()
        print(f"[dhcp-worker] DB error for {mac}: {exc}", flush=True)
    finally:
        session.close()


def upsert_seen_device(mac: str, ip: str, source: str) -> bool:
    if not mac or mac == "00:00:00:00:00:00":
        return False
    if not _cfg._is_valid_ip(ip):
        return False

    with _sniffer_seen_lock:
        _sniffer_seen_this_interval.add(mac)

    mac_lock = _get_mac_lock(mac)
    with mac_lock:
        now     = datetime.now(timezone.utc)
        session = Session()
        try:
            existing   = session.get(Device, mac)
            is_new     = existing is None
            old_ip     = None if is_new else (existing.ip_address or "")
            was_online = None if is_new else existing.is_online
            ip_changed = (not is_new) and (old_ip != ip)

            if not is_new and ip_changed:
                owner = session.execute(
                    text("SELECT mac_address FROM devices WHERE primary_ip = :ip AND mac_address != :mac"),
                    {"ip": ip, "mac": mac},
                ).fetchone()
                if owner:
                    print(f"[upsert] Skipping IP {ip} for {mac} — already primary IP of {owner[0]}", flush=True)
                    return False

            offline_duration_s = 0.0
            if not is_new and not was_online and existing.last_seen:
                offline_duration_s = (now - existing.last_seen).total_seconds()

            hostname_resolution_attempted = False
            if is_new:
                hostname = resolve_hostname(ip)
                hostname_resolution_attempted = True
                vendor   = lookup_vendor(mac)
            else:
                if existing.hostname:
                    hostname = existing.hostname
                else:
                    last_att = existing.hostname_last_attempted
                    cooldown_elapsed = (
                        last_att is None or
                        (now - last_att).total_seconds() >= _cfg.HOSTNAME_COOLDOWN_HOURS * 3600
                    )
                    if cooldown_elapsed:
                        hostname = resolve_hostname(ip)
                        hostname_resolution_attempted = True
                    else:
                        hostname = None
                vendor = existing.vendor

            hostname_val = hostname or ""

            _hostname_case = (
                "CASE WHEN devices.hostname IS NOT NULL AND devices.hostname != '' "
                "THEN devices.hostname ELSE EXCLUDED.hostname END"
            )
            if _cfg.PRIMARY_IP_MODE == "dynamic":
                _new_primary_ip_case = (
                    "CASE WHEN devices.primary_ip IS NOT NULL "
                    "THEN devices.primary_ip ELSE EXCLUDED.primary_ip END"
                )
                _existing_primary_ip_case = (
                    "CASE "
                    "WHEN devices.is_online = false THEN EXCLUDED.primary_ip "
                    "WHEN devices.primary_ip IS NOT NULL THEN devices.primary_ip "
                    "ELSE EXCLUDED.primary_ip END"
                )
            else:
                _new_primary_ip_case = (
                    "CASE WHEN devices.primary_ip_locked = true THEN devices.primary_ip "
                    "WHEN devices.primary_ip IS NOT NULL THEN devices.primary_ip "
                    "ELSE EXCLUDED.primary_ip END"
                )
                _existing_primary_ip_case = (
                    "CASE "
                    "WHEN devices.primary_ip_locked = true THEN devices.primary_ip "
                    "WHEN devices.is_online = false THEN EXCLUDED.primary_ip "
                    "WHEN devices.primary_ip IS NOT NULL THEN devices.primary_ip "
                    "ELSE EXCLUDED.primary_ip END"
                )

            if is_new:
                stmt = (
                    pg_insert(Device)
                    .values(
                        mac_address              = mac,
                        ip_address               = ip,
                        primary_ip               = ip,
                        hostname                 = hostname_val or None,
                        vendor                   = vendor,
                        custom_name              = None,
                        is_online                = True,
                        first_seen               = now,
                        last_seen                = now,
                        deep_scanned             = False,
                        miss_count               = 0,
                        is_important             = False,
                        hostname_last_attempted  = now,
                        baseline_scan_count      = 0,
                        status_changed_at        = now,
                        presence_last_seen_at    = now,
                    )
                    .on_conflict_do_update(
                        index_elements=["mac_address"],
                        set_=dict(
                            ip_address = text(
                                "CASE WHEN devices.primary_ip_locked "
                                "THEN devices.primary_ip ELSE :new_ip END"
                            ).bindparams(new_ip=ip),
                            primary_ip = text(_new_primary_ip_case),
                            is_online  = True,
                            last_seen  = text("CASE WHEN devices.is_online = false THEN NOW() ELSE devices.last_seen END"),
                            status_changed_at = text("CASE WHEN devices.is_online = false THEN NOW() ELSE devices.status_changed_at END"),
                            miss_count = 0,
                            hostname   = text(_hostname_case),
                            presence_last_seen_at = text("NOW()"),
                        ),
                    )
                )
            else:
                cur_primary = existing.primary_ip or old_ip
                locked      = bool(getattr(existing, "primary_ip_locked", False))
                try:
                    _lk = session.execute(
                        text("SELECT primary_ip, primary_ip_locked "
                             "FROM devices WHERE mac_address = :m FOR UPDATE"),
                        {"m": mac},
                    ).fetchone()
                    if _lk is not None:
                        if _lk[0]:
                            cur_primary = _lk[0]
                        locked = bool(_lk[1])
                except Exception as _e:
                    print(f"[upsert] lock re-read failed for {mac}: {_e}", flush=True)

                if is_locked_secondary_sighting(locked, cur_primary, ip):
                    new_scan = apply_secondary_ip_sighting(existing.scan_results, ip, source, now.isoformat())
                    if new_scan != (existing.scan_results or {}):
                        existing.scan_results = new_scan
                        flag_modified(existing, "scan_results")
                    session.commit()
                    with _sniffer_seen_lock:
                        _sniffer_seen_this_interval.discard(mac)
                    print(
                        f"[upsert] Locked secondary sighting for {mac}: {ip} (primary {cur_primary}) — metadata only",
                        flush=True,
                    )
                    return False

                if locked and cur_primary:
                    new_primary = cur_primary
                elif _cfg.PRIMARY_IP_MODE == "dynamic":
                    new_primary = ip if not was_online else (cur_primary or ip)
                elif not was_online:
                    new_primary = ip
                else:
                    new_primary = cur_primary or ip

                is_secondary_sighting = bool(was_online and ip != new_primary)
                if (is_secondary_sighting and not locked
                        and _primary_ip_is_stale(mac, new_primary)):
                    new_primary           = ip
                    is_secondary_sighting = False

                if locked and cur_primary:
                    ip_to_store = cur_primary
                else:
                    ip_to_store = new_primary if is_secondary_sighting else ip

                if ip != cur_primary:
                    print(
                        f"[upsert] {mac}: sighting {ip} differs from primary {cur_primary} "
                        f"(locked={locked}, was_online={was_online}, mode={_cfg.PRIMARY_IP_MODE}, "
                        f"new_primary={new_primary}, ip_to_store={ip_to_store}, source={source})",
                        flush=True,
                    )

                stmt = (
                    pg_insert(Device)
                    .values(
                        mac_address  = mac,
                        ip_address   = ip_to_store,
                        primary_ip   = existing.primary_ip or ip,
                        hostname     = hostname_val or None,
                        vendor       = vendor,
                        custom_name  = existing.custom_name,
                        is_online    = True,
                        first_seen   = existing.first_seen or now,
                        last_seen    = now,
                        deep_scanned = existing.deep_scanned,
                        miss_count   = 0,
                        is_important = existing.is_important,
                        status_changed_at     = existing.status_changed_at or now,
                        presence_last_seen_at = now,
                    )
                    .on_conflict_do_update(
                        index_elements=["mac_address"],
                        set_=dict(
                            ip_address = text(
                                "CASE WHEN devices.primary_ip_locked "
                                "THEN devices.primary_ip ELSE :computed_ip END"
                            ).bindparams(computed_ip=ip_to_store),
                            primary_ip = text(
                                "CASE WHEN devices.primary_ip_locked "
                                "THEN devices.primary_ip ELSE :computed_primary END"
                            ).bindparams(computed_primary=new_primary),
                            is_online  = True,
                            last_seen  = text("CASE WHEN devices.is_online = false THEN NOW() ELSE devices.last_seen END"),
                            status_changed_at = text("CASE WHEN devices.is_online = false THEN NOW() ELSE devices.status_changed_at END"),
                            miss_count = 0,
                            hostname   = text(_hostname_case),
                            presence_last_seen_at = text("NOW()"),
                        ),
                    )
                )

            session.execute(stmt)
            session.commit()

            if is_new:
                print(f"[+] New device via {source}: {ip} ({mac}) hostname={hostname} vendor={vendor}", flush=True)
                grouped = _try_auto_group_by_hostname(mac, hostname_val)
                _write_event(mac, "interface_joined" if grouped else "joined", {"ip": ip, "vendor": vendor or "Unknown"})
                _scan_ip = ip
                try:
                    _ns = Session()
                    try:
                        _nd = _ns.get(Device, mac)
                        if _nd and getattr(_nd, "primary_ip", None) and _cfg._is_valid_ip(_nd.primary_ip):
                            _scan_ip = _nd.primary_ip
                    finally:
                        _ns.close()
                except Exception:
                    pass
                trigger_deep_scan(_scan_ip, mac)
            else:
                if not was_online:
                    print(f"[~] Back online via {source}: {ip} ({mac})", flush=True)
                    with _confirmed_offline_lock:
                        _confirmed_offline_macs.discard(mac)
                    with _offline_lock:
                        _offline_at.pop(mac, None)
                    # If the offline event was still pending (not yet written), this was a
                    # brief flap — cancel the pending event and suppress the online event too,
                    # so neither appears in the timeline.
                    with _pending_offline_lock:
                        cancelled = _pending_offline_events.pop(mac, None)
                    if cancelled is None and not getattr(existing, "suppress_presence_events", False):
                        _write_event(mac, "online", {"ip": ip, "source": source})
                if ip_changed:
                    if is_secondary_sighting:
                        print(f"[~] Secondary IP {ip} for {mac} (primary stays {new_primary}, source={source})", flush=True)
                    elif new_primary != cur_primary:
                        print(f"[~] Primary IP {cur_primary} → {new_primary} for {mac} (source={source})", flush=True)
                        _write_event(mac, "primary_ip_changed", {"old_ip": cur_primary, "new_ip": new_primary})

        except Exception as e:
            session.rollback()
            print(f"[DB] Upsert error {mac}: {e}", flush=True)
            return False
        finally:
            session.close()

    pending_dhcp = _pop_pending_dhcp(mac)
    if pending_dhcp is not None:
        _upsert_dhcp_info(mac, pending_dhcp[0], pending_dhcp[1], pending_dhcp[2])

    sighting_counts_for_presence = True

    if hostname_resolution_attempted:
        sess_hn = Session()
        try:
            dev_hn = sess_hn.get(Device, mac)
            if dev_hn and hostname:
                _remember_name_source(dev_hn, "rdns_hostname", hostname)
            sess_hn.execute(
                text("UPDATE devices SET hostname_last_attempted = NOW() WHERE mac_address = :mac"),
                {"mac": mac},
            )
            sess_hn.commit()
        except Exception as e:
            sess_hn.rollback()
            print(f"[hostname] Failed to update hostname_last_attempted for {mac}: {e}", flush=True)
        finally:
            sess_hn.close()

    if not is_new and not was_online and offline_duration_s >= _cfg.OFFLINE_RESCAN_HOURS * 3600:
        sess_or = Session()
        try:
            dev_or = sess_or.get(Device, mac)
            if dev_or and dev_or.deep_scanned:
                print(
                    f"[scan] Device {ip} ({mac}) was offline {offline_duration_s/3600:.1f}h — "
                    "invalidating deep scan for rescan",
                    flush=True,
                )
                dev_or.deep_scanned = False
                dev_or.scan_results = None
                sess_or.commit()
        except Exception as e:
            sess_or.rollback()
            print(f"[DB] Offline-return rescan error {mac}: {e}", flush=True)
        finally:
            sess_or.close()

    if was_online is False and not is_new:
        _sr = Session()
        try:
            _dev_r = _sr.get(Device, mac)
            if _dev_r and not _dev_r.deep_scanned:
                trigger_deep_scan(_dev_r.primary_ip or ip, mac)
        except Exception:
            pass
        finally:
            _sr.close()

    is_brand_new_ip = record_ip(mac, ip, seen_while_online=bool(was_online and ip_changed))

    if ip_changed and is_brand_new_ip:
        session2 = Session()
        try:
            dev2 = session2.get(Device, mac)
            if dev2:
                scan_ip = dev2.primary_ip or ip
                if ip == scan_ip:
                    if dev2.deep_scanned:
                        print(f"[~] Primary IP changed {old_ip} -> {ip} for {mac} — invalidating deep scan", flush=True)
                        dev2.deep_scanned = False
                        dev2.scan_results = None
                        session2.commit()
                        trigger_deep_scan(scan_ip, mac)
                    else:
                        print(f"[~] Primary IP change for unscanned device {mac} — scan will use {scan_ip}", flush=True)
                else:
                    print(f"[~] Secondary IP {ip} recorded for {mac} — deep scan target remains {scan_ip}", flush=True)
        except Exception as e:
            session2.rollback()
            print(f"[DB] IP-change rescan error {mac}: {e}", flush=True)
        finally:
            session2.close()

    return sighting_counts_for_presence


def refresh_missing_vendors() -> None:
    from probe_hostname import lookup_vendor as _lookup
    from probe_hostname import _mac_vendor_db
    if not _mac_vendor_db:
        return
    session = Session()
    try:
        unvendored = session.query(Device).filter(
            (Device.vendor == None) | (Device.vendor == "Unknown")
        ).all()
        updated = 0
        for dev in unvendored:
            vendor = _lookup(dev.mac_address)
            if vendor and vendor != "Unknown":
                dev.vendor = vendor
                updated += 1
                print(f"[vendor] Resolved: {dev.mac_address} -> {vendor}", flush=True)
        if updated:
            session.commit()
            print(f"[vendor] Resolved {updated} vendor(s) from local DB.", flush=True)
    except Exception as e:
        session.rollback()
        print(f"[vendor] Refresh error: {e}", flush=True)
    finally:
        session.close()


def refresh_missing_hostnames() -> None:
    """Resolve hostnames for online devices that have none, plus a periodic re-check for
    devices whose current display hostname only ever came from DHCP (self-reported and
    often generic) — giving a real rDNS/mDNS name a chance to reclaim priority once it
    becomes resolvable, per the naming priority: manual > DNS (non-generic) > DHCP > other."""
    if not _cfg.ENABLE_HOSTNAME_RESOLUTION:
        return
    now = datetime.now(timezone.utc)
    session = Session()
    try:
        candidates = session.query(Device).filter(
            Device.is_online == True,
            Device.custom_name == None,
            (Device.hostname == None) | (Device.hostname == Device.dhcp_hostname),
        ).all()
        updated = 0
        for dev in candidates:
            scan_ip = dev.primary_ip or dev.ip_address
            if not _cfg._is_valid_ip(scan_ip):
                continue
            last_att = dev.hostname_last_attempted
            cooldown_elapsed = (
                last_att is None or
                (now - last_att).total_seconds() >= _cfg.HOSTNAME_COOLDOWN_HOURS * 3600
            )
            if not cooldown_elapsed:
                continue
            name = resolve_hostname(scan_ip)
            dev.hostname_last_attempted = now
            if name:
                _remember_name_source(dev, "rdns_hostname", name)
                current_hn = dev.hostname or ""
                # Only promote the freshly-resolved DNS name if it's meaningfully
                # better than what's there — i.e. non-generic and different from the
                # (possibly DHCP-sourced) current value.
                if name != current_hn and not _is_generic_hostname(name):
                    dev.hostname = name
                    updated += 1
                    print(f"[hostname] Resolved: {scan_ip} -> {name}", flush=True)
        if updated or True:
            session.commit()
            if updated:
                print(f"[hostname] Resolved {updated} new hostnames this pass.", flush=True)
    except Exception as e:
        session.rollback()
        print(f"[hostname] Refresh error: {e}", flush=True)
    finally:
        session.close()


def update_presence_from_sweep(session, active_macs: set) -> None:
    """Mark devices online/offline based on accumulated evidence across all signal sources."""
    now = datetime.now(timezone.utc)

    with _sniffer_seen_lock:
        seen_this_cycle = active_macs | _sniffer_seen_this_interval.copy()

    own_ips = _get_host_ipv4s()

    with _offline_lock:
        stale_macs = [m for m, ts in _offline_at.items() if (now - ts).total_seconds() > 600]
        for m in stale_macs:
            _offline_at.pop(m, None)

    # Fire deferred offline events for devices that have been continuously offline
    # for at least FLAP_SUPPRESS_SECONDS — brief dropouts shorter than this window
    # are silently cancelled when the device returns (no timeline noise).
    with _pending_offline_lock:
        to_fire = [
            (m, d) for m, (ts, d) in _pending_offline_events.items()
            if (now - ts).total_seconds() >= _cfg.FLAP_SUPPRESS_SECONDS
        ]
        for m, _ in to_fire:
            del _pending_offline_events[m]
    for _mac, _detail in to_fire:
        with _confirmed_offline_lock:
            _confirmed_offline_macs.add(_mac)
        _write_event(_mac, "offline", _detail)

    for dev in session.query(Device).all():
        dev_ip = (getattr(dev, "primary_ip", None) or dev.ip_address or "")

        if dev.mac_address in seen_this_cycle or (dev_ip and dev_ip in own_ips):
            if not dev.is_online:
                dev.status_changed_at = now
            dev.is_online = True
            dev.miss_count = 0
            dev.presence_last_seen_at = now
            continue

        if not dev.is_online:
            continue

        presence_ts = getattr(dev, "presence_last_seen_at", None) or dev.last_seen
        if presence_ts and (now - presence_ts).total_seconds() < _cfg.PRESENCE_GRACE_SECONDS:
            continue

        dev.is_online = False
        dev.status_changed_at = now
        elapsed = f"{(now - presence_ts).total_seconds():.0f}s" if presence_ts else "unknown"
        print(
            f"[-] Offline: {dev_ip} ({dev.mac_address}) "
            f"— no signal for {elapsed} (grace={_cfg.PRESENCE_GRACE_SECONDS}s)",
            flush=True,
        )

        suppressed = getattr(dev, "suppress_presence_events", False)
        if suppressed:
            continue

        with _offline_lock:
            _offline_at[dev.mac_address] = now

        # Defer the offline event write — if the device returns before
        # FLAP_SUPPRESS_SECONDS elapses, the pending entry is cancelled in
        # upsert_seen_device and neither offline nor online event is written.
        with _confirmed_offline_lock:
            already_confirmed = dev.mac_address in _confirmed_offline_macs
        with _pending_offline_lock:
            already_pending = dev.mac_address in _pending_offline_events
        if not already_confirmed and not already_pending:
            with _pending_offline_lock:
                _pending_offline_events[dev.mac_address] = (now, {
                    "ip": dev_ip,
                    "source": "sweep",
                    "elapsed_s": int((now - presence_ts).total_seconds()) if presence_ts else None,
                })
