import asyncio
import json
import re as _re
from datetime import datetime, timezone
from urllib.parse import urlparse, quote as _urlencode

import httpx
from sqlalchemy import text

import state
from database import SessionLocal

HIGH_RISK_PORTS = {21, 23, 137, 138, 139, 445, 512, 513, 514, 3389, 5900}

NOTIFICATION_EVENT_DEFS = [
    ("device.new",                  "New Device",               "Devices",         "A new device appeared on the network"),
    ("device.online.watched",       "Watched Device Online",    "Devices",         "A watched device came back online"),
    ("device.offline.watched",      "Watched Device Offline",   "Devices",         "A watched device went offline"),
    ("device.online.all",           "Any Device Online",        "Devices",         "Any device came online (includes watched)"),
    ("device.offline.all",          "Any Device Offline",       "Devices",         "Any device went offline (includes watched)"),
    ("device.returned",             "Device Returned",          "Devices",         "A device reappeared after a long absence"),
    ("device.auto_blocked",         "Device Auto-Blocked",      "Devices",         "A device was automatically blocked"),
    ("vuln.critical",               "Critical Vulnerability",   "Vulnerabilities", "Critical-severity vulnerability found on a network device"),
    ("vuln.high",                   "High Vulnerability",       "Vulnerabilities", "High-severity vulnerability found on a network device"),
    ("container.vuln_critical",     "Container Critical Vuln",  "Vulnerabilities", "Critical vulnerability found in a container image"),
    ("container.vuln_high",         "Container High Vuln",      "Vulnerabilities", "High vulnerability found in a container image"),
    ("port.high_risk",              "High-Risk Port",           "Network",         "Telnet, FTP, SMB, RDP, VNC or similar high-risk port opened"),
    ("port.opened",                 "New Port Opened",          "Network",         "A new port opened above a device's confirmed baseline"),
    ("speedtest.degraded_download", "Download Speed Degraded",  "Speed Test",      "Download speed fell below the configured threshold"),
    ("block.network_pause",         "Network Paused",           "Blocking",        "Internet access was blocked for the whole network"),
    ("block.schedule_start",        "Block Schedule Started",   "Blocking",        "A block schedule became active"),
    ("block.schedule_end",          "Block Schedule Ended",     "Blocking",        "A block schedule deactivated"),
    ("container.crashed",           "Container Crashed",        "Containers",      "A container exited with a non-zero exit code"),
    ("container.update_available",  "Container Update Available","Containers",      "A newer image version is available for a container"),
    ("container.updated",           "Container Updated",         "Containers",      "A container was successfully updated to a new image version"),
    ("container.update_blocked",    "Container Update Blocked",  "Containers",      "A container update was blocked due to critical CVEs in the new image"),
    ("container.update_failed",     "Container Update Failed",   "Containers",      "A container update failed and the original was automatically restored"),
    ("traffic.unusual_port",        "Unusual Port Traffic",     "Traffic",         "A device communicated on an unusual port"),
    ("traffic.suspicious_country",  "Suspicious Country Traffic","Traffic",        "A device communicated with a flagged country"),
    ("person.home",                 "Person Arrived Home",      "Person Presence", "A tracked person's device came online (person is home)"),
    ("person.away",                 "Person Left Home",         "Person Presence", "A tracked person's device went offline (person is away)"),
    ("person.blocked",              "Person Blocked",           "Person Presence", "All of a person's devices were manually blocked"),
    ("person.unblocked",            "Person Unblocked",         "Person Presence", "A person's devices were unblocked"),
]

PERSON_PRESENCE_COOLDOWN_SECONDS = 600  # 10 minutes


def _build_apprise_url(service: str, config: dict) -> str | None:
    """Construct an Apprise notification URL from a service name and config dict."""
    try:
        if service == "ntfy":
            server = (config.get("server") or "https://ntfy.sh").rstrip("/")
            topic  = config.get("topic", "").strip()
            if not topic:
                return None
            p      = urlparse(server)
            scheme = "ntfys" if p.scheme == "https" else "ntfy"
            host   = p.netloc or p.path
            user   = config.get("user", "").strip()
            pw     = config.get("password", "").strip()
            auth   = f"{_urlencode(user, safe='')}:{_urlencode(pw, safe='')}@" if user else ""
            return f"{scheme}://{auth}{host}/{topic}"

        if service == "gotify":
            server = (config.get("server") or "").rstrip("/")
            token  = config.get("token", "").strip()
            if not server or not token:
                return None
            p      = urlparse(server)
            scheme = "gotifys" if p.scheme == "https" else "gotify"
            host   = p.netloc or p.path
            return f"{scheme}://{host}/{token}"

        if service == "pushbullet":
            key = config.get("api_key", "").strip()
            return f"pbul://{key}" if key else None

        if service == "telegram":
            bot   = config.get("bot_token", "").strip()
            chat  = config.get("chat_id", "").strip()
            return f"tgram://{bot}/{chat}/" if bot and chat else None

        if service == "discord":
            wid  = config.get("webhook_id",    "").strip()
            wtok = config.get("webhook_token",  "").strip()
            return f"discord://{wid}/{wtok}" if wid and wtok else None

        if service == "pushover":
            ukey  = config.get("user_key", "").strip()
            token = config.get("api_token", "").strip()
            return f"pover://{ukey}@{token}" if ukey and token else None

        if service == "slack":
            ta = config.get("token_a", "").strip()
            tb = config.get("token_b", "").strip()
            tc = config.get("token_c", "").strip()
            return f"slack://{ta}/{tb}/{tc}" if ta and tb and tc else None

        if service == "email":
            smtp_host = config.get("smtp_host", "").strip()
            smtp_user = config.get("smtp_user", "").strip()
            smtp_pass = config.get("smtp_password", "").strip()
            to_email  = config.get("to_email", "").strip()
            port      = config.get("smtp_port", "587")
            secure    = config.get("secure", True)
            if not all([smtp_host, smtp_user, smtp_pass, to_email]):
                return None
            scheme = "mailtos" if secure else "mailto"
            return (f"{scheme}://{_urlencode(smtp_user, safe='')}:"
                    f"{_urlencode(smtp_pass, safe='')}@{smtp_host}:{port}/"
                    f"{_urlencode(to_email, safe='')}")

        if service == "webhook":
            url = config.get("url", "").strip()
            if not url:
                return None
            p    = urlparse(url)
            scheme = "jsons" if p.scheme == "https" else "json"
            rest = p.netloc + p.path
            if p.query:
                rest += f"?{p.query}"
            return f"{scheme}://{rest}"

        if service == "matrix":
            user     = config.get("user",     "").strip()
            password = config.get("password", "").strip()
            raw_host = config.get("host",     "").strip()
            room     = config.get("room",     "").strip()
            port     = config.get("port",     "").strip()
            secure   = bool(config.get("secure", True))
            if not user or not password or not raw_host:
                return None
            if raw_host.lower().startswith("https://"):
                secure   = True
                raw_host = raw_host[8:].rstrip("/")
            elif raw_host.lower().startswith("http://"):
                secure   = False
                raw_host = raw_host[7:].rstrip("/")
            scheme   = "matrixs" if secure else "matrix"
            port_str = f":{port}" if port else ""
            room_str = f"/{_urlencode(room, safe='#:')}" if room else ""
            return (f"{scheme}://{_urlencode(user, safe='')}:"
                    f"{_urlencode(password, safe='')}@{raw_host}{port_str}{room_str}")

        if service == "msteams":
            wh = config.get("webhook_url", "").strip()
            m  = _re.search(
                r"webhookb2/([^@]+)@([^/]+)/IncomingWebhook/([^/]+)/([^/?]+)", wh)
            return f"msteams://{m.group(1)}/{m.group(2)}/{m.group(3)}/{m.group(4)}" if m else None

        if service == "signal":
            from_phone = config.get("from_phone", "").strip()
            to_phone   = config.get("to_phone",   "").strip()
            host       = (config.get("host", "") or "localhost").strip()
            port       = (config.get("port", "") or "8080").strip()
            if not from_phone or not to_phone:
                return None
            return (f"signal://{_urlencode(from_phone, safe='+')}"
                    f"@{host}:{port}/{_urlencode(to_phone, safe='+')}")

        if service == "whatsapp":
            token    = config.get("token",    "").strip()
            phone_id = config.get("phone_id", "").strip()
            to_phone = config.get("to_phone", "").strip()
            if not all([token, phone_id, to_phone]):
                return None
            return f"whatsapp://{_urlencode(token, safe='')}@{phone_id}/{_urlencode(to_phone, safe='+')}"

        if service == "mqtt":
            raw_host = config.get("host",     "").strip()
            topic    = config.get("topic",    "").strip()
            user     = config.get("user",     "").strip()
            password = config.get("password", "").strip()
            port     = config.get("port",     "").strip()
            secure   = bool(config.get("secure", False))
            if not raw_host or not topic:
                return None
            if raw_host.lower().startswith("mqtts://"):
                secure   = True
                raw_host = raw_host[8:].rstrip("/")
            elif raw_host.lower().startswith("mqtt://"):
                raw_host = raw_host[7:].rstrip("/")
            if port == "8883":
                secure = True
            scheme   = "mqtts" if secure else "mqtt"
            auth     = ""
            if user:
                auth = (f"{_urlencode(user, safe='')}:{_urlencode(password, safe='')}@"
                        if password else f"{_urlencode(user, safe='')}@")
            port_str = f":{port}" if port else ""
            return f"{scheme}://{auth}{raw_host}{port_str}/{_urlencode(topic, safe='/')}"

        if service == "ifttt":
            key   = config.get("webhook_key", "").strip()
            event = config.get("event_id",    "").strip()
            return f"ifttt://{key}@{event}" if key and event else None

    except Exception:
        return None
    return None


def _ha_build_url(config: dict) -> tuple[str, str]:
    """Return (url, token) for the HA service REST endpoint, or raise ValueError."""
    raw_host = config.get("host", "").strip()
    token    = config.get("token", "").strip()
    if not raw_host or not token:
        raise ValueError("Home Assistant requires 'host' and 'token'")
    port   = str(config.get("port", "") or "").strip()
    secure = bool(config.get("secure", False))
    notifier = (config.get("notifier", "") or "persistent_notification/create").strip()
    if "/" not in notifier:
        notifier = f"notify/{notifier}"
    if raw_host.lower().startswith("https://"):
        secure, raw_host = True, raw_host[8:].rstrip("/")
    elif raw_host.lower().startswith("http://"):
        secure, raw_host = False, raw_host[7:].rstrip("/")
    if port == "443":
        secure = True
    scheme   = "https" if secure else "http"
    port_str = f":{port}" if port else ""
    return f"{scheme}://{raw_host}{port_str}/api/services/{notifier}", token


async def _notify_home_assistant(config: dict, title: str, body: str) -> None:
    url, token = _ha_build_url(config)
    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        resp = await client.post(
            url,
            json={"message": body, "title": title},
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()


async def _notification_dispatch(event_type: str, title: str, body: str,
                                  device_mac: str | None = None):
    """Dispatch a notification event through all matching profiles and their channels."""
    import apprise as _apprise
    db = SessionLocal()
    try:
        profiles = db.execute(text("""
            SELECT id FROM notification_profiles
            WHERE (events->>:ev)::boolean = true
        """), {"ev": event_type}).fetchall()

        if not profiles:
            return

        channels_to_send: dict = {}
        for (profile_id,) in profiles:
            rows = db.execute(text("""
                SELECT nc.id, nc.service, nc.config
                FROM notification_channels nc
                JOIN notification_profile_channels npc ON npc.channel_id = nc.id
                WHERE npc.profile_id = :pid AND nc.enabled = TRUE
            """), {"pid": profile_id}).fetchall()
            for ch_id, svc, cfg in rows:
                if ch_id not in channels_to_send:
                    channels_to_send[ch_id] = (svc, cfg if isinstance(cfg, dict) else {})
    finally:
        db.close()

    toast_notify   = any(svc == "toast"   for svc, _ in channels_to_send.values())
    browser_notify = any(svc == "browser" for svc, _ in channels_to_send.values())

    if toast_notify or browser_notify:
        state._pending_browser_notifications.append({
            "event_type": event_type, "title": title, "body": body,
            "toast": toast_notify, "browser": browser_notify,
            "ts": datetime.now(timezone.utc).isoformat(),
        })
        if len(state._pending_browser_notifications) > 200:
            state._pending_browser_notifications.pop(0)

    urls = []
    for ch_id, (svc, cfg) in channels_to_send.items():
        if svc in ("toast", "browser"):
            continue
        if svc == "home_assistant":
            try:
                await _notify_home_assistant(cfg, title, body)
            except Exception as exc:
                print(f"[notify] Home Assistant error: {exc}", flush=True)
            continue
        url = _build_apprise_url(svc, cfg)
        if url:
            urls.append(url)

    if urls:
        try:
            a = _apprise.Apprise()
            for url in urls:
                a.add(url)
            await asyncio.to_thread(a.notify, title=title, body=body)
        except Exception as exc:
            print(f"[notify] Apprise error: {exc}", flush=True)


def _is_suppressed(mac: str, event_type: str, cache: dict) -> bool:
    """Check if an alert for (mac, event_type) is suppressed. Uses cache to avoid N+1 queries."""
    key = (mac, event_type)
    if key in cache:
        return cache[key]
    db = SessionLocal()
    try:
        row = db.execute(text("""
            SELECT id FROM alert_suppressions
            WHERE (mac_address = :mac OR mac_address IS NULL)
              AND (event_type = :type OR event_type IS NULL)
              AND (expires_at IS NULL OR expires_at > NOW())
            LIMIT 1
        """), {"mac": mac, "type": event_type}).fetchone()
        result = row is not None
        cache[key] = result
        return result
    finally:
        db.close()


async def _notification_loop():
    await asyncio.sleep(20)  # startup grace

    db = SessionLocal()
    try:
        row = db.execute(text("SELECT COALESCE(MAX(id), 0) FROM device_events")).scalar()
        state._last_alert_event_id = int(row or 0)
        from models import Setting
        s = db.get(Setting, "network_paused")
        state._last_network_paused = s.value if s else "false"

        # Initialize person home state from persisted presence_state column.
        try:
            person_rows = db.execute(text(
                "SELECT id::text, presence_state FROM persons"
            )).fetchall()
            for pid, pstate in person_rows:
                if pstate == "home":
                    state._person_home_state[pid] = True
                elif pstate == "away":
                    state._person_home_state[pid] = False
        except Exception:
            pass
    except Exception:
        pass
    finally:
        db.close()

    while True:
        try:
            db = SessionLocal()
            try:
                from models import Setting
                settings = {s.key: s.value for s in db.query(Setting).all()}

                network_paused = settings.get("network_paused", "false")
                if network_paused == "true" and state._last_network_paused != "true":
                    asyncio.ensure_future(_notification_dispatch(
                        "block.network_pause", "Network Paused",
                        "Internet access has been blocked for the whole network",
                    ))
                state._last_network_paused = network_paused

                vuln_on_new    = settings.get("vuln_scan_on_new_device",  "false") == "true"
                vuln_on_port   = settings.get("vuln_scan_on_port_change", "false") == "true"
                auto_block_new = settings.get("auto_block_new_devices",   "false") == "true"
                auto_block_sev = settings.get("auto_block_vuln_severity", "none")
                returned_days       = int(settings.get("device_returned_days", "7") or "7")
                person_cooldown     = int(settings.get("person_presence_cooldown", str(PERSON_PRESENCE_COOLDOWN_SECONDS)) or str(PERSON_PRESENCE_COOLDOWN_SECONDS))
                person_away_confirm = int(settings.get("person_away_confirm_seconds", "60") or "60")
                SEV_ORDER      = ["none", "info", "clean", "low", "medium", "high", "critical"]

                rows = db.execute(text("""
                    SELECT de.id, de.mac_address, de.type, de.detail, de.created_at,
                           COALESCE(d.custom_name, d.hostname, d.ip_address, de.mac_address) AS name,
                           d.ip_address, d.is_important,
                           COALESCE(d.is_ignored, false) AS is_ignored,
                           d.scan_results, d.vuln_severity
                    FROM device_events de
                    JOIN devices d ON d.mac_address = de.mac_address
                    WHERE de.id > :last_id
                      AND de.type = ANY(:types)
                    ORDER BY de.id ASC
                    LIMIT 100
                """), {
                    "last_id": state._last_alert_event_id,
                    "types":   ["joined", "interface_joined", "online", "offline",
                                "vuln_scan_complete", "port_opened", "blocked", "unblocked"],
                }).fetchall()

                dispatches:      list = []
                vuln_scans:      list = []
                devices_to_block: list = []
                suppression_cache: dict = {}

                for row in rows:
                    eid, mac, etype, detail, created_at, name, ip, is_important, is_ignored, scan_results, vuln_severity = row
                    state._last_alert_event_id = max(state._last_alert_event_id, eid)
                    if is_ignored:
                        continue
                    d = detail or {}

                    if etype in ("joined", "interface_joined"):
                        dispatches.append(("device.new", "New Device",
                                           f"{name} ({ip}) appeared on the network", mac))
                        if auto_block_new:
                            devices_to_block.append((mac, ip))
                        if vuln_on_new and ip:
                            scripts_s = db.get(Setting, "vuln_scan_templates")
                            vuln_scans.append((mac, ip, (scripts_s.value or "").strip() if scripts_s else ""))

                    elif etype == "online":
                        dispatches.append(("device.online.all", "Device Online",
                                           f"{name} ({ip}) is back online", mac))
                        if is_important:
                            dispatches.append(("device.online.watched", "Watched Device Online",
                                               f"{name} ({ip}) is back online", mac))
                        off_row = db.execute(text("""
                            SELECT created_at FROM device_events
                            WHERE mac_address = :mac AND type = 'offline'
                            ORDER BY id DESC LIMIT 1
                        """), {"mac": mac}).fetchone()
                        if off_row:
                            off_at = off_row[0]
                            if off_at.tzinfo is None:
                                off_at = off_at.replace(tzinfo=timezone.utc)
                            days_absent = (datetime.now(timezone.utc) - off_at).days
                            if days_absent >= returned_days:
                                dispatches.append(("device.returned", "Device Returned",
                                                   f"{name} ({ip}) reappeared after {days_absent} days", mac))
                        person_row = db.execute(text("""
                            SELECT p.id::text, p.name, p.primary_mac FROM persons p
                            JOIN person_devices pd ON pd.person_id = p.id
                            JOIN devices pd_dev ON pd_dev.mac_address = pd.mac_address
                            JOIN devices trigger_dev ON trigger_dev.mac_address = :mac
                            WHERE (pd.mac_address = :mac
                                   OR (pd_dev.group_id IS NOT NULL
                                       AND pd_dev.group_id = trigger_dev.group_id))
                              AND (
                                p.primary_mac IS NULL
                                OR p.primary_mac = :mac
                                OR EXISTS (
                                    SELECT 1 FROM devices primary_dev
                                    WHERE primary_dev.mac_address = p.primary_mac
                                      AND primary_dev.group_id IS NOT NULL
                                      AND primary_dev.group_id = trigger_dev.group_id
                                )
                              )
                            LIMIT 1
                        """), {"mac": mac}).fetchone()
                        if person_row:
                            pid, pname, person_primary_mac = person_row
                            if pid in state._person_away_pending:
                                del state._person_away_pending[pid]
                                state._person_home_state[pid] = True
                                db.execute(text(
                                    "UPDATE persons SET presence_state='home' WHERE id=:pid"
                                ), {"pid": pid})
                                db.commit()
                            elif not state._person_home_state.get(pid, False):
                                last_home_ts = state._person_last_home_notified.get(pid)
                                in_cooldown = (
                                    last_home_ts is not None and
                                    (datetime.now(timezone.utc) - last_home_ts).total_seconds()
                                    < person_cooldown
                                )
                                if not in_cooldown:
                                    if person_primary_mac:
                                        any_online = db.execute(text("""
                                            SELECT 1 FROM devices primary_d
                                            LEFT JOIN devices sib ON sib.group_id = primary_d.group_id
                                                AND primary_d.group_id IS NOT NULL
                                            WHERE primary_d.mac_address = :pmac
                                              AND (primary_d.is_online = true OR sib.is_online = true)
                                            LIMIT 1
                                        """), {"pmac": person_primary_mac}).fetchone()
                                    else:
                                        any_online = db.execute(text("""
                                            SELECT 1 FROM person_devices pd
                                            JOIN devices d ON d.mac_address = pd.mac_address
                                            LEFT JOIN devices sibling ON sibling.group_id = d.group_id
                                                AND sibling.group_id IS NOT NULL
                                            WHERE pd.person_id = :pid
                                              AND (d.is_online = true OR sibling.is_online = true)
                                            LIMIT 1
                                        """), {"pid": pid}).fetchone()
                                    if any_online:
                                        state._person_home_state[pid] = True
                                        state._person_last_home_notified[pid] = datetime.now(timezone.utc)
                                        db.execute(text(
                                            "UPDATE persons SET presence_state='home' WHERE id=:pid"
                                        ), {"pid": pid})
                                        db.commit()
                                        dispatches.append(("person.home", "Person Arrived Home",
                                                           f"{pname} is now home", None))
                                else:
                                    state._person_home_state[pid] = True  # silent update

                    elif etype == "offline":
                        dispatches.append(("device.offline.all", "Device Offline",
                                           f"{name} ({ip}) went offline", mac))
                        if is_important:
                            dispatches.append(("device.offline.watched", "Watched Device Offline",
                                               f"{name} ({ip}) went offline", mac))
                        person_row = db.execute(text("""
                            SELECT p.id::text, p.name, p.primary_mac FROM persons p
                            JOIN person_devices pd ON pd.person_id = p.id
                            JOIN devices pd_dev ON pd_dev.mac_address = pd.mac_address
                            JOIN devices trigger_dev ON trigger_dev.mac_address = :mac
                            WHERE (pd.mac_address = :mac
                                   OR (pd_dev.group_id IS NOT NULL
                                       AND pd_dev.group_id = trigger_dev.group_id))
                              AND (
                                p.primary_mac IS NULL
                                OR p.primary_mac = :mac
                                OR EXISTS (
                                    SELECT 1 FROM devices primary_dev
                                    WHERE primary_dev.mac_address = p.primary_mac
                                      AND primary_dev.group_id IS NOT NULL
                                      AND primary_dev.group_id = trigger_dev.group_id
                                )
                              )
                            LIMIT 1
                        """), {"mac": mac}).fetchone()
                        if person_row:
                            pid, pname, person_primary_mac = person_row
                            was_home = state._person_home_state.get(pid, True)
                            if was_home and pid not in state._person_away_pending:
                                if person_primary_mac:
                                    any_online = db.execute(text("""
                                        SELECT 1 FROM devices primary_d
                                        LEFT JOIN devices sib ON sib.group_id = primary_d.group_id
                                            AND primary_d.group_id IS NOT NULL
                                        WHERE primary_d.mac_address = :pmac
                                          AND (primary_d.is_online = true OR sib.is_online = true)
                                        LIMIT 1
                                    """), {"pmac": person_primary_mac}).fetchone()
                                else:
                                    any_online = db.execute(text("""
                                        SELECT 1 FROM person_devices pd
                                        JOIN devices d ON d.mac_address = pd.mac_address
                                        LEFT JOIN devices sibling ON sibling.group_id = d.group_id
                                            AND sibling.group_id IS NOT NULL
                                        WHERE pd.person_id = :pid
                                          AND (d.is_online = true OR sibling.is_online = true)
                                        LIMIT 1
                                    """), {"pid": pid}).fetchone()
                                if not any_online:
                                    state._person_away_pending[pid] = (datetime.now(timezone.utc), pname)
                                    state._person_home_state[pid] = False

                    elif etype == "vuln_scan_complete":
                        severity = d.get("severity", "clean")
                        count    = d.get("vuln_count", 0)
                        if severity == "critical":
                            dispatches.append(("vuln.critical", "Critical Vulnerability",
                                               f"{name} ({ip}): {count} critical finding(s)", mac))
                        elif severity == "high":
                            dispatches.append(("vuln.high", "High Vulnerability",
                                               f"{name} ({ip}): {count} high-severity finding(s)", mac))
                        if auto_block_sev != "none":
                            try:
                                if SEV_ORDER.index(severity) >= SEV_ORDER.index(auto_block_sev):
                                    devices_to_block.append((mac, ip))
                            except ValueError:
                                pass

                    elif etype == "port_opened":
                        port = d.get("port")
                        sev  = d.get("severity", "info")
                        if port and int(port) in HIGH_RISK_PORTS:
                            dispatches.append(("port.high_risk", "High-Risk Port",
                                               f"{name} ({ip}): port {port} is high-risk", mac))
                        dispatches.append(("port.opened", "New Port Detected",
                                           f"{name} ({ip}): port {port} [{sev}] opened above baseline", mac))
                        if vuln_on_port and ip:
                            scripts_s = db.get(Setting, "vuln_scan_templates")
                            vuln_scans.append((mac, ip, (scripts_s.value or "").strip() if scripts_s else ""))

                    elif etype == "blocked":
                        reason = d.get("reason", "")
                        if reason == "schedule":
                            dispatches.append(("block.schedule_start", "Block Schedule Started",
                                               f"Block schedule activated for {name}", mac))
                        elif reason in ("auto", "auto_block"):
                            dispatches.append(("device.auto_blocked", "Device Auto-Blocked",
                                               f"{name} ({ip}) was automatically blocked", mac))

                    elif etype == "unblocked":
                        if d.get("reason") == "schedule_end":
                            dispatches.append(("block.schedule_end", "Block Schedule Ended",
                                               f"Block schedule deactivated for {name}", mac))

                    # ── Plugin event bus dispatch ─────────────────────────────
                    _sev_map     = {"low": 1, "info": 1, "medium": 2, "high": 3, "critical": 3}
                    _ports_count = len((scan_results or {}).get("open_ports", [])) if scan_results else 0
                    _vuln_count  = _sev_map.get(vuln_severity or "", 0)
                    _pe_ctx = {
                        "mac":   mac,
                        "name":  name,
                        "ip":    ip,
                        "ports": _ports_count,
                        "vulns": _vuln_count,
                    }
                    _pe_type = None
                    if etype in ("joined", "interface_joined"):
                        _pe_type = "device.new"
                    elif etype == "online":
                        _pe_type = "device.online"
                    elif etype == "offline":
                        _pe_type = "device.offline"
                    elif etype == "port_opened":
                        _pe_ctx["ports"] = _ports_count
                        _pe_type = "port.opened"
                    elif etype == "vuln_scan_complete":
                        severity_str = d.get("severity", "clean")
                        if severity_str not in ("clean", "none", ""):
                            _pe_ctx["vulns"] = d.get("vuln_count", _vuln_count)
                            _pe_type = "vuln.found"
                    elif etype == "renamed":
                        if state._ha_mqtt.connected:
                            try:
                                state._ha_mqtt.pub_device_discovery(mac, name, ip)
                            except Exception as _ha_exc:
                                print(f"[ha-mqtt] Renamed dispatch error: {_ha_exc}", flush=True)
                    if _pe_type:
                        asyncio.ensure_future(state._plugin_event_bus.notify(_pe_type, _pe_ctx))

            finally:
                db.close()

            # ── HA MQTT system stats after processing batch ──────────────────
            if state._ha_mqtt.connected:
                try:
                    _ha_db = SessionLocal()
                    try:
                        _tot_on   = _ha_db.execute(text("SELECT COUNT(*) FROM devices WHERE is_online=true")).scalar() or 0
                        _tot_vuln = _ha_db.execute(text(
                            "SELECT COUNT(*) FROM devices WHERE vuln_severity IS NOT NULL AND vuln_severity NOT IN ('none','clean')"
                        )).scalar() or 0
                        _ls_row   = _ha_db.execute(text(
                            "SELECT created_at FROM device_events WHERE type='scan_complete' ORDER BY id DESC LIMIT 1"
                        )).fetchone()
                        state._ha_mqtt.pub_system_state(_tot_on, _tot_vuln, "idle",
                                                        _ls_row[0].isoformat() if _ls_row else None)
                    finally:
                        _ha_db.close()
                except Exception as _ha_exc:
                    print(f"[ha-mqtt] System stats error: {_ha_exc}", flush=True)

            # ── Deferred "Left home" confirmation ───────────────────────────
            _now = datetime.now(timezone.utc)
            _away_db = None
            for _pid in list(state._person_away_pending.keys()):
                _pending_since, _pname = state._person_away_pending[_pid]
                if (_now - _pending_since).total_seconds() >= person_away_confirm:
                    del state._person_away_pending[_pid]
                    state._person_last_home_notified.pop(_pid, None)
                    try:
                        if _away_db is None:
                            _away_db = SessionLocal()
                        _away_db.execute(text(
                            "UPDATE persons SET presence_state='away' WHERE id=:pid"
                        ), {"pid": _pid})
                        _away_db.commit()
                    except Exception:
                        pass
                    dispatches.append(("person.away", "Person Left Home",
                                       f"{_pname} is away (all devices offline)", None))
            if _away_db:
                _away_db.close()

            # ── Presence reconciliation safety-net ──────────────────────────
            _recon_db = None
            try:
                _recon_db = SessionLocal()
                _person_rows = _recon_db.execute(text(
                    "SELECT id::text, name, presence_state, primary_mac FROM persons"
                )).fetchall()
                for _rpid, _rpname, _rpstate, _rprimary_mac in _person_rows:
                    if state._person_home_state.get(_rpid, False):
                        continue
                    if _rpid in state._person_away_pending:
                        continue
                    if _rprimary_mac:
                        _any = _recon_db.execute(text("""
                            SELECT 1 FROM devices primary_d
                            LEFT JOIN devices sib ON sib.group_id = primary_d.group_id
                                AND primary_d.group_id IS NOT NULL
                            WHERE primary_d.mac_address = :pmac
                              AND (primary_d.is_online = true OR sib.is_online = true)
                            LIMIT 1
                        """), {"pmac": _rprimary_mac}).fetchone()
                    else:
                        _any = _recon_db.execute(text("""
                            SELECT 1 FROM person_devices pd
                            JOIN devices d ON d.mac_address = pd.mac_address
                            LEFT JOIN devices sib ON sib.group_id = d.group_id
                                AND sib.group_id IS NOT NULL
                            WHERE pd.person_id = :pid
                              AND (d.is_online = true OR sib.is_online = true)
                            LIMIT 1
                        """), {"pid": _rpid}).fetchone()
                    if _any:
                        state._person_home_state[_rpid] = True
                        state._person_last_home_notified[_rpid] = _now
                        _recon_db.execute(text(
                            "UPDATE persons SET presence_state='home' WHERE id=:pid"
                        ), {"pid": _rpid})
                        _recon_db.commit()
                        dispatches.append(("person.home", "Person Arrived Home",
                                           f"{_rpname} is now home", None))
            except Exception as _recon_exc:
                print(f"[notify] Presence reconciliation error: {_recon_exc}", flush=True)
            finally:
                if _recon_db:
                    _recon_db.close()

            for event_type, title, body, mac in dispatches:
                if not _is_suppressed(mac, event_type, suppression_cache):
                    asyncio.ensure_future(_notification_dispatch(event_type, title, body, mac))

            for mac, ip, scripts in vuln_scans:
                from vuln_utils import _run_single_vuln_scan
                asyncio.ensure_future(_run_single_vuln_scan(mac, ip, scripts))

            for mac, ip in devices_to_block:
                try:
                    from probe_client import _execute_block_bg
                    from device_utils import _add_event
                    await _execute_block_bg(mac, ip, "block")
                    db2 = SessionLocal()
                    try:
                        db2.execute(text("UPDATE devices SET is_blocked=true WHERE mac_address=:mac"), {"mac": mac})
                        _add_event(db2, mac, "blocked", {"reason": "auto", "ip": ip})
                        db2.commit()
                    finally:
                        db2.close()
                    asyncio.ensure_future(state._plugin_event_bus.notify("device.blocked", {"mac": mac, "ip": ip or ""}))
                    print(f"[notify] Auto-blocked {mac}", flush=True)
                except Exception as exc:
                    print(f"[notify] Auto-block {mac}: {exc}", flush=True)

        except Exception as exc:
            print(f"[notify] Loop error: {exc}", flush=True)

        await asyncio.sleep(30)
