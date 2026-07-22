import json
import threading
from sqlalchemy import text
from sqlalchemy.orm import Session


class HAMQTTManager:
    """Persistent MQTT client for Home Assistant entity publishing."""

    def __init__(self):
        self._client    = None
        self._connected = False
        self._dp        = "homeassistant"
        self._sp        = "inspectre"
        self._lock      = threading.Lock()

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self, host: str, port: int = 1883, user: str = "",
                password: str = "", discovery_prefix: str = "homeassistant",
                state_prefix: str = "inspectre"):
        self.disconnect()
        import paho.mqtt.client as _mqtt
        self._dp = (discovery_prefix or "homeassistant").strip("/")
        self._sp = (state_prefix     or "inspectre").strip("/")
        lwt     = f"{self._sp}/system/status"
        client  = _mqtt.Client(client_id="inspectre_ha", clean_session=True)
        client.will_set(lwt, "offline", retain=True, qos=1)
        if user:
            client.username_pw_set(user, password or "")

        def _on_connect(c, _u, _f, rc):
            if rc == 0:
                self._connected = True
                c.publish(lwt, "online", retain=True, qos=1)
                print(f"[ha-mqtt] Connected to {host}:{port}", flush=True)
            else:
                self._connected = False
                print(f"[ha-mqtt] Connect failed rc={rc}", flush=True)

        def _on_disconnect(c, _u, rc):
            self._connected = False
            if rc != 0:
                print(f"[ha-mqtt] Disconnected rc={rc}", flush=True)

        client.on_connect    = _on_connect
        client.on_disconnect = _on_disconnect
        client.reconnect_delay_set(min_delay=5, max_delay=60)
        client.connect(host, int(port), keepalive=60)
        client.loop_start()
        self._client = client

    def disconnect(self):
        with self._lock:
            if self._client:
                try:
                    self._client.publish(f"{self._sp}/system/status", "offline", retain=True)
                    self._client.loop_stop()
                    self._client.disconnect()
                except Exception:
                    pass
                self._client    = None
                self._connected = False

    def publish(self, topic: str, payload, retain: bool = False, qos: int = 0):
        if not self._client or not self._connected:
            return
        self._client.publish(
            topic,
            json.dumps(payload) if isinstance(payload, dict) else str(payload),
            retain=retain,
            qos=qos,
        )

    @staticmethod
    def _mid(mac: str) -> str:
        return mac.replace(":", "_").lower()

    def pub_system_discovery(self):
        dp, sp = self._dp, self._sp
        dev = {"identifiers": ["inspectre_system_service"], "name": "InSpectre",
               "manufacturer": "InSpectre", "model": "Network Scanner"}
        for comp, uid, extra in [
            ("sensor", "total_devices",        {"name": "Total Devices Online",    "icon": "mdi:devices",
                                                 "state_topic": f"{sp}/system/total_devices"}),
            ("sensor", "total_vulnerabilities",{"name": "Total Vulnerabilities",   "icon": "mdi:shield-alert",
                                                 "state_topic": f"{sp}/system/total_vulnerabilities"}),
            ("sensor", "scan_state",           {"name": "Scan Status",             "icon": "mdi:radar",
                                                 "state_topic": f"{sp}/system/scan_state"}),
            ("sensor", "last_scan",            {"name": "Last Scan",               "icon": "mdi:clock-check",
                                                 "device_class": "timestamp",
                                                 "state_topic": f"{sp}/system/last_scan"}),
        ]:
            self.publish(f"{dp}/{comp}/inspectre_system_{uid}/config",
                         {"unique_id": f"inspectre_system_{uid}", "device": dev, **extra}, retain=True)

    def pub_device_discovery(self, mac: str, name: str | None, ip: str | None):
        dp, sp, mid = self._dp, self._sp, self._mid(mac)
        dev = {"identifiers": [f"inspectre_{mid}"], "name": name or ip or mac,
               "manufacturer": "InSpectre", "connections": [["mac", mac]]}
        for comp, uid, extra in [
            ("binary_sensor", f"{mid}_presence", {"name": "Presence", "device_class": "connectivity",
                                                   "payload_on": "ON", "payload_off": "OFF",
                                                   "state_topic": f"{sp}/clients/{mid}/presence"}),
            ("binary_sensor", f"{mid}_new",      {"name": "New Device", "device_class": "problem",
                                                   "payload_on": "ON", "payload_off": "OFF",
                                                   "state_topic": f"{sp}/clients/{mid}/new"}),
            ("sensor", f"{mid}_ip",    {"name": "IP Address",   "icon": "mdi:ip-network",
                                         "state_topic": f"{sp}/clients/{mid}/ip"}),
            ("sensor", f"{mid}_ports", {"name": "Open Ports",   "icon": "mdi:lan",
                                         "state_topic": f"{sp}/clients/{mid}/open_ports"}),
            ("sensor", f"{mid}_vulns", {"name": "Vulnerabilities", "icon": "mdi:shield-alert",
                                         "state_topic": f"{sp}/clients/{mid}/vulnerabilities"}),
        ]:
            self.publish(f"{dp}/{comp}/inspectre_{uid}/config",
                         {"unique_id": f"inspectre_{uid}", "device": dev, **extra}, retain=True)

    def pub_device_state(self, mac: str, is_online: bool, ip: str | None = None,
                          open_ports: int | None = None, vulns: int | None = None,
                          is_new: bool | None = None):
        mid, sp = self._mid(mac), self._sp
        self.publish(f"{sp}/clients/{mid}/presence", "ON" if is_online else "OFF", retain=True)
        if ip         is not None: self.publish(f"{sp}/clients/{mid}/ip",              ip,           retain=True)
        if open_ports is not None: self.publish(f"{sp}/clients/{mid}/open_ports",  str(open_ports), retain=True)
        if vulns      is not None: self.publish(f"{sp}/clients/{mid}/vulnerabilities", str(vulns),  retain=True)
        if is_new     is not None: self.publish(f"{sp}/clients/{mid}/new",  "ON" if is_new else "OFF", retain=True)

    def pub_system_state(self, total_devices: int | None = None, total_vulns: int | None = None,
                          scan_state: str | None = None, last_scan: str | None = None):
        sp = self._sp
        if total_devices is not None: self.publish(f"{sp}/system/total_devices",         str(total_devices), retain=True)
        if total_vulns   is not None: self.publish(f"{sp}/system/total_vulnerabilities",  str(total_vulns),  retain=True)
        if scan_state    is not None: self.publish(f"{sp}/system/scan_state",             scan_state,        retain=True)
        if last_scan     is not None: self.publish(f"{sp}/system/last_scan",              last_scan,         retain=True)


def _ha_startup_connect(db: Session):
    """Connect HA MQTT on startup and publish initial discovery + state for all devices."""
    from state import _ha_mqtt, _plugin_registry
    from plugin_engine import get_decrypted_config
    from models import Setting

    try:
        plugin = _plugin_registry.get("home-assistant")
        if plugin and plugin.get("enabled") and plugin.get("config", {}).get("host"):
            cfg = get_decrypted_config(plugin["manifest"], plugin["config"])
            host = cfg.get("host", "").strip()
            if not host:
                return
            _ha_mqtt.connect(
                host             = host,
                port             = int(cfg.get("port") or 1883),
                user             = cfg.get("user", ""),
                password         = cfg.get("password", ""),
                discovery_prefix = cfg.get("discovery_prefix", "homeassistant"),
                state_prefix     = cfg.get("state_prefix",     "inspectre"),
            )
        else:
            s = {r.key: r.value for r in db.query(Setting).filter(
                Setting.key.in_(["ha_mqtt_enabled", "ha_mqtt_host", "ha_mqtt_port",
                                  "ha_mqtt_user", "ha_mqtt_password",
                                  "ha_mqtt_discovery_prefix", "ha_mqtt_state_prefix"])
            ).all()}
            if s.get("ha_mqtt_enabled") != "true" or not s.get("ha_mqtt_host", "").strip():
                return
            _ha_mqtt.connect(
                host             = s["ha_mqtt_host"].strip(),
                port             = int(s.get("ha_mqtt_port", "1883") or 1883),
                user             = s.get("ha_mqtt_user", ""),
                password         = s.get("ha_mqtt_password", ""),
                discovery_prefix = s.get("ha_mqtt_discovery_prefix", "homeassistant"),
                state_prefix     = s.get("ha_mqtt_state_prefix",     "inspectre"),
            )
        import time; time.sleep(1)
        if not _ha_mqtt.connected:
            return
        _ha_mqtt.pub_system_discovery()
        NEW_SECS = 7 * 24 * 3600
        devices = db.execute(text("""
            SELECT mac_address, COALESCE(custom_name, hostname) AS name, ip_address,
                   is_online, scan_results, vuln_severity, is_acknowledged,
                   EXTRACT(EPOCH FROM (NOW() - first_seen)) AS age_secs
            FROM devices WHERE is_ignored = false
        """)).fetchall()
        for d in devices:
            mac, name, ip, online, scan_res, vsev, acked, age_secs = d
            ports   = len((scan_res or {}).get("open_ports", [])) if scan_res else 0
            sev_map = {"low": 1, "info": 1, "medium": 2, "high": 3, "critical": 3}
            vulns   = sev_map.get(vsev or "", 0)
            is_new  = not bool(acked) and (age_secs is not None and float(age_secs) < NEW_SECS)
            _ha_mqtt.pub_device_discovery(mac, name, ip)
            _ha_mqtt.pub_device_state(mac, bool(online), ip, ports, vulns, is_new)
        total_online = sum(1 for d in devices if d.is_online)
        total_vulns  = sum(1 for d in devices if (d.vuln_severity or "") not in ("", "none", "clean"))
        last_scan_r  = db.execute(text(
            "SELECT created_at FROM device_events WHERE type='scan_complete' ORDER BY id DESC LIMIT 1"
        )).fetchone()
        last_scan = last_scan_r[0].isoformat() if last_scan_r else None
        _ha_mqtt.pub_system_state(total_online, total_vulns, "idle", last_scan)
        print(f"[ha-mqtt] Published discovery for {len(devices)} device(s)", flush=True)
    except Exception as exc:
        print(f"[ha-mqtt] Startup error: {exc}", flush=True)
