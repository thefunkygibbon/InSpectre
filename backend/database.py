import json
from sqlalchemy import create_engine, text, event as _sa_event
from sqlalchemy.orm import sessionmaker, Session
import psycopg2.extras as _pg_extras

from config import DATABASE_URL
from models import Base, Setting
import container_updates as _cu

engine       = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)


# psycopg2 does not decode JSONB columns automatically unless explicitly registered.
@_sa_event.listens_for(engine, "connect")
def _register_jsonb(dbapi_conn, _rec):
    _pg_extras.register_default_jsonb(dbapi_conn, globally=False, loads=json.loads)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _migrate(db: Session):
    migrations = [
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS is_important BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS notes TEXT",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS tags VARCHAR",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS location VARCHAR",
        """
        CREATE TABLE IF NOT EXISTS device_events (
            id SERIAL PRIMARY KEY,
            mac_address VARCHAR NOT NULL REFERENCES devices(mac_address) ON DELETE CASCADE,
            type VARCHAR NOT NULL,
            detail JSONB,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_device_events_mac     ON device_events(mac_address)",
        "CREATE INDEX IF NOT EXISTS ix_device_events_type    ON device_events(type)",
        "CREATE INDEX IF NOT EXISTS ix_device_events_created ON device_events(created_at)",
        """
        CREATE TABLE IF NOT EXISTS vuln_reports (
            id          SERIAL PRIMARY KEY,
            mac_address VARCHAR NOT NULL REFERENCES devices(mac_address) ON DELETE CASCADE,
            ip_address  VARCHAR,
            scanned_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            duration_s  FLOAT,
            severity    VARCHAR NOT NULL DEFAULT 'clean',
            vuln_count  INTEGER NOT NULL DEFAULT 0,
            findings    JSONB,
            raw_output  TEXT,
            nmap_args   VARCHAR
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_vuln_reports_mac       ON vuln_reports(mac_address)",
        "CREATE INDEX IF NOT EXISTS ix_vuln_reports_scanned   ON vuln_reports(scanned_at)",
        "CREATE INDEX IF NOT EXISTS ix_vuln_reports_severity  ON vuln_reports(severity)",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS vuln_last_scanned TIMESTAMPTZ",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS vuln_severity VARCHAR",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE devices ALTER COLUMN is_blocked SET DEFAULT FALSE",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS zone VARCHAR",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS is_ignored BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS suppress_presence_events BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE vuln_reports ADD COLUMN IF NOT EXISTS scan_args VARCHAR",
        "UPDATE settings SET value = value || ' -p-' WHERE key = 'nmap_args' AND value NOT LIKE '%-p%'",
        """
        CREATE TABLE IF NOT EXISTS saved_views (
            id          SERIAL PRIMARY KEY,
            name        VARCHAR NOT NULL UNIQUE,
            description VARCHAR,
            filters     JSONB NOT NULL DEFAULT '{}',
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS alert_suppressions (
            id          SERIAL PRIMARY KEY,
            mac_address VARCHAR REFERENCES devices(mac_address) ON DELETE CASCADE,
            event_type  VARCHAR,
            reason      VARCHAR,
            expires_at  TIMESTAMPTZ,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_alert_suppressions_mac  ON alert_suppressions(mac_address)",
        "CREATE INDEX IF NOT EXISTS ix_alert_suppressions_type ON alert_suppressions(event_type)",
        """
        CREATE TABLE IF NOT EXISTS block_schedules (
            id           SERIAL PRIMARY KEY,
            mac_address  VARCHAR(17),
            label        VARCHAR(100),
            days_of_week VARCHAR(50) NOT NULL DEFAULT 'mon,tue,wed,thu,fri,sat,sun',
            start_time   VARCHAR(5)  NOT NULL,
            end_time     VARCHAR(5)  NOT NULL,
            enabled      BOOLEAN     NOT NULL DEFAULT TRUE,
            created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_block_schedules_mac ON block_schedules(mac_address)",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS is_schedule_blocked BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE block_schedules ADD COLUMN IF NOT EXISTS mac_addresses TEXT[] DEFAULT '{}'",
        "ALTER TABLE block_schedules ADD COLUMN IF NOT EXISTS tags TEXT DEFAULT ''",
        """
        CREATE TABLE IF NOT EXISTS traffic_stats (
            id            SERIAL PRIMARY KEY,
            mac_address   VARCHAR NOT NULL,
            ip_address    VARCHAR,
            bucket_ts     TIMESTAMPTZ NOT NULL,
            bytes_in      BIGINT NOT NULL DEFAULT 0,
            bytes_out     BIGINT NOT NULL DEFAULT 0,
            packets_in    INTEGER NOT NULL DEFAULT 0,
            packets_out   INTEGER NOT NULL DEFAULT 0,
            lan_bytes     BIGINT NOT NULL DEFAULT 0,
            wan_bytes     BIGINT NOT NULL DEFAULT 0,
            dns_queries   JSONB,
            tls_sni       JSONB,
            http_hosts    JSONB,
            top_ips       JSONB,
            top_ports     JSONB,
            top_countries JSONB,
            protocols     JSONB,
            unusual_ports JSONB,
            created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_traffic_stats_mac    ON traffic_stats(mac_address)",
        "CREATE INDEX IF NOT EXISTS ix_traffic_stats_bucket ON traffic_stats(bucket_ts)",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS hostname_last_attempted TIMESTAMPTZ",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS deep_scan_last_run TIMESTAMPTZ",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS baseline_ports JSONB",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS baseline_scan_count INTEGER NOT NULL DEFAULT 0",
        """
        CREATE TABLE IF NOT EXISTS speedtest_results (
            id            SERIAL PRIMARY KEY,
            tested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            server        VARCHAR,
            ping_ms       REAL,
            download_mbps REAL,
            upload_mbps   REAL,
            raw_output    TEXT
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_speedtest_results_tested ON speedtest_results(tested_at)",
        """
        CREATE TABLE IF NOT EXISTS users (
            id           SERIAL PRIMARY KEY,
            username     VARCHAR(64) NOT NULL UNIQUE,
            password_hash VARCHAR(256) NOT NULL,
            is_admin     BOOLEAN NOT NULL DEFAULT TRUE,
            created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_login   TIMESTAMPTZ
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_users_username ON users(username)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS status_changed_at TIMESTAMPTZ",
        "UPDATE settings SET value = '-sS -T3 --max-rate 100' WHERE key = 'nmap_args' AND value IN ('-sT -O --osscan-limit -T4', '-sT -O --osscan-limit -T4 -p-', '-O --osscan-limit -sV --version-intensity 5 -T4 -p-', '-sS -T3 --max-rate 300')",
        "UPDATE settings SET value = '-sS -T4' WHERE key = 'nmap_args' AND value IN ('-sS -T3 --max-rate 100', '-sS -T4 --max-rate 200', '-sS -T4 --max-rate 200 --host-timeout 360s')",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS scan_type VARCHAR NOT NULL DEFAULT 'syn'",
        """CREATE TABLE IF NOT EXISTS container_events (
            id     SERIAL PRIMARY KEY,
            name   VARCHAR NOT NULL,
            status VARCHAR NOT NULL,
            ts     TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        "CREATE INDEX IF NOT EXISTS ix_container_events_name ON container_events(name)",
        "CREATE INDEX IF NOT EXISTS ix_container_events_ts   ON container_events(ts)",
        """CREATE TABLE IF NOT EXISTS container_hosts (
            id         SERIAL PRIMARY KEY,
            name       TEXT NOT NULL,
            type       TEXT NOT NULL DEFAULT 'docker_local',
            url        TEXT,
            auth_user  TEXT,
            auth_token TEXT,
            tls_verify BOOLEAN NOT NULL DEFAULT false,
            enabled    BOOLEAN NOT NULL DEFAULT true,
            node       TEXT NOT NULL DEFAULT 'pve',
            local_ip   TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        "ALTER TABLE container_hosts ADD COLUMN IF NOT EXISTS local_ip TEXT",
        """CREATE TABLE IF NOT EXISTS container_vuln_results (
            name       TEXT NOT NULL PRIMARY KEY,
            image      TEXT NOT NULL,
            vulns      JSONB NOT NULL DEFAULT '[]',
            scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        "ALTER TABLE ip_history ADD COLUMN IF NOT EXISTS seen_while_online BOOLEAN",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS primary_ip        VARCHAR",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS primary_ip_locked BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS dhcp_hostname     VARCHAR",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS dhcp_vendor_class VARCHAR",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS dhcp_fingerprint  VARCHAR",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS fingerbank_result JSONB",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS group_id      UUID",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS group_primary BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS group_manual  BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS auto_group_optout BOOLEAN NOT NULL DEFAULT FALSE",
        "CREATE INDEX IF NOT EXISTS ix_devices_group_id ON devices(group_id)",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS is_acknowledged BOOLEAN NOT NULL DEFAULT FALSE",
        """CREATE TABLE IF NOT EXISTS notification_channels (
            id         SERIAL PRIMARY KEY,
            name       TEXT NOT NULL,
            service    TEXT NOT NULL,
            config     JSONB NOT NULL DEFAULT '{}',
            enabled    BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS notification_profiles (
            id              SERIAL PRIMARY KEY,
            name            TEXT NOT NULL,
            events          JSONB NOT NULL DEFAULT '{}',
            browser_enabled BOOLEAN NOT NULL DEFAULT FALSE,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS notification_profile_channels (
            profile_id INTEGER NOT NULL REFERENCES notification_profiles(id) ON DELETE CASCADE,
            channel_id INTEGER NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
            PRIMARY KEY (profile_id, channel_id)
        )""",
        "CREATE INDEX IF NOT EXISTS ix_npc_profile ON notification_profile_channels(profile_id)",
        "CREATE INDEX IF NOT EXISTS ix_npc_channel ON notification_profile_channels(channel_id)",
        """CREATE TABLE IF NOT EXISTS plugins (
            plugin_id     TEXT        NOT NULL PRIMARY KEY,
            display_name  TEXT        NOT NULL,
            version       TEXT        NOT NULL DEFAULT '1.0.0',
            enabled       BOOLEAN     NOT NULL DEFAULT false,
            manifest      JSONB       NOT NULL DEFAULT '{}',
            config        JSONB       NOT NULL DEFAULT '{}',
            install_source TEXT       NOT NULL DEFAULT 'builtin',
            status        TEXT        NOT NULL DEFAULT 'disabled',
            last_error    TEXT,
            installed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_polled   TIMESTAMPTZ
        )""",
        "CREATE INDEX IF NOT EXISTS ix_plugins_source ON plugins(install_source)",
        """CREATE TABLE IF NOT EXISTS plugin_device_data (
            plugin_id   TEXT        NOT NULL,
            mac_address TEXT        NOT NULL,
            data        JSONB       NOT NULL DEFAULT '{}',
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (plugin_id, mac_address)
        )""",
        "CREATE INDEX IF NOT EXISTS ix_plugin_device_data_mac ON plugin_device_data(mac_address)",
        """CREATE TABLE IF NOT EXISTS persons (
            id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name        VARCHAR(100) NOT NULL,
            photo       TEXT,
            primary_mac VARCHAR(17),
            notes       TEXT,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS person_devices (
            person_id   UUID NOT NULL REFERENCES persons(id) ON DELETE CASCADE,
            mac_address VARCHAR(17) NOT NULL REFERENCES devices(mac_address) ON DELETE CASCADE,
            PRIMARY KEY (person_id, mac_address)
        )""",
        "CREATE INDEX IF NOT EXISTS ix_person_devices_mac ON person_devices(mac_address)",
        "ALTER TABLE block_schedules ADD COLUMN IF NOT EXISTS person_id UUID REFERENCES persons(id) ON DELETE SET NULL",
        "ALTER TABLE block_schedules ADD COLUMN IF NOT EXISTS person_ids TEXT[] DEFAULT '{}'",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS person_id UUID REFERENCES persons(id) ON DELETE SET NULL",
        "CREATE INDEX IF NOT EXISTS ix_devices_person_id ON devices(person_id)",
        "ALTER TABLE persons ADD COLUMN IF NOT EXISTS presence_state VARCHAR(10) DEFAULT 'unknown'",
        "UPDATE settings SET value='60' WHERE key='person_away_confirm_seconds' AND value='180'",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS presence_last_seen_at TIMESTAMPTZ",
    ]
    for sql in migrations:
        try:
            db.execute(text(sql))
        except Exception:
            db.rollback()
    db.commit()

    # Install primary-IP lock trigger as a DB-level backstop.
    try:
        db.execute(text("""
            CREATE OR REPLACE FUNCTION enforce_primary_ip_lock() RETURNS trigger AS $$
            BEGIN
                IF OLD.primary_ip_locked THEN
                    NEW.primary_ip := OLD.primary_ip;
                    NEW.ip_address := OLD.ip_address;
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
        """))
        db.execute(text("DROP TRIGGER IF EXISTS trg_enforce_primary_ip_lock ON devices"))
        db.execute(text("""
            CREATE TRIGGER trg_enforce_primary_ip_lock
                BEFORE UPDATE ON devices
                FOR EACH ROW
                EXECUTE FUNCTION enforce_primary_ip_lock()
        """))
        db.commit()
    except Exception as _te:
        print(f"[migrate] primary_ip_lock trigger (non-fatal): {_te}", flush=True)
        db.rollback()

    _cu.migrate(db)


DEFAULT_SETTINGS = {
    "scan_interval":           ("60",    "How often to sweep the network, in seconds."),
    "offline_miss_threshold":  ("8",     "Legacy: number of missed sweeps before offline (superseded by presence_grace_seconds)."),
    "presence_grace_seconds":  ("240",   "Seconds without any network signal before a device is marked offline (default 4 minutes)."),
    "person_presence_cooldown":    ("600",  "Minimum seconds between repeated 'Arrived home' notifications for the same person."),
    "person_away_confirm_seconds": ("60",   "Seconds all devices must stay offline before 'Left home' is sent. The probe's offline grace period already filters very short dropouts; this adds a small extra buffer. Default 60s."),
    "sniffer_workers":         ("4",     "Number of parallel scanner threads."),
    "ip_range":                ("192.168.0.0/24", "CIDR range to scan."),
    "arp_scan_retry":          ("1", "ARP sweep retry rounds (0 = single pass, 1 = two rounds). Higher values increase broadcast traffic but may catch more sleeping devices. The passive sniffer catches most devices that miss sweeps."),
    "primary_ip_mode":         ("locked", "How the probe updates a device's primary IP. locked: respects the per-device IP lock flag — locked devices never have their primary IP auto-changed. dynamic: always adopts the current IP as primary when a device returns from offline (mirrors InSpectre-main behaviour)."),
    "notifications_enabled":              ("true",  "Show popup toasts when new devices appear or go offline."),
    "browser_notifications_enabled":      ("false", "Show OS-level browser notifications for device events."),
    "pushbullet_api_key":                 ("",      "Pushbullet API access token for push notifications."),
    "vuln_scan_templates":      (
        "cve,exposure,misconfig,default-login,network",
        "Comma-separated Nuclei template tags used for vulnerability scanning."
    ),
    "vuln_scan_schedule":      ("disabled", "Scheduled vulnerability scan interval. Options: disabled, 6h, 12h, 24h, weekly."),
    "vuln_scan_targets":       ("important", "Devices to include in scheduled scans. Options: all, important."),
    "vuln_scan_on_new_device": ("false", "Automatically run a vulnerability scan when a new device is first discovered."),
    "nuclei_template_update_interval": ("24h", "How often to update Nuclei templates. Options: disabled, 12h, 24h, 48h, weekly."),
    "alert_on_port_change":    ("true",   "Send an alert when a device's open ports change."),
    "alert_on_new_device":     ("false",  "Send an alert when a new device is discovered."),
    "alert_on_offline":        ("false",  "Send an alert when a watched device goes offline."),
    "alert_on_vuln":           ("false",  "Send an alert when a vulnerability scan finds issues."),
    "alert_webhook_url":       ("",       "HTTP POST webhook URL for alerts (leave blank to disable)."),
    "ntfy_url":                ("https://ntfy.sh", "ntfy server base URL."),
    "ntfy_topic":              ("",       "ntfy topic name (leave blank to disable ntfy alerts)."),
    "gotify_url":              ("",       "Gotify server URL (leave blank to disable)."),
    "gotify_token":            ("",       "Gotify application token."),
    "network_paused":          ("false",  "Whether internet access is paused for the whole network via ARP blocking."),
    "nightly_scan_start":            ("2",     "Hour (0-23) when the nightly deep-scan window opens."),
    "nightly_scan_end":              ("4",     "Hour (0-23) when the nightly deep-scan window closes."),
    "offline_rescan_hours":          ("24",     "Hours a device must be offline before triggering a rescan on return."),
    "baseline_scan_count_threshold": ("3",     "Consecutive matching scans required to confirm a port baseline."),
    "vuln_scan_on_port_change":      ("false", "Auto-trigger a vulnerability scan when a new port is detected above baseline."),
    "traffic_enabled":         ("true",   "Enable per-device traffic monitoring feature."),
    "traffic_retention_days":  ("30",     "Number of days to retain traffic_stats rows before deletion."),
    "traffic_max_sessions":    ("10",     "Maximum number of concurrent traffic monitor sessions."),
    "traffic_geoip_path":      ("/opt/geoip/GeoLite2-Country.mmdb", "Path to MaxMind GeoLite2-Country mmdb file on the probe."),
    "speedtest_schedule":      ("disabled", "Scheduled speed test interval. Options: disabled, 30m, 1h, 6h, 24h."),
    "auto_block_new_devices":    ("false", "Automatically block newly discovered devices until manually approved."),
    "auto_block_vuln_severity":  ("none",  "Minimum vuln severity to trigger auto-block. Options: none, medium, high, critical."),
    "block_method":    ("arp",  "Active blocking method: arp (probe ARP poisoning), dns (AdGuard Home / Pi-hole), infrastructure (TP-Link Omada / UniFi)."),
    "block_plugin_id": ("",    "Plugin ID used for blocking when block_method is not arp. Must be an enabled plugin with blocking capability and block_client/unblock_client actions defined."),
    "auto_group_by_hostname":    ("true",  "Automatically group devices with the same hostname as the same physical device on a different interface (e.g. laptop switching between WiFi and Ethernet). When disabled, a suggestion event is written instead."),
    "scan_grouped_members":      ("false", "Also port-scan and vulnerability-scan the IP of every interface in a device group. By default only the group's primary interface is scanned, since grouped interfaces belong to the same physical host. Enable to scan each interface IP separately."),
    "dns_server":                ("",      "LAN DNS server IP (auto-detected if blank). Set this to your router's IP for best hostname resolution."),
    "probe_interface":           ("",      "Network interface the probe uses for scanning (e.g. eth0, eno1). Auto-detected on startup if blank; changes apply immediately via Settings → Apply."),
    "fingerbank_api_key":        ("",      "Fingerbank API key for cloud-based DHCP device identification. Get a free key at fingerbank.org. Leave blank to disable."),
    "float_new_to_top":          ("true",  "Surface unacknowledged new devices and containers to the top of the list."),
    "setup_complete":            ("false", "Whether the initial setup wizard has been completed."),
    "docker_enabled":            ("false", "Enable Docker container monitoring."),
    "docker_host":               ("unix:///var/run/docker.sock", "Docker host — socket path (unix:///var/run/docker.sock) or TCP URL (tcp://host:2375)."),
    "docker_tls_verify":         ("false", "Enable TLS verification for Docker TCP connections."),
    "trivy_db_update_frequency": ("1d",   "How often to refresh the Trivy vulnerability database. Options: disabled, 1d, 2d, 7d, 30d."),
    "docker_scan_on_new":        ("false", "Automatically run a Trivy vuln scan when a new container is created."),
    "docker_scan_on_update":     ("false", "Automatically run a Trivy vuln scan when a container is recreated with an updated image."),
    "container_auto_update":           ("disabled", "What to do when an update is detected. Options: disabled, notify, scan_then_update, auto."),
    "container_update_block_critical": ("true",     "Block container updates if the new image contains critical-severity CVEs."),
    "container_backup_enabled":        ("true",     "Automatically save a full config backup before any container update."),
    "container_update_health_timeout": ("30",       "Seconds to wait for a container health check after an update before triggering rollback."),
    "container_update_stagger_seconds":("30",       "Delay in seconds between sequential container updates when running an auto-update batch."),
    "container_update_pin_labels":     ("true",     "Honour the com.inspectre.update.pin=true Docker label to exclude containers from auto-updates."),
    "container_check_enabled": ("false", "Enable scheduled container image update checks."),
    "container_check_hour":    ("3",     "Hour of day (0-23, UTC) to run container update checks."),
    "container_check_days":    ("[]",    "JSON array of JS day-of-week ints (0=Sun…6=Sat) to run checks. Empty = every day."),
    "speedtest_expected_download":   ("0",   "Expected/contracted download speed in Mbps. Set to 0 to disable speed test alerts."),
    "speedtest_expected_upload":     ("0",   "Expected/contracted upload speed in Mbps. Set to 0 to disable upload speed alerts."),
    "speedtest_alert_threshold":     ("80",  "Speed must drop below this percentage of expected before a speedtest.degraded_download alert fires."),
    "device_returned_days":          ("7",   "Days a device must be absent before a device.returned notification fires when it rejoins."),
    "traffic_suspicious_countries":  ("",    "Comma-separated ISO-3166 country codes to flag (e.g. CN,RU,KP). Leave blank to disable."),
    "enable_arp_sweep":              ("true",  "Run active ARP broadcast sweeps to discover devices on the configured subnet."),
    "enable_passive_sniffer":        ("true",  "Run the passive ARP sniffer that listens for ARP traffic. Disable to stop all passive packet capture. Takes effect immediately."),
    "sniffer_subnet_filter":         ("true",  "Restrict the passive sniffer to the configured IP range only. Disable if you want the sniffer to capture ARP traffic from all subnets on the interface."),
    "enable_hostname_resolution":    ("true",  "Attempt DNS hostname resolution for discovered devices. Disable to stop all reverse-DNS lookups."),
    "hostname_cooldown_hours":       ("24",    "Minimum hours between hostname resolution retries for each device. Lower values increase DNS query frequency."),
    "enable_port_scanning":          ("true",  "Run TCP port scans on discovered devices. Disable to stop all port scanning activity."),
    "port_scan_method":              ("tcp_connect", "Port scan method: tcp_connect (standard socket, no special privileges) or scapy_syn (raw SYN packets, requires CAP_NET_RAW — already granted in the default probe container)."),
    "port_scan_workers":             ("200",   "Number of concurrent TCP threads used per port scan (tcp_connect method only). Lower values reduce network load but increase scan time."),
    "gateway_scan_workers":          ("50",    "Number of concurrent TCP threads when port scanning the default gateway. Kept lower than regular scans to avoid overwhelming the gateway device."),
    "enable_service_fingerprinting": ("true",  "Run Nerva service fingerprinting after each port scan to identify services on open ports."),
    "enable_mdns":                   ("true",  "Run mDNS discovery to find device names and services advertised over the local mDNS/Bonjour multicast group."),
    "enable_nightly_scan":           ("true",  "Rescan all online devices during the configured nightly scan window."),
    "enable_unscanned_retry":        ("true",  "On each sweep cycle, retry port-scanning any device that has never been successfully scanned. Disable if new devices are causing too many concurrent scans."),
    "ha_mqtt_enabled":          ("false",          "Enable Home Assistant MQTT Auto-Discovery integration."),
    "ha_mqtt_host":             ("",               "MQTT broker hostname or IP for HA integration."),
    "ha_mqtt_port":             ("1883",           "MQTT broker port for HA integration."),
    "ha_mqtt_user":             ("",               "MQTT username for HA integration (optional)."),
    "ha_mqtt_password":         ("",               "MQTT password for HA integration (optional)."),
    "ha_mqtt_discovery_prefix": ("homeassistant",  "HA MQTT discovery prefix (default: homeassistant)."),
    "ha_mqtt_state_prefix":     ("inspectre",      "InSpectre MQTT state topic prefix (default: inspectre)."),
    "timezone":              ("UTC",    "System timezone for log timestamps (appliance builds). IANA format e.g. Europe/London."),
    "auto_update_enabled":   ("false",  "Enable scheduled automatic container updates (appliance builds only)."),
    "auto_update_hour":      ("3",      "Hour of day (0-23) to run scheduled auto-updates."),
    "auto_update_days":      ("[]",     "JSON array of weekday integers to run auto-updates (0=Sun…6=Sat). Empty array = every day."),
    "new_device_threshold_enabled": ("false", "Automatically mark devices as acknowledged (no longer 'new') after a set period."),
    "new_device_threshold_value":   ("7",     "Number of time units before a device is no longer considered new."),
    "new_device_threshold_unit":    ("day",   "Time unit for new-device threshold. Options: day, week, month, year."),
    "stale_device_auto_delete_enabled": ("false", "Automatically delete devices that have not been seen for a set period. Group primary devices and important devices are never deleted."),
    "stale_device_auto_delete_value":   ("90",    "Number of time units before a stale device is auto-deleted."),
    "stale_device_auto_delete_unit":    ("day",   "Time unit for stale-device deletion threshold. Options: day, week, month, year."),
}


def _seed_settings(db: Session):
    for key, (value, description) in DEFAULT_SETTINGS.items():
        if not db.get(Setting, key):
            db.add(Setting(key=key, value=value, description=description))
    db.commit()


def _migrate_legacy_docker_host(db: Session):
    """One-time migration: if docker_enabled=true and no hosts exist, create a default host entry."""
    try:
        existing = db.execute(text("SELECT COUNT(*) FROM container_hosts")).scalar()
        if existing and existing > 0:
            return
        s_enabled = db.get(Setting, "docker_enabled")
        if not s_enabled or s_enabled.value != "true":
            return
        s_host = db.get(Setting, "docker_host")
        s_tls  = db.get(Setting, "docker_tls_verify")
        url    = (s_host.value if s_host else None) or "unix:///var/run/docker.sock"
        htype  = "docker_remote" if url.startswith("tcp://") else "docker_local"
        tls    = (s_tls and s_tls.value == "true")
        db.execute(text("""
            INSERT INTO container_hosts (name, type, url, tls_verify, enabled)
            VALUES (:name, :type, :url, :tls, true)
        """), {"name": "Local Docker", "type": htype, "url": url, "tls": tls})
        db.commit()
        print("[hosts] Migrated legacy docker settings to container_hosts table.", flush=True)
    except Exception as e:
        print(f"[hosts] Legacy migration failed (non-fatal): {e}", flush=True)
        db.rollback()


def _migrate_legacy_notifications(db: Session):
    """One-time: create notification channels from old settings if the table is empty."""
    count = db.execute(text("SELECT COUNT(*) FROM notification_channels")).scalar()
    if count:
        return

    channels = []
    ntfy_topic = db.get(Setting, "ntfy_topic")
    if ntfy_topic and ntfy_topic.value.strip():
        ntfy_url_s = db.get(Setting, "ntfy_url")
        server = ntfy_url_s.value.strip() if ntfy_url_s else "https://ntfy.sh"
        channels.append(("ntfy (migrated)", "ntfy", {"server": server, "topic": ntfy_topic.value.strip()}))

    gotify_url_s  = db.get(Setting, "gotify_url")
    gotify_tok_s  = db.get(Setting, "gotify_token")
    if gotify_url_s and gotify_url_s.value.strip() and gotify_tok_s and gotify_tok_s.value.strip():
        channels.append(("Gotify (migrated)", "gotify",
                         {"server": gotify_url_s.value.strip(), "token": gotify_tok_s.value.strip()}))

    pb_s = db.get(Setting, "pushbullet_api_key")
    if pb_s and pb_s.value.strip():
        channels.append(("Pushbullet (migrated)", "pushbullet", {"api_key": pb_s.value.strip()}))

    wh_s = db.get(Setting, "alert_webhook_url")
    if wh_s and wh_s.value.strip():
        channels.append(("Webhook (migrated)", "webhook", {"url": wh_s.value.strip()}))

    if not channels:
        return

    for name, svc, cfg in channels:
        db.execute(text(
            "INSERT INTO notification_channels (name, service, config) VALUES (:n, :s, :c)"
        ), {"n": name, "s": svc, "c": json.dumps(cfg)})
    db.commit()

    events: dict = {}
    def _flag(key):
        s = db.get(Setting, key)
        return s and s.value == "true"
    if _flag("alert_on_new_device"):
        events["device.new"] = True
    if _flag("alert_on_offline"):
        events["device.offline.watched"] = True
    if _flag("alert_on_vuln"):
        events.update({"vuln.critical": True, "vuln.high": True})
    if _flag("alert_on_port_change"):
        events["port.opened"] = True

    result = db.execute(text("""
        INSERT INTO notification_profiles (name, events)
        VALUES ('Migrated Alerts', :ev) RETURNING id
    """), {"ev": json.dumps(events)})
    profile_id = result.scalar()
    ch_ids = db.execute(text("SELECT id FROM notification_channels")).scalars().all()
    for cid in ch_ids:
        db.execute(text(
            "INSERT INTO notification_profile_channels (profile_id, channel_id) VALUES (:p, :c)"
        ), {"p": profile_id, "c": cid})
    db.commit()
    print(f"[notify] Migrated {len(channels)} legacy notification channel(s)", flush=True)


def _migrate_legacy_ha_mqtt(db: Session):
    """One-time migration: copy ha_mqtt_* settings into the home-assistant plugin config."""
    from plugin_engine import encrypt_field
    try:
        row = db.execute(
            text("SELECT config FROM plugins WHERE plugin_id = 'home-assistant'")
        ).fetchone()
        if row and isinstance(row.config, dict) and row.config.get("host"):
            return

        def _s(key, default=""):
            r = db.get(Setting, key)
            return r.value if r else default

        host = _s("ha_mqtt_host").strip()
        if not host:
            return

        password = _s("ha_mqtt_password")
        config = {
            "host":             host,
            "port":             _s("ha_mqtt_port", "1883"),
            "user":             _s("ha_mqtt_user"),
            "password":         encrypt_field(password) if password else "",
            "discovery_prefix": _s("ha_mqtt_discovery_prefix", "homeassistant"),
            "state_prefix":     _s("ha_mqtt_state_prefix", "inspectre"),
        }
        enabled = _s("ha_mqtt_enabled", "false") == "true"
        new_status = "active" if enabled else "disabled"
        db.execute(
            text("""
                UPDATE plugins
                SET config  = CAST(:config AS jsonb),
                    enabled = :enabled,
                    status  = :status
                WHERE plugin_id = 'home-assistant'
            """),
            {"config": json.dumps(config), "enabled": enabled, "status": new_status},
        )
        db.commit()
        print("[ha-mqtt] Migrated legacy ha_mqtt_* settings to plugin config.", flush=True)
    except Exception as exc:
        print(f"[ha-mqtt] Legacy migration failed (non-fatal): {exc}", flush=True)
        db.rollback()
