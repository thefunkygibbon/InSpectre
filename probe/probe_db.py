import time

from sqlalchemy import text

from probe_models import Base, engine, Session


def wait_for_db(retries: int = 10, delay: int = 5) -> None:
    for attempt in range(retries):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            print("[DB] Connected.", flush=True)
            return
        except Exception as e:
            print(f"[DB] Not ready ({attempt+1}/{retries}): {e}", flush=True)
            time.sleep(delay)
    raise RuntimeError("Could not connect to database.")


def init_db() -> None:
    Base.metadata.create_all(engine)
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS deep_scanned BOOLEAN DEFAULT FALSE"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS miss_count INTEGER DEFAULT 0"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS is_important BOOLEAN NOT NULL DEFAULT FALSE"))
            conn.execute(text("ALTER TABLE devices ALTER COLUMN is_important SET DEFAULT FALSE"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS primary_ip VARCHAR"))
            conn.execute(text("""
                UPDATE devices SET primary_ip = ip_address
                WHERE primary_ip IS NULL AND ip_address IS NOT NULL
            """))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS vuln_last_scanned TIMESTAMPTZ"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS vuln_severity VARCHAR"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_type_override VARCHAR"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS hostname_last_attempted TIMESTAMPTZ"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS status_changed_at TIMESTAMPTZ"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS deep_scan_last_run TIMESTAMPTZ"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS baseline_ports JSONB"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS baseline_scan_count INTEGER NOT NULL DEFAULT 0"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS primary_ip_locked BOOLEAN NOT NULL DEFAULT FALSE"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS suppress_presence_events BOOLEAN NOT NULL DEFAULT FALSE"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS group_manual BOOLEAN NOT NULL DEFAULT FALSE"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS auto_group_optout BOOLEAN NOT NULL DEFAULT FALSE"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS presence_last_seen_at TIMESTAMPTZ"))
            conn.execute(text("""
                UPDATE devices SET presence_last_seen_at = last_seen
                WHERE presence_last_seen_at IS NULL AND last_seen IS NOT NULL
            """))
            conn.commit()
        except Exception as e:
            print(f"[DB] Column migration note: {e}", flush=True)
            conn.rollback()

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS ip_history (
                id          SERIAL PRIMARY KEY,
                mac_address VARCHAR NOT NULL,
                ip_address  VARCHAR NOT NULL,
                first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                CONSTRAINT uq_ip_history_mac_ip UNIQUE (mac_address, ip_address)
            )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ip_history_mac ON ip_history (mac_address)"))
        conn.commit()

        try:
            conn.execute(text("ALTER TABLE ip_history ADD COLUMN IF NOT EXISTS seen_while_online BOOLEAN DEFAULT FALSE"))
            conn.commit()
        except Exception:
            conn.rollback()

        try:
            conn.execute(text("""
                ALTER TABLE ip_history
                    ADD CONSTRAINT uq_ip_history_mac_ip UNIQUE (mac_address, ip_address)
            """))
            conn.commit()
            print("[DB] Added uq_ip_history_mac_ip constraint.", flush=True)
        except Exception:
            conn.rollback()

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS device_events (
                id          SERIAL PRIMARY KEY,
                mac_address VARCHAR NOT NULL REFERENCES devices(mac_address) ON DELETE CASCADE,
                type        VARCHAR NOT NULL,
                detail      JSONB,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_device_events_mac     ON device_events(mac_address)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_device_events_type    ON device_events(type)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_device_events_created ON device_events(created_at)"))
        conn.commit()

        conn.execute(text("""
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
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_vuln_reports_mac      ON vuln_reports(mac_address)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_vuln_reports_scanned  ON vuln_reports(scanned_at)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_vuln_reports_severity ON vuln_reports(severity)"))
        conn.commit()

        # Hard-pin trigger: when primary_ip_locked=TRUE, the probe must never
        # overwrite primary_ip or ip_address (Python-side CASE is the primary guard;
        # this trigger is the backstop that survives any race).
        try:
            conn.execute(text("""
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
            conn.execute(text("DROP TRIGGER IF EXISTS trg_enforce_primary_ip_lock ON devices"))
            conn.execute(text("""
                CREATE TRIGGER trg_enforce_primary_ip_lock
                    BEFORE UPDATE ON devices
                    FOR EACH ROW
                    EXECUTE FUNCTION enforce_primary_ip_lock()
            """))
            conn.commit()
            print("[DB] primary_ip_lock trigger installed.", flush=True)
        except Exception as e:
            print(f"[DB] Trigger install error: {e}", flush=True)
            conn.rollback()

    print("[DB] Migrations complete.", flush=True)
