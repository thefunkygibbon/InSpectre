import asyncio
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone

import probe_config as _cfg
from probe_models import Session, Device
from probe_ip import _write_event

# Nuclei state — last_update tracked here, asyncio.Lock for the SSE endpoint
_last_nuclei_template_update: datetime | None = None
_nuclei_update_lock = asyncio.Lock()


def _parse_nerva_output(output: str) -> list[dict]:
    """Parse Nerva URI output into service records: [{port, service, protocol, tls}].
    Prefers the most specific (non-generic HTTP/S) scheme per port."""
    _TLS_SCHEMES  = {"https", "mqtts", "ldaps", "ftps", "imaps", "pop3s", "smtps", "rediss", "wss"}
    _HTTP_GENERIC = {"http", "https"}

    candidates: dict[int, list[tuple[str, bool]]] = {}

    for line in output.strip().splitlines():
        line = line.strip()
        if not line or "://" not in line:
            continue
        try:
            scheme, rest = line.split("://", 1)
            scheme = scheme.lower()
            tls = "(tls)" in line.lower() or scheme in _TLS_SCHEMES
            host_part = rest.split("/")[0].split(" ")[0]
            if ":" not in host_part:
                continue
            _, port_str = host_part.rsplit(":", 1)
            port = int(port_str)
            candidates.setdefault(port, []).append((scheme, tls))
        except (ValueError, IndexError):
            continue

    services: list[dict] = []
    for port, entries in sorted(candidates.items()):
        specific = [(s, t) for s, t in entries if s not in _HTTP_GENERIC]
        chosen_scheme, chosen_tls = specific[0] if specific else entries[0]
        chosen_tls = chosen_tls or any(t for _, t in entries)
        services.append({"port": port, "service": chosen_scheme, "protocol": "tcp", "tls": chosen_tls})

    return services


def _run_nerva_fingerprint(ip: str, mac: str, open_ports: list[int]) -> None:
    """Pipe open host:port pairs through Nerva and store service fingerprints.
    Always advances pipeline_stage to 'services_done' regardless of outcome."""
    services: list[dict] = []

    if open_ports:
        input_data = "\n".join(f"{ip}:{p}" for p in open_ports)
        try:
            nerva_timeout = max(300, len(open_ports) * 4)
            result = subprocess.run(
                ["nerva"],
                input=input_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=nerva_timeout,
            )
            output = (result.stdout or "").strip()
            print(f"[nerva] raw output for {ip} ({len(output)} chars, exit={result.returncode}): {output[:300]}", flush=True)
            if output:
                services = _parse_nerva_output(output)
                print(
                    f"[nerva] {ip} ({mac}): {len(services)} service(s) — "
                    + ", ".join(f"{s['service']}:{s['port']}" for s in services),
                    flush=True,
                )
            if result.returncode != 0:
                print(f"[nerva] Non-zero exit ({result.returncode}) for {ip}", flush=True)
        except FileNotFoundError:
            print(f"[nerva] Binary not found — service fingerprinting skipped for {ip}", flush=True)
        except subprocess.TimeoutExpired:
            print(f"[nerva] Timeout fingerprinting {ip}", flush=True)
        except Exception as e:
            print(f"[nerva] Error for {ip}: {e}", flush=True)

    session = Session()
    try:
        device = session.get(Device, mac)
        if device:
            scan = dict(device.scan_results or {})
            scan["services"]        = services
            scan["pipeline_stage"]  = "services_done"
            if services:
                port_map = {s["port"]: s for s in services}
                scan["open_ports"] = [
                    {**p,
                     "service": port_map[p["port"]].get("service", p.get("service", "")),
                     "tls":     port_map[p["port"]].get("tls", False)}
                    if p.get("port") in port_map else p
                    for p in (scan.get("open_ports") or [])
                ]
            device.scan_results = scan
            session.commit()
            if services:
                _write_event(mac, "service_fingerprint_complete", {
                    "service_count": len(services),
                    "services": [f"{s['service']}:{s['port']}" for s in services[:20]],
                })
    except Exception as e:
        session.rollback()
        print(f"[nerva] DB save error {mac}: {e}", flush=True)
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Nuclei template management
# ---------------------------------------------------------------------------
def _nuclei_templates_exist() -> bool:
    templates_dir = "/root/nuclei-templates"
    return os.path.isdir(templates_dir) and bool(os.listdir(templates_dir))


def _nuclei_template_update_loop() -> None:
    """Background thread that periodically runs nuclei -update-templates."""
    global _last_nuclei_template_update
    if not _nuclei_templates_exist() and shutil.which("nuclei"):
        print("[nuclei] Templates directory empty — downloading now.", flush=True)
        try:
            result = subprocess.run(
                ["nuclei", "-update-templates"],
                capture_output=True, text=True, timeout=600,
            )
            if result.returncode == 0:
                print("[nuclei] Initial template download complete.", flush=True)
                _last_nuclei_template_update = datetime.now(timezone.utc)
            else:
                print(f"[nuclei] Initial download failed (exit {result.returncode})", flush=True)
        except Exception as exc:
            print(f"[nuclei] Initial download error: {exc}", flush=True)
    time.sleep(120)
    _update_intervals = {"12h": 43200, "24h": 86400, "48h": 172800, "weekly": 604800}
    while True:
        try:
            session = Session()
            try:
                from sqlalchemy import text
                row = session.execute(
                    text("SELECT value FROM settings WHERE key = 'nuclei_template_update_interval'")
                ).fetchone()
                interval_str = row[0] if row else _cfg.NUCLEI_TEMPLATE_UPDATE_INTERVAL
            finally:
                session.close()

            if interval_str != "disabled":
                interval = _update_intervals.get(interval_str, 86400)
                now = datetime.now(timezone.utc)
                if _last_nuclei_template_update is None or (now - _last_nuclei_template_update).total_seconds() >= interval:
                    print(f"[nuclei] Updating templates (interval: {interval_str})…", flush=True)
                    result = subprocess.run(
                        ["nuclei", "-update-templates"],
                        capture_output=True, text=True, timeout=300,
                    )
                    if result.stdout:
                        print(f"[nuclei] {result.stdout.strip()[:500]}", flush=True)
                    if result.returncode == 0:
                        print("[nuclei] Templates updated successfully.", flush=True)
                        _last_nuclei_template_update = now
                    else:
                        print(f"[nuclei] Template update failed (exit {result.returncode})", flush=True)
        except FileNotFoundError:
            print("[nuclei] nuclei binary not found — skipping template update.", flush=True)
        except Exception as exc:
            print(f"[nuclei-updater] Error: {exc}", flush=True)
        time.sleep(3600)
