"""
Nuclei-based vulnerability scanner (runs in the PROBE container).

Workflow:
  1. nmap quick port-scan to discover open services on the target IP
  2. Build HTTP/HTTPS/raw target strings from the discovered ports
  3. Run Nuclei in JSONL mode (-json) against all targets
  4. Stream Nuclei's stderr (progress/stats) live to keep the SSE connection alive
  5. Collect Nuclei's stdout (JSONL findings) silently in a background task
  6. Emit per-finding summary lines, then a final RESULT:<json> line

The probe runs on the host network so both nmap and nuclei reach every LAN IP directly.
Called from probe/main.py's /stream/vuln-scan/{ip} SSE endpoint.
"""
import asyncio
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import AsyncGenerator

_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "clean": 0}

# Common service ports scanned for target discovery
DEFAULT_SCAN_PORTS = (
    "21,22,23,25,53,80,110,111,139,143,443,445,465,993,995,"
    "1723,3000,3306,3389,5900,5901,6379,8000,8008,8080,8081,"
    "8443,8888,9000,9090,9200,27017"
)

# Nuclei template tags suited for LAN device scanning
DEFAULT_TEMPLATES = "cve,exposure,misconfig,default-login,network"

# Severity levels included by default
DEFAULT_SEVERITY = "critical,high,medium,low"

# Ports that are definitively HTTPS
_HTTPS_PORTS = {443, 8443, 4443, 9443}
# Ports that are definitively HTTP
_HTTP_PORTS  = {80, 8080, 8000, 8008, 8888, 9000, 9090, 3000, 7080}

# Nuclei stderr lines that are pure informational noise
_NOISE_RE = re.compile(
    r"(Current nuclei version"
    r"|Current nuclei-templates version"
    r"|New templates added in latest"
    r"|nuclei-templates are not installed"
    r"|Using retries"
    r")",
    re.IGNORECASE,
)


def _bump_severity(current: str, candidate: str) -> str:
    if _SEV_RANK.get(candidate, 0) > _SEV_RANK.get(current, 0):
        return candidate
    return current


async def _quick_port_scan(ip: str, ports: str) -> list[int]:
    """nmap greppable-format scan to discover open ports. Returns sorted list."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-p", ports, "--open", "-T4", "-n", "-oG", "-", ip,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        text = stdout.decode(errors="replace")
        found: list[int] = []
        for line in text.splitlines():
            if "Ports:" in line:
                for m in re.finditer(r"(\d+)/open", line):
                    found.append(int(m.group(1)))
        return sorted(set(found))
    except Exception:
        return []


def _build_targets(ip: str, open_ports: list[int]) -> list[str]:
    """Build nuclei target strings from discovered open ports."""
    targets: list[str] = []
    seen: set[str] = set()

    def add(t: str) -> None:
        if t not in seen:
            seen.add(t)
            targets.append(t)

    for port in open_ports:
        if port in _HTTPS_PORTS:
            add(f"https://{ip}:{port}")
        elif port in _HTTP_PORTS:
            add(f"http://{ip}:{port}")
        elif port == 80:
            add(f"http://{ip}")
        elif port == 443:
            add(f"https://{ip}")
        else:
            # Ambiguous port: probe all three ways
            add(f"http://{ip}:{port}")
            add(f"https://{ip}:{port}")
            add(f"{ip}:{port}")

    # Always include bare HTTP/HTTPS for the IP itself
    if not any(t in (f"http://{ip}", f"http://{ip}:80") for t in targets):
        add(f"http://{ip}")
    if not any(t in (f"https://{ip}", f"https://{ip}:443") for t in targets):
        add(f"https://{ip}")

    return targets


def _parse_nuclei_finding(line: str) -> dict | None:
    """Parse one Nuclei JSONL output line into a normalised finding dict."""
    try:
        raw = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None

    # Only process actual template match events
    if "info" not in raw or "template-id" not in raw:
        return None

    info           = raw.get("info", {})
    classification = info.get("classification", {})

    severity = (info.get("severity") or "info").lower()
    if severity not in _SEV_RANK:
        severity = "info"

    cvss_score = classification.get("cvss-score")

    cve_raw = classification.get("cve-id", "")
    if isinstance(cve_raw, list):
        cves = [c.upper() for c in cve_raw if c]
    elif cve_raw:
        cves = [c.strip().upper() for c in str(cve_raw).split(",") if c.strip()]
    else:
        cves = []

    reference = info.get("reference", [])
    if isinstance(reference, str):
        reference = [reference] if reference else []

    tags = info.get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]

    return {
        "template_id":  raw.get("template-id", ""),
        "name":         info.get("name") or raw.get("template-id", "Unknown"),
        "severity":     severity,
        "cvss":         float(cvss_score) if cvss_score is not None else None,
        "cvss_metrics": classification.get("cvss-metrics"),
        "cves":         cves,
        "cwe_id":       classification.get("cwe-id"),
        "description":  info.get("description"),
        "reference":    reference[:4],
        "tags":         tags[:10],
        "host":         raw.get("host", ""),
        "matched_at":   raw.get("matched-at", ""),
        "type":         raw.get("type", ""),
    }


async def run_vuln_scan(
    ip: str,
    templates: str = DEFAULT_TEMPLATES,
    severity: str = DEFAULT_SEVERITY,
    known_ports: list[int] | None = None,
) -> AsyncGenerator[str, None]:
    """
    Async generator — yields SSE log lines, ending with ``RESULT:<json>``.

    Phase 1: nmap discovers open ports (fast greppable scan, no service detection).
             Any ports already found by the nmap deep scan (known_ports) are merged in.
    Phase 2: Nuclei tests all discovered HTTP/HTTPS/raw endpoints with matching templates.
    Nuclei stdout (JSONL findings) is drained silently in a background task to prevent
    OS pipe buffer deadlock.  Nuclei stderr (progress/stats) is streamed live so the
    SSE connection stays alive through nginx.
    """
    yield f"[INFO] Starting Nuclei vulnerability scan against {ip}…"
    t0 = time.monotonic()

    # ── Phase 1: Port discovery ──────────────────────────────────────────────
    port_count = DEFAULT_SCAN_PORTS.count(",") + 1
    yield f"[INFO] Discovering open ports (checking {port_count} common ports)…"
    open_ports = await _quick_port_scan(ip, DEFAULT_SCAN_PORTS)

    # Merge ports already discovered by the nmap deep scan
    if known_ports:
        merged = sorted(set(open_ports) | set(known_ports))
        extra = sorted(set(known_ports) - set(open_ports))
        if extra:
            yield f"[INFO] Adding {len(extra)} port(s) from prior nmap scan: {', '.join(map(str, extra))}"
        open_ports = merged

    if open_ports:
        yield f"[INFO] Open ports: {', '.join(map(str, open_ports))}"
    else:
        yield "[INFO] No open ports detected — scanning default HTTP/HTTPS endpoints"

    # ── Phase 2: Build targets ───────────────────────────────────────────────
    targets = _build_targets(ip, open_ports)
    yield f"[INFO] Nuclei will test {len(targets)} endpoint(s)"

    # ── Phase 3: Run Nuclei ──────────────────────────────────────────────────
    cmd = [
        "nuclei",
        "-json",
        "-no-color",
        "-severity", severity,
        "-tags",     templates,
        "-timeout",  "10",
        "-retries",  "1",
        "-rate-limit", "100",
        "-stats", "-stats-interval", "20",
        *[arg for t in targets for arg in ("-u", t)],
    ]
    yield f"[INFO] nuclei -severity {severity} -tags {templates} — {len(targets)} target(s)"

    stdout_chunks: list[str] = []

    try:
        devnull_in = open(os.devnull, "rb")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=devnull_in,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Drain stdout silently in background — prevents OS pipe buffer deadlock
        async def _collect_stdout() -> None:
            assert proc.stdout is not None
            async for chunk in proc.stdout:
                stdout_chunks.append(chunk.decode(errors="replace"))

        stdout_task = asyncio.create_task(_collect_stdout())

        # Stream stderr in real-time so the SSE connection stays alive
        assert proc.stderr is not None
        async for raw in proc.stderr:
            line = raw.decode(errors="replace").rstrip()
            if not line:
                continue
            if _NOISE_RE.search(line):
                continue
            yield f"[NUCLEI] {line}"

        await stdout_task
        await proc.wait()
        devnull_in.close()

        if proc.returncode not in (0, 1):
            yield f"[WARN] nuclei exited with code {proc.returncode}"

    except FileNotFoundError:
        yield "[ERROR] nuclei binary not found — rebuild the probe container (./inspectre.sh rebuild)"
        yield 'RESULT:{"severity":"clean","vuln_count":0,"findings":[],"error":"nuclei_not_found"}'
        return
    except Exception as exc:
        yield f"[ERROR] Scan failed: {exc}"
        yield f'RESULT:{{"severity":"clean","vuln_count":0,"findings":[],"error":"{exc}"}}'
        return

    # ── Parse findings from collected JSONL stdout ───────────────────────────
    raw_text = "".join(stdout_chunks)
    findings: list[dict] = []
    for line in raw_text.splitlines():
        f = _parse_nuclei_finding(line)
        if f:
            findings.append(f)

    # Surface individual findings to the SSE stream before the RESULT block
    for f in findings:
        matched = f.get("matched_at") or f.get("host", "")
        yield f"[{f['severity'].upper()}] {f['name']} — {matched}"

    duration = round(time.monotonic() - t0, 1)
    highest = "clean"
    for f in findings:
        highest = _bump_severity(highest, f["severity"])

    yield f"[INFO] Scan complete in {duration}s — {len(findings)} finding(s), highest severity: {highest}"

    summary = {
        "severity":   highest,
        "vuln_count": len(findings),
        "findings":   findings,
        "duration_s": duration,
        "raw_output": raw_text,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }
    yield f"RESULT:{json.dumps(summary)}"
