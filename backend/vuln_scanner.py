"""
Phase 3 — Vulnerability Scanner

Runs Nmap NSE vulnerability scripts against a target IP and parses the output
into structured findings. Designed to be called from an async SSE endpoint so
progress lines stream back to the browser in real time.
"""
import asyncio
import re
import time
from datetime import datetime, timezone
from typing import AsyncGenerator

# ---------------------------------------------------------------------------
# NSE script set — safe, read-only scripts that don't need root for TCP connect
# ---------------------------------------------------------------------------
DEFAULT_VULN_SCRIPTS = (
    "vulners,"
    "http-vuln-cve2017-5638,"
    "http-vuln-cve2017-1001000,"
    "http-shellshock,"
    "smb-vuln-ms17-010,"
    "smb-vuln-cve-2020-0796,"
    "ssl-heartbleed,"
    "ssl-poodle,"
    "ssl-ccs-injection,"
    "ftp-vsftpd-backdoor,"
    "ftp-anon,"
    "telnet-encryption,"
    "http-csrf,"
    "http-dombased-xss,"
    "http-stored-xss"
)

# Severity ordering for comparison
_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "clean": 0}


def _bump_severity(current: str, candidate: str) -> str:
    if _SEV_RANK.get(candidate, 0) > _SEV_RANK.get(current, 0):
        return candidate
    return current


def _parse_nmap_output(raw: str) -> tuple[list[dict], str]:
    """
    Very lightweight parser — looks for NSE script output blocks that contain
    vulnerability indicators and extracts them as structured findings.
    Returns (findings_list, highest_severity).
    """
    findings: list[dict] = []
    highest = "clean"

    # Split into per-script blocks: lines starting with "| script-name:"
    script_block_re = re.compile(
        r"^\|\s+([-\w]+):\s*$",  # "| script-name:"
        re.MULTILINE,
    )
    # Alternate: "PORT   STATE  SERVICE\n...\n| script-name:"
    vuln_state_re = re.compile(
        r"STATE:\s*(VULNERABLE|LIKELY VULNERABLE|NOT VULNERABLE|UNKNOWN)",
        re.IGNORECASE,
    )
    cvss_re  = re.compile(r"cvss[\s:]+([0-9]+(\.[0-9]+)?)", re.IGNORECASE)
    cve_re   = re.compile(r"(CVE-[0-9]{4}-[0-9]+)", re.IGNORECASE)
    title_re = re.compile(r"^\|\s{4}(.*?)\s*$", re.MULTILINE)

    # Walk line by line collecting script blocks
    lines = raw.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        # Detect start of NSE output: "| script-name:"
        m = re.match(r"^\| {0,2}([-\w.]+):", line)
        if not m:
            i += 1
            continue

        script_name = m.group(1)
        block_lines = [line]
        i += 1
        while i < len(lines) and (lines[i].startswith("|") or lines[i].startswith("/_")):
            block_lines.append(lines[i])
            i += 1
        block_text = "\n".join(block_lines)

        # Determine state
        state_m = vuln_state_re.search(block_text)
        state   = state_m.group(1).upper() if state_m else None

        if state == "NOT VULNERABLE":
            continue  # skip clean results to keep the report tidy

        # Determine severity from CVSS if present, else from state
        severity = "info"
        cvss_m   = cvss_re.search(block_text)
        if cvss_m:
            score = float(cvss_m.group(1))
            if score >= 9.0:   severity = "critical"
            elif score >= 7.0: severity = "high"
            elif score >= 4.0: severity = "medium"
            else:              severity = "low"
        elif state == "VULNERABLE":
            severity = "high"
        elif state == "LIKELY VULNERABLE":
            severity = "medium"

        # Extract CVEs
        cves = list({c.upper() for c in cve_re.findall(block_text)})

        # First non-script line as title
        title_lines = [l.lstrip("| ").strip() for l in block_lines[1:] if l.strip().lstrip("|").strip()]
        title = title_lines[0] if title_lines else script_name

        findings.append({
            "script":   script_name,
            "title":    title,
            "severity": severity,
            "state":    state or "VULNERABLE",
            "cves":     cves,
            "cvss":     float(cvss_m.group(1)) if cvss_m else None,
            "detail":   block_text,
        })
        highest = _bump_severity(highest, severity)

    return findings, highest


async def run_vuln_scan(
    ip: str,
    scripts: str = DEFAULT_VULN_SCRIPTS,
    extra_args: str = "-T4 --open",
) -> AsyncGenerator[str, None]:
    """
    Async generator — yields log lines suitable for SSE `data:` fields.
    Final line is always a JSON-serialisable summary prefixed with `RESULT:`.

    Yields:
        str lines like:
            "[INFO] Starting Nmap vuln scan against 192.168.1.5"
            "Starting Nmap 7.94 ..."
            ...
            "RESULT:{\"severity\": \"high\", \"vuln_count\": 2, \"findings\": [...]}"
    """
    import json

    yield f"[INFO] Starting vulnerability scan against {ip}…"
    yield f"[INFO] Scripts: {scripts[:80]}{'…' if len(scripts) > 80 else ''}"

    cmd = [
        "nmap",
        "--script", scripts,
        *extra_args.split(),
        "-oN", "-",   # output to stdout in normal format
        ip,
    ]

    yield f"[INFO] Command: {' '.join(cmd)}"

    t0 = time.monotonic()
    raw_lines: list[str] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        async for raw in proc.stdout:
            line = raw.decode(errors="replace").rstrip()
            raw_lines.append(line)
            yield line
        await proc.wait()
    except FileNotFoundError:
        yield "[ERROR] nmap not found — is it installed in the backend container?"
        yield 'RESULT:{"severity":"clean","vuln_count":0,"findings":[],"error":"nmap_not_found"}'
        return
    except Exception as exc:
        yield f"[ERROR] Scan failed: {exc}"
        yield f'RESULT:{{"severity":"clean","vuln_count":0,"findings":[],"error":"{exc}"}}'
        return

    duration = round(time.monotonic() - t0, 1)
    raw_text = "\n".join(raw_lines)
    findings, severity = _parse_nmap_output(raw_text)

    yield f"[INFO] Scan complete in {duration}s — {len(findings)} finding(s), highest severity: {severity}"

    summary = {
        "severity":   severity,
        "vuln_count": len(findings),
        "findings":   findings,
        "duration_s": duration,
        "raw_output": raw_text,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }
    yield f"RESULT:{json.dumps(summary)}"
