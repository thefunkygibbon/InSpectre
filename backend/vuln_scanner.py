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
# NSE script set
#
# Only scripts that ship with the nmap package in Debian bookworm (apt install
# nmap) are listed here. Scripts added in later upstream releases or via
# nmap-update are intentionally omitted to avoid the
# "did not match a category, filename, or directory" fatal error.
#
# Removed:
#   smb-vuln-cve-2020-0796  – not in Debian nmap package (only upstream 7.80+)
#   http-vuln-cve2017-1001000 – absent from many distro builds
#   telnet-encryption         – absent from slim builds
#   http-csrf / http-dombased-xss / http-stored-xss – very slow; minimal value
#                                                      in a LAN context
# ---------------------------------------------------------------------------
DEFAULT_VULN_SCRIPTS = (
    "vulners,"
    "http-vuln-cve2017-5638,"
    "http-shellshock,"
    "smb-vuln-ms17-010,"
    "ssl-heartbleed,"
    "ssl-poodle,"
    "ssl-ccs-injection,"
    "ftp-vsftpd-backdoor,"
    "ftp-anon"
)

# Severity ordering for comparison
_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "clean": 0}


def _bump_severity(current: str, candidate: str) -> str:
    if _SEV_RANK.get(candidate, 0) > _SEV_RANK.get(current, 0):
        return candidate
    return current


async def _validate_scripts(scripts: str) -> tuple[str, list[str]]:
    """
    Run `nmap --script-help <scripts>` to check which script names nmap
    actually recognises. Returns (valid_csv, rejected_list).

    Falls back to returning the original string unchanged if nmap is not
    available (the caller will surface the error anyway).
    """
    rejected: list[str] = []
    names = [s.strip() for s in scripts.split(",") if s.strip()]

    try:
        proc = await asyncio.create_subprocess_exec(
            "nmap", "--script-help", ",".join(names),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr_bytes = await proc.communicate()
        stderr_text = stderr_bytes.decode(errors="replace")

        # nmap prints one line per bad script:
        # "'smb-vuln-cve-2020-0796' did not match a category, filename, or directory"
        bad_re = re.compile(r"'([^']+)'\s+did not match")
        rejected = bad_re.findall(stderr_text)

        if rejected:
            valid = [n for n in names if n not in rejected]
            return ",".join(valid), rejected
    except FileNotFoundError:
        pass  # nmap not installed — let the main path surface the error

    return scripts, []


def _parse_nmap_output(raw: str) -> tuple[list[dict], str]:
    """
    Very lightweight parser — looks for NSE script output blocks that contain
    vulnerability indicators and extracts them as structured findings.
    Returns (findings_list, highest_severity).
    """
    findings: list[dict] = []
    highest = "clean"

    vuln_state_re = re.compile(
        r"STATE:\s*(VULNERABLE|LIKELY VULNERABLE|NOT VULNERABLE|UNKNOWN)",
        re.IGNORECASE,
    )
    cvss_re = re.compile(r"cvss[\s:]+([0-9]+(\.[0-9]+)?)", re.IGNORECASE)
    cve_re  = re.compile(r"(CVE-[0-9]{4}-[0-9]+)", re.IGNORECASE)

    lines = raw.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
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

        state_m = vuln_state_re.search(block_text)
        state   = state_m.group(1).upper() if state_m else None

        if state == "NOT VULNERABLE":
            continue

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

        cves = list({c.upper() for c in cve_re.findall(block_text)})
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
    """
    import json

    yield f"[INFO] Starting vulnerability scan against {ip}…"

    # Validate scripts against the installed nmap version before running
    scripts, rejected = await _validate_scripts(scripts)
    if rejected:
        yield f"[WARN] Skipping unsupported script(s): {', '.join(rejected)}"
    if not scripts.strip(","):
        yield "[ERROR] No valid scripts remaining after validation."
        yield 'RESULT:{"severity":"clean","vuln_count":0,"findings":[],"error":"no_valid_scripts"}'
        return

    script_names = [s.strip() for s in scripts.split(",") if s.strip()]
    yield f"[INFO] Scripts: {len(script_names)} script(s) — {', '.join(script_names)}"

    cmd = [
        "nmap",
        "--script", scripts,
        *extra_args.split(),
        "-oN", "-",
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
