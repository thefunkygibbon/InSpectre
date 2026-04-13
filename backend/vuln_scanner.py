"""
Phase 3 — Vulnerability Scanner

Runs Nmap NSE vulnerability scripts against a target IP and parses the output
into structured findings.  Designed to be called from an async SSE endpoint so
progress lines stream back to the browser in real time.

Architecture
------------
nmap is invoked with ``-oN -`` which writes its normal-format output directly
to stdout.  We capture stdout in full after the process exits, then parse it.

stderr is read line-by-line while the scan runs so progress/timing lines
(emitted by ``-v``) can be streamed to the UI in real time.  Pure noise lines
(e.g. "Error in input stream", NSE pre/post scan chatter) are suppressed.

stdin is /dev/null for the full lifetime of the subprocess to prevent nmap
from trying to read a target list from the terminal on some kernel versions.
"""
import asyncio
import os
import re
import time
from datetime import datetime, timezone
from typing import AsyncGenerator

# ---------------------------------------------------------------------------
# NSE script set
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

# -sV is required for vulners to cross-reference CVEs.
# -v makes nmap write timing/progress to stderr so the UI isn't silent.
# -oN - writes normal-format results to stdout so we can capture them directly.
DEFAULT_EXTRA_ARGS = "-T4 --open -sV --version-intensity 5 -v -oN -"

# Lines from nmap stderr (or stdout noise) that are pure noise — suppress them
_NOISE_RE = re.compile(
    r"(Error in input stream"
    r"|NSE: Loaded"
    r"|NSE: Script Pre-scanning"
    r"|NSE: Script Post-scanning"
    r"|Initiating.*Ping Scan"
    r"|Scanning.*\["
    r"|Completed.*Ping Scan"
    r")",
    re.IGNORECASE,
)

# Severity ordering
_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "clean": 0}


def _bump_severity(current: str, candidate: str) -> str:
    if _SEV_RANK.get(candidate, 0) > _SEV_RANK.get(current, 0):
        return candidate
    return current


async def _validate_scripts(scripts: str) -> tuple[str, list[str]]:
    """
    Run ``nmap --script-help <scripts>`` to check which script names nmap
    recognises.  Returns (valid_csv, rejected_list).
    """
    rejected: list[str] = []
    names = [s.strip() for s in scripts.split(",") if s.strip()]

    try:
        devnull = open(os.devnull, "rb")
        proc = await asyncio.create_subprocess_exec(
            "nmap", "--script-help", ",".join(names),
            stdin=devnull,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr_bytes = await proc.communicate()
        devnull.close()
        stderr_text = stderr_bytes.decode(errors="replace")

        bad_re = re.compile(r"'([^']+)'\s+did not match")
        rejected = bad_re.findall(stderr_text)

        if rejected:
            valid = [n for n in names if n not in rejected]
            return ",".join(valid), rejected
    except FileNotFoundError:
        pass

    return scripts, []


def _parse_nmap_output(raw: str) -> tuple[list[dict], str]:
    """
    Parse NSE script output blocks from nmap normal-format output.
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
        title_lines = [ln.lstrip("| ").strip() for ln in block_lines[1:] if ln.strip().lstrip("|").strip()]
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
    extra_args: str = DEFAULT_EXTRA_ARGS,
) -> AsyncGenerator[str, None]:
    """
    Async generator — yields log lines for SSE streaming.
    Final line is always ``RESULT:<json>``.
    """
    import json

    yield f"[INFO] Starting vulnerability scan against {ip}…"

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
        ip,
    ]

    yield f"[INFO] Command: {' '.join(cmd)}"

    t0 = time.monotonic()

    devnull_in = open(os.devnull, "rb")
    stdout_chunks: list[str] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=devnull_in,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Stream stderr live for progress; collect stdout silently for parsing.
        async def _collect_stdout() -> None:
            async for chunk in proc.stdout:
                stdout_chunks.append(chunk.decode(errors="replace"))

        async def _stream_stderr() -> None:
            async for raw in proc.stderr:
                line = raw.decode(errors="replace").rstrip()
                if not line:
                    continue
                if _NOISE_RE.search(line):
                    continue
                yield f"[NMAP] {line}"

        # Run both coroutines concurrently while waiting for the process.
        stderr_lines: list[str] = []
        async def _collect_stderr() -> None:
            async for line in _stream_stderr():
                stderr_lines.append(line)

        await asyncio.gather(
            _collect_stdout(),
            _collect_stderr(),
        )
        await proc.wait()

        for line in stderr_lines:
            yield line

        rc = proc.returncode
        if rc not in (0, 1):
            yield f"[WARN] nmap exited with code {rc}"

    except FileNotFoundError:
        yield "[ERROR] nmap not found — is it installed in the backend container?"
        yield 'RESULT:{"severity":"clean","vuln_count":0,"findings":[],"error":"nmap_not_found"}'
        return
    except Exception as exc:
        yield f"[ERROR] Scan failed: {exc}"
        yield f'RESULT:{{"severity":"clean","vuln_count":0,"findings":[],"error":"{exc}"}}'
        return
    finally:
        devnull_in.close()

    raw_text = "".join(stdout_chunks)

    duration = round(time.monotonic() - t0, 1)
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
