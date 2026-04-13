"""
Phase 3 — Vulnerability Scanner

Runs Nmap NSE vulnerability scripts against a target IP and parses the output
into structured findings.  Designed to be called from an async SSE endpoint so
progress lines stream back to the browser in real time.

Why a temp file instead of -oN -
---------------------------------
Using `-oN -` (stdout) causes nmap to detect a pipe and write progress/errors
to stderr while also writing results to stdout.  On hosts with many open ports
the SSE connection can buffer or be closed before nmap finishes, producing a
SIGPIPE that nmap reports as "Error in input stream".  Writing to a temp file
sidesteps the pipe entirely.

Why stdin=/dev/null (kept open)
-------------------------------
Nmap 7.80+ checks stdin on startup and logs "Error in input stream" if stdin
is a closed/empty pipe.  We open /dev/null and keep it open for the entire
lifetime of the subprocess — closing it early (even after create_subprocess_exec
returns) races with nmap's startup check on some kernel versions and still
triggers the message.  The fd is closed in a finally block after proc.wait().
"""
import asyncio
import os
import re
import tempfile
import time
from datetime import datetime, timezone
from typing import AsyncGenerator

# ---------------------------------------------------------------------------
# NSE script set
#
# Only scripts that ship with the nmap package in Debian bookworm are listed.
# Removed:
#   smb-vuln-cve-2020-0796    – not in Debian nmap package
#   http-vuln-cve2017-1001000 – absent from many distro builds
#   telnet-encryption         – absent from slim builds
#   http-csrf / http-dombased-xss / http-stored-xss – very slow, minimal LAN value
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

# -sV is required for the `vulners` script to cross-reference CVEs.
# --version-intensity 5 keeps it reasonably fast.
DEFAULT_EXTRA_ARGS = "-T4 --open -sV --version-intensity 5"

# Severity ordering for comparison
_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "clean": 0}


def _bump_severity(current: str, candidate: str) -> str:
    if _SEV_RANK.get(candidate, 0) > _SEV_RANK.get(current, 0):
        return candidate
    return current


async def _validate_scripts(scripts: str) -> tuple[str, list[str]]:
    """
    Run `nmap --script-help <scripts>` to check which script names nmap
    actually recognises.  Returns (valid_csv, rejected_list).
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
    Lightweight parser — looks for NSE script output blocks that contain
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
    Async generator — yields log lines suitable for SSE `data:` fields.
    Final line is always a JSON-serialisable summary prefixed with `RESULT:`.
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

    # Write to a temp file — avoids -oN - pipe issues
    tmp = tempfile.NamedTemporaryFile(
        prefix="inspectre_vuln_", suffix=".nmap", delete=False, mode="w"
    )
    tmp.close()
    outfile = tmp.name

    cmd = [
        "nmap",
        "--script", scripts,
        *extra_args.split(),
        "-oN", outfile,
        ip,
    ]

    yield f"[INFO] Command: {' '.join(cmd)}"

    t0 = time.monotonic()

    # Keep devnull_in open for the entire subprocess lifetime.
    # Closing it immediately after create_subprocess_exec races with nmap's
    # stdin check on startup and causes "Error in input stream" on stdout.
    devnull_in = open(os.devnull, "rb")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=devnull_in,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Drain stdout and stderr concurrently, tagging stderr lines with [NMAP].
        async def _drain_stdout():
            async for raw in proc.stdout:
                line = raw.decode(errors="replace").rstrip()
                if line:
                    yield line

        async def _drain_stderr():
            async for raw in proc.stderr:
                line = raw.decode(errors="replace").rstrip()
                if line:
                    yield f"[NMAP] {line}"

        # Interleave both streams via asyncio queues so neither blocks the other.
        queue: asyncio.Queue[str | None] = asyncio.Queue()

        async def _enqueue(gen):
            async for item in gen:
                await queue.put(item)

        stdout_task = asyncio.ensure_future(_enqueue(_drain_stdout()))
        stderr_task = asyncio.ensure_future(_enqueue(_drain_stderr()))

        watcher = asyncio.ensure_future(
            asyncio.gather(stdout_task, stderr_task)
        )

        async def _sentinel():
            await watcher
            await queue.put(None)  # signal done

        asyncio.ensure_future(_sentinel())

        while True:
            item = await queue.get()
            if item is None:
                break
            yield item

        await proc.wait()
        rc = proc.returncode
        if rc not in (0, 1):  # nmap exits 1 when no hosts up — that's fine
            yield f"[WARN] nmap exited with code {rc}"

    except FileNotFoundError:
        yield "[ERROR] nmap not found — is it installed in the backend container?"
        yield 'RESULT:{"severity":"clean","vuln_count":0,"findings":[],"error":"nmap_not_found"}'
        try:
            os.unlink(outfile)
        except OSError:
            pass
        return
    except Exception as exc:
        yield f"[ERROR] Scan failed: {exc}"
        yield f'RESULT:{{"severity":"clean","vuln_count":0,"findings":[],"error":"{exc}"}}'
        try:
            os.unlink(outfile)
        except OSError:
            pass
        return
    finally:
        devnull_in.close()

    # Read the completed output file for parsing
    try:
        with open(outfile, "r", errors="replace") as f:
            raw_text = f.read()
    except Exception as exc:
        yield f"[ERROR] Could not read scan output file: {exc}"
        raw_text = ""
    finally:
        try:
            os.unlink(outfile)
        except OSError:
            pass

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
