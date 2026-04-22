"""
Nuclei-based vulnerability scanner (runs in the PROBE container).

Workflow:
  1. Get open ports from prior nmap deep-scan (known_ports) or run a full TCP sweep.
  2. Fingerprint services on those ports with nmap -sV (if not already known).
  3. Build a per-service scan plan: HTTP/HTTPS ports → http/ template dirs,
     network services → network/ dir filtered by service tag.
  4. Run one nuclei invocation per job, streaming progress via SSE.
  5. Collect all findings, emit a single RESULT:<json> line at the end.

This routes only the relevant templates to each port rather than running all
5000+ templates against every target.

The probe runs on the host network so nmap and nuclei reach every LAN IP directly.
Called from probe/main.py's /stream/vuln-scan/{ip} SSE endpoint.
"""
import asyncio
import json
import os
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import AsyncGenerator

_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "clean": 0}

DEFAULT_TEMPLATES = "cve,exposure,misconfig,default-login,network"
DEFAULT_SEVERITY  = "critical,high,medium,low"

_HTTPS_PORTS = {443, 8443, 4443, 9443}
_HTTP_PORTS  = {80, 8080, 8000, 8008, 8888, 9000, 9090, 3000, 7080}

# HTTP template subdirectories — intentionally excludes http/cves (4000+ templates)
# CVE templates are added per-product below via _product_nuclei_tag()
_HTTP_SUBDIRS = [
    "http/misconfiguration",
    "http/default-logins",
    "http/exposed-panels",
    "http/exposures",
    "http/vulnerabilities",
]

# Map nmap product strings (lowercased substrings) → nuclei tag for http/cves filtering
_PRODUCT_TAG_MAP: list[tuple[str, str]] = [
    ("nginx",          "nginx"),
    ("apache",         "apache"),
    ("iis",            "iis"),
    ("tomcat",         "tomcat"),
    ("jenkins",        "jenkins"),
    ("jira",           "jira"),
    ("confluence",     "confluence"),
    ("wordpress",      "wordpress"),
    ("drupal",         "drupal"),
    ("joomla",         "joomla"),
    ("phpmyadmin",     "phpmyadmin"),
    ("grafana",        "grafana"),
    ("kibana",         "kibana"),
    ("elasticsearch",  "elasticsearch"),
    ("gitlab",         "gitlab"),
    ("sonarqube",      "sonarqube"),
    ("spring",         "spring"),
    ("struts",         "struts"),
    ("weblogic",       "weblogic"),
    ("websphere",      "websphere"),
    ("coldfusion",     "coldfusion"),
    ("exchange",       "exchange"),
    ("sharepoint",     "sharepoint"),
    ("citrix",         "citrix"),
    ("fortinet",       "fortinet"),
    ("palo alto",      "paloalto"),
    ("cisco",          "cisco"),
    ("mikrotik",       "mikrotik"),
    ("solarwinds",     "solarwinds"),
    ("vmware",         "vmware"),
    ("zimbra",         "zimbra"),
    ("roundcube",      "roundcube"),
    ("nextcloud",      "nextcloud"),
    ("owncloud",       "owncloud"),
]


def _product_nuclei_tag(product: str) -> str | None:
    """Map an nmap product string to a nuclei tag for http/cves filtering."""
    p = product.lower()
    for substring, tag in _PRODUCT_TAG_MAP:
        if substring in p:
            return tag
    return None

# Network template subdirectories (all network protocols; filtered by tag per job)
_NETWORK_SUBDIRS = [
    "network/cves",
    "network/default-logins",
    "network/exposed-service",
]

# nmap service name / Nerva URI scheme → nuclei tag used to filter network/ templates
_SVC_TAGS: dict[str, str] = {
    # nmap service names
    "ssh":              "ssh",
    "ftp":              "ftp",
    "telnet":           "telnet",
    "smtp":             "smtp",
    "pop3":             "pop3",
    "imap":             "imap",
    "mysql":            "mysql",
    "ms-sql-s":         "mssql",
    "microsoft-ds":     "smb",
    "netbios-ssn":      "smb",
    "smb":              "smb",
    "redis":            "redis",
    "mongodb":          "mongodb",
    "elasticsearch":    "elasticsearch",
    "vnc":              "vnc",
    "ms-wbt-server":    "rdp",
    "domain":           "dns",
    "pptp":             "network",
    # Nerva URI scheme names (supplement nmap names)
    "postgresql":       "postgresql",
    "rdp":              "rdp",
    "mqtt":             "mqtt",
    "mqtts":            "mqtt",    # TLS MQTT → same templates
    "mssql":            "mssql",
    "ldap":             "ldap",
    "ldaps":            "ldap",
    "amqp":             "network",
    "amqps":            "network",
    "cassandra":        "network",
    "memcached":        "network",
    "rpc":              "network",
    "ntp":              "network",
}

# Port-number fallbacks when nmap service detection returned nothing
_PORT_SVC_FALLBACK: dict[int, str] = {
    21:    "ftp",
    22:    "ssh",
    23:    "telnet",
    25:    "smtp",
    53:    "domain",
    110:   "pop3",
    139:   "netbios-ssn",
    143:   "imap",
    445:   "microsoft-ds",
    1723:  "pptp",
    3306:  "mysql",
    3389:  "ms-wbt-server",
    5900:  "vnc",
    5901:  "vnc",
    6379:  "redis",
    9200:  "elasticsearch",
    27017: "mongodb",
}

# Nuclei stderr noise to suppress
_NOISE_RE = re.compile(
    r"(Current nuclei version"
    r"|Current nuclei-templates version"
    r"|New templates added in latest"
    r"|nuclei-templates are not installed"
    r"|Using retries"
    r")",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bump_severity(current: str, candidate: str) -> str:
    if _SEV_RANK.get(candidate, 0) > _SEV_RANK.get(current, 0):
        return candidate
    return current


def _classify_port(port: int, svc_map: dict[int, dict]) -> str:
    """Return 'http', 'https', or the normalised service name."""
    raw = (svc_map.get(port, {}).get("service") or "").lower()
    # Nerva TLS variants that are NOT HTTP (keep as their own service category)
    if raw in _SVC_TAGS and raw not in ("https", "ssl/http", "https-alt", "wss"):
        if raw not in ("http", "http-alt", "http-proxy", "www", "ws"):
            return raw
    if port in _HTTPS_PORTS or raw in ("https", "ssl/http", "https-alt", "wss"):
        return "https"
    if port in _HTTP_PORTS or raw in ("http", "http-alt", "http-proxy", "www", "ws"):
        return "http"
    if raw in _SVC_TAGS:
        return raw
    # Fall back to port number heuristic
    return _PORT_SVC_FALLBACK.get(port, raw or "unknown")


def _existing_dirs(roots: list[str]) -> list[str]:
    return [d for d in roots if os.path.isdir(d)]


# ---------------------------------------------------------------------------
# Port / service discovery
# ---------------------------------------------------------------------------

async def _full_tcp_scan(ip: str) -> list[int]:
    """
    Full TCP-connect sweep of all 65535 ports in 1000-port chunks.
    Only called when a device has no prior port scan data.
    """
    sem = asyncio.Semaphore(200)

    async def _check(port: int) -> int | None:
        async with sem:
            try:
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=1.0
                )
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass
                return port
            except Exception:
                return None

    open_ports: list[int] = []
    for chunk_start in range(1, 65536, 1000):
        chunk = range(chunk_start, min(chunk_start + 1000, 65536))
        results = await asyncio.gather(*(_check(p) for p in chunk))
        open_ports.extend(p for p in results if p is not None)
    return sorted(open_ports)


def _parse_nmap_xml_services(xml_text: str) -> dict[int, dict]:
    """Parse nmap XML output into {port: {service, product, version, cpe}}."""
    result: dict[int, dict] = {}
    try:
        root = ET.fromstring(xml_text)
        for host in root.findall("host"):
            for port_elem in host.findall(".//port"):
                portid = int(port_elem.get("portid", 0))
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue
                svc = port_elem.find("service")
                if svc is not None:
                    result[portid] = {
                        "service": svc.get("name", ""),
                        "product": svc.get("product", ""),
                        "version": svc.get("version", ""),
                        "cpe":     " ".join(c.text for c in svc.findall("cpe") if c.text),
                    }
    except ET.ParseError:
        pass
    return result


async def _detect_services(ip: str, ports: list[int]) -> dict[int, dict]:
    """
    Run nmap -sV on specific open ports to get service/version info.
    Much faster than a full scan because the port list is already known.
    """
    if not ports:
        return {}
    port_str = ",".join(str(p) for p in sorted(ports))
    try:
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "--version-intensity", "5",
            "-p", port_str, "-T4", "-n", "--open", "-oX", "-", ip,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return {}
        return _parse_nmap_xml_services(stdout.decode(errors="replace"))
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Scan-plan builder
# ---------------------------------------------------------------------------

def _build_scan_jobs(
    ip: str,
    open_ports: list[int],
    svc_map: dict[int, dict],
    templates_root: str,
) -> list[dict]:
    """
    Partition open ports into jobs.  Each job has:
      targets       — nuclei -u arguments
      template_args — nuclei -t / -tags arguments
      label         — human-readable description
    """
    web_http:  list[str] = []
    web_https: list[str] = []
    net_by_tag: dict[str, list[str]] = {}   # nuclei_tag → [ip:port, ...]
    unknown_net: list[str] = []

    seen: set[str] = set()

    def _add(lst: list[str], t: str) -> None:
        if t not in seen:
            seen.add(t)
            lst.append(t)

    for port in open_ports:
        kind = _classify_port(port, svc_map)
        if kind == "https":
            _add(web_https, f"https://{ip}:{port}")
        elif kind == "http":
            _add(web_http, f"http://{ip}:{port}")
        else:
            target = f"{ip}:{port}"
            tag = _SVC_TAGS.get(kind)
            if tag:
                net_by_tag.setdefault(tag, [])
                _add(net_by_tag[tag], target)
            else:
                _add(unknown_net, target)

    jobs: list[dict] = []

    # ── Web job (HTTP + HTTPS share the same template directories) ───────────
    web_targets = web_http + web_https
    if web_targets:
        dirs = _existing_dirs([
            os.path.join(templates_root, d) for d in _HTTP_SUBDIRS
        ])
        if web_https:
            ssl_dir = os.path.join(templates_root, "ssl")
            if os.path.isdir(ssl_dir):
                dirs.append(ssl_dir)
        if dirs:
            jobs.append({
                "targets":       web_targets,
                "template_args": [arg for d in dirs for arg in ("-t", d)],
                "label":         f"web — {len(web_targets)} endpoint(s), {len(dirs)} template dir(s)",
            })

        # ── Product-specific CVE jobs (only for identified products) ──────────
        cves_dir = os.path.join(templates_root, "http/cves")
        if os.path.isdir(cves_dir):
            product_tags: set[str] = set()
            for port in open_ports:
                if _classify_port(port, svc_map) in ("http", "https"):
                    product = (svc_map.get(port, {}).get("product") or "").strip()
                    tag = _product_nuclei_tag(product)
                    if tag:
                        product_tags.add(tag)
            for tag in sorted(product_tags):
                jobs.append({
                    "targets":       web_targets,
                    "template_args": ["-t", cves_dir, "-tags", tag],
                    "label":         f"http-cves/{tag} — {len(web_targets)} endpoint(s)",
                })

    # ── Per-service network jobs (one per nuclei tag so -tags filters correctly)
    net_dirs = _existing_dirs([
        os.path.join(templates_root, d) for d in _NETWORK_SUBDIRS
    ])
    for tag, targets in net_by_tag.items():
        if net_dirs:
            jobs.append({
                "targets":       targets,
                "template_args": [arg for d in net_dirs for arg in ("-t", d)] + ["-tags", tag],
                "label":         f"{tag} — {len(targets)} port(s)",
            })

    # ── Unknown / unrecognised network services ──────────────────────────────
    if unknown_net and net_dirs:
        jobs.append({
            "targets":       unknown_net,
            "template_args": [arg for d in net_dirs for arg in ("-t", d)],
            "label":         f"network-generic — {len(unknown_net)} port(s)",
        })

    return jobs


# ---------------------------------------------------------------------------
# Nuclei finding parser
# ---------------------------------------------------------------------------

def _parse_nuclei_finding(line: str) -> dict | None:
    try:
        raw = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None

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


# ---------------------------------------------------------------------------
# Template updater
# ---------------------------------------------------------------------------

async def update_nuclei_templates() -> bool:
    try:
        proc = await asyncio.create_subprocess_exec(
            "nuclei", "-update-templates",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode(errors="replace").strip()
        if output:
            print(f"[nuclei] Template update output: {output[:500]}", flush=True)
        if proc.returncode == 0:
            print("[nuclei] Templates updated successfully.", flush=True)
            return True
        print(f"[nuclei] Template update exited with code {proc.returncode}", flush=True)
        return False
    except FileNotFoundError:
        print("[nuclei] nuclei binary not found.", flush=True)
        return False
    except Exception as exc:
        print(f"[nuclei] Template update error: {exc}", flush=True)
        return False


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def run_vuln_scan(
    ip: str,
    templates: str = DEFAULT_TEMPLATES,   # kept for backward-compat; not used in routing
    severity: str = DEFAULT_SEVERITY,
    known_ports: list[int] | None = None,
    port_services: dict[int, dict] | None = None,
) -> AsyncGenerator[str, None]:
    """
    Async generator — yields SSE log lines, ending with ``RESULT:<json>``.

    Phase 1  — get open ports (from known_ports or full TCP sweep).
    Phase 2  — fingerprint services with nmap -sV on those ports (skipped when
               port_services already provides that data from the deep scan).
    Phase 3  — build a per-service scan plan routing each port to the minimal
               set of nuclei template directories relevant to its service.
    Phase 4  — run one nuclei invocation per job, streaming progress live.
    Phase 5  — merge findings across all jobs and emit RESULT:<json>.
    """
    templates_root = os.path.expanduser("~/nuclei-templates")
    if not os.path.isdir(templates_root):
        yield "[WARN] Nuclei templates not found — run 'nuclei -update-templates' in the container"
    yield f"[INFO] Starting targeted vulnerability scan against {ip}…"
    t0 = time.monotonic()

    # ── Phase 1: Open ports ──────────────────────────────────────────────────
    if known_ports:
        open_ports = sorted(set(known_ports))
        yield f"[INFO] Using {len(open_ports)} known port(s): {', '.join(map(str, open_ports))}"
    else:
        yield "[INFO] No prior port data — running full TCP sweep of all 65535 ports…"
        open_ports = await _full_tcp_scan(ip)
        if open_ports:
            yield f"[INFO] TCP sweep: {len(open_ports)} open port(s): {', '.join(map(str, open_ports))}"
        else:
            yield "[INFO] No open ports found — scanning default HTTP/HTTPS endpoints"

    # ── Phase 2: Service fingerprinting ─────────────────────────────────────
    svc_map: dict[int, dict] = dict(port_services) if port_services else {}
    missing = [p for p in open_ports if not (svc_map.get(p, {}).get("service") or "").strip()]
    if missing:
        yield f"[INFO] Fingerprinting {len(missing)} service(s) with nmap -sV…"
        detected = await _detect_services(ip, missing)
        svc_map.update(detected)
        svc_lines = [
            f"{p}/{detected[p]['service']}"
            for p in sorted(detected)
            if detected[p].get("service")
        ]
        if svc_lines:
            yield f"[INFO] Services detected: {', '.join(svc_lines)}"

    # ── Phase 3: Scan plan ───────────────────────────────────────────────────
    if open_ports:
        jobs = _build_scan_jobs(ip, open_ports, svc_map, templates_root)
    else:
        # No open ports — fall back to default HTTP/HTTPS probe
        dirs = _existing_dirs([os.path.join(templates_root, d) for d in _HTTP_SUBDIRS])
        ssl_dir = os.path.join(templates_root, "ssl")
        if os.path.isdir(ssl_dir):
            dirs.append(ssl_dir)
        jobs = [{
            "targets":       [f"http://{ip}", f"https://{ip}"],
            "template_args": [arg for d in dirs for arg in ("-t", d)],
            "label":         "web (default endpoints)",
        }] if dirs else []

    if not jobs:
        yield "[WARN] No applicable templates found for detected services"
        yield (
            f'RESULT:{{"severity":"clean","vuln_count":0,"findings":[],'
            f'"duration_s":0,"scanned_at":"{datetime.now(timezone.utc).isoformat()}"}}'
        )
        return

    yield f"[INFO] Scan plan: {len(jobs)} phase(s) — " + " | ".join(j["label"] for j in jobs)

    # ── Phase 4: Run nuclei per job ──────────────────────────────────────────
    all_findings: list[dict] = []
    all_raw: list[str] = []

    for job in jobs:
        yield f"[INFO] → {job['label']}"
        cmd = [
            "nuclei",
            "-jsonl",
            "-no-color",
            "-duc",                          # disable update check
            "-ni",                           # no interactsh
            "-severity", severity,
            "-exclude-tags", "nmap",
            "-timeout", "10",
            "-retries", "1",
            "-rate-limit", "150",
            "-c", "25",
            "-bs", "25",
            "-stats", "-stats-interval", "10",
            *job["template_args"],
            *[arg for t in job["targets"] for arg in ("-u", t)],
        ]

        stdout_chunks: list[str] = []

        try:
            devnull_in = open(os.devnull, "rb")
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=devnull_in,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            async def _collect_stdout() -> None:
                assert proc.stdout
                async for chunk in proc.stdout:
                    stdout_chunks.append(chunk.decode(errors="replace"))

            stdout_task = asyncio.create_task(_collect_stdout())

            assert proc.stderr
            async for raw in proc.stderr:
                line = raw.decode(errors="replace").rstrip()
                if not line or _NOISE_RE.search(line):
                    continue
                yield f"[NUCLEI] {line}"

            await stdout_task
            await proc.wait()
            devnull_in.close()

            if proc.returncode not in (0, 1):
                yield f"[WARN] nuclei exited {proc.returncode} for: {job['label']}"
                for err_line in "".join(stdout_chunks).splitlines():
                    s = err_line.strip()
                    if s and not _parse_nuclei_finding(err_line):
                        yield f"[NUCLEI-ERR] {s[:300]}"

        except FileNotFoundError:
            yield "[ERROR] nuclei binary not found — rebuild the probe container (./inspectre.sh rebuild)"
            yield 'RESULT:{"severity":"clean","vuln_count":0,"findings":[],"error":"nuclei_not_found"}'
            return
        except Exception as exc:
            yield f"[ERROR] Phase failed ({job['label']}): {exc}"
            continue

        raw_text = "".join(stdout_chunks)
        all_raw.append(raw_text)
        for line in raw_text.splitlines():
            f = _parse_nuclei_finding(line)
            if f:
                all_findings.append(f)

    # ── Phase 5: Surface findings and emit RESULT ────────────────────────────
    for f in all_findings:
        matched = f.get("matched_at") or f.get("host", "")
        yield f"[{f['severity'].upper()}] {f['name']} — {matched}"

    duration = round(time.monotonic() - t0, 1)
    highest = "clean"
    for f in all_findings:
        highest = _bump_severity(highest, f["severity"])

    yield f"[INFO] Scan complete in {duration}s — {len(all_findings)} finding(s), highest: {highest}"

    summary = {
        "severity":   highest,
        "vuln_count": len(all_findings),
        "findings":   all_findings,
        "duration_s": duration,
        "raw_output": "\n---\n".join(all_raw),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }
    yield f"RESULT:{json.dumps(summary)}"
