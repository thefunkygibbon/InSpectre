from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from typing import Optional, List
import asyncio, json, socket
import re as _re
import ssl as _ssl
import ipaddress as _ipaddress
import subprocess
from urllib.parse import urlparse
from database import get_db, SessionLocal
from auth_utils import get_current_user
from models import Setting
from config import PROBE_URL
from probe_client import _probe_client
from schemas import WolPayload
from email_analysis import run_email_analysis
import httpx

router = APIRouter()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_HOST_RE  = _re.compile(r'^[a-zA-Z0-9._\-]{1,253}$')
_PORTS_RE = _re.compile(r'^[\d,\-]{1,100}$')


def _validate_tool_host(host: str):
    if not host or not _HOST_RE.match(host):
        raise HTTPException(400, "Invalid host")


def _reject_ssrf_target(host: str):
    """Block SSRF to dangerous local ranges (loopback, link-local incl. cloud
    metadata 169.254.169.254, multicast, reserved). Private/LAN ranges remain
    allowed because inspecting LAN hosts is a core feature of this tool."""
    if not host:
        raise HTTPException(400, "Invalid host")
    candidates = []
    try:
        candidates = [_ipaddress.ip_address(host)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None)
            for info in infos:
                try:
                    candidates.append(_ipaddress.ip_address(info[4][0]))
                except ValueError:
                    continue
        except socket.gaierror:
            return  # let the actual request surface the DNS error
    for addr in candidates:
        if (addr.is_loopback or addr.is_link_local or addr.is_multicast
                or addr.is_reserved or addr.is_unspecified):
            raise HTTPException(400, "Refusing to connect to a restricted address")


def _validate_tool_url(url: str):
    if not url or not (url.startswith("http://") or url.startswith("https://")):
        raise HTTPException(400, "URL must start with http:// or https://")
    if len(url) > 2048:
        raise HTTPException(400, "URL too long")
    try:
        parsed = urlparse(url)
    except Exception:
        raise HTTPException(400, "Invalid URL")
    if not parsed.hostname:
        raise HTTPException(400, "Invalid URL host")
    _reject_ssrf_target(parsed.hostname)


# ---------------------------------------------------------------------------
# DNSBL list (module-level constant)
# ---------------------------------------------------------------------------
DNSBL_LISTS = [
    ("Spamhaus ZEN",     "zen.spamhaus.org"),
    ("Spamhaus SBL",     "sbl.spamhaus.org"),
    ("Barracuda",        "b.barracudacentral.org"),
    ("SORBS SPAM",       "spam.sorbs.net"),
    ("UCEProtect L1",    "dnsbl-1.uceprotect.net"),
    ("SpamCop",          "bl.spamcop.net"),
    ("NordSpam",         "combined.njabl.org"),
]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/tools/ping")
async def tools_ping(host: str = Query(...)):
    _validate_tool_host(host)

    async def _gen():
        try:
            async with _probe_client(timeout=None) as client:
                async with client.stream("GET", f"{PROBE_URL}/stream/tools/ping",
                                         params={"host": host}) as resp:
                    async for line in resp.aiter_lines():
                        yield f"{line}\n"
        except httpx.ConnectError:
            yield f"data: [ERROR] Cannot reach probe at {PROBE_URL}\n\n"
        except Exception as e:
            yield f"data: [ERROR] {e}\n\n"

    return StreamingResponse(_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/tools/traceroute")
async def tools_traceroute(host: str = Query(...)):
    _validate_tool_host(host)

    async def _gen():
        try:
            async with _probe_client(timeout=None) as client:
                async with client.stream("GET", f"{PROBE_URL}/stream/tools/traceroute",
                                         params={"host": host}) as resp:
                    async for line in resp.aiter_lines():
                        yield f"{line}\n"
        except httpx.ConnectError:
            yield f"data: [ERROR] Cannot reach probe at {PROBE_URL}\n\n"
        except Exception as e:
            yield f"data: [ERROR] {e}\n\n"

    return StreamingResponse(_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/tools/portscan")
async def tools_portscan(host: str = Query(...), ports: str = Query("1-1024")):
    _validate_tool_host(host)
    if not _PORTS_RE.match(ports):
        raise HTTPException(400, "Invalid ports specification")

    async def _gen():
        try:
            async with _probe_client(timeout=None) as client:
                async with client.stream("GET", f"{PROBE_URL}/stream/tools/portscan",
                                         params={"host": host, "ports": ports}) as resp:
                    async for line in resp.aiter_lines():
                        yield f"{line}\n"
        except httpx.ConnectError:
            yield f"data: [ERROR] Cannot reach probe at {PROBE_URL}\n\n"
        except Exception as e:
            yield f"data: [ERROR] {e}\n\n"

    return StreamingResponse(_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/tools/dns")
async def tools_dns(host: str = Query(...), type: str = Query("A")):
    import dns.resolver
    _validate_tool_host(host)
    ALL_TYPES = ["A", "AAAA", "MX", "CNAME", "TXT", "NS", "SOA", "PTR", "SRV", "CAA", "DNSKEY", "DS", "NAPTR"]
    valid_types = set(ALL_TYPES)
    qtype = type.upper()

    if qtype == "ALL":
        results = []
        for t in ALL_TYPES:
            try:
                answers = dns.resolver.resolve(host, t, lifetime=5)
                for r in answers:
                    results.append({"type": t, "value": str(r), "ttl": answers.rrset.ttl})
            except Exception:
                pass
        return {"host": host, "type": "ALL", "all_records": results, "error": None}

    if qtype not in valid_types:
        raise HTTPException(400, f"Type must be one of: {', '.join(sorted(valid_types))} or ALL")
    try:
        answers = dns.resolver.resolve(host, qtype, lifetime=10)
        return {"host": host, "type": qtype,
                "records": [str(r) for r in answers],
                "ttl": answers.rrset.ttl, "error": None}
    except dns.resolver.NXDOMAIN:
        return {"host": host, "type": qtype, "records": [], "ttl": None,
                "error": "NXDOMAIN — domain does not exist"}
    except dns.resolver.NoAnswer:
        return {"host": host, "type": qtype, "records": [], "ttl": None,
                "error": "No records of that type found"}
    except Exception as e:
        return {"host": host, "type": qtype, "records": [], "ttl": None, "error": str(e)}


@router.get("/tools/rdns")
async def tools_rdns(ip: str = Query(...)):
    try:
        _ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Invalid IP address")
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return {"ip": ip, "hostname": hostname, "error": None}
    except socket.herror:
        return {"ip": ip, "hostname": None, "error": "No reverse DNS record found"}
    except Exception as e:
        return {"ip": ip, "hostname": None, "error": str(e)}


@router.get("/tools/dns-propagation")
async def tools_dns_propagation(host: str = Query(...), type: str = Query("A")):
    import dns.resolver
    _validate_tool_host(host)
    qtype = type.upper()
    if qtype not in {"A", "AAAA", "MX", "CNAME", "TXT", "NS"}:
        raise HTTPException(400, "Invalid record type")

    servers = {
        "Google (8.8.8.8)":         "8.8.8.8",
        "Google (8.8.4.4)":         "8.8.4.4",
        "Cloudflare (1.1.1.1)":     "1.1.1.1",
        "Cloudflare (1.0.0.1)":     "1.0.0.1",
        "OpenDNS (208.67.222.222)": "208.67.222.222",
        "OpenDNS (208.67.220.220)": "208.67.220.220",
        "Quad9 (9.9.9.9)":          "9.9.9.9",
        "AdGuard (94.140.14.14)":   "94.140.14.14",
    }

    async def _query(name: str, ns_ip: str) -> dict:
        def _resolve():
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [ns_ip]
            resolver.timeout = 4
            resolver.lifetime = 4
            return [str(r) for r in resolver.resolve(host, qtype)]
        try:
            records = await asyncio.get_event_loop().run_in_executor(None, _resolve)
            return {"name": name, "ip": ns_ip, "records": records, "error": None}
        except dns.resolver.NXDOMAIN:
            return {"name": name, "ip": ns_ip, "records": [], "error": "NXDOMAIN"}
        except dns.resolver.NoAnswer:
            return {"name": name, "ip": ns_ip, "records": [], "error": "No answer"}
        except Exception as e:
            return {"name": name, "ip": ns_ip, "records": [], "error": str(e)[:80]}

    results = await asyncio.gather(*[_query(n, ip) for n, ip in servers.items()])
    return {"host": host, "type": qtype, "results": results}


@router.get("/tools/http-headers")
async def tools_http_headers(url: str = Query(...)):
    _validate_tool_url(url)
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False, verify=False) as client:
            resp = await client.get(url)
            return {
                "url": url,
                "status": resp.status_code,
                "reason": resp.reason_phrase,
                "headers": dict(resp.headers),
                "redirect": resp.headers.get("location"),
            }
    except httpx.ConnectError as e:
        raise HTTPException(502, f"Connection failed: {e}")
    except httpx.TimeoutException:
        raise HTTPException(504, "Request timed out")
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/tools/ssl")
async def tools_ssl(host: str = Query(...), port: int = Query(443)):
    _validate_tool_host(host)
    if not (1 <= port <= 65535):
        raise HTTPException(400, "Invalid port")

    def _check() -> dict:
        import socket as _sock
        ctx = _ssl.create_default_context()
        try:
            with ctx.wrap_socket(_sock.socket(), server_hostname=host) as s:
                s.settimeout(10)
                s.connect((host, port))
                cert = s.getpeercert()
                cipher = s.cipher()
                return {
                    "host": host, "port": port, "valid": True,
                    "subject": {k: v for tup in cert.get("subject", []) for k, v in tup},
                    "issuer":  {k: v for tup in cert.get("issuer",  []) for k, v in tup},
                    "not_before": cert.get("notBefore"),
                    "not_after":  cert.get("notAfter"),
                    "san": [v for t, v in cert.get("subjectAltName", []) if t == "DNS"],
                    "serial": cert.get("serialNumber"),
                    "version": cert.get("version"),
                    "cipher": cipher[0] if cipher else None,
                    "protocol": cipher[1] if cipher else None,
                    "error": None,
                }
        except _ssl.SSLCertVerificationError as e:
            return {"host": host, "port": port, "valid": False,
                    "subject": {}, "issuer": {}, "not_before": None, "not_after": None,
                    "san": [], "serial": None, "version": None, "cipher": None,
                    "protocol": None, "error": f"Certificate verification failed: {e}"}
        except ConnectionRefusedError:
            raise HTTPException(502, f"Connection refused to {host}:{port}")
        except _sock.timeout:
            raise HTTPException(504, "Connection timed out")
        except Exception as e:
            raise HTTPException(500, str(e))

    try:
        return await asyncio.get_event_loop().run_in_executor(None, _check)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/tools/geo")
async def tools_geo(ip: str = Query(...)):
    try:
        _ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Invalid IP address")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"},
            )
            return resp.json()
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/tools/whois")
async def tools_whois(host: str = Query(...)):
    _validate_tool_host(host)
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: subprocess.run(["whois", host],
                                   capture_output=True, text=True, timeout=20)
        )
        output = (result.stdout or result.stderr or "").strip()
        return {"host": host, "output": output[:8000]}
    except FileNotFoundError:
        raise HTTPException(501, "whois binary not available")
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "WHOIS query timed out")
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/tools/email")
async def tools_email(domain: str = Query(...)):
    import dns.resolver as _dns_res
    _validate_tool_host(domain)
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, run_email_analysis, domain)
        data = result.to_dict()
        try:
            data["nameservers"] = [str(r) for r in _dns_res.resolve(domain, "NS", lifetime=8)]
        except Exception:
            data["nameservers"] = []
        return data
    except Exception as exc:
        raise HTTPException(500, str(exc))


# ---------------------------------------------------------------------------
# ARP lookup + Wake-on-LAN (proxied to probe)
# ---------------------------------------------------------------------------
@router.get("/tools/arp-lookup")
async def tools_arp_lookup(query: str = Query(...)):
    try:
        async with _probe_client(timeout=10) as client:
            resp = await client.get(f"{PROBE_URL}/tools/arp-table")
            data = resp.json()
        entries = data.get("entries", [])
        q = query.strip().lower()
        matches = [e for e in entries if q in e.get("ip", "").lower() or q in e.get("mac", "").lower()]
        return {"query": query, "matches": matches, "total": len(entries)}
    except Exception as exc:
        return {"query": query, "matches": [], "error": str(exc)}


@router.post("/tools/wake-on-lan")
async def tools_wake_on_lan(payload: WolPayload):
    try:
        async with _probe_client(timeout=10) as client:
            resp = await client.post(f"{PROBE_URL}/tools/wake-on-lan",
                                     json={"mac": payload.mac, "broadcast": payload.broadcast})
            return resp.json()
    except Exception as exc:
        raise HTTPException(500, str(exc))


# ---------------------------------------------------------------------------
# DNS over HTTPS tester
# ---------------------------------------------------------------------------
@router.get("/tools/doh")
async def tools_doh(host: str = Query(...), type: str = Query("A")):
    _validate_tool_host(host)
    qtype = type.upper()
    resolvers = {
        "Cloudflare (1.1.1.1)": "https://cloudflare-dns.com/dns-query",
        "Google (8.8.8.8)":     "https://dns.google/resolve",
        # Use IP directly for Quad9 to avoid DNS resolution issues in containers
        "Quad9 (9.9.9.9)":      "https://9.9.9.9/dns-query",
    }
    results = []
    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        for name, url in resolvers.items():
            try:
                resp = await client.get(url, params={"name": host, "type": qtype},
                                        headers={"accept": "application/dns-json"})
                if not resp.content:
                    results.append({"name": name, "records": [], "error": "Empty response"})
                    continue
                data = resp.json()
                answers = [a.get("data", "") for a in data.get("Answer", []) if a.get("type")]
                results.append({"name": name, "records": answers, "status": data.get("Status", -1), "error": None})
            except Exception as e:
                results.append({"name": name, "records": [], "error": str(e)})
    return {"host": host, "type": qtype, "results": results}


# ---------------------------------------------------------------------------
# DNSSEC validator
# ---------------------------------------------------------------------------
@router.get("/tools/dnssec")
async def tools_dnssec(host: str = Query(...)):
    import dns.resolver, dns.dnssec, dns.rdatatype, dns.name
    _validate_tool_host(host)
    chain = []
    try:
        # Check DS record at parent
        try:
            ds_ans = dns.resolver.resolve(host, "DS", lifetime=8)
            chain.append({"record": "DS", "present": True,
                          "values": [str(r) for r in ds_ans][:3]})
        except Exception:
            chain.append({"record": "DS", "present": False, "values": []})

        # Check DNSKEY
        try:
            dk_ans = dns.resolver.resolve(host, "DNSKEY", lifetime=8)
            chain.append({"record": "DNSKEY", "present": True,
                          "values": [f"flags={r.flags} protocol={r.protocol} algorithm={r.algorithm}" for r in dk_ans][:3]})
        except Exception:
            chain.append({"record": "DNSKEY", "present": False, "values": []})

        # Check RRSIG on A record
        try:
            rrsig_ans = dns.resolver.resolve(host, "RRSIG", lifetime=8)
            chain.append({"record": "RRSIG", "present": True,
                          "values": [str(r)[:80] for r in rrsig_ans][:2]})
        except Exception:
            chain.append({"record": "RRSIG", "present": False, "values": []})

        signed = all(r["present"] for r in chain)
        return {"host": host, "signed": signed, "chain": chain, "error": None}
    except Exception as exc:
        return {"host": host, "signed": False, "chain": chain, "error": str(exc)}


# ---------------------------------------------------------------------------
# Reverse DNS bulk lookup (CIDR)
# ---------------------------------------------------------------------------
@router.get("/tools/rdns-bulk")
async def tools_rdns_bulk(cidr: str = Query(...)):
    import ipaddress as _ipa
    try:
        net = _ipa.ip_network(cidr, strict=False)
    except ValueError:
        raise HTTPException(400, "Invalid CIDR")
    if net.num_addresses > 256:
        raise HTTPException(400, "Maximum /24 subnet (256 hosts)")
    results = []
    for ip in net.hosts():
        ip_str = str(ip)
        try:
            hostname = socket.gethostbyaddr(ip_str)[0]
            results.append({"ip": ip_str, "hostname": hostname})
        except Exception:
            results.append({"ip": ip_str, "hostname": None})
    return {"cidr": cidr, "results": results}


# ---------------------------------------------------------------------------
# Redirect chain follower
# ---------------------------------------------------------------------------
@router.get("/tools/redirect-chain")
async def tools_redirect_chain(url: str = Query(...)):
    chain = []
    current = url
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=10,
                                     headers={"User-Agent": "InSpectre/1.0"}) as client:
            for _ in range(15):
                t0 = asyncio.get_event_loop().time()
                resp = await client.get(current)
                ms   = round((asyncio.get_event_loop().time() - t0) * 1000)
                chain.append({"url": current, "status": resp.status_code, "ms": ms,
                               "location": resp.headers.get("location")})
                if resp.status_code not in (301, 302, 303, 307, 308):
                    break
                next_url = resp.headers.get("location", "")
                if not next_url:
                    break
                if next_url.startswith("/"):
                    from urllib.parse import urlparse
                    p = urlparse(current)
                    next_url = f"{p.scheme}://{p.netloc}{next_url}"
                current = next_url
        return {"chain": chain, "hops": len(chain), "final": current}
    except Exception as exc:
        return {"chain": chain, "hops": len(chain), "final": current, "error": str(exc)}


# ---------------------------------------------------------------------------
# HTTP response timing
# ---------------------------------------------------------------------------
@router.get("/tools/http-timing")
async def tools_http_timing(url: str = Query(...)):
    import time
    steps: list[dict] = []
    try:
        t_start = time.perf_counter()
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "InSpectre/1.0"})
            t_end = time.perf_counter()
        total_ms = round((t_end - t_start) * 1000)
        return {
            "url": url,
            "status": resp.status_code,
            "total_ms": total_ms,
            "content_length": int(resp.headers.get("content-length", 0) or 0),
            "server": resp.headers.get("server"),
            "error": None,
        }
    except Exception as exc:
        return {"url": url, "total_ms": None, "error": str(exc)}


# ---------------------------------------------------------------------------
# TLS version & cipher suite tester (via nmap ssl-enum-ciphers)
# ---------------------------------------------------------------------------
@router.get("/tools/tls-versions")
async def tools_tls_versions(host: str = Query(...), port: int = Query(443)):
    _validate_tool_host(host)
    try:
        proc = await asyncio.create_subprocess_exec(
            "nmap", "--script", "ssl-enum-ciphers", "-p", str(port), host,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        output = stdout.decode(errors="replace")
        # Parse TLS versions and ciphers from nmap pipe-prefixed output
        # Lines look like: "|   TLSv1.2:", "|       TLS_ECDHE_RSA... - A", "|   least strength: A"
        versions: dict[str, dict] = {}
        cur_ver   = None
        in_ciphers = False
        for raw_line in output.splitlines():
            # Strip leading whitespace and pipe characters (nmap output prefix)
            line = raw_line.strip().lstrip("|").strip()
            if not line:
                continue
            ver_line = line.rstrip(":")
            if ver_line.startswith("TLSv") or ver_line.startswith("SSLv"):
                cur_ver    = ver_line
                in_ciphers = False
                versions[cur_ver] = {"ciphers": [], "grade": None}
            elif cur_ver and line.lower().startswith("ciphers"):
                in_ciphers = True
            elif cur_ver and line.lower().startswith("compressors"):
                in_ciphers = False
            elif cur_ver and line.lower().startswith("cipher preference"):
                in_ciphers = False
            elif cur_ver and in_ciphers and line.startswith("TLS_"):
                # Line format: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A"
                versions[cur_ver]["ciphers"].append(line)
            elif cur_ver and "least strength" in line.lower():
                grade = line.split(":")[-1].strip()
                versions[cur_ver]["grade"] = grade
        return {"host": host, "port": port, "versions": versions, "raw": output[:3000]}
    except asyncio.TimeoutError:
        return {"host": host, "port": port, "versions": {}, "error": "Scan timed out"}
    except FileNotFoundError:
        return {"host": host, "port": port, "versions": {}, "error": "nmap not available on backend"}
    except Exception as exc:
        return {"host": host, "port": port, "versions": {}, "error": str(exc)}


# ---------------------------------------------------------------------------
# BGP / ASN lookup via RIPE Stat (stat.ripe.net) — no auth, highly reliable
# ---------------------------------------------------------------------------
@router.get("/tools/bgp")
async def tools_bgp(query: str = Query(...)):
    try:
        async with httpx.AsyncClient(timeout=15, headers={"User-Agent": "InSpectre/1.0"}) as client:
            q = query.strip()
            if q.upper().startswith("AS"):
                asn_num = q[2:] if q[2:].isdigit() else q[2:]
                resp    = await client.get(
                    f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn_num}&sourceapp=InSpectre"
                )
                raw = resp.json()
                asn_data = raw.get("data", {})
                holder  = asn_data.get("holder", "")
                block   = asn_data.get("block", {})
                return {"data": {
                    "asn":         int(asn_num) if asn_num.isdigit() else None,
                    "name":        holder,
                    "country_code": block.get("country", ""),
                    "description_short": asn_data.get("description", holder),
                    "resource":    f"AS{asn_num}",
                    "prefixes":    [],
                }}
            else:
                # IP lookup — use RIPE prefix-overview + routing-status
                resp = await client.get(
                    f"https://stat.ripe.net/data/prefix-overview/data.json?resource={q}&sourceapp=InSpectre"
                )
                raw  = resp.json()
                data = raw.get("data", {})
                asns = data.get("asns", [])
                asn_info = asns[0] if asns else {}
                return {"data": {
                    "ip":          q,
                    "asn":         asn_info.get("asn"),
                    "name":        asn_info.get("holder", ""),
                    "description_short": asn_info.get("holder", ""),
                    "country_code": "",
                    "rir_allocation": {"prefix": data.get("resource", "")},
                    "prefixes":    [{"prefix": data.get("resource", "")}] if data.get("resource") else [],
                }}
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# SMTP banner grab
# ---------------------------------------------------------------------------
@router.get("/tools/smtp-banner")
async def tools_smtp_banner(host: str = Query(...), port: int = Query(25)):
    _validate_tool_host(host)
    lines: list[str] = []
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=10
        )
        try:
            # Read banner
            banner = (await asyncio.wait_for(reader.readline(), timeout=5)).decode(errors="replace").strip()
            lines.append(banner)
            # Send EHLO
            writer.write(b"EHLO inspectre.local\r\n")
            await writer.drain()
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5)
                decoded = line.decode(errors="replace").strip()
                if not decoded:
                    break
                lines.append(decoded)
                if decoded[:3].isdigit() and decoded[3] != "-":
                    break
        finally:
            writer.close()
        return {"host": host, "port": port, "banner": banner, "ehlo": lines[1:], "error": None}
    except asyncio.TimeoutError:
        return {"host": host, "port": port, "banner": None, "ehlo": lines, "error": "Connection timed out"}
    except Exception as exc:
        return {"host": host, "port": port, "banner": None, "ehlo": lines, "error": str(exc)}


# ---------------------------------------------------------------------------
# BIMI checker
# ---------------------------------------------------------------------------
@router.get("/tools/bimi")
async def tools_bimi(domain: str = Query(...)):
    import dns.resolver
    _validate_tool_host(domain)
    result: dict = {"domain": domain}
    try:
        recs = dns.resolver.resolve(f"default._bimi.{domain}", "TXT", lifetime=8)
        txt  = " ".join(str(r).strip('"') for r in recs)
        result["present"] = True
        result["record"]  = txt
        # Extract l= (logo URL) and a= (VMC URL)
        for part in txt.split(";"):
            part = part.strip()
            if part.startswith("l="):
                result["logo_url"] = part[2:].strip()
            elif part.startswith("a="):
                result["vmc_url"] = part[2:].strip()
    except dns.resolver.NXDOMAIN:
        result["present"] = False
        result["record"]  = None
    except dns.resolver.NoAnswer:
        result["present"] = False
        result["record"]  = None
    except Exception as exc:
        result["present"] = False
        result["error"] = str(exc)
    return result


# ---------------------------------------------------------------------------
# Email blacklist (DNSBL) checker
# ---------------------------------------------------------------------------
@router.get("/tools/dnsbl")
async def tools_dnsbl(ip: str = Query(...)):
    try:
        _ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Invalid IP address")
    reversed_ip = ".".join(reversed(ip.split(".")))
    results = []
    for name, bl in DNSBL_LISTS:
        query = f"{reversed_ip}.{bl}"
        try:
            socket.gethostbyname(query)
            results.append({"list": name, "listed": True, "query": query})
        except socket.gaierror:
            results.append({"list": name, "listed": False, "query": query})
        except Exception as exc:
            results.append({"list": name, "listed": None, "query": query, "error": str(exc)})
    listed = sum(1 for r in results if r.get("listed"))
    return {"ip": ip, "listed_count": listed, "total": len(results), "results": results}


# ---------------------------------------------------------------------------
# Speedtest — stream proxy, server list, results, and delete
# ---------------------------------------------------------------------------
@router.get("/tools/speedtest")
async def stream_speedtest_proxy(server_id: str = ""):
    probe_url = f"{PROBE_URL}/stream/tools/speedtest"
    params: dict = {}
    if server_id:
        params["server_id"] = server_id
    raw_lines: list[str] = []

    async def _gen():
        try:
            async with _probe_client(timeout=None) as client:
                async with client.stream("GET", probe_url, params=params) as resp:
                    if resp.status_code != 200:
                        yield f"data: ERROR Probe returned {resp.status_code}\n\n"
                        return
                    async for line in resp.aiter_lines():
                        if line:
                            raw_lines.append(line)
                            yield f"{line}\n"
                            if line.startswith("data: RESULT:"):
                                payload_str = line[len("data: RESULT:"):]
                                try:
                                    data = json.loads(payload_str)
                                    if data.get("download_mbps") is not None or data.get("upload_mbps") is not None:
                                        db2 = SessionLocal()
                                        try:
                                            db2.execute(text(
                                                "INSERT INTO speedtest_results (server, ping_ms, download_mbps, upload_mbps, raw_output) "
                                                "VALUES (:server, :ping, :dl, :ul, :raw)"
                                            ), {
                                                "server": data.get("server"),
                                                "ping":   data.get("ping_ms"),
                                                "dl":     data.get("download_mbps"),
                                                "ul":     data.get("upload_mbps"),
                                                "raw":    "\n".join(l[6:] for l in raw_lines if l.startswith("data: ")),
                                            })
                                            db2.commit()
                                        finally:
                                            db2.close()
                                except Exception:
                                    pass
        except httpx.ConnectError:
            yield f"data: ERROR Cannot reach probe at {PROBE_URL}\n\n"
        except Exception as exc:
            yield f"data: ERROR {exc}\n\n"

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/tools/speedtest-servers")
async def get_speedtest_servers():
    try:
        async with _probe_client(timeout=60) as client:
            resp = await client.get(f"{PROBE_URL}/tools/speedtest-servers")
            return resp.json()
    except Exception as exc:
        return {"servers": [], "error": str(exc)}


@router.get("/speedtest/results")
def get_speedtest_results(db: Session = Depends(get_db)):
    rows = db.execute(text(
        "SELECT id, tested_at, server, ping_ms, download_mbps, upload_mbps "
        "FROM speedtest_results ORDER BY tested_at DESC LIMIT 20"
    )).fetchall()
    return [{"id": r[0], "tested_at": r[1].isoformat() if r[1] else None,
             "server": r[2], "ping_ms": r[3], "download_mbps": r[4], "upload_mbps": r[5]}
            for r in rows]


@router.delete("/speedtest/results/{result_id}")
def delete_speedtest_result(result_id: int, db: Session = Depends(get_db)):
    db.execute(text("DELETE FROM speedtest_results WHERE id = :id"), {"id": result_id})
    db.commit()
    return {"ok": True}
