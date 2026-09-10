import json
import os
import shutil
import subprocess
from datetime import datetime, timezone


TRIVY_DB_META = "/root/.cache/trivy/db/metadata.json"


def trivy_db_exists() -> bool:
    return os.path.exists(TRIVY_DB_META)


def parse_trivy_json(data: dict) -> list[dict]:
    """Flatten Trivy JSON output into the frontend's vulnerability shape."""
    vulns: list[dict] = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        for vuln in (result.get("Vulnerabilities") or []):
            cvss_score = None
            for src in (vuln.get("CVSS") or {}).values():
                score = src.get("V3Score") or src.get("V2Score")
                if score:
                    cvss_score = score
                    break
            vulns.append({
                "id":          vuln.get("VulnerabilityID", ""),
                "severity":    vuln.get("Severity", "UNKNOWN").lower(),
                "pkg":         vuln.get("PkgName", ""),
                "installed":   vuln.get("InstalledVersion", ""),
                "fixed":       vuln.get("FixedVersion", ""),
                "title":       vuln.get("Title", ""),
                "description": (vuln.get("Description") or "")[:400],
                "cvss":        cvss_score,
                "score":       cvss_score,
                "target":      target,
                "url":         f"https://nvd.nist.gov/vuln/detail/{vuln.get('VulnerabilityID', '')}",
            })
    return vulns


def _trim_trivy_output(text: str, limit: int = 500) -> str:
    cleaned = " ".join((text or "").split()).strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[:limit].rstrip() + "…"


def ensure_trivy_db_sync() -> tuple[bool, str]:
    if trivy_db_exists():
        return True, ""
    if not shutil.which("trivy"):
        return False, "Trivy is not installed in this container."
    
    print("[trivy] Downloading vulnerability database (this may take a few minutes)...", flush=True)
    try:
        proc = subprocess.run(
            ["trivy", "image", "--download-db-only"],
            capture_output=True,
            text=True,
            timeout=1800,  # Increased timeout for slow networks
        )
    except subprocess.TimeoutExpired:
        return False, "Trivy database download timed out (network may be slow or unreachable)"
    except Exception as exc:
        return False, f"Failed to download the Trivy vulnerability database: {exc}"
    
    if proc.returncode == 0 and trivy_db_exists():
        print("[trivy] Vulnerability database downloaded successfully", flush=True)
        return True, ""
    
    # If DB still doesn't exist after successful run, Trivy might have downloaded to a different location
    # Try checking alternative locations
    alt_locations = [
        os.path.expanduser("~/.cache/trivy/db/metadata.json"),
        "/tmp/.trivy/db/metadata.json",
        os.path.join(os.environ.get("TRIVY_CACHE_DIR", ""), "db/metadata.json"),
    ]
    for alt_loc in alt_locations:
        if alt_loc and os.path.exists(alt_loc):
            print(f"[trivy] Found DB at alternative location: {alt_loc}", flush=True)
            return True, ""
    
    detail = _trim_trivy_output(proc.stderr or proc.stdout)
    if detail:
        return False, f"Trivy vulnerability DB download failed: {detail}"
    return False, f"Trivy vulnerability DB download failed with exit code {proc.returncode}"


def run_trivy_image_scan_sync(image: str) -> dict:
    if not shutil.which("trivy"):
        return {
            "ok": False,
            "error": "Trivy is not installed in this container.",
            "exit_code": None,
            "stderr": "",
            "vulns": [],
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }

    db_ok, db_error = ensure_trivy_db_sync()
    if not db_ok:
        return {
            "ok": False,
            "error": db_error,
            "exit_code": None,
            "stderr": db_error,
            "vulns": [],
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }

    scanned_at = datetime.now(timezone.utc).isoformat()
    try:
        # Configure environment to help Trivy access Docker daemon and database
        env = os.environ.copy()
        env['TRIVY_SKIP_DB_UPDATE'] = 'true'
        
        proc = subprocess.run(
            [
                "trivy", "image",
                "--format", "json",
                "--no-progress",
                "--scanners", "vuln",
                "--skip-db-update",
                "--severity", "CRITICAL,HIGH,MEDIUM",  # Focus on important vulns
                image,
            ],
            capture_output=True,
            text=True,
            timeout=900,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": f"Trivy scan timed out while scanning {image}.",
            "exit_code": None,
            "stderr": "",
            "vulns": [],
            "scanned_at": scanned_at,
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": f"Trivy scan failed: {exc}",
            "exit_code": None,
            "stderr": str(exc),
            "vulns": [],
            "scanned_at": scanned_at,
        }

    stderr = (proc.stderr or "").strip()
    stdout = proc.stdout or ""
    if proc.returncode != 0:
        # Try to provide more detailed error information
        detail = (stderr or stdout)
        if not detail or len(detail) < 20:
            # If stderr is empty, try to parse JSON stdout for error messages
            try:
                result_json = json.loads(stdout) if stdout else {}
                detail = result_json.get("Result", {}).get("Error", detail)
            except:
                pass
        
        detail = _trim_trivy_output(detail, limit=800)  # Increased limit for better error reporting
        message = f"Trivy exited with code {proc.returncode}"
        if detail:
            message = f"{message}: {detail}"
        
        # Log full stderr for debugging
        if stderr:
            print(f"[trivy] Full error for {image}: {stderr[:500]}", flush=True)
        
        return {
            "ok": False,
            "error": message,
            "exit_code": proc.returncode,
            "stderr": stderr,
            "vulns": [],
            "scanned_at": scanned_at,
        }

    if not stdout.strip():
        return {
            "ok": False,
            "error": f"Trivy returned no JSON output for {image}.",
            "exit_code": proc.returncode,
            "stderr": stderr,
            "vulns": [],
            "scanned_at": scanned_at,
        }

    try:
        payload = json.loads(stdout)
    except Exception as exc:
        return {
            "ok": False,
            "error": f"Could not parse Trivy output: {exc}",
            "exit_code": proc.returncode,
            "stderr": stderr,
            "vulns": [],
            "scanned_at": scanned_at,
        }

    vulns = parse_trivy_json(payload)
    return {
        "ok": True,
        "error": None,
        "exit_code": proc.returncode,
        "stderr": stderr,
        "vulns": vulns,
        "scanned_at": scanned_at,
    }
