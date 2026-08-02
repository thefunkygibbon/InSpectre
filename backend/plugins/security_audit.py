from __future__ import annotations

from datetime import datetime, timezone
import re

import docker as docker_sdk


_DANGEROUS_CAPS = {
    "ALL",
    "BPF",
    "DAC_OVERRIDE",
    "DAC_READ_SEARCH",
    "NET_ADMIN",
    "NET_RAW",
    "SYS_ADMIN",
    "SYS_MODULE",
    "SYS_PTRACE",
    "SYS_TIME",
}


def _finding(fid: str, severity: str, description: str, advice: str) -> dict:
    return {
        "id": fid,
        "severity": severity,
        "description": description,
        "advice": advice,
    }


def _split_csv_values(raw: str | None) -> set[str]:
    if not raw:
        return set()
    return {part.strip() for part in str(raw).split(",") if part.strip()}


def _vmid_matches_selector(vmid: int, selector: str | None) -> bool:
    if not selector:
        return False
    wanted = str(vmid)
    for token in _split_csv_values(selector):
        if token == wanted:
            return True
        if "-" in token:
            start, end = token.split("-", 1)
            if start.isdigit() and end.isdigit() and int(start) <= vmid <= int(end):
                return True
    return False


def _backup_job_covers_vmid(job: dict, vmid: int) -> bool:
    if str(job.get("enabled", "1")).lower() in {"0", "false", "no"}:
        return False
    if str(job.get("disable", "0")).lower() in {"1", "true", "yes"}:
        return False
    if str(job.get("all", "0")).lower() in {"1", "true", "yes"}:
        excludes = _split_csv_values(job.get("exclude") or job.get("exclude-vmids"))
        return str(vmid) not in excludes
    return _vmid_matches_selector(vmid, job.get("vmid") or job.get("vmids"))


def audit_docker_container(host_url: str, container_id: str, host_name: str | None = None) -> dict:
    from container_updates import _check_update_sync, _container_image_ref

    scanned_at = datetime.now(timezone.utc).isoformat()
    findings: list[dict] = []
    client = docker_sdk.DockerClient(base_url=host_url)
    try:
        container = client.containers.get(container_id)
        attrs = container.attrs or {}
        host_cfg = attrs.get("HostConfig", {}) or {}
        config = attrs.get("Config", {}) or {}
        mounts = attrs.get("Mounts") or []
        ports = (attrs.get("NetworkSettings", {}) or {}).get("Ports") or {}

        if bool(host_cfg.get("Privileged")):
            findings.append(_finding(
                "docker-privileged-container",
                "critical",
                f"Container '{container.name}' is running in privileged mode.",
                "Disable privileged mode and grant only the minimum devices, capabilities, and mounts the container actually needs.",
            ))

        sock_mounts = [
            m for m in mounts
            if (m.get("Destination") or "") in {"/var/run/docker.sock", "/run/docker.sock"}
            or (m.get("Source") or "") in {"/var/run/docker.sock", "/run/docker.sock"}
        ]
        if sock_mounts:
            findings.append(_finding(
                "docker-socket-mounted",
                "critical",
                f"Container '{container.name}' has the Docker socket mounted.",
                "Remove the Docker socket mount or replace it with a tightly scoped API proxy. A writable Docker socket usually grants host-level control.",
            ))

        run_user = (config.get("User") or "").strip()
        if run_user in {"", "0", "root"}:
            findings.append(_finding(
                "docker-running-as-root",
                "high",
                f"Container '{container.name}' runs as root inside the container.",
                "Set a non-root USER in the image or container configuration and grant only the file permissions that process needs.",
            ))

        cap_add = {str(cap).upper() for cap in (host_cfg.get("CapAdd") or []) if cap}
        dangerous = sorted(cap_add & _DANGEROUS_CAPS)
        if dangerous:
            findings.append(_finding(
                "docker-dangerous-cap-add",
                "high",
                f"Container '{container.name}' adds dangerous Linux capabilities: {', '.join(dangerous)}.",
                "Remove dangerous CapAdd entries wherever possible. Prefer the default capability set and explicitly drop capabilities that are not required.",
            ))

        has_mem_limit = bool(host_cfg.get("Memory"))
        has_cpu_limit = bool(host_cfg.get("NanoCpus") or host_cfg.get("CpuQuota"))
        has_pids_limit = host_cfg.get("PidsLimit") not in (None, 0, -1)
        if not (has_mem_limit or has_cpu_limit or has_pids_limit):
            findings.append(_finding(
                "docker-missing-resource-limits",
                "medium",
                f"Container '{container.name}' has no memory, CPU, or PID limits configured.",
                "Set sensible resource limits so one compromised or runaway container cannot starve the host or neighbouring workloads.",
            ))

        public_ports = []
        for container_port, bindings in ports.items():
            for binding in (bindings or []):
                host_ip = (binding.get("HostIp") or "").strip()
                if host_ip in {"0.0.0.0", "::", ""}:
                    public_ports.append(f"{host_ip or 'all-interfaces'}:{binding.get('HostPort', '?')}->{container_port}")
        if public_ports:
            findings.append(_finding(
                "docker-public-port-binding",
                "medium",
                f"Container '{container.name}' publishes ports on all interfaces: {', '.join(public_ports[:6])}.",
                "Bind admin or internal-only services to 127.0.0.1 or a dedicated internal interface unless they must be reachable externally.",
            ))

        restart_name = ((host_cfg.get("RestartPolicy") or {}).get("Name") or "").strip().lower()
        if restart_name in {"", "no"}:
            findings.append(_finding(
                "docker-missing-restart-policy",
                "info",
                f"Container '{container.name}' has no restart policy configured.",
                "Set a restart policy such as unless-stopped or always so the service recovers automatically after host or daemon restarts.",
            ))

        if not config.get("Healthcheck"):
            findings.append(_finding(
                "docker-missing-healthcheck",
                "info",
                f"Container '{container.name}' has no HEALTHCHECK configured.",
                "Add a healthcheck so broken containers can be detected quickly and restarted or rolled back safely.",
            ))

        image_ref = _container_image_ref(container)
        image_id = getattr(container.image, "id", None)
        update_state = _check_update_sync(image_ref, host_url, image_id)
        if update_state.get("has_update"):
            findings.append(_finding(
                "docker-outdated-image-digest",
                "info",
                f"Container '{container.name}' is not running the latest available image digest.",
                "Review the newer image, scan it, and redeploy the container when you are comfortable with the update and its security impact.",
            ))

        return {
            "kind": "docker",
            "host_name": host_name,
            "resource_name": container.name,
            "scanned_at": scanned_at,
            "findings": findings,
            "error": None,
        }
    except Exception as exc:
        return {
            "kind": "docker",
            "host_name": host_name,
            "resource_name": container_id,
            "scanned_at": scanned_at,
            "findings": [],
            "error": str(exc),
        }
    finally:
        client.close()


def audit_proxmox_guest(host: dict, node: str, vmid: int, guest_type: str, request_fn) -> dict:
    scanned_at = datetime.now(timezone.utc).isoformat()
    findings: list[dict] = []
    resource_name = f"{guest_type}-{vmid}"
    try:
        cfg_resp = request_fn(host, "GET", f"/api2/json/nodes/{node}/{guest_type}/{vmid}/config")
        cfg = cfg_resp.get("data", {}) or {}
        resource_name = cfg.get("hostname") or cfg.get("name") or resource_name

        if guest_type == "lxc" and str(cfg.get("unprivileged", "0")).lower() not in {"1", "true", "yes"}:
            findings.append(_finding(
                "proxmox-privileged-lxc",
                "high",
                f"LXC '{resource_name}' is running as a privileged container.",
                "Convert the container to unprivileged mode unless you have a strong, documented requirement for privileged operation.",
            ))

        if str(cfg.get("firewall", "0")).lower() not in {"1", "true", "yes", "on"}:
            findings.append(_finding(
                "proxmox-firewall-disabled",
                "medium",
                f"{guest_type.upper()} '{resource_name}' has its per-guest Proxmox firewall disabled.",
                "Enable the guest firewall and define explicit allow rules so management and application ports are not left broadly exposed.",
            ))

        jobs_resp = request_fn(host, "GET", "/api2/json/cluster/backup")
        jobs = jobs_resp.get("data", []) or []
        if not any(_backup_job_covers_vmid(job, vmid) for job in jobs):
            findings.append(_finding(
                "proxmox-missing-backup-job",
                "medium",
                f"{guest_type.upper()} '{resource_name}' is not covered by any enabled Proxmox backup job.",
                "Add the guest to a scheduled backup job, or enable an all-guests backup policy with clear exclusions and restore testing.",
            ))

        if guest_type == "qemu":
            args = str(cfg.get("args") or "")
            if re.search(r"-vnc\s+(?:0\.0\.0\.0|::|\*):", args) and "password=on" not in args:
                findings.append(_finding(
                    "proxmox-insecure-vnc-console",
                    "high",
                    f"VM '{resource_name}' exposes a VNC console listener without password protection in custom QEMU args.",
                    "Remove the custom public VNC binding or require authenticated console access through the Proxmox proxy instead.",
                ))
            if re.search(r"-spice\s+.*(?:addr=0\.0\.0\.0|addr=::)", args) and "password=on" not in args:
                findings.append(_finding(
                    "proxmox-insecure-spice-console",
                    "high",
                    f"VM '{resource_name}' exposes a SPICE console listener without password protection in custom QEMU args.",
                    "Remove the public SPICE listener or require authenticated console access via the Proxmox-managed proxy.",
                ))

        return {
            "kind": "proxmox",
            "host_name": host.get("name"),
            "resource_name": resource_name,
            "scanned_at": scanned_at,
            "findings": findings,
            "error": None,
        }
    except Exception as exc:
        return {
            "kind": "proxmox",
            "host_name": host.get("name"),
            "resource_name": resource_name,
            "scanned_at": scanned_at,
            "findings": [],
            "error": str(exc),
        }
