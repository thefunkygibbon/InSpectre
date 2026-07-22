from typing import Optional
import httpx

from config import PROBE_URL, PROBE_API_SECRET  # noqa: F401 — PROBE_URL re-exported for callers


def _probe_headers(extra: Optional[dict] = None) -> dict:
    """Return headers for a backend->probe request, including the shared secret."""
    headers = dict(extra) if extra else {}
    if PROBE_API_SECRET:
        headers["X-Probe-Secret"] = PROBE_API_SECRET
    return headers


def _probe_client(**kwargs):
    """httpx.AsyncClient pre-configured with the probe shared-secret header.

    Use this for ALL backend->probe calls. Never use it for external services.
    """
    if PROBE_API_SECRET:
        headers = dict(kwargs.pop("headers", {}) or {})
        headers.setdefault("X-Probe-Secret", PROBE_API_SECRET)
        kwargs["headers"] = headers
    return httpx.AsyncClient(**kwargs)


async def _execute_block_bg(mac: str, ip: Optional[str], action: str) -> None:
    """Execute a block or unblock action via the probe, using the configured method."""
    from database import SessionLocal
    from models import Setting
    from plugin_engine import get_decrypted_config

    db = SessionLocal()
    try:
        method_s = db.get(Setting, "block_method")
        method   = (method_s.value or "arp").strip() if method_s else "arp"
        plugin_id_s = db.get(Setting, "block_plugin_id")
        plugin_id   = (plugin_id_s.value or "").strip() if plugin_id_s else ""
    finally:
        db.close()

    if method == "arp" or not plugin_id:
        endpoint = "block" if action == "block" else "unblock"
        async with _probe_client(timeout=10.0) as client:
            resp = await client.post(
                f"{PROBE_URL}/{endpoint}/{mac}",
                json={"ip": ip} if ip else {},
            )
            resp.raise_for_status()
        return

    # Plugin-based blocking (DNS, infrastructure controllers, etc.)
    from state import _plugin_registry, _plugin_runner
    plugin = _plugin_registry.get(plugin_id)
    if not plugin or not plugin.get("enabled"):
        raise ValueError(f"Block plugin '{plugin_id}' not found or disabled")

    plugin_action = "block_client" if action == "block" else "unblock_client"
    cfg = get_decrypted_config(plugin["manifest"], plugin["config"])
    await _plugin_runner.run_action(plugin_id, plugin_action, {"mac": mac, "ip": ip or ""}, cfg)
