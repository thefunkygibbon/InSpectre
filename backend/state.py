"""
Shared mutable singletons and globals used across multiple modules.

Import from here rather than from the originating modules to avoid circular imports.
"""
import asyncio
from datetime import datetime

from ha_mqtt import HAMQTTManager
from plugin_engine import PluginRegistry, PluginRunner, PluginEventBus, PluginScheduler
from database import SessionLocal

# ── MQTT / Plugin singletons ─────────────────────────────────────────────────
_ha_mqtt          = HAMQTTManager()
_plugin_registry  = PluginRegistry()
_plugin_runner    = PluginRunner(_plugin_registry, _ha_mqtt)
_plugin_event_bus = PluginEventBus(_plugin_registry, _plugin_runner)
_plugin_scheduler = PluginScheduler(_plugin_registry, _plugin_runner, SessionLocal)

# ── SSE ──────────────────────────────────────────────────────────────────────
_sse_clients: "set[asyncio.Queue]" = set()
_last_sse_event_id: int = 0

# ── Event loop reference (set on startup) ────────────────────────────────────
_main_loop: asyncio.AbstractEventLoop | None = None

# ── Notification loop state ──────────────────────────────────────────────────
_last_alert_event_id: int = 0
_last_network_paused: str = ""
_person_home_state: dict[str, bool] = {}
_person_away_pending: dict[str, tuple] = {}
_person_last_home_notified: dict[str, datetime] = {}
_pending_browser_notifications: list = []
_traffic_notif_cooldowns: dict = {}  # (mac, event_type) → datetime of last notification

# ── Person timed blocks (in-memory task handles) ─────────────────────────────
_person_timed_blocks: dict = {}
