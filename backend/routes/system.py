from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
import asyncio, json
from database import get_db
from auth_utils import get_current_user
from models import Setting
from schemas import AutoUpdateRequest
from background_loops import _is_appliance, _read_appliance_meta, _run_appliance_update_task, _auto_update_running

router = APIRouter()


@router.get("/system/info")
def get_system_info(db: Session = Depends(get_db), username: str = Depends(get_current_user)):
    """Return appliance metadata and auto-update configuration."""
    def _s(key, default=""):
        row = db.get(Setting, key)
        return row.value if row else default

    is_appl = _is_appliance()
    meta    = _read_appliance_meta() if is_appl else {}

    days_raw = _s("auto_update_days", "[]")
    try:
        days = json.loads(days_raw)
    except Exception:
        days = []

    return {
        "is_appliance":   is_appl,
        "appliance_type": meta.get("type"),
        "timezone":       _s("timezone", "UTC"),
        "auto_update": {
            "enabled": _s("auto_update_enabled", "false") == "true",
            "hour":    int(_s("auto_update_hour", "3")),
            "days":    days,
            "updater": {
                "last_run":    _s("auto_update_last_run") or None,
                "last_status": _s("auto_update_last_status") or None,
                "running":     _auto_update_running,
                "last_logs":   _s("auto_update_last_detail") or None,
            },
        },
    }


@router.post("/system/auto-update")
def set_auto_update(
    payload:  AutoUpdateRequest,
    username: str     = Depends(get_current_user),
    db:       Session = Depends(get_db),
):
    """Save auto-update schedule settings."""
    to_save = {
        "auto_update_enabled": "true" if payload.enabled else "false",
        "auto_update_hour":    str(max(0, min(23, payload.hour))),
        "auto_update_days":    json.dumps(payload.days),
    }
    for key, value in to_save.items():
        s = db.get(Setting, key)
        if s:
            s.value = value
        else:
            db.add(Setting(key=key, value=value))
    db.commit()
    return {"ok": True}


@router.post("/system/auto-update/run")
async def run_auto_update_now(username: str = Depends(get_current_user)):
    """Trigger an immediate appliance update (appliance builds only)."""
    if not _is_appliance():
        raise HTTPException(403, "Not an appliance build")
    asyncio.ensure_future(_run_appliance_update_task())
    return {"ok": True, "message": "Update triggered"}
