from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
import httpx
from database import get_db
from auth_utils import get_current_user, _verify_password, _create_token, _hash_password
from config import PROBE_URL, TOKEN_EXPIRE_DEFAULT, TOKEN_EXPIRE_REMEMBER
from probe_client import _probe_client
from models import Setting
from schemas import LoginRequest, ChangePasswordRequest
from _version import __version__ as VERSION

router = APIRouter()


@router.get("/")
def root():
    return {"message": "InSpectre API", "version": VERSION}


@router.get("/health")
async def health_check(db: Session = Depends(get_db)):
    """Return connectivity status of all platform components."""
    from routes.vuln import _nuclei_subs

    result = {
        "backend": {"ok": True, "message": "Running"},
        "database": {"ok": False, "message": ""},
        "probe":    {"ok": False, "message": ""},
        "setup_complete": False,
        "active_scans": {"port": [], "vuln": []},
    }

    def _resolve_device_name(mac: str) -> str:
        try:
            row = db.execute(
                text("SELECT custom_name, hostname, ip_address FROM devices WHERE LOWER(mac_address) = :m"),
                {"m": mac.lower()}
            ).fetchone()
            if row:
                return row[0] or row[1] or row[2] or mac
        except Exception:
            pass
        return mac

    # Check database
    try:
        row = db.execute(text("SELECT COUNT(*) FROM devices")).scalar()
        result["database"] = {"ok": True, "message": f"{row} devices in DB"}
    except Exception as e:
        result["database"] = {"ok": False, "message": str(e)[:120]}

    # Check probe
    try:
        async with _probe_client(timeout=5.0) as client:
            resp = await client.get(f"{PROBE_URL}/health")
            if resp.status_code == 200:
                probe_data = resp.json()
                result["probe"] = {"ok": True, "message": probe_data.get("message", "Running")}
                for mac in probe_data.get("active_port_scans", []):
                    result["active_scans"]["port"].append({"mac": mac, "name": _resolve_device_name(mac)})
            else:
                result["probe"] = {"ok": False, "message": f"HTTP {resp.status_code}"}
    except httpx.ConnectError:
        result["probe"] = {"ok": False, "message": f"Cannot reach probe at {PROBE_URL}"}
    except Exception as e:
        result["probe"] = {"ok": False, "message": str(e)[:120]}

    # Active vuln scans (tracked by backend)
    for mac in list(_nuclei_subs.keys()):
        result["active_scans"]["vuln"].append({"mac": mac, "name": _resolve_device_name(mac)})

    # Check setup complete
    try:
        s = db.get(Setting, "setup_complete")
        result["setup_complete"] = (s.value if s else "false") == "true"
    except Exception:
        pass

    result["all_ok"] = all(v["ok"] for v in [result["backend"], result["database"], result["probe"]])
    return result


@router.post("/auth/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    row = db.execute(
        text("SELECT username, password_hash, must_change_password FROM users WHERE username = :u"),
        {"u": payload.username}
    ).fetchone()
    if not row or not _verify_password(payload.password, row[1]):
        raise HTTPException(401, "Invalid username or password")
    db.execute(
        text("UPDATE users SET last_login = NOW() WHERE username = :u"),
        {"u": payload.username}
    )
    db.commit()
    token = _create_token(
        payload.username,
        TOKEN_EXPIRE_REMEMBER if payload.remember_me else TOKEN_EXPIRE_DEFAULT,
    )
    return {"token": token, "username": payload.username, "must_change_password": bool(row[2])}


@router.get("/auth/me")
def auth_me(username: str = Depends(get_current_user), db: Session = Depends(get_db)):
    row = db.execute(
        text("SELECT must_change_password FROM users WHERE username = :u"), {"u": username}
    ).fetchone()
    must_change = bool(row[0]) if row else False
    return {"username": username, "authenticated": True, "must_change_password": must_change}


@router.post("/auth/change-password")
def change_password(
    payload: ChangePasswordRequest,
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = db.execute(
        text("SELECT password_hash FROM users WHERE username = :u"), {"u": username}
    ).fetchone()
    if not row or not _verify_password(payload.current_password, row[0]):
        raise HTTPException(401, "Current password is incorrect")
    if len(payload.new_password) < 8:
        raise HTTPException(400, "New password must be at least 8 characters")
    new_hash = _hash_password(payload.new_password)
    db.execute(
        text("UPDATE users SET password_hash = :h, must_change_password = FALSE WHERE username = :u"),
        {"h": new_hash, "u": username}
    )
    db.commit()
    return {"ok": True}
