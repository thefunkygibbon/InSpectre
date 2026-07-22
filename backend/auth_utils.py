from datetime import datetime, timezone, timedelta
from fastapi import HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import text
from jose import JWTError, jwt
import bcrypt as _bcrypt

from config import SECRET_KEY, ALGORITHM, TOKEN_EXPIRE_DEFAULT
from database import get_db

bearer_scheme = HTTPBearer(auto_error=False)


def _hash_password(password: str) -> str:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode()


def _verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode(), hashed.encode())


def _create_token(username: str, expire_minutes: int | None = None) -> str:
    minutes = expire_minutes or TOKEN_EXPIRE_DEFAULT
    expire = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    return jwt.encode({"sub": username, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)


def _decode_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None


def _has_any_user(db: Session) -> bool:
    try:
        row = db.execute(text("SELECT id FROM users LIMIT 1")).fetchone()
        return row is not None
    except Exception:
        return False


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    db: Session = Depends(get_db),
) -> str:
    """Dependency that returns the username of the authenticated user or raises 401."""
    token = credentials.credentials if credentials else None
    if not token:
        raise HTTPException(401, "Not authenticated")
    username = _decode_token(token)
    if not username:
        raise HTTPException(401, "Invalid or expired token")
    row = db.execute(text("SELECT username FROM users WHERE username = :u"), {"u": username}).fetchone()
    if not row:
        raise HTTPException(401, "User not found")
    return username


def get_current_user_optional(
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    db: Session = Depends(get_db),
) -> str | None:
    """Like get_current_user but returns None instead of raising (used for setup check)."""
    if not _has_any_user(db):
        return "__setup__"  # sentinel: setup not done, allow access
    token = credentials.credentials if credentials else None
    if not token:
        return None
    return _decode_token(token)


def _seed_default_user(db: Session) -> None:
    """
    Fallback only: if setup is marked complete but no users exist (e.g. users table
    was wiped), create admin/admin so the instance isn't permanently locked out.
    Does NOT run when setup_complete = false — the wizard handles user creation.
    """
    from models import Setting
    try:
        if _has_any_user(db):
            return
        s = db.get(Setting, "setup_complete")
        if not s or s.value != "true":
            return
        db.execute(
            text("""INSERT INTO users (username, password_hash, is_admin, must_change_password)
                    VALUES (:u, :h, TRUE, TRUE)
                    ON CONFLICT (username) DO NOTHING"""),
            {"u": "admin", "h": _hash_password("admin")},
        )
        db.commit()
        print("[startup] No users found — created default admin/admin. Please change the password.", flush=True)
    except Exception as e:
        db.rollback()
        print(f"[startup] Could not seed default user: {e}", flush=True)
