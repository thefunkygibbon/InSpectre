import os

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://admin:password123@db:5432/inspectre")

# PROBE_API_URL is the name used in docker-compose; PROBE_URL is the legacy fallback.
PROBE_URL = (
    os.environ.get("PROBE_API_URL")
    or os.environ.get("PROBE_URL")
    or "http://host.docker.internal:8666"
)

# Shared secret used to authenticate backend -> probe API calls.
PROBE_API_SECRET = os.environ.get("PROBE_API_SECRET", "").strip()

_DEFAULT_SECRET_KEY = "CHANGE_ME_IN_PRODUCTION_use_a_long_random_string"
SECRET_KEY = os.environ.get("SECRET_KEY", _DEFAULT_SECRET_KEY)
if SECRET_KEY == _DEFAULT_SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is set to the insecure default placeholder. Refusing to start. "
        "Set the SECRET_KEY environment variable to a long, random secret "
        "(e.g. `openssl rand -hex 32`)."
    )

ALGORITHM = "HS256"
TOKEN_EXPIRE_DEFAULT  = 60 * 24       # minutes — 24 hours
TOKEN_EXPIRE_REMEMBER = 60 * 24 * 30  # minutes — 30 days

_CORS_ORIGINS_RAW = os.environ.get(
    "CORS_ORIGINS",
    "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000"
)
CORS_ORIGINS = [o.strip() for o in _CORS_ORIGINS_RAW.split(",") if o.strip()]
