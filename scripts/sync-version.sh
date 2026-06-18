#!/usr/bin/env bash
#
# sync-version.sh — stamp the canonical version from /VERSION into every
# component that needs it at build/run time.
#
# The repo-root VERSION file is the single source of truth. The files written
# here are AUTO-GENERATED and should never be hand-edited:
#   - backend/_version.py      (read at runtime by the FastAPI backend)
#   - probe/_version.py        (read at runtime by the probe)
#   - frontend/src/version.js  (bundled into the SPA at build time)
#   - frontend/package.json    ("version" field)
#
# Each component is built from its own Docker context, which is why the version
# must be materialised into each subtree rather than read from one shared path.
#
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VERSION_FILE="VERSION"
if [[ ! -f "$VERSION_FILE" ]]; then
  echo "ERROR: $VERSION_FILE not found at repo root ($REPO_ROOT)" >&2
  exit 1
fi

VERSION="$(tr -d ' \t\r\n' < "$VERSION_FILE")"

# Validate semver: MAJOR.MINOR.PATCH with optional -prerelease / +build metadata.
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
  echo "ERROR: '$VERSION' in $VERSION_FILE is not valid semver (expected MAJOR.MINOR.PATCH)" >&2
  exit 1
fi

NOTE_HASH="# AUTO-GENERATED — do not edit. Source of truth: /VERSION. Run scripts/sync-version.sh."
NOTE_SLASH="// AUTO-GENERATED — do not edit. Source of truth: /VERSION. Run scripts/sync-version.sh."

cat > backend/_version.py <<EOF
$NOTE_HASH
__version__ = "$VERSION"
EOF

cat > probe/_version.py <<EOF
$NOTE_HASH
__version__ = "$VERSION"
EOF

cat > frontend/src/version.js <<EOF
$NOTE_SLASH
export const APP_VERSION = '$VERSION'
EOF

# Update frontend/package.json "version" field without disturbing the rest.
# Portable: prefer jq, fall back to python3, then a sed-based last resort, so
# the version tooling works on hosts that don't have Python installed.
if command -v jq >/dev/null 2>&1; then
  tmp="$(mktemp)"
  jq --arg v "$VERSION" '.version = $v' frontend/package.json > "$tmp"
  mv "$tmp" frontend/package.json
elif command -v python3 >/dev/null 2>&1; then
  python3 - "$VERSION" <<'PY'
import json, sys
version = sys.argv[1]
path = "frontend/package.json"
with open(path, encoding="utf-8") as fh:
    data = json.load(fh)
data["version"] = version
with open(path, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2)
    fh.write("\n")
PY
else
  # Last resort: rewrite the first "version": "..." line in place.
  sed -i -E "0,/\"version\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/s//\"version\": \"$VERSION\"/" frontend/package.json
fi

echo "[sync-version] version $VERSION → backend/_version.py, probe/_version.py, frontend/src/version.js, frontend/package.json"
