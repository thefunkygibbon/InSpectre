#!/usr/bin/env bash
#
# bump-version.sh — increment the canonical version in /VERSION and re-sync
# all derived files.
#
# Usage:
#   scripts/bump-version.sh [major|minor|patch]   (default: patch)
#   scripts/bump-version.sh set 2.0.0             (set an explicit version)
#
# Semantic versioning:
#   major — incompatible / breaking changes        (X.0.0)
#   minor — new, backwards-compatible functionality (x.Y.0)
#   patch — backwards-compatible fixes / tweaks     (x.y.Z)  ← the default
#
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VERSION_FILE="VERSION"
PART="${1:-patch}"

current="$(tr -d ' \t\r\n' < "$VERSION_FILE")"

if [[ "$PART" == "set" ]]; then
  new="${2:-}"
  if [[ -z "$new" ]]; then
    echo "Usage: $0 set <MAJOR.MINOR.PATCH>" >&2
    exit 1
  fi
else
  # Split off any -prerelease/+build metadata before incrementing.
  core="${current%%[-+]*}"
  IFS='.' read -r major minor patch <<< "$core"
  case "$PART" in
    major) major=$((major + 1)); minor=0; patch=0 ;;
    minor) minor=$((minor + 1)); patch=0 ;;
    patch) patch=$((patch + 1)) ;;
    *) echo "Usage: $0 [major|minor|patch] | set <version>" >&2; exit 1 ;;
  esac
  new="$major.$minor.$patch"
fi

printf '%s\n' "$new" > "$VERSION_FILE"
"$REPO_ROOT/scripts/sync-version.sh"
echo "[bump-version] $current → $new"
