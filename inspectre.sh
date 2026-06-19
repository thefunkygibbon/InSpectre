#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_NAME="${COMPOSE_PROJECT_NAME:-inspectre}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

usage() {
  cat <<EOF
Usage:
  ./inspectre.sh rebuild [DATA_DIR]
  ./inspectre.sh rebuild keep-data [DATA_DIR]
  ./inspectre.sh up
  ./inspectre.sh down
  ./inspectre.sh logs [service]

Commands:
  rebuild [DATA_DIR]
                  Full rebuild from the current folder — wipes containers, images,
                  build cache, AND the db/ folder (all device history).
                  Vuln scanner data (vuln/) is always preserved.
  rebuild keep-data [DATA_DIR]
                  Full rebuild but leaves db/ intact (devices, history, settings
                  are preserved across the rebuild).
  up              Start the stack normally.
  down            Stop the stack.
  logs [service]  Follow logs. Optionally filter to a single service, e.g. probe, backend, web.

Data directory:
  By default the stack stores its data in ./data (inside this folder). Pass an
  optional DATA_DIR to relocate it, e.g.:
      ./inspectre.sh rebuild /home/inspectre
      ./inspectre.sh rebuild keep-data /home/inspectre
  The chosen path is saved to .env (INSPECTRE_DATA_DIR) so up/down/logs use it too.

Notes:
  - This script does NOT run any git commands.
  - It rebuilds from the files currently present in this working directory.
  - Data layout (relative to DATA_DIR):
      <DATA_DIR>/db/         — PostgreSQL data (wiped by "rebuild", kept by "rebuild keep-data")
      <DATA_DIR>/vuln/trivy  — Trivy vulnerability DB (never wiped)
      <DATA_DIR>/vuln/nuclei — Nuclei templates (never wiped)
EOF
}

require_compose() {
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD=(docker-compose)
  else
    echo "[InSpectre] ERROR: docker compose / docker-compose not found."
    exit 1
  fi
}

confirm() {
  local prompt="$1"
  read -r -p "$prompt [y/N]: " reply
  [[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]
}

log() {
  echo "[InSpectre] $*"
}

# Default data directory lives inside the project folder.
DATA_DIR="$SCRIPT_DIR/data"

# Persist a KEY=VALUE pair into .env so docker compose (and later up/down/logs)
# pick it up automatically. Rewrites the file without the old key, then appends.
_persist_env() {
  local key="$1" val="$2" envf="$SCRIPT_DIR/.env"
  touch "$envf"
  grep -v "^${key}=" "$envf" > "$envf.tmp" 2>/dev/null || true
  echo "${key}=${val}" >> "$envf.tmp"
  mv "$envf.tmp" "$envf"
}

# Resolve the data directory from an optional argument. Empty -> default
# ($SCRIPT_DIR/data). Exports INSPECTRE_DATA_DIR for compose and persists it.
set_data_dir() {
  local req="${1:-}"
  if [[ -z "$req" ]]; then
    DATA_DIR="$SCRIPT_DIR/data"
  else
    mkdir -p "$req"
    DATA_DIR="$(cd "$req" && pwd)"
  fi
  mkdir -p "$DATA_DIR/db" "$DATA_DIR/vuln/trivy" "$DATA_DIR/vuln/nuclei"
  export INSPECTRE_DATA_DIR="$DATA_DIR"
  _persist_env INSPECTRE_DATA_DIR "$DATA_DIR"
  log "Data directory: $DATA_DIR"
}

sync_version() {
  if [[ -x "$SCRIPT_DIR/scripts/sync-version.sh" ]]; then
    log "Stamping version from VERSION file into all components..."
    "$SCRIPT_DIR/scripts/sync-version.sh" || log "WARN: version sync failed (continuing)."
  fi
}

remove_project_images() {
  log "Removing local project images if present..."
  docker image rm "${PROJECT_NAME}-probe" "${PROJECT_NAME}-web" "${PROJECT_NAME}-backend" 2>/dev/null || true

  log "Pruning dangling images (old build layers)..."
  docker image prune -f || true
}

full_rebuild() {
  local keep_data="${1:-false}"
  log "Working directory: $SCRIPT_DIR"
  log "This rebuild uses the LOCAL files currently in this folder."
  log "No git fetch/pull/reset will be performed."

  log "Data directory: $DATA_DIR"
  if [[ "$keep_data" == "true" ]]; then
    log "Database contents ($DATA_DIR/db) will be preserved."
    if ! confirm "Proceed with full rebuild keeping existing data?"; then
      log "Aborted."
      exit 1
    fi
  else
    log "This will delete containers, images, build cache, AND the db/ folder (all device history)."
    log "Vuln scanner data (vuln/) will be preserved."
    if ! confirm "Are you sure you want to wipe everything?"; then
      log "Aborted."
      exit 1
    fi
  fi

  log "Stopping existing stack..."
  "${COMPOSE_CMD[@]}" down --remove-orphans || true

  if [[ "$keep_data" == "false" ]]; then
    if [[ -d "$DATA_DIR/db" ]]; then
      log "Wiping db bind mount ($DATA_DIR/db)..."
      rm -rf "$DATA_DIR/db"
    fi
  fi

  remove_project_images

  log "Pruning Docker build cache..."
  docker builder prune -af || true

  log "Rebuilding from LOCAL source with no cache..."
  sync_version
  "${COMPOSE_CMD[@]}" build --no-cache --pull

  log "Starting fresh stack..."
  "${COMPOSE_CMD[@]}" up -d --force-recreate

  log "Current container status:"
  "${COMPOSE_CMD[@]}" ps || true

  log "Recent logs:"
  "${COMPOSE_CMD[@]}" logs --tail=100 || true
}

up_stack() {
  log "Starting stack..."
  "${COMPOSE_CMD[@]}" up -d
  "${COMPOSE_CMD[@]}" ps
}

down_stack() {
  log "Stopping stack..."
  "${COMPOSE_CMD[@]}" down --remove-orphans
}

show_logs() {
  local service="${1:-}"
  if [[ -n "$service" ]]; then
    "${COMPOSE_CMD[@]}" logs -f "$service"
  else
    "${COMPOSE_CMD[@]}" logs -f
  fi
}

main() {
  require_compose

  case "${1:-}" in
    rebuild)
      if [[ "${2:-}" == "keep-data" ]]; then
        set_data_dir "${3:-}"
        full_rebuild true
      elif [[ -z "${2:-}" ]]; then
        set_data_dir ""
        full_rebuild false
      else
        # Treat a non-"keep-data" second argument as the data directory.
        set_data_dir "${2}"
        full_rebuild false
      fi
      ;;
    up)
      up_stack
      ;;
    down)
      down_stack
      ;;
    logs)
      show_logs "${2:-}"
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"