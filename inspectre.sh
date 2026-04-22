#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_NAME="${COMPOSE_PROJECT_NAME:-inspectre}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

usage() {
  cat <<EOF
Usage:
  ./inspectre.sh rebuild
  ./inspectre.sh rebuild keep-data
  ./inspectre.sh up
  ./inspectre.sh down
  ./inspectre.sh logs [service]

Commands:
  rebuild         Full rebuild from the current folder — wipes containers, images,
                  build cache, AND the postgres_data/ folder (all device history).
  rebuild keep-data
                  Full rebuild but leaves postgres_data/ intact (devices, history, settings
                  are preserved across the rebuild).
  up              Start the stack normally.
  down            Stop the stack.
  logs [service]  Follow logs. Optionally filter to a single service, e.g. probe, backend, web.

Notes:
  - This script does NOT run any git commands.
  - It rebuilds from the files currently present in this working directory.
  - Database data lives in ./postgres_data/ (a bind mount, not a named volume).
    "rebuild" deletes that folder; "rebuild keep-data" leaves it untouched.
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

remove_project_images() {
  log "Removing local project images if present..."
  docker image rm "${PROJECT_NAME}-probe" "${PROJECT_NAME}-web" "${PROJECT_NAME}-backend" 2>/dev/null || true
}

full_rebuild() {
  local keep_data="${1:-false}"

  log "Working directory: $SCRIPT_DIR"
  log "This rebuild uses the LOCAL files currently in this folder."
  log "No git fetch/pull/reset will be performed."

  if [[ "$keep_data" == "true" ]]; then
    log "Database contents (postgres_data/) will be preserved."
    if ! confirm "Proceed with full rebuild keeping existing data?"; then
      log "Aborted."
      exit 1
    fi
  else
    log "This will delete containers, images, build cache, AND the postgres_data/ folder (all device history)."
    if ! confirm "Are you sure you want to wipe everything?"; then
      log "Aborted."
      exit 1
    fi
  fi

  log "Stopping existing stack..."
  "${COMPOSE_CMD[@]}" down --volumes --remove-orphans || true

  if [[ "$keep_data" == "false" ]]; then
    if [[ -d "$SCRIPT_DIR/postgres_data" ]]; then
      log "Wiping postgres_data bind mount..."
      rm -rf "$SCRIPT_DIR/postgres_data"
    fi
  fi

  remove_project_images

  log "Pruning Docker build cache..."
  docker builder prune -af || true

  log "Rebuilding from LOCAL source with no cache..."
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
      case "${2:-}" in
        keep-data)
          full_rebuild true
          ;;
        "" )
          full_rebuild false
          ;;
        *)
          usage
          exit 1
          ;;
      esac
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