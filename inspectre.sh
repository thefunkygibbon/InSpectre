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
  ./inspectre.sh logs

Commands:
  rebuild         Full local rebuild from the CURRENT folder, wiping containers,
                  local images, build cache, and named volumes.
  rebuild keep-data
                  Full local rebuild from the CURRENT folder, but keeps volumes/data.
  up              Start the stack normally.
  down            Stop the stack.
  logs            Follow logs.

Notes:
  - This script DOES NOT run any git commands.
  - It rebuilds from the files currently present in this working directory.
  - "rebuild" is destructive to Docker volumes/data for this project.
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
    if ! confirm "[InSpectre] Proceed with full rebuild and KEEP volumes/data?"; then
      log "Aborted."
      exit 1
    fi
  else
    log "This will remove containers, local images, build cache, and project volumes/data."
    if ! confirm "[InSpectre] Are you sure?"; then
      log "Aborted."
      exit 1
    fi
  fi

  log "Stopping existing stack..."
  if [[ "$keep_data" == "true" ]]; then
    "${COMPOSE_CMD[@]}" down --remove-orphans || true
  else
    "${COMPOSE_CMD[@]}" down --volumes --remove-orphans || true
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
  "${COMPOSE_CMD[@]}" logs -f
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
      show_logs
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"