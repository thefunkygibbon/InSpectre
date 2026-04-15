#!/usr/bin/env bash
# =============================================================================
#  inspectre.sh  —  InSpectre management script
#
#  Usage:
#    ./inspectre.sh start      Build (if needed) and start all containers
#    ./inspectre.sh stop       Stop and remove containers
#    ./inspectre.sh restart    Stop then start
#    ./inspectre.sh rebuild    Full nuclear reset — wipe images/cache/data, rebuild from scratch
#    ./inspectre.sh update     Pull latest git changes and restart
#    ./inspectre.sh logs       Tail logs from all containers (Ctrl-C to exit)
#    ./inspectre.sh status     Show running container status
# =============================================================================
set -Eeuo pipefail

PROJECT_NAME="inspectre"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_banner()  { echo ""; echo "  ██╗███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗"; \
                      echo "  ██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝"; \
                      echo "  ██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗  "; \
                      echo "  ██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝  "; \
                      echo "  ██║██║ ╚████║███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗"; \
                      echo "  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝"; \
                      echo ""; }
_info()    { echo "[InSpectre] $*"; }
_success() { echo "[InSpectre] ✓ $*"; }
_warn()    { echo "[InSpectre] ⚠  $*"; }
_error()   { echo "[InSpectre] ✗  ERROR: $*" >&2; }
_die()     { _error "$*"; exit 1; }

_check_deps() {
  command -v docker >/dev/null 2>&1 || _die "docker is not installed"
  docker info >/dev/null 2>&1       || _die "docker daemon is not running or not accessible"
}

_compose() {
  docker compose -p "$PROJECT_NAME" "$@"
}

_frontend_port() {
  # Read the host port for the frontend service from docker-compose.yml
  grep -A3 'container_name: inspectre-frontend' docker-compose.yml \
    | grep -oP '"\K[0-9]+(?=:80")' | head -1 || echo "3000"
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
cmd_start() {
  _info "Starting InSpectre..."
  _check_deps
  _compose up -d --build
  _success "All containers started."
  local port; port=$(_frontend_port)
  _info "Dashboard: http://$(hostname -I | awk '{print $1}'):${port}"
  _info "API:       http://$(hostname -I | awk '{print $1}'):8000"
  echo ""
  _compose ps
}

cmd_stop() {
  _info "Stopping InSpectre..."
  _check_deps
  _compose down --remove-orphans
  _success "All containers stopped."
}

cmd_restart() {
  _info "Restarting InSpectre..."
  _check_deps
  _compose down --remove-orphans
  _compose up -d --build
  _success "All containers restarted."
  local port; port=$(_frontend_port)
  _info "Dashboard: http://$(hostname -I | awk '{print $1}'):${port}"
}

cmd_logs() {
  _check_deps
  _info "Tailing logs (Ctrl-C to stop)..."
  _compose logs -f --tail=100
}

cmd_status() {
  _check_deps
  _compose ps
}

cmd_update() {
  _info "Pulling latest changes from git..."
  _check_deps
  git fetch origin
  git pull --ff-only origin main || {
    _warn "Fast-forward pull failed — you may have local changes. Skipping git pull."
  }
  _info "Rebuilding and restarting (no cache)..."
  _compose down --remove-orphans

  _info "Removing InSpectre images so layers are not reused..."
  docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' \
    | awk '/inspectre|InSpectre/ {print $2}' \
    | sort -u \
    | xargs -r docker rmi -f || true

  _info "Clearing build cache..."
  docker builder prune -af >/dev/null 2>&1 || true

  _compose up -d --build --no-cache 2>/dev/null || _compose up -d --build
  _success "Update complete."
  local port; port=$(_frontend_port)
  _info "Dashboard: http://$(hostname -I | awk '{print $1}'):${port}"
  echo ""
  _compose ps
}

cmd_rebuild() {
  _info "Starting full rebuild (this will wipe all containers, images, cache, and data)..."
  _check_deps

  local confirm
  read -rp "[InSpectre] Are you sure? This deletes the database and all scan history. [y/N] " confirm
  [[ "${confirm,,}" == "y" ]] || { _info "Aborted."; exit 0; }

  # ── 1. Pull latest code first ──────────────────────────────────────────────
  _info "Pulling latest code from git..."
  git fetch origin
  git pull --ff-only origin main || {
    _warn "Fast-forward pull failed — you may have local changes. Continuing with current code."
  }

  # ── 2. Tear down compose stack (removes named volumes too) ─────────────────
  _info "Stopping and removing compose stack..."
  _compose down --remove-orphans --volumes || true

  # ── 3. Remove any leftover containers ──────────────────────────────────────
  _info "Removing any leftover containers..."
  docker ps -aq --filter "label=com.docker.compose.project=$PROJECT_NAME" \
    | xargs -r docker rm -f || true

  # ── 4. Remove any leftover networks ────────────────────────────────────────
  _info "Removing any leftover networks..."
  docker network ls -q --filter "label=com.docker.compose.project=$PROJECT_NAME" \
    | xargs -r docker network rm || true

  # ── 5. Remove any leftover named volumes ───────────────────────────────────
  _info "Removing any leftover named volumes..."
  docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT_NAME" \
    | xargs -r docker volume rm -f || true

  # ── 6. Remove InSpectre images ─────────────────────────────────────────────
  _info "Removing InSpectre images..."
  docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' \
    | awk '/inspectre|InSpectre/ {print $2}' \
    | sort -u \
    | xargs -r docker rmi -f || true

  # ── 7. Prune dangling images left behind ───────────────────────────────────
  _info "Pruning dangling images..."
  docker image prune -f >/dev/null 2>&1 || true

  # ── 8. Clear all build cache ───────────────────────────────────────────────
  _info "Clearing build cache..."
  docker builder prune -af >/dev/null 2>&1 || true

  # ── 9. Wipe local data / bind-mount directories ────────────────────────────
  _info "Removing local data folders (postgres bind-mount, caches, build artefacts)..."

  # postgres bind-mount (as defined in docker-compose.yml)
  rm -rf \
    "$SCRIPT_DIR/postgres_data" \
    "$SCRIPT_DIR/postgres-data" \
    "$SCRIPT_DIR/postgres" \
    "$SCRIPT_DIR/data" \
    "$SCRIPT_DIR/db" \
    "$SCRIPT_DIR/.inspectre" \
    "$SCRIPT_DIR/backend/data" \
    "$SCRIPT_DIR/backend/db" \
    "$SCRIPT_DIR/backend/postgres-data"

  # Python bytecode caches (probe + backend)
  find "$SCRIPT_DIR/probe"   -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
  find "$SCRIPT_DIR/probe"   -type f -name "*.pyc"       -delete               2>/dev/null || true
  find "$SCRIPT_DIR/probe"   -type f -name "*.pyo"       -delete               2>/dev/null || true
  find "$SCRIPT_DIR/backend" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
  find "$SCRIPT_DIR/backend" -type f -name "*.pyc"       -delete               2>/dev/null || true
  find "$SCRIPT_DIR/backend" -type f -name "*.pyo"       -delete               2>/dev/null || true

  # Python dist/egg-info artefacts
  find "$SCRIPT_DIR/probe"   -type d \( -name "*.egg-info" -o -name "dist" -o -name "build" \) \
    -exec rm -rf {} + 2>/dev/null || true
  find "$SCRIPT_DIR/backend" -type d \( -name "*.egg-info" -o -name "dist" -o -name "build" \) \
    -exec rm -rf {} + 2>/dev/null || true

  # Frontend build artefacts + dependency cache
  rm -rf \
    "$SCRIPT_DIR/frontend/dist" \
    "$SCRIPT_DIR/frontend/build" \
    "$SCRIPT_DIR/frontend/.next" \
    "$SCRIPT_DIR/frontend/.nuxt" \
    "$SCRIPT_DIR/frontend/node_modules" \
    "$SCRIPT_DIR/frontend/.vite" \
    "$SCRIPT_DIR/frontend/.cache"

  # ── 10. Pull latest base images ────────────────────────────────────────────
  _info "Pulling latest base images..."
  _compose pull || true

  # ── 11. Rebuild and start ──────────────────────────────────────────────────
  _info "Rebuilding with no cache..."
  _compose build --no-cache --pull

  _info "Starting fresh stack..."
  _compose up -d --force-recreate

  _success "Rebuild complete."
  local port; port=$(_frontend_port)
  _info "Dashboard: http://$(hostname -I | awk '{print $1}'):${port}"
  echo ""
  _compose ps
}

cmd_help() {
  _banner
  cat <<EOF
  Usage: ./inspectre.sh <command>

  Commands:
    start     Build (if needed) and start all containers
    stop      Stop and remove containers
    restart   Stop then start
    rebuild   Full wipe and rebuild from scratch (destructive — prompts for confirmation)
    update    Pull latest git changes and restart
    logs      Tail logs from all containers (Ctrl-C to exit)
    status    Show running container status
    help      Show this help message

EOF
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
COMMAND="${1:-help}"

case "$COMMAND" in
  start)   cmd_start   ;;
  stop)    cmd_stop    ;;
  restart) cmd_restart ;;
  rebuild) cmd_rebuild ;;
  update)  cmd_update  ;;
  logs)    cmd_logs    ;;
  status)  cmd_status  ;;
  help|--help|-h) cmd_help ;;
  *)
    _error "Unknown command: '$COMMAND'"
    cmd_help
    exit 1
    ;;
esac
