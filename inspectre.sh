#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="InSpectre"

# ------------------------------------------------------------------
# Paths
# ------------------------------------------------------------------
# Recommended layout:
#   ~/InSpectre-main   -> stable checkout on main
#   ~/InSpectre-test   -> test checkout / worktree for test branches
#
# You can override any of these with env vars before running the script.
MAIN_REPO_DIR="${MAIN_REPO_DIR:-$HOME/InSpectre-main}"
TEST_REPO_DIR="${TEST_REPO_DIR:-$HOME/InSpectre-test}"

# Default branch aliases
MAIN_BRANCH="${MAIN_BRANCH:-main}"
TEST_BRANCH="${TEST_BRANCH:-test}"

COMPOSE_BIN="${COMPOSE_BIN:-docker compose}"

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
info()  { echo "[$APP_NAME] $*"; }
warn()  { echo "[$APP_NAME] WARNING: $*" >&2; }
error() { echo "[$APP_NAME] ERROR: $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  ./inspectre.sh rebuild main
  ./inspectre.sh rebuild test
  ./inspectre.sh rebuild <branch-name>
  ./inspectre.sh status [main|test|branch-name]
  ./inspectre.sh logs [main|test|branch-name]
  ./inspectre.sh branch [main|test|branch-name]
  ./inspectre.sh pull [main|test|branch-name]
  ./inspectre.sh help

Examples:
  ./inspectre.sh rebuild main
  ./inspectre.sh rebuild test
  ./inspectre.sh rebuild fix/offline-ping
  ./inspectre.sh logs test

Notes:
- "main" uses MAIN_REPO_DIR and MAIN_BRANCH.
- "test" uses TEST_REPO_DIR and TEST_BRANCH.
- Any other branch name uses TEST_REPO_DIR by default.
- rebuild is destructive to the selected working tree:
  it does git reset --hard origin/<branch> and git clean -fd
EOF
  exit 1
}

require_repo() {
  local repo_dir="$1"
  [ -d "$repo_dir/.git" ] || error "Git repo not found at $repo_dir"
}

resolve_target() {
  local target="${1:-main}"

  case "$target" in
    main)
      RESOLVED_REPO_DIR="$MAIN_REPO_DIR"
      RESOLVED_BRANCH="$MAIN_BRANCH"
      ;;
    test)
      RESOLVED_REPO_DIR="$TEST_REPO_DIR"
      RESOLVED_BRANCH="$TEST_BRANCH"
      ;;
    *)
      RESOLVED_REPO_DIR="$TEST_REPO_DIR"
      RESOLVED_BRANCH="$target"
      ;;
  esac
}

run_compose() {
  local repo_dir="$1"
  shift
  (cd "$repo_dir" && $COMPOSE_BIN "$@")
}

confirm_destructive() {
  local repo_dir="$1"
  local branch="$2"

  info "About to fully reset repo:"
  info "  Repo:   $repo_dir"
  info "  Branch: $branch"
  info "This will discard ALL local changes in that working tree."
  read -r -p "Continue? [y/N]: " reply
  case "$reply" in
    y|Y|yes|YES) ;;
    *) error "Cancelled." ;;
  esac
}

ensure_local_branch_tracks_remote() {
  local repo_dir="$1"
  local branch="$2"

  cd "$repo_dir"

  info "Fetching latest refs from origin..."
  git fetch origin --prune

  if git show-ref --verify --quiet "refs/remotes/origin/$branch"; then
    if git show-ref --verify --quiet "refs/heads/$branch"; then
      info "Checking out existing local branch: $branch"
      git checkout "$branch"
    else
      info "Creating local branch $branch tracking origin/$branch"
      git checkout -b "$branch" "origin/$branch"
    fi
  else
    error "Remote branch origin/$branch does not exist."
  fi
}

hard_sync_branch() {
  local repo_dir="$1"
  local branch="$2"

  require_repo "$repo_dir"
  ensure_local_branch_tracks_remote "$repo_dir" "$branch"

  cd "$repo_dir"

  info "Resetting working tree to origin/$branch"
  git reset --hard "origin/$branch"
  git clean -fd

  info "Now on branch: $(git branch --show-current)"
  info "Commit: $(git rev-parse --short HEAD)"
}

pull_branch_only() {
  local repo_dir="$1"
  local branch="$2"

  require_repo "$repo_dir"
  ensure_local_branch_tracks_remote "$repo_dir" "$branch"

  cd "$repo_dir"

  info "Hard syncing from GitHub..."
  git reset --hard "origin/$branch"
  git clean -fd

  info "Repo updated to:"
  info "  Branch: $(git branch --show-current)"
  info "  Commit: $(git rev-parse --short HEAD)"
}

docker_rebuild_stack() {
  local repo_dir="$1"

  require_repo "$repo_dir"

  info "Stopping containers and removing orphans..."
  run_compose "$repo_dir" down --remove-orphans || true

  info "Building fresh images with no cache..."
  run_compose "$repo_dir" build --no-cache

  info "Starting fresh stack..."
  run_compose "$repo_dir" up -d --force-recreate

  info "Stack status:"
  run_compose "$repo_dir" ps
}

show_status() {
  local repo_dir="$1"

  require_repo "$repo_dir"
  cd "$repo_dir"

  info "Repo:   $repo_dir"
  info "Branch: $(git branch --show-current)"
  info "Commit: $(git rev-parse --short HEAD)"
  info "Remote: $(git remote get-url origin)"
  echo
  run_compose "$repo_dir" ps || true
}

show_logs() {
  local repo_dir="$1"

  require_repo "$repo_dir"
  info "Streaming docker logs from $repo_dir"
  run_compose "$repo_dir" logs -f
}

show_branch() {
  local repo_dir="$1"

  require_repo "$repo_dir"
  cd "$repo_dir"

  echo "Repo:   $repo_dir"
  echo "Branch: $(git branch --show-current)"
  echo "Commit: $(git rev-parse --short HEAD)"
}

# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------
ACTION="${1:-help}"
TARGET="${2:-main}"

case "$ACTION" in
  rebuild)
    resolve_target "$TARGET"
    confirm_destructive "$RESOLVED_REPO_DIR" "$RESOLVED_BRANCH"
    hard_sync_branch "$RESOLVED_REPO_DIR" "$RESOLVED_BRANCH"
    docker_rebuild_stack "$RESOLVED_REPO_DIR"
    ;;
  pull)
    resolve_target "$TARGET"
    confirm_destructive "$RESOLVED_REPO_DIR" "$RESOLVED_BRANCH"
    pull_branch_only "$RESOLVED_REPO_DIR" "$RESOLVED_BRANCH"
    ;;
  status)
    resolve_target "$TARGET"
    show_status "$RESOLVED_REPO_DIR"
    ;;
  logs)
    resolve_target "$TARGET"
    show_logs "$RESOLVED_REPO_DIR"
    ;;
  branch)
    resolve_target "$TARGET"
    show_branch "$RESOLVED_REPO_DIR"
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    usage
    ;;
esac
