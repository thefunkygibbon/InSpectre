#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_NAME="inspectre"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[InSpectre] Starting full reset..."

if ! command -v docker >/dev/null 2>&1; then
  echo "[InSpectre] ERROR: docker is not installed"
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "[InSpectre] ERROR: docker daemon is not running or not accessible"
  exit 1
fi

echo "[InSpectre] Stopping and removing compose stack..."
docker compose -p "$PROJECT_NAME" down --remove-orphans --volumes || true

echo "[InSpectre] Removing any leftover containers for this project..."
docker ps -aq --filter "label=com.docker.compose.project=$PROJECT_NAME" | xargs -r docker rm -f || true

echo "[InSpectre] Removing any leftover networks for this project..."
docker network ls -q --filter "label=com.docker.compose.project=$PROJECT_NAME" | xargs -r docker network rm || true

echo "[InSpectre] Removing any leftover volumes for this project..."
docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT_NAME" | xargs -r docker volume rm -f || true

echo "[InSpectre] Removing likely InSpectre images..."
docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' \
  | awk '/inspectre|InSpectre/ {print $2}' \
  | sort -u \
  | xargs -r docker rmi -f || true

echo "[InSpectre] Removing build cache..."
docker builder prune -af >/dev/null 2>&1 || true

echo "[InSpectre] Removing local data folders..."
rm -rf \
  "$SCRIPT_DIR/data" \
  "$SCRIPT_DIR/db" \
  "$SCRIPT_DIR/postgres-data" \
  "$SCRIPT_DIR/postgres" \
  "$SCRIPT_DIR/.inspectre" \
  "$SCRIPT_DIR/backend/data" \
  "$SCRIPT_DIR/backend/db" \
  "$SCRIPT_DIR/backend/postgres-data" \
  "$SCRIPT_DIR/probe/data" \
  "$SCRIPT_DIR/frontend/dist"

echo "[InSpectre] Resetting git checkout to latest main..."
git fetch origin
git reset --hard origin/main
git clean -fd
chmod 777 inspectre.sh
echo "[InSpectre] Pulling any referenced base images..."
docker compose -p "$PROJECT_NAME" pull || true

echo "[InSpectre] Rebuilding with no cache..."
docker compose -p "$PROJECT_NAME" build --no-cache --pull

echo "[InSpectre] Starting fresh stack..."
docker compose -p "$PROJECT_NAME" up -d --force-recreate

echo "[InSpectre] Current containers:"
docker compose -p "$PROJECT_NAME" ps

echo "[InSpectre] Done."
echo "[InSpectre] If it still fails, immediately run:"
echo "docker compose -p $PROJECT_NAME logs --tail=200"
