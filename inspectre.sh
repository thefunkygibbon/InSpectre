#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

PROJECT_NAME="inspectre"

echo "[inspectre] Stopping stack..."
docker compose -p "$PROJECT_NAME" down --remove-orphans --volumes || true

echo "[inspectre] Removing leftover project containers..."
docker ps -aq --filter "label=com.docker.compose.project=$PROJECT_NAME" | xargs -r docker rm -f

echo "[inspectre] Removing leftover project volumes..."
docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT_NAME" | xargs -r docker volume rm -f

echo "[inspectre] Removing leftover project network..."
docker network ls -q --filter "label=com.docker.compose.project=$PROJECT_NAME" | xargs -r docker network rm

echo "[inspectre] Removing leftover project images..."
docker images -q --filter "label=com.docker.compose.project=$PROJECT_NAME" | xargs -r docker rmi -f

echo "[inspectre] Rebuilding fresh..."
docker compose -p "$PROJECT_NAME" up -d --build

echo "[inspectre] Done."
