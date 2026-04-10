#!/usr/bin/env bash
set -e

echo "==> Pulling latest code..."
git fetch origin
git reset --hard origin/main
git clean -fd
chmod +x inspectre.sh

echo "==> Tearing down all containers, networks and orphans..."
docker compose down --remove-orphans --volumes 2>/dev/null || true

echo "==> Removing project images..."
docker image rm inspectre-probe inspectre-web inspectre-frontend 2>/dev/null || true
# Also catch compose-prefixed names (e.g. inspectre-inspectre-probe)
docker images --format '{{.Repository}}' | grep -i inspectre | xargs -r docker image rm 2>/dev/null || true

echo "==> Pruning build cache and dangling images..."
docker builder prune -af
docker image prune -f

echo "==> Pruning unused networks..."
docker network prune -f

echo "==> Building from scratch..."
docker compose build --no-cache --pull

echo "==> Starting stack..."
docker compose up -d --force-recreate

echo "==> Waiting for containers to settle (15s)..."
sleep 15

echo "==> Container status:"
docker compose ps

echo ""
echo "==> Checking probe internal API health..."
if docker exec inspectre-probe curl -sf http://localhost:8001/health > /dev/null 2>&1; then
    echo "    [OK] Probe API is up on :8001"
else
    echo "    [WARN] Probe API not responding on :8001 -- check logs:"
    docker logs inspectre-probe --tail 30
fi

echo ""
echo "==> Checking web API health..."
if curl -sf http://localhost:8000/ > /dev/null 2>&1; then
    echo "    [OK] Web API is up on :8000"
else
    echo "    [WARN] Web API not responding on :8000 -- check logs:"
    docker logs inspectre-web --tail 30
fi

echo ""
echo "==> Done. Frontend: http://localhost:3000  API: http://localhost:8000"
