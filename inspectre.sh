#!/usr/bin/env bash
set -e

echo "==> Pulling latest code..."
git fetch origin
git reset --hard origin/main
git clean -fd
chmod +x inspectre.sh

echo "==> Tearing down all containers, networks and orphans..."
docker compose down --remove-orphans --volumes 2>/dev/null || true

echo "==> Removing InSpectre images only..."
docker image rm inspectre-probe inspectre-web inspectre-frontend 2>/dev/null || true
# Catch compose-prefixed variants (e.g. inspectre-inspectre-probe)
docker images --format '{{.Repository}}:{{.Tag}}' \
  | grep -i '^inspectre' \
  | xargs -r docker image rm 2>/dev/null || true

# NOTE: We do NOT run docker builder prune or docker image prune here.
# Those are system-wide and would delete cached layers from other projects on this host.

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
