
#!/usr/bin/env bash
set -e

git fetch origin
git reset --hard origin/main
git clean -fd
chmod 777 inspectre.sh
docker compose down --remove-orphans
docker image rm inspectre-probe inspectre-web 2>/dev/null || true
docker builder prune -af
docker compose build --no-cache --pull
docker compose up --force-recreate
docker compose down --remove-orphans

