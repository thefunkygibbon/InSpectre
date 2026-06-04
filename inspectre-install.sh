#!/usr/bin/env bash
# InSpectre interactive installer
# Downloads docker-compose.deploy.yml, prompts for configuration,
# writes a .env file, and starts the stack.
set -euo pipefail

DEPLOY_YML_URL="https://raw.githubusercontent.com/thefunkygibbon/InSpectre/main/docker-compose.deploy.yml"
DEFAULT_DIR="$HOME/inspectre"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

header() { echo -e "\n${CYAN}==> $1${NC}"; }
ok()     { echo -e "${GREEN}✔  $1${NC}"; }
warn()   { echo -e "${YELLOW}⚠  $1${NC}"; }
die()    { echo -e "${RED}✖  $1${NC}" >&2; exit 1; }

echo ""
echo -e "${CYAN}  ██████╗ ███╗   ██╗███████╗██████╗  █████╗  ██████╗████████╗██████╗ ███████╗${NC}"
echo -e "${CYAN}  ██╔══██╗████╗  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔════╝${NC}"
echo -e "${CYAN}  ██║  ██║██╔██╗ ██║███████╗██████╔╝███████║██║        ██║   ██████╔╝█████╗  ${NC}"
echo -e "${CYAN}  ██║  ██║██║╚██╗██║╚════██║██╔═══╝ ██╔══██║██║        ██║   ██╔══██╗██╔══╝  ${NC}"
echo -e "${CYAN}  ██████╔╝██║ ╚████║███████║██║     ██║  ██║╚██████╗   ██║   ██║  ██║███████╗${NC}"
echo -e "${CYAN}  ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝${NC}"
echo ""
echo "  InSpectre Installer — Know every device on your network"
echo ""

# ── Check dependencies ──────────────────────────────────────
header "Checking dependencies"

if ! command -v docker &>/dev/null; then
  die "Docker is not installed. Install Docker Engine 24+ from https://docs.docker.com/engine/install/"
fi
ok "Docker found: $(docker --version)"

if docker compose version &>/dev/null 2>&1; then
  ok "Docker Compose v2 found"
elif docker-compose version &>/dev/null 2>&1; then
  warn "Found docker-compose (v1). InSpectre requires Docker Compose v2 ('docker compose' plugin)."
  warn "See: https://docs.docker.com/compose/migrate/"
  die "Please install the Docker Compose v2 plugin and try again."
else
  die "Docker Compose v2 is not installed. Install it from https://docs.docker.com/compose/install/"
fi

if ! command -v curl &>/dev/null; then
  die "curl is required but not installed."
fi

# ── Install directory ────────────────────────────────────────
header "Install location"
read -rp "  Install directory [${DEFAULT_DIR}]: " INSTALL_DIR
INSTALL_DIR="${INSTALL_DIR:-$DEFAULT_DIR}"
INSTALL_DIR="${INSTALL_DIR/#\~/$HOME}"

if [ -d "$INSTALL_DIR" ]; then
  warn "Directory $INSTALL_DIR already exists."
else
  mkdir -p "$INSTALL_DIR"
  ok "Created $INSTALL_DIR"
fi
cd "$INSTALL_DIR"

# ── Download compose file ────────────────────────────────────
header "Downloading docker-compose.deploy.yml"
if [ -f "docker-compose.deploy.yml" ]; then
  warn "docker-compose.deploy.yml already exists — skipping download."
else
  curl -fsSL "$DEPLOY_YML_URL" -o docker-compose.deploy.yml
  ok "Downloaded docker-compose.deploy.yml"
fi

# ── Database password ────────────────────────────────────────
header "Database password"
echo "  InSpectre needs a strong password for its internal PostgreSQL database."
echo "  This is never exposed externally."
read -rp "  Enter DB password (leave blank to generate): " DB_PASS
if [ -z "$DB_PASS" ]; then
  DB_PASS="$(openssl rand -hex 20)"
  ok "Generated database password"
else
  ok "Using provided database password"
fi

# ── Secret key ───────────────────────────────────────────────
header "Secret key"
echo "  A random secret key is used to sign JWT authentication tokens."
SECRET_KEY="$(openssl rand -hex 32)"
ok "Generated secret key"

# ── Network settings ─────────────────────────────────────────
header "Network settings"
echo "  The probe can auto-detect your network interface and IP range from the"
echo "  host's routing table. Override only if auto-detection picks the wrong NIC."
read -rp "  Set IP_RANGE manually? (e.g. 192.168.1.0/24) [leave blank = auto]: " IP_RANGE_INPUT
read -rp "  Set INTERFACE manually? (e.g. eth0) [leave blank = auto]: "          IFACE_INPUT

# ── Write .env ───────────────────────────────────────────────
header "Writing .env"
cat > .env <<EOF
# InSpectre environment — generated by inspectre-install.sh
POSTGRES_PASSWORD=${DB_PASS}
SECRET_KEY=${SECRET_KEY}
DATA_DIR=${INSTALL_DIR}/data
EOF

if [ -n "$IP_RANGE_INPUT" ]; then
  echo "IP_RANGE=${IP_RANGE_INPUT}" >> .env
fi
if [ -n "$IFACE_INPUT" ]; then
  echo "INTERFACE=${IFACE_INPUT}" >> .env
fi

ok ".env written to ${INSTALL_DIR}/.env"

# Note: if IP_RANGE / INTERFACE are set, the deploy yml reads them from .env
# via the ${IP_RANGE} / ${INTERFACE} substitution. Since those lines are
# commented-out in the yml by default, we patch the file if needed.
if [ -n "$IP_RANGE_INPUT" ]; then
  sed -i "s|# IP_RANGE: \"192.168.1.0/24\"|IP_RANGE: \"${IP_RANGE_INPUT}\"|" docker-compose.deploy.yml
fi
if [ -n "$IFACE_INPUT" ]; then
  sed -i "s|# INTERFACE: \"eth0\"|INTERFACE: \"${IFACE_INPUT}\"|" docker-compose.deploy.yml
fi

# ── Start the stack ──────────────────────────────────────────
header "Starting InSpectre"
echo "  Pulling images and starting containers (this may take a minute)..."
docker compose -f docker-compose.deploy.yml up -d

echo ""
ok "InSpectre is running!"
echo ""
echo -e "  ${GREEN}Open your browser and go to:  http://localhost:3000${NC}"
echo ""
echo "  Complete the first-run setup wizard to create your admin account"
echo "  and configure your network settings."
echo ""
echo "  Useful commands:"
echo "    docker compose -f ${INSTALL_DIR}/docker-compose.deploy.yml logs -f"
echo "    docker compose -f ${INSTALL_DIR}/docker-compose.deploy.yml down"
echo "    docker compose -f ${INSTALL_DIR}/docker-compose.deploy.yml pull && \\"
echo "      docker compose -f ${INSTALL_DIR}/docker-compose.deploy.yml up -d"
echo ""
