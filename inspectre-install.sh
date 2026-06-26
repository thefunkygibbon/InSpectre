#!/usr/bin/env bash
# InSpectre interactive installer
# Downloads docker-compose.deploy.yml, prompts for configuration,
# writes a .env file, and starts the stack.
set -euo pipefail

# Ensure the script always reads from the terminal even when piped (e.g. curl | bash)
[ -t 0 ] || exec bash "$0" "$@" </dev/tty

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
echo -e "${CYAN}  ██╗███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗${NC}"
echo -e "${CYAN}  ██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝${NC}"
echo -e "${CYAN}  ██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗  ${NC}"
echo -e "${CYAN}  ██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝  ${NC}"
echo -e "${CYAN}  ██║██║ ╚████║███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗${NC}"
echo -e "${CYAN}  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝${NC}"
echo ""
echo "  InSpectre Installer — Know every device on your network"
echo ""

# ── Check dependencies ──────────────────────────────────────
header "Checking prerequisites"

MISSING=0

# Docker Engine
if ! command -v docker &>/dev/null; then
  warn "Docker is not installed."
  echo "      Install Docker Engine 24+ : https://docs.docker.com/engine/install/"
  MISSING=1
else
  ok "Docker found: $(docker --version)"
  if ! docker info &>/dev/null; then
    warn "Docker is installed but the daemon is not reachable."
    echo "      Start it with:  sudo systemctl start docker"
    echo "      If you get a permission error, add yourself to the docker group:"
    echo "        sudo usermod -aG docker \$USER   (then log out and back in)"
    MISSING=1
  else
    ok "Docker daemon is running"
  fi
fi

# Docker Compose v2
if docker compose version &>/dev/null 2>&1; then
  ok "Docker Compose v2 found"
elif docker-compose version &>/dev/null 2>&1; then
  warn "Found legacy docker-compose (v1). InSpectre requires Compose v2 ('docker compose')."
  echo "      Migrate: https://docs.docker.com/compose/migrate/"
  MISSING=1
else
  warn "Docker Compose v2 is not installed."
  echo "      Install : https://docs.docker.com/compose/install/"
  MISSING=1
fi

# curl
if command -v curl &>/dev/null; then
  ok "curl found"
else
  warn "curl is required but not installed."
  echo "      Install : sudo apt-get install curl   (or your distro's equivalent)"
  MISSING=1
fi

# openssl
if command -v openssl &>/dev/null; then
  ok "openssl found"
else
  warn "openssl is required (used to generate secure passwords) but not installed."
  echo "      Install : sudo apt-get install openssl   (or your distro's equivalent)"
  MISSING=1
fi

if [ "$MISSING" -ne 0 ]; then
  die "One or more prerequisites are missing. Please install them and re-run this script."
fi
ok "All prerequisites satisfied"

# ── Architecture / platform selection ───────────────────────
header "Platform selection"
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
  x86_64|amd64)            DETECTED="x64";  DETECTED_LABEL="x86-64 / Intel / AMD" ;;
  aarch64|arm64)           DETECTED="pi";   DETECTED_LABEL="ARM64 (Raspberry Pi 3/4/5, 64-bit)" ;;
  armv7l|armv6l|armhf)     DETECTED="pi";   DETECTED_LABEL="ARM (32-bit)" ;;
  *)                       DETECTED="";     DETECTED_LABEL="unknown ($HOST_ARCH)" ;;
esac

echo "  Detected host architecture: ${HOST_ARCH}  (${DETECTED_LABEL})"
echo ""
echo "  Which InSpectre images should be installed?"
echo "    1) x64        — Intel / AMD 64-bit servers, NAS, desktops   (image tag: latest)"
echo "    2) raspberry  — Raspberry Pi / ARM64                        (image tag: raspi)"
echo ""

if [ "$DETECTED" = "x64" ]; then
  DEFAULT_CHOICE="1"
elif [ "$DETECTED" = "pi" ]; then
  DEFAULT_CHOICE="2"
else
  DEFAULT_CHOICE="1"
fi

read -rp "  Select platform [${DEFAULT_CHOICE}]: " PLATFORM_CHOICE </dev/tty
PLATFORM_CHOICE="${PLATFORM_CHOICE:-$DEFAULT_CHOICE}"

case "$PLATFORM_CHOICE" in
  1|x64|amd64|intel|amd)          INSPECTRE_TAG="latest" ;;
  2|pi|raspberry|raspi|arm|arm64)  INSPECTRE_TAG="raspi"  ;;
  *) die "Invalid selection '${PLATFORM_CHOICE}'. Choose 1 (x64) or 2 (raspberry)." ;;
esac

if { [ "$INSPECTRE_TAG" = "latest" ] && [ "$DETECTED" = "pi" ]; } || \
   { [ "$INSPECTRE_TAG" = "raspi"  ] && [ "$DETECTED" = "x64" ]; }; then
  warn "You selected images for a different architecture than this host ($HOST_ARCH)."
  warn "The containers will fail to start unless this is intentional (e.g. emulation)."
  read -rp "  Continue anyway? [y/N]: " ARCH_CONFIRM </dev/tty
  [[ "$ARCH_CONFIRM" =~ ^[Yy]$ ]] || die "Aborted by user."
fi

if [ "$INSPECTRE_TAG" = "raspi" ]; then
  case "$HOST_ARCH" in
    armv7l|armv6l|armhf)
      warn "This host is running a 32-bit OS ($HOST_ARCH), but the Raspberry Pi images are 64-bit (ARM64) only."
      warn "Install a 64-bit Raspberry Pi OS (Pi 3/4/5) to run InSpectre."
      read -rp "  Continue anyway? [y/N]: " BIT_CONFIRM </dev/tty
      [[ "$BIT_CONFIRM" =~ ^[Yy]$ ]] || die "Aborted by user."
      ;;
  esac
fi
ok "Installing '${INSPECTRE_TAG}' images for ${HOST_ARCH}"

# ── Install directory ────────────────────────────────────────
header "Install location"
read -rp "  Install directory [${DEFAULT_DIR}]: " INSTALL_DIR </dev/tty
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
read -rp "  Enter DB password (leave blank to generate): " DB_PASS </dev/tty
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
read -rp "  Set IP_RANGE manually? (e.g. 192.168.1.0/24) [leave blank = auto]: " IP_RANGE_INPUT </dev/tty
read -rp "  Set INTERFACE manually? (e.g. eth0) [leave blank = auto]: "          IFACE_INPUT </dev/tty

# ── Write .env ───────────────────────────────────────────────
header "Writing .env"
cat > .env <<EOF
# InSpectre environment — generated by inspectre-install.sh
INSPECTRE_TAG=${INSPECTRE_TAG}
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
echo "  Useful commands (run from ${INSTALL_DIR}):"
echo "    cd ${INSTALL_DIR}"
echo "    docker compose -f docker-compose.deploy.yml logs -f      # view logs"
echo "    docker compose -f docker-compose.deploy.yml down         # stop"
echo "    docker compose -f docker-compose.deploy.yml pull && \\"
echo "      docker compose -f docker-compose.deploy.yml up -d      # update to latest"
echo ""
