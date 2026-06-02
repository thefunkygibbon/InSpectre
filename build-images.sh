#!/usr/bin/env bash
# =============================================================================
#  InSpectre — Appliance Image Builder  v5.3 (Production Master)
# =============================================================================
set -euo pipefail
export DOCKER_BUILDKIT=1
export DEBIAN_FRONTEND=noninteractive

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}${CYAN}━━━  $* ━━━${NC}"; }

# ── Defaults & Toggles ────────────────────────────────────────────────────────
BUILD_VM=false
BUILD_VM_ONLINE=false
BUILD_PI=false
BUILD_PI_ONLINE=false
BUILD_CONTAINERS_AMD=false
BUILD_CONTAINERS_ARM=false
CLI_TARGET_SPECIFIED=false
MAX_COMPRESS=false
PUSH_DOCKERHUB=false
VM_BASE_OS="ubuntu"   # "ubuntu" or "debian" — set interactively or via --debian flag

REPO_URL="https://github.com/thefunkygibbon/InSpectre.git"
REPO_BRANCH="main"
OUTPUT_DIR="$(pwd)/output"
CACHE_DIR="${OUTPUT_DIR}/.cache"
VM_DISK_SIZE="20G"
VM_ONLINE_DISK_SIZE="8G"
VM_IMAGE="inspectre-vm.qcow2"
VM_ONLINE_IMAGE="inspectre-vm-online.qcow2"
PI_IMAGE="inspectre-pi.img"
PI_ONLINE_IMAGE="inspectre-pi-online.img"

# ── Base OS image URLs ────────────────────────────────────────────────────────
UBUNTU_URL="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
UBUNTU_SHA_URL="https://cloud-images.ubuntu.com/jammy/current/SHA256SUMS"
DEBIAN_URL="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2"
RPI_INDEX="https://downloads.raspberrypi.com/raspios_lite_arm64/images"

WORK="$(mktemp -d /tmp/inspectre-build.XXXXXX)"
REPO="${WORK}/repo"
TAR_AMD="${CACHE_DIR}/inspectre-amd64.tar"
TAR_ARM="${CACHE_DIR}/inspectre-arm64.tar"

mkdir -p "${CACHE_DIR}"

# ── Args ──────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --vm-only)        BUILD_VM=true;         CLI_TARGET_SPECIFIED=true ;;
    --vm-online-only) BUILD_VM_ONLINE=true;  CLI_TARGET_SPECIFIED=true ;;
    --pi-only)        BUILD_PI=true;         CLI_TARGET_SPECIFIED=true ;;
    --pi-online-only) BUILD_PI_ONLINE=true;  CLI_TARGET_SPECIFIED=true ;;
    --compress)       MAX_COMPRESS=true ;;
    --push)           PUSH_DOCKERHUB=true ;;
    --debian)         VM_BASE_OS="debian" ;;
    --ubuntu)         VM_BASE_OS="ubuntu" ;;
    --branch)         REPO_BRANCH="$2"; shift ;;
    --output-dir)     OUTPUT_DIR="$2"; shift ;;
    --help|-h)        sed -n '2,15p' "$0" | sed 's/^#  \{0,2\}//'; exit 0 ;;
    *)                die "Unknown option: $1" ;;
  esac
  shift
done

# ── Interactive Menu ──────────────────────────────────────────────────────────
if ! $CLI_TARGET_SPECIFIED; then
  echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}${BOLD}║            Select a Build Option                 ║${NC}"
  echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
  echo -e "  1) Build x64 Docker Container Images Only"
  echo -e "  2) Build ARM Docker Container Images Only"
  echo -e "  3) Build x64 VM Appliance — Offline (containers baked in)"
  echo -e "  4) Build x64 VM Appliance — Online  (pulls from Docker Hub on boot)"
  echo -e "  5) Build Raspberry Pi Image — Offline (containers baked in)"
  echo -e "  6) Build Raspberry Pi Image — Online  (pulls from Docker Hub on boot)"
  echo -e "  7) Build Everything (All Container & Appliance Images)"
  echo -e "  q) Quit"
  echo ""
  read -rp "Enter selection [1-7/q]: " choice
  echo ""

  case "$choice" in
    1) BUILD_CONTAINERS_AMD=true ;;
    2) BUILD_CONTAINERS_ARM=true ;;
    3)
      BUILD_VM=true
      if [[ -f "$TAR_AMD" ]]; then
        read -rp "Found cached x64 containers. Re-compile? [y/N]: " recompile
        [[ "$recompile" =~ ^[Yy]$ ]] && BUILD_CONTAINERS_AMD=true
      else
        BUILD_CONTAINERS_AMD=true
      fi
      ;;
    4) BUILD_VM_ONLINE=true ;;
    5)
      BUILD_PI=true
      if [[ -f "$TAR_ARM" ]]; then
        read -rp "Found cached ARM containers. Re-compile? [y/N]: " recompile
        [[ "$recompile" =~ ^[Yy]$ ]] && BUILD_CONTAINERS_ARM=true
      else
        BUILD_CONTAINERS_ARM=true
      fi
      ;;
    6) BUILD_PI_ONLINE=true ;;
    7)
      BUILD_VM=true; BUILD_VM_ONLINE=true; BUILD_PI=true; BUILD_PI_ONLINE=true
      if [[ -f "$TAR_AMD" ]]; then
        read -rp "Found cached x64 containers. Re-compile? [y/N]: " recomp_amd
        [[ "$recomp_amd" =~ ^[Yy]$ ]] && BUILD_CONTAINERS_AMD=true
      else
        BUILD_CONTAINERS_AMD=true
      fi
      if [[ -f "$TAR_ARM" ]]; then
        read -rp "Found cached ARM containers. Re-compile? [y/N]: " recomp_arm
        [[ "$recomp_arm" =~ ^[Yy]$ ]] && BUILD_CONTAINERS_ARM=true
      else
        BUILD_CONTAINERS_ARM=true
      fi
      ;;
    [Qq]*) echo "Exiting."; exit 0 ;;
    *) die "Invalid choice selected: '$choice'" ;;
  esac

  # ── VM base OS selection ──────────────────────────────────────────────────
  if $BUILD_VM || $BUILD_VM_ONLINE; then
    echo ""
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║          Select VM Base Operating System         ║${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
    echo -e "  1) Ubuntu 22.04 LTS (Jammy)   — larger (~550 MB base), well-tested"
    echo -e "  2) Debian 12 (Bookworm)        — smaller (~200 MB base), leaner image"
    echo ""
    read -rp "Enter selection [1-2, default=1]: " os_choice
    echo ""
    case "${os_choice}" in
      2) VM_BASE_OS="debian"; info "Using Debian 12 Bookworm as VM base OS." ;;
      *) VM_BASE_OS="ubuntu"; info "Using Ubuntu 22.04 Jammy as VM base OS." ;;
    esac
  fi

  # ── Docker Hub push prompt ────────────────────────────────────────────────
  if $BUILD_CONTAINERS_AMD || $BUILD_CONTAINERS_ARM; then
    read -rp "Push built images to Docker Hub (thefunkygibbon)? [y/N]: " push_choice
    [[ "$push_choice" =~ ^[Yy]$ ]] && PUSH_DOCKERHUB=true
    echo ""
  fi
else
  if $BUILD_VM   && [[ ! -f "$TAR_AMD" ]]; then BUILD_CONTAINERS_AMD=true; fi
  if $BUILD_PI   && [[ ! -f "$TAR_ARM" ]]; then BUILD_CONTAINERS_ARM=true; fi
fi

# ── Optional Compression Menu ─────────────────────────────────────────────────
if ! $MAX_COMPRESS && ( $BUILD_VM || $BUILD_VM_ONLINE || $BUILD_PI || $BUILD_PI_ONLINE ); then
  echo -e "${YELLOW}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${YELLOW}${BOLD}║           Archive Size Optimization              ║${NC}"
  echo -e "${YELLOW}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
  read -rp "Enable maximum archive compression (uses xz -9)? [y/N]: " compress_choice
  [[ "$compress_choice" =~ ^[Yy]$ ]] && MAX_COMPRESS=true
  echo ""
fi

# ── Dependency Check ──────────────────────────────────────────────────────────
check_deps() {
  step "Checking dependencies"
  local missing=()
  local deps=(docker git curl xz sha256sum parted e2fsck resize2fs losetup)
  ( $BUILD_VM || $BUILD_VM_ONLINE ) && deps+=(qemu-img qemu-nbd blkid sgdisk chroot)
  ( $BUILD_PI || $BUILD_PI_ONLINE ) && deps+=(chroot)

  for d in "${deps[@]}"; do
    command -v "$d" &>/dev/null && ok "$d" || missing+=("$d")
  done
  [[ ${#missing[@]} -eq 0 ]] || die "Missing tools: ${missing[*]}. Run: sudo apt-get install -y qemu-utils git curl xz-utils parted e2fsprogs gdisk docker.io"

  # FIX #13: ARM binfmt check also triggers for ARM container-only builds
  if ( $BUILD_CONTAINERS_ARM || $BUILD_PI || $BUILD_PI_ONLINE ) && \
     ! ls /proc/sys/fs/binfmt_misc/ 2>/dev/null | grep -q aarch64; then
    info "Registering ARM64 binfmt handlers..."
    docker run --rm --privileged multiarch/qemu-user-static --reset -p yes || true
  fi
}

clone_repo() {
  step "Cloning InSpectre (branch: ${REPO_BRANCH})"
  git clone --depth=1 --branch "${REPO_BRANCH}" "${REPO_URL}" "${REPO}"
}

patch_dockerfiles() {
  step "Patching Dockerfiles for multi-arch compilation"
  local probe_df="${REPO}/probe/Dockerfile"
  local backend_df="${REPO}/backend/Dockerfile"

  python3 - "${probe_df}" <<'PY'
import sys, re
path = sys.argv[1]
with open(path) as f: txt = f.read()
txt = re.sub(r'(^FROM python:3\.12-slim\n)', r'\1ARG TARGETARCH=amd64\n', txt, count=1, flags=re.MULTILINE)
txt = txt.replace('nuclei_${NUCLEI_VERSION}_linux_amd64.zip', 'nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip')
txt = txt.replace('nerva-linux-amd64.tar.gz', 'nerva-linux-${TARGETARCH}.tar.gz')
with open(path, 'w') as f: f.write(txt)
PY

  python3 - "${backend_df}" <<'PY'
import sys, re
path = sys.argv[1]
with open(path) as f: txt = f.read()
txt = re.sub(r'(^FROM python:3\.12-slim\n)', r'\1ARG TARGETARCH=amd64\n', txt, count=1, flags=re.MULTILINE)
txt = txt.replace(
    '"https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"',
    '"https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-$([ \"$TARGETARCH\" = \"arm64\" ] && echo ARM64 || echo 64bit).tar.gz"'
)
with open(path, 'w') as f: f.write(txt)
PY
}

# ── Docker Container Image Build ──────────────────────────────────────────────
build_docker_images() {
  if ! $BUILD_CONTAINERS_AMD && ! $BUILD_CONTAINERS_ARM; then
    info "Using cached container bundles."
    return 0
  fi

  step "Building Docker container images"
  cd "${REPO}"
  local builder="inspectre-builder-$$"
  docker buildx create --name "${builder}" --driver docker-container \
    --buildkitd-flags '--allow-insecure-entitlement network.host' --use >/dev/null
  trap "docker buildx rm ${builder} 2>/dev/null || true" RETURN

  local pids=() tags=()
  _build_bg() {
    local name="$1" platform="$2" context="$3" tag="$4"
    docker buildx build --builder "${builder}" --platform "${platform}" \
      --tag "${tag}" --load --progress plain "${context}" \
      >"${WORK}/build-${name}.log" 2>&1 &
    pids+=($!); tags+=("${tag}")
  }

  if $BUILD_CONTAINERS_AMD; then
    _build_bg "backend-amd"  "linux/amd64" "./backend"  "inspectre-backend:amd64"
    _build_bg "probe-amd"    "linux/amd64" "./probe"    "inspectre-probe:amd64"
    _build_bg "frontend-amd" "linux/amd64" "./frontend" "inspectre-frontend:amd64"
  fi
  if $BUILD_CONTAINERS_ARM; then
    _build_bg "backend-arm"  "linux/arm64" "./backend"  "inspectre-backend:arm64"
    _build_bg "probe-arm"    "linux/arm64" "./probe"    "inspectre-probe:arm64"
    _build_bg "frontend-arm" "linux/arm64" "./frontend" "inspectre-frontend:arm64"
  fi

  for i in "${!pids[@]}"; do
    wait "${pids[$i]}" || die "Docker build error for ${tags[$i]}. See ${WORK}/build-*.log"
  done

  if $BUILD_CONTAINERS_AMD; then
    docker pull --platform linux/amd64 --quiet postgres:15-alpine
    docker tag postgres:15-alpine inspectre-postgres:amd64
    docker save \
      inspectre-backend:amd64 inspectre-probe:amd64 \
      inspectre-frontend:amd64 inspectre-postgres:amd64 \
      > "${TAR_AMD}"
    ok "x64 container bundle saved: ${TAR_AMD}"
  fi
  if $BUILD_CONTAINERS_ARM; then
    docker pull --platform linux/arm64 --quiet postgres:15-alpine
    docker tag postgres:15-alpine inspectre-postgres:arm64
    docker save \
      inspectre-backend:arm64 inspectre-probe:arm64 \
      inspectre-frontend:arm64 inspectre-postgres:arm64 \
      > "${TAR_ARM}"
    ok "ARM64 container bundle saved: ${TAR_ARM}"
  fi
  cd - >/dev/null
}

# ── Push to Docker Hub ────────────────────────────────────────────────────────
push_images() {
  step "Pushing images to Docker Hub (thefunkygibbon)"
  [[ -n "${DOCKERHUB_TOKEN:-}" ]] || die "DOCKERHUB_TOKEN not set. Export it before running with --push."
  echo "${DOCKERHUB_TOKEN}" | docker login -u thefunkygibbon --password-stdin \
    || die "Docker Hub login failed."

  local pushes=()
  if $BUILD_CONTAINERS_AMD; then
    docker tag inspectre-backend:amd64  thefunkygibbon/inspectre-web:latest
    docker tag inspectre-frontend:amd64 thefunkygibbon/inspectre-frontend:latest
    docker tag inspectre-probe:amd64    thefunkygibbon/inspectre-probe:latest
    pushes+=(
      thefunkygibbon/inspectre-web:latest
      thefunkygibbon/inspectre-frontend:latest
      thefunkygibbon/inspectre-probe:latest
    )
  fi
  if $BUILD_CONTAINERS_ARM; then
    docker tag inspectre-backend:arm64  thefunkygibbon/inspectre-web:raspi
    docker tag inspectre-frontend:arm64 thefunkygibbon/inspectre-frontend:raspi
    docker tag inspectre-probe:arm64    thefunkygibbon/inspectre-probe:raspi
    pushes+=(
      thefunkygibbon/inspectre-web:raspi
      thefunkygibbon/inspectre-frontend:raspi
      thefunkygibbon/inspectre-probe:raspi
    )
  fi

  [[ ${#pushes[@]} -gt 0 ]] || { warn "No images built this run — nothing to push."; return 0; }
  for img in "${pushes[@]}"; do
    info "Pushing ${img}..."
    docker push "${img}"
    ok "Pushed ${img}"
  done
  docker logout 2>/dev/null || true
}

# ─────────────────────────────────────────────────────────────────────────────
# Embedded scripts written into the appliance images
# ─────────────────────────────────────────────────────────────────────────────

# FIX #1 #2: IP fallback fixed (two separate commands, not || inside $());
#            docker load failure now shows a proper error message before exiting.
startup_script() {
  cat <<'STARTUP'
#!/bin/bash
set -e

_get_ip() {
  local ip
  ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
  [[ -z "$ip" ]] && ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo "${ip:-<this-machine-ip>}"
}

TAR="/opt/inspectre/images/inspectre-images.tar"
if [[ -f "$TAR" ]]; then
  echo "[InSpectre] Importing appliance container layers (first boot)..."
  if ! docker load < "$TAR"; then
    echo "[InSpectre] ERROR: Failed to load container images from $TAR"
    exit 1
  fi
  rm -f "$TAR"
  echo "[InSpectre] Container layers imported successfully."
fi

cd /opt/inspectre
echo "[InSpectre] Starting services..."
docker compose up -d

IP=$(_get_ip)
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  InSpectre System Protection Engine Active       ║"
printf "║  Access Web Portal : http://%-22s║\n" "${IP}:3000"
echo "╚══════════════════════════════════════════════════╝"
echo ""
STARTUP
}

# FIX #3 #4: Poll registry-1.docker.io (the actual registry endpoint, not hub web UI);
#            retry docker compose pull up to 3 times with back-off.
startup_script_online() {
  cat <<'STARTUP'
#!/bin/bash
set -e

_get_ip() {
  local ip
  ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
  [[ -z "$ip" ]] && ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo "${ip:-<this-machine-ip>}"
}

cd /opt/inspectre

echo "[InSpectre] Waiting for Docker Hub connectivity..."
connected=false
for i in $(seq 1 30); do
  if curl -fsSL --max-time 5 https://registry-1.docker.io/v2/ > /dev/null 2>&1; then
    connected=true
    break
  fi
  echo "[InSpectre] Attempt ${i}/30 — no connectivity yet, retrying in 10s..."
  sleep 10
done

if ! $connected; then
  echo "[InSpectre] ERROR: Cannot reach Docker Hub after 5 minutes."
  echo "[InSpectre] Check your network connection and retry: sudo systemctl restart inspectre"
  exit 1
fi

echo "[InSpectre] Pulling latest InSpectre images from Docker Hub..."
pull_ok=false
for attempt in 1 2 3; do
  if docker compose pull; then
    pull_ok=true
    break
  fi
  echo "[InSpectre] Pull attempt ${attempt}/3 failed. Retrying in 15s..."
  sleep 15
done

if ! $pull_ok; then
  echo "[InSpectre] ERROR: Failed to pull images after 3 attempts."
  echo "[InSpectre] Retry with: sudo systemctl restart inspectre"
  exit 1
fi

echo "[InSpectre] Starting services..."
docker compose up -d

IP=$(_get_ip)
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  InSpectre System Protection Engine Active       ║"
printf "║  Access Web Portal : http://%-22s║\n" "${IP}:3000"
echo "╚══════════════════════════════════════════════════╝"
echo ""
STARTUP
}

# FIX #5 #6: ExecStop uses 'docker compose' (no hardcoded path);
#            both After= and Wants= include network-online.target correctly.
systemd_unit() {
  cat <<'UNIT'
[Unit]
Description=InSpectre Container Orchestration Framework
After=docker.service network-online.target
Wants=docker.service network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/inspectre
ExecStart=/opt/inspectre/start.sh
ExecStop=docker compose -f /opt/inspectre/docker-compose.yml down
TimeoutStartSec=600
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
UNIT
}

motd_content() {
  cat <<'MOTD'
╔══════════════════════════════════════════════════════╗
║           InSpectre System Scanner Appliance         ║
╠══════════════════════════════════════════════════════╣
║  UI Browser Access : http://<this-ip>:3000           ║
║  System Logs       : sudo journalctl -u inspectre -f ║
║  Credentials       : inspectre / inspectre           ║
╚══════════════════════════════════════════════════════╝
MOTD
}

write_appliance_json() {
  local mnt="$1" type="$2" arch="$3" mode="$4" base_os="$5"
  sudo tee "${mnt}/opt/inspectre/appliance.json" >/dev/null <<EOF
{
  "type": "${type}",
  "arch": "${arch}",
  "mode": "${mode}",
  "base_os": "${base_os}",
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "version": "1.0.0"
}
EOF
}

# ── Shared: mount VM base image (Ubuntu or Debian) ───────────────────────────
_mount_ubuntu_base() {
  local vw="$1" disk_name="$2" disk_size="$3"
  local base_url="$UBUNTU_URL"
  [[ "${VM_BASE_OS}" == "debian" ]] && base_url="$DEBIAN_URL"

  if [[ "${VM_BASE_OS}" == "debian" ]]; then
    info "Downloading Debian 12 Bookworm cloud image..."
  else
    info "Downloading Ubuntu 22.04 Jammy cloud image..."
  fi
  curl -L --progress-bar "${base_url}" -o "${vw}/base.img"

  local disk="${vw}/${disk_name}"
  qemu-img convert -f qcow2 -O qcow2 "${vw}/base.img" "${disk}"
  qemu-img resize "${disk}" "${disk_size}"

  sudo modprobe nbd max_part=8 2>/dev/null || true
  local nbd=""
  for dev in /dev/nbd{0..15}; do
    if [[ -b "${dev}" ]] && ! sudo lsblk "${dev}" 2>/dev/null | grep -q "part\|disk.*[0-9]$"; then
      nbd="${dev}"; break
    fi
  done
  [[ -n "${nbd}" ]] || die "No available NBD devices found."

  sudo qemu-nbd --connect="${nbd}" "${disk}"
  sleep 2

  # FIX #14: suppress sgdisk stderr — it prints warnings on well-formed GPT tables
  sudo sgdisk -e "${nbd}" >/dev/null 2>&1 || true
  sudo partprobe "${nbd}" 2>/dev/null || true
  sleep 1

  local root_part="" part_num=""
  for part in "${nbd}p1" "${nbd}p2" "${nbd}p3" "${nbd}p4" "${nbd}p5"; do
    if [[ -b "${part}" ]] && sudo blkid "${part}" | grep -q 'TYPE="ext4"'; then
      root_part="${part}"; part_num="${part#${nbd}p}"; break
    fi
  done
  [[ -n "${root_part}" ]] || die "Could not find ext4 root partition on ${nbd}"

  sudo parted -f -s "${nbd}" resizepart "${part_num}" 100%
  sudo partprobe "${nbd}" 2>/dev/null || true
  sleep 1
  sudo e2fsck -f "${root_part}" -y >/dev/null 2>&1 || true
  sudo resize2fs "${root_part}" >/dev/null 2>&1 || true

  local mnt="${vw}/mnt"
  mkdir -p "${mnt}"
  sudo mount "${root_part}" "${mnt}"
  sudo mount --bind /proc    "${mnt}/proc"
  sudo mount --bind /sys     "${mnt}/sys"
  sudo mount --bind /dev     "${mnt}/dev"
  sudo mount --bind /dev/pts "${mnt}/dev/pts"

  sudo mv "${mnt}/etc/resolv.conf" "${mnt}/etc/resolv.conf.bak" 2>/dev/null || true
  echo "nameserver 8.8.8.8" | sudo tee "${mnt}/etc/resolv.conf" >/dev/null

  # ── OS-specific network + cloud-init ────────────────────────────────────
  if [[ "${VM_BASE_OS}" == "debian" ]]; then
    sudo mkdir -p "${mnt}/etc/systemd/network"
    sudo tee "${mnt}/etc/systemd/network/10-dhcp.network" >/dev/null <<'EOF'
[Match]
Name=e*

[Network]
DHCP=yes
DNS=8.8.8.8
DNS=8.8.4.4

[DHCP]
UseDNS=true
EOF
    sudo mkdir -p "${mnt}/etc/systemd/system/multi-user.target.wants"
    sudo ln -sf /lib/systemd/system/systemd-networkd.service \
      "${mnt}/etc/systemd/system/multi-user.target.wants/systemd-networkd.service" 2>/dev/null || true
    sudo ln -sf /lib/systemd/system/systemd-resolved.service \
      "${mnt}/etc/systemd/system/multi-user.target.wants/systemd-resolved.service" 2>/dev/null || true

    sudo mkdir -p "${mnt}/etc/cloud/cloud.cfg.d"
    sudo tee "${mnt}/etc/cloud/cloud.cfg.d/99-inspectre.cfg" >/dev/null <<'EOF'
datasource_list: [None]
network: {config: disabled}
users: []
disable_root: false
preserve_hostname: true
ssh_pwauth: true
EOF

  else
    sudo mkdir -p "${mnt}/etc/cloud/cloud.cfg.d"
    sudo tee "${mnt}/etc/cloud/cloud.cfg.d/99-disable-user-manipulation.cfg" >/dev/null <<'EOF'
datasource_list: [None]
network: {config: disabled}
users: []
disable_root: false
preserve_hostname: true
ssh_pwauth: true
EOF
    sudo mkdir -p "${mnt}/etc/netplan"
    sudo rm -f "${mnt}/etc/netplan/"*.yaml 2>/dev/null || true
    sudo tee "${mnt}/etc/netplan/01-inspectre-dhcp.yaml" >/dev/null <<'EOF'
network:
  version: 2
  renderer: networkd
  ethernets:
    all_eth:
      match:
        name: "e*"
      dhcp4: true
      dhcp6: false
EOF
  fi

  sudo tee "${mnt}/usr/sbin/policy-rc.d" >/dev/null <<'POLICY'
#!/bin/sh
exit 101
POLICY
  sudo chmod +x "${mnt}/usr/sbin/policy-rc.d"

  _MOUNT_NBD="${nbd}"
  _MOUNT_MNT="${mnt}"
  _MOUNT_DISK="${disk}"
}

# FIX #7 #8 #9: Docker is now explicitly enabled in both Ubuntu and Debian chroots;
#               Debian resolv.conf is properly replaced with the resolved symlink
#               (not left as .new); Ubuntu restore path unchanged.
_chroot_vm_setup() {
  local mnt="$1"

  if [[ "${VM_BASE_OS}" == "debian" ]]; then
    sudo chroot "${mnt}" /bin/bash <<'CHROOT'
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg lsb-release \
  net-tools jq openssh-server sudo

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/debian $(lsb_release -cs) stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update -qq
apt-get install -y --no-install-recommends \
  docker-ce docker-ce-cli containerd.io docker-compose-plugin
apt-get clean
rm -rf /var/lib/apt/lists/*

# FIX #8: enable docker explicitly
systemctl enable docker
systemctl enable ssh
systemctl enable systemd-networkd
systemctl enable systemd-resolved

sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#*PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config

id inspectre &>/dev/null || useradd -m -s /bin/bash inspectre
usermod -aG sudo,docker inspectre
echo "inspectre:inspectre" | chpasswd
echo "root:inspectre" | chpasswd
echo "inspectre ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/inspectre
chmod 0440 /etc/sudoers.d/inspectre

# FIX #7: Replace resolv.conf with systemd-resolved stub now (inside chroot)
rm -f /etc/resolv.conf
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
CHROOT

  else
    sudo chroot "${mnt}" /bin/bash <<'CHROOT'
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
  docker.io docker-compose-v2 curl jq net-tools ca-certificates openssh-server sudo
apt-get clean
rm -rf /var/lib/apt/lists/*

# FIX #9: enable docker explicitly
systemctl enable docker
systemctl enable ssh
systemctl enable systemd-networkd

sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#*PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config

id inspectre &>/dev/null || useradd -m -s /bin/bash inspectre
usermod -aG sudo,docker inspectre
echo "inspectre:inspectre" | chpasswd
echo "root:inspectre" | chpasswd
echo "inspectre ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/inspectre
chmod 0440 /etc/sudoers.d/inspectre
CHROOT
  fi
}

# FIX #7 cont: Debian no longer restores resolv.conf.bak (already replaced inside chroot).
#              Ubuntu restores its original symlink as before.
_finalise_vm() {
  local mnt="$1" nbd="$2" disk="$3" out_image="$4"
  sudo rm -f "${mnt}/usr/sbin/policy-rc.d"

  if [[ "${VM_BASE_OS}" == "debian" ]]; then
    # resolv.conf was replaced inside chroot with the systemd-resolved symlink —
    # just clean up the backup we took at mount time.
    sudo rm -f "${mnt}/etc/resolv.conf.bak"
  else
    # Ubuntu: restore original resolv.conf (typically a symlink to resolved stub)
    sudo rm -f "${mnt}/etc/resolv.conf"
    sudo mv "${mnt}/etc/resolv.conf.bak" "${mnt}/etc/resolv.conf" 2>/dev/null || true
  fi

  sudo umount "${mnt}/dev/pts" 2>/dev/null || true
  sudo umount "${mnt}/dev"     2>/dev/null || true
  sudo umount "${mnt}/sys"     2>/dev/null || true
  sudo umount "${mnt}/proc"    2>/dev/null || true
  sudo umount "${mnt}"
  sudo qemu-nbd --disconnect "${nbd}"
  sleep 2

  if $MAX_COMPRESS; then
    info "Converting to raw qcow2 for xz pass..."
    qemu-img convert -O qcow2 "${disk}" "${OUTPUT_DIR}/${out_image}"
    info "Compressing with xz -9 (this will take several minutes)..."
    xz --threads=0 -9 -f "${OUTPUT_DIR}/${out_image}"
    ok "VM image ready: ${OUTPUT_DIR}/${out_image}.xz"
  else
    qemu-img convert -c -O qcow2 "${disk}" "${OUTPUT_DIR}/${out_image}"
    ok "VM image ready: ${OUTPUT_DIR}/${out_image}"
  fi
}

# ── VM Appliance — Offline ────────────────────────────────────────────────────
build_vm_image() {
  step "Building VM Appliance — Offline (x86_64) [base: ${VM_BASE_OS}]"
  [[ -f "$TAR_AMD" ]] || die "x64 container bundle not found: ${TAR_AMD}"

  local vw="${WORK}/vm"
  mkdir -p "${vw}" "${OUTPUT_DIR}"

  _mount_ubuntu_base "${vw}" "${VM_IMAGE}" "${VM_DISK_SIZE}"
  local mnt="${_MOUNT_MNT}" nbd="${_MOUNT_NBD}" disk="${_MOUNT_DISK}"

  _chroot_vm_setup "${mnt}"

  sudo mkdir -p "${mnt}/opt/inspectre/images"
  sudo cp "${TAR_AMD}"                     "${mnt}/opt/inspectre/images/inspectre-images.tar"
  sudo cp "${REPO}/docker-compose.vm.yml"  "${mnt}/opt/inspectre/docker-compose.yml"
  write_appliance_json "${mnt}" "vm" "amd64" "offline" "${VM_BASE_OS}"
  startup_script | sudo tee "${mnt}/opt/inspectre/start.sh" >/dev/null
  sudo chmod +x  "${mnt}/opt/inspectre/start.sh"
  systemd_unit   | sudo tee "${mnt}/etc/systemd/system/inspectre.service" >/dev/null
  motd_content   | sudo tee "${mnt}/etc/motd" >/dev/null
  sudo chroot "${mnt}" systemctl enable inspectre

  _finalise_vm "${mnt}" "${nbd}" "${disk}" "${VM_IMAGE}"
}

# ── VM Appliance — Online ─────────────────────────────────────────────────────
build_vm_online_image() {
  step "Building VM Appliance — Online (x86_64) [base: ${VM_BASE_OS}]"
  info "Image will pull thefunkygibbon/inspectre-* from Docker Hub on first boot."

  local vw="${WORK}/vm-online"
  mkdir -p "${vw}" "${OUTPUT_DIR}"

  _mount_ubuntu_base "${vw}" "${VM_ONLINE_IMAGE}" "${VM_ONLINE_DISK_SIZE}"
  local mnt="${_MOUNT_MNT}" nbd="${_MOUNT_NBD}" disk="${_MOUNT_DISK}"

  _chroot_vm_setup "${mnt}"

  sudo mkdir -p "${mnt}/opt/inspectre"
  sudo cp "${REPO}/docker-compose.vm.online.yml" "${mnt}/opt/inspectre/docker-compose.yml"
  write_appliance_json "${mnt}" "vm" "amd64" "online" "${VM_BASE_OS}"
  startup_script_online | sudo tee "${mnt}/opt/inspectre/start.sh" >/dev/null
  sudo chmod +x         "${mnt}/opt/inspectre/start.sh"
  systemd_unit          | sudo tee "${mnt}/etc/systemd/system/inspectre.service" >/dev/null
  motd_content          | sudo tee "${mnt}/etc/motd" >/dev/null
  sudo chroot "${mnt}" systemctl enable inspectre

  _finalise_vm "${mnt}" "${nbd}" "${disk}" "${VM_ONLINE_IMAGE}"
}

# ── Pi helpers ────────────────────────────────────────────────────────────────
_prepare_pi_base() {
  local pw="$1"

  local idx; idx=$(curl -sL "${RPI_INDEX}/")
  local latest_dir; latest_dir=$(echo "${idx}" | grep -oP 'raspios_lite_arm64-\d{4}-\d{2}-\d{2}' | sort -r | head -1)
  [[ -n "${latest_dir}" ]] || die "Could not determine latest Pi OS image directory."
  local img_xz; img_xz=$(curl -sL "${RPI_INDEX}/${latest_dir}/" | grep -oP '[\w\-]+\.img\.xz' | head -1)
  [[ -n "${img_xz}" ]] || die "Could not find Pi OS .img.xz in ${latest_dir}."

  info "Downloading Pi OS: ${img_xz}"
  curl -L --progress-bar "${RPI_INDEX}/${latest_dir}/${img_xz}" -o "${pw}/${img_xz}"
  xz --decompress --keep --threads=0 "${pw}/${img_xz}"
  local raw="${pw}/${img_xz%.xz}"

  dd if=/dev/zero bs=1M count=10240 >>"${raw}" 2>/dev/null
  sudo parted -f -s "${raw}" resizepart 2 100% 2>/dev/null || true

  local loop; loop=$(sudo losetup --find --show --partscan "${raw}")
  sleep 2
  sudo e2fsck -f "${loop}p2" -y >/dev/null 2>&1 || true
  sudo resize2fs "${loop}p2" >/dev/null 2>&1 || true

  _PI_RAW="${raw}"
  _PI_LOOP="${loop}"
}

_mount_pi_base() {
  local pw="$1"
  local mnt="${pw}/mnt"
  mkdir -p "${mnt}"
  sudo mount "${_PI_LOOP}p2" "${mnt}"

  local boot_mnt="${mnt}/boot"
  [[ -d "${mnt}/boot/firmware" ]] && boot_mnt="${mnt}/boot/firmware"
  sudo mount "${_PI_LOOP}p1" "${boot_mnt}" 2>/dev/null || true

  sudo mount --bind /proc    "${mnt}/proc"
  sudo mount --bind /sys     "${mnt}/sys"
  sudo mount --bind /dev     "${mnt}/dev"
  sudo mount --bind /dev/pts "${mnt}/dev/pts"
  sudo cp /etc/resolv.conf "${mnt}/etc/resolv.conf"

  sudo tee "${mnt}/usr/sbin/policy-rc.d" >/dev/null <<'POLICY'
#!/bin/sh
exit 101
POLICY
  sudo chmod +x "${mnt}/usr/sbin/policy-rc.d"

  _PI_MNT="${mnt}"
  _PI_BOOT_MNT="${boot_mnt}"
}

# FIX #11: Pi OS (Bookworm/Debian-based) ships docker-compose-v2 in its own repos
#          but does NOT have docker-compose-plugin. Use docker-compose-v2 via the
#          official Docker apt repo for arm64 so we get both docker-ce AND
#          docker-compose-plugin (same as Debian VM path).
_chroot_pi_setup() {
  local mnt="$1"
  sudo chroot "${mnt}" /bin/bash <<'CHROOT'
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg lsb-release net-tools jq

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/debian $(lsb_release -cs) stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update -qq
apt-get install -y --no-install-recommends \
  docker-ce docker-ce-cli containerd.io docker-compose-plugin
apt-get clean
rm -rf /var/lib/apt/lists/*

systemctl enable docker

echo "root:inspectre" | chpasswd
# Add pi user to docker group if it exists
id pi &>/dev/null && usermod -aG docker pi || true
CHROOT
}

_finalise_pi() {
  local mnt="$1" boot_mnt="$2" loop="$3" raw="$4" out_image="$5"
  sudo rm -f "${mnt}/usr/sbin/policy-rc.d"
  sudo umount "${mnt}/dev/pts" 2>/dev/null || true
  sudo umount "${mnt}/dev"     2>/dev/null || true
  sudo umount "${mnt}/sys"     2>/dev/null || true
  sudo umount "${mnt}/proc"    2>/dev/null || true
  sudo umount "${boot_mnt}"    2>/dev/null || true
  sudo umount "${mnt}"
  sudo losetup -d "${loop}"
  sleep 1

  if $MAX_COMPRESS; then
    info "Compressing Pi image with xz -9..."
    xz --threads=0 -9 -z "${raw}" -c > "${OUTPUT_DIR}/${out_image}.xz"
    ok "Pi image ready: ${OUTPUT_DIR}/${out_image}.xz"
  else
    cp "${raw}" "${OUTPUT_DIR}/${out_image}"
    ok "Pi image ready: ${OUTPUT_DIR}/${out_image}"
  fi
}

_pi_boot_setup() {
  local boot_mnt="$1"
  sudo touch "${boot_mnt}/ssh"
  # FIX #12: generate the hash at build time so it's guaranteed correct
  local pi_pw_hash
  pi_pw_hash=$(echo 'inspectre' | openssl passwd -6 -stdin)
  echo "pi:${pi_pw_hash}" | sudo tee "${boot_mnt}/userconf.txt" >/dev/null
}

_pi_enable_services() {
  local mnt="$1"
  sudo mkdir -p "${mnt}/etc/systemd/system/multi-user.target.wants"
  sudo ln -sf /lib/systemd/system/docker.service \
    "${mnt}/etc/systemd/system/multi-user.target.wants/docker.service" 2>/dev/null || true
  sudo ln -sf /etc/systemd/system/inspectre.service \
    "${mnt}/etc/systemd/system/multi-user.target.wants/inspectre.service" 2>/dev/null || true
}

# ── Pi Appliance — Offline ────────────────────────────────────────────────────
build_pi_image() {
  step "Building Raspberry Pi Image — Offline (arm64)"
  [[ -f "$TAR_ARM" ]] || die "ARM container bundle not found: ${TAR_ARM}"

  local pw="${WORK}/pi"
  mkdir -p "${pw}" "${OUTPUT_DIR}"

  _prepare_pi_base "${pw}"
  _mount_pi_base   "${pw}"
  local mnt="${_PI_MNT}" boot_mnt="${_PI_BOOT_MNT}" loop="${_PI_LOOP}" raw="${_PI_RAW}"

  _chroot_pi_setup "${mnt}"

  sudo mkdir -p "${mnt}/opt/inspectre/images"
  sudo cp "${TAR_ARM}"                    "${mnt}/opt/inspectre/images/inspectre-images.tar"
  sudo cp "${REPO}/docker-compose.pi.yml" "${mnt}/opt/inspectre/docker-compose.yml"
  write_appliance_json "${mnt}" "pi" "arm64" "offline" "raspios"
  startup_script | sudo tee "${mnt}/opt/inspectre/start.sh" >/dev/null
  sudo chmod +x  "${mnt}/opt/inspectre/start.sh"
  systemd_unit   | sudo tee "${mnt}/etc/systemd/system/inspectre.service" >/dev/null
  motd_content   | sudo tee "${mnt}/etc/motd" >/dev/null

  _pi_boot_setup     "${boot_mnt}"
  _pi_enable_services "${mnt}"
  _finalise_pi "${mnt}" "${boot_mnt}" "${loop}" "${raw}" "${PI_IMAGE}"
}

# ── Pi Appliance — Online ─────────────────────────────────────────────────────
build_pi_online_image() {
  step "Building Raspberry Pi Image — Online (arm64)"
  info "Image will pull thefunkygibbon/inspectre-*:raspi from Docker Hub on first boot."

  local pw="${WORK}/pi-online"
  mkdir -p "${pw}" "${OUTPUT_DIR}"

  _prepare_pi_base "${pw}"
  _mount_pi_base   "${pw}"
  local mnt="${_PI_MNT}" boot_mnt="${_PI_BOOT_MNT}" loop="${_PI_LOOP}" raw="${_PI_RAW}"

  _chroot_pi_setup "${mnt}"

  sudo mkdir -p "${mnt}/opt/inspectre"
  sudo cp "${REPO}/docker-compose.pi.online.yml" "${mnt}/opt/inspectre/docker-compose.yml"
  write_appliance_json "${mnt}" "pi" "arm64" "online" "raspios"
  startup_script_online | sudo tee "${mnt}/opt/inspectre/start.sh" >/dev/null
  sudo chmod +x         "${mnt}/opt/inspectre/start.sh"
  systemd_unit          | sudo tee "${mnt}/etc/systemd/system/inspectre.service" >/dev/null
  motd_content          | sudo tee "${mnt}/etc/motd" >/dev/null

  _pi_boot_setup     "${boot_mnt}"
  _pi_enable_services "${mnt}"
  _finalise_pi "${mnt}" "${boot_mnt}" "${loop}" "${raw}" "${PI_ONLINE_IMAGE}"
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
  for mp in \
    "${WORK}/pi/mnt/dev/pts"              "${WORK}/pi/mnt/dev"          \
    "${WORK}/pi/mnt/sys"                  "${WORK}/pi/mnt/proc"         \
    "${WORK}/pi/mnt/boot/firmware"        "${WORK}/pi/mnt/boot"         \
    "${WORK}/pi/mnt"                      \
    "${WORK}/pi-online/mnt/dev/pts"       "${WORK}/pi-online/mnt/dev"   \
    "${WORK}/pi-online/mnt/sys"           "${WORK}/pi-online/mnt/proc"  \
    "${WORK}/pi-online/mnt/boot/firmware" "${WORK}/pi-online/mnt/boot"  \
    "${WORK}/pi-online/mnt"               \
    "${WORK}/vm/mnt/dev/pts"              "${WORK}/vm/mnt/dev"          \
    "${WORK}/vm/mnt/sys"                  "${WORK}/vm/mnt/proc"         \
    "${WORK}/vm/mnt"                      \
    "${WORK}/vm-online/mnt/dev/pts"       "${WORK}/vm-online/mnt/dev"   \
    "${WORK}/vm-online/mnt/sys"           "${WORK}/vm-online/mnt/proc"  \
    "${WORK}/vm-online/mnt"               \
  ; do
    sudo umount "${mp}" 2>/dev/null || true
  done
  for nbd in /dev/nbd{0..15}; do
    sudo qemu-nbd --disconnect "${nbd}" 2>/dev/null || true
  done
  while IFS= read -r line; do
    local lo; lo=$(echo "${line}" | awk '{print $1}')
    sudo losetup -d "${lo}" 2>/dev/null || true
  done < <(sudo losetup -l -n -O NAME,BACK-FILE 2>/dev/null | grep "${WORK}" || true)
  sudo rm -rf "${WORK}"
}
trap cleanup EXIT INT TERM

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  echo -e "\n${CYAN}${BOLD}InSpectre Image Builder v5.3 Active${NC}"
  check_deps
  clone_repo

  # FIX #13: patch Dockerfiles whenever any ARM build is needed (not just VM/Pi)
  ( $BUILD_VM || $BUILD_PI || $BUILD_CONTAINERS_ARM || $BUILD_PI_ONLINE ) && patch_dockerfiles

  build_docker_images
  $PUSH_DOCKERHUB  && push_images
  $BUILD_VM        && build_vm_image
  $BUILD_VM_ONLINE && build_vm_online_image
  $BUILD_PI        && build_pi_image
  $BUILD_PI_ONLINE && build_pi_online_image

  echo ""
  ok "All targeted image profiles completed successfully."
  echo ""
}

main "$@"
