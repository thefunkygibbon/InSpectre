#!/usr/bin/env bash
# =============================================================================
#  InSpectre — Appliance Image Builder  v5.1 (Production Master)
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
UBUNTU_URL="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
UBUNTU_SHA_URL="https://cloud-images.ubuntu.com/jammy/current/SHA256SUMS"
RPI_INDEX="https://downloads.raspberrypi.com/raspios_lite_arm64/images"

WORK="$(mktemp -d /tmp/inspectre-build.XXXXXX)"
REPO="${WORK}/repo"
TAR_AMD="${CACHE_DIR}/inspectre-amd64.tar"
TAR_ARM="${CACHE_DIR}/inspectre-arm64.tar"

mkdir -p "${CACHE_DIR}"

# ── Args ──────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --vm-only)        BUILD_VM=true; CLI_TARGET_SPECIFIED=true ;;
    --vm-online-only) BUILD_VM_ONLINE=true; CLI_TARGET_SPECIFIED=true ;;
    --pi-only)        BUILD_PI=true; CLI_TARGET_SPECIFIED=true ;;
    --pi-online-only) BUILD_PI_ONLINE=true; CLI_TARGET_SPECIFIED=true ;;
    --compress)       MAX_COMPRESS=true ;;
    --push)           PUSH_DOCKERHUB=true ;;
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
    4)
      BUILD_VM_ONLINE=true
      ;;
    5)
      BUILD_PI=true
      if [[ -f "$TAR_ARM" ]]; then
        read -rp "Found cached ARM containers. Re-compile? [y/N]: " recompile
        [[ "$recompile" =~ ^[Yy]$ ]] && BUILD_CONTAINERS_ARM=true
      else
        BUILD_CONTAINERS_ARM=true
      fi
      ;;
    6)
      BUILD_PI_ONLINE=true
      ;;
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

  # Ask about Docker Hub push when containers are being built
  if $BUILD_CONTAINERS_AMD || $BUILD_CONTAINERS_ARM; then
    read -rp "Push built images to Docker Hub (thefunkygibbon)? [y/N]: " push_choice
    [[ "$push_choice" =~ ^[Yy]$ ]] && PUSH_DOCKERHUB=true
    echo ""
  fi
else
  if $BUILD_VM   && [[ ! -f "$TAR_AMD" ]]; then BUILD_CONTAINERS_AMD=true; fi
  if $BUILD_PI   && [[ ! -f "$TAR_ARM" ]]; then BUILD_CONTAINERS_ARM=true; fi
  # Online builds never need local container compilation
fi

# ── Optional Compression Menu ─────────────────────────────────────────────────
if ! $MAX_COMPRESS && ( $BUILD_VM || $BUILD_VM_ONLINE || $BUILD_PI || $BUILD_PI_ONLINE ); then
  echo -e "${YELLOW}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${YELLOW}${BOLD}║           Archive Size Optimization              ║${NC}"
  echo -e "${YELLOW}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
  read -rp "Enable maximum archive compression (uses heavy xz -9)? [y/N]: " compress_choice
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
  [[ ${#missing[@]} -eq 0 ]] || die "Missing tools. Run: sudo apt-get install -y qemu-utils git curl xz-utils parted e2fsprogs gdisk docker.io"

  if $BUILD_CONTAINERS_ARM && ! ls /proc/sys/fs/binfmt_misc/ 2>/dev/null | grep -q aarch64; then
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

build_docker_images() {
  if ! $BUILD_CONTAINERS_AMD && ! $BUILD_CONTAINERS_ARM; then
    info "Using cached container bundles."
    return 0
  fi

  step "Building Docker container images"
  cd "${REPO}"
  local builder="inspectre-builder-$$"
  docker buildx create --name "${builder}" --driver docker-container --buildkitd-flags '--allow-insecure-entitlement network.host' --use >/dev/null
  trap "docker buildx rm ${builder} 2>/dev/null || true" RETURN

  local pids=() tags=()
  _build_bg() {
    local name="$1" platform="$2" context="$3" tag="$4"
    docker buildx build --builder "${builder}" --platform "${platform}" --tag "${tag}" --load --progress plain "${context}" >"${WORK}/build-${name}.log" 2>&1 &
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
    wait "${pids[$i]}" || die "Docker compile error for ${tags[$i]}. Check logs in /tmp."
  done

  if $BUILD_CONTAINERS_AMD; then
    docker pull --platform linux/amd64 --quiet postgres:15-alpine
    docker tag postgres:15-alpine inspectre-postgres:amd64
    docker save inspectre-backend:amd64 inspectre-probe:amd64 inspectre-frontend:amd64 inspectre-postgres:amd64 > "${TAR_AMD}"
  fi

  if $BUILD_CONTAINERS_ARM; then
    docker pull --platform linux/arm64 --quiet postgres:15-alpine
    docker tag postgres:15-alpine inspectre-postgres:arm64
    docker save inspectre-backend:arm64 inspectre-probe:arm64 inspectre-frontend:arm64 inspectre-postgres:arm64 > "${TAR_ARM}"
  fi
  cd - >/dev/null
}

# ── Push images to Docker Hub ─────────────────────────────────────────────────
push_images() {
  step "Pushing images to Docker Hub (thefunkygibbon)"

  if [[ -z "${DOCKERHUB_TOKEN:-}" ]]; then
    die "DOCKERHUB_TOKEN environment variable is not set. Export it before running with --push."
  fi

  echo "${DOCKERHUB_TOKEN}" | docker login -u thefunkygibbon --password-stdin \
    || die "Docker Hub login failed. Check your DOCKERHUB_TOKEN."

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

  [[ ${#pushes[@]} -eq 0 ]] && { warn "No images were built this run — nothing to push."; return 0; }

  for img in "${pushes[@]}"; do
    info "Pushing ${img}..."
    docker push "${img}"
    ok "Pushed ${img}"
  done

  docker logout 2>/dev/null || true
}

# ── Startup script: offline (loads baked tar on first boot) ───────────────────
startup_script() {
  cat <<'STARTUP'
#!/bin/bash
set -e
TAR="/opt/inspectre/images/inspectre-images.tar"
if [[ -f "$TAR" ]]; then
  echo "[InSpectre] Importing appliance container layers..."
  docker load < "$TAR" && rm -f "$TAR"
fi
cd /opt/inspectre
docker compose up -d
IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' || hostname -I | awk '{print $1}')
echo -e "\n╔══════════════════════════════════════════════════╗"
echo "║  InSpectre System Protection Engine Active       ║"
echo "║  Access Web Portal : http://${IP}:3000          ║"
echo "╚══════════════════════════════════════════════════╝\n"
STARTUP
}

# ── Startup script: online (pulls from Docker Hub on first boot) ──────────────
startup_script_online() {
  cat <<'STARTUP'
#!/bin/bash
set -e
cd /opt/inspectre

# Wait for internet connectivity (Docker Hub must be reachable)
echo "[InSpectre] Waiting for internet access..."
for i in $(seq 1 30); do
  curl -fsSL --max-time 5 https://hub.docker.com > /dev/null 2>&1 && break
  sleep 5
  echo "[InSpectre] Retrying... (${i}/30)"
done
curl -fsSL --max-time 5 https://hub.docker.com > /dev/null 2>&1 || {
  echo "[InSpectre] ERROR: No internet access. Cannot pull images from Docker Hub."
  echo "[InSpectre] Check your network connection and run: sudo systemctl restart inspectre"
  exit 1
}

echo "[InSpectre] Pulling latest images from Docker Hub..."
docker compose pull

echo "[InSpectre] Starting InSpectre..."
docker compose up -d

IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' || hostname -I | awk '{print $1}')
echo -e "\n╔══════════════════════════════════════════════════╗"
echo "║  InSpectre System Protection Engine Active       ║"
echo "║  Access Web Portal : http://${IP}:3000          ║"
echo "╚══════════════════════════════════════════════════╝\n"
STARTUP
}

systemd_unit() {
  cat <<'UNIT'
[Unit]
Description=InSpectre Container Orchestration Framework
After=docker.service systemd-networkd-wait-online.service network-online.target
Wants=docker.service systemd-networkd-wait-online.service network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/inspectre
ExecStart=/opt/inspectre/start.sh
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=600

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
╚══════════════════════════════════════════════════════╝
MOTD
}

# ── Shared: write appliance.json flag file ────────────────────────────────────
write_appliance_json() {
  local mnt="$1" type="$2" arch="$3" mode="$4"
  sudo tee "${mnt}/opt/inspectre/appliance.json" >/dev/null <<EOF
{
  "type": "${type}",
  "arch": "${arch}",
  "mode": "${mode}",
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "version": "1.0.0"
}
EOF
}

# ── Shared: mount a qcow2 Ubuntu base image and return nbd + mnt paths ────────
_mount_ubuntu_base() {
  local vw="$1" disk_name="$2" disk_size="$3"

  curl -L --progress-bar "${UBUNTU_URL}" -o "${vw}/ubuntu-base.img"

  local disk="${vw}/${disk_name}"
  qemu-img convert -f qcow2 -O qcow2 "${vw}/ubuntu-base.img" "${disk}"
  qemu-img resize "${disk}" "${disk_size}"

  sudo modprobe nbd max_part=8 2>/dev/null || true
  local nbd=""
  for dev in /dev/nbd{0..15}; do
    if [[ -b "${dev}" ]] && ! sudo lsblk "${dev}" 2>/dev/null | grep -q "part\|disk.*[0-9]$"; then
      nbd="${dev}"; break
    fi
  done
  [[ -n "${nbd}" ]] || die "No available network block devices."

  sudo qemu-nbd --connect="${nbd}" "${disk}"
  sleep 2

  sudo sgdisk -e "${nbd}"
  sudo partprobe "${nbd}" 2>/dev/null || true
  sleep 1

  local root_part="" part_num=""
  for part in "${nbd}p1" "${nbd}p2" "${nbd}p3" "${nbd}p4" "${nbd}p5"; do
    if [[ -b "${part}" ]] && sudo blkid "${part}" | grep -q 'ext4'; then
      root_part="${part}"; part_num="${part#${nbd}p}"; break
    fi
  done

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

  # Cloud-init + netplan
  sudo mkdir -p "${mnt}/etc/cloud/cloud.cfg.d"
  sudo tee "${mnt}/etc/cloud/cloud.cfg.d/99-disable-user-manipulation.cfg" >/dev/null <<'EOF'
users: []
disable_root: false
preserve_hostname: true
ssh_pwauth: true
network: {config: disabled}
EOF

  sudo mkdir -p "${mnt}/etc/netplan"
  sudo tee "${mnt}/etc/netplan/01-netcfg.yaml" >/dev/null <<'EOF'
network:
  version: 2
  renderer: networkd
  ethernets:
    all_eth:
      match:
        name: e*
      dhcp4: true
EOF

  sudo tee "${mnt}/usr/sbin/policy-rc.d" >/dev/null <<'POLICY'
#!/bin/sh
exit 101
POLICY
  sudo chmod +x "${mnt}/usr/sbin/policy-rc.d"

  _MOUNT_NBD="${nbd}"
  _MOUNT_MNT="${mnt}"
  _MOUNT_DISK="${disk}"
}

# ── Shared: install Docker + users inside a chroot ────────────────────────────
_chroot_vm_setup() {
  local mnt="$1"
  sudo chroot "${mnt}" /bin/bash <<'CHROOT'
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends docker.io docker-compose-v2 curl jq net-tools ca-certificates openssh-server
apt-get clean
systemctl enable ssh
if [ -f /etc/ssh/sshd_config ]; then
  sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
  sed -i 's/^#*PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config
fi
if ! id inspectre &>/dev/null; then
  useradd -m -s /bin/bash inspectre
fi
usermod -aG sudo,docker inspectre
echo "inspectre:inspectre" | chpasswd
echo "root:inspectre" | chpasswd
echo "inspectre ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/inspectre
chmod 0440 /etc/sudoers.d/inspectre
CHROOT
}

# ── Shared: unmount + finalise a VM image ─────────────────────────────────────
_finalise_vm() {
  local mnt="$1" nbd="$2" disk="$3" out_image="$4"
  sudo rm -f "${mnt}/usr/sbin/policy-rc.d"
  sudo rm -f "${mnt}/etc/resolv.conf"
  sudo mv "${mnt}/etc/resolv.conf.bak" "${mnt}/etc/resolv.conf" 2>/dev/null || true

  sudo umount "${mnt}/dev/pts" 2>/dev/null || true
  sudo umount "${mnt}/dev"     2>/dev/null || true
  sudo umount "${mnt}/sys"     2>/dev/null || true
  sudo umount "${mnt}/proc"    2>/dev/null || true
  sudo umount "${mnt}"
  sudo qemu-nbd --disconnect "${nbd}"
  sleep 1

  if $MAX_COMPRESS; then
    # No -c: leave qcow2 uncompressed so xz can compress the raw data optimally.
    # Using -c first (zlib) then xz is double-compression and results in a larger file.
    info "Converting to uncompressed qcow2 for xz pass..."
    qemu-img convert -O qcow2 "${disk}" "${OUTPUT_DIR}/${out_image}"
    info "Compressing VM image (xz -9) — this may take a while..."
    xz --threads=0 -9 -f "${OUTPUT_DIR}/${out_image}"
    ok "VM image built: ${OUTPUT_DIR}/${out_image}.xz"
  else
    # Without xz, qcow2 internal compression (-c) is the right choice for a
    # ready-to-use file that's reasonably sized without the long xz wait.
    qemu-img convert -c -O qcow2 "${disk}" "${OUTPUT_DIR}/${out_image}"
    ok "VM image built: ${OUTPUT_DIR}/${out_image}"
  fi
}

# ── VM Appliance — Offline (containers baked in) ──────────────────────────────
build_vm_image() {
  step "Building VM Appliance image — Offline (x86_64)"
  [[ -f "$TAR_AMD" ]] || die "x64 container bundle cache missing."

  local vw="${WORK}/vm"
  mkdir -p "${vw}" "${OUTPUT_DIR}"

  _mount_ubuntu_base "${vw}" "${VM_IMAGE}" "${VM_DISK_SIZE}"
  local mnt="${_MOUNT_MNT}" nbd="${_MOUNT_NBD}" disk="${_MOUNT_DISK}"

  _chroot_vm_setup "${mnt}"

  sudo mkdir -p "${mnt}/opt/inspectre/images"
  sudo cp "${TAR_AMD}" "${mnt}/opt/inspectre/images/inspectre-images.tar"
  sudo cp "${REPO}/docker-compose.vm.yml" "${mnt}/opt/inspectre/docker-compose.yml"
  write_appliance_json "${mnt}" "vm" "amd64" "offline"
  startup_script        | sudo tee "${mnt}/opt/inspectre/start.sh" >/dev/null
  sudo chmod +x "${mnt}/opt/inspectre/start.sh"
  systemd_unit          | sudo tee "${mnt}/etc/systemd/system/inspectre.service" >/dev/null
  motd_content          | sudo tee "${mnt}/etc/motd" >/dev/null
  sudo chroot "${mnt}" /bin/bash -c "systemctl enable docker inspectre"

  _finalise_vm "${mnt}" "${nbd}" "${disk}" "${VM_IMAGE}"
}

# ── VM Appliance — Online (pulls from Docker Hub on boot) ─────────────────────
build_vm_online_image() {
  step "Building VM Appliance image — Online / Docker Hub (x86_64)"
  info "This image pulls thefunkygibbon/inspectre-* from Docker Hub on first boot."
  info "No local container build required."

  local vw="${WORK}/vm-online"
  mkdir -p "${vw}" "${OUTPUT_DIR}"

  _mount_ubuntu_base "${vw}" "${VM_ONLINE_IMAGE}" "${VM_ONLINE_DISK_SIZE}"
  local mnt="${_MOUNT_MNT}" nbd="${_MOUNT_NBD}" disk="${_MOUNT_DISK}"

  _chroot_vm_setup "${mnt}"

  sudo mkdir -p "${mnt}/opt/inspectre"
  sudo cp "${REPO}/docker-compose.vm.online.yml" "${mnt}/opt/inspectre/docker-compose.yml"
  write_appliance_json "${mnt}" "vm" "amd64" "online"
  startup_script_online | sudo tee "${mnt}/opt/inspectre/start.sh" >/dev/null
  sudo chmod +x "${mnt}/opt/inspectre/start.sh"
  systemd_unit           | sudo tee "${mnt}/etc/systemd/system/inspectre.service" >/dev/null
  motd_content           | sudo tee "${mnt}/etc/motd" >/dev/null
  sudo chroot "${mnt}" /bin/bash -c "systemctl enable docker inspectre"

  _finalise_vm "${mnt}" "${nbd}" "${disk}" "${VM_ONLINE_IMAGE}"
}

# ── Shared: download + expand Raspberry Pi base image ─────────────────────────
_prepare_pi_base() {
  local pw="$1"

  local idx; idx=$(curl -sL "${RPI_INDEX}/")
  local latest_dir; latest_dir=$(echo "${idx}" | grep -oP 'raspios_lite_arm64-\d{4}-\d{2}-\d{2}' | sort -r | head -1)
  local img_xz; img_xz=$(curl -sL "${RPI_INDEX}/${latest_dir}/" | grep -oP '[\w\-]+\.img\.xz' | head -1)

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

# ── Shared: mount Pi loop device, bind-mount proc/sys/dev, set resolv.conf ────
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

# ── Shared: chroot install for Pi ─────────────────────────────────────────────
_chroot_pi_setup() {
  local mnt="$1"
  sudo chroot "${mnt}" /bin/bash <<'CHROOT'
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends docker.io docker-compose-v2 curl jq net-tools ca-certificates
echo "root:inspectre" | chpasswd
apt-get clean
CHROOT
}

# ── Shared: finalise Pi image ─────────────────────────────────────────────────
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
    # Pi base is already a raw .img — xz compresses it directly with no intermediate
    # conversion step needed. This gives optimal compression ratios.
    info "Compressing Pi image (xz -9) — this may take a while..."
    xz --threads=0 -9 -z "${raw}" -c > "${OUTPUT_DIR}/${out_image}.xz"
    ok "Pi image built: ${OUTPUT_DIR}/${out_image}.xz"
  else
    cp "${raw}" "${OUTPUT_DIR}/${out_image}"
    ok "Pi image built: ${OUTPUT_DIR}/${out_image}"
  fi
}

# ── Shared: write Pi boot files (ssh enable, userconf) ────────────────────────
_pi_boot_setup() {
  local boot_mnt="$1"
  sudo touch "${boot_mnt}/ssh" || true
  local pi_pw_hash='$6$rounds=4096$inspectre$9T1j/dxZpyW7dB4qoMFlEq4K7kZwxlN.ZF09wRqiNEi9VJ/SRRvxlCkIMVtCnBfHHpOuAQEP6oROxL0bz6lD41'
  echo "pi:${pi_pw_hash}" | sudo tee "${boot_mnt}/userconf.txt" >/dev/null
}

# ── Shared: enable systemd services on Pi ─────────────────────────────────────
_pi_enable_services() {
  local mnt="$1"
  sudo mkdir -p "${mnt}/etc/systemd/system/multi-user.target.wants"
  sudo ln -sf /lib/systemd/system/docker.service \
    "${mnt}/etc/systemd/system/multi-user.target.wants/docker.service" || true
  sudo ln -sf /etc/systemd/system/inspectre.service \
    "${mnt}/etc/systemd/system/multi-user.target.wants/inspectre.service" || true
}

# ── Pi Appliance — Offline (containers baked in) ──────────────────────────────
build_pi_image() {
  step "Building Raspberry Pi Image — Offline (arm64)"
  [[ -f "$TAR_ARM" ]] || die "ARM container archive missing."

  local pw="${WORK}/pi"
  mkdir -p "${pw}" "${OUTPUT_DIR}"

  _prepare_pi_base "${pw}"
  _mount_pi_base "${pw}"
  local mnt="${_PI_MNT}" boot_mnt="${_PI_BOOT_MNT}" loop="${_PI_LOOP}" raw="${_PI_RAW}"

  _chroot_pi_setup "${mnt}"

  sudo mkdir -p "${mnt}/opt/inspectre/images"
  sudo cp "${TAR_ARM}" "${mnt}/opt/inspectre/images/inspectre-images.tar"
  sudo cp "${REPO}/docker-compose.pi.yml" "${mnt}/opt/inspectre/docker-compose.yml"
  write_appliance_json "${mnt}" "pi" "arm64" "offline"
  startup_script      | sudo tee "${mnt}/opt/inspectre/start.sh" >/dev/null
  sudo chmod +x "${mnt}/opt/inspectre/start.sh"
  systemd_unit        | sudo tee "${mnt}/etc/systemd/system/inspectre.service" >/dev/null
  motd_content        | sudo tee "${mnt}/etc/motd" >/dev/null

  _pi_boot_setup "${boot_mnt}"
  _pi_enable_services "${mnt}"
  _finalise_pi "${mnt}" "${boot_mnt}" "${loop}" "${raw}" "${PI_IMAGE}"
}

# ── Pi Appliance — Online (pulls from Docker Hub on boot) ─────────────────────
build_pi_online_image() {
  step "Building Raspberry Pi Image — Online / Docker Hub (arm64)"
  info "This image pulls thefunkygibbon/inspectre-*:raspi from Docker Hub on first boot."
  info "No local container build required."

  local pw="${WORK}/pi-online"
  mkdir -p "${pw}" "${OUTPUT_DIR}"

  _prepare_pi_base "${pw}"
  _mount_pi_base "${pw}"
  local mnt="${_PI_MNT}" boot_mnt="${_PI_BOOT_MNT}" loop="${_PI_LOOP}" raw="${_PI_RAW}"

  _chroot_pi_setup "${mnt}"

  sudo mkdir -p "${mnt}/opt/inspectre"
  sudo cp "${REPO}/docker-compose.pi.online.yml" "${mnt}/opt/inspectre/docker-compose.yml"
  write_appliance_json "${mnt}" "pi" "arm64" "online"
  startup_script_online | sudo tee "${mnt}/opt/inspectre/start.sh" >/dev/null
  sudo chmod +x "${mnt}/opt/inspectre/start.sh"
  systemd_unit           | sudo tee "${mnt}/etc/systemd/system/inspectre.service" >/dev/null
  motd_content           | sudo tee "${mnt}/etc/motd" >/dev/null

  _pi_boot_setup "${boot_mnt}"
  _pi_enable_services "${mnt}"
  _finalise_pi "${mnt}" "${boot_mnt}" "${loop}" "${raw}" "${PI_ONLINE_IMAGE}"
}

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
  for nbd in /dev/nbd{0..15}; do sudo qemu-nbd --disconnect "${nbd}" 2>/dev/null || true; done
  while IFS= read -r line; do
    local lo; lo=$(echo "${line}" | awk '{print $1}')
    sudo losetup -d "${lo}" 2>/dev/null || true
  done < <(sudo losetup -l -n -O NAME,BACK-FILE 2>/dev/null | grep "${WORK}" || true)
  sudo rm -rf "${WORK}"
}
trap cleanup EXIT INT TERM

main() {
  echo -e "\n${CYAN}${BOLD}InSpectre Image Builder v5.1 Active${NC}"
  check_deps
  clone_repo
  ( $BUILD_VM || $BUILD_PI ) && patch_dockerfiles
  build_docker_images
  $PUSH_DOCKERHUB  && push_images
  $BUILD_VM        && build_vm_image
  $BUILD_VM_ONLINE && build_vm_online_image
  $BUILD_PI        && build_pi_image
  $BUILD_PI_ONLINE && build_pi_online_image
  ok "All targeted image profiles completed successfully."
}

main "$@"
