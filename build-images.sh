#!/usr/bin/env bash
# =============================================================================
#  InSpectre — Appliance Image Builder  v2.1 (Interactive Edition)
#
#  Produces:
#    output/inspectre-vm.qcow2      x86_64 VM  (QEMU/KVM, Proxmox, VirtualBox)
#    output/inspectre-pi.img.xz     arm64 Pi   (Raspberry Pi 4 / Pi 5)
#
#  Both images are fully self-contained — no internet needed on first boot.
#  Docker and all containers are pre-installed. Boot → running stack in < 60s.
# =============================================================================
set -euo pipefail
export DOCKER_BUILDKIT=1

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
BUILD_PI=false
BUILD_CONTAINERS_AMD=false
BUILD_CONTAINERS_ARM=false
CLI_TARGET_SPECIFIED=false

REPO_URL="https://github.com/thefunkygibbon/InSpectre.git"
REPO_BRANCH="main"
OUTPUT_DIR="$(pwd)/output"
CACHE_DIR="${OUTPUT_DIR}/.cache"
VM_DISK_SIZE="20G"
VM_IMAGE="inspectre-vm.qcow2"
PI_IMAGE="inspectre-pi.img"
UBUNTU_URL="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
UBUNTU_SHA_URL="https://cloud-images.ubuntu.com/jammy/current/SHA256SUMS"
RPI_INDEX="https://downloads.raspberrypi.com/raspios_lite_arm64/images"

WORK="$(mktemp -d /tmp/inspectre-build.XXXXXX)"
REPO="${WORK}/repo"
TAR_AMD="${CACHE_DIR}/inspectre-amd64.tar"
TAR_ARM="${CACHE_DIR}/inspectre-arm64.tar"

# ── Args ──────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --vm-only)     BUILD_VM=true; CLI_TARGET_SPECIFIED=true ;;
    --pi-only)     BUILD_PI=true; CLI_TARGET_SPECIFIED=true ;;
    --branch)      REPO_BRANCH="$2"; shift ;;
    --output-dir)  OUTPUT_DIR="$2"; shift ;;
    --help|-h)     sed -n '2,15p' "$0" | sed 's/^#  \{0,2\}//'; exit 0 ;;
    *)             die "Unknown option: $1" ;;
  esac
  shift
done

# Ensure output and cache tracking paths exist early
mkdir -p "${CACHE_DIR}"

# ── Interactive Prompt Selection ──────────────────────────────────────────────
if ! $CLI_TARGET_SPECIFIED; then
  echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}${BOLD}║            Select a Build Option                 ║${NC}"
  echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
  echo -e "  1) Build x64 Docker Container Images Only"
  echo -e "  2) Build ARM Docker Container Images Only"
  echo -e "  3) Build x64 VM Appliance Image (.qcow2)"
  echo -e "  4) Build Raspberry Pi SD Card Image (.img.xz)"
  echo -e "  5) Build Everything (All Container & Appliance Images)"
  echo -e "  q) Quit"
  echo ""
  read -rp "Enter selection [1-5/q]: " choice
  echo ""

  case "$choice" in
    1)
      BUILD_CONTAINERS_AMD=true
      ;;
    2)
      BUILD_CONTAINERS_ARM=true
      ;;
    3)
      BUILD_VM=true
      if [[ -f "$TAR_AMD" ]]; then
        echo -e "${YELLOW}[WARN] Found existing cached x64 container bundle.${NC}"
        read -rp "Do you want to re-compile the x64 container images? [y/N]: " recompile
        if [[ "$recompile" =~ ^[Yy]$ ]]; then BUILD_CONTAINERS_AMD=true; fi
      else
        BUILD_CONTAINERS_AMD=true
      fi
      ;;
    4)
      BUILD_PI=true
      if [[ -f "$TAR_ARM" ]]; then
        echo -e "${YELLOW}[WARN] Found existing cached ARM container bundle.${NC}"
        read -rp "Do you want to re-compile the ARM container images? [y/N]: " recompile
        if [[ "$recompile" =~ ^[Yy]$ ]]; then BUILD_CONTAINERS_ARM=true; fi
      else
        BUILD_CONTAINERS_ARM=true
      fi
      ;;
    5)
      BUILD_VM=true
      BUILD_PI=true
      if [[ -f "$TAR_AMD" ]]; then
        read -rp "Found cached x64 container bundle. Re-compile? [y/N]: " recomp_amd
        if [[ "$recomp_amd" =~ ^[Yy]$ ]]; then BUILD_CONTAINERS_AMD=true; fi
      else
        BUILD_CONTAINERS_AMD=true
      fi
      if [[ -f "$TAR_ARM" ]]; then
        read -rp "Found cached ARM container bundle. Re-compile? [y/N]: " recomp_arm
        if [[ "$recomp_arm" =~ ^[Yy]$ ]]; then BUILD_CONTAINERS_ARM=true; fi
      else
        BUILD_CONTAINERS_ARM=true
      fi
      ;;
    [Qq]*)
      echo "Exiting."
      exit 0
      ;;
    *)
      die "Invalid choice selected: '$choice'"
      ;;
  esac
else
  # Non-interactive CLI target fallback evaluations
  if $BUILD_VM && [[ ! -f "$TAR_AMD" ]]; then BUILD_CONTAINERS_AMD=true; fi
  if $BUILD_PI && [[ ! -f "$TAR_ARM" ]]; then BUILD_CONTAINERS_ARM=true; fi
fi

# ── Dependency check ──────────────────────────────────────────────────────────
check_deps() {
  step "Checking dependencies"
  local missing=()
  local deps=(docker git curl xz sha256sum)
  
  if $BUILD_VM || $BUILD_PI; then
    deps+=(parted e2fsck resize2fs losetup)
  fi
  $BUILD_VM && deps+=(qemu-img cloud-localds qemu-system-x86_64 qemu-nbd)
  $BUILD_PI && deps+=(chroot)
  
  for d in "${deps[@]}"; do
    command -v "$d" &>/dev/null && ok "$d" || missing+=("$d")
  done
  [[ ${#missing[@]} -eq 0 ]] || \
    die "Missing tools: ${missing[*]}\n\nInstall:\n  sudo apt-get install -y qemu-system-x86 qemu-system-arm qemu-utils cloud-image-utils git curl xz-utils parted e2fsprogs"

  # Docker buildx verification
  docker buildx version &>/dev/null || die "docker buildx not available"

  # binfmt for cross-compiling ARM architecture on x86 machines
  if $BUILD_CONTAINERS_ARM && ! ls /proc/sys/fs/binfmt_misc/ 2>/dev/null | grep -q aarch64; then
    warn "Registering QEMU binfmt for arm64..."
    docker run --rm --privileged multiarch/qemu-user-static --reset -p yes \
      || die "Failed. Run manually: docker run --rm --privileged multiarch/qemu-user-static --reset -p yes"
  fi
  ok "All dependencies satisfied"
}

# ── Step 1: Clone repo ────────────────────────────────────────────────────────
clone_repo() {
  step "Cloning InSpectre (branch: ${REPO_BRANCH})"
  git clone --depth=1 --branch "${REPO_BRANCH}" "${REPO_URL}" "${REPO}"
  ok "Cloned to ${REPO}"
}

# ── Step 2: Patch Dockerfiles for multi-arch ──────────────────────────────────
patch_dockerfiles() {
  step "Patching Dockerfiles for multi-arch compatibility"

  local probe_df="${REPO}/probe/Dockerfile"
  local backend_df="${REPO}/backend/Dockerfile"

  # ── probe/Dockerfile ──────────────────────────────────────────────────────
  python3 - "${probe_df}" <<'PY'
import sys, re
path = sys.argv[1]
with open(path) as f:
    txt = f.read()

txt = re.sub(
    r'(^FROM python:3\.12-slim\n)',
    r'\1ARG TARGETARCH=amd64\n',
    txt, count=1, flags=re.MULTILINE
)
txt = txt.replace('nuclei_${NUCLEI_VERSION}_linux_amd64.zip', 'nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip')
txt = txt.replace('nerva-linux-amd64.tar.gz', 'nerva-linux-${TARGETARCH}.tar.gz')

with open(path, 'w') as f:
    f.write(txt)
print("  probe/Dockerfile patched")
PY

  # ── backend/Dockerfile ────────────────────────────────────────────────────
  python3 - "${backend_df}" <<'PY'
import sys, re
path = sys.argv[1]
with open(path) as f:
    txt = f.read()

txt = re.sub(
    r'(^FROM python:3\.12-slim\n)',
    r'\1ARG TARGETARCH=amd64\n',
    txt, count=1, flags=re.MULTILINE
)
txt = txt.replace(
    '"https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"',
    '"https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-$([ \\"$TARGETARCH\\" = \\"arm64\\" ] && echo ARM64 || echo 64bit).tar.gz"'
)

with open(path, 'w') as f:
    f.write(txt)
print("  backend/Dockerfile patched")
PY

  ok "Dockerfiles patched successfully"
}

# ── Step 3: Build Docker images ───────────────────────────────────────────────
build_docker_images() {
  if ! $BUILD_CONTAINERS_AMD && ! $BUILD_CONTAINERS_ARM; then
    info "Skipping container compiling phases (Using cached tar bundles)."
    return 0
  fi

  step "Building Docker container images"
  cd "${REPO}"

  local builder="inspectre-builder-$$"
  docker buildx create \
    --name "${builder}" \
    --driver docker-container \
    --buildkitd-flags '--allow-insecure-entitlement network.host' \
    --use >/dev/null
  trap "docker buildx rm ${builder} 2>/dev/null || true" RETURN

  local pids=() log files tags=()

  _build_bg() {
    local name="$1" platform="$2" context="$3" tag="$4"
    local logfile="${WORK}/build-${name}.log"
    docker buildx build \
      --builder "${builder}" \
      --platform "${platform}" \
      --tag "${tag}" \
      --load \
      --progress plain \
      "${context}" \
      >"${logfile}" 2>&1 &
    pids+=($!)
    tags+=("${tag}")
    info "  Started: ${tag} [pid $!]"
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

  local failed=0
  for i in "${!pids[@]}"; do
    if wait "${pids[$i]}"; then
      ok "  ${tags[$i]} completed successfully"
    else
      warn "  ${tags[$i]} FAILED. Check build log details inside ${WORK}/"
      failed=1
    fi
  done
  [[ $failed -eq 0 ]] || die "One or more parallel Docker image compilations failed."

  if $BUILD_CONTAINERS_AMD; then
    info "Pulling postgres:15-alpine (amd64)..."
    docker pull --platform linux/amd64 --quiet postgres:15-alpine
    docker tag postgres:15-alpine inspectre-postgres:amd64
    info "Exporting amd64 container bundle..."
    docker save inspectre-backend:amd64 inspectre-probe:amd64 inspectre-frontend:amd64 inspectre-postgres:amd64 > "${TAR_AMD}"
    ok "amd64 cached container bundle finalized: $(du -sh "${TAR_AMD}" | cut -f1)"
  fi

  if $BUILD_CONTAINERS_ARM; then
    info "Pulling postgres:15-alpine (arm64)..."
    docker pull --platform linux/arm64 --quiet postgres:15-alpine
    docker tag postgres:15-alpine inspectre-postgres:arm64
    info "Exporting arm64 container bundle..."
    docker save inspectre-backend:arm64 inspectre-probe:arm64 inspectre-frontend:arm64 inspectre-postgres:arm64 > "${TAR_ARM}"
    ok "arm64 cached container bundle finalized: $(du -sh "${TAR_ARM}" | cut -f1)"
  fi

  cd - >/dev/null
}

# ── Helpers: Appliance Configuration Content Creators ─────────────────────────
compose_content() {
  local arch="$1"
  cat <<COMPOSE
services:
  db:
    image: inspectre-postgres:${arch}
    container_name: inspectre-db
    restart: always
    environment:
      POSTGRES_USER: admin
      POSTGRES_PASSWORD: inspectre_db_pass
      POSTGRES_DB: inspectre
    volumes:
      - ./postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U admin -d inspectre"]
      interval: 5s
      timeout: 5s
      retries: 10
      start_period: 10s

  web:
    image: inspectre-backend:${arch}
    container_name: inspectre-web
    restart: always
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: postgresql://admin:inspectre_db_pass@db:5432/inspectre
      PROBE_API_URL: http://host.docker.internal:8666
      SECRET_KEY: CHANGE_THIS_TO_A_LONG_RANDOM_SECRET
      CORS_ORIGINS: http://localhost:3000
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    extra_hosts:
      - "host.docker.internal:host-gateway"
    depends_on:
      db:
        condition: service_healthy

  probe:
    image: inspectre-probe:${arch}
    container_name: inspectre-probe
    network_mode: "host"
    privileged: true
    restart: always
    environment:
      DATABASE_URL: postgresql://admin:inspectre_db_pass@localhost:5432/inspectre
      SCAN_INTERVAL: "60"
      NMAP_ARGS: "-sT -O --osscan-limit -T4"
      PROBE_API_PORT: "8666"
      PYTHONUNBUFFERED: "1"
    cap_add:
      - NET_ADMIN
      - NET_RAW
    depends_on:
      db:
        condition: service_healthy

  frontend:
    image: inspectre-frontend:${arch}
    container_name: inspectre-frontend
    restart: always
    ports:
      - "3000:80"
    depends_on:
      - web
COMPOSE
}

startup_script() {
  cat <<'STARTUP'
#!/bin/bash
set -e
TAR="/opt/inspectre/images/inspectre-images.tar"
if [[ -f "$TAR" ]]; then
  echo "[InSpectre] Loading baked container system images from bundle archive..."
  docker load < "$TAR"
  rm -f "$TAR"
fi
cd /opt/inspectre
docker compose up -d
IP=$(hostname -I | awk '{print $1}')
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  InSpectre Application Active                    ║"
echo "║  Frontend UI : http://${IP}:3000                 ║"
echo "║  Backend API : http://${IP}:8000                 ║"
echo "╚══════════════════════════════════════════════════╝"
STARTUP
}

systemd_unit() {
  cat <<'UNIT'
[Unit]
Description=InSpectre System Framework
After=docker.service network-online.target
Requires=docker.service

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
║  Core API Backend  : http://<this-ip>:8000           ║
║  System Logs       : sudo journalctl -u inspectre -f ║
╚══════════════════════════════════════════════════════╝
MOTD
}

# ── Step 4: VM Image Generation ───────────────────────────────────────────────
build_vm_image() {
  step "Building VM image (x86_64)"
  [[ -f "$TAR_AMD" ]] || die "x64 container compilation bundle missing from local cache."
  
  local vw="${WORK}/vm"
  mkdir -p "${vw}" "${OUTPUT_DIR}"

  info "Downloading Ubuntu Cloud framework image..."
  local base="${vw}/ubuntu-base.img"
  curl -L --progress-bar "${UBUNTU_URL}" -o "${base}"
  
  info "Validating architecture download checksums..."
  local expected
  expected=$(curl -sL "${UBUNTU_SHA_URL}" | grep "jammy-server-cloudimg-amd64.img" | head -n1 | awk '{print $1}')
  echo "${expected}  ${base}" | sha256sum --check - || die "Base OS image download corrupted."

  local disk="${vw}/${VM_IMAGE}"
  qemu-img convert -f qcow2 -O qcow2 "${base}" "${disk}"
  qemu-img resize "${disk}" "${VM_DISK_SIZE}"

  local ci="${vw}/cloud-init"
  mkdir -p "${ci}"
  echo "instance-id: inspectre-appliance" > "${ci}/meta-data"
  echo "local-hostname: inspectre" >> "${ci}/meta-data"

  local pw_hash='$6$rounds=4096$inspectre$9T1j/dxZpyW7dB4qoMFlEq4K7kZwxlN.ZF09wRqiNEi9VJ/SRRvxlCkIMVtCnBfHHpOuAQEP6oROxL0bz6lD41'

  cat >"${ci}/user-data" <<USERDATA
#cloud-config
users:
  - name: inspectre
    groups: [sudo, docker]
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    passwd: "${pw_hash}"
    shell: /bin/bash

package_update: true
packages: [docker.io, docker-compose-v2, curl, jq, net-tools]

write_files:
  - path: /opt/inspectre/docker-compose.yml
    content: |
$(compose_content "amd64" | sed 's/^/      /')
  - path: /opt/inspectre/start.sh
    permissions: '0755'
    content: |
$(startup_script | sed 's/^/      /')
  - path: /etc/systemd/system/inspectre.service
    content: |
$(systemd_unit | sed 's/^/      /')
  - path: /etc/motd
    content: |
$(motd_content | sed 's/^/      /')

runcmd:
  - systemctl enable docker
  - systemctl start docker
  - usermod -aG docker inspectre
  - mkdir -p /opt/inspectre/images
  - systemctl enable inspectre
USERDATA

  local seed="${vw}/seed.iso"
  cloud-localds "${seed}" "${ci}/user-data" "${ci}/meta-data"

  info "Injecting cached x64 containers directly into internal partition structure..."
  sudo modprobe nbd max_part=8 2>/dev/null || true
  
  local nbd=""
  for dev in /dev/nbd{0..15}; do
    if [[ -b "${dev}" ]] && ! sudo lsblk "${dev}" 2>/dev/null | grep -q "part\|disk.*[0-9]$"; then
      nbd="${dev}"; break
    fi
  done
  [[ -n "${nbd}" ]] || die "Network block devices exhausted. Check kernel module loads."

  sudo qemu-nbd --connect="${nbd}" "${disk}"
  sleep 2
  sudo partprobe "${nbd}" 2>/dev/null || true
  sleep 1

  local mnt="${vw}/mnt"
  mkdir -p "${mnt}"
  local mounted=false
  for part in "${nbd}p1" "${nbd}p2" "${nbd}p3"; do
    [[ -b "${part}" ]] || continue
    sudo mount "${part}" "${mnt}" 2>/dev/null && mounted=true && break
  done
  
  if ! $mounted; then
    sudo qemu-nbd --disconnect "${nbd}"
    die "Failed tracking viable filesystem structures inside VM target disk partitions."
  fi

  sudo mkdir -p "${mnt}/opt/inspectre/images"
  sudo cp "${TAR_AMD}" "${mnt}/opt/inspectre/images/inspectre-images.tar"

  sudo umount "${mnt}"
  sudo qemu-nbd --disconnect "${nbd}"
  sleep 1

  # Check for /dev/kvm write access to attach hardware virtualization acceleration
  local kvm_arg=""
  if [[ -w /dev/kvm ]]; then
    kvm_arg="-enable-kvm"
    info "KVM acceleration detected. Initializing rapid headless configuration engine..."
  else
    warn "KVM acceleration missing. Running step via standard software virtualization emulation..."
  fi

  info "Executing headless target environment configuration operations..."
  timeout 480 qemu-system-x86_64 \
    ${kvm_arg} \
    -name "inspectre-firstboot" \
    -m 2048 -smp 4 \
    -drive "file=${disk},format=qcow2,if=virtio" \
    -drive "file=${seed},format=raw,if=virtio" \
    -nographic \
    -serial mon:stdio \
    -no-reboot \
    -netdev "user,id=net0" \
    -device "virtio-net-pci,netdev=net0" \
    2>&1 | grep --line-buffered -E "cloud-init|inspectre|Reached target|login:|runcmd" || true

  info "Compressing final production appliance artifact..."
  qemu-img convert -c -O qcow2 "${disk}" "${OUTPUT_DIR}/${VM_IMAGE}"
  ok "VM build finalized: ${OUTPUT_DIR}/${VM_IMAGE}"
}

# ── Step 5: Pi Image Generation ───────────────────────────────────────────────
build_pi_image() {
  step "Building Raspberry Pi SD Card Image (arm64)"
  [[ -f "$TAR_ARM" ]] || die "ARM container compilation bundle missing from local cache."

  local pw="${WORK}/pi"
  mkdir -p "${pw}" "${OUTPUT_DIR}"

  info "Locating stable upstream image distributions..."
  local idx; idx=$(curl -sL "${RPI_INDEX}/")
  local latest_dir; latest_dir=$(echo "${idx}" | grep -oP 'raspios_lite_arm64-\d{4}-\d{2}-\d{2}' | sort -r | head -1)
  local dir_url="${RPI_INDEX}/${latest_dir}/"
  local img_xz; img_xz=$(curl -sL "${dir_url}" | grep -oP '[\w\-]+\.img\.xz' | head -1)

  local xz_path="${pw}/${img_xz}"
  curl -L --progress-bar "${dir_url}${img_xz}" -o "${xz_path}"
  
  info "Extracting Raspberry Pi OS filesystems..."
  xz --decompress --keep --threads=0 "${xz_path}"
  local raw="${pw}/${img_xz%.xz}"

  info "Expanding local base storage tracks by 10GB..."
  dd if=/dev/zero bs=1M count=10240 >>"${raw}" 2>/dev/null
  sudo parted -s "${raw}" resizepart 2 100% 2>/dev/null || true

  local loop; loop=$(sudo losetup --find --show --partscan "${raw}")
  sleep 2
  sudo e2fsck -f "${loop}p2" -y >/dev/null 2>&1 || true
  sudo resize2fs "${loop}p2" >/dev/null 2>&1 || true

  local mnt="${pw}/mnt"
  mkdir -p "${mnt}"
  sudo mount "${loop}p2" "${mnt}"

  local boot_mnt="${mnt}/boot"
  [[ -d "${mnt}/boot/firmware" ]] && boot_mnt="${mnt}/boot/firmware"
  sudo mount "${loop}p1" "${boot_mnt}" 2>/dev/null || true

  info "Initializing isolated OS Environment Chroot for system updates..."
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

  sudo chroot "${mnt}" /bin/bash <<'CHROOT'
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends docker.io docker-compose-v2 curl jq net-tools ca-certificates
apt-get clean
rm -rf /var/lib/apt/lists/*
CHROOT

  info "Baking system service profiles and cached ARM containers into Pi tracks..."
  sudo mkdir -p "${mnt}/opt/inspectre/images"
  sudo cp "${TAR_ARM}" "${mnt}/opt/inspectre/images/inspectre-images.tar"

  compose_content "arm64" | sudo tee "${mnt}/opt/inspectre/docker-compose.yml" >/dev/null
  startup_script | sudo tee "${mnt}/opt/inspectre/start.sh" >/dev/null
  sudo chmod +x "${mnt}/opt/inspectre/start.sh"
  systemd_unit | sudo tee "${mnt}/etc/systemd/system/inspectre.service" >/dev/null
  motd_content | sudo tee "${mnt}/etc/motd" >/dev/null

  sudo mkdir -p "${mnt}/etc/systemd/system/multi-user.target.wants"
  sudo ln -sf /lib/systemd/system/docker.service "${mnt}/etc/systemd/system/multi-user.target.wants/docker.service" || true
  sudo ln -sf /etc/systemd/system/inspectre.service "${mnt}/etc/systemd/system/multi-user.target.wants/inspectre.service" || true

  sudo touch "${boot_mnt}/ssh" || true
  
  local pi_pw_hash='$6$rounds=4096$inspectre$9T1j/dxZpyW7dB4qoMFlEq4K7kZwxlN.ZF09wRqiNEi9VJ/SRRvxlCkIMVtCnBfHHpOuAQEP6oROxL0bz6lD41'
  echo "pi:${pi_pw_hash}" | sudo tee "${boot_mnt}/userconf.txt" >/dev/null
  sudo chroot "${mnt}" usermod -aG docker pi 2>/dev/null || true

  # Chroot Environment Cleanup Execution Block
  sudo rm -f "${mnt}/usr/sbin/policy-rc.d"
  sudo umount "${mnt}/dev/pts" 2>/dev/null || true
  sudo umount "${mnt}/dev"     2>/dev/null || true
  sudo umount "${mnt}/sys"     2>/dev/null || true
  sudo umount "${mnt}/proc"    2>/dev/null || true
  sudo umount "${boot_mnt}"    2>/dev/null || true
  sudo umount "${mnt}"
  sudo losetup -d "${loop}"
  sleep 1

  info "Packing compressed multi-threaded Pi SD Card production artifact..."
  xz --threads=0 -9 -z "${raw}" -c > "${OUTPUT_DIR}/${PI_IMAGE}.xz"
  ok "Pi Flash image finalized: ${OUTPUT_DIR}/${PI_IMAGE}.xz"
}

# ── Dynamic System Mount Safe-cleanup Engine ──────────────────────────────────
cleanup() {
  for mp in "${WORK}/pi/mnt/dev/pts" "${WORK}/pi/mnt/dev" "${WORK}/pi/mnt/sys" "${WORK}/pi/mnt/proc" "${WORK}/pi/mnt/boot/firmware" "${WORK}/pi/mnt/boot" "${WORK}/pi/mnt" "${WORK}/vm/mnt"; do
    sudo umount "${mp}" 2>/dev/null || true
  done
  for nbd in /dev/nbd{0..15}; do sudo qemu-nbd --disconnect "${nbd}" 2>/dev/null || true; done
  while IFS= read -r line; do
    local lo; lo=$(echo "${line}" | awk '{print $1}')
    sudo losetup -d "${lo}" 2>/dev/null || true
  done < <(sudo losetup -l -n -O NAME,BACK-FILE 2>/dev/null | grep "${WORK}" || true)
  rm -rf "${WORK}"
}
trap cleanup EXIT INT TERM

# ── Main Context Execution ────────────────────────────────────────────────────
main() {
  echo -e "\n${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}${BOLD}║    InSpectre Appliance Image Builder  v2.1       ║${NC}"
  echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${NC}\n"
  
  info "Branch  : ${REPO_BRANCH}"
  info "Output  : ${OUTPUT_DIR}"
  
  local desc=""
  $BUILD_CONTAINERS_AMD && desc+="[x64 Containers] "
  $BUILD_CONTAINERS_ARM && desc+="[ARM Containers] "
  $BUILD_VM && desc+="[x64 VM Image] "
  $BUILD_PI && desc+="[Pi SD Card Image] "
  info "Building: ${desc:-Nothing Selected. Exit.}"
  
  if [[ -z "${desc}" ]]; then exit 0; fi

  local start_time=$SECONDS

  check_deps
  clone_repo
  patch_dockerfiles
  build_docker_images
  $BUILD_VM && build_vm_image
  $BUILD_PI && build_pi_image

  local elapsed=$(( SECONDS - start_time ))
  echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}${BOLD}║              Build Complete! 🎉                 ║${NC}"
  echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${NC}\n"
  echo "  Total build execution runtime time: $((elapsed / 60))m $((elapsed % 60))s"
  
  echo -e "\n  Generated Targets:"
  ls -lh "${OUTPUT_DIR}/" 2>/dev/null || true

  if $BUILD_VM; then
    echo -e "\n${BOLD}  VM Launch Instructions (KVM/QEMU):${NC}"
    echo "    qemu-system-x86_64 -m 4096 -smp 4 -accel kvm \\"
    echo "      -drive file=${OUTPUT_DIR}/${VM_IMAGE},format=qcow2,if=virtio \\"
    echo "      -netdev user,id=n,hostfwd=tcp::3000-:3000,hostfwd=tcp::8000-:8000 \\"
    echo "      -device virtio-net-pci,netdev=n -nographic"
  fi
  
  if $BUILD_PI; then
    echo -e "\n${BOLD}  Pi SD Flash Instructions:${NC}"
    echo "    xzcat ${OUTPUT_DIR}/${PI_IMAGE}.xz | sudo dd of=/dev/sdX bs=4M status=progress conv=fsync"
  fi
  echo -e "\n${YELLOW}${BOLD}  Default Appliance System Logins: inspectre / inspectre${NC}\n"
}

main "$@"
