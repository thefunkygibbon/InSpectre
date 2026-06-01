#!/usr/bin/env bash
# =============================================================================
#  InSpectre — Appliance Image Builder  v2.1
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

# ── Defaults ──────────────────────────────────────────────────────────────────
BUILD_VM=true
BUILD_PI=true
REPO_URL="https://github.com/thefunkygibbon/InSpectre.git"
REPO_BRANCH="main"
OUTPUT_DIR="$(pwd)/output"
VM_DISK_SIZE="20G"
VM_IMAGE="inspectre-vm.qcow2"
PI_IMAGE="inspectre-pi.img"
UBUNTU_URL="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
UBUNTU_SHA_URL="${UBUNTU_URL}.sha256sum"
RPI_INDEX="https://downloads.raspberrypi.com/raspios_lite_arm64/images"

WORK="$(mktemp -d /tmp/inspectre-build.XXXXXX)"
REPO="${WORK}/repo"
TAR_AMD="${WORK}/inspectre-amd64.tar"
TAR_ARM="${WORK}/inspectre-arm64.tar"

# ── Args ──────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --vm-only)     BUILD_PI=false ;;
    --pi-only)     BUILD_VM=false ;;
    --branch)      REPO_BRANCH="$2"; shift ;;
    --output-dir)  OUTPUT_DIR="$2"; shift ;;
    --help|-h)     sed -n '2,20p' "$0" | sed 's/^#  \{0,2\}//'; exit 0 ;;
    *)             die "Unknown option: $1" ;;
  esac
  shift
done

# ── Dependency check ──────────────────────────────────────────────────────────
check_deps() {
  step "Checking dependencies"
  local missing=()
  local deps=(docker git curl xz sha256sum parted e2fsck resize2fs losetup qemu-img)
  $BUILD_VM && deps+=(cloud-localds qemu-system-x86_64 qemu-nbd)
  $BUILD_PI && deps+=(chroot)
  for d in "${deps[@]}"; do
    command -v "$d" &>/dev/null && ok "$d" || missing+=("$d")
  done
  [[ ${#missing[@]} -eq 0 ]] || \
    die "Missing tools: ${missing[*]}\n\nInstall:\n  sudo apt-get install -y qemu-system-x86 qemu-system-arm qemu-utils cloud-image-utils git curl xz-utils parted e2fsprogs"

  docker buildx version &>/dev/null || die "docker buildx not available"

  if $BUILD_PI && ! ls /proc/sys/fs/binfmt_misc/ 2>/dev/null | grep -q aarch64; then
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

  python3 - "${probe_df}" <<'PY'
import sys, re
path = sys.argv[1]
with open(path) as f:
    txt = f.read()
txt = re.sub(r'(^FROM python:3\.12-slim\n)', r'\1ARG TARGETARCH=amd64\n', txt, count=1, flags=re.MULTILINE)
txt = txt.replace('nuclei_${NUCLEI_VERSION}_linux_amd64.zip', 'nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip')
txt = txt.replace('nerva-linux-amd64.tar.gz', 'nerva-linux-${TARGETARCH}.tar.gz')
with open(path, 'w') as f:
    f.write(txt)
print("  probe/Dockerfile patched")
PY

  python3 - "${backend_df}" <<'PY'
import sys, re
path = sys.argv[1]
with open(path) as f:
    txt = f.read()
txt = re.sub(r'(^FROM python:3\.12-slim\n)', r'\1ARG TARGETARCH=amd64\n', txt, count=1, flags=re.MULTILINE)
txt = txt.replace(
    '"https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"',
    '"https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-$([ \\"$TARGETARCH\\" = \\"arm64\\" ] && echo ARM64 || echo 64bit).tar.gz"'
)
with open(path, 'w') as f:
    f.write(txt)
print("  backend/Dockerfile patched")
PY

  ok "Dockerfiles patched"
}

# ── Step 3: Build Docker images ───────────────────────────────────────────────
build_docker_images() {
  step "Building Docker images (amd64 + arm64 in parallel)"
  cd "${REPO}"

  local builder="inspectre-builder-$$"
  docker buildx create \
    --name "${builder}" \
    --driver docker-container \
    --buildkitd-flags '--allow-insecure-entitlement network.host' \
    --use >/dev/null
  trap "docker buildx rm ${builder} 2>/dev/null || true" RETURN

  local pids=() logs=() tags=()
  _build_bg() {
    local name="$1" platform="$2" context="$3" tag="$4"
    local log="${WORK}/build-${name}.log"
    logs+=("${log}")
    tags+=("${tag}")
    docker buildx build \
      --builder "${builder}" \
      --platform "${platform}" \
      --tag "${tag}" \
      --load \
      --progress plain \
      "${context}" \
      >"${log}" 2>&1 &
    pids+=($!)
    info "  Started: ${tag}  [pid $!]"
  }

  _build_bg "backend-amd"  "linux/amd64" "./backend"  "inspectre-backend:amd64"
  _build_bg "probe-amd"    "linux/amd64" "./probe"    "inspectre-probe:amd64"
  _build_bg "frontend-amd" "linux/amd64" "./frontend" "inspectre-frontend:amd64"

  if $BUILD_PI; then
    _build_bg "backend-arm"  "linux/arm64" "./backend"  "inspectre-backend:arm64"
    _build_bg "probe-arm"    "linux/arm64" "./probe"    "inspectre-probe:arm64"
    _build_bg "frontend-arm" "linux/arm64" "./frontend" "inspectre-frontend:arm64"
  fi

  local failed=0
  for i in "${!pids[@]}"; do
    if wait "${pids[$i]}"; then
      ok "  ${tags[$i]} done"
    else
      warn "  ${tags[$i]} FAILED — showing tail of log:"
      tail -30 "${logs[$i]}" >&2
      failed=1
    fi
  done
  [[ $failed -eq 0 ]] || die "One or more Docker builds failed — see logs in ${WORK}/"

  info "Pulling postgres:15-alpine (amd64)..."
  docker pull --platform linux/amd64 --quiet postgres:15-alpine
  docker tag postgres:15-alpine inspectre-postgres:amd64

  if $BUILD_PI; then
    info "Pulling postgres:15-alpine (arm64)..."
    docker pull --platform linux/arm64 --quiet postgres:15-alpine
    docker tag postgres:15-alpine inspectre-postgres:arm64
  fi

  info "Exporting amd64 image bundle..."
  docker save inspectre-backend:amd64 inspectre-probe:amd64 inspectre-frontend:amd64 inspectre-postgres:amd64 >"${TAR_AMD}"
  ok "amd64 bundle: $(du -sh "${TAR_AMD}" | cut -f1)"

  if $BUILD_PI; then
    info "Exporting arm64 image bundle..."
    docker save inspectre-backend:arm64 inspectre-probe:arm64 inspectre-frontend:arm64 inspectre-postgres:arm64 >"${TAR_ARM}"
    ok "arm64 bundle: $(du -sh "${TAR_ARM}" | cut -f1)"
  fi

  cd - >/dev/null
}

# ── Helpers: shared file content generators ───────────────────────────────────
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
  echo "[InSpectre] Loading Docker images from bundle..."
  docker load < "$TAR"
  rm -f "$TAR"
  echo "[InSpectre] Images loaded."
fi
cd /opt/inspectre
docker compose up -d
IP=$(hostname -I | awk '{print $1}')
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  InSpectre is running!                           ║"
echo "║  Frontend : http://${IP}:3000                    ║"
echo "║  API      : http://${IP}:8000                    ║"
echo "╚══════════════════════════════════════════════════╝"
STARTUP
}

systemd_unit() {
  cat <<'UNIT'
[Unit]
Description=InSpectre Network Scanner
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/inspectre
ExecStart=/opt/inspectre/start.sh
ExecStop=/usr/bin/docker compose -f /opt/inspectre/docker-compose.yml down
TimeoutStartSec=600

[Install]
WantedBy=multi-user.target
UNIT
}

motd_content() {
  cat <<'MOTD'

╔══════════════════════════════════════════════════════╗
║           InSpectre Network Scanner                  ║
╠══════════════════════════════════════════════════════╣
║  Open in browser : http://<this-ip>:3000             ║
║  API             : http://<this-ip>:8000             ║
║  View logs       : sudo journalctl -u inspectre -f   ║
╚══════════════════════════════════════════════════════╝
MOTD
}

# ── Step 4: VM Image ──────────────────────────────────────────────────────────
build_vm_image() {
  step "Building VM image (x86_64)"
  local vw="${WORK}/vm"
  mkdir -p "${vw}" "${OUTPUT_DIR}"

  info "Downloading Ubuntu 22.04 cloud image..."
  local base="${vw}/ubuntu-base.img"
  curl -L --progress-bar "${UBUNTU_URL}" -o "${base}"
  info "Verifying checksum..."
  local expected; expected=$(curl -sL "${UBUNTU_SHA_URL}" | awk '{print $1}')
  echo "${expected}  ${base}" | sha256sum --check - || die "Ubuntu image checksum mismatch"

  local disk="${vw}/${VM_IMAGE}"
  info "Creating ${VM_DISK_SIZE} qcow2 disk..."
  qemu-img convert -f qcow2 -O qcow2 "${base}" "${disk}"
  qemu-img resize "${disk}" "${VM_DISK_SIZE}"

  info "Generating cloud-init seed..."
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
  - systemctl daemon-reload
USERDATA

  local seed="${vw}/seed.iso"
  cloud-localds "${seed}" "${ci}/user-data" "${ci}/meta-data"

  info "Injecting Docker image bundle into VM disk..."
  sudo modprobe nbd max_part=8 2>/dev/null || true

  local nbd=""
  for dev in /dev/nbd{0..15}; do
    if [[ -b "${dev}" ]] && ! sudo lsblk "${dev}" 2>/dev/null | grep -q "part\|disk.*[0-9]$"; then
      nbd="${dev}"; break
    fi
  done
  [[ -n "${nbd}" ]] || die "No free nbd device found — is the nbd kernel module loaded?"

  sudo qemu-nbd --connect="${nbd}" "${disk}"
  sleep 2
  sudo partprobe "${nbd}" 2>/dev/null || true
  sleep 1

  # NEW LOGIC: Dynamic mapping, growing partition boundaries, and resizing filesystem
  local root_part=""
  local part_num=""
  for part in "${nbd}p1" "${nbd}p2" "${nbd}p3" "${nbd}p4" "${nbd}p5"; do
    if [[ -b "${part}" ]] && sudo blkid "${part}" | grep -q 'ext4'; then
      root_part="${part}"
      part_num="${part#${nbd}p}"
      break
    fi
  done

  if [[ -n "${root_part}" ]]; then
    info "Expanding root partition ${part_num} and filesystem maps to fill allocation..."
    sudo parted -s "${nbd}" resizepart "${part_num}" 100%
    sudo partprobe "${nbd}" 2>/dev/null || true
    sleep 1
    sudo e2fsck -f "${root_part}" -y >/dev/null 2>&1 || true
    sudo resize2fs "${root_part}" >/dev/null 2>&1 || true
  else
    sudo qemu-nbd --disconnect "${nbd}"
    die "Could not locate a recognizable ext4 filesystem map inside the image partition tables."
  fi

  local mnt="${vw}/mnt"
  mkdir -p "${mnt}"
  sudo mount "${root_part}" "${mnt}"

  sudo mkdir -p "${mnt}/opt/inspectre/images"
  info "Copying amd64 bundle ($(du -sh "${TAR_AMD}" | cut -f1)) — please wait..."
  sudo cp "${TAR_AMD}" "${mnt}/opt/inspectre/images/inspectre-images.tar"

  sudo umount "${mnt}"
  sudo qemu-nbd --disconnect "${nbd}"
  sleep 1

  info "Running first-boot provisioning via QEMU (up to 8 min)..."
  timeout 480 qemu-system-x86_64 \
    -name "inspectre-firstboot" \
    -m 2048 -smp 4 \
    -drive "file=${disk},format=qcow2,if=virtio" \
    -drive "file=${seed},format=raw,if=virtio" \
    -nographic \
    -serial mon:stdio \
    -no-reboot \
    -netdev "user,id=net0" \
    -device "virtio-net-pci,netdev=net0" \
    2>&1 | grep --line-buffered -E "cloud-init|inspectre|Reached target|login:|runcmd|WARN|ERROR" \
    || warn "First-boot QEMU exited non-zero (usually fine if cloud-init completed)"

  info "Compressing VM image..."
  qemu-img convert -c -O qcow2 "${disk}" "${OUTPUT_DIR}/${VM_IMAGE}"
  ok "VM image: ${OUTPUT_DIR}/${VM_IMAGE}  ($(du -sh "${OUTPUT_DIR}/${VM_IMAGE}" | cut -f1))"
}

# ── Step 5: Pi Image ──────────────────────────────────────────────────────────
build_pi_image() {
  step "Building Raspberry Pi image (arm64)"
  local pw="${WORK}/pi"
  mkdir -p "${pw}" "${OUTPUT_DIR}"

  info "Finding latest Raspberry Pi OS Lite (64-bit)..."
  local idx; idx=$(curl -sL "${RPI_INDEX}/")
  local latest_dir; latest_dir=$(echo "${idx}" | grep -oP 'raspios_lite_arm64-\d{4}-\d{2}-\d{2}' | sort -r | head -1)
  [[ -n "${latest_dir}" ]] || die "Could not determine latest RPi OS directory"
  local dir_url="${RPI_INDEX}/${latest_dir}/"
  local img_xz; img_xz=$(curl -sL "${dir_url}" | grep -oP '[\w\-]+\.img\.xz' | head -1)

  local xz_path="${pw}/${img_xz}"
  info "Downloading ${img_xz}..."
  curl -L --progress-bar "${dir_url}${img_xz}" -o "${xz_path}"

  info "Decompressing (all CPU threads)..."
  xz --decompress --keep --threads=0 "${xz_path}"
  local raw="${pw}/${img_xz%.xz}"

  info "Expanding image by 10 GB..."
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
  sudo mount "${loop}p1" "${boot_mnt}" 2>/dev/null || warn "Could not mount boot partition"

  info "Pre-installing Docker into Pi chroot..."
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

  ok "Docker installed in chroot"

  info "Injecting Docker image bundle..."
  sudo mkdir -p "${mnt}/opt/inspectre/images"
  sudo cp "${TAR_ARM}" "${mnt}/opt/inspectre/images/inspectre-images.tar"

  compose_content "arm64" | sudo tee "${mnt}/opt/inspectre/docker-compose.yml" >/dev/null
  startup_script | sudo tee "${mnt}/opt/inspectre/start.sh" >/dev/null
  sudo chmod +x "${mnt}/opt/inspectre/start.sh"
  systemd_unit | sudo tee "${mnt}/etc/systemd/system/inspectre.service" >/dev/null
  motd_content | sudo tee "${mnt}/etc/motd" >/dev/null

  sudo mkdir -p "${mnt}/etc/systemd/system/multi-user.target.wants"
  sudo ln -sf /lib/systemd/system/docker.service "${mnt}/etc/systemd/system/multi-user.target.wants/docker.service" 2>/dev/null || true
  sudo ln -sf /etc/systemd/system/inspectre.service "${mnt}/etc/systemd/system/multi-user.target.wants/inspectre.service" 2>/dev/null || true

  sudo touch "${boot_mnt}/ssh" 2>/dev/null || true

  local pi_pw_hash='$6$rounds=4096$inspectre$9T1j/dxZpyW7dB4qoMFlEq4K7kZwxlN.ZF09wRqiNEi9VJ/SRRvxlCkIMVtCnBfHHpOuAQEP6oROxL0bz6lD41'
  echo "pi:${pi_pw_hash}" | sudo tee "${boot_mnt}/userconf.txt" >/dev/null
  sudo chroot "${mnt}" usermod -aG docker pi 2>/dev/null || true

  sudo rm -f "${mnt}/usr/sbin/policy-rc.d"
  sudo umount "${mnt}/dev/pts" 2>/dev/null || true
  sudo umount "${mnt}/dev"     2>/dev/null || true
  sudo umount "${mnt}/sys"     2>/dev/null || true
  sudo umount "${mnt}/proc"    2>/dev/null || true
  sudo umount "${boot_mnt}" 2>/dev/null || true
  sudo umount "${mnt}"
  sudo losetup -d "${loop}"
  sleep 1

  info "Compressing Pi image..."
  xz --threads=0 -9 -z "${raw}" -c >"${OUTPUT_DIR}/${PI_IMAGE}.xz"
  ok "Pi image: ${OUTPUT_DIR}/${PI_IMAGE}.xz  ($(du -sh "${OUTPUT_DIR}/${PI_IMAGE}.xz" | cut -f1))"
}

# ── Cleanup trap ──────────────────────────────────────────────────────────────
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

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  echo ""
  echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}${BOLD}║    InSpectre Appliance Image Builder  v2.1       ║${NC}"
  echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
  echo ""
  info "Branch  : ${REPO_BRANCH}"
  info "Output  : ${OUTPUT_DIR}"
  info "Building: $( $BUILD_VM && $BUILD_PI && echo 'VM + Pi' || ( $BUILD_VM && echo 'VM only' ) || echo 'Pi only' )"
  echo ""

  local start_time=$SECONDS
  check_deps
  clone_repo
  patch_dockerfiles
  build_docker_images
  $BUILD_VM && build_vm_image
  $BUILD_PI && build_pi_image

  local elapsed=$(( SECONDS - start_time ))
  local mins=$(( elapsed / 60 ))
  local secs=$(( elapsed % 60 ))

  echo ""
  echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}${BOLD}║              Build Complete!  🎉                 ║${NC}"
  echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
  echo ""
  echo "  Total build time: ${mins}m ${secs}s"
  echo ""
  ls -lh "${OUTPUT_DIR}/" 2>/dev/null || true
  echo ""
}

main "$@"
