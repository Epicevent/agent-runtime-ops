#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${AGENT_RUNTIME_OPS_DIR:-/opt/agent-runtime-ops}"
STATE_ROOT="${AGENT_RUNTIME_STATE_ROOT:-/srv/openclaw-ops}"
OPS_USER="${AGENT_RUNTIME_OPS_USER:-svcops}"
OPS_GROUP="${AGENT_RUNTIME_OPS_GROUP:-svcops}"
BIN_LINK="${AGENT_RUNTIME_OPS_BIN:-/usr/local/bin/opsctl}"
MANIFEST="${AGENT_RUNTIME_OPS_MANIFEST:-$INSTALL_DIR/.agent-runtime-ops-manifest}"
REPO_URL="${AGENT_RUNTIME_OPS_REPO_URL:-https://github.com/Epicevent/agent-runtime-ops.git}"
REPO_REF="${AGENT_RUNTIME_OPS_REF:-main}"

info() {
  printf '%s\n' "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

repo_root() {
  local dir
  dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P || true)"
  if [[ -n "$dir" && -f "$dir/pyproject.toml" && -d "$dir/profiles/runtime" ]]; then
    printf '%s\n' "$dir"
    return 0
  fi
  return 1
}

require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "run as root/admin; svcops runs opsctl after install"
}

ensure_base_packages() {
  local packages=()
  command -v git >/dev/null || packages+=(git)
  command -v rsync >/dev/null || packages+=(rsync)
  command -v python3 >/dev/null || packages+=(python3)
  command -v runuser >/dev/null || packages+=(util-linux)
  command -v mktemp >/dev/null || packages+=(coreutils)

  if command -v python3 >/dev/null && command -v mktemp >/dev/null; then
    local tmp
    tmp="$(mktemp -d)"
    if ! python3 -m venv "$tmp/venv" >/dev/null 2>&1; then
      packages+=(python3-venv)
    fi
    rm -rf "$tmp"
  else
    packages+=(python3-venv)
  fi

  if [[ "${#packages[@]}" -eq 0 ]]; then
    return 0
  fi
  command -v apt-get >/dev/null || die "missing required packages and apt-get is unavailable: ${packages[*]}"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update >/dev/null
  apt-get install -y "${packages[@]}"
}

require_ops_account() {
  getent passwd "$OPS_USER" >/dev/null || die "missing ops user: $OPS_USER; create the operating account first"
  getent group "$OPS_GROUP" >/dev/null || die "missing ops group: $OPS_GROUP; create the operating account first"
}

require_commands() {
  command -v python3 >/dev/null || die "missing command: python3"
  command -v rsync >/dev/null || die "missing command: rsync"
  command -v runuser >/dev/null || die "missing command: runuser"
}

bootstrap_from_git() {
  require_root
  ensure_base_packages
  require_ops_account
  require_commands
  command -v mktemp >/dev/null || die "missing command: mktemp"

  local tmp repo
  tmp="$(mktemp -d)"
  repo="$tmp/agent-runtime-ops"
  info "bootstrap_repo=$REPO_URL"
  info "bootstrap_ref=$REPO_REF"
  git clone --depth 1 --branch "$REPO_REF" "$REPO_URL" "$repo" >/dev/null 2>&1 || {
    git clone "$REPO_URL" "$repo" >/dev/null
    git -C "$repo" checkout "$REPO_REF" >/dev/null
  }
  exec bash "$repo/install.sh" install
}

source_commit() {
  local src="$1"
  if git -C "$src" rev-parse --verify HEAD >/dev/null 2>&1; then
    git -C "$src" rev-parse HEAD
  else
    printf 'unknown\n'
  fi
}

write_manifest() {
  local src="$1"
  local tmp
  tmp="$(mktemp)"
  {
    printf 'source_commit=%s\n' "$(source_commit "$src")"
    printf 'installed_at=%s\n' "$(date -Iseconds)"
    printf 'installed_dir=%s\n' "$INSTALL_DIR"
    printf 'ops_user=%s\n' "$OPS_USER"
    printf 'ops_group=%s\n' "$OPS_GROUP"
    printf 'state_root=%s\n' "$STATE_ROOT"
    printf 'opsctl=%s\n' "$BIN_LINK"
  } >"$tmp"
  install -o root -g "$OPS_GROUP" -m 0644 "$tmp" "$MANIFEST"
  rm -f "$tmp"
}

copy_tree() {
  local src="$1"
  local dst="$2"
  install -d -o root -g "$OPS_GROUP" -m 0755 "$dst"
  rsync -a --delete \
    --exclude '.git' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    "$src"/ "$dst"/
  chown -R root:"$OPS_GROUP" "$dst"
  find "$dst" -type d -exec chmod 0755 {} +
  find "$dst" -type f -exec chmod 0644 {} +
  chmod 0755 "$dst/install.sh"
}

install_package() {
  local src
  if ! src="$(repo_root)"; then
    bootstrap_from_git
  fi

  require_root
  ensure_base_packages
  require_ops_account
  require_commands

  if [[ "$(realpath "$src")" == "$(realpath "$INSTALL_DIR" 2>/dev/null || printf '%s' "$INSTALL_DIR")" ]]; then
    info "copy_tree=skipped_same_source_and_destination"
  else
    copy_tree "$src" "$INSTALL_DIR"
  fi

  python3 -m venv "$INSTALL_DIR/.venv"
  "$INSTALL_DIR/.venv/bin/pip" install --upgrade pip >/dev/null
  "$INSTALL_DIR/.venv/bin/pip" install "$INSTALL_DIR" >/dev/null

  ln -sfn "$INSTALL_DIR/.venv/bin/opsctl" "$BIN_LINK"
  chown -h root:"$OPS_GROUP" "$BIN_LINK" 2>/dev/null || true

  if [[ -d "$STATE_ROOT" ]]; then
    chgrp "$OPS_GROUP" "$STATE_ROOT" 2>/dev/null || true
    chmod 0750 "$STATE_ROOT" 2>/dev/null || true
  fi

  write_manifest "$src"

  info "installed_dir=$INSTALL_DIR"
  info "manifest=$MANIFEST"
  info "ops_user=$OPS_USER"
  info "ops_group=$OPS_GROUP"
  info "opsctl=$BIN_LINK"
  info "state_root=$STATE_ROOT"
}

state_file_status() {
  local name="$1"
  local path="$STATE_ROOT/$name"
  if [[ ! -e "$path" ]]; then
    info "state_file_${name}=missing"
    return 1
  fi
  if runuser -u "$OPS_USER" -- test -r "$path"; then
    info "state_file_${name}=readable_by_${OPS_USER}"
    return 0
  fi
  info "state_file_${name}=not_readable_by_${OPS_USER}"
  return 1
}

check_install() {
  require_ops_account
  command -v runuser >/dev/null || die "missing command: runuser"
  [[ -x "$BIN_LINK" ]] || die "opsctl is not executable: $BIN_LINK"
  [[ -d "$INSTALL_DIR" ]] || die "missing install dir: $INSTALL_DIR"
  [[ -d "$STATE_ROOT" ]] || die "missing state root: $STATE_ROOT"
  [[ -r "$MANIFEST" ]] || die "missing manifest: $MANIFEST"

  info "ops_user=present"
  info "ops_group=present"
  info "install_dir=present"
  info "state_root=present"
  info "manifest=present"
  runuser -u "$OPS_USER" -- "$BIN_LINK" profile list

  local missing=0
  for name in slots.yaml lanes.yaml releases.yaml nas-policy.yaml; do
    state_file_status "$name" || missing=1
  done
  if [[ "$missing" -eq 0 ]]; then
    info "private_state_ready=yes"
  else
    info "private_state_ready=no"
    info "next_action=create_or_fix_/srv/openclaw-ops/lanes.yaml_and_releases.yaml"
  fi
}

case "${1:-install}" in
  install)
    install_package
    ;;
  --check|check)
    check_install
    ;;
  *)
    die "usage: sudo bash install.sh [install|--check]"
    ;;
esac
