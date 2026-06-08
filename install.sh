#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${AGENT_RUNTIME_OPS_DIR:-/opt/agent-runtime-ops}"
STATE_ROOT="${AGENT_RUNTIME_STATE_ROOT:-/srv/openclaw-ops}"
OPS_USER="${AGENT_RUNTIME_OPS_USER:-svcops}"
OPS_GROUP="${AGENT_RUNTIME_OPS_GROUP:-svcops}"
BIN_LINK="${AGENT_RUNTIME_OPS_BIN:-/usr/local/bin/opsctl}"

info() {
  printf '%s\n' "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

repo_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")"
  pwd -P
}

require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "run as root"
}

require_ops_account() {
  getent passwd "$OPS_USER" >/dev/null || die "missing ops user: $OPS_USER"
  getent group "$OPS_GROUP" >/dev/null || die "missing ops group: $OPS_GROUP"
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
  src="$(repo_root)"

  require_root
  require_ops_account

  copy_tree "$src" "$INSTALL_DIR"

  python3 -m venv "$INSTALL_DIR/.venv"
  "$INSTALL_DIR/.venv/bin/pip" install --upgrade pip >/dev/null
  "$INSTALL_DIR/.venv/bin/pip" install "$INSTALL_DIR" >/dev/null

  ln -sfn "$INSTALL_DIR/.venv/bin/opsctl" "$BIN_LINK"
  chown -h root:"$OPS_GROUP" "$BIN_LINK" 2>/dev/null || true

  if [[ -d "$STATE_ROOT" ]]; then
    chgrp "$OPS_GROUP" "$STATE_ROOT" 2>/dev/null || true
    chmod 0750 "$STATE_ROOT" 2>/dev/null || true
  fi

  info "installed_dir=$INSTALL_DIR"
  info "ops_user=$OPS_USER"
  info "ops_group=$OPS_GROUP"
  info "opsctl=$BIN_LINK"
  info "state_root=$STATE_ROOT"
}

check_install() {
  require_ops_account
  [[ -x "$BIN_LINK" ]] || die "opsctl is not executable: $BIN_LINK"
  [[ -d "$INSTALL_DIR" ]] || die "missing install dir: $INSTALL_DIR"
  [[ -d "$STATE_ROOT" ]] || die "missing state root: $STATE_ROOT"

  info "ops_user=present"
  info "ops_group=present"
  info "install_dir=present"
  info "state_root=present"
  "$BIN_LINK" profile list
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
