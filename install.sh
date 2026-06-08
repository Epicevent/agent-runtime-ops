#!/usr/bin/env bash
set -euo pipefail

INSTALL_ROOT="${AGENT_RUNTIME_OPS_DIR:-/opt/agent-runtime-ops}"
RELEASES_DIR="$INSTALL_ROOT/releases"
CURRENT_LINK="$INSTALL_ROOT/current"
STATE_ROOT="${AGENT_RUNTIME_STATE_ROOT:-/srv/openclaw-ops}"
OPS_USER="${AGENT_RUNTIME_OPS_USER:-svcops}"
OPS_GROUP="${AGENT_RUNTIME_OPS_GROUP:-svcops}"
BIN_LINK="${AGENT_RUNTIME_OPS_BIN:-/usr/local/bin/opsctl}"
MANIFEST="${AGENT_RUNTIME_OPS_MANIFEST:-$INSTALL_ROOT/.agent-runtime-ops-manifest}"
REPO_URL="${AGENT_RUNTIME_OPS_REPO_URL:-https://github.com/Epicevent/agent-runtime-ops.git}"
REPO_REF="${AGENT_RUNTIME_OPS_REF:-}"
SUDOERS_FILE="${AGENT_RUNTIME_OPS_SUDOERS_FILE:-/etc/sudoers.d/agent-runtime-ops}"
LEGACY_SUDOERS_FILE="/etc/sudoers.d/agent-runtime-ops-self-update"
LOCK_FILE="${AGENT_RUNTIME_OPS_LOCK_FILE:-/run/lock/agent-runtime-ops.install.lock}"
FULL_SHA_RE='^[0-9a-f]{40}$'

info() {
  printf '%s\n' "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_full_sha() {
  local value="$1"
  [[ "$value" =~ $FULL_SHA_RE ]] || die "AGENT_RUNTIME_OPS_REF must be a full 40-character commit sha"
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

validate_install_root() {
  local resolved
  resolved="$(realpath -m "$INSTALL_ROOT")"
  [[ -n "$resolved" && "$resolved" != "/" ]] || die "unsafe install root: $INSTALL_ROOT"
}

with_install_lock() {
  command -v flock >/dev/null || die "missing command: flock"
  install -d -o root -g root -m 0755 "$(dirname "$LOCK_FILE")"
  exec 9>"$LOCK_FILE"
  flock -n 9 || die "another agent-runtime-ops install is already running"
}

ensure_base_packages() {
  local packages=()
  command -v git >/dev/null || packages+=(git)
  command -v rsync >/dev/null || packages+=(rsync)
  command -v python3 >/dev/null || packages+=(python3)
  command -v runuser >/dev/null || packages+=(util-linux)
  command -v flock >/dev/null || packages+=(util-linux)
  command -v nsenter >/dev/null || packages+=(util-linux)
  command -v findmnt >/dev/null || packages+=(util-linux)
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
  validate_install_root
  require_full_sha "$REPO_REF"
  ensure_base_packages
  require_ops_account
  require_commands

  local tmp repo resolved
  tmp="$(mktemp -d)"
  repo="$tmp/agent-runtime-ops"
  info "bootstrap_repo=$REPO_URL"
  info "bootstrap_ref=$REPO_REF"
  git init "$repo" >/dev/null
  git -C "$repo" remote add origin "$REPO_URL"
  git -C "$repo" fetch --depth 1 origin "$REPO_REF" >/dev/null
  git -C "$repo" checkout --detach FETCH_HEAD >/dev/null
  resolved="$(git -C "$repo" rev-parse HEAD)"
  [[ "$resolved" == "$REPO_REF" ]] || die "checkout mismatch: expected $REPO_REF got $resolved"
  exec env AGENT_RUNTIME_OPS_REF="$resolved" bash "$repo/install.sh" install
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
  local release_dir="$1"
  local src="$2"
  local commit="$3"
  local tmp="$release_dir/.agent-runtime-ops-manifest.tmp"
  {
    printf 'source_commit=%s\n' "$commit"
    printf 'installed_at=%s\n' "$(date -Iseconds)"
    printf 'installed_dir=%s\n' "$release_dir"
    printf 'install_root=%s\n' "$INSTALL_ROOT"
    printf 'ops_user=%s\n' "$OPS_USER"
    printf 'ops_group=%s\n' "$OPS_GROUP"
    printf 'state_root=%s\n' "$STATE_ROOT"
    printf 'opsctl=%s\n' "$BIN_LINK"
    printf 'source_path=%s\n' "$src"
  } >"$tmp"
  install -o root -g "$OPS_GROUP" -m 0644 "$tmp" "$release_dir/.agent-runtime-ops-manifest"
  rm -f "$tmp"
}

copy_tree() {
  local src="$1"
  local dst="$2"
  install -d -o root -g "$OPS_GROUP" -m 0755 "$dst"
  rsync -a --delete \
    --exclude '.git' \
    --exclude '.venv' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    "$src"/ "$dst"/
  chown root:"$OPS_GROUP" "$dst"
  find "$dst" -path "$dst/.venv" -prune -o -type d -exec chown root:"$OPS_GROUP" {} + -exec chmod 0755 {} +
  find "$dst" -path "$dst/.venv" -prune -o -type f -exec chown root:"$OPS_GROUP" {} + -exec chmod 0644 {} +
  chmod 0755 "$dst/install.sh"
}

install_python_env() {
  local release_dir="$1"
  python3 -m venv "$release_dir/.venv"
  "$release_dir/.venv/bin/pip" install \
    --no-cache-dir \
    --only-binary=:all: \
    --require-hashes \
    -r "$release_dir/requirements.lock" >/dev/null
  "$release_dir/.venv/bin/pip" install --no-deps "$release_dir" >/dev/null
  "$release_dir/.venv/bin/opsctl" profile list >/dev/null
}

install_ops_sudoers() {
  local tmp
  command -v visudo >/dev/null || die "missing command: visudo"
  tmp="$(mktemp)"
  {
    printf 'Defaults:%s env_reset, !setenv, use_pty\n' "$OPS_USER"
    printf '%s ALL=(root) NOPASSWD: %s self-update\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s check --live *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s apply *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s rollback *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s nas mount *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s nas unmount *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s nas approve-auto *\n' "$OPS_USER" "$BIN_LINK"
  } >"$tmp"
  chmod 0440 "$tmp"
  visudo -cf "$tmp" >/dev/null
  install -o root -g root -m 0440 "$tmp" "$SUDOERS_FILE"
  rm -f "$tmp"
  if [[ "$SUDOERS_FILE" != "$LEGACY_SUDOERS_FILE" && -e "$LEGACY_SUDOERS_FILE" ]]; then
    rm -f "$LEGACY_SUDOERS_FILE"
  fi
}

activate_release() {
  local release_dir="$1"
  local release_name
  release_name="$(basename "$release_dir")"
  local next_link="$INSTALL_ROOT/.current.next"
  [[ -d "$release_dir" ]] || die "missing release dir: $release_dir"
  ln -sfn "releases/$release_name" "$next_link"
  mv -Tf "$next_link" "$CURRENT_LINK"
  rm -f "$BIN_LINK"
  cat >"$BIN_LINK" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec "$CURRENT_LINK/.venv/bin/opsctl" "\$@"
EOF
  chmod 0755 "$BIN_LINK"
  ln -sfn "current/.agent-runtime-ops-manifest" "$MANIFEST"
  chown root:"$OPS_GROUP" "$BIN_LINK" 2>/dev/null || true
  chown -h root:"$OPS_GROUP" "$CURRENT_LINK" "$MANIFEST" 2>/dev/null || true
}

install_package() {
  local src commit release_name tmp_release release_dir
  if ! src="$(repo_root)"; then
    bootstrap_from_git
  fi

  require_root
  validate_install_root
  ensure_base_packages
  with_install_lock
  require_ops_account
  require_commands

  commit="$(source_commit "$src")"
  require_full_sha "$commit"
  if [[ -n "$REPO_REF" && "$REPO_REF" != "$commit" ]]; then
    die "source commit does not match AGENT_RUNTIME_OPS_REF: $commit != $REPO_REF"
  fi

  install -d -o root -g "$OPS_GROUP" -m 0755 "$INSTALL_ROOT" "$RELEASES_DIR"
  release_name="$commit.$(date +%Y%m%d%H%M%S).$$"
  release_dir="$RELEASES_DIR/$release_name"
  tmp_release="$RELEASES_DIR/.tmp.$release_name"
  rm -rf "$tmp_release"
  copy_tree "$src" "$tmp_release"
  mv "$tmp_release" "$release_dir"
  if ! install_python_env "$release_dir"; then
    rm -rf "$release_dir"
    die "failed to build release python environment"
  fi
  write_manifest "$release_dir" "$src" "$commit"
  chown -R root:"$OPS_GROUP" "$release_dir"

  activate_release "$release_dir"
  install_ops_sudoers

  if [[ -d "$STATE_ROOT" ]]; then
    chgrp "$OPS_GROUP" "$STATE_ROOT" 2>/dev/null || true
    chmod 0750 "$STATE_ROOT" 2>/dev/null || true
  fi

  info "installed_dir=$release_dir"
  info "current=$CURRENT_LINK"
  info "manifest=$MANIFEST"
  info "ops_user=$OPS_USER"
  info "ops_group=$OPS_GROUP"
  info "opsctl=$BIN_LINK"
  info "sudoers=$SUDOERS_FILE"
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
  [[ -L "$CURRENT_LINK" && -d "$CURRENT_LINK" ]] || die "missing current release link: $CURRENT_LINK"
  [[ -x "$BIN_LINK" ]] || die "opsctl is not executable: $BIN_LINK"
  [[ -d "$INSTALL_ROOT" ]] || die "missing install root: $INSTALL_ROOT"
  [[ -d "$STATE_ROOT" ]] || die "missing state root: $STATE_ROOT"
  [[ -r "$MANIFEST" ]] || die "missing manifest: $MANIFEST"
  [[ -r "$SUDOERS_FILE" ]] || die "missing sudoers file: $SUDOERS_FILE"

  info "ops_user=present"
  info "ops_group=present"
  info "install_root=present"
  info "current_release=present"
  info "state_root=present"
  info "manifest=present"
  info "sudoers=present"
  runuser -u "$OPS_USER" -- bash -lc "cd / && exec '$BIN_LINK' profile list"

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
