#!/usr/bin/env bash
set -euo pipefail

INSTALL_ROOT="${AGENT_RUNTIME_OPS_DIR:-/opt/agent-runtime-ops}"
RELEASES_DIR="$INSTALL_ROOT/releases"
RELEASE_HISTORY_DIR="${AGENT_RUNTIME_OPS_RELEASE_HISTORY_DIR:-$INSTALL_ROOT/release-history}"
CURRENT_LINK="$INSTALL_ROOT/current"
STATE_ROOT="${AGENT_RUNTIME_STATE_ROOT:-/srv/openclaw-ops}"
OPS_USER="${AGENT_RUNTIME_OPS_USER:-svcops}"
OPS_GROUP="${AGENT_RUNTIME_OPS_GROUP:-svcops}"
# Developer accounts that may self-deploy to their OWN dev-* slots (space-separated).
# They get a least-privilege sudoers grant (image-dev-apply / image-canary only); opsctl
# further refuses any non-dev-* target for these accounts. Inert if the account is absent.
DEV_USERS="${AGENT_RUNTIME_DEV_USERS:-openclawdev}"
OPS_HOME="${AGENT_RUNTIME_OPS_HOME:-/home/$OPS_USER}"
CODEX_HOME="${AGENT_RUNTIME_CODEX_HOME:-$OPS_HOME/.codex}"
CODEX_SKILL_NAME="agent-runtime-ops"
CODEX_SKILL_DIR="$CODEX_HOME/skills/$CODEX_SKILL_NAME"
CODEX_AGENTS_LINK="${AGENT_RUNTIME_CODEX_AGENTS:-$CODEX_HOME/AGENTS.md}"
GEMINI_HOME="${AGENT_RUNTIME_GEMINI_HOME:-$OPS_HOME/.gemini}"
GEMINI_AGENTS_LINK="${AGENT_RUNTIME_GEMINI_AGENTS:-$GEMINI_HOME/GEMINI.md}"
OPS_HOME_AGENTS_LINK="${AGENT_RUNTIME_OPS_HOME_AGENTS:-$OPS_HOME/AGENTS.md}"
BIN_LINK="${AGENT_RUNTIME_OPS_BIN:-/usr/local/bin/opsctl}"
MCP_BIN_LINK="${AGENT_RUNTIME_OPS_MCP_BIN:-/usr/local/bin/agent-runtime-ops-mcp}"
GEMINI_BIN_LINK="${AGENT_RUNTIME_GEMINI_BIN:-/usr/local/bin/gemini}"
MANIFEST="${AGENT_RUNTIME_OPS_MANIFEST:-$INSTALL_ROOT/.agent-runtime-ops-manifest}"
REPO_URL="${AGENT_RUNTIME_OPS_REPO_URL:-https://github.com/Epicevent/agent-runtime-ops.git}"
REPO_REF="${AGENT_RUNTIME_OPS_REF:-}"
SUDOERS_FILE="${AGENT_RUNTIME_OPS_SUDOERS_FILE:-/etc/sudoers.d/agent-runtime-ops}"
BOOT_RESTORE_UNIT_FILE="${AGENT_RUNTIME_OPS_BOOT_UNIT_FILE:-/etc/systemd/system/agent-runtime-nas-restore.service}"
USAGE_COLLECT_SERVICE_FILE="${AGENT_RUNTIME_USAGE_SERVICE_FILE:-/etc/systemd/system/agent-runtime-usage-collect.service}"
USAGE_COLLECT_TIMER_FILE="${AGENT_RUNTIME_USAGE_TIMER_FILE:-/etc/systemd/system/agent-runtime-usage-collect.timer}"
USAGE_COST_SERVICE_FILE="${AGENT_RUNTIME_USAGE_COST_SERVICE_FILE:-/etc/systemd/system/agent-runtime-usage-cost-estimate.service}"
USAGE_COST_TIMER_FILE="${AGENT_RUNTIME_USAGE_COST_TIMER_FILE:-/etc/systemd/system/agent-runtime-usage-cost-estimate.timer}"
USAGE_FX_SERVICE_FILE="${AGENT_RUNTIME_USAGE_FX_SERVICE_FILE:-/etc/systemd/system/agent-runtime-usage-fx-refresh.service}"
USAGE_FX_TIMER_FILE="${AGENT_RUNTIME_USAGE_FX_TIMER_FILE:-/etc/systemd/system/agent-runtime-usage-fx-refresh.timer}"
ROOT_ACTION_STATE_ROOT="/var/lib/agent-runtime-ops/root-actions"
ROOT_ACTION_PRIVATE_ROOT="$ROOT_ACTION_STATE_ROOT/private"
ROOT_ACTION_PUBLIC_ROOT="$ROOT_ACTION_STATE_ROOT/public"
ROOT_ACTION_RUNTIME_ROOT="/run/agent-runtime-ops"
ROOT_ACTION_BROKER_SERVICE_FILE="/etc/systemd/system/agent-runtime-root-action-broker.service"
ROOT_ACTION_TRUSTED_ACCOUNT="svcops"
ROOT_ACTION_POST_RESTART_ATTESTATION_ATTEMPTS=40
ROOT_ACTION_POST_RESTART_ATTESTATION_INTERVAL_SECONDS=0.25
ROOT_ACTION_MUTATION_COMMAND_TIMEOUT_SECONDS=30
ROOT_ACTION_POST_RESTART_COMMAND_TIMEOUT_SECONDS=1
OPS_CLI_ATTESTATION_COMMAND_TIMEOUT_SECONDS=10
USAGE_DB_DEFAULTS_FILE="${AGENT_RUNTIME_USAGE_DB_DEFAULTS_FILE:-/etc/agent-runtime-ops/usage-writer.cnf}"
USAGE_PRICING_DIR="${AGENT_RUNTIME_USAGE_PRICING_DIR:-$STATE_ROOT/usage-pricing}"
USAGE_PRICING_FILE="${AGENT_RUNTIME_USAGE_PRICING_FILE:-$USAGE_PRICING_DIR/current.json}"
USAGE_FX_FILE="${AGENT_RUNTIME_USAGE_FX_FILE:-$USAGE_PRICING_DIR/fx-daily.json}"
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
  [[ -x /usr/bin/timeout ]] || die "missing executable: /usr/bin/timeout"
  command -v node >/dev/null || die "missing command: node"
  command -v npm >/dev/null || die "missing command: npm"
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

source_summary() {
  local src="$1"
  if git -C "$src" rev-parse --verify HEAD >/dev/null 2>&1; then
    git -C "$src" log -1 --format=%s HEAD | tr '\r\n' ' '
  else
    printf 'unknown\n'
  fi
}

manifest_value() {
  local manifest="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$manifest"
}

write_manifest() {
  local release_dir="$1"
  local src="$2"
  local commit="$3"
  local summary="$4"
  local tmp="$release_dir/.agent-runtime-ops-manifest.tmp"
  {
    printf 'source_commit=%s\n' "$commit"
    printf 'source_summary=%s\n' "$summary"
    printf 'installed_at=%s\n' "$(date -Iseconds)"
    printf 'installed_dir=%s\n' "$release_dir"
    printf 'install_root=%s\n' "$INSTALL_ROOT"
    printf 'ops_user=%s\n' "$OPS_USER"
    printf 'ops_group=%s\n' "$OPS_GROUP"
    printf 'state_root=%s\n' "$STATE_ROOT"
    printf 'opsctl=%s\n' "$BIN_LINK"
    printf 'mcp=%s\n' "$MCP_BIN_LINK"
    printf 'source_path=%s\n' "$src"
  } >"$tmp"
  install -o root -g "$OPS_GROUP" -m 0644 "$tmp" "$release_dir/.agent-runtime-ops-manifest"
  rm -f "$tmp"
}

write_release_history_entry() {
  local release_dir="$1"
  local release_name manifest history tmp commit summary installed_at
  release_name="$(basename "$release_dir")"
  manifest="$release_dir/.agent-runtime-ops-manifest"
  [[ -r "$manifest" ]] || return 0

  [[ ! -L "$RELEASE_HISTORY_DIR" ]] || die "release history dir must not be a symlink: $RELEASE_HISTORY_DIR"
  install -d -o root -g "$OPS_GROUP" -m 0755 "$RELEASE_HISTORY_DIR"
  history="$RELEASE_HISTORY_DIR/$release_name.txt"
  tmp="$RELEASE_HISTORY_DIR/.$release_name.tmp"
  commit="$(manifest_value "$manifest" source_commit)"
  summary="$(manifest_value "$manifest" source_summary)"
  installed_at="$(manifest_value "$manifest" installed_at)"
  [[ -n "$commit" ]] || commit="${release_name%%.*}"
  [[ -n "$summary" ]] || summary="unknown"
  [[ -n "$installed_at" ]] || installed_at="unknown"
  {
    printf 'release=%s\n' "$release_name"
    printf 'source_commit=%s\n' "$commit"
    printf 'source_summary=%s\n' "$summary"
    printf 'installed_at=%s\n' "$installed_at"
  } >"$tmp"
  install -o root -g "$OPS_GROUP" -m 0644 "$tmp" "$history"
  rm -f "$tmp"
}

prune_old_release_code() {
  local current_real releases_real release_dir release_name release_real pruned
  [[ -d "$RELEASES_DIR" ]] || return 0
  current_real="$(readlink -f "$CURRENT_LINK" 2>/dev/null || true)"
  releases_real="$(realpath -m "$RELEASES_DIR")"
  pruned=0

  for release_dir in "$RELEASES_DIR"/*; do
    [[ -e "$release_dir" ]] || continue
    [[ -d "$release_dir" && ! -L "$release_dir" ]] || continue
    release_name="$(basename "$release_dir")"
    [[ "$release_name" == .* ]] && continue
    release_real="$(realpath -m "$release_dir")"
    [[ -n "$current_real" && "$release_real" == "$current_real" ]] && continue
    [[ "$release_real" == "$releases_real"/* ]] || die "refusing to prune release outside releases dir: $release_dir"
    write_release_history_entry "$release_dir"
    rm -rf --one-file-system "$release_dir"
    pruned=$((pruned + 1))
  done

  info "release_history=$RELEASE_HISTORY_DIR"
  info "old_release_code_pruned=$pruned"
}

copy_tree() {
  local src="$1"
  local dst="$2"
  install -d -o root -g "$OPS_GROUP" -m 0755 "$dst"
  rsync -a --delete \
    --exclude '.git' \
    --exclude '.venv' \
    --exclude 'node_modules' \
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

root_action_broker_release_attested() {
  local service_name="$1"
  local release_dir="$2"
  local main_pid
  /usr/bin/timeout --kill-after=1 "$ROOT_ACTION_POST_RESTART_COMMAND_TIMEOUT_SECONDS" \
    systemctl is-active --quiet "$service_name" || return 1
  main_pid="$(
    /usr/bin/timeout --kill-after=1 "$ROOT_ACTION_POST_RESTART_COMMAND_TIMEOUT_SECONDS" \
      systemctl show --property=MainPID --value "$service_name"
  )" \
    || return 1
  [[ "$main_pid" =~ ^[1-9][0-9]{0,9}$ ]] || return 1
  /usr/bin/timeout --kill-after=1 "$ROOT_ACTION_POST_RESTART_COMMAND_TIMEOUT_SECONDS" \
    grep -Fzqx "AGENT_RUNTIME_OPS_RELEASE=$release_dir" "/proc/$main_pid/environ" \
    || return 1
}

root_action_broker_inactive_attested() {
  local service_name="$1"
  local active_check_rc
  if /usr/bin/timeout --kill-after=1 "$ROOT_ACTION_POST_RESTART_COMMAND_TIMEOUT_SECONDS" \
    systemctl is-active --quiet "$service_name"; then
    return 1
  else
    active_check_rc="$?"
  fi
  [[ "$active_check_rc" -eq 3 ]]
}

root_action_broker_absent_attested() {
  local service_name="$1"
  local active_check_rc
  if /usr/bin/timeout --kill-after=1 "$ROOT_ACTION_POST_RESTART_COMMAND_TIMEOUT_SECONDS" \
    systemctl is-active --quiet "$service_name"; then
    return 1
  else
    active_check_rc="$?"
  fi
  [[ "$active_check_rc" -eq 4 ]]
}

restart_root_action_broker_for_release() {
  local service_name="$1"
  local release_dir="$2"
  /usr/bin/timeout --kill-after=1 "$ROOT_ACTION_MUTATION_COMMAND_TIMEOUT_SECONDS" \
    systemctl restart "$service_name" >/dev/null \
    || return 1
  wait_for_root_action_broker_release "$service_name" "$release_dir"
}

wait_for_root_action_broker_release() {
  local service_name="$1"
  local release_dir="$2"
  local attempt
  for ((attempt = 1; attempt <= ROOT_ACTION_POST_RESTART_ATTESTATION_ATTEMPTS; attempt++)); do
    root_action_broker_release_attested "$service_name" "$release_dir" && return 0
    if [[ "$attempt" -lt "$ROOT_ACTION_POST_RESTART_ATTESTATION_ATTEMPTS" ]]; then
      /usr/bin/sleep "$ROOT_ACTION_POST_RESTART_ATTESTATION_INTERVAL_SECONDS"
    fi
  done
  return 1
}

install_root_action_broker_contract() {
  local release_dir="$1"
  local unit_source="$release_dir/systemd/agent-runtime-root-action-broker.service"
  local active_check_rc install_root_real current_path service_name unit_tmp
  [[ -f "$unit_source" && ! -L "$unit_source" ]] || return 1
  # Resolve the trusted reader by its production account name at install time.
  # Numeric IDs are host facts and must never be embedded in the release.
  getent passwd "$ROOT_ACTION_TRUSTED_ACCOUNT" >/dev/null || return 1
  getent group "$ROOT_ACTION_TRUSTED_ACCOUNT" >/dev/null || return 1
  [[ "$(id -gn "$ROOT_ACTION_TRUSTED_ACCOUNT")" == "$ROOT_ACTION_TRUSTED_ACCOUNT" ]] \
    || return 1
  install_root_real="$(realpath -m "$INSTALL_ROOT")" || return 1
  current_path="$install_root_real/current"
  [[ "$current_path" =~ ^/[A-Za-z0-9._/-]+$ ]] || return 1
  install -d -o root -g "$ROOT_ACTION_TRUSTED_ACCOUNT" -m 0750 "$ROOT_ACTION_STATE_ROOT" \
    || return 1
  install -d -o root -g root -m 0700 "$ROOT_ACTION_PRIVATE_ROOT" || return 1
  install -d -o root -g "$ROOT_ACTION_TRUSTED_ACCOUNT" -m 0750 "$ROOT_ACTION_PUBLIC_ROOT" \
    || return 1
  install -d -o root -g "$ROOT_ACTION_TRUSTED_ACCOUNT" -m 0750 "$ROOT_ACTION_RUNTIME_ROOT" \
    || return 1
  unit_tmp="$(mktemp)" || return 1
  sed \
    -e "s|@@CURRENT_LINK@@|$current_path|g" \
    -e "s|@@RELEASE_DIR@@|$release_dir|g" \
    "$unit_source" >"$unit_tmp" || { rm -f -- "$unit_tmp"; return 1; }
  ! grep -Eq '@@(CURRENT_LINK|RELEASE_DIR)@@' "$unit_tmp" \
    || { rm -f -- "$unit_tmp"; return 1; }
  install -o root -g root -m 0644 "$unit_tmp" "$ROOT_ACTION_BROKER_SERVICE_FILE" \
    || { rm -f -- "$unit_tmp"; return 1; }
  rm -f -- "$unit_tmp" || return 1
  if command -v systemctl >/dev/null 2>&1; then
    [[ -x /usr/bin/timeout ]] || return 1
    /usr/bin/timeout --kill-after=1 "$ROOT_ACTION_MUTATION_COMMAND_TIMEOUT_SECONDS" \
      systemctl daemon-reload >/dev/null \
      || return 1
    service_name="$(basename "$ROOT_ACTION_BROKER_SERVICE_FILE")" || return 1
    if /usr/bin/timeout --kill-after=1 "$ROOT_ACTION_POST_RESTART_COMMAND_TIMEOUT_SECONDS" \
      systemctl is-active --quiet "$service_name"; then
      /usr/bin/timeout --kill-after=1 "$ROOT_ACTION_MUTATION_COMMAND_TIMEOUT_SECONDS" \
        systemctl restart "$service_name" >/dev/null \
        || return 1
      wait_for_root_action_broker_release "$service_name" "$release_dir" \
        || return 1
      info "root_action_broker_update=active_restarted_release_verified" || return 1
    else
      active_check_rc="$?"
      [[ "$active_check_rc" -eq 3 ]] || return 1
    fi
  fi
  # An inactive broker remains a separate ratified activation boundary. An
  # already-active broker must move with self-update so old code can be pruned.
  info "root_action_broker_unit=$ROOT_ACTION_BROKER_SERVICE_FILE" || return 1
  info "root_action_broker_activation=deferred_not_enabled_or_started" || return 1
}

capture_root_action_broker_unit_backup() {
  local backup_dir="$1"
  local backup="$backup_dir/broker-unit"
  local state="$backup_dir/broker-unit-state"
  if [[ ! -e "$ROOT_ACTION_BROKER_SERVICE_FILE" && ! -L "$ROOT_ACTION_BROKER_SERVICE_FILE" ]]; then
    printf 'absent\n' >"$state" || return 1
    chmod 0600 "$state" || return 1
    return 0
  fi
  [[ -f "$ROOT_ACTION_BROKER_SERVICE_FILE" && ! -L "$ROOT_ACTION_BROKER_SERVICE_FILE" ]] \
    || return 1
  [[ "$(stat -c '%a:%h:%u:%g' "$ROOT_ACTION_BROKER_SERVICE_FILE" 2>/dev/null || true)" == "644:1:0:0" ]] \
    || return 1
  install -m 0600 "$ROOT_ACTION_BROKER_SERVICE_FILE" "$backup" || return 1
  cmp -s "$ROOT_ACTION_BROKER_SERVICE_FILE" "$backup" || return 1
  printf 'present\n' >"$state" || return 1
  chmod 0600 "$state" || return 1
}

restore_root_action_broker_unit_backup() {
  local backup_dir="$1"
  local backup="$backup_dir/broker-unit"
  local state_file="$backup_dir/broker-unit-state"
  local state
  [[ -f "$state_file" && ! -L "$state_file" ]] || return 1
  state="$(<"$state_file")"
  case "$state" in
    present)
      [[ -f "$backup" && ! -L "$backup" ]] || return 1
      [[ "$(stat -c '%a:%h:%u' "$backup" 2>/dev/null || true)" == "600:1:$(id -u)" ]] \
        || return 1
      [[ ! -L "$ROOT_ACTION_BROKER_SERVICE_FILE" ]] || return 1
      rm -f -- "$ROOT_ACTION_BROKER_SERVICE_FILE" || return 1
      install -m 0644 "$backup" "$ROOT_ACTION_BROKER_SERVICE_FILE" || return 1
      chown root:root "$ROOT_ACTION_BROKER_SERVICE_FILE" || return 1
      cmp -s "$backup" "$ROOT_ACTION_BROKER_SERVICE_FILE" || return 1
      ;;
    absent)
      rm -f -- "$ROOT_ACTION_BROKER_SERVICE_FILE" || return 1
      [[ ! -e "$ROOT_ACTION_BROKER_SERVICE_FILE" && ! -L "$ROOT_ACTION_BROKER_SERVICE_FILE" ]] \
        || return 1
      ;;
    *) return 1 ;;
  esac
  if command -v systemctl >/dev/null 2>&1; then
    /usr/bin/timeout --kill-after=1 "$ROOT_ACTION_MUTATION_COMMAND_TIMEOUT_SECONDS" \
      systemctl daemon-reload >/dev/null \
      || return 1
  fi
}

install_gemini_cli() {
  local release_dir="$1"
  local package_dir="$release_dir/agent-clis/gemini-cli"
  [[ -f "$package_dir/package-lock.json" ]] || die "missing Gemini CLI package-lock.json"
  (cd "$package_dir" && npm ci --omit=dev --audit=false --fund=false) >/dev/null
  "$package_dir/node_modules/.bin/gemini" --version >/dev/null
  info "gemini_cli=$package_dir"
}

normalize_generated_runtime_tree_permissions() {
  local tree="$1"
  local unexpected
  [[ -d "$tree" && ! -L "$tree" ]] || return 1
  unexpected="$(
    find "$tree" -xdev -mindepth 1 \
      ! -type d ! -type f ! -type l -print -quit
  )" || return 1
  [[ -z "$unexpected" ]] || return 1
  # The installer may be invoked below a restrictive operator umask.  Keep
  # generated code private to root + the operating group, while making the
  # exact svcops command surface independent of that caller state.  find does
  # not follow the intentional Python/npm symlinks in these trees.
  find "$tree" -xdev -type d -exec chmod 0750 {} + || return 1
  find "$tree" -xdev -type f -perm /0111 -exec chmod 0750 {} + || return 1
  find "$tree" -xdev -type f ! -perm /0111 -exec chmod 0640 {} + || return 1
}

install_boot_restore_unit() {
  # Boot-time NAS restore: a one-shot @reboot cron loses the power-cut race
  # (2026-07-07: server booted before the NAS answered; five CIFS mounts
  # failed silently under nofail). This unit orders after network-online and
  # lets `nas view restore` wait for SMB with bounded backoff, remount every
  # fstab CIFS entry, then rebuild the view binds — failing loudly (exit!=0)
  # if anything stays down. Regenerated on every install, like sudoers.
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp" <<UNIT
# agent-runtime-ops managed boot restore (regenerated by install.sh — do not edit)
[Unit]
Description=agent-runtime-ops NAS mounts and slot view restore after boot
Wants=network-online.target
After=network-online.target remote-fs.target

[Service]
Type=oneshot
ExecStart=$BIN_LINK nas view restore --nas-wait-seconds 600
TimeoutStartSec=900

[Install]
WantedBy=multi-user.target
UNIT
  install -o root -g root -m 0644 "$tmp" "$BOOT_RESTORE_UNIT_FILE"
  rm -f "$tmp"
  # No is-system-running gate: a post-outage system reports "degraded"
  # (non-zero) precisely when this unit matters most — always attempt.
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable "$(basename "$BOOT_RESTORE_UNIT_FILE")" >/dev/null 2>&1 || true
  fi
  info "boot_restore_unit=$BOOT_RESTORE_UNIT_FILE"
}

install_usage_collect_timer() {
  # Product ledgers are authoritative and append-only. This timer only moves their
  # content-free receipts into nas_ops; it never creates a missing schema/credential
  # and never advances a cursor after a failed or conflicting page.
  local service_tmp timer_tmp
  service_tmp="$(mktemp)"
  timer_tmp="$(mktemp)"
  cat >"$service_tmp" <<UNIT
# agent-runtime-ops managed usage collector (regenerated by install.sh -- do not edit)
[Unit]
Description=Collect content-free provider usage receipts into nas_ops
After=docker.service network-online.target mysql.service mariadb.service
Wants=network-online.target
ConditionPathExists=$USAGE_DB_DEFAULTS_FILE

[Service]
Type=oneshot
ExecStart=$BIN_LINK usage collect --all --db-defaults-file $USAGE_DB_DEFAULTS_FILE
TimeoutStartSec=1800
Nice=10
UMask=0077
NoNewPrivileges=true
UNIT
  cat >"$timer_tmp" <<UNIT
# agent-runtime-ops managed usage collector timer (regenerated by install.sh -- do not edit)
[Unit]
Description=Run the provider usage collector every three minutes

[Timer]
OnBootSec=3min
OnUnitInactiveSec=3min
AccuracySec=15s
RandomizedDelaySec=15s
Persistent=true
Unit=$(basename "$USAGE_COLLECT_SERVICE_FILE")

[Install]
WantedBy=timers.target
UNIT
  install -o root -g root -m 0644 "$service_tmp" "$USAGE_COLLECT_SERVICE_FILE"
  install -o root -g root -m 0644 "$timer_tmp" "$USAGE_COLLECT_TIMER_FILE"
  rm -f "$service_tmp" "$timer_tmp"
  command -v systemctl >/dev/null 2>&1 || die "missing command: systemctl"
  systemctl daemon-reload >/dev/null
  systemctl enable --now "$(basename "$USAGE_COLLECT_TIMER_FILE")" >/dev/null
  systemctl is-enabled --quiet "$(basename "$USAGE_COLLECT_TIMER_FILE")" \
    || die "usage collector timer is not enabled"
  systemctl is-active --quiet "$(basename "$USAGE_COLLECT_TIMER_FILE")" \
    || die "usage collector timer is not active"
  info "usage_collect_timer=$USAGE_COLLECT_TIMER_FILE"
}

install_usage_pricing_timers() {
  # Pricing remains a human-curated OPS artifact. FX is a daily budgeting
  # reference, not the payment-card conversion rate. Missing either artifact
  # skips cost projection without weakening authoritative usage collection.
  local release_dir seed_catalog cost_service_tmp cost_timer_tmp fx_service_tmp fx_timer_tmp
  release_dir="$1"
  seed_catalog="$release_dir/profiles/usage-pricing/google-gemini-paid-standard-2026-07-27.json"
  cost_service_tmp="$(mktemp)"
  cost_timer_tmp="$(mktemp)"
  fx_service_tmp="$(mktemp)"
  fx_timer_tmp="$(mktemp)"
  install -d -o root -g "$OPS_GROUP" -m 0750 "$USAGE_PRICING_DIR"
  install -d -o root -g "$OPS_GROUP" -m 0750 "$USAGE_PRICING_DIR/evidence"
  [[ -r "$seed_catalog" ]] || die "missing usage pricing seed: $seed_catalog"
  if [[ ! -e "$USAGE_PRICING_FILE" ]]; then
    install -o root -g "$OPS_GROUP" -m 0640 "$seed_catalog" "$USAGE_PRICING_FILE"
  fi
  cat >"$cost_service_tmp" <<UNIT
# agent-runtime-ops managed usage cost projection (regenerated by install.sh)
[Unit]
Description=Project provider usage into auditable USD and reference KRW estimates
After=mysql.service mariadb.service agent-runtime-usage-collect.service
ConditionPathExists=$USAGE_DB_DEFAULTS_FILE
ConditionPathExists=$USAGE_PRICING_FILE
ConditionPathExists=$USAGE_FX_FILE

[Service]
Type=oneshot
ExecStart=$BIN_LINK usage cost-estimate --pricing-file $USAGE_PRICING_FILE --fx-file $USAGE_FX_FILE --db-defaults-file $USAGE_DB_DEFAULTS_FILE
TimeoutStartSec=600
Nice=10
UMask=0077
NoNewPrivileges=true
UNIT
  cat >"$cost_timer_tmp" <<UNIT
# agent-runtime-ops managed usage cost projection timer
[Unit]
Description=Project newly collected usage every three minutes

[Timer]
OnBootSec=5min
OnUnitInactiveSec=3min
AccuracySec=15s
RandomizedDelaySec=15s
Persistent=true
Unit=$(basename "$USAGE_COST_SERVICE_FILE")

[Install]
WantedBy=timers.target
UNIT
  cat >"$fx_service_tmp" <<UNIT
# agent-runtime-ops managed ECB daily reference FX refresh
[Unit]
Description=Refresh auditable ECB USD/KRW daily reference rates
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$BIN_LINK usage fx-refresh --output $USAGE_FX_FILE --evidence-dir $USAGE_PRICING_DIR/evidence
TimeoutStartSec=120
UMask=0077
NoNewPrivileges=true
UNIT
  cat >"$fx_timer_tmp" <<UNIT
# agent-runtime-ops managed ECB daily reference FX timer
[Unit]
Description=Refresh the budgeting reference FX once per KST day

[Timer]
OnBootSec=2min
OnCalendar=*-*-* 01:30:00 Asia/Seoul
RandomizedDelaySec=10min
Persistent=true
Unit=$(basename "$USAGE_FX_SERVICE_FILE")

[Install]
WantedBy=timers.target
UNIT
  install -o root -g root -m 0644 "$cost_service_tmp" "$USAGE_COST_SERVICE_FILE"
  install -o root -g root -m 0644 "$cost_timer_tmp" "$USAGE_COST_TIMER_FILE"
  install -o root -g root -m 0644 "$fx_service_tmp" "$USAGE_FX_SERVICE_FILE"
  install -o root -g root -m 0644 "$fx_timer_tmp" "$USAGE_FX_TIMER_FILE"
  rm -f "$cost_service_tmp" "$cost_timer_tmp" "$fx_service_tmp" "$fx_timer_tmp"
  command -v systemctl >/dev/null || die "missing command: systemctl"
  systemctl daemon-reload >/dev/null
  systemctl enable --now "$(basename "$USAGE_COST_TIMER_FILE")" >/dev/null
  systemctl enable --now "$(basename "$USAGE_FX_TIMER_FILE")" >/dev/null
  systemctl is-active --quiet "$(basename "$USAGE_COST_TIMER_FILE")" \
    || die "usage cost timer is not active"
  systemctl is-active --quiet "$(basename "$USAGE_FX_TIMER_FILE")" \
    || die "usage FX timer is not active"
  info "usage_cost_timer=$USAGE_COST_TIMER_FILE"
  info "usage_fx_timer=$USAGE_FX_TIMER_FILE"
}

install_ops_sudoers() {
  local tmp
  command -v visudo >/dev/null || die "missing command: visudo"
  tmp="$(mktemp)"
  {
    printf 'Defaults:%s env_reset, !setenv, use_pty\n' "$OPS_USER"
    printf '%s ALL=(root) NOPASSWD: %s self-update\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s check --live *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s check * --live\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s check * --live *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s apply *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s rollback *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s diagnostics show *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s diagnostics logs *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s diagnostics session-health *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s binding normalize *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s binding set-public-host *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s apache set-host *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s runtime truth *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s runtime config-status *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s runtime model-catalog *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s runtime model-attest *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s runtime set-model *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s runtime config-sanitize *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s document-tools status *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s recipe apply-dev *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s recipe capture-dev *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s rollout status *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s rollout image-plan *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s rollout image-dev-apply *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s rollout image-canary *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s rollout image-promote *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s rollout verify *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s runtime-secret *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s handoff status *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s handoff value-command *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s handoff print *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s heartbeat status *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s heartbeat disable *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s admin create-image-dev *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s projection *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s checklist pack *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s usage collect *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s usage status *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s usage cost-estimate *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s artifact probe kwrag-product --revision *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s observation status *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s mitigation *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s config validate *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s config migrate *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s nas requests\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s nas mount *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s nas unmount *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s nas remove *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s nas credential status *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s nas credential migrate-to-root *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s nas workspace-assign *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s nas workspace-status\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s nas probe\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s nas approve-auto *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s nas view *\n' "$OPS_USER" "$BIN_LINK"
    printf '%s ALL=(root) NOPASSWD: %s nas legacy *\n' "$OPS_USER" "$BIN_LINK"
    # Developer self-deploy to own dev-* slots: least-privilege (dev-apply / canary only).
    # opsctl refuses any non-dev-* target for these accounts (see _authorize_deploy_target).
    for dev_user in $DEV_USERS; do
      [ -n "$dev_user" ] || continue
      printf 'Defaults:%s env_reset, !setenv, use_pty\n' "$dev_user"
      printf '%s ALL=(root) NOPASSWD: %s rollout image-dev-apply *\n' "$dev_user" "$BIN_LINK"
      printf '%s ALL=(root) NOPASSWD: %s rollout image-canary *\n' "$dev_user" "$BIN_LINK"
      printf '%s ALL=(root) NOPASSWD: %s rollout verify *\n' "$dev_user" "$BIN_LINK"
    done
  } >"$tmp"
  chmod 0440 "$tmp"
  visudo -cf "$tmp" >/dev/null
  install -o root -g root -m 0440 "$tmp" "$SUDOERS_FILE"
  rm -f "$tmp"
  if [[ "$SUDOERS_FILE" != "$LEGACY_SUDOERS_FILE" && -e "$LEGACY_SUDOERS_FILE" ]]; then
    rm -f "$LEGACY_SUDOERS_FILE"
  fi
}

repair_private_state_permissions() {
  [[ -d "$STATE_ROOT" ]] || return 0
  chgrp "$OPS_GROUP" "$STATE_ROOT" 2>/dev/null || true
  chmod 0750 "$STATE_ROOT" 2>/dev/null || true
  local name path
  for name in dev-recipes.yaml nas-policy.yaml runtime-bindings.json ops-update.yaml; do
    path="$STATE_ROOT/$name"
    if [[ -f "$path" && ! -L "$path" ]]; then
      chgrp "$OPS_GROUP" "$path" 2>/dev/null || true
      chmod 0640 "$path" 2>/dev/null || true
    fi
  done
}

seed_runtime_bindings() {
  [[ -d "$STATE_ROOT" ]] || return 0
  if [[ -f "$STATE_ROOT/runtime-bindings.json" ]]; then
    if "$BIN_LINK" --state-root "$STATE_ROOT" binding normalize --write >/dev/null; then
      info "runtime_bindings=normalized"
    else
      info "runtime_bindings=normalize_failed"
    fi
    return 0
  fi
}

migrate_legacy_runtime_backups() {
  local release_dir="$1"
  if [[ ! -f "$STATE_ROOT/runtime-bindings.json" ]]; then
    info "legacy_runtime_backup_migration=skipped reason=runtime_bindings_absent"
    return 0
  fi
  "$release_dir/.venv/bin/python" -m agent_runtime_ops.install_migrations \
    --state-root "$STATE_ROOT"
}

archive_legacy_state_files() {
  [[ -d "$STATE_ROOT" ]] || return 0
  [[ -f "$STATE_ROOT/runtime-bindings.json" ]] || return 0

  local binding_text
  if ! binding_text="$("$BIN_LINK" --state-root "$STATE_ROOT" binding list 2>/dev/null)"; then
    info "legacy_state_archive=skipped reason=binding_list_failed"
    return 0
  fi

  local family status missing
  for family in openclaw hermes; do
    if grep -q "family=$family" <<<"$binding_text"; then
      if ! status="$("$BIN_LINK" --state-root "$STATE_ROOT" rollout status --family "$family" 2>/dev/null)"; then
        info "legacy_state_archive=skipped reason=rollout_status_failed family=$family"
        return 0
      fi
      missing="$(awk -F= '$1=="runtime_manifest_missing_targets"{print $2}' <<<"$status")"
      if [[ -n "$missing" ]]; then
        info "legacy_state_archive=skipped reason=runtime_manifest_missing family=$family targets=$missing"
        return 0
      fi
    fi
  done

  local archive_root archive_dir moved name path
  archive_root="$STATE_ROOT/legacy-state-archive"
  archive_dir="$archive_root/$(date +%Y%m%dT%H%M%S%z)"
  moved=0
  install -d -o root -g "$OPS_GROUP" -m 0750 "$archive_root"
  for path in \
    "$STATE_ROOT"/slots.yaml "$STATE_ROOT"/slots.yaml.* \
    "$STATE_ROOT"/lanes.yaml "$STATE_ROOT"/lanes.yaml.* \
    "$STATE_ROOT"/releases.yaml "$STATE_ROOT"/releases.yaml.* \
    "$STATE_ROOT"/slot-registry.json "$STATE_ROOT"/slot-registry.json.* \
    "$STATE_ROOT"/rollout-state.yaml "$STATE_ROOT"/rollout-state.yaml.* \
    "$STATE_ROOT"/images.yaml "$STATE_ROOT"/images.yaml.*; do
    if [[ -e "$path" || -L "$path" ]]; then
      name="$(basename "$path")"
      if [[ "$moved" -eq 0 ]]; then
        install -d -o root -g "$OPS_GROUP" -m 0750 "$archive_dir"
      fi
      mv "$path" "$archive_dir/$name"
      moved=1
    fi
  done
  if [[ "$moved" -eq 1 ]]; then
    chown -R root:"$OPS_GROUP" "$archive_dir" 2>/dev/null || true
    info "legacy_state_archive=$archive_dir"
  else
    info "legacy_state_archive=none"
  fi
}

cleanup_activation_staging() {
  local failed=0 path
  for path in "$@"; do
    [[ -n "$path" ]] || continue
    rm -f -- "$path" || failed=1
    [[ ! -e "$path" && ! -L "$path" ]] || failed=1
  done
  [[ "$failed" -eq 0 ]]
}

activate_release() {
  local release_dir="$1"
  local release_name bin_tmp="" mcp_tmp="" gemini_tmp=""
  release_name="$(basename "$release_dir")" || return 1
  local next_link="$INSTALL_ROOT/.current.next.$$"
  local manifest_tmp="$INSTALL_ROOT/.manifest.next.$$"
  [[ -d "$release_dir" ]] || return 1
  for path in "$next_link" "$manifest_tmp"; do
    [[ ! -e "$path" && ! -L "$path" ]] || return 1
  done
  bin_tmp="$(mktemp "${BIN_LINK}.next.XXXXXX")" || return 1
  mcp_tmp="$(mktemp "${MCP_BIN_LINK}.next.XXXXXX")" \
    || { cleanup_activation_staging "$bin_tmp"; return 1; }
  gemini_tmp="$(mktemp "${GEMINI_BIN_LINK}.next.XXXXXX")" \
    || { cleanup_activation_staging "$bin_tmp" "$mcp_tmp"; return 1; }
  cat >"$bin_tmp" <<EOF \
    || { cleanup_activation_staging "$bin_tmp" "$mcp_tmp" "$gemini_tmp"; return 1; }
#!/usr/bin/env bash
set -euo pipefail
exec "$CURRENT_LINK/.venv/bin/opsctl" "\$@"
EOF
  chmod 0755 "$bin_tmp" \
    || { cleanup_activation_staging "$bin_tmp" "$mcp_tmp" "$gemini_tmp"; return 1; }
  cat >"$mcp_tmp" <<EOF \
    || { cleanup_activation_staging "$bin_tmp" "$mcp_tmp" "$gemini_tmp"; return 1; }
#!/usr/bin/env bash
set -euo pipefail
exec "$CURRENT_LINK/.venv/bin/agent-runtime-ops-mcp" "\$@"
EOF
  chmod 0755 "$mcp_tmp" \
    || { cleanup_activation_staging "$bin_tmp" "$mcp_tmp" "$gemini_tmp"; return 1; }
  if [[ -e "$GEMINI_BIN_LINK" || -L "$GEMINI_BIN_LINK" ]]; then
    if [[ ! -f "$GEMINI_BIN_LINK" || -L "$GEMINI_BIN_LINK" ]] \
      || ! grep -q 'agent-runtime-ops managed gemini wrapper' "$GEMINI_BIN_LINK" 2>/dev/null; then
      cleanup_activation_staging "$bin_tmp" "$mcp_tmp" "$gemini_tmp" || true
      return 1
    fi
  fi
  cat >"$gemini_tmp" <<EOF \
    || { cleanup_activation_staging "$bin_tmp" "$mcp_tmp" "$gemini_tmp"; return 1; }
#!/usr/bin/env bash
set -euo pipefail
# agent-runtime-ops managed gemini wrapper
OPS_USER="$OPS_USER"
GEMINI_ENV="\${AGENT_RUNTIME_GEMINI_ENV:-$GEMINI_HOME/.env}"
if [[ -r "\$GEMINI_ENV" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "\$GEMINI_ENV"
  set +a
fi
if [[ "\$(id -un 2>/dev/null || true)" == "\$OPS_USER" ]]; then
  export GEMINI_CLI_TRUST_WORKSPACE="\${GEMINI_CLI_TRUST_WORKSPACE:-true}"
  skip_agent_runtime_mcp_default=0
  for arg in "\$@"; do
    case "\$arg" in
      --)
        break
        ;;
      mcp|extensions|extension|skills|skill|hooks|hook|gemma)
        skip_agent_runtime_mcp_default=1
        ;;
    esac
  done
  has_allowed_mcp=0
  for arg in "\$@"; do
    case "\$arg" in
      --allowed-mcp-server-names|--allowed-mcp-server-names=*)
        has_allowed_mcp=1
        ;;
    esac
  done
  if [[ "\$skip_agent_runtime_mcp_default" -eq 0 && "\$has_allowed_mcp" -eq 0 ]]; then
    set -- --allowed-mcp-server-names agent-runtime-ops "\$@"
  fi
fi
exec "$CURRENT_LINK/agent-clis/gemini-cli/node_modules/.bin/gemini" "\$@"
EOF
  chmod 0755 "$gemini_tmp" \
    || { cleanup_activation_staging "$bin_tmp" "$mcp_tmp" "$gemini_tmp"; return 1; }
  chown root:"$OPS_GROUP" "$bin_tmp" "$mcp_tmp" "$gemini_tmp" \
    || { cleanup_activation_staging "$bin_tmp" "$mcp_tmp" "$gemini_tmp"; return 1; }
  ln -s "current/.agent-runtime-ops-manifest" "$manifest_tmp" \
    || { cleanup_activation_staging "$bin_tmp" "$mcp_tmp" "$gemini_tmp" "$manifest_tmp"; return 1; }
  ln -s "releases/$release_name" "$next_link" \
    || { cleanup_activation_staging "$bin_tmp" "$mcp_tmp" "$gemini_tmp" "$manifest_tmp" "$next_link"; return 1; }
  mv -Tf "$bin_tmp" "$BIN_LINK" \
    || { cleanup_activation_staging "$bin_tmp" "$mcp_tmp" "$gemini_tmp" "$manifest_tmp" "$next_link"; return 1; }
  mv -Tf "$mcp_tmp" "$MCP_BIN_LINK" \
    || { cleanup_activation_staging "$bin_tmp" "$mcp_tmp" "$gemini_tmp" "$manifest_tmp" "$next_link"; return 1; }
  mv -Tf "$gemini_tmp" "$GEMINI_BIN_LINK" \
    || { cleanup_activation_staging "$bin_tmp" "$mcp_tmp" "$gemini_tmp" "$manifest_tmp" "$next_link"; return 1; }
  mv -Tf "$manifest_tmp" "$MANIFEST" \
    || { cleanup_activation_staging "$bin_tmp" "$mcp_tmp" "$gemini_tmp" "$manifest_tmp" "$next_link"; return 1; }
  mv -Tf "$next_link" "$CURRENT_LINK" \
    || { cleanup_activation_staging "$bin_tmp" "$mcp_tmp" "$gemini_tmp" "$manifest_tmp" "$next_link"; return 1; }
  chown -h root:"$OPS_GROUP" "$CURRENT_LINK" "$MANIFEST" \
    || { cleanup_activation_staging "$bin_tmp" "$mcp_tmp" "$gemini_tmp" "$manifest_tmp" "$next_link"; return 1; }
  cleanup_activation_staging \
    "$bin_tmp" "$mcp_tmp" "$gemini_tmp" "$manifest_tmp" "$next_link"
}

deactivate_first_release() {
  local release_dir="$1"
  local current_release path
  if [[ -e "$CURRENT_LINK" || -L "$CURRENT_LINK" ]]; then
    [[ -L "$CURRENT_LINK" ]] || return 1
    current_release="$(readlink -f "$CURRENT_LINK" 2>/dev/null || true)"
    [[ "$current_release" == "$release_dir" ]] || return 1
  fi
  if [[ -e "$BIN_LINK" || -L "$BIN_LINK" ]]; then
    [[ -f "$BIN_LINK" && ! -L "$BIN_LINK" ]] || return 1
    grep -Fqx "exec \"$CURRENT_LINK/.venv/bin/opsctl\" \"\$@\"" "$BIN_LINK" \
      || return 1
  fi
  if [[ -e "$MCP_BIN_LINK" || -L "$MCP_BIN_LINK" ]]; then
    [[ -f "$MCP_BIN_LINK" && ! -L "$MCP_BIN_LINK" ]] || return 1
    grep -Fqx "exec \"$CURRENT_LINK/.venv/bin/agent-runtime-ops-mcp\" \"\$@\"" "$MCP_BIN_LINK" \
      || return 1
  fi
  if [[ -e "$GEMINI_BIN_LINK" || -L "$GEMINI_BIN_LINK" ]]; then
    [[ -f "$GEMINI_BIN_LINK" && ! -L "$GEMINI_BIN_LINK" ]] || return 1
    grep -Fq 'agent-runtime-ops managed gemini wrapper' "$GEMINI_BIN_LINK" \
      || return 1
  fi
  if [[ -e "$MANIFEST" || -L "$MANIFEST" ]]; then
    [[ -L "$MANIFEST" ]] || return 1
    [[ "$(readlink "$MANIFEST")" == "current/.agent-runtime-ops-manifest" ]] \
      || return 1
  fi
  for path in "$BIN_LINK" "$MCP_BIN_LINK" "$GEMINI_BIN_LINK" "$MANIFEST" "$CURRENT_LINK"; do
    rm -f -- "$path" || return 1
    [[ ! -e "$path" && ! -L "$path" ]] || return 1
  done
}

capture_previous_activation_identity() {
  local previous_release="$1"
  local backup_dir="$2"
  local gid name source target
  [[ -d "$backup_dir" && ! -L "$backup_dir" ]] || return 1
  [[ "$(stat -c '%a:%h:%u' "$backup_dir" 2>/dev/null || true)" == "700:1:$(id -u)" ]] \
    || return 1
  if [[ -z "$previous_release" ]]; then
    printf 'first_install\n' >"$backup_dir/state" || return 1
    chmod 0600 "$backup_dir/state" || return 1
    return 0
  fi
  gid="$(id -g "$OPS_USER")" || return 1
  for name in opsctl mcp gemini; do
    case "$name" in
      opsctl) source="$BIN_LINK" ;;
      mcp) source="$MCP_BIN_LINK" ;;
      gemini) source="$GEMINI_BIN_LINK" ;;
      *) return 1 ;;
    esac
    [[ -f "$source" && ! -L "$source" ]] || return 1
    [[ "$(stat -c '%a:%h:%u:%g' "$source" 2>/dev/null || true)" == "755:1:0:$gid" ]] \
      || return 1
    target="$backup_dir/$name"
    install -m 0600 "$source" "$target" || return 1
    cmp -s "$source" "$target" || return 1
  done
  [[ -L "$MANIFEST" ]] || return 1
  [[ "$(readlink "$MANIFEST")" == "current/.agent-runtime-ops-manifest" ]] \
    || return 1
  printf 'previous\n' >"$backup_dir/state" || return 1
  printf 'current/.agent-runtime-ops-manifest\n' >"$backup_dir/manifest-target" \
    || return 1
  chmod 0600 "$backup_dir/state" "$backup_dir/manifest-target" || return 1
}

restore_previous_activation_identity() {
  local failed_release="$1"
  local previous_release="$2"
  local backup_dir="$3"
  local backup destination name next_link release_name state target
  [[ -f "$backup_dir/state" && ! -L "$backup_dir/state" ]] || return 1
  state="$(<"$backup_dir/state")"
  if [[ "$state" == "first_install" ]]; then
    [[ -z "$previous_release" ]] || return 1
    deactivate_first_release "$failed_release" || return 1
    return 0
  fi
  [[ "$state" == "previous" && -n "$previous_release" ]] || return 1
  [[ -d "$previous_release" && ! -L "$previous_release" ]] || return 1
  release_name="$(basename "$previous_release")"
  [[ "$previous_release" == "$(realpath -m "$RELEASES_DIR")/$release_name" ]] \
    || return 1
  next_link="$INSTALL_ROOT/.current.restore.$$"
  ln -s "releases/$release_name" "$next_link" || return 1
  mv -Tf "$next_link" "$CURRENT_LINK" || return 1
  for name in opsctl mcp gemini; do
    backup="$backup_dir/$name"
    case "$name" in
      opsctl) destination="$BIN_LINK" ;;
      mcp) destination="$MCP_BIN_LINK" ;;
      gemini) destination="$GEMINI_BIN_LINK" ;;
      *) return 1 ;;
    esac
    [[ -f "$backup" && ! -L "$backup" ]] || return 1
    [[ "$(stat -c '%a:%h:%u' "$backup" 2>/dev/null || true)" == "600:1:$(id -u)" ]] \
      || return 1
    rm -f -- "$destination" || return 1
    install -m 0755 "$backup" "$destination" || return 1
    chown root:"$OPS_GROUP" "$destination" || return 1
    cmp -s "$backup" "$destination" || return 1
  done
  [[ -f "$backup_dir/manifest-target" && ! -L "$backup_dir/manifest-target" ]] \
    || return 1
  target="$(<"$backup_dir/manifest-target")"
  [[ "$target" == "current/.agent-runtime-ops-manifest" ]] || return 1
  rm -f -- "$MANIFEST" || return 1
  ln -s "$target" "$MANIFEST" || return 1
  chown -h root:"$OPS_GROUP" "$CURRENT_LINK" "$MANIFEST" || return 1
  [[ "$(readlink -f "$CURRENT_LINK" 2>/dev/null || true)" == "$previous_release" ]] \
    || return 1
}

cleanup_activation_identity_backup() {
  local backup_dir="$1"
  local path
  [[ -d "$backup_dir" && ! -L "$backup_dir" ]] || return 1
  for path in state manifest-target opsctl mcp gemini broker-unit broker-unit-state; do
    rm -f -- "$backup_dir/$path" || return 1
  done
  rmdir "$backup_dir"
}

install_ops_home_agents() {
  local release_dir="$1"
  local target="$release_dir/ops-home/AGENTS.md"
  local link_target="$CURRENT_LINK/ops-home/AGENTS.md"
  if [[ ! -f "$target" ]]; then
    info "ops_home_agents=missing_source"
    return 0
  fi
  if [[ -L "$OPS_HOME_AGENTS_LINK" ]]; then
    ln -sfn "$link_target" "$OPS_HOME_AGENTS_LINK"
    chown -h "$OPS_USER:$OPS_GROUP" "$OPS_HOME_AGENTS_LINK" 2>/dev/null || true
    info "ops_home_agents=linked"
    return 0
  fi
  if [[ -e "$OPS_HOME_AGENTS_LINK" ]]; then
    info "ops_home_agents=skipped_existing_file path=$OPS_HOME_AGENTS_LINK"
    return 0
  fi
  ln -s "$link_target" "$OPS_HOME_AGENTS_LINK"
  chown -h "$OPS_USER:$OPS_GROUP" "$OPS_HOME_AGENTS_LINK" 2>/dev/null || true
  info "ops_home_agents=linked"
}

install_codex_agents() {
  local release_dir="$1"
  local target="$release_dir/ops-home/AGENTS.md"
  local link_target="$CURRENT_LINK/ops-home/AGENTS.md"
  if [[ ! -f "$target" ]]; then
    info "codex_agents=missing_source"
    return 0
  fi
  if [[ ! -d "$CODEX_HOME" ]]; then
    install -d -o "$OPS_USER" -g "$OPS_GROUP" -m 0700 "$CODEX_HOME"
  fi
  if [[ -L "$CODEX_AGENTS_LINK" ]]; then
    ln -sfn "$link_target" "$CODEX_AGENTS_LINK"
    chown -h "$OPS_USER:$OPS_GROUP" "$CODEX_AGENTS_LINK" 2>/dev/null || true
    info "codex_agents=linked"
    return 0
  fi
  if [[ -e "$CODEX_AGENTS_LINK" ]]; then
    info "codex_agents=skipped_existing_file path=$CODEX_AGENTS_LINK"
    return 0
  fi
  ln -s "$link_target" "$CODEX_AGENTS_LINK"
  chown -h "$OPS_USER:$OPS_GROUP" "$CODEX_AGENTS_LINK" 2>/dev/null || true
  info "codex_agents=linked"
}

install_gemini_agents() {
  local release_dir="$1"
  local target="$release_dir/ops-home/GEMINI.md"
  local link_target="$CURRENT_LINK/ops-home/GEMINI.md"
  if [[ ! -f "$target" ]]; then
    info "gemini_agents=missing_source"
    return 0
  fi
  if [[ ! -d "$GEMINI_HOME" ]]; then
    install -d -o "$OPS_USER" -g "$OPS_GROUP" -m 0700 "$GEMINI_HOME"
  fi
  if [[ -L "$GEMINI_AGENTS_LINK" ]]; then
    ln -sfn "$link_target" "$GEMINI_AGENTS_LINK"
    chown -h "$OPS_USER:$OPS_GROUP" "$GEMINI_AGENTS_LINK" 2>/dev/null || true
    info "gemini_agents=linked"
    return 0
  fi
  if [[ -e "$GEMINI_AGENTS_LINK" ]]; then
    info "gemini_agents=skipped_existing_file path=$GEMINI_AGENTS_LINK"
    return 0
  fi
  ln -s "$link_target" "$GEMINI_AGENTS_LINK"
  chown -h "$OPS_USER:$OPS_GROUP" "$GEMINI_AGENTS_LINK" 2>/dev/null || true
  info "gemini_agents=linked"
}

install_gemini_settings() {
  local settings="$GEMINI_HOME/settings.json"
  if [[ ! -d "$GEMINI_HOME" ]]; then
    install -d -o "$OPS_USER" -g "$OPS_GROUP" -m 0700 "$GEMINI_HOME"
  fi
  python3 - "$settings" "$MCP_BIN_LINK" "$CURRENT_LINK" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
mcp_bin = sys.argv[2]
repo_dir = sys.argv[3]
if path.exists():
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"{path} must contain a JSON object")
else:
    data = {}

context = data.setdefault("context", {})
if not isinstance(context, dict):
    raise SystemExit("context must be a JSON object")
current = context.get("fileName", [])
if isinstance(current, str):
    current = [current]
elif not isinstance(current, list):
    current = []
ordered = []
for item in ["AGENTS.md", "GEMINI.md", *current]:
    if isinstance(item, str) and item not in ordered:
        ordered.append(item)
context["fileName"] = ordered
include_directories = context.get("includeDirectories", [])
if isinstance(include_directories, str):
    include_directories = [include_directories]
elif not isinstance(include_directories, list):
    include_directories = []
included = []
for item in [repo_dir, *include_directories]:
    if isinstance(item, str) and item not in included:
        included.append(item)
context["includeDirectories"] = included

mcp_servers = data.setdefault("mcpServers", {})
if not isinstance(mcp_servers, dict):
    raise SystemExit("mcpServers must be a JSON object")
mcp_servers["agent-runtime-ops"] = {"command": mcp_bin}

path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  chown "$OPS_USER:$OPS_GROUP" "$settings"
  chmod 0600 "$settings"
  info "gemini_settings=$settings"
}

install_codex_skill() {
  local release_dir="$1"
  local src="$release_dir/skills/$CODEX_SKILL_NAME"
  if [[ ! -d "$src" ]]; then
    info "codex_skill=missing_source"
    return 0
  fi
  if [[ ! -d "$CODEX_HOME" ]]; then
    install -d -o "$OPS_USER" -g "$OPS_GROUP" -m 0700 "$CODEX_HOME"
  fi
  if [[ ! -d "$CODEX_HOME/skills" ]]; then
    install -d -o "$OPS_USER" -g "$OPS_GROUP" -m 0700 "$CODEX_HOME/skills"
  fi
  install -d -o "$OPS_USER" -g "$OPS_GROUP" -m 0700 "$CODEX_SKILL_DIR"
  rsync -a --delete "$src"/ "$CODEX_SKILL_DIR"/
  chown -R "$OPS_USER:$OPS_GROUP" "$CODEX_SKILL_DIR"
  find "$CODEX_SKILL_DIR" -type d -exec chmod 0700 {} +
  find "$CODEX_SKILL_DIR" -type f -exec chmod 0600 {} +
  info "codex_skill=$CODEX_SKILL_DIR"
}

run_as_ops() {
  runuser -u "$OPS_USER" -- env HOME="$OPS_HOME" USER="$OPS_USER" LOGNAME="$OPS_USER" CODEX_HOME="$CODEX_HOME" "$@"
}

run_cli_as_ops() {
  local cli="$1"
  shift
  /usr/bin/timeout --kill-after=1 "$OPS_CLI_ATTESTATION_COMMAND_TIMEOUT_SECONDS" \
    runuser -u "$OPS_USER" -- env -i \
      HOME="$OPS_HOME" \
      USER="$OPS_USER" \
      LOGNAME="$OPS_USER" \
      PATH=/usr/local/bin:/usr/bin:/bin \
      "$cli" "$@"
}

validate_update_status_output() {
  local output="$1"
  local expected_ref="$2"
  local require_current="$3"
  local line key value
  local update_status="" installed_ref="" repo_url="" approved_ref="" matches=""
  declare -A seen=()
  while IFS= read -r line; do
    [[ -n "$line" && "$line" == *=* ]] || return 1
    key="${line%%=*}"
    value="${line#*=}"
    [[ -z "${seen[$key]:-}" ]] || return 1
    seen[$key]=1
    case "$key" in
      update_status) update_status="$value" ;;
      installed_ref) installed_ref="$value" ;;
      repo_url) repo_url="$value" ;;
      approved_ref) approved_ref="$value" ;;
      approved_matches_installed) matches="$value" ;;
      *) return 1 ;;
    esac
  done <<<"$output"
  [[ -n "${seen[update_status]:-}" ]] || return 1
  [[ -n "${seen[repo_url]:-}" ]] || return 1
  [[ -n "${seen[approved_ref]:-}" ]] || return 1
  [[ -n "${seen[approved_matches_installed]:-}" ]] || return 1
  [[ "$repo_url" == "$REPO_URL" ]] || return 1
  [[ "$approved_ref" == "$expected_ref" ]] || return 1
  [[ "$installed_ref" =~ ^[0-9a-f]{40}$ || -z "$installed_ref" ]] || return 1
  if [[ "$require_current" == "yes" ]]; then
    [[ "$installed_ref" == "$expected_ref" ]] || return 1
    [[ "$update_status" == "current" && "$matches" == "yes" ]] || return 1
    return 0
  fi
  if [[ "$installed_ref" == "$expected_ref" ]]; then
    [[ "$update_status" == "current" && "$matches" == "yes" ]] || return 1
  else
    [[ "$update_status" == "ready" && "$matches" == "no" ]] || return 1
  fi
}

attest_candidate_cli_as_ops() {
  local release_dir="$1"
  local commit="$2"
  local output
  if [[ -f "$STATE_ROOT/ops-update.yaml" ]]; then
    output="$(
      run_cli_as_ops "$release_dir/.venv/bin/opsctl" \
        --state-root "$STATE_ROOT" update status
    )" || return 1
    validate_update_status_output "$output" "$commit" no || return 1
  else
    /usr/bin/timeout --kill-after=1 "$OPS_CLI_ATTESTATION_COMMAND_TIMEOUT_SECONDS" \
      runuser -u "$OPS_USER" -- env -i \
        HOME="$OPS_HOME" \
        USER="$OPS_USER" \
        LOGNAME="$OPS_USER" \
        PATH=/usr/local/bin:/usr/bin:/bin \
        AGENT_RUNTIME_OPS_DEV=1 \
        AGENT_RUNTIME_OPS_ROOT="$release_dir" \
        "$release_dir/.venv/bin/opsctl" profile list >/dev/null \
      || return 1
  fi
  run_cli_as_ops \
    "$release_dir/agent-clis/gemini-cli/node_modules/.bin/gemini" \
    --version >/dev/null || return 1
}

prepare_release_for_activation() {
  local release_dir="$1"
  local commit="$2"
  if ! normalize_generated_runtime_tree_permissions "$release_dir/.venv" \
    || ! normalize_generated_runtime_tree_permissions \
      "$release_dir/agent-clis/gemini-cli/node_modules" \
    || ! attest_candidate_cli_as_ops "$release_dir" "$commit"; then
    rm -rf --one-file-system "$release_dir"
    die "generated runtime permissions or pre-activation svcops attestation failed"
  fi
  info "ops_cli_pre_activation=svcops_verified"
}

attest_active_cli_as_ops() {
  local release_dir="$1"
  local commit="$2"
  local output
  [[ "$(readlink -f "$CURRENT_LINK" 2>/dev/null || true)" == "$release_dir" ]] \
    || return 1
  if [[ -f "$STATE_ROOT/ops-update.yaml" ]]; then
    output="$(
      run_cli_as_ops "$BIN_LINK" --state-root "$STATE_ROOT" update status
    )" || return 1
    validate_update_status_output "$output" "$commit" yes || return 1
  else
    run_cli_as_ops "$BIN_LINK" profile list >/dev/null || return 1
  fi
}

attest_restored_cli_as_ops() {
  local release_dir="$1"
  local expected_ref="$2"
  local previous_ref output
  [[ "$(readlink -f "$CURRENT_LINK" 2>/dev/null || true)" == "$release_dir" ]] \
    || return 1
  previous_ref="$(manifest_value "$release_dir/.agent-runtime-ops-manifest" source_commit)"
  require_full_sha "$previous_ref"
  if [[ -f "$STATE_ROOT/ops-update.yaml" ]]; then
    output="$(
      run_cli_as_ops "$BIN_LINK" --state-root "$STATE_ROOT" update status
    )" || return 1
    validate_update_status_output "$output" "$expected_ref" no || return 1
    grep -Fqx "installed_ref=$previous_ref" <<<"$output" || return 1
  else
    run_cli_as_ops "$BIN_LINK" profile list >/dev/null || return 1
  fi
  run_cli_as_ops "$GEMINI_BIN_LINK" --version >/dev/null || return 1
  [[ -x "$MCP_BIN_LINK" ]] || return 1
}

capture_previous_active_release() {
  local expected_ref="$1"
  local previous_release releases_real
  if [[ ! -L "$CURRENT_LINK" ]]; then
    [[ ! -e "$CURRENT_LINK" ]] || die "current release path exists but is not a symlink"
    [[ ! -e "$BIN_LINK" && ! -e "$MCP_BIN_LINK" && ! -e "$MANIFEST" ]] \
      || die "first install requires absent managed current wrappers"
    if [[ -e "$GEMINI_BIN_LINK" ]]; then
      grep -q 'agent-runtime-ops managed gemini wrapper' "$GEMINI_BIN_LINK" \
        || die "refusing first install with unmanaged Gemini wrapper"
      die "first install requires absent managed current wrappers"
    fi
    printf '\n'
    return 0
  fi
  previous_release="$(readlink -f "$CURRENT_LINK" 2>/dev/null || true)"
  releases_real="$(realpath -m "$RELEASES_DIR")"
  [[ -n "$previous_release" && "$previous_release" == "$releases_real"/* ]] \
    || die "current release resolves outside the releases directory"
  [[ -d "$previous_release" && ! -L "$previous_release" ]] \
    || die "current release target is not a fixed release directory"
  attest_restored_cli_as_ops "$previous_release" "$expected_ref" \
    || die "previous active svcops CLI identity is not restorable"
  printf '%s\n' "$previous_release"
}

capture_root_action_broker_state() {
  local previous_release="$1"
  local active_check_rc service_name
  if ! command -v systemctl >/dev/null 2>&1; then
    printf 'unavailable\n'
    return 0
  fi
  service_name="$(basename "$ROOT_ACTION_BROKER_SERVICE_FILE")"
  if /usr/bin/timeout --kill-after=1 "$ROOT_ACTION_POST_RESTART_COMMAND_TIMEOUT_SECONDS" \
    systemctl is-active --quiet "$service_name"; then
    [[ -n "$previous_release" ]] \
      || die "active root-action broker has no previous active release"
    root_action_broker_release_attested "$service_name" "$previous_release" \
      || die "previous root-action broker release is not exactly attested"
    printf 'active\n'
    return 0
  else
    active_check_rc="$?"
  fi
  case "$active_check_rc" in
    3) printf 'inactive\n' ;;
    4) printf 'absent\n' ;;
    *) die "root-action broker pre-activation state probe failed" ;;
  esac
}

restore_previous_active_identity() {
  local failed_release="$1"
  local expected_ref="$2"
  local previous_release="$3"
  local broker_state="$4"
  local backup_dir="$5"
  local service_name
  restore_previous_activation_identity \
    "$failed_release" "$previous_release" "$backup_dir" || return 1
  if [[ -n "$previous_release" ]]; then
    attest_restored_cli_as_ops "$previous_release" "$expected_ref" || return 1
  fi
  case "$broker_state" in
    active)
      service_name="$(basename "$ROOT_ACTION_BROKER_SERVICE_FILE")"
      restart_root_action_broker_for_release "$service_name" "$previous_release" \
        || return 1
      ;;
    inactive)
      service_name="$(basename "$ROOT_ACTION_BROKER_SERVICE_FILE")"
      root_action_broker_inactive_attested "$service_name" || return 1
      ;;
    absent)
      service_name="$(basename "$ROOT_ACTION_BROKER_SERVICE_FILE")" || return 1
      root_action_broker_absent_attested "$service_name" || return 1
      ;;
    unavailable) ;;
    *) return 1 ;;
  esac
  info "activation_rollback=previous_identity_restored"
}

activate_and_attest_cli_or_restore() {
  local release_dir="$1"
  local commit="$2"
  local previous_release="$3"
  local broker_state="$4"
  local backup_dir="$5"
  local activation_rc=0
  activate_release "$release_dir" || activation_rc="$?"
  if [[ "$activation_rc" -eq 0 ]]; then
    attest_active_cli_as_ops "$release_dir" "$commit" || activation_rc="$?"
  fi
  if [[ "$activation_rc" -ne 0 ]]; then
    restore_previous_active_identity \
      "$release_dir" "$commit" "$previous_release" "$broker_state" "$backup_dir" \
      || die "post-activation svcops CLI attestation failed and previous identity restoration failed"
    cleanup_activation_identity_backup "$backup_dir" \
      || die "previous active identity restored but activation backup cleanup failed"
    die "post-activation svcops CLI attestation failed; previous active identity restored"
  fi
  info "ops_cli_post_activation=svcops_verified"
}

install_root_action_broker_or_restore() {
  local release_dir="$1"
  local commit="$2"
  local previous_release="$3"
  local broker_state="$4"
  local backup_dir="$5"
  local broker_install_rc=0 identity_restore_rc=0 unit_restore_rc=0
  if ! capture_root_action_broker_unit_backup "$backup_dir"; then
    restore_previous_active_identity \
      "$release_dir" "$commit" "$previous_release" "$broker_state" "$backup_dir" \
      || die "broker unit capture failed and previous identity restoration failed"
    cleanup_activation_identity_backup "$backup_dir" \
      || die "previous active identity restored but activation backup cleanup failed"
    die "broker unit capture failed; previous active identity restored"
  fi
  install_root_action_broker_contract "$release_dir" || broker_install_rc="$?"
  if [[ "$broker_install_rc" -eq 0 ]]; then
    cleanup_activation_identity_backup "$backup_dir" \
      || die "broker installed but activation backup cleanup failed"
    return 0
  fi
  restore_root_action_broker_unit_backup "$backup_dir" || unit_restore_rc="$?"
  restore_previous_active_identity \
    "$release_dir" "$commit" "$previous_release" "$broker_state" "$backup_dir" \
    || identity_restore_rc="$?"
  if [[ "$unit_restore_rc" -ne 0 || "$identity_restore_rc" -ne 0 ]]; then
    die "root-action broker setup failed and previous active identity restoration failed"
  fi
  cleanup_activation_identity_backup "$backup_dir" \
    || die "previous active identity restored but activation backup cleanup failed"
  die "root-action broker setup failed; previous active identity restored"
}

register_codex_mcp() {
  if ! command -v codex >/dev/null 2>&1; then
    info "codex_mcp=codex_missing"
    return 0
  fi
  run_as_ops codex mcp remove "$CODEX_SKILL_NAME" >/dev/null 2>&1 || true
  if run_as_ops codex mcp add "$CODEX_SKILL_NAME" -- "$MCP_BIN_LINK" >/dev/null 2>&1; then
    info "codex_mcp=registered"
  else
    info "codex_mcp=register_failed"
  fi
}

install_package() {
  local src commit summary release_name tmp_release release_dir
  local activation_backup_dir previous_active_release previous_broker_state
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
  summary="$(source_summary "$src")"
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
  if ! install_gemini_cli "$release_dir"; then
    rm -rf "$release_dir"
    die "failed to install Gemini CLI"
  fi
  write_manifest "$release_dir" "$src" "$commit" "$summary"
  chown -R root:"$OPS_GROUP" "$release_dir"
  prepare_release_for_activation "$release_dir" "$commit"

  # Import recovery points with the new release before changing current.  A
  # malformed slot-owned legacy tree aborts the update, while successful
  # copies are durable under STATE_ROOT and remain useful even if activation
  # later fails.
  migrate_legacy_runtime_backups "$release_dir"

  previous_active_release="$(capture_previous_active_release "$commit")"
  previous_broker_state="$(capture_root_action_broker_state "$previous_active_release")"
  activation_backup_dir="$(mktemp -d)" \
    || die "failed to create activation identity backup directory"
  if ! capture_previous_activation_identity \
    "$previous_active_release" "$activation_backup_dir"; then
    cleanup_activation_identity_backup "$activation_backup_dir" || true
    die "failed to capture exact previous activation identity"
  fi
  activate_and_attest_cli_or_restore \
    "$release_dir" "$commit" "$previous_active_release" \
    "$previous_broker_state" "$activation_backup_dir"
  install_root_action_broker_or_restore \
    "$release_dir" "$commit" "$previous_active_release" \
    "$previous_broker_state" "$activation_backup_dir"
  install_ops_sudoers
  install_boot_restore_unit
  install_usage_collect_timer
  install_usage_pricing_timers "$release_dir"
  install_ops_home_agents "$release_dir"
  install_codex_agents "$release_dir"
  install_gemini_agents "$release_dir"
  install_gemini_settings
  install_codex_skill "$release_dir"
  register_codex_mcp

  repair_private_state_permissions
  seed_runtime_bindings
  archive_legacy_state_files
  repair_private_state_permissions
  prune_old_release_code

  info "installed_dir=$release_dir"
  info "current=$CURRENT_LINK"
  info "manifest=$MANIFEST"
  info "ops_user=$OPS_USER"
  info "ops_group=$OPS_GROUP"
  info "opsctl=$BIN_LINK"
  info "mcp=$MCP_BIN_LINK"
  info "gemini=$GEMINI_BIN_LINK"
  info "ops_home_agents=$OPS_HOME_AGENTS_LINK"
  info "codex_agents=$CODEX_AGENTS_LINK"
  info "gemini_agents=$GEMINI_AGENTS_LINK"
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
  [[ -x "$MCP_BIN_LINK" ]] || die "agent-runtime-ops-mcp is not executable: $MCP_BIN_LINK"
  [[ -x "$GEMINI_BIN_LINK" ]] || die "gemini is not executable: $GEMINI_BIN_LINK"
  [[ -d "$INSTALL_ROOT" ]] || die "missing install root: $INSTALL_ROOT"
  [[ -d "$STATE_ROOT" ]] || die "missing state root: $STATE_ROOT"
  [[ -r "$MANIFEST" ]] || die "missing manifest: $MANIFEST"
  [[ -r "$SUDOERS_FILE" ]] || die "missing sudoers file: $SUDOERS_FILE"
  [[ -r "$USAGE_COLLECT_SERVICE_FILE" ]] || die "missing usage collector service: $USAGE_COLLECT_SERVICE_FILE"
  [[ -r "$USAGE_COLLECT_TIMER_FILE" ]] || die "missing usage collector timer: $USAGE_COLLECT_TIMER_FILE"
  [[ -r "$USAGE_COST_TIMER_FILE" ]] || die "missing usage cost timer: $USAGE_COST_TIMER_FILE"
  [[ -r "$USAGE_FX_TIMER_FILE" ]] || die "missing usage FX timer: $USAGE_FX_TIMER_FILE"
  command -v systemctl >/dev/null 2>&1 || die "missing command: systemctl"
  systemctl is-enabled --quiet "$(basename "$USAGE_COLLECT_TIMER_FILE")" \
    || die "usage collector timer is not enabled"
  systemctl is-active --quiet "$(basename "$USAGE_COLLECT_TIMER_FILE")" \
    || die "usage collector timer is not active"
  systemctl is-active --quiet "$(basename "$USAGE_COST_TIMER_FILE")" \
    || die "usage cost timer is not active"
  systemctl is-active --quiet "$(basename "$USAGE_FX_TIMER_FILE")" \
    || die "usage FX timer is not active"

  info "ops_user=present"
  info "ops_group=present"
  info "install_root=present"
  info "current_release=present"
  info "mcp=present"
  info "gemini=present"
  info "state_root=present"
  info "manifest=present"
  info "sudoers=present"
  info "usage_collector_units=present_enabled_active"
  info "usage_cost_units=present_enabled_active"
  info "usage_fx_units=present_enabled_active"
  if [[ -r "$CODEX_SKILL_DIR/SKILL.md" ]]; then
    info "codex_skill=present"
  else
    info "codex_skill=missing"
  fi
  if [[ -L "$OPS_HOME_AGENTS_LINK" && -r "$OPS_HOME_AGENTS_LINK" ]]; then
    info "ops_home_agents=present"
  elif [[ -e "$OPS_HOME_AGENTS_LINK" ]]; then
    info "ops_home_agents=existing_non_symlink"
  else
    info "ops_home_agents=missing"
  fi
  if [[ -L "$CODEX_AGENTS_LINK" && -r "$CODEX_AGENTS_LINK" ]]; then
    info "codex_agents=present"
  elif [[ -e "$CODEX_AGENTS_LINK" ]]; then
    info "codex_agents=existing_non_symlink"
  else
    info "codex_agents=missing"
  fi
  if [[ -L "$GEMINI_AGENTS_LINK" && -r "$GEMINI_AGENTS_LINK" ]]; then
    info "gemini_agents=present"
  elif [[ -e "$GEMINI_AGENTS_LINK" ]]; then
    info "gemini_agents=existing_non_symlink"
  else
    info "gemini_agents=missing"
  fi
  if [[ -r "$GEMINI_HOME/settings.json" ]]; then
    info "gemini_settings=present"
  else
    info "gemini_settings=missing"
  fi
  runuser -u "$OPS_USER" -- bash -lc "cd / && exec '$BIN_LINK' profile list"

  local missing=0
  for name in runtime-bindings.json nas-policy.yaml; do
    state_file_status "$name" || missing=1
  done
  if [[ "$missing" -eq 0 ]]; then
    info "private_state_ready=yes"
  else
    info "private_state_ready=no"
    info "next_action=create_or_fix_/srv/openclaw-ops/runtime-bindings.json_and_nas-policy.yaml"
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
