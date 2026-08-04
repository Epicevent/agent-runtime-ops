#!/usr/bin/env bash
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

RELEASE_ROOT=/opt/agent-runtime-root-action-broker/releases
UNIT_NAME=agent-runtime-root-action-broker-standalone.service
LEGACY_UNIT=agent-runtime-root-action-broker.service
UNIT_PATH=/etc/systemd/system/$UNIT_NAME
ENV_FILE=/etc/agent-runtime-ops/root-action-webauthn.env
SOCKET=/run/agent-runtime-ops/root-action-broker.sock
RECEIPT_ROOT=/var/lib/agent-runtime-ops/install-receipts
TEMPLATE_SHA256=3fbf074e7b9d728f46bbfaa6ef26ff739be126940754ec77d51f2157cbdc275d
REQUIREMENTS_SHA256=4f90ad9fce6b954074a9df32602983641d567d9b2916f75ea6bca41d57fef2b7
SHA256_RE='^[0-9a-f]{64}$'
COMMIT_RE='^[0-9a-f]{40}$'
failure_reason=unexpected_failure
receipt_enabled=0
cutover_started=0
cutover_committed=0
rollback_attempted=0
rollback_verified=0
TREE_SHA256=
PID=0

die() {
    failure_reason=$1
    printf 'error=%s\n' "$1" >&2
    exit 1
}

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die root_required
[[ "$#" -eq 3 ]] || die usage_wheel_wheel_sha_source_commit
WHEEL=$1
WHEEL_SHA256=$2
SOURCE_COMMIT=$3
[[ "$WHEEL_SHA256" =~ $SHA256_RE ]] || die wheel_sha256_invalid
[[ "$SOURCE_COMMIT" =~ $COMMIT_RE ]] || die source_commit_invalid
exec 9>/run/lock/agent-runtime-root-action-broker-standalone.lock
flock -n 9 || die install_lock_busy
[[ "$WHEEL" = /* && -f "$WHEEL" && ! -L "$WHEEL" ]] || die wheel_identity_invalid
[[ "$(stat -c %h "$WHEEL")" == 1 ]] || die wheel_link_count_invalid
[[ "$(stat -c %s "$WHEEL")" -le 20971520 ]] || die wheel_too_large
[[ "$(sha256sum "$WHEEL" | awk '{print $1}')" == "$WHEEL_SHA256" ]] \
    || die wheel_sha256_mismatch
[[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || die webauthn_env_invalid
[[ "$(stat -c '%u/%a/%h' "$ENV_FILE")" == 0/600/1 ]] \
    || die webauthn_env_identity_invalid

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd -P)
TEMPLATE=$SCRIPT_DIR/agent-runtime-root-action-broker-standalone.service
REQUIREMENTS=$SCRIPT_DIR/../requirements.lock
WHEELHOUSE=$SCRIPT_DIR/wheelhouse
[[ -f "$TEMPLATE" && ! -L "$TEMPLATE" ]] || die unit_template_invalid
[[ "$(sha256sum "$TEMPLATE" | awk '{print $1}')" == "$TEMPLATE_SHA256" ]] \
    || die unit_template_sha256_mismatch
[[ -f "$REQUIREMENTS" && ! -L "$REQUIREMENTS" ]] || die requirements_lock_invalid
[[ "$(sha256sum "$REQUIREMENTS" | awk '{print $1}')" == "$REQUIREMENTS_SHA256" ]] \
    || die requirements_lock_sha256_mismatch

install -d -o root -g root -m 0755 "$RELEASE_ROOT"
FINAL=$RELEASE_ROOT/$SOURCE_COMMIT
TMP=$(mktemp -d "$RELEASE_ROOT/.install-$SOURCE_COMMIT.XXXXXX")
UNIT_NEXT=$TMP/$UNIT_NAME
WHEEL_COPY=$TMP/source.whl
TEMPLATE_COPY=$TMP/unit.template
REQUIREMENTS_COPY=$TMP/requirements.lock
PREVIOUS_UNIT=$TMP/previous.service
legacy_was_active=0
legacy_was_enabled=0
unit_preexisted=0

write_receipt() {
    local terminal=$1 reason=$2 standalone_active=false legacy_active=false
    systemctl is-active --quiet "$UNIT_NAME" && standalone_active=true || true
    systemctl is-active --quiet "$LEGACY_UNIT" && legacy_active=true || true
    install -d -o root -g svcops -m 0750 "$RECEIPT_ROOT"
    RECEIPT=$RECEIPT_ROOT/root-action-standalone-$SOURCE_COMMIT.json
    /usr/bin/python3 - \
        "$RECEIPT" "$SOURCE_COMMIT" "$WHEEL_SHA256" "${TREE_SHA256:-}" \
        "${PID:-0}" "$terminal" "$reason" "$standalone_active" "$legacy_active" \
        "$rollback_attempted" "$rollback_verified" <<'PY'
import datetime as dt
import grp
import json
import os
import pathlib
import sys

target = pathlib.Path(sys.argv[1])
commit, wheel, tree, pid, terminal, reason = sys.argv[2:8]
standalone_active, legacy_active, rollback_attempted, rollback_verified = (
    value == "true" or value == "1" for value in sys.argv[8:12]
)
payload = {
    "legacy_broker_active": legacy_active,
    "reason": reason,
    "rollback_attempted": rollback_attempted,
    "rollback_verified": rollback_verified,
    "schema": "root-action-standalone-install/v1",
    "source_commit": commit,
    "standalone_broker_active": standalone_active,
    "standalone_main_pid": int(pid),
    "terminal": terminal,
    "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "tree_sha256": tree or None,
    "wheel_sha256": wheel,
}
raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
tmp = target.with_name(f".{target.name}.next.{os.getpid()}")
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o640)
try:
    remaining = memoryview(raw)
    while remaining:
        written = os.write(fd, remaining)
        if written <= 0:
            raise OSError("short receipt write")
        remaining = remaining[written:]
    os.fsync(fd)
    os.fchown(fd, 0, grp.getgrnam("svcops").gr_gid)
finally:
    os.close(fd)
os.replace(tmp, target)
directory = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

cleanup() {
    local rc=$?
    trap - EXIT
    if [[ "$rc" -ne 0 && "$cutover_started" -eq 1 && "$cutover_committed" -eq 0 ]]; then
        rollback_attempted=1
        systemctl stop "$UNIT_NAME" >/dev/null 2>&1 || true
        systemctl disable "$UNIT_NAME" >/dev/null 2>&1 || true
        if [[ "$unit_preexisted" -eq 1 && -f "$PREVIOUS_UNIT" ]]; then
            install -o root -g root -m 0644 "$PREVIOUS_UNIT" "$UNIT_PATH"
        else
            rm -f -- "$UNIT_PATH"
        fi
        systemctl daemon-reload >/dev/null 2>&1 || true
        if [[ "$legacy_was_enabled" -eq 1 ]]; then
            systemctl enable "$LEGACY_UNIT" >/dev/null 2>&1 || true
        fi
        if [[ "$legacy_was_active" -eq 1 ]]; then
            systemctl start "$LEGACY_UNIT" >/dev/null 2>&1 || true
        fi
        if ! systemctl is-active --quiet "$UNIT_NAME"; then
            legacy_active_now=0
            legacy_enabled_now=0
            systemctl is-active --quiet "$LEGACY_UNIT" && legacy_active_now=1 || true
            systemctl is-enabled --quiet "$LEGACY_UNIT" && legacy_enabled_now=1 || true
            if [[ "$legacy_active_now" -eq "$legacy_was_active" \
                && "$legacy_enabled_now" -eq "$legacy_was_enabled" ]]; then
                rollback_verified=1
            fi
        fi
    fi
    if [[ "$rc" -ne 0 && "$receipt_enabled" -eq 1 ]]; then
        write_receipt failed "$failure_reason" || true
    fi
    case "$TMP" in
        "$RELEASE_ROOT"/.install-"$SOURCE_COMMIT".*) rm -rf --one-file-system -- "$TMP" ;;
    esac
    exit "$rc"
}
trap cleanup EXIT

install -o root -g root -m 0400 "$TEMPLATE" "$TEMPLATE_COPY"
install -o root -g root -m 0400 "$REQUIREMENTS" "$REQUIREMENTS_COPY"
[[ "$(sha256sum "$TEMPLATE_COPY" | awk '{print $1}')" == "$TEMPLATE_SHA256" ]] \
    || die copied_unit_template_sha256_mismatch
[[ "$(sha256sum "$REQUIREMENTS_COPY" | awk '{print $1}')" == "$REQUIREMENTS_SHA256" ]] \
    || die copied_requirements_lock_sha256_mismatch
receipt_enabled=1

[[ -d "$WHEELHOUSE" && ! -L "$WHEELHOUSE" ]] || die wheelhouse_identity_invalid
wheel_count=$(find "$WHEELHOUSE" -xdev -mindepth 1 -maxdepth 1 \
    -type f -name '*.whl' -links 1 -printf . | wc -c) \
    || die wheelhouse_scan_failed
[[ "$wheel_count" -ge 1 && "$wheel_count" -le 64 ]] || die wheelhouse_file_count_invalid
if find "$WHEELHOUSE" -xdev -mindepth 1 -maxdepth 1 \
    ! \( -type f -name '*.whl' -links 1 \) -print -quit | grep -q .; then
    die wheelhouse_entry_invalid
fi
wheelhouse_bytes=$(find "$WHEELHOUSE" -xdev -mindepth 1 -maxdepth 1 \
    -type f -name '*.whl' -links 1 -printf '%s\n' \
    | awk '{total += $1} END {print total + 0}') || die wheelhouse_scan_failed
[[ "$wheelhouse_bytes" -le 67108864 ]] || die wheelhouse_too_large

tree_digest() {
    /usr/bin/python3 - "$1" <<'PY'
import hashlib
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
root_real = root.resolve(strict=True)
digest = hashlib.sha256()
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    rel = path.relative_to(root).as_posix()
    st = path.lstat()
    mode = stat.S_IMODE(st.st_mode)
    if st.st_uid != 0 or st.st_gid != 0:
        raise SystemExit(f"release inode owner mismatch: {rel}")
    if stat.S_ISREG(st.st_mode):
        if st.st_nlink != 1:
            raise SystemExit(f"release file link count mismatch: {rel}")
        kind = "file"
        body = hashlib.sha256(path.read_bytes()).hexdigest()
    elif stat.S_ISDIR(st.st_mode):
        kind = "dir"
        body = ""
    elif stat.S_ISLNK(st.st_mode):
        kind = "symlink"
        body = os.readlink(path)
        try:
            path.resolve(strict=True).relative_to(root_real)
        except (OSError, ValueError) as exc:
            raise SystemExit(f"release symlink escapes tree: {rel}") from exc
    else:
        raise SystemExit(f"unsupported release inode: {rel}")
    row = f"{rel}\0{kind}\0{mode:o}\0{st.st_uid}\0{st.st_gid}\0{st.st_nlink}\0{body}\n"
    digest.update(row.encode("utf-8"))
print(digest.hexdigest())
PY
}

validate_release() {
    local release=$1 expected_wheel=$2 import_path
    [[ -d "$release" && ! -L "$release" ]] || return 1
    [[ "$(<"$release/.source-commit")" == "$SOURCE_COMMIT" ]] || return 1
    [[ "$(<"$release/.source-wheel-sha256")" == "$expected_wheel" ]] || return 1
    [[ -x "$release/.venv/bin/python" ]] || return 1
    import_path=$(
        "$release/.venv/bin/python" -I -B - <<'PY'
from pathlib import Path
import agent_runtime_ops.root_actions.service as service
print(Path(service.__file__).resolve())
PY
    ) || return 1
    [[ "$import_path" == "$release"/.venv/lib/python*/site-packages/agent_runtime_ops/root_actions/service.py ]] \
        || return 1
    find "$release" -xdev \( -type f -o -type d \) -perm /022 -print -quit \
        | grep -q . && return 1
    tree_digest "$release" >/dev/null || return 1
}

if [[ -e "$FINAL" ]]; then
    validate_release "$FINAL" "$WHEEL_SHA256" || die existing_release_invalid
else
    install -o root -g root -m 0400 "$WHEEL" "$WHEEL_COPY"
    [[ "$(sha256sum "$WHEEL_COPY" | awk '{print $1}')" == "$WHEEL_SHA256" ]] \
        || die copied_wheel_sha256_mismatch
    STAGE=$TMP/release
    install -d -o root -g root -m 0755 "$STAGE"
    /usr/bin/python3 -m venv --copies "$STAGE/.venv" || die venv_creation_failed
    "$STAGE/.venv/bin/python" -I -B -m pip install \
        --no-index --only-binary=:all: --find-links "$WHEELHOUSE" \
        --require-hashes -r "$REQUIREMENTS_COPY" >/dev/null \
        || die dependency_install_failed
    "$STAGE/.venv/bin/python" -I -B -m pip install \
        --no-index --no-deps --force-reinstall "$WHEEL_COPY" >/dev/null \
        || die source_wheel_install_failed
    printf '%s\n' "$SOURCE_COMMIT" >"$STAGE/.source-commit" \
        || die source_commit_marker_write_failed
    printf '%s\n' "$WHEEL_SHA256" >"$STAGE/.source-wheel-sha256" \
        || die source_wheel_marker_write_failed
    chown -R root:root "$STAGE" || die staged_release_chown_failed
    chmod -R go-w "$STAGE" || die staged_release_chmod_failed
    validate_release "$STAGE" "$WHEEL_SHA256" || die staged_release_invalid
    mv -- "$STAGE" "$FINAL" || die release_publish_failed
    sync -f "$RELEASE_ROOT" || die release_parent_fsync_failed
fi

TREE_SHA256=$(tree_digest "$FINAL") || die tree_digest_failed
[[ "$TREE_SHA256" =~ $SHA256_RE ]] || die tree_digest_invalid
/usr/bin/python3 - "$TEMPLATE_COPY" "$UNIT_NEXT" "$FINAL" "$SOURCE_COMMIT" "$TREE_SHA256" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
release, commit, tree = sys.argv[3:]
raw = source.read_text(encoding="utf-8")
values = {
    "@@BROKER_RELEASE_DIR@@": release,
    "@@SOURCE_COMMIT@@": commit,
    "@@BROKER_TREE_SHA256@@": f"sha256:{tree}",
}
for marker, value in values.items():
    if raw.count(marker) < 1:
        raise SystemExit(f"unit placeholder missing: {marker}")
    raw = raw.replace(marker, value)
if "@@" in raw:
    raise SystemExit("unit has unresolved placeholder")
target.write_text(raw, encoding="utf-8")
PY
chmod 0644 "$UNIT_NEXT" || die rendered_unit_chmod_failed
chown root:root "$UNIT_NEXT" || die rendered_unit_chown_failed
systemd-analyze verify "$UNIT_NEXT" >/dev/null || die rendered_unit_verify_failed

systemctl is-active --quiet "$LEGACY_UNIT" && legacy_was_active=1 || true
systemctl is-enabled --quiet "$LEGACY_UNIT" && legacy_was_enabled=1 || true
if [[ -e "$UNIT_PATH" ]]; then
    [[ -f "$UNIT_PATH" && ! -L "$UNIT_PATH" ]] || die existing_unit_invalid
    cmp -s "$UNIT_PATH" "$UNIT_NEXT" || die existing_unit_mismatch
    cp --preserve=mode,ownership,timestamps "$UNIT_PATH" "$PREVIOUS_UNIT"
    unit_preexisted=1
fi
install -o root -g root -m 0644 "$UNIT_NEXT" "$UNIT_PATH"
cutover_started=1
systemctl daemon-reload || die daemon_reload_failed
systemctl disable --now "$LEGACY_UNIT" || die legacy_disable_failed
systemctl enable --now "$UNIT_NAME" || die standalone_enable_failed

for _ in $(seq 1 30); do
    systemctl is-active --quiet "$UNIT_NAME" && [[ -S "$SOCKET" ]] && break
    sleep 0.5
done
systemctl is-active --quiet "$UNIT_NAME" || die standalone_broker_not_active
[[ -S "$SOCKET" ]] || die standalone_broker_socket_missing
! systemctl is-active --quiet "$LEGACY_UNIT" || die legacy_broker_still_active
PID=$(systemctl show "$UNIT_NAME" --property=MainPID --value)
[[ "$PID" =~ ^[1-9][0-9]*$ && -r "/proc/$PID/cmdline" ]] || die main_pid_invalid
/usr/bin/python3 - "/proc/$PID" "$FINAL" "$SOURCE_COMMIT" "$TREE_SHA256" <<'PY'
import pathlib
import sys

proc = pathlib.Path(sys.argv[1])
release, commit, tree = sys.argv[2:]
argv = proc.joinpath("cmdline").read_bytes().split(b"\0")[:-1]
expected = [
    f"{release}/.venv/bin/python".encode(), b"-I", b"-B", b"-m",
    b"agent_runtime_ops.root_actions.service",
]
if argv != expected:
    raise SystemExit("standalone broker argv mismatch")
env = set(proc.joinpath("environ").read_bytes().split(b"\0"))
required = {
    f"AGENT_RUNTIME_ROOT_ACTION_RELEASE={release}".encode(),
    f"AGENT_RUNTIME_ROOT_ACTION_SOURCE_COMMIT={commit}".encode(),
    f"AGENT_RUNTIME_ROOT_ACTION_TREE_SHA256=sha256:{tree}".encode(),
}
if not required.issubset(env):
    raise SystemExit("standalone broker environment mismatch")
PY

write_receipt succeeded cutover_attested
cutover_committed=1
printf 'schema=root-action-standalone-install/v1\n'
printf 'source_commit=%s\n' "$SOURCE_COMMIT"
printf 'tree_sha256=%s\n' "$TREE_SHA256"
printf 'standalone_main_pid=%s\n' "$PID"
printf 'receipt=%s\n' "$RECEIPT"
