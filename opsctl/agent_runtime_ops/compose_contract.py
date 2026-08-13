from __future__ import annotations

import posixpath
from dataclasses import dataclass
from typing import Any

import yaml

from .yamlio import load_yaml
from .runtime_socket_projection import runtime_group_token, runtime_socket_projection


@dataclass(frozen=True)
class ComposeContractCheck:
    ok: bool
    name: str
    detail: str | None = None


def _labels_as_dict(raw_labels: Any) -> dict[str, str]:
    if isinstance(raw_labels, dict):
        return {str(key): str(value) for key, value in raw_labels.items()}
    if isinstance(raw_labels, list):
        labels: dict[str, str] = {}
        for item in raw_labels:
            if isinstance(item, str) and "=" in item:
                key, value = item.split("=", 1)
                labels[key] = value
        return labels
    return {}


def _volume_target(volume: Any) -> str:
    if isinstance(volume, dict):
        return str(volume.get("target") or "")
    if isinstance(volume, str):
        parts = volume.split(":")
        if len(parts) >= 2:
            return parts[1]
    return ""


def _volume_source(volume: Any) -> str:
    if isinstance(volume, dict):
        return str(volume.get("source") or "")
    if isinstance(volume, str):
        return volume.split(":", 1)[0]
    return ""


def _volume_is_read_only(volume: Any) -> bool:
    if isinstance(volume, dict):
        return volume.get("read_only") is True
    if isinstance(volume, str):
        parts = volume.split(":")
        return any(part == "ro" or part.endswith(",ro") or ",ro," in part for part in parts[2:])
    return False


def _volume_type(volume: Any) -> str:
    if isinstance(volume, dict):
        return str(volume.get("type") or "")
    return "bind" if isinstance(volume, str) else ""


def _volume_propagation(volume: Any) -> str:
    if isinstance(volume, dict):
        bind = volume.get("bind")
        if isinstance(bind, dict):
            return str(bind.get("propagation") or "")
        return ""
    if isinstance(volume, str):
        for part in volume.split(":")[2:]:
            for option in part.split(","):
                if option in {"slave", "rslave", "shared", "rshared", "private"}:
                    return option
    return ""


def _volume_contains_source_output(volume: Any) -> bool:
    return "${SOURCE_OUTPUT}" in str(volume)


def _mount_covers_target(mount_target: str, output_target: str) -> bool:
    """A dev source mount is valid if it maps the host build output into the container AT, or at a
    PARENT of, the recipe's ``source_output_target``.

    Mounting only ``/app/dist/control-ui`` gives a live frontend but a baked server. Mounting the
    whole ``/app/dist`` (a parent that contains ``control-ui``) gives full-stack live dev — server
    (``dist/index.js``) and UI both from source — and still satisfies the contract, so we do not
    have to change the ``source_output_target`` label (which is baked into wrapper images).
    """
    if not mount_target:
        return False
    if mount_target == output_target:
        return True
    return output_target.startswith(mount_target.rstrip("/") + "/")


def _propagation_matches(actual: str, required: str) -> bool:
    if not required:
        return True
    if required in {"slave", "rslave"}:
        return actual in {"slave", "rslave"}
    if required in {"shared", "rshared"}:
        return actual in {"shared", "rshared"}
    return actual == required


def _command_as_list(raw_command: Any) -> list[str] | None:
    if isinstance(raw_command, list):
        return [str(item) for item in raw_command]
    return None


def _env_file_entries(raw_env_file: Any) -> list[str]:
    if isinstance(raw_env_file, str):
        return [raw_env_file]
    if isinstance(raw_env_file, dict):
        path = raw_env_file.get("path")
        return [str(path)] if path else []
    if not isinstance(raw_env_file, list):
        return []
    entries: list[str] = []
    for item in raw_env_file:
        if isinstance(item, str):
            entries.append(item)
        elif isinstance(item, dict) and item.get("path"):
            entries.append(str(item["path"]))
    return entries


def _env_file_matches_secret(entry: str, expected_path: str, slot: str) -> bool:
    if entry == expected_path:
        return True
    if entry.startswith("/"):
        return False
    runtime_dir = f"/home/{slot}/openclaw"
    return posixpath.normpath(posixpath.join(runtime_dir, entry)) == expected_path


def _profile_secret_file_paths(profile: Any, slot: str) -> list[str]:
    contract = load_yaml(profile.path / "env.contract.yaml")
    raw_files = contract.get("secret_files") if isinstance(contract, dict) else None
    if not isinstance(raw_files, list):
        return []
    paths: list[str] = []
    for item in raw_files:
        if isinstance(item, str):
            paths.append(item.format(slot=slot))
    return paths


def _port_targets_container_port(raw_port: Any, container_port: str) -> bool:
    if isinstance(raw_port, dict):
        target = raw_port.get("target")
        return str(target) == container_port
    if not isinstance(raw_port, str):
        return False
    text = raw_port.strip()
    if "/" in text:
        text = text.split("/", 1)[0]
    return text.split(":")[-1] == container_port


def validate_compose_contract(profile: Any, desired: Any, rendered_text: str) -> list[ComposeContractCheck]:
    checks: list[ComposeContractCheck] = []
    try:
        compose = yaml.safe_load(rendered_text)
    except Exception as exc:
        return [ComposeContractCheck(False, "compose_yaml_valid", str(exc))]

    checks.append((ComposeContractCheck(isinstance(compose, dict), "compose_yaml_mapping")))
    if not isinstance(compose, dict):
        return checks

    services = compose.get("services")
    checks.append(ComposeContractCheck(isinstance(services, dict), "compose_services_present"))
    if not isinstance(services, dict):
        return checks

    service_name = str(profile.metadata.get("service") or "openclaw-gateway")
    service = services.get(service_name)
    checks.append(ComposeContractCheck(isinstance(service, dict), "compose_profile_service_exists", service_name))
    if not isinstance(service, dict):
        return checks

    labels = _labels_as_dict(service.get("labels"))
    instance_id = str(getattr(desired.route, "instance_id", "") or "")
    linux_account = str(getattr(desired.route, "linux_account", "") or desired.slot)
    checks.extend(
        [
            ComposeContractCheck(
                bool(instance_id) and labels.get("agent-runtime.instance-id") == instance_id,
                "compose_instance_label_matches",
                f"label={labels.get('agent-runtime.instance-id')}",
            ),
            ComposeContractCheck(
                labels.get("agent-runtime.linux-account") == linux_account,
                "compose_linux_account_label_matches",
                f"label={labels.get('agent-runtime.linux-account')}",
            ),
            ComposeContractCheck(
                labels.get("agent-runtime.slot") == linux_account,
                "compose_legacy_slot_label_matches",
                f"label={labels.get('agent-runtime.slot')}",
            ),
            ComposeContractCheck(
                labels.get("agent-runtime.profile") == profile.name,
                "compose_profile_label_matches",
                f"label={labels.get('agent-runtime.profile')}",
            ),
            ComposeContractCheck(
                labels.get("agent-runtime.service") == "gateway",
                "compose_service_label_gateway",
                f"label={labels.get('agent-runtime.service')}",
            ),
        ]
    )

    env_files = _env_file_entries(service.get("env_file"))
    secret_files = _profile_secret_file_paths(profile, desired.slot)
    if secret_files:
        missing_secret_files = [
            path
            for path in secret_files
            if not any(_env_file_matches_secret(entry, path, desired.slot) for entry in env_files)
        ]
        checks.append(
            ComposeContractCheck(
                not missing_secret_files,
                "compose_secret_files_present",
                (
                    "count="
                    + str(len(secret_files))
                    if not missing_secret_files
                    else "missing=" + ",".join(missing_secret_files)
                ),
            )
        )

    runtime_user_mode = str(profile.metadata.get("runtime_user_mode") or "compose")
    user_value = service.get("user")
    user_present = user_value not in {None, ""}
    if runtime_user_mode == "image-managed":
        checks.append(
            ComposeContractCheck(
                not user_present,
                "compose_runtime_user_model",
                "mode=image-managed user_present=yes" if user_present else "mode=image-managed",
            )
        )
    elif runtime_user_mode == "compose":
        checks.append(
            ComposeContractCheck(
                user_present and str(user_value) not in {"0", "0:0", "root"},
                "compose_runtime_user_model",
                f"mode=compose user={user_value or 'empty'}",
            )
        )
    else:
        checks.append(ComposeContractCheck(False, "compose_runtime_user_model", f"unknown_mode={runtime_user_mode}"))

    if profile.metadata.get("image_default_command") is True:
        actual_command = _command_as_list(service.get("command"))
        checks.append(
            ComposeContractCheck(
                actual_command is None,
                "compose_uses_image_default_command",
                f"actual={' '.join(actual_command) if actual_command else 'missing'}",
            )
        )
    elif (required_command := profile.metadata.get("required_command")) is not None:
        expected_command = [str(item) for item in required_command] if isinstance(required_command, list) else []
        actual_command = _command_as_list(service.get("command"))
        checks.append(
            ComposeContractCheck(
                bool(expected_command) and actual_command == expected_command,
                "compose_required_command",
                f"required={' '.join(expected_command) or 'invalid'} actual={' '.join(actual_command) if actual_command else 'missing'}",
            )
        )

    expected_working_dir = str(profile.metadata.get("required_working_dir") or "")
    if expected_working_dir:
        actual_working_dir = str(service.get("working_dir") or "")
        checks.append(
            ComposeContractCheck(
                actual_working_dir == expected_working_dir,
                "compose_required_working_dir",
                f"required={expected_working_dir} actual={actual_working_dir or 'missing'}",
            )
        )

    required_http_container_port = str(profile.metadata.get("required_http_container_port") or "")
    if required_http_container_port:
        ports = service.get("ports") if isinstance(service.get("ports"), list) else []
        checks.append(
            ComposeContractCheck(
                any(_port_targets_container_port(port, required_http_container_port) for port in ports),
                "compose_customer_surface_port",
                (
                    f"contract={profile.metadata.get('runtime_contract') or 'unknown'} "
                    f"container_port={required_http_container_port}"
                ),
            )
        )

    volumes = service.get("volumes") if isinstance(service.get("volumes"), list) else []
    try:
        socket_projection = runtime_socket_projection(profile, desired.slot)
    except ValueError as exc:
        checks.append(ComposeContractCheck(False, "compose_runtime_socket_contract_valid", str(exc)))
        socket_projection = None
    if socket_projection is not None:
        socket_volumes = [
            volume for volume in volumes if _volume_target(volume) == socket_projection.target
        ]
        checks.append(
            ComposeContractCheck(
                len(socket_volumes) == 1,
                "compose_runtime_socket_bind_present",
                f"target={socket_projection.target} count={len(socket_volumes)}",
            )
        )
        socket_volume = socket_volumes[0] if len(socket_volumes) == 1 else None
        checks.extend(
            [
                ComposeContractCheck(
                    _volume_type(socket_volume) == "bind",
                    "compose_runtime_socket_bind_type",
                    f"type={_volume_type(socket_volume) or 'missing'}",
                ),
                ComposeContractCheck(
                    _volume_source(socket_volume) == str(socket_projection.source),
                    "compose_runtime_socket_source_slot_scoped",
                    f"source={_volume_source(socket_volume) or 'missing'}",
                ),
                ComposeContractCheck(
                    _volume_is_read_only(socket_volume),
                    "compose_runtime_socket_readonly",
                    f"target={socket_projection.target}",
                ),
            ]
        )
        raw_group_add = service.get("group_add")
        group_add = raw_group_add if isinstance(raw_group_add, list) else []
        expected_group = runtime_group_token(desired.slot)
        checks.append(
            ComposeContractCheck(
                expected_group in {str(item) for item in group_add},
                "compose_runtime_socket_peer_group_present",
                f"expected={expected_group}",
            )
        )
    container_nas_root = str(profile.metadata.get("container_nas_root") or "")
    nas_volumes = [volume for volume in volumes if _volume_target(volume) == container_nas_root]
    checks.append(
        ComposeContractCheck(
            bool(container_nas_root and nas_volumes),
            "compose_nas_root_bind_present",
            container_nas_root or "missing_container_nas_root",
        )
    )
    if nas_volumes:
        nas_volume = nas_volumes[0]
        if profile.metadata.get("required_read_only_nas") is True:
            checks.append(
                ComposeContractCheck(
                    _volume_is_read_only(nas_volume),
                    "compose_nas_root_readonly",
                    f"target={container_nas_root}",
                )
            )
        required_propagation = str(profile.metadata.get("required_mount_propagation") or "")
        if required_propagation:
            actual_propagation = _volume_propagation(nas_volume)
            checks.append(
                ComposeContractCheck(
                    _propagation_matches(actual_propagation, required_propagation),
                    "compose_nas_root_propagation",
                    f"required={required_propagation} actual={actual_propagation or 'missing'}",
                )
            )
        target_home = f"/home/{desired.slot}"
        checks.append(
            ComposeContractCheck(
                _volume_source(nas_volume) == f"{target_home}/nas_docs",
                "compose_nas_root_source_slot_scoped",
                f"source={_volume_source(nas_volume)}",
            )
        )

    # Workspace bind (OCn own-folder): the writable twin of the nas_docs tree.
    # Must exist, must NOT be read_only (a read_only here is the freeze bug in
    # template form), and must source the slot's own {home}/workspace.
    container_workspace_root = str(profile.metadata.get("container_workspace_root") or "")
    if container_workspace_root:
        workspace_volumes = [volume for volume in volumes if _volume_target(volume) == container_workspace_root]
        checks.append(
            ComposeContractCheck(
                bool(workspace_volumes),
                "compose_workspace_bind_present",
                container_workspace_root,
            )
        )
        if workspace_volumes:
            workspace_volume = workspace_volumes[0]
            checks.append(
                ComposeContractCheck(
                    not _volume_is_read_only(workspace_volume),
                    "compose_workspace_writable",
                    f"target={container_workspace_root}",
                )
            )
            workspace_home = f"/home/{desired.slot}"
            checks.append(
                ComposeContractCheck(
                    _volume_source(workspace_volume) == f"{workspace_home}/workspace",
                    "compose_workspace_source_slot_scoped",
                    f"source={_volume_source(workspace_volume)}",
                )
            )
            workspace_propagation = str(profile.metadata.get("required_mount_propagation") or "")
            if workspace_propagation:
                actual_ws_propagation = _volume_propagation(workspace_volume)
                checks.append(
                    ComposeContractCheck(
                        _propagation_matches(actual_ws_propagation, workspace_propagation),
                        "compose_workspace_propagation",
                        f"required={workspace_propagation} actual={actual_ws_propagation or 'missing'}",
                    )
                )

    source_mounts = [volume for volume in volumes if _volume_contains_source_output(volume)]
    if profile.metadata.get("allow_source_mount") is False:
        checks.append(
            ComposeContractCheck(
                not source_mounts,
                "compose_customer_source_mount_absent",
                f"count={len(source_mounts)}",
            )
        )
    elif profile.metadata.get("allow_source_mount") is True:
        target = str(profile.metadata.get("source_output_target") or "")
        checks.append(
            ComposeContractCheck(
                bool(source_mounts)
                and (not target or any(_mount_covers_target(_volume_target(volume), target) for volume in source_mounts)),
                "compose_dev_source_mount_present",
                f"target={target or 'any'} count={len(source_mounts)}",
            )
        )

    return checks
