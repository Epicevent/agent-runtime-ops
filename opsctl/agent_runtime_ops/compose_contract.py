from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import yaml


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


def _environment_as_dict(raw_environment: Any) -> dict[str, str]:
    if isinstance(raw_environment, dict):
        return {str(key): str(value) for key, value in raw_environment.items()}
    if isinstance(raw_environment, list):
        values: dict[str, str] = {}
        for item in raw_environment:
            if isinstance(item, str) and "=" in item:
                key, value = item.split("=", 1)
                values[key] = value
        return values
    return {}


def _port_target(port: Any) -> str:
    if isinstance(port, dict):
        return str(port.get("target") or "")
    if isinstance(port, str):
        value = port.split("/", 1)[0]
        parts = value.rsplit(":", 1)
        return parts[-1] if parts else ""
    return ""


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
    checks.extend(
        [
            ComposeContractCheck(
                labels.get("agent-runtime.slot") == desired.slot,
                "compose_slot_label_matches",
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

    required_command = profile.metadata.get("required_command")
    if required_command is not None:
        expected_command = [str(item) for item in required_command] if isinstance(required_command, list) else []
        actual_command = _command_as_list(service.get("command"))
        checks.append(
            ComposeContractCheck(
                bool(expected_command) and actual_command == expected_command,
                "compose_required_command",
                f"required={' '.join(expected_command) or 'invalid'} actual={' '.join(actual_command) if actual_command else 'missing'}",
            )
        )

    environment = _environment_as_dict(service.get("environment"))
    required_environment = profile.metadata.get("required_environment")
    if isinstance(required_environment, dict):
        for key, value in required_environment.items():
            expected_value = str(value)
            actual_value = environment.get(str(key))
            checks.append(
                ComposeContractCheck(
                    actual_value == expected_value,
                    f"compose_required_environment_{str(key).lower()}",
                    f"required={expected_value} actual={actual_value if actual_value is not None else 'missing'}",
                )
            )

    required_gateway_container_port = str(profile.metadata.get("required_gateway_container_port") or "")
    if required_gateway_container_port:
        ports = service.get("ports") if isinstance(service.get("ports"), list) else []
        targets = [_port_target(port) for port in ports]
        checks.append(
            ComposeContractCheck(
                required_gateway_container_port in targets,
                "compose_gateway_port_targets_required_container_port",
                f"required={required_gateway_container_port} actual={','.join(targets) or 'missing'}",
            )
        )

    volumes = service.get("volumes") if isinstance(service.get("volumes"), list) else []
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
                bool(source_mounts) and (not target or any(_volume_target(volume) == target for volume in source_mounts)),
                "compose_dev_source_mount_present",
                f"target={target or 'any'} count={len(source_mounts)}",
            )
        )

    return checks
