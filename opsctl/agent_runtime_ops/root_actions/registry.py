from __future__ import annotations

from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Any, Mapping


REGISTRY_VERSION = "agent-runtime-root-action-registry/v1"
_IDENTIFIER_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_REVISION_RE = re.compile(r"[0-9a-f]{40}")


class RegistryValidationError(ValueError):
    """A typed operation or its parameters do not match the fixed registry."""


@dataclass(frozen=True)
class ParameterRule:
    kind: str
    choices: tuple[str, ...] = ()
    minimum: int | None = None
    maximum: int | None = None
    max_items: int = 0

    def validate(self, value: Any, *, field: str) -> None:
        if self.kind == "identifier":
            _require_matching_string(value, _IDENTIFIER_RE, field)
            return
        if self.kind == "digest":
            _require_matching_string(value, _DIGEST_RE, field)
            return
        if self.kind == "nullable_digest":
            if value is not None:
                _require_matching_string(value, _DIGEST_RE, field)
            return
        if self.kind == "revision":
            _require_matching_string(value, _REVISION_RE, field)
            return
        if self.kind == "enum":
            if not isinstance(value, str) or value not in self.choices:
                raise RegistryValidationError(
                    f"{field} must be one of {sorted(self.choices)}"
                )
            return
        if self.kind == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                raise RegistryValidationError(f"{field} must be an integer")
            if self.minimum is not None and value < self.minimum:
                raise RegistryValidationError(f"{field} is below its minimum")
            if self.maximum is not None and value > self.maximum:
                raise RegistryValidationError(f"{field} exceeds its maximum")
            return
        if self.kind in {"identifier_list", "digest_list"}:
            if (
                not isinstance(value, list)
                or not value
                or len(value) > self.max_items
            ):
                raise RegistryValidationError(
                    f"{field} must be a non-empty list with at most {self.max_items} items"
                )
            pattern = _IDENTIFIER_RE if self.kind == "identifier_list" else _DIGEST_RE
            for index, item in enumerate(value):
                _require_matching_string(item, pattern, f"{field}[{index}]")
            if len(set(value)) != len(value):
                raise RegistryValidationError(f"{field} must not contain duplicates")
            return
        raise AssertionError(f"unsupported parameter rule: {self.kind}")

    def projection(self) -> dict[str, Any]:
        value: dict[str, Any] = {"kind": self.kind}
        if self.choices:
            value["choices"] = list(self.choices)
        if self.minimum is not None:
            value["minimum"] = self.minimum
        if self.maximum is not None:
            value["maximum"] = self.maximum
        if self.max_items:
            value["max_items"] = self.max_items
        return value


def _require_matching_string(value: Any, pattern: re.Pattern[str], field: str) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise RegistryValidationError(f"{field} has an invalid value")


@dataclass(frozen=True)
class OperationSpec:
    operation_id: str
    version: int
    parameter_rules: tuple[tuple[str, ParameterRule], ...]

    @property
    def parameter_names(self) -> tuple[str, ...]:
        return tuple(name for name, _ in self.parameter_rules)

    def validate_parameters(self, value: Any) -> None:
        if not isinstance(value, dict):
            raise RegistryValidationError("parameters must be an object")
        expected = set(self.parameter_names)
        actual = set(value)
        if actual != expected:
            missing = sorted(expected - actual)
            extra = sorted(actual - expected)
            raise RegistryValidationError(
                f"parameters field set mismatch missing={missing} extra={extra}"
            )
        for name, rule in self.parameter_rules:
            rule.validate(value[name], field=f"parameters.{name}")

    def projection(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "operation_version": self.version,
            "parameters": {
                name: rule.projection() for name, rule in self.parameter_rules
            },
        }


class OperationRegistry:
    def __init__(self, specs: tuple[OperationSpec, ...]) -> None:
        by_id: dict[str, OperationSpec] = {}
        for spec in specs:
            if _IDENTIFIER_RE.fullmatch(spec.operation_id) is None:
                raise ValueError(f"invalid operation id: {spec.operation_id}")
            if spec.operation_id in by_id:
                raise ValueError(f"duplicate operation id: {spec.operation_id}")
            if spec.version < 1:
                raise ValueError(f"invalid operation version: {spec.operation_id}")
            if len(set(spec.parameter_names)) != len(spec.parameter_names):
                raise ValueError(f"duplicate parameter name: {spec.operation_id}")
            by_id[spec.operation_id] = spec
        self._specs: Mapping[str, OperationSpec] = MappingProxyType(by_id)

    @property
    def operation_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._specs))

    def spec(self, operation_id: str) -> OperationSpec:
        try:
            return self._specs[operation_id]
        except KeyError as exc:
            raise RegistryValidationError(
                f"operation_id is not registered: {operation_id}"
            ) from exc

    def validate(self, operation_id: str, version: int, parameters: Any) -> None:
        spec = self.spec(operation_id)
        if isinstance(version, bool) or not isinstance(version, int):
            raise RegistryValidationError("operation_version must be an integer")
        if version != spec.version:
            raise RegistryValidationError(
                f"operation version mismatch expected={spec.version} actual={version}"
            )
        spec.validate_parameters(parameters)
        if operation_id == "kwrag.network_ensure":
            expected_state = parameters["expected_state"]
            expected_identity = parameters["expected_identity_digest"]
            if expected_state == "absent" and expected_identity is not None:
                raise RegistryValidationError(
                    "expected_identity_digest must be null when expected_state is absent"
                )
            if expected_state == "owned" and expected_identity is None:
                raise RegistryValidationError(
                    "expected_identity_digest is required when expected_state is owned"
                )

    def projection(self) -> dict[str, Any]:
        return {
            "schema": REGISTRY_VERSION,
            "operations": [self._specs[key].projection() for key in sorted(self._specs)],
        }


def _rule(kind: str, **kwargs: Any) -> ParameterRule:
    return ParameterRule(kind=kind, **kwargs)


DEFAULT_REGISTRY = OperationRegistry(
    (
        OperationSpec(
            "audit.verify",
            1,
            (
                ("target_identity", _rule("identifier")),
                ("expected_schema", _rule("identifier")),
                ("freshness_seconds", _rule("integer", minimum=1, maximum=86_400)),
                ("allowlisted_fields", _rule("identifier_list", max_items=64)),
            ),
        ),
        OperationSpec(
            "projection.staging_selftest",
            1,
            (
                ("fixture_id", _rule("identifier")),
                ("expected_contract_digest", _rule("digest")),
            ),
        ),
        OperationSpec(
            "agent_loop.campaign_run",
            1,
            (
                ("campaign_id", _rule("identifier")),
                ("image_digest", _rule("digest")),
                ("input_digest", _rule("digest")),
                ("runtime_seconds", _rule("integer", minimum=1, maximum=21_600)),
                ("memory_mib", _rule("integer", minimum=128, maximum=262_144)),
            ),
        ),
        OperationSpec(
            "kwrag.candidate_build",
            1,
            (
                ("source_revision", _rule("revision")),
                ("build_input_digest", _rule("digest")),
                ("base_image_digest", _rule("digest")),
                ("runtime_seconds", _rule("integer", minimum=1, maximum=21_600)),
                ("memory_mib", _rule("integer", minimum=128, maximum=262_144)),
            ),
        ),
        OperationSpec(
            "kwrag.artifact_finalize",
            1,
            (
                ("source_revision", _rule("revision")),
                ("artifact_digests", _rule("digest_list", max_items=32)),
                ("expected_image_id", _rule("digest")),
            ),
        ),
        OperationSpec(
            "kwrag.runtime_verify",
            1,
            (
                ("candidate_digest", _rule("digest")),
                ("fixture_id", _rule("identifier")),
                ("projection_digest", _rule("digest")),
                ("runtime_seconds", _rule("integer", minimum=1, maximum=7_200)),
            ),
        ),
        OperationSpec(
            "kwrag.network_ensure",
            1,
            (
                ("network_plan_digest", _rule("digest")),
                ("expected_state", _rule("enum", choices=("absent", "owned"))),
                ("expected_identity_digest", _rule("nullable_digest")),
            ),
        ),
    )
)
