from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Mapping, Protocol

from ..domain.artifact_probe import (
    probe_kwrag_product_artifact,
    serialize_probe_payload,
)
from .contracts import SealedJob
from .registry import DEFAULT_REGISTRY


class OperationAvailability(str, Enum):
    ENABLED = "enabled"
    DISABLED_BY_PRODUCT_BOUNDARY = "disabled_by_product_boundary"
    DISABLED_UNVERIFIED_AUTHORITY = "disabled_unverified_authority"


@dataclass(frozen=True)
class ExecutionPolicy:
    operation_id: str
    operation_version: int
    availability: OperationAvailability
    reason_code: str | None


class ExecutionPolicyRegistry:
    def __init__(self, policies: tuple[ExecutionPolicy, ...]) -> None:
        by_id: dict[str, ExecutionPolicy] = {}
        for policy in policies:
            if policy.operation_id in by_id:
                raise ValueError(f"duplicate execution policy: {policy.operation_id}")
            if policy.operation_id not in DEFAULT_REGISTRY.operation_ids:
                raise ValueError(
                    f"execution policy has no manifest contract: {policy.operation_id}"
                )
            if (
                policy.operation_version
                != DEFAULT_REGISTRY.spec(policy.operation_id).version
            ):
                raise ValueError(
                    "execution policy version does not match manifest contract"
                )
            if policy.availability is OperationAvailability.ENABLED:
                if policy.reason_code is not None:
                    raise ValueError(
                        "enabled execution policy cannot have a denial reason"
                    )
            elif not policy.reason_code:
                raise ValueError("disabled execution policy requires a reason code")
            by_id[policy.operation_id] = policy
        if set(by_id) != set(DEFAULT_REGISTRY.operation_ids):
            raise ValueError("execution policy must cover every manifest operation")
        self._policies: Mapping[str, ExecutionPolicy] = by_id

    @property
    def enabled_operation_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                key
                for key, value in self._policies.items()
                if value.availability is OperationAvailability.ENABLED
            )
        )

    @property
    def disabled_operation_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                key
                for key, value in self._policies.items()
                if value.availability is not OperationAvailability.ENABLED
            )
        )

    def policy(self, operation_id: str) -> ExecutionPolicy:
        return self._policies[operation_id]


DEFAULT_EXECUTION_POLICIES = ExecutionPolicyRegistry(
    (
        ExecutionPolicy(
            "artifact.probe_kwrag_product",
            1,
            OperationAvailability.ENABLED,
            None,
        ),
        ExecutionPolicy(
            "audit.verify",
            1,
            OperationAvailability.DISABLED_UNVERIFIED_AUTHORITY,
            "disabled_unverified_authority",
        ),
        ExecutionPolicy(
            "projection.staging_selftest",
            1,
            OperationAvailability.DISABLED_UNVERIFIED_AUTHORITY,
            "disabled_unverified_authority",
        ),
        ExecutionPolicy(
            "agent_loop.campaign_run",
            1,
            OperationAvailability.DISABLED_UNVERIFIED_AUTHORITY,
            "disabled_unverified_authority",
        ),
        ExecutionPolicy(
            "kwrag.candidate_build",
            1,
            OperationAvailability.DISABLED_UNVERIFIED_AUTHORITY,
            "disabled_unverified_authority",
        ),
        ExecutionPolicy(
            "kwrag.artifact_finalize",
            1,
            OperationAvailability.DISABLED_UNVERIFIED_AUTHORITY,
            "disabled_unverified_authority",
        ),
        ExecutionPolicy(
            "kwrag.runtime_verify",
            1,
            OperationAvailability.DISABLED_UNVERIFIED_AUTHORITY,
            "disabled_unverified_authority",
        ),
        ExecutionPolicy(
            "kwrag.network_ensure",
            1,
            OperationAvailability.DISABLED_BY_PRODUCT_BOUNDARY,
            "disabled_by_product_boundary",
        ),
    )
)


@dataclass(frozen=True)
class HandlerResult:
    raw_bytes: bytes
    public_status: str
    public_facts: tuple[tuple[str, str], ...]


class OperationHandler(Protocol):
    operation_id: str
    operation_version: int

    def run(self, job: SealedJob) -> HandlerResult: ...


ArtifactProbe = Callable[..., dict[str, object]]


class KwragProductArtifactProbeHandler:
    operation_id = "artifact.probe_kwrag_product"
    operation_version = 1

    def __init__(self, *, probe: ArtifactProbe = probe_kwrag_product_artifact) -> None:
        self._probe = probe

    def run(self, job: SealedJob) -> HandlerResult:
        if (
            job.operation_id != self.operation_id
            or job.operation_version != self.operation_version
        ):
            raise ValueError("artifact probe handler received the wrong operation")
        manifest = job.manifest_copy()
        revision = manifest["parameters"]["revision"]
        payload = self._probe(revision)
        raw = serialize_probe_payload(payload).encode("utf-8")
        derived = payload.get("derived")
        directory = payload.get("directoryObservation")
        docker = payload.get("dockerObservation")
        if (
            not isinstance(derived, dict)
            or not isinstance(directory, dict)
            or not isinstance(docker, dict)
        ):
            raise ValueError("artifact probe output is missing its typed observations")
        image = docker.get("image")
        if not isinstance(image, dict):
            raise ValueError(
                "artifact probe output is missing docker image observation"
            )
        facts = (
            ("revision", str(payload.get("revision"))),
            ("candidate_tag", str(derived.get("candidateTag"))),
            ("matching_directory_count", str(directory.get("matchingCount"))),
            ("image_exists", str(image.get("exists")).lower()),
            ("image_id", str(image.get("id"))),
            ("ancestor_container_count", str(docker.get("ancestorContainerCount"))),
            ("writes", str(payload.get("writes"))),
        )
        if any(value in {"None", "none"} for _, value in facts):
            raise ValueError("artifact probe output cannot form complete public facts")
        return HandlerResult(raw_bytes=raw, public_status="pass", public_facts=facts)


class OperationHandlerRegistry:
    def __init__(
        self,
        handlers: tuple[OperationHandler, ...],
        *,
        policies: ExecutionPolicyRegistry = DEFAULT_EXECUTION_POLICIES,
    ) -> None:
        by_id: dict[str, OperationHandler] = {}
        for handler in handlers:
            if handler.operation_id in by_id:
                raise ValueError(f"duplicate operation handler: {handler.operation_id}")
            policy = policies.policy(handler.operation_id)
            if policy.availability is not OperationAvailability.ENABLED:
                raise ValueError(
                    "disabled operation must not have an executable handler"
                )
            if handler.operation_version != policy.operation_version:
                raise ValueError("operation handler version does not match its policy")
            by_id[handler.operation_id] = handler
        if set(by_id) != set(policies.enabled_operation_ids):
            raise ValueError("every enabled operation must have exactly one handler")
        self._handlers: Mapping[str, OperationHandler] = by_id

    def handler(self, operation_id: str) -> OperationHandler:
        return self._handlers[operation_id]


DEFAULT_OPERATION_HANDLERS = OperationHandlerRegistry(
    (KwragProductArtifactProbeHandler(),)
)
