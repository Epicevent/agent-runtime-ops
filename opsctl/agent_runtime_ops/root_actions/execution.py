from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Protocol
from .contracts import SealedJob
from .registry import DEFAULT_REGISTRY


class OperationAvailability(str, Enum):
    ENABLED = "enabled"
    DISABLED_UNVERIFIED_AUTHORITY = "disabled_unverified_authority"


@dataclass(frozen=True)
class ExecutionPolicy:
    operation_id: str
    operation_version: int
    availability: OperationAvailability
    reason_code: str | None
    auto_dispatch: bool = False


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
            if not isinstance(policy.auto_dispatch, bool):
                raise ValueError("execution policy auto-dispatch flag is invalid")
            if (
                policy.availability is not OperationAvailability.ENABLED
                and policy.auto_dispatch
            ):
                raise ValueError("disabled operation cannot auto-dispatch")
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
            "nas.observe_groupware_runtime",
            1,
            OperationAvailability.ENABLED,
            None,
            True,
        ),
    )
)


@dataclass(frozen=True)
class HandlerResult:
    raw_bytes: bytes
    public_status: str
    public_facts: tuple[tuple[str, str], ...]
    terminal_outcome: str = "succeeded"
    reason_code: str = "handler_succeeded"
    exit_code: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.raw_bytes, bytes) or not self.raw_bytes:
            raise ValueError("handler raw receipt must be non-empty bytes")
        if self.terminal_outcome not in {"succeeded", "failed"}:
            raise ValueError("handler terminal outcome is invalid")
        if not isinstance(self.reason_code, str) or not self.reason_code:
            raise ValueError("handler reason code is invalid")
        if isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int):
            raise ValueError("handler exit code is invalid")
        if self.terminal_outcome == "succeeded" and self.exit_code != 0:
            raise ValueError("successful handler result requires exit code zero")


class OperationHandler(Protocol):
    operation_id: str
    operation_version: int

    def run(self, job: SealedJob) -> HandlerResult: ...


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


from .groupware_runtime_observation import GroupwareRuntimeObservationHandler


DEFAULT_OPERATION_HANDLERS = OperationHandlerRegistry(
    (GroupwareRuntimeObservationHandler(),)
)
