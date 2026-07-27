from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Mapping


TECHNICAL_FAILURE_REASON_CODES = frozenset(
    {
        "handler_contract_failed",
        "handler_failed",
        "precondition_mismatch",
        "receipt_publish_failed",
        "reconcile_failed",
        "worker_crashed",
        "worker_lost",
    }
)
CIRCUIT_BREAKER_REASON_CODE = "technical_failure_circuit_open"


@dataclass(frozen=True)
class LineageFailurePolicy:
    window_seconds: int = 24 * 60 * 60
    maximum_technical_failures: int = 2
    technical_reason_codes: frozenset[str] = TECHNICAL_FAILURE_REASON_CODES
    circuit_reason_code: str = CIRCUIT_BREAKER_REASON_CODE

    def __post_init__(self) -> None:
        if (
            isinstance(self.window_seconds, bool)
            or not isinstance(self.window_seconds, int)
            or self.window_seconds < 1
        ):
            raise ValueError("lineage failure window must be a positive integer")
        if (
            isinstance(self.maximum_technical_failures, bool)
            or not isinstance(self.maximum_technical_failures, int)
            or self.maximum_technical_failures < 1
        ):
            raise ValueError("lineage failure limit must be a positive integer")
        if not self.technical_reason_codes:
            raise ValueError("technical reason allowlist must not be empty")


@dataclass(frozen=True)
class LineageSummary:
    lineage_id: str
    measured_at: str
    window_seconds: int
    submission_count: int
    terminal_counts: Mapping[str, int]
    technical_failure_count: int
    source: str = "root_owned_ledger"

    def __post_init__(self) -> None:
        datetime.strptime(self.measured_at, "%Y-%m-%dT%H:%M:%SZ")
        if self.source != "root_owned_ledger":
            raise ValueError("lineage summary source must be root_owned_ledger")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (
                self.window_seconds,
                self.submission_count,
                self.technical_failure_count,
                *self.terminal_counts.values(),
            )
        ):
            raise ValueError("lineage summary counter is invalid")
        object.__setattr__(
            self,
            "terminal_counts",
            MappingProxyType(dict(sorted(self.terminal_counts.items()))),
        )

    def projection(self) -> dict[str, object]:
        return {
            "lineage_id": self.lineage_id,
            "measured_at": self.measured_at,
            "measurement_semantics": "root_ledger_window_ending_at_measured_at",
            "window_seconds": self.window_seconds,
            "source": self.source,
            "submission_count": self.submission_count,
            "terminal_counts": dict(self.terminal_counts),
            "technical_failure_count": self.technical_failure_count,
            "approval_count": {
                "availability": "unavailable",
                "reason": "approval_design_not_ratified",
            },
        }


@dataclass(frozen=True)
class SubmissionAdmission:
    allowed: bool
    reason_code: str | None
    summary: LineageSummary

    def __post_init__(self) -> None:
        if self.allowed != (self.reason_code is None):
            raise ValueError("submission admission reason invariant failed")
