from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
import re


MAX_PROVIDER_OBSERVATION_COUNT = 1_000_000
MAX_PUBLIC_PATH_BYTES = 1024
UNAVAILABLE_FACT_VALUE = "unavailable"
_PUBLIC_PATH_RE = re.compile(r"/[A-Za-z0-9._/-]+")


class ObservationValidationError(ValueError):
    """A handler observation cannot be exposed as bounded public facts."""


def _optional_boolean(value: bool | None, field: str) -> None:
    if value is not None and not isinstance(value, bool):
        raise ObservationValidationError(f"{field} must be boolean or unavailable")


def _optional_count(value: int | None, field: str) -> None:
    if value is None:
        return
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > MAX_PROVIDER_OBSERVATION_COUNT
    ):
        raise ObservationValidationError(f"{field} is outside the public count bound")


def _canonical_public_path(value: str, field: str) -> PurePosixPath:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > MAX_PUBLIC_PATH_BYTES
        or _PUBLIC_PATH_RE.fullmatch(value) is None
    ):
        raise ObservationValidationError(f"{field} is not a bounded public path")
    path = PurePosixPath(value)
    if (
        not path.is_absolute()
        or path.as_posix() != value
        or path == PurePosixPath("/")
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise ObservationValidationError(f"{field} is not a canonical absolute path")
    return path


def _public_path(
    value: str | None,
    field: str,
    *,
    allowed_roots: tuple[PurePosixPath, ...],
) -> str:
    if value is None:
        return UNAVAILABLE_FACT_VALUE
    path = _canonical_public_path(value, field)
    if not allowed_roots or not any(
        path == root or path.is_relative_to(root) for root in allowed_roots
    ):
        raise ObservationValidationError(f"{field} is outside its public path roots")
    return value


def _boolean_fact(value: bool | None) -> str:
    if value is None:
        return UNAVAILABLE_FACT_VALUE
    return "true" if value else "false"


def _count_fact(value: int | None) -> str:
    return UNAVAILABLE_FACT_VALUE if value is None else str(value)


@dataclass(frozen=True)
class SanitizedExecutionObservation:
    """Decision-independent auxiliary facts for a future typed handler receipt.

    The receipt's top-level ``terminal_outcome`` remains the terminal status source.
    ``None`` means the handler did not measure a value and is never converted to zero.
    Paths are exposed only under roots selected by the concrete typed handler.
    This object grants no authority and performs no dispatch.
    """

    dispatch_started: bool | None
    dispatch_completed: bool | None
    provider_request_count: int | None
    provider_reservation_count: int | None
    preserved_snapshot_path: str | None
    staging_path: str | None

    def __post_init__(self) -> None:
        _optional_boolean(self.dispatch_started, "dispatch_started")
        _optional_boolean(self.dispatch_completed, "dispatch_completed")
        if self.dispatch_completed is True and self.dispatch_started is not True:
            raise ObservationValidationError(
                "dispatch_completed=true requires dispatch_started=true"
            )
        _optional_count(self.provider_request_count, "provider_request_count")
        _optional_count(
            self.provider_reservation_count, "provider_reservation_count"
        )
        for value, field in (
            (self.preserved_snapshot_path, "preserved_snapshot_path"),
            (self.staging_path, "staging_path"),
        ):
            if value is not None:
                _canonical_public_path(value, field)

    def public_facts(
        self, *, allowed_path_roots: tuple[str, ...]
    ) -> tuple[tuple[str, str], ...]:
        if not isinstance(allowed_path_roots, tuple) or len(allowed_path_roots) > 16:
            raise ObservationValidationError(
                "allowed_path_roots must be a bounded tuple"
            )
        roots = tuple(
            _canonical_public_path(root, f"allowed_path_roots[{index}]")
            for index, root in enumerate(allowed_path_roots)
        )
        if len(set(roots)) != len(roots):
            raise ObservationValidationError("allowed_path_roots must be unique")
        return (
            ("dispatch_started", _boolean_fact(self.dispatch_started)),
            ("dispatch_completed", _boolean_fact(self.dispatch_completed)),
            ("provider_request_count", _count_fact(self.provider_request_count)),
            (
                "provider_reservation_count",
                _count_fact(self.provider_reservation_count),
            ),
            (
                "preserved_snapshot_path",
                _public_path(
                    self.preserved_snapshot_path,
                    "preserved_snapshot_path",
                    allowed_roots=roots,
                ),
            ),
            (
                "staging_path",
                _public_path(
                    self.staging_path,
                    "staging_path",
                    allowed_roots=roots,
                ),
            ),
        )
