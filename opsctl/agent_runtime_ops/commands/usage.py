from __future__ import annotations

import argparse
from dataclasses import replace
import json
from pathlib import Path
import sys

from ..domain.common import is_root, run_text, state_root
from ..domain.runtime_truth import find_gateway_container_by_binding, live_runtime_truth
from ..domain.usage_ledger import (
    RuntimeUsageStamp,
    UsageContractError,
    UsageLedgerConflict,
    build_runtime_stamp,
    coverage_command,
    ensure_binding_unchanged,
    export_command,
    mysql_connection_factory,
    now_rfc3339,
    parse_coverage_stdout,
    parse_export_stdout,
    redact_error,
    runtime_binding_digest,
)
from ..domain.usage_store import (
    UsageCollectionBusy,
    acquire_collection_lock,
    ensure_schema,
    list_collection_status,
    read_cursor,
    record_collection_failure,
    store_export_page,
)
from ..routing import RuntimeBinding, get_runtime_binding, load_runtime_bindings


DEFAULT_USAGE_DB_DEFAULTS = Path("/etc/agent-runtime-ops/usage-writer.cnf")


def _failure_stamp(
    binding: RuntimeBinding, *, container_id: str = "", truth: dict | None = None
) -> RuntimeUsageStamp:
    truth = truth or {}
    return RuntimeUsageStamp(
        instance_id=binding.instance_id,
        linux_account=binding.linux_account,
        public_host=binding.public_host,
        family=binding.family,
        runtime_class=binding.runtime_class,
        binding_digest=runtime_binding_digest(binding),
        container_id=container_id,
        wrapper_image=str(truth.get("wrapper_image") or ""),
        product_image=str(truth.get("product_image") or ""),
        ops_repo_commit=str(truth.get("ops_repo_commit") or ""),
        collected_at=now_rfc3339(),
    )


def _live_stamp(binding: RuntimeBinding, state: Path) -> RuntimeUsageStamp:
    container_id, lookup = find_gateway_container_by_binding(binding)
    if not container_id:
        raise UsageContractError(f"gateway container not found: {lookup}")
    truth, checks = live_runtime_truth(binding.instance_id, state)
    failed = [name for ok, name, _detail in checks if not ok]
    if failed:
        raise UsageContractError(
            f"live runtime truth checks failed: {','.join(failed)}"
        )
    return build_runtime_stamp(binding=binding, container_id=container_id, truth=truth)


def _record_failure_safely(
    connection, stamp: RuntimeUsageStamp, code: str, detail: str
) -> None:
    try:
        record_collection_failure(
            connection, stamp=stamp, error_code=code, detail=detail
        )
    except Exception as audit_exc:
        print(
            f"usage_failure_audit_status=fail target={stamp.linux_account} "
            f"reason={redact_error(audit_exc)}",
            file=sys.stderr,
        )


def collect_target(
    *,
    binding: RuntimeBinding,
    state: Path,
    connection_factory,
    limit: int,
    max_pages: int,
) -> dict[str, object]:
    connection = connection_factory()
    total_inserted = 0
    total_idempotent = 0
    pages = 0
    current_stamp = _failure_stamp(binding)
    try:
        ensure_schema(connection)
        acquire_collection_lock(connection, binding.instance_id)
        while pages < max_pages:
            binding_before = get_runtime_binding(binding.instance_id, state)
            current_stamp = _live_stamp(binding_before, state)
            cursor = read_cursor(connection, current_stamp)
            coverage_argv = [
                "docker",
                "exec",
                current_stamp.container_id,
                *coverage_command(binding.family),
            ]
            coverage_proc = run_text(coverage_argv, timeout=120)
            if coverage_proc.returncode != 0:
                detail = (
                    coverage_proc.stderr
                    or coverage_proc.stdout
                    or f"returncode={coverage_proc.returncode}"
                ).strip()
                raise UsageContractError(
                    f"product_coverage_failed: {redact_error(detail)}"
                )
            coverage = parse_coverage_stdout(
                coverage_proc.stdout,
                expected_family=binding.family,
            )
            argv = [
                "docker",
                "exec",
                current_stamp.container_id,
                *export_command(binding.family, after=cursor, limit=limit),
            ]
            proc = run_text(argv, timeout=120)
            if proc.returncode != 0:
                detail = (
                    proc.stderr or proc.stdout or f"returncode={proc.returncode}"
                ).strip()
                raise UsageContractError(
                    f"product_export_failed: {redact_error(detail)}"
                )
            page = parse_export_stdout(
                proc.stdout,
                expected_after=cursor,
                expected_family=binding.family,
            )

            binding_after = get_runtime_binding(binding.instance_id, state)
            ensure_binding_unchanged(binding_before, binding_after)
            after_stamp = _live_stamp(binding_after, state)
            if after_stamp.container_id != current_stamp.container_id:
                raise UsageContractError(
                    "gateway container changed during usage export"
                )
            if (
                after_stamp.wrapper_image != current_stamp.wrapper_image
                or after_stamp.product_image != current_stamp.product_image
            ):
                raise UsageContractError("runtime image changed during usage export")
            current_stamp = replace(current_stamp, collected_at=now_rfc3339())
            result = store_export_page(
                connection,
                stamp=current_stamp,
                coverage=coverage,
                page=page,
            )
            total_inserted += int(result["inserted"])
            total_idempotent += int(result["idempotent"])
            pages += 1
            if not page.has_more:
                return {
                    "target": binding.linux_account,
                    "instanceId": binding.instance_id,
                    "family": binding.family,
                    "status": "ok",
                    "pages": pages,
                    "inserted": total_inserted,
                    "idempotent": total_idempotent,
                    "cursor": page.next_cursor,
                    "highWatermark": page.high_watermark,
                    "producerCoverageStatus": coverage.status,
                    "producerCoverageDigest": coverage.manifest_digest,
                }
        raise UsageContractError(
            f"collection page limit reached: max_pages={max_pages}"
        )
    except UsageCollectionBusy as exc:
        return {
            "target": binding.linux_account,
            "instanceId": binding.instance_id,
            "family": binding.family,
            "status": "busy",
            "pages": pages,
            "inserted": total_inserted,
            "idempotent": total_idempotent,
            "reason": redact_error(exc),
        }
    except Exception as exc:
        if not isinstance(exc, UsageLedgerConflict):
            _record_failure_safely(
                connection, current_stamp, type(exc).__name__, str(exc)
            )
        return {
            "target": binding.linux_account,
            "instanceId": binding.instance_id,
            "family": binding.family,
            "status": "failed",
            "pages": pages,
            "inserted": total_inserted,
            "idempotent": total_idempotent,
            "reason": redact_error(exc),
        }
    finally:
        connection.close()


def _targets(args: argparse.Namespace, state: Path) -> list[RuntimeBinding]:
    all_targets = bool(getattr(args, "all", False))
    target = str(getattr(args, "target", "") or "").strip()
    if all_targets and target:
        raise UsageContractError("provide either TARGET or --all, not both")
    if not all_targets and not target:
        raise UsageContractError("provide TARGET or --all")
    if target:
        binding = get_runtime_binding(target, state)
        if not binding.enabled:
            raise UsageContractError(
                f"runtime binding is disabled: {binding.linux_account}"
            )
        return [binding]
    return [binding for binding in load_runtime_bindings(state) if binding.enabled]


def cmd_usage_collect(args: argparse.Namespace) -> int:
    if not is_root():
        print(
            "error: run as root/admin: sudo /usr/local/bin/opsctl usage collect ...",
            file=sys.stderr,
        )
        return 2
    state = state_root(args)
    try:
        bindings = _targets(args, state)
        factory = mysql_connection_factory(Path(args.db_defaults_file))
    except Exception as exc:
        print(
            json.dumps(
                {"status": "failed", "reason": redact_error(exc)}, ensure_ascii=False
            )
        )
        return 2
    results = [
        collect_target(
            binding=binding,
            state=state,
            connection_factory=factory,
            limit=int(args.limit),
            max_pages=int(args.max_pages),
        )
        for binding in bindings
    ]
    statuses = {str(item["status"]) for item in results}
    if statuses <= {"ok"}:
        status = "ok"
    elif statuses <= {"ok", "busy"}:
        status = "busy"
    else:
        status = "failed"
    print(
        json.dumps(
            {
                "schema": "jitech-usage-collection-run/v1",
                "status": status,
                "results": results,
            },
            ensure_ascii=False,
        )
    )
    return 0 if status in {"ok", "busy"} else 1


def _json_safe(value: object) -> object:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def cmd_usage_status(args: argparse.Namespace) -> int:
    if not is_root():
        print(
            "error: run as root/admin: sudo /usr/local/bin/opsctl usage status ...",
            file=sys.stderr,
        )
        return 2
    try:
        factory = mysql_connection_factory(Path(args.db_defaults_file))
        connection = factory()
        try:
            ensure_schema(connection)
            rows = list_collection_status(
                connection, linux_account=str(args.target or "") or None
            )
        finally:
            connection.close()
        payload = {
            "schema": "jitech-usage-collection-status/v1",
            "status": "ok",
            "rows": [
                {key: _json_safe(value) for key, value in row.items()} for row in rows
            ],
        }
        print(json.dumps(payload, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {"status": "failed", "reason": redact_error(exc)}, ensure_ascii=False
            )
        )
        return 1
