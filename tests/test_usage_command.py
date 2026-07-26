from __future__ import annotations

import json
from pathlib import Path
import subprocess
from unittest.mock import Mock, call, patch

from argparse import Namespace

import pytest

from agent_runtime_ops.commands.usage import (
    DEFAULT_USAGE_API_PRODUCT,
    DEFAULT_USAGE_DB_DEFAULTS,
    DEFAULT_USAGE_FX_FILE,
    DEFAULT_USAGE_PRICE_SCENARIO,
    DEFAULT_USAGE_PRICING_FILE,
    _enforce_sudo_usage_artifact_defaults,
    collect_target,
)
from agent_runtime_ops.domain.usage_ledger import UsageContractError
from agent_runtime_ops.routing import RuntimeBinding

from tests.test_usage_ledger import export_page


BINDING = RuntimeBinding(
    instance_id="e4526f41-9f61-4db8-90a5-b5eb53c29737",
    linux_account="oc20",
    public_host="oc20.ji-tech.co.kr",
    family="hermes",
    runtime_class="customer",
    gateway_port=18789,
    bridge_port=8020,
)


class Connection:
    def close(self) -> None:
        return None


def _coverage_payload() -> dict:
    path = Path(__file__).parent / "fixtures" / "jitech-provider-usage-coverage-v1.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["productFamily"] = "hermes"
    from agent_runtime_ops.domain.usage_ledger import coverage_manifest_digest

    payload["manifestDigest"] = coverage_manifest_digest(payload)
    return payload


def _proc(payload: object, *, returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        ["product"],
        returncode,
        stdout=json.dumps(payload),
        stderr="",
    )


def test_collect_validates_coverage_before_export_and_pins_it_to_storage() -> None:
    connection = Connection()
    run = Mock(side_effect=[_proc(_coverage_payload()), _proc(export_page())])
    stored = Mock(return_value={"inserted": 1, "idempotent": 0, "nextCursor": 1})
    stamp = Mock(
        container_id="container-1", wrapper_image="wrapper", product_image="product"
    )
    with (
        patch("agent_runtime_ops.commands.usage.ensure_schema"),
        patch("agent_runtime_ops.commands.usage.acquire_collection_lock"),
        patch(
            "agent_runtime_ops.commands.usage.get_runtime_binding", return_value=BINDING
        ),
        patch("agent_runtime_ops.commands.usage._live_stamp", return_value=stamp),
        patch("agent_runtime_ops.commands.usage.read_cursor", return_value=0),
        patch("agent_runtime_ops.commands.usage.ensure_binding_unchanged"),
        patch(
            "agent_runtime_ops.commands.usage.now_rfc3339",
            return_value="2026-07-26T01:00:00Z",
        ),
        patch("agent_runtime_ops.commands.usage.replace", return_value=stamp),
        patch("agent_runtime_ops.commands.usage.run_text", run),
        patch("agent_runtime_ops.commands.usage.store_export_page", stored),
    ):
        result = collect_target(
            binding=BINDING,
            state=Path("/state"),
            connection_factory=lambda: connection,
            limit=100,
            max_pages=1,
        )
    assert result["status"] == "ok"
    assert result["producerCoverageStatus"] == "partial"
    assert run.call_args_list[0] == call(
        [
            "docker",
            "exec",
            "container-1",
            "hermes",
            "usage-receipts",
            "coverage",
            "--json",
        ],
        timeout=120,
    )
    assert "export" in run.call_args_list[1].args[0]
    coverage = stored.call_args.kwargs["coverage"]
    assert coverage.family == "hermes"
    assert coverage.status == "partial"


def test_invalid_coverage_fails_before_export_and_never_stores_or_advances() -> None:
    connection = Connection()
    invalid = _coverage_payload()
    invalid["manifestDigest"] = "sha256:" + "0" * 64
    run = Mock(return_value=_proc(invalid))
    stored = Mock()
    stamp = Mock(
        container_id="container-1", wrapper_image="wrapper", product_image="product"
    )
    with (
        patch("agent_runtime_ops.commands.usage.ensure_schema"),
        patch("agent_runtime_ops.commands.usage.acquire_collection_lock"),
        patch(
            "agent_runtime_ops.commands.usage.get_runtime_binding", return_value=BINDING
        ),
        patch("agent_runtime_ops.commands.usage._live_stamp", return_value=stamp),
        patch("agent_runtime_ops.commands.usage.read_cursor", return_value=0),
        patch("agent_runtime_ops.commands.usage.run_text", run),
        patch("agent_runtime_ops.commands.usage.store_export_page", stored),
        patch("agent_runtime_ops.commands.usage._record_failure_safely"),
    ):
        result = collect_target(
            binding=BINDING,
            state=Path("/state"),
            connection_factory=lambda: connection,
            limit=100,
            max_pages=1,
        )
    assert result["status"] == "failed"
    assert run.call_count == 1
    stored.assert_not_called()


def test_sudo_cost_projection_cannot_turn_into_an_arbitrary_root_file_reader(
    monkeypatch,
) -> None:
    monkeypatch.setenv("SUDO_USER", "svcops")
    args = Namespace(
        pricing_file=DEFAULT_USAGE_PRICING_FILE,
        fx_file=DEFAULT_USAGE_FX_FILE,
        db_defaults_file=DEFAULT_USAGE_DB_DEFAULTS,
        api_product=DEFAULT_USAGE_API_PRODUCT,
        price_scenario=DEFAULT_USAGE_PRICE_SCENARIO,
    )
    _enforce_sudo_usage_artifact_defaults(args)
    args.pricing_file = "/etc/shadow"
    with pytest.raises(UsageContractError, match="installed defaults: pricing_file"):
        _enforce_sudo_usage_artifact_defaults(args)
