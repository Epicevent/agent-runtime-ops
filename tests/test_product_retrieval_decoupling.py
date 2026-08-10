from pathlib import Path
from types import SimpleNamespace

from agent_runtime_ops.domain.runtime_truth import live_image_truth_from_info
from agent_runtime_ops.root_actions.inventory import INVENTORY_COVERAGE
from agent_runtime_ops.root_actions.registry import DEFAULT_REGISTRY
from agent_runtime_ops.routing import RuntimeBinding


ROOT = Path(__file__).resolve().parents[1]
ACTIVE_RUNTIME_FILES = (
    "opsctl/agent_runtime_ops/commands/apply.py",
    "opsctl/agent_runtime_ops/commands/observation.py",
    "opsctl/agent_runtime_ops/commands/rollout.py",
    "opsctl/agent_runtime_ops/commands/rollout_verify.py",
    "opsctl/agent_runtime_ops/domain/image_specs.py",
    "opsctl/agent_runtime_ops/domain/runtime_apply.py",
    "opsctl/agent_runtime_ops/domain/runtime_manifest.py",
    "opsctl/agent_runtime_ops/domain/runtime_rollup.py",
    "opsctl/agent_runtime_ops/domain/runtime_targets.py",
    "opsctl/agent_runtime_ops/domain/runtime_truth.py",
    "opsctl/agent_runtime_ops/mcp/handlers/rollout.py",
    "opsctl/agent_runtime_ops/mcp/specs.py",
    "opsctl/agent_runtime_ops/renderer.py",
    "opsctl/agent_runtime_ops/state.py",
)
RETIRED_PRODUCT_MODULES = (
    "opsctl/agent_runtime_ops/commands/artifact.py",
    "opsctl/agent_runtime_ops/commands/retrieval.py",
    "opsctl/agent_runtime_ops/domain/artifact_probe.py",
    "opsctl/agent_runtime_ops/domain/hermes_p1_canary.py",
    "opsctl/agent_runtime_ops/domain/kwrag_runtime_capsule.py",
    "opsctl/agent_runtime_ops/domain/retrieval_contract.py",
    "opsctl/agent_runtime_ops/domain/retrieval_resources.py",
)


def test_active_rollout_path_has_no_product_retrieval_contract_dependency() -> None:
    forbidden = (
        "retrieval_contract",
        "kwrag_runtime_capsule",
        "hermes_p1_canary",
        "JITECH_RETRIEVAL_",
        "agent-runtime.retrieval-",
    )
    for relative in ACTIVE_RUNTIME_FILES:
        source = (ROOT / relative).read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in source, f"{relative} still owns product token {token}"


def test_runtime_profiles_only_mount_the_product_corpus_read_only() -> None:
    profiles = tuple((ROOT / "profiles" / "runtime").glob("*/compose.yml.tpl"))
    assert profiles
    for path in profiles:
        source = path.read_text(encoding="utf-8")
        assert "JITECH_RETRIEVAL_" not in source
        assert "agent-runtime.retrieval-" not in source
        assert "kwrag-p1-state" not in source
        assert "retrieval_attachment_capable" not in source
        assert "read_only: true" in source


def test_wrapper_publication_does_not_reimplement_product_retrieval() -> None:
    source = (ROOT / ".github" / "workflows" / "publish-hermes-wrapper.yml").read_text(
        encoding="utf-8"
    )
    assert "retrieval_label_count" not in source
    assert "agent_runtime_ops.domain.retrieval_contract" not in source
    assert "kwrag-slot status" not in source


def test_cli_and_mcp_expose_only_product_agnostic_image_rollout() -> None:
    sources = (
        (ROOT / "opsctl" / "agent_runtime_ops" / "cli.py").read_text(encoding="utf-8"),
        (ROOT / "opsctl" / "agent_runtime_ops" / "mcp" / "specs.py").read_text(
            encoding="utf-8"
        ),
        (
            ROOT / "opsctl" / "agent_runtime_ops" / "mcp" / "handlers" / "rollout.py"
        ).read_text(encoding="utf-8"),
    )
    for source in sources:
        assert "commands.retrieval" not in source
        assert "cmd_retrieval" not in source
        assert "retrieval_enabled" not in source
        assert "--retrieval-enabled" not in source
        assert "retrieval_runtime_capsule" not in source


def test_opsctl_has_no_kwrag_product_artifact_or_root_action_surface() -> None:
    for relative in RETIRED_PRODUCT_MODULES:
        assert not (ROOT / relative).exists()

    active_sources = (
        (ROOT / "opsctl" / "agent_runtime_ops" / "cli.py"),
        (ROOT / "opsctl" / "agent_runtime_ops" / "root_actions" / "registry.py"),
        (ROOT / "opsctl" / "agent_runtime_ops" / "root_actions" / "execution.py"),
        (ROOT / "install.sh"),
    )
    forbidden = (
        "artifact.probe_kwrag_product",
        "artifact probe kwrag-product",
        "kwrag.candidate_build",
        "kwrag.artifact_finalize",
        "kwrag.runtime_verify",
        "kwrag.network_ensure",
    )
    for path in active_sources:
        source = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in source, f"{path} still exposes {token}"

    historical_kwrag = {
        operation_id
        for operation_id in INVENTORY_COVERAGE.operation_ids
        if operation_id.startswith("kwrag.")
    }
    assert historical_kwrag
    assert historical_kwrag.isdisjoint(DEFAULT_REGISTRY.operation_ids)


def test_operator_docs_do_not_instruct_product_retrieval_projection() -> None:
    sources = (
        (ROOT / "docs" / "DEV_SLOTS.md").read_text(encoding="utf-8"),
        (ROOT / "docs" / "KWRAG_EMBEDDED_RETRIEVAL_ROLLOUT.md").read_text(
            encoding="utf-8"
        ),
    )
    for source in sources:
        assert "--retrieval-enabled" not in source
        assert "--retrieval-runtime-capsule" not in source
        assert "JITECH_RETRIEVAL_" not in source


def test_live_runtime_truth_is_product_retrieval_agnostic() -> None:
    binding = RuntimeBinding(
        instance_id="11111111-1111-4111-8111-111111111111",
        linux_account="oc20",
        public_host="oc20.ji-tech.co.kr",
        family="hermes",
        runtime_class="customer",
        gateway_port=30689,
        bridge_port=30690,
    )
    labels = {
        "com.epicevent.agent-runtime.recipe.schema": "v1",
        "com.epicevent.agent-runtime.family": "hermes",
        "com.epicevent.agent-runtime.product-image": "product",
        "com.epicevent.agent-runtime.runtime-profile.customer": "hermes-runtime-customer",
        "com.epicevent.agent-runtime.runtime-contract.customer": "contract",
        "com.epicevent.agent-runtime.recipe.name": "hermes-runtime",
        "com.epicevent.agent-runtime.recipe.digest": "sha256:" + "1" * 64,
        "com.epicevent.hermes.kwrag.component-digest": "sha256:" + "2" * 64,
    }
    truth = live_image_truth_from_info(
        binding,
        {"Config": {"Image": "wrapper", "Labels": labels}},
        SimpleNamespace(
            public_host=binding.public_host, gateway_port=binding.gateway_port
        ),
    )
    assert all(not key.startswith("retrieval_") for key in truth)
