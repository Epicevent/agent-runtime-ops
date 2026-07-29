from __future__ import annotations

import argparse
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid
from unittest.mock import patch

import agent_runtime_ops.cli as cli
import agent_runtime_ops.commands.document_tools as document_tools
from agent_runtime_ops.cli import build_parser
from agent_runtime_ops.commands.apply import cmd_apply
from agent_runtime_ops.commands.binding import cmd_binding_normalize
from agent_runtime_ops.commands.check import cmd_check
from agent_runtime_ops.commands.diagnostics import cmd_diagnostics_show
from agent_runtime_ops.commands.document_tools import cmd_document_tools_status
from agent_runtime_ops.domain.runtime_truth import live_image_truth_from_info, live_runtime_truth
from agent_runtime_ops.commands.recipe import (
    cmd_recipe_capture_dev,
    cmd_recipe_dev_apply,
    cmd_recipe_dev_status,
    cmd_recipe_validate_canonical,
)
from agent_runtime_ops.commands.rollout import (
    cmd_rollout_image_canary,
    cmd_rollout_image_dev_apply,
    cmd_rollout_image_plan,
    cmd_rollout_image_promote,
    cmd_rollout_status,
)
from agent_runtime_ops.canonical_recipes import load_canonical_recipe
from agent_runtime_ops.domain.image_specs import IMAGE_RECIPE_LABEL_PREFIX, image_recipe_from_wrapper_image
from agent_runtime_ops.domain.runtime_checks import (
    contract_health_endpoints,
    run_live_slot_checks,
    run_workspace_user_nas_docs_listing_check,
    workspace_hermes_config_api_checks,
)
from agent_runtime_ops.domain.retrieval_contract import bind_retrieval_intent
from agent_runtime_ops.domain.runtime_truth import local_canonical_recipe_check_from_truth
from agent_runtime_ops.domain.source_provenance import source_provenance
from agent_runtime_ops.profiles import load_profile
from agent_runtime_ops.routing import RuntimeBinding, dump_runtime_bindings, load_runtime_bindings
from agent_runtime_ops.state import RuntimeTarget
from agent_runtime_ops.yamlio import dump_yaml, load_yaml


def image_ref(digest_char: str) -> str:
    return "ghcr.io/epicevent/openclaw-nas-agent@sha256:" + digest_char * 64


def wrapper_image_ref(repo: str, digest_char: str) -> str:
    return f"ghcr.io/epicevent/{repo}@sha256:" + digest_char * 64


def binding(account: str, family: str, runtime_class: str, gateway: int, bridge: int) -> RuntimeBinding:
    return RuntimeBinding(
        instance_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, account)),
        linux_account=account,
        public_host=f"{account}.ji-tech.co.kr",
        family=family,
        runtime_class=runtime_class,
        gateway_port=gateway,
        bridge_port=bridge,
    )


def hermes_workspace_recipe_digest() -> str:
    return load_canonical_recipe("hermes-workspace").digest


def hermes_runtime_recipe_digest() -> str:
    return load_canonical_recipe("hermes-runtime").digest


def hermes_combined_recipe_digest() -> str:
    return load_canonical_recipe("hermes-combined").digest


def openclaw_control_recipe_digest() -> str:
    return load_canonical_recipe("openclaw-control").digest


def openclaw_image_recipe(*, product_image: str) -> dict[str, object]:
    return {
        "schema": "v1",
        "source": "wrapper_image_labels",
        "canonical_recipe_name": "openclaw-control",
        "canonical_recipe_digest": openclaw_control_recipe_digest(),
        "family": "openclaw",
        "product_image": product_image,
        "product_component": "openclaw-control",
        "wrapper_component": "openclaw-wrapper",
        "runtime_profiles": {
            "customer": "openclaw-customer",
            "dev": "openclaw-dev",
        },
        "runtime_contracts": {
            "customer": "openclaw-gateway-http-18789",
            "dev": "openclaw-gateway-source-http-18789",
        },
        "command_mode": "compose-command",
        "working_dir": "",
        "http_port": "18789",
        "source_output_target": "/app/dist/control-ui",
        "container_nas_root": "/home/node/nas_docs",
        "host_nas_root_template": "/home/{slot}/nas_docs",
        "nas_read_only": "true",
        "nas_mount_propagation": "rslave",
        "nas_child_mount_mode": "host-propagated-cifs",
        "ops_repo_commit": "ec892a32f9ca846f390e2dd19c577dd13d4f044f",
    }


def hermes_image_recipe(
    *,
    product_image: str | None = None,
    product_component: str = "hermes-workspace",
    customer_profile: str = "hermes-workspace-customer",
    dev_profile: str = "hermes-workspace-dev",
) -> dict[str, object]:
    product_image = product_image or wrapper_image_ref("hermes-workspace", "2")
    return {
        "schema": "v1",
        "source": "wrapper_image_labels",
        "canonical_recipe_name": "hermes-workspace",
        "canonical_recipe_digest": hermes_workspace_recipe_digest(),
        "family": "hermes",
        "product_image": product_image,
        "product_component": product_component,
        "wrapper_component": "hermes-wrapper",
        "runtime_profiles": {
            "customer": customer_profile,
            "dev": dev_profile,
        },
        "runtime_contracts": {
            "customer": "hermes-workspace-http-3000",
            "dev": "hermes-workspace-source-http-3000",
        },
        "command_mode": "image-default",
        "working_dir": "/app",
        "http_port": "3000",
        "source_output_target": "/opt/hermes-workspace",
        "container_nas_root": "/workspace/nas_docs",
        "host_nas_root_template": "/home/{slot}/nas_docs",
        "nas_read_only": "true",
        "nas_mount_propagation": "rslave",
        "nas_child_mount_mode": "host-propagated-cifs",
        "ops_repo_commit": "8be9e466c28f821a907a40ab2b0068910c6762cf",
    }


def hermes_runtime_image_recipe(*, product_image: str | None = None) -> dict[str, object]:
    product_image = product_image or wrapper_image_ref("hermes-runtime", "4")
    return {
        "schema": "v1",
        "source": "wrapper_image_labels",
        "canonical_recipe_name": "hermes-runtime",
        "canonical_recipe_digest": hermes_runtime_recipe_digest(),
        "family": "hermes",
        "product_image": product_image,
        "product_component": "hermes-runtime",
        "wrapper_component": "hermes-wrapper",
        "runtime_profiles": {
            "customer": "hermes-runtime-customer",
            "dev": "hermes-runtime-dev",
        },
        "runtime_contracts": {
            "customer": "hermes-runtime-http-3000",
            "dev": "hermes-runtime-source-http-3000",
        },
        "command_mode": "image-default",
        "working_dir": "/opt/hermes-workspace",
        "http_port": "3000",
        "source_output_target": "/opt/hermes-workspace",
        "container_nas_root": "/workspace/nas_docs",
        "host_nas_root_template": "/home/{slot}/nas_docs",
        "nas_read_only": "true",
        "nas_mount_propagation": "rslave",
        "nas_child_mount_mode": "host-propagated-cifs",
        "contract_version": "v2",
        "health_endpoints": {
            "workspace": "http://127.0.0.1:3000/",
            "gateway": "http://127.0.0.1:8642/health",
            "dashboard": "http://127.0.0.1:9119/api/status",
        },
        "ops_repo_commit": "8be9e466c28f821a907a40ab2b0068910c6762cf",
    }


def hermes_combined_image_recipe(*, product_image: str | None = None) -> dict[str, object]:
    product_image = product_image or image_ref("1")
    return {
        "schema": "v1",
        "source": "runtime_manifest_test",
        "canonical_recipe_name": "hermes-combined",
        "canonical_recipe_digest": hermes_combined_recipe_digest(),
        "family": "hermes",
        "product_image": product_image,
        "product_component": "combined-runtime",
        "wrapper_component": "hermes-wrapper",
        "runtime_profiles": {
            "customer": "hermes-customer",
            "dev": "hermes-dev",
        },
        "runtime_contracts": {
            "customer": "hermes-workspace-http-3000",
            "dev": "hermes-workspace-source-http-3000",
        },
        "command_mode": "gateway-run",
        "working_dir": "/opt/data/home",
        "http_port": "3000",
        "source_output_target": "/opt/hermes-workspace",
        "container_nas_root": "/workspace/nas_docs",
        "host_nas_root_template": "/home/{slot}/nas_docs",
        "nas_read_only": "true",
        "nas_mount_propagation": "rslave",
        "nas_child_mount_mode": "host-propagated-cifs",
        "ops_repo_commit": "8be9e466c28f821a907a40ab2b0068910c6762cf",
    }


def hermes_recipe_labels(**overrides: str) -> dict[str, str]:
    product_image = overrides.pop("product_image", wrapper_image_ref("hermes-workspace", "2"))
    values = {
        "recipe.schema": "v1",
        "recipe.name": "hermes-workspace",
        "recipe.digest": hermes_workspace_recipe_digest(),
        "family": "hermes",
        "product-image": product_image,
        "product-component": "hermes-workspace",
        "wrapper-component": "hermes-wrapper",
        "runtime-profile.customer": "hermes-workspace-customer",
        "runtime-profile.dev": "hermes-workspace-dev",
        "runtime-contract.customer": "hermes-workspace-http-3000",
        "runtime-contract.dev": "hermes-workspace-source-http-3000",
        "command-mode": "image-default",
        "working-dir": "/app",
        "http-port": "3000",
        "source-output-target": "/opt/hermes-workspace",
        "nas.container-root": "/workspace/nas_docs",
        "nas.host-root-template": "/home/{slot}/nas_docs",
        "nas.read-only": "true",
        "nas.propagation": "rslave",
        "nas.child-mount-mode": "host-propagated-cifs",
        "ops-repo-commit": "8be9e466c28f821a907a40ab2b0068910c6762cf",
    }
    values.update(overrides)
    return {IMAGE_RECIPE_LABEL_PREFIX + key: value for key, value in values.items()}


def hermes_runtime_recipe_labels(**overrides: str) -> dict[str, str]:
    product_image = overrides.pop("product_image", wrapper_image_ref("hermes-runtime", "4"))
    values = {
        "recipe.schema": "v1",
        "recipe.name": "hermes-runtime",
        "recipe.digest": hermes_runtime_recipe_digest(),
        "family": "hermes",
        "product-image": product_image,
        "product-component": "hermes-runtime",
        "wrapper-component": "hermes-wrapper",
        "runtime-profile.customer": "hermes-runtime-customer",
        "runtime-profile.dev": "hermes-runtime-dev",
        "runtime-contract.customer": "hermes-runtime-http-3000",
        "runtime-contract.dev": "hermes-runtime-source-http-3000",
        "command-mode": "image-default",
        "working-dir": "/opt/hermes-workspace",
        "http-port": "3000",
        "contract.version": "v2",
        "source-output-target": "/opt/hermes-workspace",
        "nas.container-root": "/workspace/nas_docs",
        "nas.host-root-template": "/home/{slot}/nas_docs",
        "nas.read-only": "true",
        "nas.propagation": "rslave",
        "nas.child-mount-mode": "host-propagated-cifs",
        "health.endpoints": "dashboard=http://127.0.0.1:9119/api/status,gateway=http://127.0.0.1:8642/health,workspace=http://127.0.0.1:3000/",
        "health.endpoints.json": '{"dashboard":"http://127.0.0.1:9119/api/status","gateway":"http://127.0.0.1:8642/health","workspace":"http://127.0.0.1:3000/"}',
        "ops-repo-commit": "8be9e466c28f821a907a40ab2b0068910c6762cf",
    }
    values.update(overrides)
    return {IMAGE_RECIPE_LABEL_PREFIX + key: value for key, value in values.items()}


def openclaw_recipe_labels(**overrides: str) -> dict[str, str]:
    product_image = overrides.pop("product_image", wrapper_image_ref("openclaw-jitech", "8"))
    values = {
        "recipe.schema": "v1",
        "recipe.name": "openclaw-control",
        "recipe.digest": openclaw_control_recipe_digest(),
        "family": "openclaw",
        "product-image": product_image,
        "product-component": "openclaw-control",
        "wrapper-component": "openclaw-wrapper",
        "runtime-profile.customer": "openclaw-customer",
        "runtime-profile.dev": "openclaw-dev",
        "runtime-contract.customer": "openclaw-gateway-http-18789",
        "runtime-contract.dev": "openclaw-gateway-source-http-18789",
        "command-mode": "compose-command",
        "working-dir": "",
        "http-port": "18789",
        "source-output-target": "/app/dist/control-ui",
        "nas.container-root": "/home/node/nas_docs",
        "nas.host-root-template": "/home/{slot}/nas_docs",
        "nas.read-only": "true",
        "nas.propagation": "rslave",
        "nas.child-mount-mode": "host-propagated-cifs",
        "ops-repo-commit": "ec892a32f9ca846f390e2dd19c577dd13d4f044f",
    }
    values.update(overrides)
    return {IMAGE_RECIPE_LABEL_PREFIX + key: value for key, value in values.items()}


def write_runtime_manifest(
    root: Path,
    *,
    slot: str,
    family: str,
    runtime_class: str,
    runtime_profile: str,
    wrapper_image: str,
    product_image: str,
    image_recipe: dict[str, object],
) -> None:
    manifest_dir = root / "runtime" / slot
    manifest_dir.mkdir(parents=True, exist_ok=True)
    (manifest_dir / "manifest.yaml").write_text(
        dump_yaml(
            {
                "schema_version": 1,
                "target": slot,
                "linux_account": slot,
                "image_name": "direct-image",
                "family": family,
                "runtime_class": runtime_class,
                "runtime_profile": runtime_profile,
                "wrapper_image": wrapper_image,
                "product_image": product_image,
                "wrapper_image_digest": wrapper_image.rsplit("@", 1)[-1],
                "product_image_digest": product_image.rsplit("@", 1)[-1],
                "recipe": {
                    "mode": "wrapped_product_image",
                    "product_component": image_recipe["product_component"],
                    "wrapper_component": image_recipe["wrapper_component"],
                    "components": {
                        "product_image": product_image,
                        "wrapper_image": wrapper_image,
                        "product_component": image_recipe["product_component"],
                        "wrapper_component": image_recipe["wrapper_component"],
                        "canonical_recipe_name": image_recipe["canonical_recipe_name"],
                        "canonical_recipe_digest": image_recipe["canonical_recipe_digest"],
                    },
                    "image_recipe": image_recipe,
                    "canonical_recipe_name": image_recipe["canonical_recipe_name"],
                    "canonical_recipe_digest": image_recipe["canonical_recipe_digest"],
                },
            }
        ),
        encoding="utf-8",
    )


def write_slot_registry(root: Path, slots: list[str]) -> None:
    default_ports = {
        "oc3": (28989, 28990),
        "oc4": (29089, 29090),
        "oc20": (30689, 30690),
        "dev-oc": (30789, 30790),
        "dev-hermess": (30889, 30890),
    }
    slot_family = {
        "oc3": "openclaw",
        "oc4": "openclaw",
        "dev-oc": "openclaw",
        "oc20": "hermes",
        "dev-hermess": "hermes",
    }
    runtime_class = {
        "oc3": "customer",
        "oc4": "customer",
        "oc20": "customer",
        "dev-oc": "dev",
        "dev-hermess": "dev",
    }
    bindings = []
    for index, slot in enumerate(slots):
        gateway_port, bridge_port = default_ports.get(slot, (32000 + index * 2, 32001 + index * 2))
        bindings.append(binding(slot, slot_family.get(slot, "openclaw"), runtime_class.get(slot, "customer"), gateway_port, bridge_port))
    (root / "runtime-bindings.json").write_text(dump_runtime_bindings(bindings), encoding="utf-8")


def write_hermes_state(root: Path) -> None:
    write_slot_registry(root, ["oc20", "dev-hermess"])
    product_image = image_ref("1")
    wrapper_image = wrapper_image_ref("agent-runtime-hermes", "1")
    write_runtime_manifest(
        root,
        slot="oc20",
        family="hermes",
        runtime_class="customer",
        runtime_profile="hermes-customer",
        wrapper_image=wrapper_image,
        product_image=product_image,
        image_recipe=hermes_combined_image_recipe(product_image=product_image),
    )
    write_runtime_manifest(
        root,
        slot="dev-hermess",
        family="hermes",
        runtime_class="dev",
        runtime_profile="hermes-dev",
        wrapper_image=wrapper_image,
        product_image=product_image,
        image_recipe=hermes_combined_image_recipe(product_image=product_image),
    )


def write_state(root: Path) -> None:
    write_slot_registry(root, ["oc3", "oc4", "dev-oc"])
    product_image = wrapper_image_ref("openclaw-jitech", "1")
    wrapper_image = wrapper_image_ref("agent-runtime-openclaw", "1")
    write_runtime_manifest(
        root,
        slot="oc3",
        family="openclaw",
        runtime_class="customer",
        runtime_profile="openclaw-customer",
        wrapper_image=wrapper_image,
        product_image=product_image,
        image_recipe=openclaw_image_recipe(product_image=product_image),
    )
    write_runtime_manifest(
        root,
        slot="oc4",
        family="openclaw",
        runtime_class="customer",
        runtime_profile="openclaw-customer",
        wrapper_image=wrapper_image,
        product_image=product_image,
        image_recipe=openclaw_image_recipe(product_image=product_image),
    )
    write_runtime_manifest(
        root,
        slot="dev-oc",
        family="openclaw",
        runtime_class="dev",
        runtime_profile="openclaw-dev",
        wrapper_image=wrapper_image,
        product_image=product_image,
        image_recipe=openclaw_image_recipe(product_image=product_image),
    )
class CliReleaseRolloutTests(unittest.TestCase):
    def test_rollout_status_uses_runtime_manifests_not_legacy_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hermes_state(root)
            wrapper_image = wrapper_image_ref("agent-runtime-hermes", "3")
            product_image = wrapper_image_ref("hermes-workspace", "2")
            manifest_dir = root / "runtime" / "oc20"
            manifest_dir.mkdir(parents=True, exist_ok=True)
            (manifest_dir / "manifest.yaml").write_text(
                dump_yaml(
                    {
                        "schema_version": 1,
                        "target": "oc20",
                        "linux_account": "oc20",
                        "image_name": "direct-image",
                        "family": "hermes",
                        "runtime_class": "customer",
                        "runtime_profile": "hermes-workspace-customer",
                        "wrapper_image": wrapper_image,
                        "product_image": product_image,
                        "recipe": {
                            "canonical_recipe_name": "hermes-workspace",
                            "canonical_recipe_digest": hermes_workspace_recipe_digest(),
                        },
                    }
                ),
                encoding="utf-8",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = cmd_rollout_status(argparse.Namespace(state_root=str(root), family="hermes"))

            text = output.getvalue()
            self.assertEqual(rc, 0, text)
            self.assertIn("status_source=runtime_manifests", text)
            self.assertIn("binding_targets=oc20,dev-hermess", text)
            self.assertIn("runtime_manifest_direct_image_targets=oc20,dev-hermess", text)
            self.assertIn("runtime_manifest_missing_targets=", text)
            self.assertIn("runtime_manifest_canonical_recipe_names=hermes-combined,hermes-workspace", text)
            self.assertNotIn("legacy_rollout_state", text)

    def test_release_state_rollout_commands_do_not_exist_on_public_or_internal_surface(self) -> None:
        parser = build_parser()
        rollout = next(action for action in parser._actions if action.dest == "command").choices["rollout"]
        rollout_choices = next(action for action in rollout._actions if action.dest == "rollout_command").choices

        self.assertEqual(
            set(rollout_choices),
            {"status", "image-plan", "image-dev-apply", "image-canary", "image-promote", "verify"},
        )
        self.assertNotIn("release", next(action for action in parser._actions if action.dest == "command").choices)
        for name in (
            "cmd_release_import",
            "cmd_release_add",
            "cmd_release_promote",
            "cmd_rollout_plan",
            "cmd_rollout_dev_plan",
            "cmd_rollout_dev_apply",
            "cmd_rollout_canary",
            "cmd_rollout_promote",
            "cmd_rollout_rollback_canary",
        ):
            self.assertFalse(hasattr(cli, name), name)

    def test_apply_force_recreates_compose_container(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            runtime_dir = root / "home" / "oc3" / "openclaw"
            runtime_dir.mkdir(parents=True)
            (runtime_dir / ".env").write_text(
                "RUNTIME_UID=993\nRUNTIME_GID=980\nDATA_GID=980\n",
                encoding="utf-8",
            )
            calls: list[list[str]] = []

            def fake_run(command: list[str], cwd: Path, timeout: int = 20) -> subprocess.CompletedProcess[str]:
                calls.append(command)
                return subprocess.CompletedProcess(command, 0, "", "")

            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.apply._is_root", return_value=True),
                patch("agent_runtime_ops.domain.runtime_apply.slot_runtime_dir", return_value=runtime_dir),
                patch("agent_runtime_ops.domain.runtime_apply.FINAL_WORKSPACE_GUIDANCE_STABILIZE_DELAYS_SECONDS", []),
                patch("agent_runtime_ops.domain.runtime_apply.ensure_runtime_workspace_guidance", return_value={"workspace_guidance": "present"}) as guidance,
                patch("agent_runtime_ops.domain.runtime_apply.ensure_nas_workspace_dir", return_value=runtime_dir / "workspace"),
                patch("agent_runtime_ops.domain.runtime_apply.run_text_cwd", side_effect=fake_run),
                patch(
                    "agent_runtime_ops.domain.runtime_apply.run_live_slot_checks_with_wait",
                    return_value=[(True, "live_runtime_recreated", "ok")],
                ),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_apply(argparse.Namespace(state_root=str(root), slot="oc3", allow_first_apply=True))

            self.assertEqual(rc, 0, output.getvalue())
            self.assertIn("workspace_guidance=present", output.getvalue())
            self.assertIn("post_workspace_guidance=present", output.getvalue())
            self.assertIn("final_workspace_guidance=present", output.getvalue())
            self.assertEqual(guidance.call_count, 3)
            up_calls = [call for call in calls if "up" in call]
            self.assertEqual(len(up_calls), 1)
            self.assertIn("--force-recreate", up_calls[0])
            self.assertIn("--remove-orphans", up_calls[0])

    def test_apply_writes_diagnostics_before_live_failure_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            runtime_dir = root / "home" / "oc3" / "openclaw"
            runtime_dir.mkdir(parents=True)
            (runtime_dir / ".env").write_text(
                "RUNTIME_UID=993\nRUNTIME_GID=980\nDATA_GID=980\n",
                encoding="utf-8",
            )
            events: list[str] = []
            diag_dir = root / "runtime-recovery" / "oc3" / "backups" / "failed-container"

            def fake_restore(*args: object, **kwargs: object) -> tuple[bool, str]:
                events.append("restore")
                return True, "rollback_applied"

            def fake_diagnostics(*args: object, **kwargs: object) -> Path:
                events.append("diagnostics")
                return diag_dir

            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.apply._is_root", return_value=True),
                patch("agent_runtime_ops.domain.runtime_apply.slot_runtime_dir", return_value=runtime_dir),
                patch("agent_runtime_ops.domain.runtime_apply.FINAL_WORKSPACE_GUIDANCE_STABILIZE_DELAYS_SECONDS", []),
                patch("agent_runtime_ops.domain.runtime_apply.ensure_runtime_workspace_guidance", return_value={"workspace_guidance": "present"}),
                patch("agent_runtime_ops.domain.runtime_apply.ensure_nas_workspace_dir", return_value=runtime_dir / "workspace"),
                patch(
                    "agent_runtime_ops.domain.runtime_apply.run_text_cwd",
                    return_value=subprocess.CompletedProcess(["docker"], 0, "", ""),
                ),
                patch(
                    "agent_runtime_ops.domain.runtime_apply.run_live_slot_checks_with_wait",
                    return_value=[(False, "live_backend_http_smoke_ok", "connection reset")],
                ),
                patch("agent_runtime_ops.domain.runtime_apply.write_failed_container_diagnostics", side_effect=fake_diagnostics),
                patch("agent_runtime_ops.domain.runtime_apply.restore_backup", side_effect=fake_restore),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_apply(argparse.Namespace(state_root=str(root), slot="oc3", allow_first_apply=True))

            self.assertEqual(rc, 1)
            self.assertEqual(events, ["diagnostics", "restore"])
            self.assertIn(f"failure_diagnostics_dir={diag_dir}", output.getvalue())

    def test_diagnostics_show_prints_redacted_failure_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diag_dir = (
                root
                / "runtime-recovery"
                / "oc3"
                / "backups"
                / "20260609T000000+0900"
                / "failed-container"
            )
            diag_dir.mkdir(parents=True)
            secret = "server-secret-value"
            (diag_dir / "lookup.txt").write_text("container=abc123\nlookup=label\n", encoding="utf-8")
            inspect_stdout = [
                {
                    "Id": "abc123456789",
                    "Name": "/agent-runtime-oc3-openclaw-gateway-1",
                    "State": {"Running": True, "Pid": 1234, "ExitCode": 0, "Health": {"Status": "none"}},
                    "Config": {
                        "Image": "ghcr.io/epicevent/agent-runtime-hermes@sha256:" + "a" * 64,
                        "Entrypoint": ["/init", "/opt/hermes/docker/main-wrapper.sh"],
                        "Cmd": ["gateway", "run"],
                        "WorkingDir": "/opt/data/home",
                        "Env": [f"API_SERVER_KEY={secret}"],
                    },
                }
            ]
            (diag_dir / "inspect.json").write_text(
                json.dumps({"returncode": 0, "stdout": json.dumps(inspect_stdout), "stderr": ""}),
                encoding="utf-8",
            )
            (diag_dir / "logs.txt").write_text(
                json.dumps({"returncode": 0, "stdout": f"API_SERVER_KEY={secret}\nready\n", "stderr": ""}),
                encoding="utf-8",
            )
            (diag_dir / "ports.txt").write_text(
                json.dumps({"returncode": 0, "stdout": "3000/tcp -> 127.0.0.1:30689\n", "stderr": ""}),
                encoding="utf-8",
            )
            (diag_dir / "top.txt").write_text(
                json.dumps({"returncode": 0, "stdout": "PID CMD\n1234 hermes gateway run\n", "stderr": ""}),
                encoding="utf-8",
            )
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.diagnostics._is_root", return_value=True),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_diagnostics_show(
                    argparse.Namespace(
                        state_root=str(root),
                        slot="oc3",
                        dir=str(diag_dir),
                        tail=20,
                    )
                )

            text = output.getvalue()
            self.assertEqual(rc, 0, text)
            self.assertIn("diagnostics_status=ok", text)
            self.assertIn("container_cmd=gateway run", text)
            self.assertIn("ports_tail_begin", text)
            self.assertNotIn(secret, text)
            self.assertIn("API_SERVER_KEY=<redacted>", text)

    def test_recipe_apply_dev_records_source_output_without_image_bake(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            source_output = root / "openclawdev" / "dist" / "control-ui"
            source_output.mkdir(parents=True)
            (source_output / "index.html").write_text("ok", encoding="utf-8")
            runtime_dir = root / "home" / "dev-oc" / "openclaw"
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.recipe._is_root", return_value=True),
                patch("agent_runtime_ops.commands.recipe._ensure_dev_runtime_dir", return_value=runtime_dir),
                patch("agent_runtime_ops.commands.recipe.slot_uid_gid", return_value=(1000, 1000)),
                patch("agent_runtime_ops.host.account_files.os.chown"),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_recipe_dev_apply(
                    argparse.Namespace(
                        state_root=str(root),
                        slot="dev-oc",
                        recipe_name="openclaw-ui",
                        source_output=str(source_output),
                        sync_from=None,
                        build_command="npm run build",
                        allow_first_apply=False,
                        no_apply=True,
                    )
                )
            self.assertEqual(rc, 0, output.getvalue())
            env_text = (runtime_dir / ".env").read_text(encoding="utf-8")
            self.assertIn(f"SOURCE_OUTPUT={source_output}", env_text)
            self.assertIn("OPENCLAW_RUNTIME_FAMILY=openclaw", env_text)
            recipe = load_yaml(root / "dev-recipes.yaml")["recipes"]["dev-oc"]
            self.assertEqual(recipe["recipe_name"], "openclaw-ui")
            self.assertEqual(recipe["source_output"], str(source_output))
            self.assertEqual(recipe["build_command"], "npm run build")
            self.assertEqual(recipe["source_provenance"]["status"], "no_git")

    def test_source_provenance_marks_git_worktree_safe_for_cross_account_read(self) -> None:
        source = Path("/home/openclawdev/src/hermes-workspace-jitech")
        safe_source = str(source.resolve(strict=False))
        calls: list[list[str]] = []

        def fake_run(command: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            if command[-3:] == ["rev-parse", "--show-toplevel", "HEAD"]:
                return subprocess.CompletedProcess(command, 0, f"{safe_source}\n0123456789abcdef0123456789abcdef01234567\n", "")
            if command[-2:] == ["status", "--porcelain"]:
                return subprocess.CompletedProcess(command, 0, "", "")
            if command[-3:] == ["remote", "get-url", "origin"]:
                return subprocess.CompletedProcess(command, 0, "https://token@example.com/org/repo.git\n", "")
            return subprocess.CompletedProcess(command, 1, "", "unexpected")

        with patch("agent_runtime_ops.domain.source_provenance._run_text", side_effect=fake_run):
            provenance = source_provenance(source)

        self.assertEqual(provenance["status"], "git")
        self.assertEqual(provenance["git_dirty"], False)
        self.assertEqual(provenance["git_remote_origin"], "https://<redacted>@example.com/org/repo.git")
        self.assertTrue(calls)
        for command in calls:
            self.assertEqual(command[:4], ["git", "-c", f"safe.directory={safe_source}", "-C"])
            self.assertEqual(command[4], safe_source)

    def test_install_sudoers_allows_capture_dev_and_live_check_argument_orders(self) -> None:
        text = Path("install.sh").read_text(encoding="utf-8")
        self.assertIn(" check --live *", text)
        self.assertIn(" check * --live", text)
        self.assertIn(" check * --live *", text)
        self.assertIn(" runtime config-sanitize *", text)
        self.assertIn(" runtime model-catalog *", text)
        self.assertIn(" runtime model-attest *", text)
        self.assertIn(" document-tools status *", text)
        self.assertIn(" recipe apply-dev *", text)
        self.assertIn(" recipe capture-dev *", text)

    def test_runtime_model_attest_is_a_first_class_cli_command(self) -> None:
        args = build_parser().parse_args(["runtime", "model-attest", "oc20"])
        self.assertEqual(args.command, "runtime")
        self.assertEqual(args.runtime_command, "model-attest")
        self.assertEqual(args.slot, "oc20")
        self.assertEqual(args.func.__name__, "cmd_runtime_model_attest")

    def test_document_tools_baseline_status_requires_hwp_helper_and_aliases(self) -> None:
        data = {
            "cmd_openclaw_hwp_text": "yes",
            "cmd_openclaw_document_tools": "yes",
            "cmd_read_hwp": "yes",
            "cmd_hwp_read": "yes",
            "cmd_hwp2txt": "yes",
            "cmd_hwp5txt": "yes",
            "cmd_hwp5proc": "yes",
            "cmd_libreoffice": "yes",
            "cmd_soffice": "yes",
            "python_olefile": "yes",
        }
        self.assertEqual(document_tools._document_tool_payload_status(data), "baseline")
        self.assertEqual(document_tools._hwp_readiness(data), "full")

        missing_alias = dict(data)
        missing_alias["cmd_hwp2txt"] = "no"
        self.assertEqual(document_tools._document_tool_payload_status(missing_alias), "partial")
        self.assertEqual(document_tools._hwp_readiness(missing_alias), "partial")

    def test_document_tools_failure_reasons_require_full_baseline_and_guidance(self) -> None:
        result = {f"cmd_{key}": "yes" for key in document_tools._DOCUMENT_TOOL_REQUIRED_COMMAND_KEYS}
        result.update(
            {
                "probe_status": "ok",
                "document_tool_payload": "baseline",
                "hwp_readiness": "full",
                "locale_utf8": "yes",
                "locale_ko_kr": "yes",
                "korean_fonts": "yes",
                "tesseract_kor": "yes",
                "python_document_modules": "yes",
                "workspace_guidance_status": "present",
            }
        )
        self.assertEqual(document_tools._document_tools_failure_reasons(result), [])

        result["cmd_openclaw_hwp_text"] = "no"
        self.assertIn("missing_commands=openclaw_hwp_text", ";".join(document_tools._document_tools_failure_reasons(result)))

    def test_workspace_guidance_status_is_family_specific(self) -> None:
        hermes = {
            "hermes_agents_guidance": "yes",
            "hermes_claude_guidance": "yes",
            "hermes_gemini_guidance": "yes",
        }
        openclaw = {
            "openclaw_agents_guidance": "yes",
            "openclaw_claude_guidance": "yes",
            "openclaw_gemini_guidance": "yes",
        }
        self.assertEqual(document_tools._workspace_guidance_status("hermes", hermes), "present")
        self.assertEqual(document_tools._workspace_guidance_status("openclaw", openclaw), "present")
        openclaw["openclaw_gemini_guidance"] = "no"
        self.assertEqual(document_tools._workspace_guidance_status("openclaw", openclaw), "missing")

    def test_document_tools_status_all_uses_runtime_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)

            def fake_status(slot: str, state_root: Path) -> dict[str, str]:
                result = {f"cmd_{key}": "yes" for key in document_tools._DOCUMENT_TOOL_REQUIRED_COMMAND_KEYS}
                result.update({
                    "target": slot,
                    "family": "openclaw",
                    "runtime_class": "customer",
                    "runtime_profile": "openclaw-customer",
                    "canonical_recipe_name": "openclaw-control",
                    "probe_status": "ok",
                    "document_tool_payload": "baseline",
                    "hwp_readiness": "full",
                    "document_tools_ready": "yes",
                    "workspace_guidance_status": "present",
                    "locale_utf8": "yes",
                    "locale_ko_kr": "yes",
                    "korean_fonts": "yes",
                    "tesseract_kor": "yes",
                    "python_document_modules": "yes",
                    "python_olefile": "yes",
                })
                return result

            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.document_tools._is_root", return_value=True),
                patch("agent_runtime_ops.commands.document_tools._document_tools_status_for_slot", side_effect=fake_status) as status_for_slot,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_document_tools_status(argparse.Namespace(state_root=str(root), slot=None, all=True))

            text = output.getvalue()
            self.assertEqual(rc, 0, text)
            self.assertIn("target=oc3", text)
            self.assertIn("document_tool_payload=baseline", text)
            self.assertIn("document_tools_status=ok", text)
            self.assertGreaterEqual(status_for_slot.call_count, 2)

    def test_document_tools_status_for_slot_reads_runtime_labels_after_module_split(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            labels = openclaw_recipe_labels(product_image=wrapper_image_ref("openclaw-jitech", "8"))
            inspect_info = {
                "State": {"Running": False, "Pid": 0},
                "Config": {
                    "Image": wrapper_image_ref("agent-runtime-openclaw", "9"),
                    "Labels": labels,
                },
            }
            inspect_result = subprocess.CompletedProcess(
                ["docker", "inspect", "container-1"],
                0,
                stdout=json.dumps([inspect_info]),
                stderr="",
            )
            apache_route = argparse.Namespace(public_host="oc3.ji-tech.co.kr", gateway_port=30689)

            with (
                patch("agent_runtime_ops.commands.document_tools.parse_apache_route", return_value=apache_route),
                patch("agent_runtime_ops.commands.document_tools.find_gateway_container_by_binding", return_value=("container-1", "instance_label")),
                patch("agent_runtime_ops.commands.document_tools.shutil.which", return_value="/usr/bin/tool"),
                patch("agent_runtime_ops.commands.document_tools._run_text", return_value=inspect_result),
            ):
                result = document_tools._document_tools_status_for_slot("oc3", root)

            self.assertEqual(result["probe_status"], "not_running")
            self.assertEqual(result["runtime_profile"], "openclaw-customer")
            self.assertEqual(result["canonical_recipe_name"], "openclaw-control")

    def test_recipe_status_reports_missing_recipe_for_dev_slot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = cmd_recipe_dev_status(argparse.Namespace(state_root=str(root), slot="dev-oc"))
            self.assertEqual(rc, 0, output.getvalue())
            self.assertIn("recipe_status=missing", output.getvalue())

    def test_recipe_validate_canonical_reports_digest(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rc = cmd_recipe_validate_canonical(
                argparse.Namespace(name="hermes-workspace", emit_build_args=False)
            )
        text = output.getvalue()
        self.assertEqual(rc, 0, text)
        self.assertIn("canonical_recipe_status=ok", text)
        self.assertIn(f"canonical_recipe_digest={hermes_workspace_recipe_digest()}", text)

    def test_recipe_validate_canonical_emits_wrapper_build_args(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rc = cmd_recipe_validate_canonical(
                argparse.Namespace(name="hermes-workspace", emit_build_args=True)
            )
        text = output.getvalue()
        self.assertEqual(rc, 0, text)
        self.assertIn("CANONICAL_RECIPE_NAME=hermes-workspace", text)
        self.assertIn(f"CANONICAL_RECIPE_DIGEST={hermes_workspace_recipe_digest()}", text)
        self.assertIn("RUNTIME_PROFILE_DEV=hermes-workspace-dev", text)
        self.assertIn("RUNTIME_SOURCE_OUTPUT_TARGET=/opt/hermes-workspace", text)
        self.assertIn("RUNTIME_NAS_CONTAINER_ROOT=/workspace/nas_docs", text)
        self.assertIn("RUNTIME_NAS_HOST_ROOT_TEMPLATE=/home/{slot}/nas_docs", text)
        self.assertIn("RUNTIME_NAS_READ_ONLY=true", text)
        self.assertIn("RUNTIME_NAS_PROPAGATION=rslave", text)
        self.assertIn("RUNTIME_NAS_CHILD_MOUNT_MODE=host-propagated-cifs", text)

    def test_recipe_validate_canonical_hermes_runtime_emits_v2_health_args(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rc = cmd_recipe_validate_canonical(
                argparse.Namespace(name="hermes-runtime", emit_build_args=True)
            )
        text = output.getvalue()
        self.assertEqual(rc, 0, text)
        self.assertIn("CANONICAL_RECIPE_NAME=hermes-runtime", text)
        self.assertIn(f"CANONICAL_RECIPE_DIGEST={hermes_runtime_recipe_digest()}", text)
        self.assertIn("PRODUCT_COMPONENT=hermes-runtime", text)
        self.assertIn("RUNTIME_PROFILE_DEV=hermes-runtime-dev", text)
        self.assertIn("RUNTIME_CONTRACT_VERSION=v2", text)
        self.assertIn(
            "RUNTIME_HEALTH_ENDPOINTS=dashboard=http://127.0.0.1:9119/api/status,gateway=http://127.0.0.1:8642/health,workspace=http://127.0.0.1:3000/",
            text,
        )
        self.assertIn(
            'RUNTIME_HEALTH_ENDPOINTS_JSON=\'{"dashboard":"http://127.0.0.1:9119/api/status","gateway":"http://127.0.0.1:8642/health","workspace":"http://127.0.0.1:3000/"}\'',
            text,
        )

    def test_recipe_capture_dev_requires_clean_live_v2_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_slot_registry(root, ["dev-hermess"])
            source_output = root / "hermesdev" / "dist"
            source_output.mkdir(parents=True)
            product_image = wrapper_image_ref("hermes-runtime", "4")
            wrapper_image = wrapper_image_ref("agent-runtime-hermes", "5")
            image_spec = {
                "family": "hermes",
                "image_name": "direct-image",
                "wrapper_image": wrapper_image,
                "product_image": product_image,
                "digest": "sha256:" + "5" * 64,
                "product_digest": "sha256:" + "4" * 64,
                "mode": "wrapped_product_image",
                "image_recipe": hermes_runtime_image_recipe(product_image=product_image),
            }
            route = next(route for route in load_runtime_bindings(root) if route.linux_account == "dev-hermess")
            desired = RuntimeTarget(
                target="dev-hermess",
                family="hermes",
                runtime_class="dev",
                image_name="direct-image",
                image_spec=image_spec,
                runtime_profile="hermes-runtime-dev",
                route=route,
            )
            (root / "dev-recipes.yaml").write_text(
                dump_yaml(
                    {
                        "recipes": {
                            "dev-hermess": {
                                "recipe_name": "hermes-runtime",
                                "source_output": str(source_output),
                                "source_provenance": {
                                    "status": "git",
                                    "git_head": "0123456789abcdef0123456789abcdef01234567",
                                    "git_dirty": False,
                                },
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            output = io.StringIO()
            stored_head = "0123456789abcdef0123456789abcdef01234567"
            with (
                patch("agent_runtime_ops.commands.recipe._is_root", return_value=True),
                patch(
                    "agent_runtime_ops.commands.recipe._desired_from_live_image_truth",
                    return_value=(desired, load_profile("hermes-runtime-dev")),
                ),
                patch(
                    "agent_runtime_ops.commands.recipe._run_live_slot_checks",
                    return_value=[
                        (True, "live_container_image_matches_spec", wrapper_image),
                        (True, "live_internal_http_workspace_ok", "url=http://127.0.0.1:3000/"),
                        (True, "live_internal_http_gateway_ok", "url=http://127.0.0.1:8642/health"),
                        (True, "live_internal_http_dashboard_ok", "url=http://127.0.0.1:9119/api/status"),
                    ],
                ),
                patch(
                    "agent_runtime_ops.domain.source_provenance.source_provenance",
                    return_value={
                        "path": str(source_output),
                        "status": "git",
                        "git_head": stored_head,
                        "git_dirty": False,
                        "git_toplevel": str(source_output.parent),
                        "git_remote_origin": "",
                    },
                ),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_recipe_capture_dev(
                    argparse.Namespace(state_root=str(root), slot="dev-hermess", recipe_name="hermes-runtime")
                )

            text = output.getvalue()
            self.assertEqual(rc, 0, text)
            self.assertIn("recipe_capture_dev_status=ok", text)
            self.assertIn("contract_version=v2", text)
            self.assertIn("source_git_dirty=False", text)
            self.assertIn(f"source_git_head_at_apply={stored_head}", text)
            self.assertIn("secret_value_printed=no", text)

    def test_recipe_capture_dev_rejects_current_dirty_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_slot_registry(root, ["dev-hermess"])
            source_output = root / "hermesdev" / "dist"
            source_output.mkdir(parents=True)
            product_image = wrapper_image_ref("hermes-runtime", "4")
            wrapper_image = wrapper_image_ref("agent-runtime-hermes", "5")
            image_spec = {
                "family": "hermes",
                "image_name": "direct-image",
                "wrapper_image": wrapper_image,
                "product_image": product_image,
                "digest": "sha256:" + "5" * 64,
                "product_digest": "sha256:" + "4" * 64,
                "mode": "wrapped_product_image",
                "image_recipe": hermes_runtime_image_recipe(product_image=product_image),
            }
            route = next(route for route in load_runtime_bindings(root) if route.linux_account == "dev-hermess")
            desired = RuntimeTarget(
                target="dev-hermess",
                family="hermes",
                runtime_class="dev",
                image_name="direct-image",
                image_spec=image_spec,
                runtime_profile="hermes-runtime-dev",
                route=route,
            )
            stored_head = "0123456789abcdef0123456789abcdef01234567"
            (root / "dev-recipes.yaml").write_text(
                dump_yaml(
                    {
                        "recipes": {
                            "dev-hermess": {
                                "recipe_name": "hermes-runtime",
                                "source_output": str(source_output),
                                "source_provenance": {
                                    "status": "git",
                                    "git_head": stored_head,
                                    "git_dirty": False,
                                },
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.recipe._is_root", return_value=True),
                patch(
                    "agent_runtime_ops.commands.recipe._desired_from_live_image_truth",
                    return_value=(desired, load_profile("hermes-runtime-dev")),
                ),
                patch(
                    "agent_runtime_ops.domain.source_provenance.source_provenance",
                    return_value={
                        "path": str(source_output),
                        "status": "git",
                        "git_head": stored_head,
                        "git_dirty": True,
                        "git_toplevel": str(source_output.parent),
                        "git_remote_origin": "",
                    },
                ),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_recipe_capture_dev(
                    argparse.Namespace(state_root=str(root), slot="dev-hermess", recipe_name="hermes-runtime")
                )

            text = output.getvalue()
            self.assertEqual(rc, 1, text)
            self.assertIn("recipe_capture_dev_status=fail", text)
            self.assertIn("current source provenance must be clean", text)

    def test_recipe_capture_dev_rejects_head_changed_since_apply(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_slot_registry(root, ["dev-hermess"])
            source_output = root / "hermesdev" / "dist"
            source_output.mkdir(parents=True)
            product_image = wrapper_image_ref("hermes-runtime", "4")
            wrapper_image = wrapper_image_ref("agent-runtime-hermes", "5")
            image_spec = {
                "family": "hermes",
                "image_name": "direct-image",
                "wrapper_image": wrapper_image,
                "product_image": product_image,
                "digest": "sha256:" + "5" * 64,
                "product_digest": "sha256:" + "4" * 64,
                "mode": "wrapped_product_image",
                "image_recipe": hermes_runtime_image_recipe(product_image=product_image),
            }
            route = next(route for route in load_runtime_bindings(root) if route.linux_account == "dev-hermess")
            desired = RuntimeTarget(
                target="dev-hermess",
                family="hermes",
                runtime_class="dev",
                image_name="direct-image",
                image_spec=image_spec,
                runtime_profile="hermes-runtime-dev",
                route=route,
            )
            stored_head = "0123456789abcdef0123456789abcdef01234567"
            current_head = "fedcba9876543210fedcba9876543210fedcba98"
            (root / "dev-recipes.yaml").write_text(
                dump_yaml(
                    {
                        "recipes": {
                            "dev-hermess": {
                                "recipe_name": "hermes-runtime",
                                "source_output": str(source_output),
                                "source_provenance": {
                                    "status": "git",
                                    "git_head": stored_head,
                                    "git_dirty": False,
                                },
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.recipe._is_root", return_value=True),
                patch(
                    "agent_runtime_ops.commands.recipe._desired_from_live_image_truth",
                    return_value=(desired, load_profile("hermes-runtime-dev")),
                ),
                patch(
                    "agent_runtime_ops.domain.source_provenance.source_provenance",
                    return_value={
                        "path": str(source_output),
                        "status": "git",
                        "git_head": current_head,
                        "git_dirty": False,
                        "git_toplevel": str(source_output.parent),
                        "git_remote_origin": "",
                    },
                ),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_recipe_capture_dev(
                    argparse.Namespace(state_root=str(root), slot="dev-hermess", recipe_name="hermes-runtime")
                )

            text = output.getvalue()
            self.assertEqual(rc, 1, text)
            self.assertIn("recipe_capture_dev_status=fail", text)
            self.assertIn("source git head changed since apply-dev", text)

    def test_binding_normalize_requires_runtime_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            (root / "runtime-bindings.json").unlink()
            output = io.StringIO()
            with patch("agent_runtime_ops.commands.binding._is_root", return_value=True), contextlib.redirect_stdout(output):
                rc = cmd_binding_normalize(argparse.Namespace(state_root=str(root), write=True))
            self.assertEqual(rc, 1)
            self.assertIn("binding_normalize_status=fail", output.getvalue())
            self.assertIn("runtime bindings not found", output.getvalue())

    def test_binding_normalize_rewrites_runtime_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.binding._is_root", return_value=True),
                patch("agent_runtime_ops.commands.binding.os.chown"),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_binding_normalize(argparse.Namespace(state_root=str(root), write=True))
            text = (root / "runtime-bindings.json").read_text(encoding="utf-8")
            self.assertEqual(rc, 0, output.getvalue())
            self.assertIn('"schema": "v1"', text)
            bindings = {item.linux_account: item for item in load_runtime_bindings(root)}
            self.assertEqual(bindings["oc3"].public_host, "oc3.ji-tech.co.kr")

    def test_rollout_image_plan_uses_wrapper_labels_and_routing_ports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hermes_state(root)
            wrapper = wrapper_image_ref("agent-runtime-hermes", "3")
            product = wrapper_image_ref("hermes-workspace", "2")
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.rollout._is_root", return_value=True),
                patch("agent_runtime_ops.domain.image_specs.image_recipe_labels_from_wrapper", return_value=hermes_recipe_labels(product_image=product)),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_rollout_image_plan(
                    argparse.Namespace(
                        state_root=str(root),
                        wrapper_image=wrapper,
                        product_image=product,
                        slot="oc20",
                        slots=None,
                    )
                )
            self.assertEqual(rc, 0, output.getvalue())
            plan = json.loads(output.getvalue())
            self.assertEqual(plan["family"], "hermes")
            self.assertEqual(plan["targets"][0]["gateway_port"], 30689)
            self.assertEqual(plan["targets"][0]["runtime_profile"], "hermes-workspace-customer")

    def test_rollout_image_canary_builds_target_from_wrapper_labels_and_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hermes_state(root)
            wrapper = wrapper_image_ref("agent-runtime-hermes", "3")
            product = wrapper_image_ref("hermes-workspace", "2")
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.rollout._is_root", return_value=True),
                patch("agent_runtime_ops.domain.image_specs.image_recipe_labels_from_wrapper", return_value=hermes_recipe_labels(product_image=product)),
                patch("agent_runtime_ops.commands.rollout._ensure_runtime_dir"),
                patch("agent_runtime_ops.commands.rollout._prepare_runtime_env_for_direct_image") as prepare,
                patch("agent_runtime_ops.commands.rollout._apply_desired_slot", return_value=0) as apply,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_rollout_image_canary(
                    argparse.Namespace(
                        state_root=str(root),
                        slot="oc20",
                        wrapper_image=wrapper,
                        product_image=product,
                        allow_first_apply=False,
                    )
                )
                prepare.assert_not_called()
                apply.call_args.kwargs["prepare_runtime_env"]()
                prepare.assert_called_once_with(
                    apply.call_args.kwargs["desired"],
                    apply.call_args.kwargs["profile"],
                )

            self.assertEqual(rc, 0, output.getvalue())
            desired = apply.call_args.kwargs["desired"]
            self.assertEqual(desired.slot, "oc20")
            self.assertEqual(desired.runtime_class, "customer")
            self.assertEqual(desired.image_name, "direct-image")
            self.assertEqual(desired.runtime_profile, "hermes-workspace-customer")
            self.assertEqual(desired.image_spec["wrapper_image"], wrapper)
            self.assertEqual(desired.image_spec["product_image"], product)
            self.assertIn("canonical_recipe_name=hermes-workspace", output.getvalue())

    def test_rollout_image_dev_apply_uses_dev_projection_from_same_wrapper_recipe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hermes_state(root)
            wrapper = wrapper_image_ref("agent-runtime-hermes", "3")
            product = wrapper_image_ref("hermes-workspace", "2")
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.rollout._is_root", return_value=True),
                patch("agent_runtime_ops.domain.image_specs.image_recipe_labels_from_wrapper", return_value=hermes_recipe_labels(product_image=product)),
                patch("agent_runtime_ops.commands.rollout._ensure_runtime_dir"),
                patch("agent_runtime_ops.commands.rollout._prepare_runtime_env_for_direct_image") as prepare,
                patch("agent_runtime_ops.commands.rollout._apply_desired_slot", return_value=0) as apply,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_rollout_image_dev_apply(
                    argparse.Namespace(
                        state_root=str(root),
                        slot="dev-hermess",
                        wrapper_image=wrapper,
                        product_image=product,
                        allow_first_apply=True,
                    )
                )
                prepare.assert_not_called()
                apply.call_args.kwargs["prepare_runtime_env"]()
                prepare.assert_called_once_with(
                    apply.call_args.kwargs["desired"],
                    apply.call_args.kwargs["profile"],
                )

            self.assertEqual(rc, 0, output.getvalue())
            desired = apply.call_args.kwargs["desired"]
            self.assertEqual(desired.slot, "dev-hermess")
            self.assertEqual(desired.runtime_class, "dev")
            self.assertEqual(desired.image_name, "direct-image")
            self.assertEqual(desired.runtime_profile, "hermes-workspace-dev")
            self.assertTrue(apply.call_args.kwargs["allow_first_apply"])

    def test_rollout_image_promote_uses_live_canary_truth_and_explicit_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            wrapper = wrapper_image_ref("agent-runtime-openclaw", "9")
            product = wrapper_image_ref("openclaw-jitech", "8")
            source_route = next(item for item in load_runtime_bindings(root) if item.linux_account == "oc3")
            source_desired = RuntimeTarget(
                target="oc3",
                family="openclaw",
                runtime_class="customer",
                image_name="direct-image",
                image_spec={"wrapper_image": wrapper, "product_image": product},
                runtime_profile="openclaw-customer",
                route=source_route,
            )
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.rollout._is_root", return_value=True),
                patch(
                    "agent_runtime_ops.commands.rollout._desired_from_live_image_truth",
                    return_value=(source_desired, load_profile("openclaw-customer")),
                ),
                patch(
                    "agent_runtime_ops.domain.image_specs.image_recipe_labels_from_wrapper",
                    return_value=openclaw_recipe_labels(product_image=product),
                ),
                patch("agent_runtime_ops.commands.rollout._run_static_slot_checks", return_value=[]),
                patch("agent_runtime_ops.commands.rollout._run_live_slot_checks", return_value=[]),
                patch("agent_runtime_ops.commands.rollout._ensure_runtime_dir"),
                patch("agent_runtime_ops.commands.rollout._prepare_runtime_env_for_direct_image") as prepare,
                patch("agent_runtime_ops.commands.rollout._apply_desired_slot", return_value=0) as apply,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_rollout_image_promote(
                    argparse.Namespace(
                        state_root=str(root),
                        from_slot="oc3",
                        slots="oc4",
                    )
                )
                prepare.assert_not_called()
                for call in apply.call_args_list:
                    call.kwargs["prepare_runtime_env"]()

            self.assertEqual(rc, 0, output.getvalue())
            self.assertEqual([call.kwargs["desired"].slot for call in apply.call_args_list], ["oc4"])
            self.assertEqual([call.kwargs["desired"].image_name for call in apply.call_args_list], ["direct-image"])
            self.assertEqual(
                [call.args[0].slot for call in prepare.call_args_list],
                ["oc4"],
            )
            self.assertIn(f"wrapper_image={wrapper}", output.getvalue())
            self.assertIn(f"product_image={product}", output.getvalue())

    def test_wrapper_image_recipe_reads_oci_labels(self) -> None:
        product_image = wrapper_image_ref("hermes-workspace", "2")
        wrapper_image = wrapper_image_ref("agent-runtime-hermes", "3")
        with patch("agent_runtime_ops.domain.image_specs.image_recipe_labels_from_wrapper", return_value=hermes_recipe_labels()):
            recipe = image_recipe_from_wrapper_image(wrapper_image, family="hermes", product_image=product_image)
        self.assertEqual(recipe["source"], "wrapper_image_labels")
        self.assertEqual(recipe["canonical_recipe_name"], "hermes-workspace")
        self.assertEqual(recipe["canonical_recipe_digest"], hermes_workspace_recipe_digest())
        self.assertEqual(recipe["runtime_profiles"]["customer"], "hermes-workspace-customer")
        self.assertEqual(recipe["product_component"], "hermes-workspace")
        self.assertEqual(recipe["container_nas_root"], "/workspace/nas_docs")
        self.assertEqual(recipe["host_nas_root_template"], "/home/{slot}/nas_docs")
        self.assertEqual(recipe["nas_read_only"], "true")
        self.assertEqual(recipe["nas_mount_propagation"], "rslave")
        self.assertEqual(recipe["nas_child_mount_mode"], "host-propagated-cifs")

    def test_wrapper_image_recipe_reads_hermes_runtime_v2_health_contract(self) -> None:
        product_image = wrapper_image_ref("hermes-runtime", "4")
        wrapper_image = wrapper_image_ref("agent-runtime-hermes", "5")
        labels = hermes_runtime_recipe_labels(product_image=product_image)
        with patch("agent_runtime_ops.domain.image_specs.image_recipe_labels_from_wrapper", return_value=labels):
            recipe = image_recipe_from_wrapper_image(wrapper_image, family="hermes", product_image=product_image)
        self.assertEqual(recipe["canonical_recipe_name"], "hermes-runtime")
        self.assertEqual(recipe["canonical_recipe_digest"], hermes_runtime_recipe_digest())
        self.assertEqual(recipe["runtime_profiles"]["customer"], "hermes-runtime-customer")
        self.assertEqual(recipe["runtime_profiles"]["dev"], "hermes-runtime-dev")
        self.assertEqual(recipe["contract_version"], "v2")
        self.assertEqual(
            recipe["health_endpoints"],
            {
                "dashboard": "http://127.0.0.1:9119/api/status",
                "gateway": "http://127.0.0.1:8642/health",
                "workspace": "http://127.0.0.1:3000/",
            },
        )

    def test_wrapper_image_recipe_prefers_health_endpoint_json_label(self) -> None:
        product_image = wrapper_image_ref("hermes-runtime", "4")
        wrapper_image = wrapper_image_ref("agent-runtime-hermes", "5")
        labels = hermes_runtime_recipe_labels(
            product_image=product_image,
            **{"health.endpoints": "dashboard=http://wrong.invalid"},
        )
        with patch("agent_runtime_ops.domain.image_specs.image_recipe_labels_from_wrapper", return_value=labels):
            recipe = image_recipe_from_wrapper_image(wrapper_image, family="hermes", product_image=product_image)
        self.assertEqual(recipe["health_endpoints"]["gateway"], "http://127.0.0.1:8642/health")

    def test_live_contract_health_endpoints_come_from_image_recipe(self) -> None:
        product_image = wrapper_image_ref("hermes-runtime", "4")
        desired = RuntimeTarget(
            target="dev-hermess",
            family="hermes",
            runtime_class="dev",
            image_name="direct-image",
            image_spec={
                "wrapper_image": wrapper_image_ref("agent-runtime-hermes", "5"),
                "product_image": product_image,
                "image_recipe": hermes_runtime_image_recipe(product_image=product_image),
            },
            runtime_profile="hermes-runtime-dev",
            route=binding("dev-hermess", "hermes", "dev", 30889, 30890),
        )
        endpoints = contract_health_endpoints(desired, load_profile("hermes-runtime-dev"))
        self.assertEqual(endpoints["workspace"], "http://127.0.0.1:3000/")
        self.assertEqual(endpoints["gateway"], "http://127.0.0.1:8642/health")
        self.assertEqual(endpoints["dashboard"], "http://127.0.0.1:9119/api/status")

    def test_live_slot_checks_include_hermes_workspace_node_and_nas_listing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hermes_state(root)
            product_image = wrapper_image_ref("hermes-runtime", "4")
            wrapper_image = wrapper_image_ref("agent-runtime-hermes", "5")
            route = binding("dev-hermess", "hermes", "dev", 30889, 30890)
            desired = RuntimeTarget(
                target="dev-hermess",
                family="hermes",
                runtime_class="dev",
                image_name="direct-image",
                image_spec={
                    "family": "hermes",
                    "image_name": "direct-image",
                    "wrapper_image": wrapper_image,
                    "product_image": product_image,
                    "digest": "sha256:" + "5" * 64,
                    "product_digest": "sha256:" + "4" * 64,
                    "mode": "wrapped_product_image",
                    "image_recipe": hermes_runtime_image_recipe(product_image=product_image),
                },
                runtime_profile="hermes-runtime-dev",
                route=route,
            )
            inspect_result = subprocess.CompletedProcess(
                ["docker", "inspect", "container-1"],
                0,
                stdout=json.dumps(
                    [
                        {
                            "State": {
                                "Running": True,
                                "Pid": 123,
                                "Health": {"Status": "healthy"},
                            },
                            "Config": {"Image": wrapper_image, "User": ""},
                            "Image": "image-id",
                            "RepoDigests": [wrapper_image],
                        }
                    ]
                ),
                stderr="",
            )

            def fake_run_text(command, timeout=20):
                if command == ["docker", "inspect", "container-1"]:
                    return inspect_result
                if command[:4] == ["docker", "exec", "container-1", "node"]:
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout=json.dumps(
                            [
                                {
                                    "name": "live_workspace_api_status_ok",
                                    "ok": True,
                                    "detail": "status=200 isValid=true path=/workspace source=env",
                                },
                                {
                                    "name": "live_workspace_files_root_listing_ok",
                                    "ok": True,
                                    "detail": "status=200 entries_array=true error=none",
                                },
                                {
                                    "name": "live_workspace_files_nas_docs_listing_ok",
                                    "ok": True,
                                    "detail": "status=200 root=nas_docs entries_array=true error=none",
                                },
                            ]
                        ),
                        stderr="",
                    )
                if command[:4] == ["docker", "exec", "container-1", "sh"]:
                    script = command[-1]
                    if "server-entry[.]js" in script:
                        return subprocess.CompletedProcess(command, 0, stdout="42 12345 12346 12347\n", stderr="")
                    if "ls -la" in script:
                        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
                if command and command[0].endswith("nsenter"):
                    return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
                return subprocess.CompletedProcess(command, 1, stdout="", stderr="unexpected command")

            with (
                patch("agent_runtime_ops.domain.runtime_checks.is_root", return_value=True),
                patch("agent_runtime_ops.domain.runtime_checks.find_gateway_container", return_value=("container-1", "instance_label")),
                patch(
                    "agent_runtime_ops.domain.runtime_checks.live_runtime_truth",
                    return_value=(
                        {
                            "truth_status": "ok",
                            "runtime_profile": "hermes-runtime-dev",
                            "canonical_recipe_name": "hermes-runtime",
                        },
                        [],
                    ),
                ),
                patch("agent_runtime_ops.domain.runtime_checks.runtime_ids", return_value=(12345, 12346, 12347)),
                patch("agent_runtime_ops.domain.runtime_checks.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"),
                patch("agent_runtime_ops.domain.runtime_checks._findmnt_under", return_value=(0, "", [])),
                patch(
                    "agent_runtime_ops.domain.runtime_checks._findmnt_tree",
                    return_value=(
                        0,
                        "",
                        [
                            {
                                "target": "/workspace/nas_docs",
                                "source": "/home/dev-hermess/nas_docs",
                                "fstype": "bind",
                                "options": "rw,ro",
                                "propagation": "rslave",
                            }
                        ],
                    ),
                ),
                patch("agent_runtime_ops.domain.runtime_checks.run_text", side_effect=fake_run_text),
                patch(
                    "agent_runtime_ops.domain.runtime_checks.workspace_hermes_config_api_checks",
                    return_value=[
                        (True, "live_workspace_session_cookie_present", "secret_value_printed=no"),
                        (True, "live_workspace_hermes_config_api_ok", "status=200 provider=google model=gemini-3.1-pro-preview"),
                    ],
                ),
            ):
                checks = run_live_slot_checks(desired, load_profile("hermes-runtime-dev"), root)

            results = {name: (ok, detail) for ok, name, detail in checks}
            self.assertEqual(results["live_workspace_node_process_present"], (True, "pid=42"))
            self.assertEqual(results["live_workspace_node_uid_not_default_10000"], (True, "uid=12345"))
            self.assertEqual(results["live_workspace_node_gid_not_default_10000"], (True, "gid=12346"))
            self.assertEqual(
                results["live_workspace_node_uid_matches_slot"],
                (True, "actual=12345 expected=12345"),
            )
            self.assertEqual(
                results["live_workspace_node_gid_matches_slot"],
                (True, "actual=12346 expected=12346"),
            )
            self.assertEqual(
                results["live_workspace_node_groups_include_data_gid"],
                (True, "groups=12347 expected=12347"),
            )
            self.assertEqual(results["live_container_nas_docs_listing_ok"], (True, "/workspace/nas_docs"))
            self.assertEqual(results["live_workspace_user_nas_docs_listing_ok"], (True, "/workspace/nas_docs"))
            self.assertEqual(
                results["live_workspace_api_status_ok"],
                (True, "status=200 isValid=true path=/workspace source=env"),
            )
            self.assertEqual(
                results["live_workspace_files_root_listing_ok"],
                (True, "status=200 entries_array=true error=none"),
            )
            self.assertEqual(
                results["live_workspace_files_nas_docs_listing_ok"],
                (True, "status=200 root=nas_docs entries_array=true error=none"),
            )

    def test_compose_runtime_nas_listing_uses_docker_exec_user(self) -> None:
        calls: list[list[str]] = []

        def fake_run_text(command, timeout=20):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        with (
            patch("agent_runtime_ops.domain.runtime_checks.runtime_ids", return_value=(995, 982, 1042)),
            patch("agent_runtime_ops.domain.runtime_checks.run_text", side_effect=fake_run_text),
        ):
            result = run_workspace_user_nas_docs_listing_check(
                "container-1",
                "/home/node/nas_docs",
                runtime_user_mode="compose",
                slot="oc1",
            )

        self.assertEqual(result, (True, "live_workspace_user_nas_docs_listing_ok", "/home/node/nas_docs"))
        self.assertEqual(calls[0][:5], ["docker", "exec", "--user", "995:982", "container-1"])
        self.assertIn("/home/node/nas_docs", calls[0][-1])

    def test_workspace_hermes_config_api_reuses_existing_session_cookie(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hermes_state(root)
            calls: list[str] = []

            class FakeResponse:
                headers: dict[str, str] = {}

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback) -> None:
                    return None

                def getcode(self) -> int:
                    return 200

                def read(self, size: int = -1) -> bytes:
                    return json.dumps(
                        {
                            "ok": True,
                            "activeProvider": "google",
                            "activeModel": "gemini-3.1-pro-preview",
                            "providers": [
                                {
                                    "id": "google",
                                    "configured": True,
                                    "authenticated": True,
                                }
                            ],
                        }
                    ).encode("utf-8")

            def fake_urlopen(request, timeout=8):
                calls.append(request.full_url)
                self.assertNotIn("/api/auth", request.full_url)
                self.assertEqual(request.get_header("Cookie"), "claude-auth=session-token")
                return FakeResponse()

            with (
                patch(
                    "agent_runtime_ops.domain.runtime_checks._existing_workspace_session_cookie",
                    return_value="claude-auth=session-token",
                ),
                patch(
                    "agent_runtime_ops.domain.runtime_checks._slot_hermes_config",
                    return_value=("google", "gemini-3.1-pro-preview"),
                ),
                patch("agent_runtime_ops.domain.runtime_checks.urllib.request.urlopen", side_effect=fake_urlopen),
            ):
                checks = workspace_hermes_config_api_checks("dev-hermess", root)

            results = {name: (ok, detail) for ok, name, detail in checks}
            self.assertEqual(results["live_workspace_session_cookie_present"], (True, "secret_value_printed=no"))
            self.assertEqual(
                results["live_workspace_hermes_config_api_ok"],
                (True, "status=200 provider=google model=gemini-3.1-pro-preview"),
            )
            self.assertEqual(calls, ["http://127.0.0.1:30889/api/hermes-config"])

    def test_wrapper_image_recipe_rejects_canonical_digest_mismatch(self) -> None:
        product_image = wrapper_image_ref("hermes-workspace", "2")
        wrapper_image = wrapper_image_ref("agent-runtime-hermes", "3")
        labels = hermes_recipe_labels(**{"recipe.digest": "sha256:" + "9" * 64})
        with patch("agent_runtime_ops.domain.image_specs.image_recipe_labels_from_wrapper", return_value=labels):
            with self.assertRaisesRegex(ValueError, "canonical recipe digest mismatch"):
                image_recipe_from_wrapper_image(wrapper_image, family="hermes", product_image=product_image)

    def test_wrapper_image_recipe_rejects_missing_canonical_identity(self) -> None:
        product_image = wrapper_image_ref("hermes-workspace", "2")
        wrapper_image = wrapper_image_ref("agent-runtime-hermes", "3")
        labels = hermes_recipe_labels(**{"recipe.name": "", "recipe.digest": ""})
        with patch("agent_runtime_ops.domain.image_specs.image_recipe_labels_from_wrapper", return_value=labels):
            with self.assertRaisesRegex(ValueError, "missing canonical recipe name"):
                image_recipe_from_wrapper_image(wrapper_image, family="hermes", product_image=product_image)

    def test_wrapper_image_recipe_rejects_missing_nas_contract_labels(self) -> None:
        product_image = wrapper_image_ref("openclaw-jitech", "8")
        wrapper_image = wrapper_image_ref("agent-runtime-openclaw", "9")
        labels = openclaw_recipe_labels(**{"nas.propagation": ""})
        with patch("agent_runtime_ops.domain.image_specs.image_recipe_labels_from_wrapper", return_value=labels):
            with self.assertRaisesRegex(ValueError, "recipe labels are incomplete: .*nas.propagation"):
                image_recipe_from_wrapper_image(wrapper_image, family="openclaw", product_image=product_image)

    def test_wrapper_image_recipe_rejects_nas_contract_mismatch(self) -> None:
        product_image = wrapper_image_ref("openclaw-jitech", "8")
        wrapper_image = wrapper_image_ref("agent-runtime-openclaw", "9")
        labels = openclaw_recipe_labels(**{"nas.propagation": "private"})
        with patch("agent_runtime_ops.domain.image_specs.image_recipe_labels_from_wrapper", return_value=labels):
            with self.assertRaisesRegex(ValueError, "canonical recipe mismatch: nas.propagation"):
                image_recipe_from_wrapper_image(wrapper_image, family="openclaw", product_image=product_image)

    def test_live_image_truth_rejects_partial_recipe_labels(self) -> None:
        route = binding("oc20", "hermes", "customer", 30689, 30690)
        labels = hermes_recipe_labels(**{"recipe.name": "", "recipe.digest": ""})
        info = {
            "Config": {
                "Image": wrapper_image_ref("agent-runtime-hermes", "3"),
                "Labels": labels,
            }
        }
        truth = live_image_truth_from_info(route, info, route)
        self.assertEqual(truth["truth_status"], "incomplete_recipe_labels")
        self.assertEqual(truth["canonical_recipe_name"], "")
        self.assertEqual(truth["canonical_recipe_digest"], "")

    def test_live_image_truth_reports_partial_retrieval_label_presence(self) -> None:
        route = binding("oc20", "hermes", "customer", 30689, 30690)
        labels = hermes_recipe_labels()
        labels["com.epicevent.agent-runtime.retrieval.component-digest"] = (
            "sha256:" + "1" * 64
        )
        info = {
            "Config": {
                "Image": wrapper_image_ref("agent-runtime-hermes", "3"),
                "Labels": labels,
            }
        }

        truth = live_image_truth_from_info(route, info, route)

        self.assertEqual(truth["retrieval_labels_present"], "true")
        self.assertEqual(truth["retrieval_contract_complete"], "false")
        self.assertEqual(truth["retrieval_schema"], "")

    def test_live_image_truth_rejects_schema_only_retrieval_label_set(self) -> None:
        route = binding("oc20", "hermes", "customer", 30689, 30690)
        labels = hermes_recipe_labels()
        labels["com.epicevent.agent-runtime.retrieval.schema"] = (
            "jitech-embedded-retrieval/v1"
        )
        info = {
            "Config": {
                "Image": wrapper_image_ref("agent-runtime-hermes", "3"),
                "Labels": labels,
            }
        }

        truth = live_image_truth_from_info(route, info, route)

        self.assertEqual(truth["retrieval_labels_present"], "true")
        self.assertEqual(truth["retrieval_contract_complete"], "false")

    def test_live_image_truth_accepts_exact_retrieval_label_set(self) -> None:
        route = binding("oc20", "hermes", "customer", 30689, 30690)
        fixture = json.loads(
            (
                Path(__file__).parent
                / "fixtures"
                / "kwrag_embedded_retrieval"
                / "hermes-compatibility-v1.json"
            ).read_text(encoding="utf-8")
        )
        info = {
            "Config": {
                "Image": wrapper_image_ref("agent-runtime-hermes", "3"),
                "Labels": fixture["capabilityLabels"],
            }
        }

        truth = live_image_truth_from_info(route, info, route)

        self.assertEqual(truth["retrieval_labels_present"], "true")
        self.assertEqual(truth["retrieval_contract_complete"], "true")

    def test_live_image_truth_rejects_partial_runtime_projection_labels(self) -> None:
        route = binding("oc20", "hermes", "customer", 30689, 30690)
        labels = hermes_recipe_labels()
        labels["agent-runtime.retrieval-component-digest"] = "sha256:" + "1" * 64
        info = {
            "Config": {
                "Image": wrapper_image_ref("agent-runtime-hermes", "3"),
                "Labels": labels,
            }
        }

        truth = live_image_truth_from_info(route, info, route)

        self.assertEqual(truth["retrieval_projection_labels_present"], "true")
        self.assertEqual(truth["retrieval_projection_complete"], "false")
        self.assertEqual(truth["retrieval_projection_consistent"], "false")

    def test_live_image_truth_rejects_unknown_only_runtime_projection_label(self) -> None:
        route = binding("oc20", "hermes", "customer", 30689, 30690)
        labels = hermes_recipe_labels()
        labels["agent-runtime.retrieval-bindng-digest"] = "sha256:" + "1" * 64
        info = {
            "Config": {
                "Image": wrapper_image_ref("agent-runtime-hermes", "3"),
                "Labels": labels,
            }
        }

        truth = live_image_truth_from_info(route, info, route)

        self.assertEqual(truth["retrieval_projection_labels_present"], "true")
        self.assertEqual(truth["retrieval_projection_complete"], "false")
        self.assertEqual(truth["retrieval_projection_consistent"], "false")

    def test_live_image_truth_rejects_extra_runtime_projection_label(self) -> None:
        route = binding("oc20", "hermes", "customer", 30689, 30690)
        labels = hermes_recipe_labels()
        labels.update(
            {
                "agent-runtime.retrieval-enabled": "false",
                "agent-runtime.retrieval-component-digest": "",
                "agent-runtime.retrieval-binding-digest": "sha256:" + "9" * 64,
                "agent-runtime.retrieval-resource-profile-digest": "",
                "agent-runtime.retrieval-unexpected": "present",
            }
        )
        info = {
            "Config": {
                "Image": wrapper_image_ref("agent-runtime-hermes", "3"),
                "Labels": labels,
            }
        }

        truth = live_image_truth_from_info(route, info, route)

        self.assertEqual(truth["retrieval_projection_complete"], "false")
        self.assertEqual(truth["retrieval_projection_consistent"], "false")

    def test_live_image_truth_accepts_complete_absent_runtime_projection(self) -> None:
        route = binding("oc20", "hermes", "customer", 30689, 30690)
        labels = hermes_recipe_labels()
        labels.update(
            {
                "agent-runtime.retrieval-enabled": "false",
                "agent-runtime.retrieval-component-digest": "",
                "agent-runtime.retrieval-binding-digest": "sha256:" + "9" * 64,
                "agent-runtime.retrieval-resource-profile-digest": "",
            }
        )
        info = {
            "Config": {
                "Image": wrapper_image_ref("agent-runtime-hermes", "3"),
                "Labels": labels,
            }
        }

        truth = live_image_truth_from_info(route, info, route)

        self.assertEqual(truth["retrieval_projection_complete"], "true")
        self.assertEqual(truth["retrieval_projection_consistent"], "true")

    def test_live_image_truth_accepts_exact_capability_projection_binding(self) -> None:
        route = binding("oc20", "hermes", "customer", 30689, 30690)
        fixture = json.loads(
            (
                Path(__file__).parent
                / "fixtures"
                / "kwrag_embedded_retrieval"
                / "hermes-compatibility-v1.json"
            ).read_text(encoding="utf-8")
        )
        labels = dict(fixture["capabilityLabels"])
        prefix = "com.epicevent.agent-runtime.retrieval."
        resource = json.loads(labels[prefix + "resource.json"])
        labels.update(
            {
                "agent-runtime.retrieval-enabled": "false",
                "agent-runtime.retrieval-component-digest": labels[
                    prefix + "component-digest"
                ],
                "agent-runtime.retrieval-binding-digest": "sha256:" + "9" * 64,
                "agent-runtime.retrieval-resource-profile-digest": resource[
                    "profileDigest"
                ],
            }
        )
        info = {
            "Config": {
                "Image": wrapper_image_ref("agent-runtime-hermes", "3"),
                "Labels": labels,
            }
        }

        truth = live_image_truth_from_info(route, info, route)

        self.assertEqual(truth["retrieval_contract_complete"], "true")
        self.assertEqual(truth["retrieval_projection_complete"], "true")
        self.assertEqual(truth["retrieval_projection_consistent"], "true")

    def test_enabled_promotion_refuses_unverified_retrieval_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            source_route = next(
                item
                for item in load_runtime_bindings(root)
                if item.linux_account == "oc3"
            )
            source_desired = RuntimeTarget(
                target="oc3",
                family="openclaw",
                runtime_class="customer",
                image_name="direct-image",
                image_spec={
                    "wrapper_image": wrapper_image_ref("agent-runtime-openclaw", "9"),
                    "product_image": wrapper_image_ref("openclaw-jitech", "8"),
                    "retrieval_enabled": True,
                },
                runtime_profile="openclaw-customer",
                route=source_route,
            )
            target_route = next(
                item
                for item in load_runtime_bindings(root)
                if item.linux_account == "oc4"
            )
            target_desired = RuntimeTarget(
                target="oc4",
                family="openclaw",
                runtime_class="customer",
                image_name="direct-image",
                image_spec={"retrieval_enabled": True},
                runtime_profile="openclaw-customer",
                route=target_route,
            )
            output = io.StringIO()

            def apply_with_admission(**kwargs: object) -> int:
                admission = kwargs.get("pre_apply_admission")
                self.assertIsNotNone(admission)
                assert callable(admission)
                admission()
                return 0

            with (
                patch("agent_runtime_ops.commands.rollout._is_root", return_value=True),
                patch(
                    "agent_runtime_ops.commands.rollout._desired_from_live_image_truth",
                    return_value=(source_desired, load_profile("openclaw-customer")),
                ),
                patch(
                    "agent_runtime_ops.commands.rollout._run_static_slot_checks",
                    return_value=[],
                ),
                patch(
                    "agent_runtime_ops.commands.rollout._run_live_slot_checks",
                    return_value=[],
                ),
                patch(
                    "agent_runtime_ops.commands.rollout.find_gateway_container_by_binding",
                    return_value=("container-1", "instance_label"),
                ),
                patch(
                    "agent_runtime_ops.commands.rollout.run_retrieval_status_probe",
                    side_effect=ValueError("consumer unhealthy"),
                ),
                patch(
                    "agent_runtime_ops.commands.rollout.image_spec_from_direct_images",
                    return_value={
                        "wrapper_image": source_desired.image_spec["wrapper_image"],
                        "product_image": source_desired.image_spec["product_image"],
                    },
                ),
                patch(
                    "agent_runtime_ops.commands.rollout._desired_from_direct_images",
                    return_value=(
                        target_desired,
                        load_profile("openclaw-customer"),
                    ),
                ),
                patch("agent_runtime_ops.commands.rollout._require_retrieval_approval"),
                patch("agent_runtime_ops.commands.rollout._ensure_runtime_dir"),
                patch(
                    "agent_runtime_ops.commands.rollout._apply_desired_slot",
                    side_effect=apply_with_admission,
                ) as apply,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_rollout_image_promote(
                    argparse.Namespace(
                        state_root=str(root),
                        from_slot="oc3",
                        slots="oc4",
                    )
                )

            self.assertEqual(rc, 1)
            self.assertIn("consumer unhealthy", output.getvalue())
            apply.assert_called_once()

    def test_enabled_promotion_refuses_changed_live_source_tuple_under_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            routes = {
                item.linux_account: item for item in load_runtime_bindings(root)
            }
            source_desired = RuntimeTarget(
                target="oc3",
                family="openclaw",
                runtime_class="customer",
                image_name="direct-image",
                image_spec={
                    "wrapper_image": wrapper_image_ref(
                        "agent-runtime-openclaw", "9"
                    ),
                    "product_image": wrapper_image_ref("openclaw-jitech", "8"),
                    "retrieval_enabled": True,
                },
                runtime_profile="openclaw-customer",
                route=routes["oc3"],
            )
            refreshed_source = RuntimeTarget(
                target="oc3",
                family="openclaw",
                runtime_class="customer",
                image_name="direct-image",
                image_spec={
                    "wrapper_image": wrapper_image_ref(
                        "agent-runtime-openclaw", "7"
                    ),
                    "product_image": wrapper_image_ref("openclaw-jitech", "6"),
                    "retrieval_enabled": True,
                },
                runtime_profile="openclaw-customer",
                route=routes["oc3"],
            )
            target_desired = RuntimeTarget(
                target="oc4",
                family="openclaw",
                runtime_class="customer",
                image_name="direct-image",
                image_spec={"retrieval_enabled": True},
                runtime_profile="openclaw-customer",
                route=routes["oc4"],
            )

            def apply_with_admission(**kwargs: object) -> int:
                admission = kwargs.get("pre_apply_admission")
                self.assertIsNotNone(admission)
                assert callable(admission)
                admission()
                return 0

            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.rollout._is_root", return_value=True),
                patch(
                    "agent_runtime_ops.commands.rollout._desired_from_live_image_truth",
                    side_effect=[
                        (source_desired, load_profile("openclaw-customer")),
                        (refreshed_source, load_profile("openclaw-customer")),
                    ],
                ),
                patch(
                    "agent_runtime_ops.commands.rollout._run_static_slot_checks",
                    return_value=[],
                ),
                patch(
                    "agent_runtime_ops.commands.rollout._run_live_slot_checks",
                    return_value=[],
                ),
                patch(
                    "agent_runtime_ops.commands.rollout.find_gateway_container_by_binding",
                    return_value=("source-container", "instance_label"),
                ),
                patch(
                    "agent_runtime_ops.commands.rollout.image_spec_from_direct_images",
                    return_value={
                        "wrapper_image": source_desired.image_spec["wrapper_image"],
                        "product_image": source_desired.image_spec["product_image"],
                    },
                ),
                patch(
                    "agent_runtime_ops.commands.rollout._desired_from_direct_images",
                    return_value=(
                        target_desired,
                        load_profile("openclaw-customer"),
                    ),
                ),
                patch("agent_runtime_ops.commands.rollout._require_retrieval_approval"),
                patch("agent_runtime_ops.commands.rollout._ensure_runtime_dir"),
                patch(
                    "agent_runtime_ops.commands.rollout.run_retrieval_status_probe"
                ) as probe,
                patch(
                    "agent_runtime_ops.commands.rollout.measure_retrieval_promotion_headroom"
                ) as headroom,
                patch(
                    "agent_runtime_ops.commands.rollout._apply_desired_slot",
                    side_effect=apply_with_admission,
                ) as apply,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_rollout_image_promote(
                    argparse.Namespace(
                        state_root=str(root),
                        from_slot="oc3",
                        slots="oc4",
                    )
                )

            self.assertEqual(rc, 1)
            self.assertIn(
                "retrieval promotion source live tuple changed during promotion",
                output.getvalue(),
            )
            apply.assert_called_once()
            probe.assert_not_called()
            headroom.assert_not_called()

    def test_promotion_rejects_duplicate_or_source_targets_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            source_route = next(
                item
                for item in load_runtime_bindings(root)
                if item.linux_account == "oc3"
            )
            source_desired = RuntimeTarget(
                target="oc3",
                family="openclaw",
                runtime_class="customer",
                image_name="direct-image",
                image_spec={
                    "wrapper_image": wrapper_image_ref(
                        "agent-runtime-openclaw", "9"
                    ),
                    "product_image": wrapper_image_ref("openclaw-jitech", "8"),
                },
                runtime_profile="openclaw-customer",
                route=source_route,
            )
            target_route = next(
                item
                for item in load_runtime_bindings(root)
                if item.linux_account == "oc4"
            )
            dev_target_route = RuntimeBinding(
                instance_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, "dev-target-img")),
                linux_account="dev-target-img",
                public_host="image-target.ji-tech.co.kr",
                family="openclaw",
                runtime_class="customer",
                gateway_port=32004,
                bridge_port=32005,
            )
            current_bindings = load_runtime_bindings(root)
            (root / "runtime-bindings.json").write_text(
                dump_runtime_bindings([*current_bindings, dev_target_route]),
                encoding="utf-8",
            )
            with (
                patch("agent_runtime_ops.commands.rollout._is_root", return_value=True),
                patch(
                    "agent_runtime_ops.commands.rollout._desired_from_live_image_truth",
                    return_value=(
                        source_desired,
                        load_profile("openclaw-customer"),
                    ),
                ),
                patch(
                    "agent_runtime_ops.commands.rollout._run_static_slot_checks",
                    return_value=[],
                ),
                patch(
                    "agent_runtime_ops.commands.rollout._run_live_slot_checks",
                    return_value=[],
                ),
                patch("agent_runtime_ops.commands.rollout._apply_desired_slot") as apply,
            ):
                for targets, reason in (
                    (
                        f"oc4,{target_route.public_host}",
                        "image-promote targets must be unique",
                    ),
                    (
                        f"oc4,{target_route.instance_id}",
                        "image-promote targets must be unique",
                    ),
                    (
                        source_route.public_host,
                        "image-promote source must not also be a target",
                    ),
                    (
                        source_route.instance_id,
                        "image-promote source must not also be a target",
                    ),
                    (
                        f"oc4,{dev_target_route.public_host}",
                        "image-promote target must not be a dev target: "
                        "dev-target-img",
                    ),
                    (
                        f"oc4,{dev_target_route.instance_id}",
                        "image-promote target must not be a dev target: "
                        "dev-target-img",
                    ),
                ):
                    with self.subTest(targets=targets):
                        output = io.StringIO()
                        with contextlib.redirect_stdout(output):
                            rc = cmd_rollout_image_promote(
                                argparse.Namespace(
                                    state_root=str(root),
                                    from_slot="oc3",
                                    slots=targets,
                                )
                            )
                        self.assertEqual(rc, 1)
                        self.assertIn(reason, output.getvalue())
                apply.assert_not_called()

    def test_promotion_rejects_canonical_dev_source_alias_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            dev_source_route = RuntimeBinding(
                instance_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, "dev-oc-img")),
                linux_account="dev-oc-img",
                public_host="image-canary.ji-tech.co.kr",
                family="openclaw",
                runtime_class="customer",
                gateway_port=32002,
                bridge_port=32003,
            )
            current_bindings = load_runtime_bindings(root)
            (root / "runtime-bindings.json").write_text(
                dump_runtime_bindings([*current_bindings, dev_source_route]),
                encoding="utf-8",
            )
            source_desired = RuntimeTarget(
                target="dev-oc-img",
                family="openclaw",
                runtime_class="customer",
                image_name="direct-image",
                image_spec={
                    "wrapper_image": wrapper_image_ref(
                        "agent-runtime-openclaw", "9"
                    ),
                    "product_image": wrapper_image_ref("openclaw-jitech", "8"),
                },
                runtime_profile="openclaw-customer",
                route=dev_source_route,
            )
            with (
                patch("agent_runtime_ops.commands.rollout._is_root", return_value=True),
                patch(
                    "agent_runtime_ops.commands.rollout._desired_from_live_image_truth",
                    return_value=(
                        source_desired,
                        load_profile("openclaw-customer"),
                    ),
                ),
                patch(
                    "agent_runtime_ops.commands.rollout._run_static_slot_checks",
                    return_value=[],
                ),
                patch(
                    "agent_runtime_ops.commands.rollout._run_live_slot_checks",
                    return_value=[],
                ),
                patch("agent_runtime_ops.commands.rollout._apply_desired_slot") as apply,
            ):
                for source_alias in (
                    dev_source_route.public_host,
                    dev_source_route.instance_id,
                ):
                    with self.subTest(source_alias=source_alias):
                        output = io.StringIO()
                        with contextlib.redirect_stdout(output):
                            rc = cmd_rollout_image_promote(
                                argparse.Namespace(
                                    state_root=str(root),
                                    from_slot=source_alias,
                                    slots="oc4",
                                )
                            )
                        self.assertEqual(rc, 1)
                        self.assertIn(
                            "image-promote source must not be a dev target: "
                            "dev-oc-img",
                            output.getvalue(),
                        )
                apply.assert_not_called()

    def test_enabled_promotion_verifies_source_before_first_target_apply(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            routes = {
                item.linux_account: item for item in load_runtime_bindings(root)
            }
            source_desired = RuntimeTarget(
                target="oc3",
                family="openclaw",
                runtime_class="customer",
                image_name="direct-image",
                image_spec={
                    "wrapper_image": wrapper_image_ref(
                        "agent-runtime-openclaw", "9"
                    ),
                    "product_image": wrapper_image_ref("openclaw-jitech", "8"),
                    "retrieval_enabled": True,
                },
                runtime_profile="openclaw-customer",
                route=routes["oc3"],
            )
            target_desired = RuntimeTarget(
                target="oc4",
                family="openclaw",
                runtime_class="customer",
                image_name="direct-image",
                image_spec={"retrieval_enabled": True},
                runtime_profile="openclaw-customer",
                route=routes["oc4"],
            )
            events: list[str] = []

            def verified_status(*args: object, **kwargs: object) -> dict[str, str]:
                events.append("source_verified")
                return {"bindingDigest": "sha256:" + "1" * 64}

            def verified_headroom(*args: object, **kwargs: object) -> dict[str, object]:
                events.append("headroom_verified")
                return {
                    "schema": "agent-runtime-retrieval-headroom/v1",
                    "status": "within_required_headroom",
                    "observationDigest": "sha256:" + "2" * 64,
                }

            def applied(**kwargs: object) -> int:
                admission = kwargs.get("pre_apply_admission")
                self.assertIsNotNone(admission)
                assert callable(admission)
                admission()
                events.append("target_applied")
                return 0

            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.rollout._is_root", return_value=True),
                patch(
                    "agent_runtime_ops.commands.rollout._desired_from_live_image_truth",
                    return_value=(source_desired, load_profile("openclaw-customer")),
                ),
                patch(
                    "agent_runtime_ops.commands.rollout._run_static_slot_checks",
                    return_value=[],
                ),
                patch(
                    "agent_runtime_ops.commands.rollout._run_live_slot_checks",
                    return_value=[],
                ),
                patch(
                    "agent_runtime_ops.commands.rollout.find_gateway_container_by_binding",
                    return_value=("container-1", "instance_label"),
                ),
                patch(
                    "agent_runtime_ops.commands.rollout.run_retrieval_status_probe",
                    side_effect=verified_status,
                ),
                patch(
                    "agent_runtime_ops.commands.rollout.measure_retrieval_promotion_headroom",
                    side_effect=verified_headroom,
                ),
                patch(
                    "agent_runtime_ops.commands.rollout.image_spec_from_direct_images",
                    return_value={
                        "wrapper_image": source_desired.image_spec["wrapper_image"],
                        "product_image": source_desired.image_spec["product_image"],
                    },
                ),
                patch(
                    "agent_runtime_ops.commands.rollout._desired_from_direct_images",
                    return_value=(
                        target_desired,
                        load_profile("openclaw-customer"),
                    ),
                ),
                patch("agent_runtime_ops.commands.rollout._require_retrieval_approval"),
                patch("agent_runtime_ops.commands.rollout._ensure_runtime_dir"),
                patch(
                    "agent_runtime_ops.commands.rollout._apply_desired_slot",
                    side_effect=applied,
                ),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_rollout_image_promote(
                    argparse.Namespace(
                        state_root=str(root),
                        from_slot="oc3",
                        slots="oc4",
                    )
                )

            self.assertEqual(rc, 0, output.getvalue())
            self.assertEqual(events, ["source_verified", "headroom_verified", "target_applied"])
            self.assertIn("PASS promotion_retrieval_source_verified", output.getvalue())
            self.assertIn("PASS promotion_retrieval_headroom_verified", output.getvalue())

    def test_enabled_promotion_refuses_insufficient_headroom_before_apply(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            routes = {item.linux_account: item for item in load_runtime_bindings(root)}
            source_desired = RuntimeTarget(
                target="oc3",
                family="openclaw",
                runtime_class="customer",
                image_name="direct-image",
                image_spec={
                    "wrapper_image": wrapper_image_ref("agent-runtime-openclaw", "9"),
                    "product_image": wrapper_image_ref("openclaw-jitech", "8"),
                    "retrieval_enabled": True,
                },
                runtime_profile="openclaw-customer",
                route=routes["oc3"],
            )
            target_desired = RuntimeTarget(
                target="oc4",
                family="openclaw",
                runtime_class="customer",
                image_name="direct-image",
                image_spec={"retrieval_enabled": True},
                runtime_profile="openclaw-customer",
                route=routes["oc4"],
            )
            output = io.StringIO()
            target_mutations: list[str] = []

            def apply_with_admission(**kwargs: object) -> int:
                admission = kwargs.get("pre_apply_admission")
                self.assertIsNotNone(admission)
                assert callable(admission)
                admission()
                target_mutations.append("target_applied")
                return 0

            with (
                patch("agent_runtime_ops.commands.rollout._is_root", return_value=True),
                patch(
                    "agent_runtime_ops.commands.rollout._desired_from_live_image_truth",
                    return_value=(source_desired, load_profile("openclaw-customer")),
                ),
                patch("agent_runtime_ops.commands.rollout._run_static_slot_checks", return_value=[]),
                patch("agent_runtime_ops.commands.rollout._run_live_slot_checks", return_value=[]),
                patch(
                    "agent_runtime_ops.commands.rollout.find_gateway_container_by_binding",
                    return_value=("container-1", "instance_label"),
                ),
                patch(
                    "agent_runtime_ops.commands.rollout.run_retrieval_status_probe",
                    return_value={"bindingDigest": "sha256:" + "1" * 64},
                ),
                patch(
                    "agent_runtime_ops.commands.rollout.image_spec_from_direct_images",
                    return_value={
                        "wrapper_image": source_desired.image_spec["wrapper_image"],
                        "product_image": source_desired.image_spec["product_image"],
                    },
                ),
                patch(
                    "agent_runtime_ops.commands.rollout._desired_from_direct_images",
                    return_value=(target_desired, load_profile("openclaw-customer")),
                ),
                patch("agent_runtime_ops.commands.rollout._require_retrieval_approval"),
                patch("agent_runtime_ops.commands.rollout._ensure_runtime_dir"),
                patch(
                    "agent_runtime_ops.commands.rollout.measure_retrieval_promotion_headroom",
                    side_effect=ValueError(
                        "host memory headroom is below retrieval reservation"
                    ),
                ),
                patch(
                    "agent_runtime_ops.commands.rollout._apply_desired_slot",
                    side_effect=apply_with_admission,
                ) as apply,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_rollout_image_promote(
                    argparse.Namespace(
                        state_root=str(root),
                        from_slot="oc3",
                        slots="oc4",
                    )
                )

            self.assertEqual(rc, 1)
            self.assertIn(
                "host memory headroom is below retrieval reservation",
                output.getvalue(),
            )
            self.assertEqual(target_mutations, [])
            apply.assert_called_once()

    def test_enabled_promotion_refreshes_source_container_for_each_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            oc5_route = binding(
                "oc5", "openclaw", "customer", 32000, 32001
            )
            current_bindings = load_runtime_bindings(root)
            (root / "runtime-bindings.json").write_text(
                dump_runtime_bindings([*current_bindings, oc5_route]),
                encoding="utf-8",
            )
            routes = {
                item.linux_account: item for item in load_runtime_bindings(root)
            }
            source_desired = RuntimeTarget(
                target="oc3",
                family="openclaw",
                runtime_class="customer",
                image_name="direct-image",
                image_spec={
                    "wrapper_image": wrapper_image_ref(
                        "agent-runtime-openclaw", "9"
                    ),
                    "product_image": wrapper_image_ref("openclaw-jitech", "8"),
                    "retrieval_enabled": True,
                },
                runtime_profile="openclaw-customer",
                route=routes["oc3"],
            )
            target_desired = [
                RuntimeTarget(
                    target="oc4",
                    family="openclaw",
                    runtime_class="customer",
                    image_name="direct-image",
                    image_spec={"retrieval_enabled": True},
                    runtime_profile="openclaw-customer",
                    route=routes["oc4"],
                ),
                RuntimeTarget(
                    target="oc5",
                    family="openclaw",
                    runtime_class="customer",
                    image_name="direct-image",
                    image_spec={"retrieval_enabled": True},
                    runtime_profile="openclaw-customer",
                    route=oc5_route,
                ),
            ]
            verified_containers: list[str] = []
            measured_containers: list[str] = []

            def verify(container: str, *_args: object) -> dict[str, str]:
                verified_containers.append(container)
                return {"bindingDigest": "sha256:" + "1" * 64}

            def measure(container: str, *_args: object) -> dict[str, object]:
                measured_containers.append(container)
                return {
                    "schema": "agent-runtime-retrieval-headroom/v1",
                    "status": "within_required_headroom",
                    "observationDigest": (
                        "sha256:" + str(len(measured_containers)) * 64
                    ),
                }

            def apply_with_admission(**kwargs: object) -> int:
                admission = kwargs.get("pre_apply_admission")
                self.assertIsNotNone(admission)
                assert callable(admission)
                admission()
                return 0

            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.rollout._is_root", return_value=True),
                patch(
                    "agent_runtime_ops.commands.rollout._desired_from_live_image_truth",
                    return_value=(
                        source_desired,
                        load_profile("openclaw-customer"),
                    ),
                ),
                patch(
                    "agent_runtime_ops.commands.rollout._run_static_slot_checks",
                    return_value=[],
                ),
                patch(
                    "agent_runtime_ops.commands.rollout._run_live_slot_checks",
                    return_value=[],
                ),
                patch(
                    "agent_runtime_ops.commands.rollout.find_gateway_container_by_binding",
                    side_effect=[
                        ("source-container-1", "instance_label"),
                        ("source-container-1", "instance_label"),
                        ("source-container-2", "instance_label"),
                        ("source-container-2", "instance_label"),
                    ],
                ),
                patch(
                    "agent_runtime_ops.commands.rollout.run_retrieval_status_probe",
                    side_effect=verify,
                ),
                patch(
                    "agent_runtime_ops.commands.rollout.measure_retrieval_promotion_headroom",
                    side_effect=measure,
                ),
                patch(
                    "agent_runtime_ops.commands.rollout.image_spec_from_direct_images",
                    return_value={
                        "wrapper_image": source_desired.image_spec["wrapper_image"],
                        "product_image": source_desired.image_spec["product_image"],
                    },
                ),
                patch(
                    "agent_runtime_ops.commands.rollout._desired_from_direct_images",
                    side_effect=[
                        (target_desired[0], load_profile("openclaw-customer")),
                        (target_desired[1], load_profile("openclaw-customer")),
                    ],
                ),
                patch("agent_runtime_ops.commands.rollout._require_retrieval_approval"),
                patch("agent_runtime_ops.commands.rollout._ensure_runtime_dir"),
                patch(
                    "agent_runtime_ops.commands.rollout._apply_desired_slot",
                    side_effect=apply_with_admission,
                ),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_rollout_image_promote(
                    argparse.Namespace(
                        state_root=str(root),
                        from_slot="oc3",
                        slots="oc4,oc5",
                    )
                )

            self.assertEqual(rc, 0, output.getvalue())
            self.assertEqual(
                verified_containers,
                ["source-container-1", "source-container-2"],
            )
            self.assertEqual(measured_containers, verified_containers)

    def test_runtime_truth_compares_image_recipe_digest_to_local_canonical_recipe(self) -> None:
        ok, name, detail = local_canonical_recipe_check_from_truth(
            {
                "canonical_recipe_name": "hermes-runtime",
                "canonical_recipe_digest": hermes_runtime_recipe_digest(),
            }
        )
        self.assertTrue(ok, detail)
        self.assertEqual(name, "truth_canonical_recipe_digest_matches_local")

        ok, name, detail = local_canonical_recipe_check_from_truth(
            {
                "canonical_recipe_name": "hermes-runtime",
                "canonical_recipe_digest": "sha256:" + "0" * 64,
            }
        )
        self.assertFalse(ok)
        self.assertEqual(name, "truth_canonical_recipe_digest_matches_local")
        self.assertIn("local=", detail or "")

    def test_live_image_truth_reports_nas_contract_from_image_labels(self) -> None:
        route = binding("dev-oc", "openclaw", "dev", 30789, 30790)
        product_image = wrapper_image_ref("openclaw-jitech", "8")
        labels = openclaw_recipe_labels(product_image=product_image)
        info = {
            "Config": {
                "Image": wrapper_image_ref("agent-runtime-openclaw", "9"),
                "Labels": labels,
            }
        }
        truth = live_image_truth_from_info(route, info, route)
        self.assertEqual(truth["truth_status"], "ok")
        self.assertEqual(truth["runtime_profile"], "openclaw-dev")
        self.assertEqual(truth["container_nas_root"], "/home/node/nas_docs")
        self.assertEqual(truth["host_nas_root_template"], "/home/{slot}/nas_docs")
        self.assertEqual(truth["nas_read_only"], "true")
        self.assertEqual(truth["nas_mount_propagation"], "rslave")
        self.assertEqual(truth["nas_child_mount_mode"], "host-propagated-cifs")

    def test_live_runtime_truth_runs_route_checks_after_module_split(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            route = next(item for item in load_runtime_bindings(root) if item.linux_account == "oc3")
            product_image = wrapper_image_ref("openclaw-jitech", "8")
            labels = openclaw_recipe_labels(product_image=product_image)
            profile = load_profile("openclaw-customer")
            absent_binding = bind_retrieval_intent(
                {},
                instance_id=route.instance_id,
                family=route.family,
                runtime_profile_digest=profile.digest,
                container_nas_root=str(profile.metadata["container_nas_root"]),
                enabled=False,
            )
            labels.update(
                {
                    "agent-runtime.retrieval-enabled": "false",
                    "agent-runtime.retrieval-component-digest": "",
                    "agent-runtime.retrieval-binding-digest": str(
                        absent_binding["retrieval_binding_digest"]
                    ),
                    "agent-runtime.retrieval-resource-profile-digest": "",
                }
            )
            info = {
                "Config": {
                    "Image": wrapper_image_ref("agent-runtime-openclaw", "9"),
                    "Labels": labels,
                }
            }
            apache_route = argparse.Namespace(
                public_host=route.public_host,
                gateway_port=route.gateway_port,
                websocket_port=None,
            )
            inspect_result = subprocess.CompletedProcess(
                ["docker", "inspect", "container-1"],
                0,
                stdout=json.dumps([info]),
                stderr="",
            )

            with (
                patch("agent_runtime_ops.domain.runtime_truth.parse_apache_route", return_value=apache_route),
                patch("agent_runtime_ops.domain.runtime_truth.find_gateway_container_by_binding", return_value=("container-1", "instance_label")),
                patch("agent_runtime_ops.domain.runtime_truth.run_text", return_value=inspect_result),
            ):
                truth, checks = live_runtime_truth("oc3", root)

            self.assertEqual(truth["truth_status"], "ok")
            self.assertIn((True, "apache_public_host_matches_binding", f"apache={route.public_host} binding={route.public_host}"), checks)
            self.assertTrue(any(name == "truth_container_lookup" and ok for ok, name, _ in checks))
            self.assertTrue(
                any(
                    name == "truth_retrieval_binding_matches_expected" and ok
                    for ok, name, _ in checks
                )
            )

    def test_live_runtime_truth_rejects_empty_runtime_projection_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            route = next(
                item
                for item in load_runtime_bindings(root)
                if item.linux_account == "oc3"
            )
            labels = openclaw_recipe_labels(
                product_image=wrapper_image_ref("openclaw-jitech", "8")
            )
            info = {
                "Config": {
                    "Image": wrapper_image_ref("agent-runtime-openclaw", "9"),
                    "Labels": labels,
                }
            }
            apache_route = argparse.Namespace(
                public_host=route.public_host,
                gateway_port=route.gateway_port,
                websocket_port=None,
            )
            inspect_result = subprocess.CompletedProcess(
                ["docker", "inspect", "container-1"],
                0,
                stdout=json.dumps([info]),
                stderr="",
            )

            with (
                patch(
                    "agent_runtime_ops.domain.runtime_truth.parse_apache_route",
                    return_value=apache_route,
                ),
                patch(
                    "agent_runtime_ops.domain.runtime_truth.find_gateway_container_by_binding",
                    return_value=("container-1", "instance_label"),
                ),
                patch(
                    "agent_runtime_ops.domain.runtime_truth.run_text",
                    return_value=inspect_result,
                ),
            ):
                _, checks = live_runtime_truth("oc3", root)

            self.assertIn(
                (
                    False,
                    "truth_retrieval_projection_complete_and_consistent",
                    "invalid",
                ),
                checks,
            )
            self.assertTrue(
                any(
                    name == "truth_retrieval_binding_matches_expected" and not ok
                    for ok, name, _ in checks
                )
            )

    def test_live_runtime_truth_rejects_wrong_target_specific_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            route = next(
                item
                for item in load_runtime_bindings(root)
                if item.linux_account == "oc3"
            )
            labels = openclaw_recipe_labels(
                product_image=wrapper_image_ref("openclaw-jitech", "8")
            )
            labels.update(
                {
                    "agent-runtime.retrieval-enabled": "false",
                    "agent-runtime.retrieval-component-digest": "",
                    "agent-runtime.retrieval-binding-digest": "sha256:" + "9" * 64,
                    "agent-runtime.retrieval-resource-profile-digest": "",
                }
            )
            info = {
                "Config": {
                    "Image": wrapper_image_ref("agent-runtime-openclaw", "9"),
                    "Labels": labels,
                }
            }
            apache_route = argparse.Namespace(
                public_host=route.public_host,
                gateway_port=route.gateway_port,
                websocket_port=None,
            )
            inspect_result = subprocess.CompletedProcess(
                ["docker", "inspect", "container-1"],
                0,
                stdout=json.dumps([info]),
                stderr="",
            )

            with (
                patch(
                    "agent_runtime_ops.domain.runtime_truth.parse_apache_route",
                    return_value=apache_route,
                ),
                patch(
                    "agent_runtime_ops.domain.runtime_truth.find_gateway_container_by_binding",
                    return_value=("container-1", "instance_label"),
                ),
                patch(
                    "agent_runtime_ops.domain.runtime_truth.run_text",
                    return_value=inspect_result,
                ),
            ):
                truth, checks = live_runtime_truth("oc3", root)

            self.assertNotEqual(
                truth["retrieval_binding_digest"],
                truth["retrieval_expected_binding_digest"],
            )
            self.assertTrue(
                any(
                    name == "truth_retrieval_binding_matches_expected" and not ok
                    for ok, name, _ in checks
                )
            )

    def test_live_runtime_truth_rejects_partial_retrieval_label_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            route = next(
                item
                for item in load_runtime_bindings(root)
                if item.linux_account == "oc3"
            )
            labels = openclaw_recipe_labels(
                product_image=wrapper_image_ref("openclaw-jitech", "8")
            )
            labels["com.epicevent.agent-runtime.retrieval.component-digest"] = (
                "sha256:" + "1" * 64
            )
            info = {
                "Config": {
                    "Image": wrapper_image_ref("agent-runtime-openclaw", "9"),
                    "Labels": labels,
                }
            }
            apache_route = argparse.Namespace(
                public_host=route.public_host,
                gateway_port=route.gateway_port,
                websocket_port=None,
            )
            inspect_result = subprocess.CompletedProcess(
                ["docker", "inspect", "container-1"],
                0,
                stdout=json.dumps([info]),
                stderr="",
            )

            with (
                patch(
                    "agent_runtime_ops.domain.runtime_truth.parse_apache_route",
                    return_value=apache_route,
                ),
                patch(
                    "agent_runtime_ops.domain.runtime_truth.find_gateway_container_by_binding",
                    return_value=("container-1", "instance_label"),
                ),
                patch(
                    "agent_runtime_ops.domain.runtime_truth.run_text",
                    return_value=inspect_result,
                ),
            ):
                truth, checks = live_runtime_truth("oc3", root)

            self.assertEqual(truth["retrieval_labels_present"], "true")
            self.assertIn(
                (False, "truth_retrieval_label_set_complete", "false"),
                checks,
            )

    def test_wrapper_image_recipe_rejects_component_mismatch(self) -> None:
        product_image = wrapper_image_ref("hermes-workspace", "2")
        wrapper_image = wrapper_image_ref("agent-runtime-hermes", "3")
        labels = hermes_recipe_labels(**{"product-component": "combined-runtime"})
        with patch("agent_runtime_ops.domain.image_specs.image_recipe_labels_from_wrapper", return_value=labels):
            with self.assertRaisesRegex(ValueError, "product-component mismatch"):
                image_recipe_from_wrapper_image(wrapper_image, family="hermes", product_image=product_image)

    def test_live_check_prefers_live_image_truth_over_legacy_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            route = next(route for route in load_runtime_bindings(root) if route.linux_account == "dev-oc")
            wrapper_image = wrapper_image_ref("agent-runtime-openclaw", "9")
            product_image = wrapper_image_ref("openclaw-jitech", "8")
            image_spec = {
                "family": "openclaw",
                "image_name": "direct-image",
                "wrapper_image": wrapper_image,
                "product_image": product_image,
                "digest": "sha256:" + "9" * 64,
                "product_digest": "sha256:" + "8" * 64,
                "mode": "wrapped_product_image",
                "image_recipe": openclaw_image_recipe(product_image=product_image),
            }
            desired = RuntimeTarget(
                target="dev-oc",
                family="openclaw",
                runtime_class="dev",
                image_name="direct-image",
                image_spec=image_spec,
                runtime_profile="openclaw-dev",
                route=route,
            )
            output = io.StringIO()
            with (
                patch(
                    "agent_runtime_ops.commands.check._desired_from_live_image_truth",
                    return_value=(desired, load_profile("openclaw-dev")),
                ),
                patch(
                    "agent_runtime_ops.commands.check._run_live_slot_checks",
                    return_value=[(True, "live_container_image_matches_spec", wrapper_image)],
                ),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_check(argparse.Namespace(state_root=str(root), slot="dev-oc", live=True))

            text = output.getvalue()
            self.assertEqual(rc, 0, text)
            self.assertIn("image_name=direct-image", text)
            self.assertIn(wrapper_image, text)
            self.assertIn("canonical_recipe_name=openclaw-control", text)
            self.assertNotIn(image_ref("1"), text)
            self.assertIn("PASS live_container_image_matches_spec", text)

    def test_live_slot_checks_resolve_gateway_lookup_after_module_split(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            route = next(item for item in load_runtime_bindings(root) if item.linux_account == "oc3")
            desired = RuntimeTarget(
                target="oc3",
                family="openclaw",
                runtime_class="customer",
                image_name="direct-image",
                image_spec={
                    "family": "openclaw",
                    "image_name": "direct-image",
                    "wrapper_image": wrapper_image_ref("agent-runtime-openclaw", "9"),
                    "product_image": wrapper_image_ref("openclaw-jitech", "8"),
                    "digest": "sha256:" + "9" * 64,
                    "product_digest": "sha256:" + "8" * 64,
                    "mode": "wrapped_product_image",
                    "image_recipe": openclaw_image_recipe(product_image=wrapper_image_ref("openclaw-jitech", "8")),
                },
                runtime_profile="openclaw-customer",
                route=route,
            )

            with (
                patch("agent_runtime_ops.domain.runtime_checks.is_root", return_value=True),
                patch("agent_runtime_ops.domain.runtime_checks.find_gateway_container", return_value=(None, "not_found")),
            ):
                checks = run_live_slot_checks(desired, load_profile("openclaw-customer"), root)

            self.assertIn((False, "live_container_lookup", "not_found"), checks)

    def test_check_ignores_legacy_lane_release_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hermes_state(root)
            (root / "lanes.yaml").write_text(
                dump_yaml({"lanes": {"hermes": {"family": "hermes", "runtime_profile": "wrong-profile"}}}),
                encoding="utf-8",
            )
            (root / "releases.yaml").write_text(
                dump_yaml(
                    {
                        "releases": {
                            "hermes-candidate": {
                                "family": "hermes",
                                "wrapper_image": image_ref("9"),
                                "product_image": image_ref("9"),
                                "digest": "sha256:" + "9" * 64,
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = cmd_check(argparse.Namespace(state_root=str(root), slot="oc20", live=False))

            text = output.getvalue()
            self.assertEqual(rc, 0, text)
            self.assertIn("image_name=direct-image", text)
            self.assertIn("runtime_contract=hermes-workspace-http-3000", text)
            self.assertIn("PASS product_image_matches_runtime_contract", text)
            self.assertIn("canonical_recipe_name=hermes-combined", text)

    def test_hermes_customer_accepts_current_combined_runtime_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hermes_state(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = cmd_check(argparse.Namespace(state_root=str(root), slot="oc20", live=False))

            text = output.getvalue()
            self.assertEqual(rc, 0, text)
            self.assertIn("runtime_contract=hermes-workspace-http-3000", text)
            self.assertIn("PASS product_image_matches_runtime_contract", text)
            self.assertIn("product_component=combined-runtime", text)
            self.assertIn("canonical_recipe_name=hermes-combined", text)

if __name__ == "__main__":
    unittest.main()
