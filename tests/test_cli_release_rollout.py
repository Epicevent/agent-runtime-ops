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

from agent_runtime_ops.cli import (
    IMAGE_RECIPE_LABEL_PREFIX,
    cmd_apply,
    cmd_check,
    cmd_binding_normalize,
    cmd_diagnostics_show,
    cmd_recipe_dev_apply,
    cmd_recipe_dev_status,
    cmd_recipe_validate_canonical,
    cmd_release_import,
    cmd_rollout_canary,
    cmd_rollout_dev_apply,
    cmd_rollout_dev_plan,
    cmd_rollout_image_plan,
    cmd_rollout_plan,
    cmd_rollout_promote,
    cmd_rollout_rollback_canary,
    cmd_rollout_status,
    _image_recipe_from_wrapper_image,
    _live_image_truth_from_info,
)
from agent_runtime_ops.canonical_recipes import load_canonical_recipe
from agent_runtime_ops.profiles import load_profile
from agent_runtime_ops.routing import RuntimeBinding, dump_runtime_bindings, load_runtime_bindings
from agent_runtime_ops.state import DesiredSlot
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
        "ops-repo-commit": "8be9e466c28f821a907a40ab2b0068910c6762cf",
    }
    values.update(overrides)
    return {IMAGE_RECIPE_LABEL_PREFIX + key: value for key, value in values.items()}


def hermes_release_entry(candidate_product_repo: str = "hermes-workspace") -> str:
    candidate_digest = "sha256:" + "2" * 64
    wrapper_digest = "sha256:" + "3" * 64
    product_image = f"ghcr.io/epicevent/{candidate_product_repo}@{candidate_digest}"
    recipe = hermes_image_recipe(
        product_image=product_image,
        product_component="hermes-workspace" if candidate_product_repo == "hermes-workspace" else "hermes-agent",
    )
    return f"""
  hermes-candidate:
    family: hermes
    wrapper_image: ghcr.io/epicevent/agent-runtime-hermes@{wrapper_digest}
    product_image: {product_image}
    digest: {wrapper_digest}
    compatibility_mode: wrapped_product_image
    image_recipe: {json.dumps(recipe)}
    components:
      product_image: {product_image}
      wrapper_image: ghcr.io/epicevent/agent-runtime-hermes@{wrapper_digest}
      product_component: {recipe["product_component"]}
      wrapper_component: hermes-wrapper
      runtime_profile_customer: hermes-workspace-customer
      runtime_profile_dev: hermes-workspace-dev
"""


def import_args(root: Path, **overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "state_root": str(root),
        "name": "openclaw-candidate",
        "family": "openclaw",
        "image": image_ref("2"),
        "product_image": None,
        "wrapper_image": None,
        "image_name": None,
        "compat_combined": True,
        "replace": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def write_slot_registry(root: Path, slots: list[str]) -> None:
    default_ports = {
        "oc3": (28989, 28990),
        "oc4": (29089, 29090),
        "oc20": (30689, 30690),
        "dev-oc": (30789, 30790),
        "dev-hermess": (30889, 30890),
    }
    slot_family = {}
    slot_class = {}
    slots_data = load_yaml(root / "slots.yaml")
    lanes_data = load_yaml(root / "lanes.yaml")
    lanes = lanes_data.get("lanes") or {}
    for item in slots_data.get("slots") or []:
        if isinstance(item, dict):
            lane = item.get("lane")
            lane_data = lanes.get(lane) if lane else {}
            slot_family[str(item.get("slot"))] = str(lane_data.get("family") or "openclaw")
            slot_class[str(item.get("slot"))] = str(lane_data.get("slot_class") or "customer")
    bindings = []
    for index, slot in enumerate(slots):
        gateway_port, bridge_port = default_ports.get(slot, (32000 + index * 2, 32001 + index * 2))
        bindings.append(binding(slot, slot_family.get(slot, "openclaw"), slot_class.get(slot, "customer"), gateway_port, bridge_port))
    (root / "runtime-bindings.json").write_text(dump_runtime_bindings(bindings), encoding="utf-8")


def write_hermes_state(root: Path, *, candidate_product_repo: str = "hermes-workspace") -> None:
    current_digest = "sha256:" + "1" * 64
    (root / "slots.yaml").write_text(
        """
slots:
  - slot: oc20
    lane: hermes
  - slot: dev-hermess
    lane: dev-hermes
""".lstrip(),
        encoding="utf-8",
    )
    (root / "lanes.yaml").write_text(
        """
lanes:
  hermes:
    family: hermes
    slot_class: customer
    release: hermes-current
    runtime_profile: hermes-customer
  dev-hermes:
    family: hermes
    slot_class: dev
    release: hermes-current
    runtime_profile: hermes-dev
""".lstrip(),
        encoding="utf-8",
    )
    (root / "releases.yaml").write_text(
        f"""
releases:
  hermes-current:
    family: hermes
    wrapper_image: ghcr.io/epicevent/openclaw-nas-agent@{current_digest}
    product_image: ghcr.io/epicevent/openclaw-nas-agent@{current_digest}
    digest: {current_digest}
{hermes_release_entry(candidate_product_repo)}
""".lstrip(),
        encoding="utf-8",
    )
    write_slot_registry(root, ["oc20", "dev-hermess"])


def write_state(root: Path) -> None:
    current_digest = "sha256:" + "1" * 64
    (root / "slots.yaml").write_text(
        """
slots:
  - slot: oc3
    lane: openclaw
  - slot: oc4
    lane: openclaw
  - slot: dev-oc
    lane: dev-openclaw
""".lstrip(),
        encoding="utf-8",
    )
    (root / "lanes.yaml").write_text(
        """
lanes:
  openclaw:
    family: openclaw
    slot_class: customer
    release: openclaw-current
    runtime_profile: openclaw-customer
  dev-openclaw:
    family: openclaw
    slot_class: dev
    release: openclaw-current
    runtime_profile: openclaw-dev
""".lstrip(),
        encoding="utf-8",
    )
    (root / "releases.yaml").write_text(
        f"""
releases:
  openclaw-current:
    family: openclaw
    wrapper_image: ghcr.io/epicevent/openclaw-nas-agent@{current_digest}
    product_image: ghcr.io/epicevent/openclaw-nas-agent@{current_digest}
    digest: {current_digest}
""".lstrip(),
        encoding="utf-8",
    )
    write_slot_registry(root, ["oc3", "oc4", "dev-oc"])


def import_candidate(root: Path, name: str = "openclaw-candidate") -> None:
    output = io.StringIO()
    with patch("agent_runtime_ops.cli._is_root", return_value=True), contextlib.redirect_stdout(output):
        rc = cmd_release_import(import_args(root, name=name))
    assert rc == 0, output.getvalue()


class CliReleaseRolloutTests(unittest.TestCase):
    def test_rollout_status_reports_runtime_manifest_truth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hermes_state(root)
            wrapper_image = wrapper_image_ref("agent-runtime-hermes", "3")
            product_image = wrapper_image_ref("hermes-workspace", "2")
            manifest_dir = root / "runtime" / "oc20"
            manifest_dir.mkdir(parents=True)
            (manifest_dir / "manifest.yaml").write_text(
                dump_yaml(
                    {
                        "schema_version": 1,
                        "slot": "oc20",
                        "release": "direct-image",
                        "family": "hermes",
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
            self.assertIn("status_source=legacy_rollout_state", text)
            self.assertIn("runtime_status_source=runtime_manifests", text)
            self.assertIn("runtime_manifest_direct_image_slots=oc20", text)
            self.assertIn("runtime_manifest_canonical_recipe_names=hermes-workspace", text)
            self.assertIn("status_warning=legacy_rollout_state_is_not_runtime_truth", text)

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
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli._slot_runtime_dir", return_value=runtime_dir),
                patch("agent_runtime_ops.cli._run_text_cwd", side_effect=fake_run),
                patch(
                    "agent_runtime_ops.cli._run_live_slot_checks_with_wait",
                    return_value=[(True, "live_runtime_recreated", "ok")],
                ),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_apply(argparse.Namespace(state_root=str(root), slot="oc3", allow_first_apply=True))

            self.assertEqual(rc, 0, output.getvalue())
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
            diag_dir = runtime_dir / ".agent-runtime-backups" / "failed-container"

            def fake_restore(*args: object, **kwargs: object) -> tuple[bool, str]:
                events.append("restore")
                return True, "rollback_applied"

            def fake_diagnostics(*args: object, **kwargs: object) -> Path:
                events.append("diagnostics")
                return diag_dir

            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli._slot_runtime_dir", return_value=runtime_dir),
                patch(
                    "agent_runtime_ops.cli._run_text_cwd",
                    return_value=subprocess.CompletedProcess(["docker"], 0, "", ""),
                ),
                patch(
                    "agent_runtime_ops.cli._run_live_slot_checks_with_wait",
                    return_value=[(False, "live_backend_http_smoke_ok", "connection reset")],
                ),
                patch("agent_runtime_ops.cli._write_failed_container_diagnostics", side_effect=fake_diagnostics),
                patch("agent_runtime_ops.cli._restore_backup", side_effect=fake_restore),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_apply(argparse.Namespace(state_root=str(root), slot="oc3", allow_first_apply=True))

            self.assertEqual(rc, 1)
            self.assertEqual(events, ["diagnostics", "restore"])
            self.assertIn(f"failure_diagnostics_dir={diag_dir}", output.getvalue())

    def test_diagnostics_show_prints_redacted_failure_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime_dir = root / "home" / "oc3" / "openclaw"
            diag_dir = runtime_dir / ".agent-runtime-backups" / "20260609T000000+0900" / "failed-container"
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
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli._slot_runtime_dir", return_value=runtime_dir),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_diagnostics_show(argparse.Namespace(slot="oc3", dir=str(diag_dir), tail=20))

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
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli._ensure_dev_runtime_dir", return_value=runtime_dir),
                patch("agent_runtime_ops.cli._slot_uid_gid", return_value=(1000, 1000)),
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

    def test_binding_normalize_migrates_legacy_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            (root / "runtime-bindings.json").unlink()
            (root / "slot-registry.json").write_text(
                json.dumps(
                    {
                        "schema": "v2",
                        "slots": [
                            {"slot": "oc3", "gateway_port": 28989, "bridge_port": 28990},
                            {"slot": "dev-oc", "gateway_port": 30789, "bridge_port": 30790},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output = io.StringIO()
            with patch("agent_runtime_ops.cli._is_root", return_value=True), contextlib.redirect_stdout(output):
                rc = cmd_binding_normalize(argparse.Namespace(state_root=str(root), write=True))
            self.assertEqual(rc, 0, output.getvalue())
            bindings = {item.linux_account: item for item in load_runtime_bindings(root)}
            self.assertEqual(bindings["oc3"].gateway_port, 28989)
            self.assertEqual(bindings["oc3"].family, "openclaw")
            self.assertEqual(bindings["dev-oc"].runtime_class, "dev")
            text = (root / "runtime-bindings.json").read_text(encoding="utf-8")
            self.assertIn('"schema": "v1"', text)
            self.assertIn("public_host", text)
            self.assertNotIn("notes", text)
            self.assertNotIn("runtime_profile", text)
            self.assertNotIn("release", text)

    def test_binding_normalize_rewrites_runtime_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            output = io.StringIO()
            with patch("agent_runtime_ops.cli._is_root", return_value=True), contextlib.redirect_stdout(output):
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
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli._image_recipe_labels_from_wrapper", return_value=hermes_recipe_labels(product_image=product)),
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
            self.assertEqual(plan["slots"][0]["gateway_port"], 30689)
            self.assertEqual(plan["slots"][0]["runtime_profile"], "hermes-workspace-customer")

    def test_release_import_registers_combined_digest_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            output = io.StringIO()
            with patch("agent_runtime_ops.cli._is_root", return_value=True), contextlib.redirect_stdout(output):
                rc = cmd_release_import(import_args(root))
            self.assertEqual(rc, 0, output.getvalue())
            releases = load_yaml(root / "releases.yaml")["releases"]
            candidate = releases["openclaw-candidate"]
            self.assertEqual(candidate["family"], "openclaw")
            self.assertEqual(candidate["wrapper_image"], image_ref("2"))
            self.assertEqual(candidate["product_image"], image_ref("2"))
            self.assertEqual(candidate["digest"], "sha256:" + "2" * 64)
            self.assertEqual(candidate["compatibility_mode"], "combined_runtime_image")
            self.assertEqual(candidate["components"]["product_component"], "combined-runtime")
            self.assertIn("release_digest=sha256:" + "2" * 64, output.getvalue())
            self.assertIn("product_component=combined-runtime", output.getvalue())

    def test_wrapper_image_recipe_reads_oci_labels(self) -> None:
        product_image = wrapper_image_ref("hermes-workspace", "2")
        wrapper_image = wrapper_image_ref("agent-runtime-hermes", "3")
        with patch("agent_runtime_ops.cli._image_recipe_labels_from_wrapper", return_value=hermes_recipe_labels()):
            recipe = _image_recipe_from_wrapper_image(wrapper_image, family="hermes", product_image=product_image)
        self.assertEqual(recipe["source"], "wrapper_image_labels")
        self.assertEqual(recipe["canonical_recipe_name"], "hermes-workspace")
        self.assertEqual(recipe["canonical_recipe_digest"], hermes_workspace_recipe_digest())
        self.assertEqual(recipe["runtime_profiles"]["customer"], "hermes-workspace-customer")
        self.assertEqual(recipe["product_component"], "hermes-workspace")

    def test_wrapper_image_recipe_rejects_canonical_digest_mismatch(self) -> None:
        product_image = wrapper_image_ref("hermes-workspace", "2")
        wrapper_image = wrapper_image_ref("agent-runtime-hermes", "3")
        labels = hermes_recipe_labels(**{"recipe.digest": "sha256:" + "9" * 64})
        with patch("agent_runtime_ops.cli._image_recipe_labels_from_wrapper", return_value=labels):
            with self.assertRaisesRegex(ValueError, "canonical recipe digest mismatch"):
                _image_recipe_from_wrapper_image(wrapper_image, family="hermes", product_image=product_image)

    def test_wrapper_image_recipe_rejects_missing_canonical_identity(self) -> None:
        product_image = wrapper_image_ref("hermes-workspace", "2")
        wrapper_image = wrapper_image_ref("agent-runtime-hermes", "3")
        labels = hermes_recipe_labels(**{"recipe.name": "", "recipe.digest": ""})
        with patch("agent_runtime_ops.cli._image_recipe_labels_from_wrapper", return_value=labels):
            with self.assertRaisesRegex(ValueError, "missing canonical recipe name"):
                _image_recipe_from_wrapper_image(wrapper_image, family="hermes", product_image=product_image)

    def test_live_image_truth_rejects_partial_recipe_labels(self) -> None:
        route = binding("oc20", "hermes", "customer", 30689, 30690)
        labels = hermes_recipe_labels(**{"recipe.name": "", "recipe.digest": ""})
        info = {
            "Config": {
                "Image": wrapper_image_ref("agent-runtime-hermes", "3"),
                "Labels": labels,
            }
        }
        truth = _live_image_truth_from_info(route, info, route)
        self.assertEqual(truth["truth_status"], "incomplete_recipe_labels")
        self.assertEqual(truth["canonical_recipe_name"], "")
        self.assertEqual(truth["canonical_recipe_digest"], "")

    def test_wrapper_image_recipe_rejects_component_mismatch(self) -> None:
        product_image = wrapper_image_ref("hermes-workspace", "2")
        wrapper_image = wrapper_image_ref("agent-runtime-hermes", "3")
        labels = hermes_recipe_labels(**{"product-component": "combined-runtime"})
        with patch("agent_runtime_ops.cli._image_recipe_labels_from_wrapper", return_value=labels):
            with self.assertRaisesRegex(ValueError, "product-component mismatch"):
                _image_recipe_from_wrapper_image(wrapper_image, family="hermes", product_image=product_image)

    def test_release_import_registers_labeled_wrapper_recipe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hermes_state(root)
            product_image = wrapper_image_ref("hermes-workspace", "2")
            wrapper_image = wrapper_image_ref("agent-runtime-hermes", "3")
            recipe = hermes_image_recipe(product_image=product_image)
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli._image_recipe_from_wrapper_image", return_value=recipe),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_release_import(
                    import_args(
                        root,
                        name="hermes-labeled",
                        family="hermes",
                        image=None,
                        product_image=product_image,
                        wrapper_image=wrapper_image,
                        compat_combined=False,
                    )
                )
            self.assertEqual(rc, 0, output.getvalue())
            release = load_yaml(root / "releases.yaml")["releases"]["hermes-labeled"]
            self.assertEqual(release["compatibility_mode"], "wrapped_product_image")
            self.assertEqual(release["image_recipe"]["canonical_recipe_name"], "hermes-workspace")
            self.assertEqual(release["image_recipe"]["canonical_recipe_digest"], hermes_workspace_recipe_digest())
            self.assertEqual(release["components"]["canonical_recipe_name"], "hermes-workspace")
            self.assertEqual(release["image_recipe"]["runtime_profiles"]["customer"], "hermes-workspace-customer")
            self.assertEqual(release["components"]["runtime_profile_customer"], "hermes-workspace-customer")
            self.assertIn("canonical_recipe_name=hermes-workspace", output.getvalue())
            self.assertIn("runtime_profile_customer=hermes-workspace-customer", output.getvalue())

    def test_release_import_rejects_split_wrapper_without_recipe_labels(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hermes_state(root)
            product_image = wrapper_image_ref("hermes-workspace", "2")
            wrapper_image = wrapper_image_ref("agent-runtime-hermes", "3")
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch(
                    "agent_runtime_ops.cli._image_recipe_from_wrapper_image",
                    side_effect=ValueError("wrapper image is missing agent-runtime recipe labels"),
                ),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_release_import(
                    import_args(
                        root,
                        name="hermes-unlabeled",
                        family="hermes",
                        image=None,
                        product_image=product_image,
                        wrapper_image=wrapper_image,
                        compat_combined=False,
                    )
                )
            self.assertEqual(rc, 1)
            self.assertIn("missing agent-runtime recipe labels", output.getvalue())

    def test_release_import_rejects_tag_only_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            output = io.StringIO()
            with patch("agent_runtime_ops.cli._is_root", return_value=True), contextlib.redirect_stdout(output):
                rc = cmd_release_import(import_args(root, name="openclaw-bad", image="ghcr.io/epicevent/openclaw-nas-agent:latest"))
            self.assertEqual(rc, 1)
            self.assertIn("pinned by digest", output.getvalue())

    def test_rollout_plan_is_non_mutating(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            import_candidate(root)
            before = (root / "lanes.yaml").read_text(encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = cmd_rollout_plan(
                    argparse.Namespace(state_root=str(root), family="openclaw", release="openclaw-candidate")
                )
            self.assertEqual(rc, 0, output.getvalue())
            self.assertIn('"mutates": false', output.getvalue())
            self.assertIn('"release_digest": "sha256:' + "2" * 64 + '"', output.getvalue())
            self.assertEqual((root / "lanes.yaml").read_text(encoding="utf-8"), before)

    def test_live_check_prefers_live_image_truth_over_legacy_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            route = next(route for route in load_runtime_bindings(root) if route.linux_account == "dev-oc")
            wrapper_image = wrapper_image_ref("agent-runtime-openclaw", "9")
            product_image = wrapper_image_ref("openclaw-jitech", "8")
            release_data = {
                "family": "openclaw",
                "image_name": "direct-image",
                "wrapper_image": wrapper_image,
                "product_image": product_image,
                "digest": "sha256:" + "9" * 64,
                "product_digest": "sha256:" + "8" * 64,
                "compatibility_mode": "wrapped_product_image",
                "image_recipe": openclaw_image_recipe(product_image=product_image),
            }
            desired = DesiredSlot(
                slot="dev-oc",
                lane="image-openclaw-dev",
                lane_data={"family": "openclaw", "slot_class": "dev"},
                release_name="direct-image",
                release_data=release_data,
                runtime_profile="openclaw-dev",
                route=route,
            )
            output = io.StringIO()
            with (
                patch(
                    "agent_runtime_ops.cli._desired_from_live_image_truth",
                    return_value=(desired, load_profile("openclaw-dev")),
                ),
                patch(
                    "agent_runtime_ops.cli._run_live_slot_checks",
                    return_value=[(True, "live_container_image_matches_release", wrapper_image)],
                ),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_check(argparse.Namespace(state_root=str(root), slot="dev-oc", live=True))

            text = output.getvalue()
            self.assertEqual(rc, 0, text)
            self.assertIn("release=direct-image", text)
            self.assertIn(wrapper_image, text)
            self.assertIn("canonical_recipe_name=openclaw-control", text)
            self.assertNotIn(image_ref("1"), text)
            self.assertIn("PASS live_container_image_matches_release", text)

    def test_hermes_customer_rejects_agent_only_product_image_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hermes_state(root, candidate_product_repo="hermes-jitech")
            lanes = load_yaml(root / "lanes.yaml")
            lanes["lanes"]["hermes"]["release"] = "hermes-candidate"
            (root / "lanes.yaml").write_text(dump_yaml(lanes), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = cmd_check(argparse.Namespace(state_root=str(root), slot="oc20", live=False))

            text = output.getvalue()
            self.assertEqual(rc, 1, text)
            self.assertIn("runtime_contract=hermes-workspace-http-3000", text)
            self.assertIn("FAIL product_image_matches_runtime_contract", text)
            self.assertIn("product_component=hermes-agent", text)

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

    def test_rollout_plan_shows_hermes_contract_incompatibility(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hermes_state(root, candidate_product_repo="hermes-jitech")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = cmd_rollout_plan(argparse.Namespace(state_root=str(root), family="hermes", release="hermes-candidate"))

            self.assertEqual(rc, 0, output.getvalue())
            plan = json.loads(output.getvalue())
            self.assertFalse(plan["contract_compatible"])
            self.assertEqual(plan["runtime_profile"], "hermes-workspace-customer")
            self.assertEqual(plan["runtime_contract"], "hermes-workspace-http-3000")
            failed = [item["name"] for item in plan["contract_checks"] if not item["ok"]]
            self.assertIn("product_image_matches_runtime_contract", failed)

    def test_rollout_plan_uses_image_recipe_runtime_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hermes_state(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = cmd_rollout_plan(argparse.Namespace(state_root=str(root), family="hermes", release="hermes-candidate"))

            self.assertEqual(rc, 0, output.getvalue())
            plan = json.loads(output.getvalue())
            self.assertTrue(plan["contract_compatible"], output.getvalue())
            self.assertEqual(plan["fleet_runtime_profile"], "hermes-customer")
            self.assertEqual(plan["runtime_profile"], "hermes-workspace-customer")
            self.assertEqual(plan["recipe"]["canonical_recipe_name"], "hermes-workspace")
            self.assertEqual(plan["recipe"]["canonical_recipe_digest"], hermes_workspace_recipe_digest())

    def test_rollout_dev_plan_uses_image_recipe_dev_runtime_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hermes_state(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = cmd_rollout_dev_plan(
                    argparse.Namespace(
                        state_root=str(root),
                        family="hermes",
                        release="hermes-candidate",
                        slot="dev-hermess",
                    )
                )

            self.assertEqual(rc, 0, output.getvalue())
            plan = json.loads(output.getvalue())
            self.assertTrue(plan["contract_compatible"], output.getvalue())
            self.assertEqual(plan["current_runtime_profile"], "hermes-dev")
            self.assertEqual(plan["runtime_profile"], "hermes-workspace-dev")
            self.assertEqual(plan["lane_slots"], ["dev-hermess"])
            self.assertEqual(plan["recipe"]["canonical_recipe_name"], "hermes-workspace")

    def test_rollout_dev_apply_records_image_recipe_dev_runtime_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hermes_state(root)
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli.cmd_apply", return_value=0) as apply,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_rollout_dev_apply(
                    argparse.Namespace(
                        state_root=str(root),
                        family="hermes",
                        release="hermes-candidate",
                        slot="dev-hermess",
                        allow_first_apply=False,
                    )
                )
            self.assertEqual(rc, 0, output.getvalue())
            lanes = load_yaml(root / "lanes.yaml")["lanes"]
            self.assertEqual(lanes["dev-hermes"]["release"], "hermes-candidate")
            self.assertEqual(lanes["dev-hermes"]["runtime_profile"], "hermes-workspace-dev")
            rollout = load_yaml(root / "rollout-state.yaml")
            self.assertEqual(rollout["families"]["hermes"]["dev_slots"]["dev-hermess"]["runtime_profile"], "hermes-workspace-dev")
            self.assertEqual(
                rollout["families"]["hermes"]["dev_slots"]["dev-hermess"]["canonical_recipe_name"],
                "hermes-workspace",
            )
            self.assertEqual(apply.call_args.args[0].slot, "dev-hermess")

    def test_rollout_dev_apply_restores_lane_when_apply_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hermes_state(root)
            lanes_before = load_yaml(root / "lanes.yaml")
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli.cmd_apply", return_value=1),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_rollout_dev_apply(
                    argparse.Namespace(
                        state_root=str(root),
                        family="hermes",
                        release="hermes-candidate",
                        slot="dev-hermess",
                        allow_first_apply=False,
                    )
                )
            self.assertEqual(rc, 1)
            self.assertIn("reason=dev_apply_failed", output.getvalue())
            self.assertEqual(load_yaml(root / "lanes.yaml"), lanes_before)

    def test_rollout_canary_rejects_hermes_agent_only_image_before_state_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hermes_state(root, candidate_product_repo="hermes-jitech")
            before_slots = (root / "slots.yaml").read_text(encoding="utf-8")
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli.cmd_apply") as apply,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_rollout_canary(
                    argparse.Namespace(
                        state_root=str(root),
                        family="hermes",
                        release="hermes-candidate",
                        slot="oc20",
                        allow_first_apply=False,
                    )
                )

            self.assertEqual(rc, 1)
            self.assertIn("release does not satisfy runtime contract", output.getvalue())
            self.assertEqual((root / "slots.yaml").read_text(encoding="utf-8"), before_slots)
            apply.assert_not_called()

    def test_rollout_canary_records_image_recipe_runtime_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hermes_state(root)
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli.cmd_apply", return_value=0) as apply,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_rollout_canary(
                    argparse.Namespace(
                        state_root=str(root),
                        family="hermes",
                        release="hermes-candidate",
                        slot="oc20",
                        allow_first_apply=False,
                    )
                )
            self.assertEqual(rc, 0, output.getvalue())
            lanes = load_yaml(root / "lanes.yaml")["lanes"]
            self.assertEqual(lanes["hermes-canary"]["release"], "hermes-candidate")
            self.assertEqual(lanes["hermes-canary"]["runtime_profile"], "hermes-workspace-customer")
            rollout = load_yaml(root / "rollout-state.yaml")
            self.assertEqual(rollout["families"]["hermes"]["canary"]["runtime_profile"], "hermes-workspace-customer")
            self.assertEqual(rollout["families"]["hermes"]["canary"]["canonical_recipe_name"], "hermes-workspace")
            self.assertEqual(apply.call_args.args[0].slot, "oc20")

    def test_rollout_canary_moves_only_target_slot_and_records_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            import_candidate(root)
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli.cmd_apply", return_value=0) as apply,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_rollout_canary(
                    argparse.Namespace(
                        state_root=str(root),
                        family="openclaw",
                        release="openclaw-candidate",
                        slot="oc3",
                        allow_first_apply=False,
                    )
                )
            self.assertEqual(rc, 0, output.getvalue())
            slots = load_yaml(root / "slots.yaml")["slots"]
            lanes = load_yaml(root / "lanes.yaml")["lanes"]
            self.assertEqual(next(item for item in slots if item["slot"] == "oc3")["lane"], "openclaw-canary")
            self.assertEqual(next(item for item in slots if item["slot"] == "oc4")["lane"], "openclaw")
            self.assertEqual(lanes["openclaw"]["release"], "openclaw-current")
            self.assertEqual(lanes["openclaw-canary"]["release"], "openclaw-candidate")
            rollout = load_yaml(root / "rollout-state.yaml")
            self.assertEqual(rollout["families"]["openclaw"]["canary"]["status"], "ok")
            self.assertEqual(apply.call_args.args[0].slot, "oc3")

    def test_rollout_canary_restores_state_when_apply_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            import_candidate(root)
            lanes_before = load_yaml(root / "lanes.yaml")
            slots_before = load_yaml(root / "slots.yaml")
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli.cmd_apply", return_value=1),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_rollout_canary(
                    argparse.Namespace(
                        state_root=str(root),
                        family="openclaw",
                        release="openclaw-candidate",
                        slot="oc3",
                        allow_first_apply=False,
                    )
                )
            self.assertEqual(rc, 1)
            self.assertIn("reason=canary_apply_failed", output.getvalue())
            self.assertEqual(load_yaml(root / "lanes.yaml"), lanes_before)
            self.assertEqual(load_yaml(root / "slots.yaml"), slots_before)

    def test_rollout_promote_requires_matching_canary_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            import_candidate(root)
            output = io.StringIO()
            with patch("agent_runtime_ops.cli._is_root", return_value=True), contextlib.redirect_stdout(output):
                rc = cmd_rollout_promote(
                    argparse.Namespace(state_root=str(root), family="openclaw", release="openclaw-candidate")
                )
            self.assertEqual(rc, 1)
            self.assertIn("matching successful canary", output.getvalue())

    def test_rollout_promote_returns_canary_to_fleet_and_applies_all_fleet_slots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            import_candidate(root)
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli.cmd_apply", return_value=0),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(
                    cmd_rollout_canary(
                        argparse.Namespace(
                            state_root=str(root),
                            family="openclaw",
                            release="openclaw-candidate",
                            slot="oc3",
                            allow_first_apply=False,
                        )
                    ),
                    0,
                )
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli.cmd_apply", return_value=0) as apply,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_rollout_promote(
                    argparse.Namespace(state_root=str(root), family="openclaw", release="openclaw-candidate")
                )
            self.assertEqual(rc, 0, output.getvalue())
            slots = load_yaml(root / "slots.yaml")["slots"]
            lanes = load_yaml(root / "lanes.yaml")["lanes"]
            self.assertEqual(next(item for item in slots if item["slot"] == "oc3")["lane"], "openclaw")
            self.assertEqual(lanes["openclaw"]["release"], "openclaw-candidate")
            self.assertEqual([call.args[0].slot for call in apply.call_args_list], ["oc3", "oc4"])
            rollout = load_yaml(root / "rollout-state.yaml")
            self.assertEqual(rollout["families"]["openclaw"]["promotion"]["status"], "ok")

    def test_rollout_rollback_canary_restores_previous_lane(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            import_candidate(root)
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli.cmd_apply", return_value=0),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(
                    cmd_rollout_canary(
                        argparse.Namespace(
                            state_root=str(root),
                            family="openclaw",
                            release="openclaw-candidate",
                            slot="oc3",
                            allow_first_apply=False,
                        )
                    ),
                    0,
                )
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli.cmd_apply", return_value=0) as apply,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_rollout_rollback_canary(argparse.Namespace(state_root=str(root), family="openclaw"))
            self.assertEqual(rc, 0, output.getvalue())
            slots = load_yaml(root / "slots.yaml")["slots"]
            self.assertEqual(next(item for item in slots if item["slot"] == "oc3")["lane"], "openclaw")
            self.assertEqual(apply.call_args.args[0].slot, "oc3")
            rollout = load_yaml(root / "rollout-state.yaml")
            self.assertEqual(rollout["families"]["openclaw"]["canary"]["status"], "rolled_back")

    def test_rollout_rollback_canary_recovers_single_canary_slot_without_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            import_candidate(root)
            lanes = load_yaml(root / "lanes.yaml")
            slots = load_yaml(root / "slots.yaml")
            lanes["lanes"]["openclaw-canary"] = {
                "family": "openclaw",
                "slot_class": "customer",
                "release": "openclaw-candidate",
                "runtime_profile": "openclaw-customer",
            }
            for item in slots["slots"]:
                if item["slot"] == "oc3":
                    item["lane"] = "openclaw-canary"
            (root / "lanes.yaml").write_text(dump_yaml(lanes), encoding="utf-8")
            (root / "slots.yaml").write_text(dump_yaml(slots), encoding="utf-8")
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli.cmd_apply", return_value=0) as apply,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_rollout_rollback_canary(argparse.Namespace(state_root=str(root), family="openclaw"))
            self.assertEqual(rc, 0, output.getvalue())
            self.assertIn("inferred_without_record=true", output.getvalue())
            slots_after = load_yaml(root / "slots.yaml")["slots"]
            self.assertEqual(next(item for item in slots_after if item["slot"] == "oc3")["lane"], "openclaw")
            self.assertEqual(apply.call_args.args[0].slot, "oc3")
            rollout = load_yaml(root / "rollout-state.yaml")
            canary = rollout["families"]["openclaw"]["canary"]
            self.assertEqual(canary["status"], "rolled_back_without_record")
            self.assertEqual(canary["release"], "openclaw-candidate")


if __name__ == "__main__":
    unittest.main()
