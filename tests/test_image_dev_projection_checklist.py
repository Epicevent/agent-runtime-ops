from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from agent_runtime_ops.commands.admin import (
    _clone_provider_secret_values,
    _ensure_openclaw_app_dirs,
    cmd_admin_create_image_dev,
)
from agent_runtime_ops.commands.checklist import HERMES_RUNTIME_REQUIRED_CHECKS, cmd_checklist_pack
from agent_runtime_ops.commands.rollout import cmd_rollout_image_canary, cmd_rollout_image_promote
from agent_runtime_ops.profiles import load_profile
from agent_runtime_ops.routing import RuntimeBinding, dump_runtime_bindings, load_runtime_bindings
from agent_runtime_ops.state import RuntimeTarget


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


def write_bindings(root: Path, rows: list[RuntimeBinding]) -> None:
    (root / "runtime-bindings.json").write_text(dump_runtime_bindings(rows), encoding="utf-8")


class ImageDevProjectionChecklistTests(unittest.TestCase):
    def test_admin_create_image_dev_adds_customer_image_mode_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bindings(root, [binding("oc20", "hermes", "customer", 30689, 30690)])

            args = argparse.Namespace(
                state_root=str(root),
                target="dev-hermes-img",
                public_host="dev-hermes-img.ji-tech.co.kr",
                family="hermes",
                gateway_port=30989,
                bridge_port=30990,
                instance_id=None,
                clone_config_from=None,
                clone_provider_secrets_from=None,
            )
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.admin._is_root", return_value=True),
                patch("agent_runtime_ops.commands.admin._ensure_group", return_value="created"),
                patch("agent_runtime_ops.commands.admin._ensure_user", return_value="created"),
                patch("agent_runtime_ops.commands.admin._ensure_customer_data_membership"),
                patch("agent_runtime_ops.commands.admin._ensure_runtime_membership"),
                patch("agent_runtime_ops.commands.admin._ensure_target_dirs_and_secrets", return_value=("present", "not_cloned", "not_cloned")),
                patch("agent_runtime_ops.commands.admin._ensure_apache_route", return_value=(Path("/etc/apache2/openclaw/apache-subdomain-dev-hermes-img.conf"), "created")),
                patch("agent_runtime_ops.commands.binding.os.chown"),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_admin_create_image_dev(args)

            text = output.getvalue()
            self.assertEqual(rc, 0, text)
            rows = {item.linux_account: item for item in load_runtime_bindings(root)}
            self.assertEqual(rows["dev-hermes-img"].runtime_class, "customer")
            self.assertEqual(rows["dev-hermes-img"].family, "hermes")
            self.assertIn("profile_mode=image", text)
            self.assertIn("binding=created", text)
            self.assertIn("secret_value_printed=no", text)

    def test_admin_create_image_dev_reuses_existing_matching_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_bindings(root, [binding("dev-hermes-img", "hermes", "customer", 30989, 30990)])

            args = argparse.Namespace(
                state_root=str(root),
                target="dev-hermes-img",
                public_host="dev-hermes-img.ji-tech.co.kr",
                family="hermes",
                gateway_port=30989,
                bridge_port=30990,
                instance_id=None,
                clone_config_from=None,
                clone_provider_secrets_from=None,
            )
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.admin._is_root", return_value=True),
                patch("agent_runtime_ops.commands.admin._ensure_group", return_value="exists"),
                patch("agent_runtime_ops.commands.admin._ensure_user", return_value="exists"),
                patch("agent_runtime_ops.commands.admin._ensure_customer_data_membership"),
                patch("agent_runtime_ops.commands.admin._ensure_runtime_membership"),
                patch("agent_runtime_ops.commands.admin._ensure_target_dirs_and_secrets", return_value=("present", "not_cloned", "not_cloned")),
                patch("agent_runtime_ops.commands.admin._ensure_apache_route", return_value=(Path("/etc/apache2/openclaw/apache-subdomain-dev-hermes-img.conf"), "exists")),
                patch("agent_runtime_ops.commands.admin._write_runtime_bindings_file") as write_bindings_file,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_admin_create_image_dev(args)

            text = output.getvalue()
            self.assertEqual(rc, 0, text)
            self.assertIn("binding=exists", text)
            self.assertEqual(len(load_runtime_bindings(root)), 1)
            write_bindings_file.assert_not_called()

    def test_image_dev_secret_clone_includes_workspace_auth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret_path = root / "source.env"
            secret_path.write_text(
                "GEMINI_API_KEY='provider'\nHERMES_PASSWORD='workspace-auth'\nAPI_SERVER_KEY='do-not-clone'\n",
                encoding="utf-8",
            )
            source = RuntimeTarget(
                target="dev-hermess",
                family="hermes",
                runtime_class="dev",
                image_name="direct-image",
                image_spec={},
                runtime_profile="hermes-runtime-dev",
                route=binding("dev-hermess", "hermes", "dev", 30889, 30890),
            )
            with (
                patch("agent_runtime_ops.commands.admin.load_runtime_target", return_value=source),
                patch("agent_runtime_ops.commands.admin.load_profile", return_value=load_profile("hermes-runtime-dev")),
                patch(
                    "agent_runtime_ops.commands.admin.primary_profile_secret_file",
                    return_value=argparse.Namespace(path=secret_path),
                ),
            ):
                values = _clone_provider_secret_values("dev-hermess", root)

            self.assertEqual(values["GEMINI_API_KEY"], "provider")
            self.assertEqual(values["HERMES_PASSWORD"], "workspace-auth")
            self.assertNotIn("API_SERVER_KEY", values)

    def test_image_dev_secret_clone_can_exclude_workspace_auth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret_path = root / "source.env"
            secret_path.write_text(
                "GEMINI_API_KEY='provider'\nHERMES_PASSWORD='workspace-auth'\n",
                encoding="utf-8",
            )
            source = RuntimeTarget(
                target="dev-oc",
                family="openclaw",
                runtime_class="dev",
                image_name="direct-image",
                image_spec={},
                runtime_profile="openclaw-dev",
                route=binding("dev-oc", "openclaw", "dev", 30789, 30790),
            )
            with (
                patch("agent_runtime_ops.commands.admin.load_runtime_target", return_value=source),
                patch("agent_runtime_ops.commands.admin.load_profile", return_value=load_profile("openclaw-dev")),
                patch(
                    "agent_runtime_ops.commands.admin.primary_profile_secret_file",
                    return_value=argparse.Namespace(path=secret_path),
                ),
            ):
                values = _clone_provider_secret_values("dev-oc", root, include_workspace_auth=False)

            self.assertEqual(values["GEMINI_API_KEY"], "provider")
            self.assertNotIn("HERMES_PASSWORD", values)

    def test_openclaw_image_dev_dirs_match_openclaw_mounts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "dev-oc-img"
            home.mkdir()
            with patch("agent_runtime_ops.commands.admin.os.chown"):
                state_dir = _ensure_openclaw_app_dirs(home, runtime_uid=1001, runtime_gid=1002, data_gid=1003)

            self.assertEqual(state_dir, home / ".openclaw")
            self.assertTrue((home / ".openclaw").is_dir())
            self.assertTrue((home / ".openclaw" / "workspace").is_dir())
            self.assertTrue((home / ".openclaw-auth-profile-secrets").is_dir())
            self.assertEqual((home / ".openclaw").stat().st_mode & 0o777, 0o750)
            self.assertEqual((home / ".openclaw" / "workspace").stat().st_mode & 0o777, 0o750)
            self.assertEqual((home / ".openclaw-auth-profile-secrets").stat().st_mode & 0o777, 0o700)

    def test_rollout_image_canary_prepares_runtime_env_before_apply(self) -> None:
        route = binding("dev-hermes-img", "hermes", "customer", 30989, 30990)
        profile = load_profile("hermes-runtime-customer")
        image_spec = {
            "family": "hermes",
            "wrapper_image": "ghcr.io/epicevent/agent-runtime-hermes@sha256:" + "1" * 64,
            "product_image": "ghcr.io/epicevent/hermes-runtime@sha256:" + "2" * 64,
            "digest": "sha256:" + "1" * 64,
            "product_digest": "sha256:" + "2" * 64,
            "mode": "wrapped_product_image",
        }
        desired = RuntimeTarget(
            target="dev-hermes-img",
            family="hermes",
            runtime_class="customer",
            image_name="direct-image",
            image_spec=image_spec,
            runtime_profile="hermes-runtime-customer",
            route=route,
        )
        output = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.rollout._is_root", return_value=True),
            patch("agent_runtime_ops.commands.rollout._direct_image_spec_from_args", return_value=image_spec),
            patch("agent_runtime_ops.commands.rollout._desired_from_direct_images", return_value=(desired, profile)),
            patch("agent_runtime_ops.commands.rollout._ensure_runtime_dir"),
            patch("agent_runtime_ops.commands.rollout._prepare_runtime_env_for_direct_image") as prepare_env,
            patch("agent_runtime_ops.commands.rollout._apply_desired_slot", return_value=0) as apply_slot,
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_rollout_image_canary(
                argparse.Namespace(
                    state_root="/tmp/missing",
                    slot="dev-hermes-img",
                    wrapper_image=image_spec["wrapper_image"],
                    product_image=image_spec["product_image"],
                    allow_first_apply=True,
                )
            )
            prepare_env.assert_not_called()
            apply_slot.call_args.kwargs["prepare_runtime_env"]()

        self.assertEqual(rc, 0, output.getvalue())
        apply_slot.assert_called_once()
        prepare_env.assert_called_once_with(desired, profile)

    def test_rollout_promote_rejects_dev_named_source(self) -> None:
        output = io.StringIO()
        with patch("agent_runtime_ops.commands.rollout._is_root", return_value=True), contextlib.redirect_stdout(output):
            rc = cmd_rollout_image_promote(
                argparse.Namespace(state_root="/tmp/missing", from_slot="dev-hermes-img", slots="oc20")
            )

        text = output.getvalue()
        self.assertNotEqual(rc, 0)
        self.assertIn("image-promote source must not be a dev target", text)

    def test_rollout_promote_rejects_dev_named_target_before_apply(self) -> None:
        route = binding("oc20", "hermes", "customer", 30689, 30690)
        profile = load_profile("hermes-runtime-customer")
        desired = RuntimeTarget(
            target="oc20",
            family="hermes",
            runtime_class="customer",
            image_name="direct-image",
            image_spec={
                "family": "hermes",
                "wrapper_image": "ghcr.io/epicevent/agent-runtime-hermes@sha256:" + "1" * 64,
                "product_image": "ghcr.io/epicevent/hermes-runtime@sha256:" + "2" * 64,
                "digest": "sha256:" + "1" * 64,
                "product_digest": "sha256:" + "2" * 64,
                "mode": "wrapped_product_image",
            },
            runtime_profile="hermes-runtime-customer",
            route=route,
        )
        output = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.rollout._is_root", return_value=True),
            patch("agent_runtime_ops.commands.rollout._desired_from_live_image_truth", return_value=(desired, profile)),
            patch("agent_runtime_ops.commands.rollout._run_static_slot_checks", return_value=[]),
            patch("agent_runtime_ops.commands.rollout._run_live_slot_checks", return_value=[]),
            patch("agent_runtime_ops.commands.rollout.image_spec_from_direct_images", return_value=desired.image_spec),
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_rollout_image_promote(
                argparse.Namespace(state_root="/tmp/missing", from_slot="oc20", slots="dev-hermes-img")
            )

        text = output.getvalue()
        self.assertNotEqual(rc, 0)
        self.assertIn("image-promote target must not be a dev target", text)

    def test_checklist_pack_fails_when_required_live_check_is_missing(self) -> None:
        route = binding("oc20", "hermes", "customer", 30689, 30690)
        profile = load_profile("hermes-runtime-customer")
        desired = RuntimeTarget(
            target="oc20",
            family="hermes",
            runtime_class="customer",
            image_name="direct-image",
            image_spec={},
            runtime_profile="hermes-runtime-customer",
            route=route,
        )
        live_checks = [(True, name, "ok") for name in sorted(HERMES_RUNTIME_REQUIRED_CHECKS) if name != "live_workspace_files_nas_docs_listing_ok"]
        output = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.checklist._is_root", return_value=True),
            patch("agent_runtime_ops.commands.checklist._desired_from_live_image_truth", return_value=(desired, profile)),
            patch("agent_runtime_ops.commands.checklist._run_live_slot_checks", return_value=live_checks),
            patch("agent_runtime_ops.commands.checklist._hermes_runtime_pack_checks", return_value=[]),
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_checklist_pack(argparse.Namespace(state_root="/tmp/missing", slot="oc20", pack="hermes-runtime", gemini_chat_smoke=False))

        text = output.getvalue()
        self.assertNotEqual(rc, 0)
        self.assertIn("FAIL live_workspace_files_nas_docs_listing_ok missing_from_live_check", text)


if __name__ == "__main__":
    unittest.main()
