from __future__ import annotations

import argparse
import contextlib
import io
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from agent_runtime_ops.commands.mitigation import (
    cmd_mitigation_add,
    cmd_mitigation_check,
    cmd_mitigation_list,
    cmd_mitigation_remove,
)
from agent_runtime_ops.domain.mitigations import (
    env_key_present,
    evaluate_env_mitigation,
    load_mitigations,
    new_env_mitigation,
    parse_version_triple,
    save_mitigations,
)

MODULE = "agent_runtime_ops.commands.mitigation"


class RegistryRoundtripTest(unittest.TestCase):
    def test_add_save_load_roundtrip(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = new_env_mitigation(
                mitigation_id="openclaw-version-env-override",
                slots=["oc1", "oc2"],
                env_key="OPENCLAW_VERSION",
                reason="masks the stamped image version",
                expires_product_version="2026.7.6",
            )
            save_mitigations(root, [entry])
            loaded = load_mitigations(root)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["id"], "openclaw-version-env-override")
        self.assertEqual(loaded[0]["slots"], ["oc1", "oc2"])
        self.assertEqual(loaded[0]["kind"], "env")

    def test_missing_register_loads_empty(self) -> None:
        with TemporaryDirectory() as tmp:
            self.assertEqual(load_mitigations(Path(tmp)), [])

    def test_bad_expiry_version_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            new_env_mitigation(
                mitigation_id="x",
                slots=["oc1"],
                env_key="K",
                reason="r",
                expires_product_version="soon",
            )


class EnvKeyPresenceTest(unittest.TestCase):
    def test_detects_key_without_reading_values(self) -> None:
        with TemporaryDirectory() as tmp:
            env = Path(tmp) / ".env"
            env.write_text(
                "# comment\nGEMINI_API_KEY=secret\nexport OPENCLAW_VERSION=v2026.6.11\nOTHER=1\n",
                encoding="utf-8",
            )
            self.assertTrue(env_key_present(env, "OPENCLAW_VERSION"))
            self.assertTrue(env_key_present(env, "GEMINI_API_KEY"))
            self.assertFalse(env_key_present(env, "OPENCLAW"))
            self.assertFalse(env_key_present(env, "MISSING"))

    def test_missing_file_is_absent(self) -> None:
        with TemporaryDirectory() as tmp:
            self.assertFalse(env_key_present(Path(tmp) / ".env", "K"))


class EvaluationTest(unittest.TestCase):
    ENTRY = {"id": "m1", "expires_product_version": "2026.7.6"}

    def test_absent_is_cleared(self) -> None:
        status, _ = evaluate_env_mitigation(self.ENTRY, "oc1", present=False, running_version=None)
        self.assertEqual(status, "cleared")

    def test_present_and_old_version_is_active(self) -> None:
        status, _ = evaluate_env_mitigation(
            self.ENTRY, "oc1", present=True, running_version="2026.5.19"
        )
        self.assertEqual(status, "active")

    def test_present_and_new_version_is_expired_still_present(self) -> None:
        status, detail = evaluate_env_mitigation(
            self.ENTRY, "oc1", present=True, running_version="2026.7.6"
        )
        self.assertEqual(status, "expired_still_present")
        self.assertIn("remove the override", detail)

    def test_probe_failure_is_unknown(self) -> None:
        status, _ = evaluate_env_mitigation(
            self.ENTRY, "oc1", present=True, running_version=None, probe_error="no container"
        )
        self.assertEqual(status, "unknown")

    def test_version_parse(self) -> None:
        self.assertEqual(parse_version_triple("2026.7.6"), (2026, 7, 6))
        self.assertEqual(parse_version_triple("v2026.7.6"), (2026, 7, 6))
        self.assertIsNone(parse_version_triple("soon"))


def _args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {"state_root": "", "slot": None}
    values.update(overrides)
    return argparse.Namespace(**values)


class CommandTest(unittest.TestCase):
    def test_add_list_remove_flow(self) -> None:
        with TemporaryDirectory() as tmp, patch(f"{MODULE}._is_root", return_value=True):
            add_rc = cmd_mitigation_add(
                _args(
                    state_root=tmp,
                    mitigation_id="m1",
                    slots=["oc1"],
                    env_key="OPENCLAW_VERSION",
                    reason="masks stamped version",
                    expires_product_version="2026.7.6",
                )
            )
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                list_rc = cmd_mitigation_list(_args(state_root=tmp))
            remove_rc = cmd_mitigation_remove(_args(state_root=tmp, mitigation_id="m1"))
            empty = load_mitigations(Path(tmp))
        self.assertEqual((add_rc, list_rc, remove_rc), (0, 0, 0))
        self.assertIn("mitigation_count=1", out.getvalue())
        self.assertEqual(empty, [])

    def test_duplicate_id_refused(self) -> None:
        with TemporaryDirectory() as tmp, patch(f"{MODULE}._is_root", return_value=True):
            base = dict(
                state_root=tmp,
                mitigation_id="m1",
                slots=["oc1"],
                env_key="K",
                reason="r",
                expires_product_version="2026.7.6",
            )
            self.assertEqual(cmd_mitigation_add(_args(**base)), 0)
            self.assertEqual(cmd_mitigation_add(_args(**base)), 2)

    def test_check_reports_expired_still_present_and_fails(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            env_dir = root / "home" / "oc1" / "openclaw"
            env_dir.mkdir(parents=True)
            (env_dir / ".env").write_text("OPENCLAW_VERSION=v2026.6.11\n", encoding="utf-8")
            save_mitigations(
                root,
                [
                    new_env_mitigation(
                        mitigation_id="m1",
                        slots=["oc1"],
                        env_key="OPENCLAW_VERSION",
                        reason="r",
                        expires_product_version="2026.7.6",
                    )
                ],
            )
            binding = type("B", (), {"linux_account": "oc1"})()
            with (
                patch(f"{MODULE}._is_root", return_value=True),
                patch(f"{MODULE}._slot_env_path", side_effect=lambda slot: root / "home" / slot / "openclaw" / ".env"),
                patch(f"{MODULE}.load_runtime_bindings", return_value=[binding]),
                patch(f"{MODULE}.running_product_version", return_value="2026.7.6"),
            ):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    rc = cmd_mitigation_check(_args(state_root=str(root)))
        self.assertEqual(rc, 1)
        text = out.getvalue()
        self.assertIn("mitigation_m1_expired_still_present", text)
        self.assertIn("mitigation_check_status=fail checked=1", text)

    def test_check_cleared_passes(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            save_mitigations(
                root,
                [
                    new_env_mitigation(
                        mitigation_id="m1",
                        slots=["oc1"],
                        env_key="OPENCLAW_VERSION",
                        reason="r",
                        expires_product_version="2026.7.6",
                    )
                ],
            )
            with (
                patch(f"{MODULE}._is_root", return_value=True),
                patch(f"{MODULE}._slot_env_path", side_effect=lambda slot: root / "missing" / ".env"),
                patch(f"{MODULE}.load_runtime_bindings", return_value=[]),
            ):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    rc = cmd_mitigation_check(_args(state_root=str(root)))
        self.assertEqual(rc, 0)
        self.assertIn("mitigation_m1_cleared", out.getvalue())


if __name__ == "__main__":
    unittest.main()
