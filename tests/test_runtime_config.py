from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent_runtime_ops.commands.runtime_config import (
    _gemini_model_catalog,
    cmd_runtime_config_sanitize,
    cmd_runtime_config_status,
    cmd_runtime_set_model,
    cmd_runtime_version_note,
    runtime_provider_id,
)


class RuntimeConfigTests(unittest.TestCase):
    def test_gemini_model_catalog_returns_all_generate_content_ids(self) -> None:
        payloads = iter([
            {
                "models": [
                    {"name": "models/gemini-3.6-flash", "supportedGenerationMethods": ["generateContent"]},
                    {"name": "models/text-embedding", "supportedGenerationMethods": ["embedContent"]},
                ],
                "nextPageToken": "next",
            },
            {
                "models": [
                    {"name": "models/gemini-3.5-flash-lite", "supportedGenerationMethods": ["generateContent"]},
                ]
            },
        ])

        class Response:
            def __init__(self, payload):
                self.payload = payload
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self):
                return json.dumps(self.payload).encode()

        with patch(
            "agent_runtime_ops.commands.runtime_config.urllib.request.urlopen",
            side_effect=lambda request, timeout: Response(next(payloads)),
        ):
            models = _gemini_model_catalog("not-printed")

        self.assertEqual(models, ["gemini-3.5-flash-lite", "gemini-3.6-flash"])

    def test_runtime_provider_id_canonicalizes_google_aliases(self) -> None:
        for provider in ("google", "google-ai", "google_ai", "google-gemini", "google_gemini", "gemini"):
            self.assertEqual(runtime_provider_id(provider), "gemini")

    def test_runtime_set_model_stores_runtime_provider_id(self) -> None:
        written: dict[str, object] = {}
        output = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.runtime_config.is_root", return_value=True),
            patch("agent_runtime_ops.commands.runtime_config._load_config_target", return_value=SimpleNamespace(slot="oc16", family="hermes")),
            patch("agent_runtime_ops.commands.runtime_config.hermes_config_path", return_value=Path("/home/oc16/.hermes/config.yaml")),
            patch("agent_runtime_ops.commands.runtime_config.read_hermes_config", return_value={}),
            patch("agent_runtime_ops.commands.runtime_config.write_hermes_config", side_effect=lambda _slot, _path, config: written.update(config)),
            patch("agent_runtime_ops.commands.runtime_config.append_action_log"),
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_runtime_set_model(
                argparse.Namespace(
                    slot="oc16",
                    provider="google",
                    model="gemini-3.1-pro-preview",
                    state_root="/srv/openclaw-ops",
                )
            )
        text = output.getvalue()
        self.assertEqual(rc, 0, text)
        self.assertEqual(written["provider"], "gemini")
        self.assertEqual(written["model"], "gemini-3.1-pro-preview")
        self.assertIn("provider_raw=google", text)
        self.assertIn("provider_runtime=gemini", text)
        self.assertIn("family=hermes", text)

    def test_runtime_set_model_drops_stale_provider_routing(self) -> None:
        # A base_url/api_key/api_mode left over from a previous provider (e.g. an
        # OpenRouter endpoint carried onto a gemini provider) must not survive a
        # provider/model change — otherwise gemini traffic keeps routing to the
        # stale endpoint and 401s against a keyless OpenRouter. set-model writes
        # the canonical provider/model with no inherited routing overrides.
        written: dict[str, object] = {}
        stale = {
            "provider": "gemini",
            "model": {
                "default": "gemini-2.0-flash",
                "provider": "gemini",
                "base_url": "https://openrouter.ai/api/v1",
                "api_key": "sk-stale",
                "api_mode": "responses",
            },
        }
        with (
            patch("agent_runtime_ops.commands.runtime_config.is_root", return_value=True),
            patch("agent_runtime_ops.commands.runtime_config._load_config_target", return_value=SimpleNamespace(slot="oc16", family="hermes")),
            patch("agent_runtime_ops.commands.runtime_config.hermes_config_path", return_value=Path("/home/oc16/.hermes/config.yaml")),
            patch("agent_runtime_ops.commands.runtime_config.read_hermes_config", return_value=stale),
            patch("agent_runtime_ops.commands.runtime_config.write_hermes_config", side_effect=lambda _slot, _path, config: written.update(config)),
            patch("agent_runtime_ops.commands.runtime_config.append_action_log"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            rc = cmd_runtime_set_model(
                argparse.Namespace(
                    slot="oc16",
                    provider="google",
                    model="gemini-3.5-flash",
                    state_root="/srv/openclaw-ops",
                )
            )
        self.assertEqual(rc, 0)
        self.assertEqual(
            written["model"],
            {"default": "gemini-3.5-flash", "provider": "gemini"},
        )
        self.assertNotIn("base_url", written["model"])
        self.assertNotIn("api_key", written["model"])

    def test_runtime_config_status_prints_raw_and_runtime_provider(self) -> None:
        output = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.runtime_config.is_root", return_value=True),
            patch("agent_runtime_ops.commands.runtime_config._load_config_target", return_value=SimpleNamespace(slot="oc16", family="hermes")),
            patch("agent_runtime_ops.commands.runtime_config.hermes_config_path", return_value=Path("/home/oc16/.hermes/config.yaml")),
            patch(
                "agent_runtime_ops.commands.runtime_config.read_hermes_config",
                return_value={"provider": "google", "model": "gemini-3.1-pro-preview"},
            ),
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_runtime_config_status(argparse.Namespace(slot="oc16", state_root="/srv/openclaw-ops"))
        text = output.getvalue()
        self.assertEqual(rc, 0, text)
        self.assertIn("provider=gemini", text)
        self.assertIn("provider_raw=google", text)
        self.assertIn("provider_runtime=gemini", text)
        self.assertIn("family=hermes", text)
        # a clean config surfaces no drift and no leftover routing keys
        self.assertIn("model_endpoint_drift=no", text)
        self.assertIn("model_routing_keys=none", text)

    def test_runtime_config_status_flags_stray_endpoint_drift(self) -> None:
        # A gemini slot left pointed at openrouter.ai must be flagged by
        # config-status so an operator SEES the misroute without a live probe.
        output = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.runtime_config.is_root", return_value=True),
            patch("agent_runtime_ops.commands.runtime_config._load_config_target", return_value=SimpleNamespace(slot="oc16", family="hermes")),
            patch("agent_runtime_ops.commands.runtime_config.hermes_config_path", return_value=Path("/home/oc16/.hermes/config.yaml")),
            patch(
                "agent_runtime_ops.commands.runtime_config.read_hermes_config",
                return_value={
                    "provider": "gemini",
                    "model": {
                        "default": "gemini-3.5-flash",
                        "provider": "gemini",
                        "base_url": "https://openrouter.ai/api/v1",
                    },
                },
            ),
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_runtime_config_status(argparse.Namespace(slot="oc16", state_root="/srv/openclaw-ops"))
        text = output.getvalue()
        self.assertEqual(rc, 0, text)
        self.assertIn("model_endpoint_drift=yes", text)
        self.assertIn("model_base_url_host=openrouter.ai", text)
        self.assertIn("model_routing_keys=base_url", text)
        self.assertIn("model_endpoint_drift_reason=", text)

    def test_runtime_config_sanitize_dry_run_reports_paths_without_writing_values(self) -> None:
        secret_value = "do-not-print-this-secret"
        output = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.runtime_config.is_root", return_value=True),
            patch("agent_runtime_ops.commands.runtime_config._load_hermes_target", return_value=SimpleNamespace(slot="oc16")),
            patch("agent_runtime_ops.commands.runtime_config.hermes_config_path", return_value=Path("/home/oc16/.hermes/config.yaml")),
            patch(
                "agent_runtime_ops.commands.runtime_config.read_hermes_config",
                return_value={"providers": {"google": {"api_key": secret_value, "enabled": True}}},
            ),
            patch("agent_runtime_ops.commands.runtime_config.write_hermes_config") as write_config,
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_runtime_config_sanitize(
                argparse.Namespace(slot="oc16", state_root="/srv/openclaw-ops", dry_run=True, apply=False)
            )
        text = output.getvalue()
        self.assertEqual(rc, 0, text)
        write_config.assert_not_called()
        self.assertIn("runtime_config_sanitize_mode=dry_run", text)
        self.assertIn("remove_path=providers.google.api_key value_present=yes secret_value_printed=no", text)
        self.assertIn("runtime_config_sanitize_status=dry_run", text)
        self.assertNotIn(secret_value, text)

    def test_runtime_config_sanitize_apply_removes_secret_override_paths(self) -> None:
        written: dict[str, object] = {}
        output = io.StringIO()
        config = {
            "providers": {
                "google": {"apiKey": "google-secret", "enabled": True},
                "gemini": {"key": "gemini-secret", "model": "gemini-3.1-pro-preview"},
            },
            "auth": {"gemini": {"api_key": "auth-secret", "other": "keep"}},
        }
        with (
            patch("agent_runtime_ops.commands.runtime_config.is_root", return_value=True),
            patch("agent_runtime_ops.commands.runtime_config._load_hermes_target", return_value=SimpleNamespace(slot="oc16")),
            patch("agent_runtime_ops.commands.runtime_config.hermes_config_path", return_value=Path("/home/oc16/.hermes/config.yaml")),
            patch("agent_runtime_ops.commands.runtime_config.read_hermes_config", return_value=config),
            patch("agent_runtime_ops.commands.runtime_config.write_hermes_config", side_effect=lambda _slot, _path, value: written.update(value)),
            patch("agent_runtime_ops.commands.runtime_config.append_action_log"),
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_runtime_config_sanitize(
                argparse.Namespace(slot="oc16", state_root="/srv/openclaw-ops", dry_run=False, apply=True)
            )
        text = output.getvalue()
        self.assertEqual(rc, 0, text)
        self.assertEqual(written["providers"]["google"], {"enabled": True})
        self.assertEqual(written["providers"]["gemini"], {"model": "gemini-3.1-pro-preview"})
        self.assertEqual(written["auth"]["gemini"], {"other": "keep"})
        self.assertIn("remove_count=3", text)
        self.assertIn("runtime_config_sanitize_status=updated", text)
        self.assertNotIn("google-secret", text)
        self.assertNotIn("gemini-secret", text)
        self.assertNotIn("auth-secret", text)


class RuntimeVersionNoteTests(unittest.TestCase):
    def _run(self, *, existing, argv_extra):
        written: dict[str, object] = {}
        output = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.runtime_config.is_root", return_value=True),
            patch("agent_runtime_ops.commands.runtime_config._load_config_target", return_value=SimpleNamespace(slot="oc16", family="hermes")),
            patch("agent_runtime_ops.commands.runtime_config.version_notes_path", return_value=Path("/home/oc16/.hermes/version-notes.json")),
            patch("agent_runtime_ops.commands.runtime_config.read_version_notes", return_value=existing),
            patch("agent_runtime_ops.commands.runtime_config.write_version_notes", side_effect=lambda _slot, _path, entries: written.update({"entries": entries})),
            patch("agent_runtime_ops.commands.runtime_config.append_action_log"),
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_runtime_version_note(
                argparse.Namespace(slot="oc16", state_root="/srv/openclaw-ops", **argv_extra)
            )
        return rc, written, output.getvalue()

    def test_write_note_upserts_and_prints(self) -> None:
        rc, written, text = self._run(
            existing=[],
            argv_extra={"version": "2026.7.17", "date": "2026-07-17", "note": ["폴더 정리 지원"], "clear": False},
        )
        self.assertEqual(rc, 0, text)
        self.assertEqual(written["entries"], [{"version": "2026.7.17", "notes": ["폴더 정리 지원"], "date": "2026-07-17"}])
        self.assertIn("action=written", text)
        self.assertIn("  - 폴더 정리 지원", text)

    def test_clear_removes_entry(self) -> None:
        rc, written, text = self._run(
            existing=[{"version": "2026.7.17", "notes": ["x"]}],
            argv_extra={"version": "2026.7.17", "date": "", "note": None, "clear": True},
        )
        self.assertEqual(rc, 0, text)
        self.assertEqual(written["entries"], [])
        self.assertIn("action=cleared", text)

    def test_show_without_version_reads_only(self) -> None:
        rc, written, text = self._run(
            existing=[{"version": "2026.7.14", "notes": ["이미지 표시"], "date": "2026-07-14"}],
            argv_extra={"version": "", "date": "", "note": None, "clear": False},
        )
        self.assertEqual(rc, 0, text)
        self.assertNotIn("entries", written)  # no write on show
        self.assertIn("action=show", text)
        self.assertIn("entry 2026.7.14", text)

    def test_invalid_version_fails(self) -> None:
        rc, written, text = self._run(
            existing=[],
            argv_extra={"version": "v1", "date": "", "note": ["x"], "clear": False},
        )
        self.assertEqual(rc, 1)
        self.assertNotIn("entries", written)
        self.assertIn("runtime_version_note_status=fail", text)


class RuntimeVersionNoteOpenClawTests(unittest.TestCase):
    """Same pen, openclaw family: {version: "single note string"} at
    <slot home>/.openclaw/version-notes.json (product contract)."""

    def _run(self, *, existing, argv_extra):
        written: dict[str, object] = {}
        output = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.runtime_config.is_root", return_value=True),
            patch("agent_runtime_ops.commands.runtime_config._load_config_target", return_value=SimpleNamespace(slot="oc14", family="openclaw")),
            patch("agent_runtime_ops.commands.runtime_config.openclaw_version_notes_path", return_value=Path("/home/oc14/.openclaw/version-notes.json")),
            patch("agent_runtime_ops.commands.runtime_config.read_openclaw_version_notes", return_value=existing),
            patch("agent_runtime_ops.commands.runtime_config.write_openclaw_version_notes", side_effect=lambda _slot, _path, notes: written.update({"notes": notes})),
            patch("agent_runtime_ops.commands.runtime_config.append_action_log"),
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_runtime_version_note(
                argparse.Namespace(slot="oc14", state_root="/srv/openclaw-ops", **argv_extra)
            )
        return rc, written, output.getvalue()

    def test_write_joins_notes_into_single_string(self) -> None:
        rc, written, text = self._run(
            existing={},
            argv_extra={"version": "2026.7.16", "date": "", "note": ["세션 스크롤", "이미지 수정"], "clear": False},
        )
        self.assertEqual(rc, 0, text)
        self.assertEqual(written["notes"], {"2026.7.16": "세션 스크롤, 이미지 수정"})
        self.assertIn("action=written", text)
        self.assertIn("family=openclaw", text)

    def test_clear_removes_key(self) -> None:
        rc, written, text = self._run(
            existing={"2026.7.16": "x"},
            argv_extra={"version": "2026.7.16", "date": "", "note": None, "clear": True},
        )
        self.assertEqual(rc, 0, text)
        self.assertEqual(written["notes"], {})
        self.assertIn("action=cleared", text)

    def test_date_rejected_for_openclaw(self) -> None:
        rc, written, text = self._run(
            existing={},
            argv_extra={"version": "2026.7.16", "date": "2026-07-16", "note": ["x"], "clear": False},
        )
        self.assertEqual(rc, 1)
        self.assertNotIn("notes", written)
        self.assertIn("baked build timeline", text)

    def test_show_reads_only(self) -> None:
        rc, written, text = self._run(
            existing={"2026.7.16": "세션 스크롤 지원"},
            argv_extra={"version": "", "date": "", "note": None, "clear": False},
        )
        self.assertEqual(rc, 0, text)
        self.assertNotIn("notes", written)
        self.assertIn("entry 2026.7.16", text)
        self.assertIn("  - 세션 스크롤 지원", text)


class OpenClawSetModelTests(unittest.TestCase):
    """openclaw set-model applies the change with the product's OWN `models set` inside the live
    container (docker exec), then shows a before/after diff of the on-disk config."""

    def _run(self, *, initial, models_set, container=("c123", "instance_label"), provider="google", model="gemini-3.5-flash", attest=None):
        store = {"cfg": initial}
        calls: list[tuple[str, str]] = []
        output = io.StringIO()

        def _read(_path):
            import copy as _copy

            return _copy.deepcopy(store["cfg"])

        def _models_set(container_id, ref, **_kw):
            calls.append((container_id, ref))
            return models_set(store, container_id, ref)

        with (
            patch("agent_runtime_ops.commands.runtime_config.is_root", return_value=True),
            patch(
                "agent_runtime_ops.commands.runtime_config._load_config_target",
                return_value=SimpleNamespace(slot="oc1", family="openclaw", route=object(), runtime_profile="openclaw-customer", image_spec={}),
            ),
            patch("agent_runtime_ops.commands.runtime_config.load_profile", return_value=object()),
            patch("agent_runtime_ops.commands.runtime_config.find_gateway_container", return_value=container),
            patch("agent_runtime_ops.commands.runtime_config.openclaw_config_path", return_value=Path("/home/oc1/.openclaw/openclaw.json")),
            patch("agent_runtime_ops.commands.runtime_config.read_openclaw_config", side_effect=_read),
            patch("agent_runtime_ops.commands.runtime_config.run_openclaw_models_set", side_effect=_models_set),
            patch(
                "agent_runtime_ops.commands.runtime_config.capture_openclaw_config_snapshot",
                return_value=object(),
            ),
            patch(
                "agent_runtime_ops.commands.runtime_config.restore_openclaw_config_snapshot",
                side_effect=lambda _path, _snapshot: store.update(cfg=initial),
            ),
            patch(
                "agent_runtime_ops.commands.runtime_config._attest_openclaw_model_change",
                side_effect=attest or (lambda *_args: (True, "verified")),
            ),
            patch("agent_runtime_ops.commands.runtime_config.append_action_log"),
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_runtime_set_model(
                argparse.Namespace(slot="oc1", provider=provider, model=model, state_root="/srv/openclaw-ops")
            )
        return rc, output.getvalue(), store["cfg"], calls

    def test_calls_product_models_set_and_diffs(self) -> None:
        def apply(store, _container, ref):
            store["cfg"] = {"agents": {"defaults": {"model": ref}}}
            return True, "exit=0"

        rc, text, cfg, calls = self._run(
            initial={"agents": {"defaults": {"model": "google/gemini-2.5-flash"}}}, models_set=apply
        )
        self.assertEqual(rc, 0, text)
        # the product command was invoked with the composed provider/model ref
        self.assertEqual(calls, [("c123", "google/gemini-3.5-flash")])
        self.assertEqual(cfg["agents"]["defaults"]["model"], "google/gemini-3.5-flash")
        self.assertNotIn("models", cfg)
        self.assertIn("family=openclaw", text)
        self.assertIn("exec_container=c123:instance_label", text)
        self.assertIn("model_ref=google/gemini-3.5-flash", text)
        self.assertIn("previous_model_ref=google/gemini-2.5-flash", text)
        self.assertIn("~ agents.defaults.model: google/gemini-2.5-flash -> google/gemini-3.5-flash", text)
        self.assertIn("runtime_config_status=updated", text)

    def test_no_running_container_fails(self) -> None:
        rc, text, _cfg, calls = self._run(
            initial={"agents": {"defaults": {"model": "google/gemini-2.5-flash"}}},
            models_set=lambda *_a: (True, "exit=0"),
            container=(None, "no_match"),
        )
        self.assertEqual(rc, 1, text)
        self.assertEqual(calls, [])  # product command never runs without a container
        self.assertIn("no running gateway container", text)
        self.assertIn("runtime_config_status=fail", text)

    def test_unverified_current_state_is_never_mutated(self) -> None:
        rc, text, _cfg, calls = self._run(
            initial={"agents": {"defaults": {"model": "google/gemini-2.5-flash"}}},
            models_set=lambda *_a: (True, "must not run"),
            attest=lambda *_args: (False, "selftest=current model failed"),
        )
        self.assertEqual(rc, 1, text)
        self.assertEqual(calls, [])
        self.assertIn("current state is not verified-good", text)

    def test_preserves_product_written_config_without_schema_reach_in(self) -> None:
        def apply(store, _container, ref):
            store["cfg"]["agents"]["defaults"]["model"] = ref
            return True, "exit=0"

        initial = {
            "agents": {"defaults": {"model": "google/gemini-2.5-flash"}},
            "models": {
                "providers": {
                    "google": {
                        "baseUrl": "https://generativelanguage.googleapis.com",
                        "models": [{"id": "gemini-3.5-flash", "name": "kept"}],
                    }
                }
            },
        }
        rc, text, cfg, _calls = self._run(initial=initial, models_set=apply)
        self.assertEqual(rc, 0, text)
        google = cfg["models"]["providers"]["google"]
        self.assertEqual(google["baseUrl"], "https://generativelanguage.googleapis.com")
        self.assertEqual(google["models"], [{"id": "gemini-3.5-flash", "name": "kept"}])

    def test_failed_candidate_attestation_restores_exact_previous_config(self) -> None:
        initial = {"agents": {"defaults": {"model": "google/gemini-2.5-flash"}}}

        def apply(store, _container, ref):
            store["cfg"] = {"agents": {"defaults": {"model": ref}}}
            return True, "exit=0"

        attest_results = iter([
            (True, "before verified"),
            (False, "selftest=model roundtrip failed"),
            (True, "restore verified"),
        ])

        rc, text, cfg, _calls = self._run(
            initial=initial,
            models_set=apply,
            attest=lambda *_args: next(attest_results),
        )
        self.assertEqual(rc, 1, text)
        self.assertIn("rollback=restored_verified", text)
        self.assertEqual(cfg, initial)

    def test_product_command_failure_reports(self) -> None:
        rc, text, _cfg, _calls = self._run(
            initial={"agents": {"defaults": {"model": "google/gemini-2.5-flash"}}},
            models_set=lambda *_a: (False, "boom: bad model"),
        )
        self.assertEqual(rc, 1, text)
        self.assertIn("product models set failed", text)
        self.assertIn("rollback=not_needed_verified", text)
        self.assertIn("runtime_config_status=fail", text)

    def test_product_command_partial_write_is_restored_on_failure(self) -> None:
        initial = {"agents": {"defaults": {"model": "google/gemini-2.5-flash"}}}

        def fail_after_partial_write(store, _container, ref):
            store["cfg"] = {"agents": {"defaults": {"model": ref}}}
            return False, "exit=1 stderr=late failure"

        rc, text, cfg, _calls = self._run(initial=initial, models_set=fail_after_partial_write)
        self.assertEqual(rc, 1, text)
        self.assertIn("rollback=restored", text)
        self.assertEqual(cfg, initial)

    def test_openclaw_config_status_reports_ref(self) -> None:
        output = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.runtime_config.is_root", return_value=True),
            patch(
                "agent_runtime_ops.commands.runtime_config._load_config_target",
                return_value=SimpleNamespace(slot="oc1", family="openclaw"),
            ),
            patch("agent_runtime_ops.commands.runtime_config.openclaw_config_path", return_value=Path("/home/oc1/.openclaw/openclaw.json")),
            patch(
                "agent_runtime_ops.commands.runtime_config.read_openclaw_config",
                return_value={
                    "agents": {"defaults": {"model": "google/gemini-2.5-flash"}},
                    "models": {"providers": {"google": {"models": [{"id": "gemini-2.5-flash"}]}}},
                },
            ),
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_runtime_config_status(argparse.Namespace(slot="oc1", state_root="/srv/openclaw-ops"))
        text = output.getvalue()
        self.assertEqual(rc, 0, text)
        self.assertIn("family=openclaw", text)
        self.assertIn("provider=google", text)
        self.assertIn("model=gemini-2.5-flash", text)
        self.assertIn("model_ref=google/gemini-2.5-flash", text)
        self.assertNotIn("provider_model_registered", text)


class OpenClawConfigDomainTests(unittest.TestCase):
    def test_snapshot_restore_preserves_exact_bytes_and_mode(self) -> None:
        from agent_runtime_ops.domain.openclaw_config import (
            capture_openclaw_config_snapshot,
            restore_openclaw_config_snapshot,
        )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "openclaw.json"
            original = b'{\n  "agents": {"defaults": {"model": "google/gemini-3.5-flash"}}\n}\n'
            path.write_bytes(original)
            path.chmod(0o640)
            snapshot = capture_openclaw_config_snapshot(path)
            path.write_text('{"broken":true}\n', encoding="utf-8")
            path.chmod(0o600)
            with patch("agent_runtime_ops.domain.openclaw_config.os.chown", create=True):
                restore_openclaw_config_snapshot(path, snapshot)
            self.assertEqual(path.read_bytes(), original)
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o640)

    def test_current_model_string_object_missing(self) -> None:
        from agent_runtime_ops.domain.openclaw_config import current_openclaw_model

        self.assertEqual(
            current_openclaw_model({"agents": {"defaults": {"model": "google/gemini-2.5-flash"}}}),
            ("google", "gemini-2.5-flash", "google/gemini-2.5-flash", "string"),
        )
        self.assertEqual(
            current_openclaw_model({"agents": {"defaults": {"model": {"primary": "google/gemini-3.5-flash"}}}}),
            ("google", "gemini-3.5-flash", "google/gemini-3.5-flash", "object"),
        )
        self.assertEqual(current_openclaw_model({}), ("", "", "", "missing"))

    def test_build_ref_composes_provider_and_model(self) -> None:
        from agent_runtime_ops.domain.openclaw_config import build_model_ref

        self.assertEqual(build_model_ref("google", "gemini-3.5-flash"), "google/gemini-3.5-flash")
        self.assertEqual(build_model_ref("", "gemini-3.5-flash"), "gemini-3.5-flash")  # bare model, no provider


if __name__ == "__main__":
    unittest.main()
