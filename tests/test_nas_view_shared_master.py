from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import uuid
from unittest.mock import patch

from agent_runtime_ops.commands.nas_view import (
    _restore_views,
    _remove_stale_per_slot_master_registration,
    _validate_shared_master,
    _view_grant_evidence,
    cmd_nas_view_assign,
    cmd_nas_view_detach,
    cmd_nas_view_preflight,
    cmd_nas_view_status,
)
from agent_runtime_ops.domain.nas_views import (
    Corpus,
    load_views_state,
    put_view_record,
    save_views_state,
    shared_master_fstab_entry_present,
)
from agent_runtime_ops.nas import canonical_shared_master_path, parse_smb_share
from agent_runtime_ops.routing import RuntimeBinding, dump_runtime_bindings
from agent_runtime_ops.yamlio import dump_yaml


SHARE = "//10.10.10.2/hanpass_groupware"


def _valid_grant_item(path: str = "mails/seung23") -> dict:
    return {
        "path": path,
        "entry_path": f"/home/oc3/nas_docs/groupware/{path.replace('/', '_')}",
        "mount_exact": True,
        "mount_readonly": True,
        "mount_safe_options": True,
        "source_identity_match": True,
        "source_uid": 0,
        "source_gid": 1003,
        "source_mode": "0750",
        "entry_uid": 0,
        "entry_gid": 1003,
        "entry_mode": "0750",
        "account_uid": 1003,
        "account_gid": 1003,
        "account_traverse": True,
        "account_read": True,
        "issues": [],
        "gaps": [],
    }


def _write_state(root: Path) -> None:
    binding = RuntimeBinding(
        instance_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, "oc3")),
        linux_account="oc3",
        public_host="oc3.ji-tech.co.kr",
        family="openclaw",
        runtime_class="customer",
        gateway_port=28989,
        bridge_port=28990,
    )
    (root / "runtime-bindings.json").write_text(dump_runtime_bindings([binding]), encoding="utf-8")
    (root / "nas-policy.yaml").write_text(
        dump_yaml(
            {
                "defaults": {"auto_approve": False},
                "accounts": {
                    "oc3": {"auto_approve": True, "grants": [{"allow": SHARE}]},
                },
            }
        ),
        encoding="utf-8",
    )


class SharedMasterPolicyTest(unittest.TestCase):
    def test_exact_share_maps_to_posix_path(self) -> None:
        policy = {"corpus_master_mounts": {SHARE: "/mnt/nas/hanpass_groupware"}}
        got = canonical_shared_master_path(parse_smb_share(SHARE), policy)
        self.assertIsNotNone(got)
        self.assertEqual(got.as_posix(), "/mnt/nas/hanpass_groupware")

    def test_mapping_is_exact_and_rejects_unsafe_paths(self) -> None:
        other = parse_smb_share("//10.10.10.2/kakao-work")
        self.assertIsNone(canonical_shared_master_path(other, {"corpus_master_mounts": {SHARE: "/mnt/nas/gw"}}))
        for bad in ("", "relative/path", "/", "/mnt/../etc", "C:\\temp"):
            with self.assertRaises(ValueError, msg=bad):
                canonical_shared_master_path(
                    parse_smb_share(SHARE), {"corpus_master_mounts": {SHARE: bad}}
                )

    def test_shared_master_boot_entry_matches_exact_source_target(self) -> None:
        fstab = (
            "# collector\n"
            f"{SHARE} /mnt/nas/hanpass_groupware cifs credentials=/secret,defaults 0 0\n"
        )
        self.assertTrue(
            shared_master_fstab_entry_present(SHARE, Path("/mnt/nas/hanpass_groupware"), fstab)
        )
        self.assertFalse(shared_master_fstab_entry_present(SHARE, Path("/mnt/nas/other"), fstab))
        self.assertNotIn("/secret", json.dumps({"present": True}))


class SharedMasterAssignTest(unittest.TestCase):
    def test_groupware_preflight_output_matches_versioned_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_state(root)
            output = io.StringIO()
            plan = SimpleNamespace(room_binds=[object(), object()])
            with (
                patch("agent_runtime_ops.commands.nas_view._is_root", return_value=True),
                patch("agent_runtime_ops.commands.nas_view._findmnt_one", return_value=(1, "", [])),
                patch(
                    "agent_runtime_ops.commands.nas_view.shared_master_for_share",
                    return_value=Path("/mnt/nas/hanpass_groupware"),
                ),
                patch("agent_runtime_ops.commands.nas_view._validate_shared_master"),
                patch("agent_runtime_ops.commands.nas_view.build_view_plan", return_value=plan),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_nas_view_preflight(
                    argparse.Namespace(
                        state_root=str(root), slot="oc3", user_id="seung23", share=SHARE,
                        path=["mails/seung23", "approval/example"],
                    )
                )

        expected = (Path(__file__).parent / "fixtures" / "nas-view-preflight-pass-v1.txt").read_text(
            encoding="utf-8"
        )
        self.assertEqual(rc, 0)
        self.assertEqual(output.getvalue(), expected)

    @unittest.skipIf(os.name == "nt", "CLI imports POSIX account modules")
    def test_cli_exposes_exact_preflight_surface(self) -> None:
        from agent_runtime_ops.cli import build_parser

        args = build_parser().parse_args([
            "nas", "view", "preflight", "oc3", "seung23",
            "--share", SHARE,
            "--path", "mails/seung23",
        ])

        self.assertIs(args.func, cmd_nas_view_preflight)
        self.assertEqual(args.slot, "oc3")
        self.assertEqual(args.user_id, "seung23")
        self.assertEqual(args.share, SHARE)
        self.assertEqual(args.path, ["mails/seung23"])
        self.assertFalse(args.require_content_ready)

    def test_groupware_preflight_requires_policy_mapping_without_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_state(root)
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.nas_view._is_root", return_value=True),
                patch("agent_runtime_ops.commands.nas_view._findmnt_one", return_value=(1, "", [])),
                patch("agent_runtime_ops.commands.nas_view.shared_master_for_share", return_value=None),
                patch("agent_runtime_ops.commands.nas_view._ensure_hidden_dirs") as ensure_dirs,
                patch("agent_runtime_ops.commands.nas_view._write_managed_fstab_entry") as write_fstab,
                patch("agent_runtime_ops.commands.nas_view._mount_master") as mount_master,
                patch("agent_runtime_ops.commands.nas_view.bind_ro") as bind,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_nas_view_preflight(
                    argparse.Namespace(
                        state_root=str(root), slot="oc3", user_id="seung23", share=SHARE,
                        path=["mails/seung23"],
                    )
                )

        self.assertEqual(rc, 1)
        self.assertIn("view_preflight_status=fail", output.getvalue())
        self.assertIn("reason=shared_master_policy_missing", output.getvalue())
        ensure_dirs.assert_not_called()
        write_fstab.assert_not_called()
        mount_master.assert_not_called()
        bind.assert_not_called()

    def test_groupware_preflight_validates_exact_paths_without_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "state"
            root.mkdir()
            _write_state(root)
            shared = Path(tmp) / "collector"
            (shared / "mails" / "seung23").mkdir(parents=True)
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.nas_view._is_root", return_value=True),
                patch("agent_runtime_ops.commands.nas_view._findmnt_one", return_value=(1, "", [])),
                patch("agent_runtime_ops.commands.nas_view.shared_master_for_share", return_value=shared),
                patch("agent_runtime_ops.commands.nas_view._validate_shared_master"),
                patch("agent_runtime_ops.commands.nas_view._ensure_hidden_dirs") as ensure_dirs,
                patch("agent_runtime_ops.commands.nas_view._write_managed_fstab_entry") as write_fstab,
                patch("agent_runtime_ops.commands.nas_view._mount_master") as mount_master,
                patch("agent_runtime_ops.commands.nas_view.bind_ro") as bind,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_nas_view_preflight(
                    argparse.Namespace(
                        state_root=str(root), slot="oc3", user_id="seung23", share=SHARE,
                        path=["mails/seung23"],
                    )
                )

        self.assertEqual(rc, 0, output.getvalue())
        self.assertIn("master_contract=shared_policy_required", output.getvalue())
        self.assertIn("content_validation=complete", output.getvalue())
        self.assertIn("selected_bind_count=1", output.getvalue())
        self.assertIn("mutates=false", output.getvalue())
        self.assertIn("view_preflight_status=pass", output.getvalue())
        ensure_dirs.assert_not_called()
        write_fstab.assert_not_called()
        mount_master.assert_not_called()
        bind.assert_not_called()

    def test_assign_missing_groupware_mapping_fails_before_first_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_state(root)
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.nas_view._is_root", return_value=True),
                patch("agent_runtime_ops.commands.nas_view._findmnt_one", return_value=(1, "", [])),
                patch("agent_runtime_ops.commands.nas_view.shared_master_for_share", return_value=None),
                patch("agent_runtime_ops.commands.nas_view._ensure_hidden_dirs") as ensure_dirs,
                patch("agent_runtime_ops.commands.nas_view._write_managed_fstab_entry") as write_fstab,
                patch("agent_runtime_ops.commands.nas_view._mount_master") as mount_master,
                patch("agent_runtime_ops.commands.nas_view._append_action_log"),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_nas_view_assign(
                    argparse.Namespace(
                        state_root=str(root), slot="oc3", user_id="seung23", share=SHARE,
                        username=None, password_stdin=False, domain=None,
                        path=["mails/seung23"],
                    )
                )

        self.assertEqual(rc, 1)
        self.assertIn("reason=shared_master_policy_missing", output.getvalue())
        ensure_dirs.assert_not_called()
        write_fstab.assert_not_called()
        mount_master.assert_not_called()

    def test_groupware_validates_shared_content_but_delivers_from_per_slot_master(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "state"
            root.mkdir()
            _write_state(root)
            shared = Path(tmp) / "collector"
            hidden = Path(tmp) / "slot-master"
            (shared / "mails" / "seung23").mkdir(parents=True)
            (hidden / "mails" / "seung23").mkdir(parents=True)
            credential = Path(tmp) / "root-credential"
            credential.write_text("username=x\npassword=x\n", encoding="utf-8")
            binds: list[Path] = []

            def fake_bind(source: Path, _target: Path, *, recursive: bool = False):
                if not recursive:
                    binds.append(source)
                return True, "ok"

            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.nas_view._is_root", return_value=True),
                patch("agent_runtime_ops.commands.nas_view._findmnt_one", return_value=(1, "", [])),
                patch("agent_runtime_ops.commands.nas_view.shared_master_for_share", return_value=shared),
                patch("agent_runtime_ops.commands.nas_view._validate_shared_master") as validate_shared,
                patch("agent_runtime_ops.commands.nas_view.hidden_master", return_value=hidden),
                patch("agent_runtime_ops.commands.nas_view._ensure_hidden_dirs"),
                patch("agent_runtime_ops.commands.nas_view.root_credential_path", return_value=credential),
                patch("agent_runtime_ops.commands.nas_view.migrate_customer_credential_to_root"),
                patch("agent_runtime_ops.commands.nas_view._write_managed_fstab_entry") as write_fstab,
                patch("agent_runtime_ops.commands.nas_view._mount_master", return_value=(True, "ok")) as mount,
                patch("agent_runtime_ops.commands.nas_view.bind_ro", side_effect=fake_bind),
                patch("agent_runtime_ops.commands.nas_view._append_action_log"),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_nas_view_assign(
                    argparse.Namespace(
                        state_root=str(root), slot="oc3", user_id="seung23", share=SHARE,
                        username=None, password_stdin=False, domain=None,
                        path=["mails/seung23"],
                    )
                )
            record = load_views_state(root)["corpus_views"]["oc3"]["groupware"]

        self.assertEqual(rc, 0, output.getvalue())
        validate_shared.assert_called_once_with(shared, SHARE)
        write_fstab.assert_called_once()
        mount.assert_called_once_with(hidden, SHARE)
        self.assertEqual(binds, [hidden / "mails" / "seung23"])
        self.assertIn("master_mode=per_slot_cifs", output.getvalue())
        self.assertEqual(record["master_mode"], "per_slot_cifs")
        self.assertEqual(Path(record["master_path"]), hidden)

    def test_stale_registration_migration_rejects_wrong_target_or_live_mount(self) -> None:
        expected = Path("/srv/kw-nas/slots/oc3/groupware/master")
        wrong = [{
            "slot": "oc3", "source": SHARE, "mountpoint": "/srv/kw-nas/slots/oc9/master",
            "access": "ro", "credentials": "/secret",
        }]
        with (
            patch("agent_runtime_ops.commands.nas_view._read_managed_fstab_entries", return_value=wrong),
            patch("agent_runtime_ops.commands.nas_view.hidden_master", return_value=expected),
            patch("agent_runtime_ops.commands.nas_view._remove_managed_fstab_entry") as remove,
        ):
            with self.assertRaisesRegex(ValueError, "identity_mismatch"):
                _remove_stale_per_slot_master_registration("oc3", SHARE, "groupware")
        remove.assert_not_called()

        exact = [{
            "slot": "oc3", "source": SHARE, "mountpoint": str(expected),
            "access": "ro", "credentials": "/secret",
        }]
        with (
            patch("agent_runtime_ops.commands.nas_view._read_managed_fstab_entries", return_value=exact),
            patch("agent_runtime_ops.commands.nas_view.hidden_master", return_value=expected),
            patch("agent_runtime_ops.commands.nas_view._findmnt_one", return_value=(0, "", [{"target": str(expected)}])),
            patch("agent_runtime_ops.commands.nas_view._remove_managed_fstab_entry") as remove,
        ):
            with self.assertRaisesRegex(ValueError, "still_mounted"):
                _remove_stale_per_slot_master_registration("oc3", SHARE, "groupware")
        remove.assert_not_called()

    def test_assign_reuses_shared_master_and_migrates_only_stale_registration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "state"
            root.mkdir()
            _write_state(root)
            shared = Path(tmp) / "collector-master"
            (shared / "mails" / "seung23").mkdir(parents=True)
            (shared / "groupware" / "approval" / "황정승 책임").mkdir(parents=True)
            hidden = Path(tmp) / "slot-hidden-master"
            binds: list[tuple[Path, Path, bool]] = []

            def fake_bind(source: Path, target: Path, *, recursive: bool = False):
                binds.append((source, target, recursive))
                return True, "ok"

            stale = [{
                "slot": "oc3",
                "source": SHARE,
                "mountpoint": str(hidden),
                "access": "ro",
                "credentials": "/etc/samba/credentials/ro_groupware.cred",
            }]
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.nas_view._is_root", return_value=True),
                patch("agent_runtime_ops.commands.nas_view._ensure_hidden_dirs"),
                patch("agent_runtime_ops.commands.nas_view.hidden_master", return_value=hidden),
                patch("agent_runtime_ops.commands.nas_view.shared_master_for_share", return_value=shared),
                patch(
                    "agent_runtime_ops.commands.nas_view.corpus_for_share",
                    return_value=Corpus("groupware", "groupware", "granted_paths", "shared_policy_required"),
                ),
                patch("agent_runtime_ops.commands.nas_view._validate_shared_master"),
                patch("agent_runtime_ops.commands.nas_view._read_managed_fstab_entries", return_value=stale),
                patch("agent_runtime_ops.commands.nas_view._remove_managed_fstab_entry", return_value=True) as remove,
                patch("agent_runtime_ops.commands.nas_view._findmnt_one", return_value=(1, "", [])),
                patch("agent_runtime_ops.commands.nas_view.bind_ro", side_effect=fake_bind),
                patch("agent_runtime_ops.commands.nas_view._write_managed_fstab_entry") as write_fstab,
                patch("agent_runtime_ops.commands.nas_view._mount_master") as mount_master,
                patch("agent_runtime_ops.commands.nas_view.migrate_customer_credential_to_root") as migrate,
                patch("agent_runtime_ops.commands.nas_view.read_password_from_stdin") as password,
                patch("agent_runtime_ops.commands.nas_view._append_action_log"),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_nas_view_assign(
                    argparse.Namespace(
                        state_root=str(root),
                        slot="oc3",
                        user_id="seung23",
                        share=SHARE,
                        username=None,
                        password_stdin=False,
                        domain=None,
                        path=["groupware/approval/황정승 책임", "mails/seung23"],
                    )
                )

            self.assertEqual(rc, 0, output.getvalue())
            self.assertIn("master_mode=shared_policy_mount", output.getvalue())
            self.assertIn("legacy_fstab_removed=yes", output.getvalue())
            remove.assert_called_once_with("oc3", SHARE)
            write_fstab.assert_not_called()
            mount_master.assert_not_called()
            migrate.assert_not_called()
            password.assert_not_called()
            self.assertEqual([source for source, _, _ in binds[:-1]], [
                shared / "groupware" / "approval" / "황정승 책임",
                shared / "mails" / "seung23",
            ])
            record = load_views_state(root)["corpus_views"]["oc3"]["groupware"]
            self.assertEqual(record["master_mode"], "shared_policy_mount")
            self.assertEqual(Path(record["master_path"]), shared)

    def test_shared_policy_rejects_per_slot_credential_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_state(root)
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.nas_view._is_root", return_value=True),
                patch("agent_runtime_ops.commands.nas_view._ensure_hidden_dirs"),
                patch("agent_runtime_ops.commands.nas_view._findmnt_one", return_value=(1, "", [])),
                patch("agent_runtime_ops.commands.nas_view.shared_master_for_share", return_value=Path(tmp)),
                patch("agent_runtime_ops.commands.nas_view.read_password_from_stdin") as read_password,
                patch("agent_runtime_ops.commands.nas_view._append_action_log"),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_nas_view_assign(
                    argparse.Namespace(
                        state_root=str(root), slot="oc3", user_id="seung23", share=SHARE,
                        username="wrong-shape", password_stdin=True, domain=None,
                        path=["mails/seung23"],
                    )
                )
        self.assertEqual(rc, 1)
        self.assertIn("forbids per-slot credential", output.getvalue())
        read_password.assert_not_called()

    def test_shared_detach_never_unmounts_global_master_or_removes_fstab(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            views = load_views_state(root)
            put_view_record(views, "oc3", "groupware", {
                "user_id": "seung23", "share": SHARE, "corpus": "groupware",
                "master_mode": "shared_policy_mount", "master_path": "/mnt/nas/hanpass_groupware",
            })
            save_views_state(root, views)
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.nas_view._is_root", return_value=True),
                patch("agent_runtime_ops.commands.nas_view.unmount_tree", return_value=(0, [])) as unmount,
                patch("agent_runtime_ops.commands.nas_view._remove_managed_fstab_entry") as remove,
                patch("agent_runtime_ops.commands.nas_view._append_action_log"),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_nas_view_detach(
                    argparse.Namespace(state_root=str(root), slot="oc3", corpus="groupware", share=None)
                )
        self.assertEqual(rc, 0, output.getvalue())
        self.assertEqual(unmount.call_count, 2)
        self.assertTrue(all("/mnt/nas/hanpass_groupware" not in str(call) for call in unmount.call_args_list))
        remove.assert_not_called()
        self.assertIn("fstab_entry_removed=no", output.getvalue())

    def test_shared_restore_revalidates_policy_and_skips_per_slot_mount(self) -> None:
        record = {
            "user_id": "seung23", "share": SHARE, "paths": ["mails/seung23"],
            "master_mode": "shared_policy_mount", "master_path": "/mnt/nas/hanpass_groupware",
        }
        plan = SimpleNamespace(user_id="seung23")
        with (
            patch("agent_runtime_ops.commands.nas_view._ensure_hidden_dirs"),
            patch("agent_runtime_ops.commands.nas_view._shared_master_for_record", return_value=Path("/mnt/nas/hanpass_groupware")),
            patch("agent_runtime_ops.commands.nas_view._mount_master") as mount_master,
            patch("agent_runtime_ops.commands.nas_view.build_view_plan", return_value=plan) as build,
            patch("agent_runtime_ops.commands.nas_view._apply_binds", return_value=(True, "ok", 1)),
            patch("agent_runtime_ops.commands.nas_view._append_action_log"),
        ):
            failed = _restore_views(Path("/state"), [("oc3", "groupware", record)])
        self.assertEqual(failed, 0)
        mount_master.assert_not_called()
        self.assertEqual(build.call_args.kwargs["master_override"], Path("/mnt/nas/hanpass_groupware"))

    def test_status_is_honest_about_rw_collector_but_requires_ro_entry(self) -> None:
        master = Path("/mnt/nas/hanpass_groupware")
        record = {
            "user_id": "seung23", "share": SHARE, "paths": ["mails/seung23"],
            "master_mode": "shared_policy_mount", "master_path": master.as_posix(),
        }
        records = {"views": {}, "corpus_views": {"oc3": {"groupware": record}}}
        fstab = f"{SHARE} {master.as_posix()} cifs credentials=/not-output,rw 0 0\n"

        def findmnt(path: Path):
            if path == master:
                return 0, "", [{
                    "target": master.as_posix(), "source": SHARE, "fstype": "cifs", "options": "rw",
                }]
            return 0, "", [{
                "target": str(path), "source": f"{SHARE}[/mails/seung23]",
                "fstype": "none", "options": "ro,nosuid,nodev,bind",
            }]

        output = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.nas_view.load_views_state", return_value=records),
            patch("agent_runtime_ops.commands.nas_view._shared_master_for_record", return_value=master),
            patch("agent_runtime_ops.commands.nas_view.shared_master_for_share", return_value=master),
            patch("agent_runtime_ops.commands.nas_view._findmnt_one", side_effect=findmnt),
            patch("agent_runtime_ops.commands.nas_view._read_fstab", return_value=fstab),
            patch("agent_runtime_ops.commands.nas_view._is_root", return_value=False),
            patch("agent_runtime_ops.commands.nas_view.failed_cifs_mount_units", return_value=([], None)),
            patch(
                "agent_runtime_ops.commands.nas_view._view_grant_evidence",
                return_value=("yes", [_valid_grant_item()], True, True),
            ),
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_nas_view_status(SimpleNamespace(state_root="/unused"))
        text = output.getvalue()
        self.assertEqual(rc, 0, text)
        self.assertIn("view_1_master_readonly=no", text)
        self.assertIn("view_1_master_readonly_required=no", text)
        self.assertIn("view_1_entry_mounted_readonly=yes", text)
        self.assertIn("view_1_grant_evidence_applicable=yes", text)
        self.assertIn("view_1_grant_evidence_count=1", text)
        self.assertIn("view_1_grant_evidence_complete=yes", text)
        self.assertIn("view_1_healthy=yes", text)
        self.assertIn("boot_fstab_entries=1/1", text)
        self.assertNotIn("not-output", text)

    def test_status_degrades_when_grant_evidence_is_incomplete(self) -> None:
        master = Path("/mnt/nas/hanpass_groupware")
        record = {
            "user_id": "seung23", "share": SHARE, "paths": ["mails/seung23"],
            "master_mode": "shared_policy_mount", "master_path": master.as_posix(),
        }
        records = {"views": {}, "corpus_views": {"oc3": {"groupware": record}}}
        output = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.nas_view.load_views_state", return_value=records),
            patch("agent_runtime_ops.commands.nas_view._shared_master_for_record", return_value=master),
            patch("agent_runtime_ops.commands.nas_view.shared_master_for_share", return_value=master),
            patch(
                "agent_runtime_ops.commands.nas_view._findmnt_one",
                return_value=(0, "", [{"target": master.as_posix(), "options": "rw"}]),
            ),
            patch("agent_runtime_ops.commands.nas_view._read_fstab", return_value=""),
            patch("agent_runtime_ops.commands.nas_view._is_root", return_value=False),
            patch("agent_runtime_ops.commands.nas_view.failed_cifs_mount_units", return_value=([], None)),
            patch(
                "agent_runtime_ops.commands.nas_view._view_grant_evidence",
                return_value=("yes", [], False, False),
            ),
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_nas_view_status(SimpleNamespace(state_root="/unused"))
        text = output.getvalue()
        self.assertEqual(rc, 1, text)
        self.assertIn("view_1_grant_evidence_complete=no", text)
        self.assertIn("view_1_healthy=no", text)
        self.assertIn('view_observation_gaps_json=["boot_restore_requires_root","grant_evidence_incomplete"]', text)

    def test_grant_evidence_rejects_duplicate_alias_and_non_string_path(self) -> None:
        record = {"paths": ["mails/user", "mails_user"]}
        self.assertEqual(
            _view_grant_evidence("oc3", "groupware", record, Path("/master")),
            ("yes", [], False, False),
        )
        self.assertEqual(
            _view_grant_evidence("oc3", "groupware", {"paths": [7]}, Path("/master")),
            ("yes", [], False, False),
        )
        self.assertEqual(
            _view_grant_evidence("oc3", "groupware", {"paths": []}, Path("/master")),
            ("yes", [], False, False),
        )

    def test_grant_evidence_uses_exact_source_entry_and_budget(self) -> None:
        item = _valid_grant_item()
        with (
            patch(
                "agent_runtime_ops.commands.nas_view.observe_ro_view_grant",
                return_value=(item, True, True),
            ) as observe,
            patch(
                "agent_runtime_ops.commands.nas_view.observe_mount_targets_under",
                return_value=({
                    "/home/oc3/nas_docs/groupware",
                    "/home/oc3/nas_docs/groupware/mails_seung23",
                }, None),
            ),
        ):
            result = _view_grant_evidence(
                "oc3", "groupware", {"paths": ["mails/seung23"]}, Path("/master")
            )
        self.assertEqual(result, ("yes", [item], True, True))
        self.assertEqual(observe.call_args.args[:3], (
            Path("/master/mails/seung23"),
            Path("/home/oc3/nas_docs/groupware/mails_seung23"),
            "oc3",
        ))
        self.assertGreater(observe.call_args.kwargs["timeout"], 0)
        self.assertLessEqual(observe.call_args.kwargs["timeout"], 3.0)

    def test_unrecorded_actual_child_mount_makes_evidence_incomplete(self) -> None:
        item = _valid_grant_item()
        with (
            patch(
                "agent_runtime_ops.commands.nas_view.observe_ro_view_grant",
                return_value=(item, True, True),
            ),
            patch(
                "agent_runtime_ops.commands.nas_view.observe_mount_targets_under",
                return_value=({
                    "/home/oc3/nas_docs/groupware",
                    "/home/oc3/nas_docs/groupware/mails_seung23",
                    "/home/oc3/nas_docs/groupware/approval_old_owner",
                }, None),
            ),
        ):
            applicable, evidence, complete, green = _view_grant_evidence(
                "oc3", "groupware", {"paths": ["mails/seung23"]}, Path("/master")
            )
        self.assertEqual(applicable, "yes")
        self.assertEqual(evidence, [item])
        self.assertFalse(complete)
        self.assertFalse(green)

    def test_inventory_is_bracketed_by_two_identical_grant_rounds(self) -> None:
        before = _valid_grant_item()
        after = dict(before)
        after["entry_mode"] = "0700"
        inventory_seen = False

        def observe(*_args, **_kwargs):
            return (after if inventory_seen else before, True, True)

        def inventory(*_args, **_kwargs):
            nonlocal inventory_seen
            inventory_seen = True
            return ({
                "/home/oc3/nas_docs/groupware",
                "/home/oc3/nas_docs/groupware/mails_seung23",
            }, None)

        with (
            patch(
                "agent_runtime_ops.commands.nas_view.observe_ro_view_grant",
                side_effect=observe,
            ),
            patch(
                "agent_runtime_ops.commands.nas_view.observe_mount_targets_under",
                side_effect=inventory,
            ),
        ):
            applicable, evidence, complete, green = _view_grant_evidence(
                "oc3", "groupware", {"paths": ["mails/seung23"]}, Path("/master")
            )
        self.assertEqual(applicable, "yes")
        self.assertEqual(evidence[0]["entry_mode"], "0700")
        self.assertFalse(complete)
        self.assertFalse(green)


@unittest.skipUnless(os.name == "posix", "requires POSIX directory fd and mount path semantics")
class SharedMasterPosixValidationTest(unittest.TestCase):
    def test_exact_mount_identity_validates_and_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            master = Path(tmp) / "master"
            master.mkdir()
            row = {"target": str(master), "source": SHARE, "fstype": "cifs", "options": "rw"}
            with patch("agent_runtime_ops.commands.nas_view._findmnt_one", return_value=(0, "", [row])):
                self.assertEqual(_validate_shared_master(master, SHARE), row)

            link = Path(tmp) / "link"
            link.symlink_to(master, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                _validate_shared_master(link, SHARE)


if __name__ == "__main__":
    unittest.main()
