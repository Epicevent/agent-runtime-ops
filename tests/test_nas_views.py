from __future__ import annotations

import argparse
import contextlib
import io
import json
import sqlite3
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from agent_runtime_ops.commands.nas_view import (
    cmd_nas_view_assign,
    cmd_nas_view_detach,
    cmd_nas_view_status,
    cmd_nas_view_catalog,
)
from agent_runtime_ops.domain.nas_views import (
    build_view_plan,
    find_user_package,
    load_membership_rooms,
    load_package_room_summary,
    load_views_state,
    save_views_state,
    validate_room_id,
    validate_user_id,
)
from agent_runtime_ops.nas import parse_smb_share
from agent_runtime_ops.routing import RuntimeBinding, dump_runtime_bindings
from agent_runtime_ops.yamlio import dump_yaml


def binding(account: str, runtime_class: str, gateway: int, bridge: int) -> RuntimeBinding:
    return RuntimeBinding(
        instance_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, account)),
        linux_account=account,
        public_host=f"{account}.ji-tech.co.kr",
        family="openclaw",
        runtime_class=runtime_class,
        gateway_port=gateway,
        bridge_port=bridge,
    )


def write_state(root: Path) -> None:
    (root / "runtime-bindings.json").write_text(
        dump_runtime_bindings([binding("oc3", "customer", 28989, 28990), binding("dev-oc", "dev", 30789, 30790)]),
        encoding="utf-8",
    )
    (root / "nas-policy.yaml").write_text(
        dump_yaml(
            {
                "defaults": {"auto_approve": False},
                "accounts": {
                    "oc3": {
                        "auto_approve": True,
                        "grants": [{"allow": "//192.168.0.222/*"}],
                    }
                },
            }
        ),
        encoding="utf-8",
    )


def write_master(master: Path, *, user_id: str = "7521796", rooms: list[str] | None = None) -> Path:
    rooms = rooms if rooms is not None else ["r1", "r2"]
    package = master / "users" / f"홍길동_대리_{user_id}"
    package.mkdir(parents=True)
    (package / "membership.json").write_text(
        json.dumps({"user_id": user_id, "conversation_ids": rooms}),
        encoding="utf-8",
    )
    for room in rooms[:-1]:  # last room deliberately has no media dir
        (master / "media" / room).mkdir(parents=True)
    return package


class NasViewDomainTests(unittest.TestCase):
    def test_validate_user_id_rejects_traversal(self) -> None:
        for bad in ("../x", "a/b", "", "a" * 65, ".."):
            with self.assertRaises(ValueError):
                validate_user_id(bad)
        self.assertEqual(validate_user_id(" 7521796 "), "7521796")

    def test_validate_room_id_rejects_separator(self) -> None:
        with self.assertRaises(ValueError):
            validate_room_id("rooms/../../etc")
        self.assertEqual(validate_room_id("abc-123"), "abc-123")

    def test_find_user_package_matches_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            master = Path(tmp)
            package = write_master(master, user_id="42")
            self.assertEqual(find_user_package(master, "42"), package)

    def test_find_user_package_rejects_missing_and_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            master = Path(tmp)
            write_master(master, user_id="42")
            with self.assertRaises(FileNotFoundError):
                find_user_package(master, "43")
            (master / "users" / "김철수_과장_42").mkdir()
            with self.assertRaises(ValueError):
                find_user_package(master, "42")

    def test_load_membership_rooms_validates_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            master = Path(tmp)
            package = write_master(master, rooms=["ok1", "../bad"])
            with self.assertRaises(ValueError):
                load_membership_rooms(package)

    def test_package_room_summary_uses_membership_and_real_sqlite_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            package = write_master(Path(tmp), rooms=["r1", "r2"])
            conn = sqlite3.connect(package / "messages.sqlite")
            conn.execute("CREATE TABLE messages (conversation_id TEXT, room_name TEXT, sent_time INTEGER)")
            conn.executemany(
                "INSERT INTO messages VALUES (?,?,?)",
                [("r1", "실제 방 1", 10), ("r1", "실제 방 1", 20), ("outside", "제외", 30)],
            )
            conn.commit()
            conn.close()
            rows = load_package_room_summary(package)
        self.assertEqual(rows, [{
            "conversation_id": "r1", "room_name": "실제 방 1",
            "message_count": 2, "latest_sent_time": 20,
        }])

    def test_build_view_plan_binds_only_rooms_with_media(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "state"
            root.mkdir()
            write_state(root)
            master = Path(tmp) / "master"
            write_master(master, rooms=["r1", "r2", "r3"])
            with patch("agent_runtime_ops.domain.nas_views.hidden_master", return_value=master):
                plan = build_view_plan("oc3", "7521796", "//192.168.0.222/kakao-work", root)
        self.assertEqual(plan.slot, "oc3")
        self.assertEqual([source.name for source, _ in plan.room_binds], ["r1", "r2"])
        self.assertEqual(plan.missing_rooms, ["r3"])
        self.assertEqual(plan.entry, Path("/home/oc3/nas_docs/kw"))

    def test_build_view_plan_denies_non_customer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            with self.assertRaises(ValueError):
                build_view_plan("dev-oc", "1", "//192.168.0.222/kakao-work", root)

    def test_views_state_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = load_views_state(root)
            self.assertEqual(data["views"], {})
            data["views"]["oc3"] = {"user_id": "42", "share": "//h/s"}
            save_views_state(root, data)
            again = load_views_state(root)
            self.assertEqual(again["views"]["oc3"]["user_id"], "42")
            self.assertEqual(again["meta"]["schema_version"], 1)


class NasViewCliTests(unittest.TestCase):
    def _assign(self, root: Path, master: Path, binds: list[tuple[Path, Path, bool]]) -> tuple[int, str]:
        def fake_bind_ro(source: Path, target: Path, *, recursive: bool = False) -> tuple[bool, str]:
            binds.append((source, target, recursive))
            return True, "ok"

        credential = root / "cred" / "share.cred"
        credential.parent.mkdir(parents=True, exist_ok=True)
        credential.write_text("username=x\npassword=y\n", encoding="utf-8")
        output = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.nas_view._is_root", return_value=True),
            patch("agent_runtime_ops.commands.nas_view._ensure_hidden_dirs"),
            patch("agent_runtime_ops.commands.nas_view.hidden_master", return_value=master),
            patch("agent_runtime_ops.domain.nas_views.hidden_master", return_value=master),
            patch("agent_runtime_ops.commands.nas_view.root_credential_path", return_value=credential),
            patch("agent_runtime_ops.commands.nas_view._write_managed_fstab_entry"),
            patch("agent_runtime_ops.commands.nas_view._mount_master", return_value=(True, "ok")),
            patch("agent_runtime_ops.commands.nas_view._findmnt_one", return_value=(1, "", [])),
            patch("agent_runtime_ops.commands.nas_view.bind_ro", side_effect=fake_bind_ro),
            patch("agent_runtime_ops.commands.nas_view._append_action_log"),
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_nas_view_assign(
                argparse.Namespace(
                    state_root=str(root),
                    slot="oc3",
                    user_id="7521796",
                    share="//192.168.0.222/kakao-work",
                    username=None,
                    password_stdin=False,
                    domain=None,
                )
            )
        return rc, output.getvalue()

    def test_assign_records_view_and_binds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "state"
            root.mkdir()
            write_state(root)
            master = Path(tmp) / "master"
            write_master(master)
            binds: list[tuple[Path, Path, bool]] = []
            rc, out = self._assign(root, master, binds)
            self.assertEqual(rc, 0, out)
            self.assertIn("view_assign_status=ok", out)
            self.assertIn("rooms_bound=1", out)
            self.assertIn("rooms_missing_media=1", out)
            state = load_views_state(root)
            self.assertEqual(state["views"]["oc3"]["user_id"], "7521796")
            # binds: package + 1 room + entry
            self.assertEqual(len(binds), 3)
            self.assertEqual(binds[-1][1], Path("/home/oc3/nas_docs/kw"))
            # only the entry bind is recursive (--rbind pulls the submounts along)
            self.assertEqual([recursive for _, _, recursive in binds], [False, False, True])

    def test_assign_refuses_double_assign(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "state"
            root.mkdir()
            write_state(root)
            master = Path(tmp) / "master"
            write_master(master)
            binds: list[tuple[Path, Path, bool]] = []
            rc, _ = self._assign(root, master, binds)
            self.assertEqual(rc, 0)
            rc, out = self._assign(root, master, binds)
            self.assertEqual(rc, 1)
            self.assertIn("view_assign_status=fail", out)
            self.assertIn("detach", out)

    def test_assign_rejects_own_folder_share(self) -> None:
        # nas view is corpus-only; an OCn own-folder share must be refused before
        # any credential is touched (its slot-owned cred is legitimate, not corpus).
        decision = type(
            "Decision",
            (),
            {"slot": "oc3", "share": parse_smb_share("//10.10.10.2/OC3"), "allowed": True, "reason": "grant_matched"},
        )()
        with tempfile.TemporaryDirectory() as tmp:
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.nas_view._is_root", return_value=True),
                patch("agent_runtime_ops.commands.nas_view.check_nas_policy", return_value=decision),
                patch("agent_runtime_ops.commands.nas_view.migrate_customer_credential_to_root") as migrate,
                patch("agent_runtime_ops.commands.nas_view._mount_master") as mount_master,
                patch("agent_runtime_ops.commands.nas_view._append_action_log"),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_nas_view_assign(
                    argparse.Namespace(
                        state_root=str(Path(tmp)),
                        slot="oc3",
                        user_id="7",
                        share="//10.10.10.2/OC3",
                        username=None,
                        password_stdin=False,
                        domain=None,
                    )
                )
        self.assertEqual(rc, 1)
        self.assertIn("view_assign_status=fail", output.getvalue())
        self.assertIn("nas mount", output.getvalue())
        migrate.assert_not_called()
        mount_master.assert_not_called()

    def test_detach_rejects_own_folder_share_before_side_effects(self) -> None:
        # detach must reject an OCn own-folder --share before unmounting anything or
        # deleting a cred that is legitimately slot-owned.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "state"
            root.mkdir()
            write_state(root)
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.nas_view._is_root", return_value=True),
                patch("agent_runtime_ops.commands.nas_view.unmount_tree", return_value=(0, [])) as unmount,
                patch("agent_runtime_ops.commands.nas_view._remove_managed_fstab_entry") as remove_fstab,
                patch("agent_runtime_ops.commands.nas_view._append_action_log"),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_nas_view_detach(
                    argparse.Namespace(state_root=str(root), slot="oc3", share="//10.10.10.2/OC3")
                )
        self.assertEqual(rc, 1)
        self.assertIn("view_detach_status=fail", output.getvalue())
        self.assertIn("nas unmount", output.getvalue())
        unmount.assert_not_called()
        remove_fstab.assert_not_called()

    def test_detach_removes_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "state"
            root.mkdir()
            write_state(root)
            data = load_views_state(root)
            data["views"]["oc3"] = {"user_id": "42", "share": "//192.168.0.222/kakao-work"}
            save_views_state(root, data)
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.nas_view._is_root", return_value=True),
                patch("agent_runtime_ops.commands.nas_view.unmount_tree", return_value=(0, [])),
                patch("agent_runtime_ops.commands.nas_view._remove_managed_fstab_entry", return_value=True),
                patch("agent_runtime_ops.commands.nas_view._append_action_log"),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_nas_view_detach(argparse.Namespace(state_root=str(root), slot="oc3", share=None))
            self.assertEqual(rc, 0, output.getvalue())
            self.assertIn("view_detach_status=ok", output.getvalue())
            self.assertEqual(load_views_state(root)["views"], {})

    def test_status_reports_views(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "state"
            root.mkdir()
            data = load_views_state(root)
            data["views"]["oc3"] = {
                "user_id": "42", "share": "//h/s", "package": "p_42",
                "paths": ["groupware/mails/jitech", "groupware/approval/대표 이사"],
            }
            save_views_state(root, data)
            output = io.StringIO()
            fstab = "# agent-runtime-ops nas slot=oc3 source=//h/s\n//h/s /srv/kw-nas/slots/oc3/master cifs ro,nofail 0 0\n"
            with (
                patch(
                    "agent_runtime_ops.commands.nas_view._findmnt_one",
                    return_value=(0, "", [{"target": "x", "source": "y", "fstype": "cifs", "options": "ro"}]),
                ),
                patch("agent_runtime_ops.commands.nas_view._read_fstab", return_value=fstab),
                patch("agent_runtime_ops.commands.nas_view._is_root", return_value=False),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_nas_view_status(argparse.Namespace(state_root=str(root)))
            self.assertEqual(rc, 0, output.getvalue())
            self.assertIn("view_1_target=oc3", output.getvalue())
            self.assertIn(
                'view_1_paths_json=["groupware/mails/jitech","groupware/approval/대표 이사"]',
                output.getvalue(),
            )
            self.assertIn("view_1_healthy=yes", output.getvalue())
            self.assertIn("boot_fstab_entries=1/1", output.getvalue())
            self.assertIn("boot_restore_cron=unknown_requires_root", output.getvalue())


class CatalogCommandTests(unittest.TestCase):
    def test_catalog_returns_only_sanitized_non_secret_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "users.json").write_text(json.dumps({
                "schema": "kw-users-catalog/1",
                "generated_at": "2026-07-22T00:00:00Z",
                "internal_note": "must not leak",
                "users": [{
                    "user_id": "7362168", "display_name": "함석헌", "job_title": "대표이사",
                    "package_dir": "users/함석헌_대표이사_7362168", "secret": "nope",
                }],
            }, ensure_ascii=False), encoding="utf-8")
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.nas_view._KAKAO_PACKAGE_ROOT", root),
                patch("agent_runtime_ops.commands.nas_view._is_root", return_value=True),
                patch("agent_runtime_ops.commands.nas_view._findmnt_one", return_value=(0, "", [{"fstype": "cifs"}])),
                patch("agent_runtime_ops.commands.nas_view._is_readonly_mount", return_value=True),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_nas_view_catalog(argparse.Namespace())
        self.assertEqual(rc, 0, output.getvalue())
        values = dict(line.split("=", 1) for line in output.getvalue().splitlines() if "=" in line)
        users = json.loads(values["catalog_json"])
        self.assertEqual(users, [{
            "user_id": "7362168", "display_name": "함석헌", "job_title": "대표이사",
            "package_dir": "users/함석헌_대표이사_7362168",
        }])
        self.assertNotIn("secret", output.getvalue())
        self.assertEqual(values["mutates"], "false")


class FakeProc:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class BindRoTests(unittest.TestCase):
    def _ro_row(self) -> list[dict[str, str]]:
        return [{"target": "t", "source": "s", "fstype": "none", "options": "ro,bind"}]

    def test_bind_ro_uses_rbind_when_recursive(self) -> None:
        from agent_runtime_ops.host import bind_mounts

        commands: list[list[str]] = []

        def fake_run(command: list[str], timeout: int = 20) -> FakeProc:
            commands.append(command)
            return FakeProc()

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "src"
            source.mkdir()
            target = Path(tmp) / "dst"
            with (
                patch.object(bind_mounts, "_run_text", side_effect=fake_run),
                patch.object(bind_mounts, "findmnt_one", side_effect=[(1, "", []), (0, "", self._ro_row())]),
            ):
                ok, reason = bind_mounts.bind_ro(source, target, recursive=True)
        self.assertTrue(ok, reason)
        self.assertEqual(commands[0][:2], ["mount", "--rbind"])

    def test_bind_ro_rebuilds_stale_existing_mount(self) -> None:
        from agent_runtime_ops.host import bind_mounts

        commands: list[list[str]] = []

        def fake_run(command: list[str], timeout: int = 20) -> FakeProc:
            commands.append(command)
            return FakeProc()

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "src"
            source.mkdir()
            target = Path(tmp) / "dst"
            with (
                patch.object(bind_mounts, "_run_text", side_effect=fake_run),
                # first findmnt: a stale mount exists; second: post-bind verify
                patch.object(bind_mounts, "findmnt_one", side_effect=[(0, "", self._ro_row()), (0, "", self._ro_row())]),
                patch.object(bind_mounts, "unmount_tree", return_value=(0, [])) as fake_unmount,
            ):
                ok, reason = bind_mounts.bind_ro(source, target)
        self.assertTrue(ok, reason)
        fake_unmount.assert_called_once_with(target)
        self.assertEqual(commands[0][:2], ["mount", "--bind"])

    def test_bind_ro_fails_when_stale_unmount_fails(self) -> None:
        from agent_runtime_ops.host import bind_mounts

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "src"
            source.mkdir()
            target = Path(tmp) / "dst"
            with (
                patch.object(bind_mounts, "findmnt_one", return_value=(0, "", self._ro_row())),
                patch.object(bind_mounts, "unmount_tree", return_value=(1, ["busy"])),
            ):
                ok, reason = bind_mounts.bind_ro(source, target)
        self.assertFalse(ok)
        self.assertIn("stale_mount_unmount_failed", reason)


if __name__ == "__main__":
    unittest.main()
