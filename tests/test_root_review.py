from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from agent_runtime_ops.root_review import RootReviewError, RootReviewStore


NO_PENDING = (
    "STATUS=NO_PENDING_ROOT_COMMAND\n"
    "PURPOSE=No pending command.\n"
    "TRANSCRIPT_VERIFIED=YES\n"
    "POST_STATE_VERIFIED=YES\n"
).encode("utf-8")


class RootReviewFixture:
    def __init__(self, root: Path) -> None:
        self.assignments = root / "assignments"
        self.requests = root / "requests"
        self.output = root / "output"
        for directory in (self.assignments, self.requests, self.output):
            directory.mkdir()
        self.session = "agent-one"
        self.pane = "%42"
        self.request = self.requests / f"{self.session}.txt"
        self.transcript = self.output / f"{self.session}.log"
        self.request.write_bytes(NO_PENDING)
        self.transcript.write_bytes(b"existing transcript\n")
        (self.assignments / f"{self.session}.env").write_text(
            "\n".join(
                (
                    "assignment_schema=root-review-assignment/v3",
                    f"agent_tmux_session={self.session}",
                    f"agent_pane={self.pane}",
                    "agent_pane_pid=4242",
                    "agent_codex_executable=/usr/local/bin/codex",
                    "root_session=agent-one-root",
                    "root_session_id=$1",
                    "root_pane=%43",
                    "viewer_pane=%44",
                    f"transcript={self.transcript}",
                    f"request={self.request}",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        uid = os.getuid() if hasattr(os, "getuid") else 0
        gid = os.getgid() if hasattr(os, "getgid") else 0
        self.store = RootReviewStore(
            assignment_dir=self.assignments,
            request_dir=self.requests,
            transcript_dir=self.output,
            pane_id=self.pane,
            agent_uid=uid,
            agent_gid=gid,
            root_uid=uid,
            enforce_posix_metadata=False,
        )


@pytest.fixture
def root_review(tmp_path: Path) -> RootReviewFixture:
    return RootReviewFixture(tmp_path)


def test_publish_wait_and_resolve_preserve_existing_viewer_contract(
    root_review: RootReviewFixture,
) -> None:
    command = "/usr/bin/id -u"
    published = root_review.store.publish(purpose="Read identity", command=command)

    request = root_review.request.read_text(encoding="utf-8")
    lines = request.splitlines()
    assert lines[0] == "STATUS=WAITING_FOR_USER_REVIEW_AND_APPROVAL_NOT_EXECUTED"
    assert lines[1].startswith("CARD_ID=")
    assert len(lines[1]) == len("CARD_ID=") + 32
    assert lines[2:] == ["# 목적: Read identity", f"command={command}"]
    assert published["command"] == command
    assert published["command_sha256"] == (
        "sha256:" + hashlib.sha256(command.encode("utf-8")).hexdigest()
    )
    assert published["command_bytes"] == len(command.encode("utf-8"))
    assert set(published) == {
        "handle",
        "state",
        "request_sha256",
        "command",
        "command_sha256",
        "command_bytes",
    }
    assert published["state"] == "pending"

    unchanged = root_review.store.wait(
        raw_handle=published["handle"],
        timeout_seconds=0,
        poll_interval_seconds=0.001,
    )
    assert unchanged["state"] == "pending"
    assert unchanged["transcript_append_sha256"] is None
    assert unchanged["transcript_appended_bytes"] == 0

    with root_review.transcript.open("ab") as stream:
        stream.write(b"user command terminal output\n")
    observed = root_review.store.wait(
        raw_handle=published["handle"],
        timeout_seconds=0,
        poll_interval_seconds=0.001,
    )
    assert observed["state"] == "transcript_appended"
    assert observed["transcript_appended_bytes"] > 0
    assert "terminal output" not in str(observed)

    resolved = root_review.store.resolve(raw_handle=published["handle"])
    assert resolved["state"] == "no_pending"
    assert root_review.request.read_text(encoding="utf-8").splitlines() == [
        "STATUS=NO_PENDING_ROOT_COMMAND",
        "PURPOSE=Previous root-review card was observed and cleared; no next root command is pending.",
        "TRANSCRIPT_VERIFIED=YES",
        "POST_STATE_VERIFIED=YES",
    ]


def test_publish_preserves_full_multiline_command_for_viewer(
    root_review: RootReviewFixture,
) -> None:
    command = "set -eu\nprintf '%s\\n' visible\n/usr/bin/id -u"

    published = root_review.store.publish(
        purpose="Show every operation", command=command
    )

    assert published["command"] == command
    assert published["command_bytes"] == len(command.encode("utf-8"))
    request = root_review.request.read_text(encoding="utf-8")
    assert "command=" not in request
    assert f"COMMAND_BEGIN\n{command}\nCOMMAND_END\n" in request


def test_publish_replaces_observed_card_with_same_handle(
    root_review: RootReviewFixture,
) -> None:
    first = root_review.store.publish(purpose="First", command="/usr/bin/true")
    with root_review.transcript.open("ab") as stream:
        stream.write(b"first complete\n")

    second = root_review.store.publish(
        purpose="Second",
        command="/usr/bin/false",
        previous_handle=first["handle"],
    )
    assert second["handle"] != first["handle"]
    assert "# 목적: Second" in root_review.request.read_text(encoding="utf-8")


def test_old_handle_cannot_clear_republished_identical_card(
    root_review: RootReviewFixture,
) -> None:
    first = root_review.store.publish(purpose="Same", command="/usr/bin/true")
    with root_review.transcript.open("ab") as stream:
        stream.write(b"first complete\n")
    root_review.store.resolve(raw_handle=first["handle"])

    second = root_review.store.publish(purpose="Same", command="/usr/bin/true")
    assert second["request_sha256"] != first["request_sha256"]
    with pytest.raises(RootReviewError, match="stale_or_mismatched"):
        root_review.store.resolve(raw_handle=first["handle"])
    assert "command=/usr/bin/true" in root_review.request.read_text(encoding="utf-8")


def test_publish_refuses_to_overwrite_pending_card(
    root_review: RootReviewFixture,
) -> None:
    root_review.store.publish(purpose="First", command="/usr/bin/true")
    with pytest.raises(RootReviewError, match="pending_card_exists"):
        root_review.store.publish(purpose="Second", command="/usr/bin/false")


def test_resolve_rejects_unchanged_transcript(root_review: RootReviewFixture) -> None:
    published = root_review.store.publish(purpose="Read", command="/usr/bin/true")
    with pytest.raises(RootReviewError, match="transcript_unchanged"):
        root_review.store.resolve(raw_handle=published["handle"])


def test_stale_handle_rejects_changed_request(root_review: RootReviewFixture) -> None:
    published = root_review.store.publish(purpose="Read", command="/usr/bin/true")
    root_review.request.write_text("STATUS=NO_PENDING_ROOT_COMMAND\n", encoding="utf-8")
    with pytest.raises(RootReviewError, match="stale_or_mismatched"):
        root_review.store.wait(
            raw_handle=published["handle"],
            timeout_seconds=0,
            poll_interval_seconds=0.001,
        )


def test_assignment_mismatch_and_irregular_request_fail_closed(
    root_review: RootReviewFixture,
) -> None:
    root_review.store.pane_id = "%99"
    with pytest.raises(RootReviewError, match="assignment_not_unique"):
        root_review.store.publish(purpose="Read", command="/usr/bin/true")

    root_review.store.pane_id = root_review.pane
    root_review.request.unlink()
    root_review.request.mkdir()
    with pytest.raises(RootReviewError, match="file_identity_unsafe"):
        root_review.store.publish(purpose="Read", command="/usr/bin/true")


@pytest.mark.parametrize(
    "field,value", [("purpose", "bad\nline"), ("command", "bad\targ")]
)
def test_publish_rejects_invalid_control_input(
    root_review: RootReviewFixture, field: str, value: str
) -> None:
    arguments = {"purpose": "Read", "command": "/usr/bin/true"}
    arguments[field] = value
    with pytest.raises(RootReviewError, match=f"root_review_{field}_invalid"):
        root_review.store.publish(**arguments)


@pytest.mark.parametrize(
    "command",
    (
        "echo before\nCOMMAND_END\necho after",
        "echo before\nSTATUS=NO_PENDING_ROOT_COMMAND",
        "echo before\ncommand=/usr/bin/false",
        "echo before\nPURPOSE=hidden",
        "echo before\n# 목적: hidden",
    ),
)
def test_publish_rejects_viewer_grammar_injection(
    root_review: RootReviewFixture, command: str
) -> None:
    with pytest.raises(RootReviewError, match="root_review_command_invalid"):
        root_review.store.publish(purpose="Read", command=command)


def test_root_review_module_has_no_execution_or_root_control_dependency() -> None:
    source = (
        Path(__file__).parents[1] / "opsctl" / "agent_runtime_ops" / "root_review.py"
    ).read_text(encoding="utf-8")
    assert "import subprocess" not in source
    assert "import socket" not in source
    assert "tmux send-keys" not in source
    assert "/run/codex-root-review/control" not in source


@pytest.mark.skipif(os.name != "posix", reason="POSIX account identity contract")
def test_current_uses_account_primary_gid_not_effective_gid(monkeypatch) -> None:
    import pwd

    uid = os.getuid()
    primary_gid = pwd.getpwuid(uid).pw_gid
    monkeypatch.setattr(os, "getgid", lambda: primary_gid + 1)
    monkeypatch.setenv("TMUX_PANE", "%42")

    store = RootReviewStore.current()

    assert store.agent_uid == uid
    assert store.agent_gid == primary_gid
