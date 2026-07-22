import sqlite3
from pathlib import Path

import pytest

from agent_runtime_ops.domain import nas_views
from agent_runtime_ops.nas import NasPolicyDecision, parse_smb_share


def _db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE messages(chat_id TEXT, is_group INTEGER, author TEXT, from_addr TEXT)")
    conn.executemany(
        "INSERT INTO messages VALUES (?,?,?,?)",
        [("room-a@g.us", 1, "person@lid", "room-a@g.us"),
         ("room-b@g.us", 1, "other@lid", "room-b@g.us")],
    )
    conn.commit()
    conn.close()


def test_whatsapp_plan_exposes_only_authored_room(monkeypatch, tmp_path):
    share = "//10.10.10.2/whatsapp"
    monkeypatch.setattr(nas_views, "check_nas_policy", lambda *a: NasPolicyDecision("oc1", parse_smb_share(share), True, "ok", None, None, tmp_path))
    monkeypatch.setattr(nas_views, "VIEWS_ROOT", tmp_path / "slots")
    master = nas_views.hidden_master("oc1", "whatsapp")
    (master / "messages").mkdir(parents=True)
    (master / "media" / "room-a@g.us").mkdir(parents=True)
    (master / "messages" / "room-a@g.us.json").write_text("[]")
    _db(master / "whatsapp.db")
    plan = nas_views.build_view_plan("oc1", "person@lid", share, tmp_path)
    sources = {source.relative_to(master).as_posix() for source, _ in plan.room_binds}
    assert sources == {"messages/room-a@g.us.json", "media/room-a@g.us"}
    assert plan.corpus == "whatsapp"
    assert plan.entry == Path("/home/oc1/nas_docs/whatsapp")


def test_whatsapp_plan_rejects_identity_without_observed_room(monkeypatch, tmp_path):
    share = "//10.10.10.2/whatsapp"
    monkeypatch.setattr(nas_views, "check_nas_policy", lambda *a: NasPolicyDecision("oc1", parse_smb_share(share), True, "ok", None, None, tmp_path))
    monkeypatch.setattr(nas_views, "VIEWS_ROOT", tmp_path / "slots")
    master = nas_views.hidden_master("oc1", "whatsapp")
    master.mkdir(parents=True)
    _db(master / "whatsapp.db")
    with pytest.raises(FileNotFoundError, match="no authored WhatsApp rooms"):
        nas_views.build_view_plan("oc1", "silent@lid", share, tmp_path)
