"""한 슬롯에 여러 소스 뷰 — 카카오 경로 불변 + 그룹웨어 나란히.

배경: 뷰 상태가 슬롯 키 dict 라 슬롯당 뷰가 하나뿐이었고, 그래서 "사람이 슬롯에 오면
그 사람 것 전부가 보인다"가 아래층에서 불가능했다. 코퍼스별 경로/레코드로 그 벽을 연다.

가장 중요한 불변식: **카카오(PRIMARY)의 경로는 한 바이트도 변하지 않는다** — 고객
슬롯 14곳에 이미 마운트돼 있고, 진입점 /home/{slot}/nas_docs/kw 는 고객이 보는 경로다.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from agent_runtime_ops.domain.nas_views import (
    PRIMARY_CORPUS,
    corpus_for_share,
    drop_view_record,
    get_view_record,
    hidden_master,
    iter_view_records,
    put_view_record,
    slot_entry,
    view_root,
)


class PrimaryPathsUnchangedTest(unittest.TestCase):
    """회귀 잠금: 카카오 경로가 바뀌면 라이브 슬롯이 깨진다."""

    def test_kakao_paths_are_byte_identical_to_before(self):
        self.assertEqual(hidden_master("oc3"), Path("/srv/kw-nas/slots/oc3/master"))
        self.assertEqual(view_root("oc3"), Path("/srv/kw-nas/slots/oc3/view"))
        self.assertEqual(slot_entry("oc3"), Path("/home/oc3/nas_docs/kw"))

    def test_default_corpus_is_kakao(self):
        self.assertEqual(hidden_master("oc3", PRIMARY_CORPUS), hidden_master("oc3"))


class CorpusPathsTest(unittest.TestCase):
    def test_groupware_gets_sibling_paths(self):
        self.assertEqual(hidden_master("oc3", "groupware"), Path("/srv/kw-nas/slots/oc3/groupware/master"))
        self.assertEqual(view_root("oc3", "groupware"), Path("/srv/kw-nas/slots/oc3/groupware/view"))
        self.assertEqual(slot_entry("oc3", "groupware"), Path("/home/oc3/nas_docs/groupware"))

    def test_share_resolves_to_corpus(self):
        self.assertEqual(corpus_for_share("//10.10.10.2/kakao-work").name, "kakao")
        spec = corpus_for_share("//10.10.10.2/hanpass_groupware")
        self.assertEqual((spec.name, spec.layout, spec.person_root), ("groupware", "person_dir", "groupware/mails"))

    def test_unknown_share_is_refused_not_defaulted(self):
        # 조용히 카카오 레이아웃으로 흘러 엉뚱한 폴더를 여는 것보다 안 붙는 편이 안전하다.
        with self.assertRaises(ValueError):
            corpus_for_share("//10.10.10.2/some-new-share")


class ViewRecordsTest(unittest.TestCase):
    def test_two_sources_live_on_one_slot(self):
        views = {"views": {}, "corpus_views": {}}
        put_view_record(views, "oc3", "kakao", {"user_id": "7362168", "share": "//h/kakao-work"})
        put_view_record(views, "oc3", "groupware", {"user_id": "bkkim", "share": "//h/hanpass_groupware"})
        records = list(iter_view_records(views))
        self.assertEqual(len(records), 2)
        self.assertEqual({c for _s, c, _r in records}, {"kakao", "groupware"})
        # 카카오는 기존 스키마 자리에 그대로 — 구 opsctl 이 읽어도 보인다.
        self.assertEqual(views["views"]["oc3"]["user_id"], "7362168")

    def test_detaching_one_source_leaves_the_other(self):
        views = {"views": {}, "corpus_views": {}}
        put_view_record(views, "oc3", "kakao", {"user_id": "7362168"})
        put_view_record(views, "oc3", "groupware", {"user_id": "bkkim"})
        self.assertTrue(drop_view_record(views, "oc3", "groupware"))
        self.assertIsNone(get_view_record(views, "oc3", "groupware"))
        self.assertIsNotNone(get_view_record(views, "oc3", "kakao"))
        self.assertNotIn("oc3", views["corpus_views"])  # 빈 껍데기 안 남긴다


if __name__ == "__main__":
    unittest.main()
