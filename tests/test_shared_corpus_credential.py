from __future__ import annotations

import unittest

from agent_runtime_ops.nas import canonical_shared_credential_path, parse_smb_share


KAKAO = parse_smb_share("//10.10.10.2/kakao-work")
OTHER = parse_smb_share("//10.10.10.2/some-rw-share")


class SharedCorpusCredentialTest(unittest.TestCase):
    def test_exact_share_maps_to_shared_cred(self) -> None:
        # 결론: kakao 코퍼스는 ONE 공유 ro_kakao.cred (슬롯별 복사 아님).
        policy = {"corpus_credentials": {"//10.10.10.2/kakao-work": "/etc/samba/credentials/ro_kakao.cred"}}
        got = canonical_shared_credential_path(KAKAO, policy)
        self.assertIsNotNone(got)
        self.assertEqual(str(got), "/etc/samba/credentials/ro_kakao.cred")

    def test_wildcard_pattern_matches(self) -> None:
        policy = {"corpus_credentials": {"//10.10.10.2/kakao-work": "/etc/samba/credentials/ro_kakao.cred"}}
        # 정확 일치만 매핑 — 다른 share 는 안 잡힌다(오배정 방지).
        self.assertIsNone(canonical_shared_credential_path(OTHER, policy))

    def test_no_mapping_is_none(self) -> None:
        # 선언 없으면 조용히 None → assign 은 종전대로 fail-closed (몰래 아무 cred 안 씀).
        self.assertIsNone(canonical_shared_credential_path(KAKAO, {}))
        self.assertIsNone(canonical_shared_credential_path(KAKAO, {"corpus_credentials": {}}))

    def test_empty_cred_value_ignored(self) -> None:
        policy = {"corpus_credentials": {"//10.10.10.2/kakao-work": ""}}
        self.assertIsNone(canonical_shared_credential_path(KAKAO, policy))

    def test_malformed_mapping_is_none(self) -> None:
        self.assertIsNone(canonical_shared_credential_path(KAKAO, {"corpus_credentials": "not-a-dict"}))


if __name__ == "__main__":
    unittest.main()
