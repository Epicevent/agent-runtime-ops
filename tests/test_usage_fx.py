from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_runtime_ops.domain.usage_fx import (
    build_ecb_reference_fx_ledger,
    refresh_ecb_reference_fx,
)
from agent_runtime_ops.domain.usage_ledger import (
    UsageContractError,
    canonical_json_bytes,
)


ECB_FIXTURE = b"""<?xml version="1.0" encoding="UTF-8"?>
<gesmes:Envelope xmlns:gesmes="http://www.gesmes.org/xml/2002-08-01"
 xmlns="http://www.ecb.int/vocabulary/2002-08-01/eurofxref">
  <Cube><Cube time="2026-07-24">
    <Cube currency="USD" rate="1.1377"/>
    <Cube currency="KRW" rate="1662.18"/>
  </Cube></Cube>
</gesmes:Envelope>"""

OLDER_ECB_FIXTURE = ECB_FIXTURE.replace(b"2026-07-24", b"2026-04-01")


class UsageFxTest(unittest.TestCase):
    def test_builds_auditable_usd_krw_cross_rate_from_raw_ecb_values(self) -> None:
        ledger = build_ecb_reference_fx_ledger(
            ECB_FIXTURE,
            revision="2026-07-24.ecb",
            published_at=datetime(2026, 7, 24, 14, 10, tzinfo=timezone.utc),
            retrieved_at=datetime(2026, 7, 24, 14, 10, tzinfo=timezone.utc),
        )
        row = ledger["rates"][0]
        self.assertEqual(row["usdPerEur"], "1.1377")
        self.assertEqual(row["krwPerEur"], "1662.18")
        self.assertEqual(row["krwPerUsd"], "1461.000263689901")
        self.assertRegex(row["source"]["documentSha256"], r"^sha256:[0-9a-f]{64}$")

    def test_rejects_missing_currency_instead_of_inventing_a_rate(self) -> None:
        without_krw = ECB_FIXTURE.replace(b'<Cube currency="KRW" rate="1662.18"/>', b"")
        with self.assertRaisesRegex(UsageContractError, "lacks USD or KRW"):
            build_ecb_reference_fx_ledger(
                without_krw,
                revision="2026-07-24.ecb",
                published_at=datetime.now(timezone.utc),
                retrieved_at=datetime.now(timezone.utc),
            )

    def test_refresh_preserves_raw_evidence_and_atomically_publishes_canonical_ledger(
        self,
    ) -> None:
        observed_at = datetime(2026, 7, 24, 14, 10, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            output = root / "usage-pricing" / "fx-daily.json"
            evidence = root / "usage-pricing" / "evidence"
            with patch(
                "agent_runtime_ops.domain.usage_fx.fetch_ecb_90_day_xml",
                return_value=(ECB_FIXTURE, observed_at),
            ):
                first = refresh_ecb_reference_fx(
                    output_path=output,
                    evidence_dir=evidence,
                )
                second = refresh_ecb_reference_fx(
                    output_path=output,
                    evidence_dir=evidence,
                )
            payload = json.loads(output.read_bytes())
            self.assertEqual(output.read_bytes(), canonical_json_bytes(payload))
            self.assertEqual(Path(first["evidencePath"]).read_bytes(), ECB_FIXTURE)
            self.assertEqual(first["ledgerStatus"], "published")
            self.assertEqual(second["ledgerStatus"], "unchanged")
            self.assertEqual(second["evidenceStatus"], "unchanged")
            self.assertEqual(first["latestRateDate"], "2026-07-24")

    def test_refresh_keeps_rates_that_fall_out_of_the_rolling_ecb_window(self) -> None:
        old_observed_at = datetime(2026, 4, 1, 14, 10, tzinfo=timezone.utc)
        new_observed_at = datetime(2026, 7, 24, 14, 10, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            output = root / "usage-pricing" / "fx-daily.json"
            evidence = root / "usage-pricing" / "evidence"
            with patch(
                "agent_runtime_ops.domain.usage_fx.fetch_ecb_90_day_xml",
                side_effect=[
                    (OLDER_ECB_FIXTURE, old_observed_at),
                    (ECB_FIXTURE, new_observed_at),
                ],
            ):
                refresh_ecb_reference_fx(output_path=output, evidence_dir=evidence)
                refresh_ecb_reference_fx(output_path=output, evidence_dir=evidence)
            payload = json.loads(output.read_bytes())
            self.assertEqual(
                [row["rateDate"] for row in payload["rates"]],
                ["2026-04-01", "2026-07-24"],
            )
            self.assertEqual(output.read_bytes(), canonical_json_bytes(payload))

    def test_refresh_rejects_a_symlinked_existing_ledger(self) -> None:
        observed_at = datetime(2026, 7, 24, 14, 10, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            real_output = root / "real.json"
            real_output.write_bytes(b"{}")
            output = root / "fx-daily.json"
            try:
                output.symlink_to(real_output)
            except OSError:
                self.skipTest("symlink creation is unavailable")
            with patch(
                "agent_runtime_ops.domain.usage_fx.fetch_ecb_90_day_xml",
                return_value=(ECB_FIXTURE, observed_at),
            ):
                with self.assertRaisesRegex(
                    UsageContractError, "target is not a regular file"
                ):
                    refresh_ecb_reference_fx(
                        output_path=output,
                        evidence_dir=root / "evidence",
                    )


if __name__ == "__main__":
    unittest.main()
