from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import server


LANE = "1" * 32
OTHER = "2" * 32
A = "a" * 40
B = "b" * 40
C = "c" * 40


class FindingFreshnessTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        state = self.root / "state"
        state.mkdir(mode=0o700)
        for name, value in (
            ("STATE_ROOT", state),
            ("FINDINGS_ROOT", state / "findings"),
            ("INBOX_ROOT", state / "worktree-inboxes"),
            ("_FINDING_INDEX", None),
        ):
            self._patch(name, value)
        server._ensure_state()
        self.current = {"checkpoint": A}
        self._patch("_read_work_target", lambda lane: {
            "lane_id": lane,
            "checkpoint": self.current["checkpoint"],
            "repository": "fixture",
            "worktree": str(self.root / "worktree"),
            "branch": "fixture",
        })

    def _patch(self, name: str, value: object) -> None:
        item = patch.object(server, name, value)
        item.start()
        self.addCleanup(item.stop)

    def _record(
        self, index: int, *, checkpoint: str = A, target: str = LANE,
        recheck_of: str | None = None, conclusion: str | None = None,
    ) -> str:
        finding_id = f"ga-20261106T070000Z-{index:012x}"
        payload = {
            "schema_version": 2,
            "finding_contract": server.FINDING_CONTRACT,
            "finding_id": finding_id,
            "adler_identity": server.IDENTITY,
            "kind": "risk",
            "severity": "high",
            "confidence": 0.99,
            "subject": f"lane:{target}",
            "target_lane_id": target,
            "checkpoint": checkpoint,
            "binding_strength": "exact",
            "summary": "fixture",
            "evidence_refs": ["fixture:test_finding_freshness.py"],
            "observed_at": f"2026-11-06T07:00:{index:02d}+00:00",
            "effect_contract": "advisory_only_no_automatic_action",
        }
        if recheck_of is not None:
            payload["recheck_of"] = recheck_of
            payload["conclusion"] = conclusion
        server._persist_finding(payload)
        return finding_id

    def test_checkpoint_changes_reopen_uncertainty_not_automatically_fix(self) -> None:
        root = self._record(1)
        self._record(2, target=OTHER)
        before = server.assess_lane_findings(LANE)
        self.assertEqual(before["total_root_finding_count"], 1)
        self.assertEqual(before["counts"]["observed_at_checkpoint"], 1)
        self.assertTrue(before["source_complete"])
        root_path = server.FINDINGS_ROOT / f"{root}.json"
        original = root_path.read_bytes()

        self.current["checkpoint"] = B
        changed = server.assess_lane_findings(LANE)
        self.assertEqual(changed["counts"]["recheck_required"], 1)
        self.assertEqual(changed["counts"]["resolved_at_checkpoint"], 0)

        resolved = self._record(
            3, checkpoint=B, recheck_of=root, conclusion="no_longer_reproduced",
        )
        result = server.assess_lane_findings(LANE)
        self.assertEqual(result["counts"]["resolved_at_checkpoint"], 1)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["resolved_finding_ids"], [root])
        self.assertEqual(result["total_open_finding_count"], 0)

        self.current["checkpoint"] = C
        self.assertEqual(server.assess_lane_findings(LANE)["counts"]["recheck_required"], 1)
        self._record(4, checkpoint=C, recheck_of=root, conclusion="still_current")
        self.assertEqual(
            server.assess_lane_findings(LANE)["counts"]["still_current_at_checkpoint"], 1,
        )
        self.assertEqual(root_path.read_bytes(), original)
        self.assertEqual(len(server.list_findings(limit=10)["findings"]), 4)

    def test_corrupt_history_reports_incompleteness(self) -> None:
        root = self._record(1)
        self._record(3, recheck_of=root, conclusion="no_longer_reproduced")
        corrupt = server.FINDINGS_ROOT / "ga-20261106T070000Z-000000000099.json"
        corrupt.write_text("{not-json", encoding="utf-8")
        result = server.assess_lane_findings(LANE)
        self.assertFalse(result["source_complete"])
        self.assertEqual(result["source_error_count"], 1)
        self.assertEqual(result["total_root_finding_count"], 1)
        self.assertEqual(result["total_open_finding_count"], 1)
        self.assertEqual(result["resolved_finding_ids"], [])
        self.assertEqual(result["findings"][0]["state"], "resolved_at_checkpoint")

    def test_head_race_never_returns_stale_projection(self) -> None:
        self._record(1)
        targets = [
            {"lane_id": LANE, "checkpoint": ck, "repository": "fixture",
             "worktree": str(self.root), "branch": "fixture"}
            for ck in (A, B)
        ]
        with patch.object(server, "_read_work_target", side_effect=targets):
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                server.assess_lane_findings(LANE)

    def test_limit_validation(self) -> None:
        for value in (0, 51, True, "10"):
            with self.assertRaisesRegex(ValueError, "limit"):
                server.assess_lane_findings(LANE, limit=value)


if __name__ == "__main__":
    unittest.main()
