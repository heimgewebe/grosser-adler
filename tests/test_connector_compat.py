from __future__ import annotations

import json
from pathlib import Path

import pytest

import server


OID_A = "a" * 40
OID_B = "b" * 40


def _configure_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setattr(server, "STATE_ROOT", state)
    monkeypatch.setattr(server, "FINDINGS_ROOT", state / "findings")
    monkeypatch.setattr(server, "INBOX_ROOT", state / "worktree-inboxes")
    monkeypatch.setattr(server, "WORKTREE_ROOT", tmp_path.resolve())
    return state


def _install_pointer(worktree: Path, state: Path, lane_id: str) -> Path:
    worktree.mkdir(parents=True, exist_ok=True)
    sidecar = worktree / ".adler"
    sidecar.mkdir(mode=0o700)
    (sidecar / ".gitignore").write_text("*\n", encoding="utf-8")
    (sidecar / ".gitignore").chmod(0o600)
    target = state / "worktree-inboxes" / f"{lane_id}.json"
    (sidecar / "inbox.json").symlink_to(target)
    return target


def _target(worktree: Path, lane_id: str) -> dict:
    return {
        "lane_id": lane_id,
        "repository": "fixture",
        "worktree": str(worktree),
        "branch": "feature/compat",
        "purpose": "fixture",
        "base_head": OID_B,
        "checkpoint": OID_A,
        "source": "fixture",
        "observed_at": "fixture",
    }


def test_legacy_connector_record_does_not_invent_v1_confidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    result = server.submit_finding_legacy(
        subject_kind="repo",
        subject="repo:fixture",
        severity="medium",
        summary="legacy connector observation",
        evidence_refs=["fixture:legacy"],
    )
    assert result["accepted"] is True
    assert result["legacy"] is True
    payload = json.loads(
        (state / "findings" / f"{result['finding_id']}.json").read_text(encoding="utf-8")
    )
    assert payload["schema_version"] == 1
    assert payload["status"] == "finding"
    assert "finding_contract" not in payload
    assert "confidence" not in payload
    assert "binding_strength" not in payload

    listed = server.list_findings(limit=1)["findings"][0]
    assert listed["legacy"] is True
    assert listed["confidence"] is None
    assert listed["binding_strength"] == "legacy-unbound"


def test_legacy_lane_submission_resolves_current_checkpoint_and_publishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "a" * 32
    inbox_path = _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(server, "_read_work_target", lambda lane: _target(worktree, lane))

    result = server.submit_finding_legacy(
        subject_kind="grabowski_lane",
        subject=lane_id,
        severity="high",
        status="recheck_suggested",
        summary="verify the separately imported helper",
        evidence_refs=["fixture:runner-import"],
    )
    assert result["delivery"]["state"] == "published"
    inbox = json.loads(inbox_path.read_text(encoding="utf-8"))
    assert inbox["checkpoint"] == OID_A
    assert len(inbox["findings"]) == 1
    finding = inbox["findings"][0]
    assert finding["legacy"] is True
    assert finding["subject"] == f"lane:{lane_id}"
    assert finding["checkpoint"] == OID_A
    assert finding["status"] == "recheck_suggested"
    assert finding["confidence"] is None
    assert finding["binding_strength"] == "legacy-unbound"


def test_legacy_lane_submission_rejects_stale_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "b" * 32
    _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(server, "_read_work_target", lambda lane: _target(worktree, lane))

    with pytest.raises(ValueError, match="does not match the current worktree checkpoint"):
        server.submit_finding_legacy(
            subject_kind="grabowski_lane",
            subject=f"lane:{lane_id}",
            checkpoint=OID_B,
            severity="medium",
            summary="stale fixture",
            evidence_refs=["fixture:stale"],
        )
    assert not (state / "findings").exists() or list((state / "findings").glob("*.json")) == []


def test_strict_v1_entry_remains_available_as_python_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    result = server.submit_finding(
        kind="observation",
        severity="low",
        confidence=0.8,
        subject="repo:fixture",
        checkpoint=OID_A,
        binding_strength="strong",
        summary="strict V1 remains unchanged",
        evidence_refs=["fixture:v1"],
    )
    payload = json.loads(
        (state / "findings" / f"{result['finding_id']}.json").read_text(encoding="utf-8")
    )
    assert payload["finding_contract"] == server.FINDING_CONTRACT
    assert payload["confidence"] == 0.8
    assert payload["binding_strength"] == "strong"
