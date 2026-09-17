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
    assert result["sha256"] == result["record_sha256"]
    payload = json.loads(
        (state / "findings" / f"{result['finding_id']}.json").read_text(encoding="utf-8")
    )
    assert payload["schema_version"] == 1
    assert payload["status"] == "finding"
    assert payload["compatibility_contract"] == server.LEGACY_CONNECTOR_CONTRACT
    assert "finding_contract" not in payload
    assert "confidence" not in payload
    assert "binding_strength" not in payload

    listed = server.list_findings(limit=1)["findings"][0]
    assert listed["legacy"] is True
    assert listed["confidence"] is None
    assert listed["binding_strength"] == "legacy-unbound"


def test_legacy_checkpoint_is_redacted_before_persistence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    secret_checkpoint = "token=compatibility-secret-value"

    result = server.submit_finding_legacy(
        subject_kind="repo",
        subject="repo:fixture",
        checkpoint=secret_checkpoint,
        severity="medium",
        summary="legacy checkpoint redaction fixture",
        evidence_refs=["fixture:checkpoint-redaction"],
    )

    finding_path = state / "findings" / f"{result['finding_id']}.json"
    serialized = finding_path.read_text(encoding="utf-8")
    payload = json.loads(serialized)
    assert secret_checkpoint not in serialized
    assert payload["checkpoint"] == "<REDACTED>"


@pytest.mark.parametrize("checkpoint", [None, ""])
def test_legacy_lane_submission_preserves_blank_checkpoint_without_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, checkpoint: str | None
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "a" * 32
    inbox_path = _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(server, "_read_work_target", lambda lane: _target(worktree, lane))

    result = server.submit_finding_legacy(
        subject_kind="grabowski_lane",
        subject=lane_id,
        checkpoint=checkpoint,
        severity="high",
        status="recheck_suggested",
        summary="preserve the historical checkpoint-free request",
        evidence_refs=["fixture:blank-checkpoint"],
    )
    assert result["accepted"] is True
    assert result["delivery"]["state"] == "not_applicable"
    payload = json.loads(
        (state / "findings" / f"{result['finding_id']}.json").read_text(encoding="utf-8")
    )
    assert payload["subject"] == lane_id
    assert payload["checkpoint"] == checkpoint
    assert not inbox_path.exists()


def test_legacy_lane_submission_with_explicit_checkpoint_publishes_raw_subject(
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
        checkpoint=OID_A,
        severity="high",
        status="recheck_suggested",
        summary="deliver the explicitly checkpoint-bound legacy finding",
        evidence_refs=["fixture:explicit-checkpoint"],
    )
    assert result["delivery"]["state"] == "published"
    inbox = json.loads(inbox_path.read_text(encoding="utf-8"))
    assert inbox["checkpoint"] == OID_A
    assert len(inbox["findings"]) == 1
    finding = inbox["findings"][0]
    assert finding["legacy"] is True
    assert finding["subject"] == lane_id
    assert finding["checkpoint"] == OID_A
    assert finding["status"] == "recheck_suggested"
    assert finding["compatibility_contract"] == server.LEGACY_CONNECTOR_CONTRACT
    assert finding["confidence"] is None
    assert finding["binding_strength"] == "legacy-unbound"


def test_legacy_lane_submission_persists_noncanonical_subject_without_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    subject = "former-human-readable-lane"

    result = server.submit_finding_legacy(
        subject_kind="grabowski_lane",
        subject=subject,
        severity="low",
        summary="preserve historical free-form lane subject",
        evidence_refs=["fixture:noncanonical-lane-subject"],
    )

    assert result["accepted"] is True
    assert result["legacy"] is True
    assert result["delivery"]["state"] == "not_applicable"
    payload = json.loads(
        (state / "findings" / f"{result['finding_id']}.json").read_text(encoding="utf-8")
    )
    assert payload["subject_kind"] == "grabowski_lane"
    assert payload["subject"] == subject
    assert payload["checkpoint"] is None
    assert payload["compatibility_contract"] == server.LEGACY_CONNECTOR_CONTRACT


def test_legacy_lane_submission_redacts_sensitive_subject_and_keeps_it_durable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    sensitive_value = "tok" + "en=" + "fixture-value"
    subject = f"former-lane {sensitive_value}"

    result = server.submit_finding_legacy(
        subject_kind="grabowski_lane",
        subject=subject,
        severity="low",
        summary="preserve historical subject while redacting sensitive material",
        evidence_refs=["fixture:redacted-legacy-subject"],
    )

    assert result["accepted"] is True
    assert result["legacy"] is True
    assert result["delivery"]["state"] == "not_applicable"
    path = state / "findings" / f"{result['finding_id']}.json"
    serialized = path.read_text(encoding="utf-8")
    payload = json.loads(serialized)
    assert payload["subject"] == "former-lane <REDACTED>"
    assert sensitive_value not in serialized
    assert payload["compatibility_contract"] == server.LEGACY_CONNECTOR_CONTRACT

def test_legacy_lane_submission_persists_stale_checkpoint_and_fails_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "b" * 32
    inbox_path = _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(server, "_read_work_target", lambda lane: _target(worktree, lane))

    result = server.submit_finding_legacy(
        subject_kind="grabowski_lane",
        subject=f"lane:{lane_id}",
        checkpoint=OID_B,
        severity="medium",
        summary="stale fixture",
        evidence_refs=["fixture:stale"],
    )

    assert result["accepted"] is True
    assert result["delivery"]["state"] == "delivery_failed"
    assert result["delivery"]["error_type"] == "RuntimeError"
    assert result["delivery"]["finding_remains_durable"] is True
    payload = json.loads(
        (state / "findings" / f"{result['finding_id']}.json").read_text(encoding="utf-8")
    )
    assert payload["checkpoint"] == OID_B
    assert not inbox_path.exists()


def test_legacy_lane_submission_persists_when_lane_cannot_be_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    lane_id = "e" * 32

    def unavailable(_lane: str) -> dict:
        raise RuntimeError("lane unavailable")

    monkeypatch.setattr(server, "_read_work_target", unavailable)

    result = server.submit_finding_legacy(
        subject_kind="grabowski_lane",
        subject=lane_id,
        checkpoint=OID_A,
        severity="medium",
        summary="preserve finding even when delivery target is unavailable",
        evidence_refs=["fixture:unresolved-lane"],
    )
    assert result["accepted"] is True
    assert result["legacy"] is True
    assert result["delivery"]["state"] == "delivery_failed"
    assert result["delivery"]["error_type"] == "RuntimeError"
    assert result["delivery"]["finding_remains_durable"] is True
    payload = json.loads(
        (state / "findings" / f"{result['finding_id']}.json").read_text(encoding="utf-8")
    )
    assert payload["subject"] == lane_id
    assert payload["checkpoint"] == OID_A
    assert payload["compatibility_contract"] == server.LEGACY_CONNECTOR_CONTRACT
    assert "confidence" not in payload
    assert "binding_strength" not in payload


def test_legacy_lane_delivery_fails_closed_if_checkpoint_advances_after_persist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "c" * 32
    inbox_path = _install_pointer(worktree, state, lane_id)
    targets = iter([
        {**_target(worktree, lane_id), "checkpoint": OID_B},
    ])
    monkeypatch.setattr(server, "_read_work_target", lambda lane: next(targets))

    result = server.submit_finding_legacy(
        subject_kind="grabowski_lane",
        subject=lane_id,
        checkpoint=OID_A,
        severity="medium",
        summary="checkpoint race fixture",
        evidence_refs=["fixture:checkpoint-race"],
    )
    assert result["accepted"] is True
    assert result["delivery"]["state"] == "delivery_failed"
    assert result["delivery"]["error_type"] == "RuntimeError"
    assert result["delivery"]["finding_remains_durable"] is True
    payload = json.loads(
        (state / "findings" / f"{result['finding_id']}.json").read_text(encoding="utf-8")
    )
    assert payload["subject"] == lane_id
    assert payload["checkpoint"] == OID_A
    assert not inbox_path.exists()


def test_legacy_lane_delivery_fails_closed_if_checkpoint_advances_after_inbox_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "f" * 32
    inbox_path = _install_pointer(worktree, state, lane_id)
    targets = iter([
        _target(worktree, lane_id),
        _target(worktree, lane_id),
        {**_target(worktree, lane_id), "checkpoint": OID_B},
    ])
    monkeypatch.setattr(server, "_read_work_target", lambda lane: next(targets))

    result = server.submit_finding_legacy(
        subject_kind="grabowski_lane",
        subject=lane_id,
        checkpoint=OID_A,
        severity="medium",
        summary="post-write checkpoint race fixture",
        evidence_refs=["fixture:post-write-checkpoint-race"],
    )

    assert result["accepted"] is True
    assert result["delivery"]["state"] == "delivery_failed"
    assert result["delivery"]["error_type"] == "RuntimeError"
    assert result["delivery"]["finding_remains_durable"] is True
    payload = json.loads(
        (state / "findings" / f"{result['finding_id']}.json").read_text(encoding="utf-8")
    )
    assert payload["checkpoint"] == OID_A
    inbox = json.loads(inbox_path.read_text(encoding="utf-8"))
    assert inbox["checkpoint"] == OID_A


def test_strict_v1_lane_delivery_fails_closed_if_checkpoint_has_advanced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "d" * 32
    inbox_path = _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(
        server,
        "_read_work_target",
        lambda lane: {**_target(worktree, lane), "checkpoint": OID_B},
    )

    result = server.submit_finding(
        kind="risk",
        severity="medium",
        confidence=0.9,
        subject=f"lane:{lane_id}",
        checkpoint=OID_A,
        binding_strength="exact",
        summary="strict V1 checkpoint race fixture",
        evidence_refs=["fixture:v1-checkpoint-race"],
    )
    assert result["accepted"] is True
    assert result["delivery"]["state"] == "delivery_failed"
    assert result["delivery"]["error_type"] == "RuntimeError"
    payload = json.loads(
        (state / "findings" / f"{result['finding_id']}.json").read_text(encoding="utf-8")
    )
    assert payload["checkpoint"] == OID_A
    assert not inbox_path.exists()


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
