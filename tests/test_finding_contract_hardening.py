from __future__ import annotations

import json
from pathlib import Path

import pytest

import server


FINDING_ID = "ga-20260916T000000Z-aaaaaaaaaaaa"
CHECKPOINT = "a" * 40


def _configure_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setattr(server, "STATE_ROOT", state)
    monkeypatch.setattr(server, "FINDINGS_ROOT", state / "findings")
    monkeypatch.setattr(server, "INBOX_ROOT", state / "worktree-inboxes")
    server._ensure_state()
    return state


def _v1_payload(**overrides):
    payload = {
        "schema_version": 1,
        "finding_contract": server.FINDING_CONTRACT,
        "finding_id": FINDING_ID,
        "adler_identity": server.IDENTITY,
        "kind": "risk",
        "severity": "medium",
        "confidence": 0.9,
        "subject": "repo:fixture",
        "checkpoint": CHECKPOINT,
        "binding_strength": "exact",
        "summary": "fixture",
        "evidence_refs": ["fixture:test"],
        "observed_at": "2026-09-16T00:00:00Z",
        "effect_contract": "advisory_only_no_automatic_action",
    }
    payload.update(overrides)
    payload["finding_sha256"] = server._sha256_json(payload)
    return payload


def _write_payload(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _finding_args(**overrides):
    data = {
        "kind": "risk",
        "severity": "medium",
        "confidence": 0.9,
        "subject": "repo:fixture",
        "checkpoint": CHECKPOINT,
        "binding_strength": "exact",
        "summary": "fixture",
        "evidence_refs": ["fixture:test"],
    }
    data.update(overrides)
    return data


def test_missing_v1_contract_is_not_silently_treated_as_legacy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    path = state / "findings" / f"{FINDING_ID}.json"
    payload = _v1_payload()
    payload.pop("finding_contract")
    payload.pop("finding_sha256")
    payload["finding_sha256"] = server._sha256_json(payload)
    _write_payload(path, payload)

    listing = server.list_findings(limit=10)
    assert listing["source_complete"] is False
    assert listing["source_error_count"] == 1
    assert listing["findings"] == []


@pytest.mark.parametrize("schema_version", [1, 2, 3])
def test_explicit_historical_legacy_records_remain_readable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, schema_version: int
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    finding_id = f"ga-20260916T00000{schema_version}Z-{schema_version:012x}"
    legacy = {
        "schema_version": schema_version,
        "finding_id": finding_id,
        "adler_identity": server.IDENTITY,
        "subject_kind": "work",
        "subject": "legacy-subject",
        "checkpoint": "legacy-checkpoint",
        "severity": "medium",
        "status": "advice",
        "summary": "legacy",
        "evidence_refs": ["fixture:legacy"],
        "observed_at": "2026-09-16T00:00:00Z",
        "effect_contract": "advisory_only_no_automatic_action",
    }
    _write_payload(state / "findings" / f"{finding_id}.json", legacy)

    listing = server.list_findings(limit=10)
    assert listing["source_complete"] is True
    assert listing["count"] == 1
    assert listing["findings"][0]["legacy"] is True
    assert listing["findings"][0]["kind"] == "advice"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("adler_identity", "other-observer"),
        ("effect_contract", "automatic_action_allowed"),
        ("kind", "unknown"),
        ("severity", "urgent"),
        ("binding_strength", "absolute"),
        ("confidence", True),
        ("confidence", 1.1),
    ],
)
def test_v1_schema_and_identity_fields_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    path = state / "findings" / f"{FINDING_ID}.json"
    payload = _v1_payload(**{field: value})
    _write_payload(path, payload)

    with pytest.raises(RuntimeError):
        server._validate_v1_finding_payload(payload, path)
    assert server.list_findings(limit=10)["source_complete"] is False


def test_digest_covers_full_stored_core_including_extra_unicode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    path = state / "findings" / f"{FINDING_ID}.json"
    payload = _v1_payload(extra={"note": "Grüßer Adler 🦅"})
    _write_payload(path, payload)
    server._validate_v1_finding_payload(payload, path)

    payload["extra"]["note"] = "mutated"
    with pytest.raises(RuntimeError, match="digest mismatch"):
        server._validate_v1_finding_payload(payload, path)


def test_recheck_rejects_corrupted_parent_even_with_recomputed_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    root = server.submit_finding(**_finding_args())
    parent_path = state / "findings" / f"{root['finding_id']}.json"
    parent = json.loads(parent_path.read_text(encoding="utf-8"))
    parent["schema_version"] = 2
    parent.pop("finding_sha256")
    parent["finding_sha256"] = server._sha256_json(parent)
    _write_payload(parent_path, parent)

    with pytest.raises(ValueError, match="valid V1 finding"):
        server.submit_finding(
            **_finding_args(
                checkpoint="b" * 40,
                recheck_of=root["finding_id"],
                conclusion="still_current",
            )
        )


def test_persistence_rejects_invalid_runtime_literal_before_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    with pytest.raises(RuntimeError, match="kind is invalid"):
        server.submit_finding(**_finding_args(kind="not-a-kind"))
    assert list((state / "findings").glob("*.json")) == []


def test_write_all_rejects_zero_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server.os, "write", lambda _fd, _data: 0)
    with pytest.raises(OSError, match="made no progress"):
        server._write_all(123, b"payload")
