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
    server._ensure_state()
    return state


def _install_pointer(worktree: Path, state: Path, lane_id: str) -> Path:
    worktree.mkdir(parents=True, exist_ok=True)
    sidecar = worktree / ".adler"
    sidecar.mkdir(mode=0o700)
    gitignore = sidecar / ".gitignore"
    gitignore.write_bytes(b"*\n")
    gitignore.chmod(0o600)
    target = state / "worktree-inboxes" / f"{lane_id}.json"
    (sidecar / "inbox.json").symlink_to(target)
    return target


def _target(worktree: Path, lane_id: str) -> dict:
    return {
        "lane_id": lane_id,
        "repository": "fixture",
        "worktree": str(worktree),
        "branch": "feature/finding-store-bounds",
        "purpose": "fixture",
        "base_head": OID_B,
        "checkpoint": OID_A,
        "source": "fixture",
        "observed_at": "fixture",
    }


def _finding_args(lane_id: str, **overrides) -> dict:
    data = {
        "kind": "risk",
        "severity": "medium",
        "confidence": 0.9,
        "subject": f"lane:{lane_id}",
        "checkpoint": OID_A,
        "binding_strength": "exact",
        "summary": "fixture finding",
        "evidence_refs": ["fixture:test_finding_store_bounds.py"],
    }
    data.update(overrides)
    return data


def _persist_fixture_record(
    *,
    finding_id: str,
    subject: str,
    summary: str = "fixture history",
) -> None:
    server._persist_finding(
        {
            "schema_version": 1,
            "finding_contract": server.FINDING_CONTRACT,
            "finding_id": finding_id,
            "adler_identity": server.IDENTITY,
            "kind": "observation",
            "severity": "low",
            "confidence": 1.0,
            "subject": subject,
            "checkpoint": OID_A,
            "binding_strength": "exact",
            "summary": summary,
            "evidence_refs": ["fixture:history"],
            "observed_at": "2026-09-19T13:00:00+00:00",
            "effect_contract": "advisory_only_no_automatic_action",
        }
    )


def test_same_checkpoint_hot_submit_does_not_rescan_unrelated_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "1" * 32
    target = _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(
        server, "_read_work_target", lambda lane: _target(worktree, lane)
    )

    for index in range(200):
        _persist_fixture_record(
            finding_id=f"ga-20260919T130000Z-{index:012x}",
            subject=f"repo:unrelated-{index}",
        )

    real_loader = server._load_finding_payloads
    scans = 0

    def counted_loader(names=None):
        nonlocal scans
        scans += 1
        return real_loader(names)

    monkeypatch.setattr(server, "_load_finding_payloads", counted_loader)
    first = server.submit_finding(**_finding_args(lane_id))
    assert first["delivery"]["state"] == "published"
    assert first["delivery"]["source_scan_mode"] == "full-history-scan"
    assert scans == 1

    scans = 0
    second = server.submit_finding(
        **_finding_args(lane_id, summary="second same-checkpoint finding")
    )
    assert second["delivery"]["state"] == "published"
    assert second["delivery"]["source_scan_mode"] == "incremental-memory-index"
    assert second["delivery"]["source_complete"] is False
    assert second["delivery"]["source_rescan_required"] is True
    assert scans == 0

    inbox = json.loads(target.read_text(encoding="utf-8"))
    assert inbox["source_scan_mode"] == "incremental-memory-index"
    assert inbox["total_current_finding_count"] == 2
    assert inbox["finding_count"] == 2


def test_oversized_current_view_is_compacted_not_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "2" * 32
    target = _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(
        server, "_read_work_target", lambda lane: _target(worktree, lane)
    )

    for index in range(12):
        _persist_fixture_record(
            finding_id=f"ga-20260919T131000Z-{index:012x}",
            subject=f"lane:{lane_id}",
            summary=("x" * 3000) + str(index),
        )

    monkeypatch.setattr(server, "MAX_OUTPUT_BYTES", 8000)
    result = server.publish_worktree_inbox(lane_id)
    assert result["state"] == "published"
    assert result["projection_complete"] is False
    assert result["total_current_finding_count"] == 12
    assert 0 < result["finding_count"] < 12
    assert result["omitted_finding_count"] == 12 - result["finding_count"]
    assert target.stat().st_size <= 8000

    inbox = json.loads(target.read_text(encoding="utf-8"))
    assert inbox["projection_complete"] is False
    assert inbox["omission_reason"] == "bounded_current_view"
    assert inbox["omitted_identity_complete"] is False


def test_corrupt_history_is_visible_without_globally_blocking_lane_inbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "3" * 32
    target = _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(
        server, "_read_work_target", lambda lane: _target(worktree, lane)
    )

    bad = state / "findings" / "broken.json"
    bad.write_text("{broken", encoding="utf-8")
    bad.chmod(0o600)

    submitted = server.submit_finding(**_finding_args(lane_id))
    assert submitted["delivery"]["state"] == "published"
    assert submitted["delivery"]["source_complete"] is False
    assert submitted["delivery"]["quarantined_record_count"] == 1

    inbox = json.loads(target.read_text(encoding="utf-8"))
    assert inbox["source_complete"] is False
    assert inbox["finding_count"] == 1
    assert inbox["quarantined_record_count"] == 1
    assert inbox["quarantined_records"][0]["record"] == "broken.json"

    listing = server.list_findings(limit=10)
    assert listing["source_complete"] is False
    assert listing["store_health"]["quarantined_record_count"] == 1
    assert listing["store_health"]["history_mutation_model"] == "immutable_append_only"

def test_tampered_current_view_never_defines_incremental_membership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "4" * 32
    target = _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(
        server, "_read_work_target", lambda lane: _target(worktree, lane)
    )

    first = server.submit_finding(**_finding_args(lane_id))
    assert first["delivery"]["source_scan_mode"] == "full-history-scan"
    cached = json.loads(target.read_text(encoding="utf-8"))
    cached["findings"] = []
    cached["finding_count"] = 0
    cached["total_current_finding_count"] = 0
    cached["projection_complete"] = True
    cached["omitted_finding_count"] = 0
    cached["omission_reason"] = None
    cached["omitted_identity_complete"] = True
    core = dict(cached)
    core.pop("projection_sha256", None)
    cached["projection_sha256"] = server._sha256_json(core)
    target.write_text(
        json.dumps(cached, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    target.chmod(0o600)

    real_loader = server._load_finding_payloads
    scans = 0

    def counted_loader(names=None):
        nonlocal scans
        scans += 1
        return real_loader(names)

    monkeypatch.setattr(server, "_load_finding_payloads", counted_loader)
    second = server.submit_finding(
        **_finding_args(lane_id, summary="canonical second finding")
    )
    assert second["delivery"]["state"] == "published"
    assert second["delivery"]["source_scan_mode"] == "incremental-memory-index"
    assert scans == 0
    repaired = json.loads(target.read_text(encoding="utf-8"))
    assert repaired["source_complete"] is False
    assert repaired["source_rescan_required"] is True
    assert {item["summary"] for item in repaired["findings"]} == {
        "fixture finding",
        "canonical second finding",
    }


def test_invalid_recheck_is_quarantined_and_excluded_from_lane_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "5" * 32
    target = _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(
        server, "_read_work_target", lambda lane: _target(worktree, lane)
    )

    root_id = "ga-20260919T132000Z-000000000001"
    _persist_fixture_record(
        finding_id=root_id,
        subject=f"lane:{lane_id}",
        summary="valid root",
    )
    server._persist_finding(
        {
            "schema_version": 1,
            "finding_contract": server.FINDING_CONTRACT,
            "finding_id": "ga-20260919T132001Z-000000000002",
            "adler_identity": server.IDENTITY,
            "kind": "risk",
            "severity": "critical",
            "confidence": 1.0,
            "subject": f"lane:{lane_id}",
            "checkpoint": OID_A,
            "binding_strength": "exact",
            "summary": "orphan recheck must not project",
            "evidence_refs": ["fixture:orphan"],
            "observed_at": "2026-09-19T13:20:01+00:00",
            "effect_contract": "advisory_only_no_automatic_action",
            "recheck_of": "ga-20260919T132000Z-ffffffffffff",
            "conclusion": "still_current",
        }
    )

    result = server.publish_worktree_inbox(lane_id)
    assert result["state"] == "published"
    assert result["source_complete"] is False
    assert result["quarantined_record_count"] == 1
    inbox = json.loads(target.read_text(encoding="utf-8"))
    assert [item["finding_id"] for item in inbox["findings"]] == [root_id]
    assert inbox["quarantined_records"] == [
        {
            "record": "ga-20260919T132001Z-000000000002.json",
            "error_type": "RuntimeError",
        }
    ]

def test_history_ahead_of_projection_forces_full_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "6" * 32
    target = _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(
        server, "_read_work_target", lambda lane: _target(worktree, lane)
    )

    first = server.submit_finding(**_finding_args(lane_id))
    assert first["delivery"]["source_scan_mode"] == "full-history-scan"

    missed_id = "ga-20260919T133000Z-000000000006"
    _persist_fixture_record(
        finding_id=missed_id,
        subject=f"lane:{lane_id}",
        summary="persisted while inbox delivery was missed",
    )

    real_loader = server._load_finding_payloads
    scans = 0

    def counted_loader(names=None):
        nonlocal scans
        scans += 1
        return real_loader(names)

    monkeypatch.setattr(server, "_load_finding_payloads", counted_loader)
    third = server.submit_finding(
        **_finding_args(lane_id, summary="third finding")
    )
    assert third["delivery"]["state"] == "published"
    assert third["delivery"]["source_scan_mode"] == "full-history-scan"
    assert scans == 1
    inbox = json.loads(target.read_text(encoding="utf-8"))
    ids = [item["finding_id"] for item in inbox["findings"]]
    assert len(ids) == 3
    assert len(ids) == len(set(ids))
    assert missed_id in ids


def test_corrupt_existing_inbox_is_rebuilt_from_canonical_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "7" * 32
    target = _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(
        server, "_read_work_target", lambda lane: _target(worktree, lane)
    )

    first = server.submit_finding(**_finding_args(lane_id))
    assert first["delivery"]["state"] == "published"
    target.write_bytes(b"{broken")
    target.chmod(0o600)

    monkeypatch.setattr(server, "_FINDING_INDEX", None)
    second = server.submit_finding(
        **_finding_args(lane_id, summary="second after corrupt inbox")
    )
    assert second["delivery"]["state"] == "published"
    assert second["delivery"]["source_scan_mode"] == "full-history-scan"
    rebuilt = json.loads(target.read_text(encoding="utf-8"))
    assert rebuilt["writer_identity"] == server.IDENTITY
    assert rebuilt["projection_complete"] is True
    assert {item["summary"] for item in rebuilt["findings"]} == {
        "fixture finding",
        "second after corrupt inbox",
    }

def test_hidden_json_record_is_in_watermark_and_quarantine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "8" * 32
    target = _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(
        server, "_read_work_target", lambda lane: _target(worktree, lane)
    )

    hidden = state / "findings" / ".hidden.json"
    hidden.write_text("{broken", encoding="utf-8")
    hidden.chmod(0o600)

    result = server.publish_worktree_inbox(lane_id)
    assert result["state"] == "published"
    assert result["source_complete"] is False
    inbox = json.loads(target.read_text(encoding="utf-8"))
    assert inbox["store_record_name_count"] == 1
    assert inbox["quarantined_record_count"] == 1
    assert inbox["quarantined_records"] == [
        {"record": ".hidden.json", "error_type": "RuntimeError"}
    ]
    assert inbox["source_complete"] is False


def test_append_during_increment_validation_forces_full_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "9" * 32
    target = _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(
        server, "_read_work_target", lambda lane: _target(worktree, lane)
    )

    first = server.submit_finding(**_finding_args(lane_id))
    assert first["delivery"]["source_scan_mode"] == "full-history-scan"
    prior_names = {
        path.name for path in (state / "findings").iterdir() if path.name.endswith(".json")
    }

    concurrent_id = "ga-20260919T134000Z-000000000009"
    concurrent_core = {
        "schema_version": 1,
        "finding_contract": server.FINDING_CONTRACT,
        "finding_id": concurrent_id,
        "adler_identity": server.IDENTITY,
        "kind": "observation",
        "severity": "low",
        "confidence": 1.0,
        "subject": f"lane:{lane_id}",
        "checkpoint": OID_A,
        "binding_strength": "exact",
        "summary": "concurrent append during incremental validation",
        "evidence_refs": ["fixture:concurrent"],
        "observed_at": "2026-09-19T13:40:00+00:00",
        "effect_contract": "advisory_only_no_automatic_action",
    }
    concurrent_payload = dict(concurrent_core)
    concurrent_payload["finding_sha256"] = server._sha256_json(concurrent_core)
    concurrent_path = state / "findings" / f"{concurrent_id}.json"

    real_read = server._read_json_file_no_symlink
    injected = False

    def injecting_read(path: Path):
        nonlocal injected
        payload = real_read(path)
        if (
            not injected
            and path.parent == state / "findings"
            and path.name not in prior_names
            and path.name != concurrent_path.name
        ):
            concurrent_path.write_text(
                json.dumps(
                    concurrent_payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            concurrent_path.chmod(0o600)
            injected = True
        return payload

    monkeypatch.setattr(server, "_read_json_file_no_symlink", injecting_read)
    real_loader = server._load_finding_payloads
    scans = 0

    def counted_loader(names=None):
        nonlocal scans
        scans += 1
        return real_loader(names)

    monkeypatch.setattr(server, "_load_finding_payloads", counted_loader)
    second = server.submit_finding(
        **_finding_args(lane_id, summary="second finding around concurrent append")
    )
    assert injected is True
    assert second["delivery"]["state"] == "published"
    assert second["delivery"]["source_scan_mode"] == "full-history-scan"
    assert scans == 1

    inbox = json.loads(target.read_text(encoding="utf-8"))
    ids = [item["finding_id"] for item in inbox["findings"]]
    assert concurrent_id in ids
    assert len(ids) == 3
    assert len(ids) == len(set(ids))
    assert inbox["source_complete"] is True
