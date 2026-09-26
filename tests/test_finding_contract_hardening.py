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
    payload.pop("finding_sha256", None)
    payload["finding_sha256"] = server._sha256_json(payload)
    return payload


def _legacy_payload(
    schema_version: int,
    *,
    finding_id: str,
    status: str | None = None,
) -> dict:
    if status is None:
        status = "advice" if schema_version == 3 else "finding"
    payload = {
        "schema_version": schema_version,
        "finding_id": finding_id,
        "adler_identity": server.IDENTITY,
        "subject_kind": "work",
        "subject": "legacy-subject",
        "checkpoint": "legacy-checkpoint",
        "severity": "medium",
        "status": status,
        "summary": "legacy",
        "evidence_refs": ["fixture:legacy"],
        "observed_at": "2026-09-16T00:00:00Z",
        "effect_contract": "advisory_only_no_automatic_action",
    }
    if schema_version == 2:
        components = [
            {"name": "git_head", "value": "a" * 40},
            {"name": "pr_head", "value": "b" * 40},
        ]
        payload.update(
            {
                "checkpoint_mode": "relational",
                "checkpoint_components": components,
                "checkpoint_set_sha256": server._sha256_json(components),
                "checkpoint_contract": "all_components_must_match_or_recheck",
            }
        )
    if schema_version == 3:
        payload.update(
            {
                "target_actor": None,
                "binding": None,
                "recommendation": None,
                "rationale": None,
                "confidence": None,
            }
        )
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
def test_exact_historical_legacy_schemas_remain_readable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, schema_version: int
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    finding_id = f"ga-20260916T00000{schema_version}Z-{schema_version:012x}"
    legacy = _legacy_payload(schema_version, finding_id=finding_id)
    _write_payload(state / "findings" / f"{finding_id}.json", legacy)

    listing = server.list_findings(limit=10)
    assert listing["source_complete"] is True
    assert listing["count"] == 1
    item = listing["findings"][0]
    assert item["legacy"] is True
    assert item["status"] == legacy["status"]
    assert item["kind"] == legacy["status"]
    assert item["subject_kind"] == "work"


@pytest.mark.parametrize("status", ["finding", "recheck_suggested", "recheck_required"])
def test_legacy_status_semantics_are_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    finding_id = f"ga-20260916T000010Z-{len(status):012x}"
    schema_version = 3 if status == "recheck_required" else 1
    legacy = _legacy_payload(schema_version, finding_id=finding_id, status=status)
    _write_payload(state / "findings" / f"{finding_id}.json", legacy)

    item = server.list_findings(limit=10)["findings"][0]
    assert item["legacy"] is True
    assert item["status"] == status
    assert item["kind"] == status


def test_fragment_is_not_accepted_as_legacy_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    _write_payload(state / "findings" / f"{FINDING_ID}.json", {"status": "risk"})

    listing = server.list_findings(limit=10)
    assert listing["source_complete"] is False
    assert listing["source_error_count"] == 1
    assert listing["findings"] == []


def test_legacy_filename_identity_mismatch_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    legacy = _legacy_payload(1, finding_id=FINDING_ID)
    wrong_path = state / "findings" / "ga-20260916T000001Z-bbbbbbbbbbbb.json"
    _write_payload(wrong_path, legacy)

    listing = server.list_findings(limit=10)
    assert listing["source_complete"] is False
    assert listing["findings"] == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", True),
        ("schema_version", 3),
        ("schema_version", 0),
        ("schema_version", -1),
        ("schema_version", "2"),
        ("schema_version", 2.0),
        ("schema_version", None),
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


@pytest.mark.parametrize("schema_version", [1, 2])
def test_digest_covers_full_stored_core_including_extra_unicode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, schema_version: int,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    path = state / "findings" / f"{FINDING_ID}.json"
    payload = _v1_payload(schema_version=schema_version, extra={"note": "Grüßer Adler 🦅"})
    _write_payload(path, payload)
    server._validate_v1_finding_payload(payload, path)

    payload["extra"]["note"] = "mutated"
    with pytest.raises(RuntimeError, match="digest mismatch"):
        server._validate_v1_finding_payload(payload, path)


@pytest.mark.parametrize("target_lane_id", [None, "a" * 32, "A" * 32, False])
def test_schema1_forbids_target_field_even_with_valid_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target_lane_id,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    path = state / "findings" / f"{FINDING_ID}.json"
    payload = _v1_payload(subject="lane:" + "a" * 32, target_lane_id=target_lane_id)
    core = dict(payload)
    core.pop("finding_sha256")
    with pytest.raises(RuntimeError, match="lane target"):
        server._persist_finding(core)
    assert not path.exists()
    _write_payload(path, payload)
    listing = server.list_findings()
    assert listing["source_complete"] is False
    assert listing["source_error_count"] == 1
    assert listing["findings"] == []


@pytest.mark.parametrize("target_lane_id", [None, 123, False, []])
def test_schema2_invalid_target_type_is_reported_as_invalid_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target_lane_id,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    path = state / "findings" / f"{FINDING_ID}.json"
    payload = _v1_payload(
        schema_version=2,
        subject="lane:" + "a" * 32,
        target_lane_id=target_lane_id,
    )
    with pytest.raises(RuntimeError, match=r"V1 finding lane target is invalid$"):
        server._validate_v1_finding_payload(payload, path)


def test_schema_version_is_digest_covered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    payload = _v1_payload(schema_version=2)
    payload["schema_version"] = 1
    with pytest.raises(RuntimeError, match="digest mismatch"):
        server._validate_v1_finding_payload(payload, state / "findings" / f"{FINDING_ID}.json")


@pytest.mark.parametrize("root_schema", [1, 2])
@pytest.mark.parametrize("recheck_schema", [1, 2])
def test_supported_schema_rechecks_require_same_subject_and_resolved_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, root_schema: int, recheck_schema: int,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    lane_id = "a" * 32
    root = _v1_payload(schema_version=root_schema, subject=f"lane:{lane_id}")
    if root_schema == 2:
        root = _v1_payload(**{**root, "target_lane_id": lane_id})
    recheck_id = "ga-20260916T000023Z-bbbbbbbbbbbb"
    recheck = _v1_payload(
        schema_version=recheck_schema, finding_id=recheck_id, subject=root["subject"],
        recheck_of=FINDING_ID, conclusion="still_current",
    )
    if root_schema == 2 and recheck_schema == 2:
        recheck = _v1_payload(**{**recheck, "target_lane_id": lane_id})
    for payload in (root, recheck):
        _write_payload(state / "findings" / f"{payload['finding_id']}.json", payload)
    listing = server.list_findings()
    assert listing["source_complete"] is True
    assert {item["finding_id"]: item["schema_version"] for item in listing["findings"]} == {
        FINDING_ID: root_schema, recheck_id: recheck_schema,
    }
    current = server._current_lane_findings(lane_id, CHECKPOINT)
    assert [item["finding_id"] for item in current] == [FINDING_ID]
    assert current[0]["current_recheck"]["schema_version"] == recheck_schema
    if root_schema == 2 and recheck_schema == 2:
        assert current[0]["current_recheck"]["target_lane_id"] == lane_id

    # A valid digest cannot authorize a recheck with another subject/binding.
    recheck = _v1_payload(**{**recheck, "subject": "lane:" + "b" * 32})
    _write_payload(state / "findings" / f"{recheck_id}.json", recheck)
    listing = server.list_findings()
    assert listing["source_complete"] is False
    assert listing["source_error_count"] == 1
    assert [item["finding_id"] for item in listing["findings"]] == [FINDING_ID]


@pytest.mark.parametrize("root_schema", [1, 2])
def test_unbound_root_cannot_gain_lane_binding_via_recheck(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, root_schema: int,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    root = _v1_payload(schema_version=root_schema)
    _write_payload(state / "findings" / f"{FINDING_ID}.json", root)
    with pytest.raises(ValueError, match="recheck lane target"):
        server.submit_finding(**_finding_args(
            target_lane_id="a" * 32, recheck_of=FINDING_ID, conclusion="still_current",
        ))
    assert len(list((state / "findings").glob("*.json"))) == 1

    recheck_id = "ga-20260916T000023Z-bbbbbbbbbbbb"
    recheck = _v1_payload(
        schema_version=2, finding_id=recheck_id, target_lane_id="a" * 32,
        recheck_of=FINDING_ID, conclusion="still_current",
    )
    _write_payload(state / "findings" / f"{recheck_id}.json", recheck)
    listing = server.list_findings()
    assert listing["source_complete"] is False
    assert listing["source_error_count"] == 1
    assert [item["finding_id"] for item in listing["findings"]] == [FINDING_ID]


def test_orphaned_persisted_recheck_marks_store_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    orphan_id = "ga-20260916T000020Z-bbbbbbbbbbbb"
    orphan = _v1_payload(
        finding_id=orphan_id,
        recheck_of="ga-20260916T000019Z-cccccccccccc",
        conclusion="still_current",
    )
    _write_payload(state / "findings" / f"{orphan_id}.json", orphan)

    listing = server.list_findings(limit=10)
    assert listing["source_complete"] is False
    assert listing["source_error_count"] == 1


def test_chained_persisted_recheck_marks_store_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    root_id = FINDING_ID
    first_recheck_id = "ga-20260916T000021Z-bbbbbbbbbbbb"
    chained_id = "ga-20260916T000022Z-cccccccccccc"
    root = _v1_payload(finding_id=root_id)
    first_recheck = _v1_payload(
        finding_id=first_recheck_id,
        recheck_of=root_id,
        conclusion="still_current",
    )
    chained = _v1_payload(
        finding_id=chained_id,
        recheck_of=first_recheck_id,
        conclusion="still_current",
    )
    for payload in (root, first_recheck, chained):
        _write_payload(state / "findings" / f"{payload['finding_id']}.json", payload)

    listing = server.list_findings(limit=10)
    assert listing["source_complete"] is False
    assert listing["source_error_count"] == 1


def test_persisted_recheck_subject_mismatch_marks_store_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    root = _v1_payload(finding_id=FINDING_ID, subject="repo:one")
    recheck_id = "ga-20260916T000023Z-bbbbbbbbbbbb"
    recheck = _v1_payload(
        finding_id=recheck_id,
        subject="repo:two",
        recheck_of=FINDING_ID,
        conclusion="still_current",
    )
    for payload in (root, recheck):
        _write_payload(state / "findings" / f"{payload['finding_id']}.json", payload)

    listing = server.list_findings(limit=10)
    assert listing["source_complete"] is False
    assert listing["source_error_count"] == 1


def test_recheck_rejects_corrupted_parent_even_with_recomputed_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    root = server.submit_finding(**_finding_args())
    parent_path = state / "findings" / f"{root['finding_id']}.json"
    parent = json.loads(parent_path.read_text(encoding="utf-8"))
    parent["schema_version"] = 3
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
