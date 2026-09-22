from __future__ import annotations

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
    monkeypatch.setattr(server, "_FINDING_INDEX", None)
    server._ensure_state()
    return state


def _persist(
    finding_id: str,
    *,
    subject: str = "repo:alpha",
    checkpoint: str = OID_A,
    kind: str = "observation",
    severity: str = "low",
    recheck_of: str | None = None,
    conclusion: str | None = None,
) -> None:
    payload = {
        "schema_version": 1,
        "finding_contract": server.FINDING_CONTRACT,
        "finding_id": finding_id,
        "adler_identity": server.IDENTITY,
        "kind": kind,
        "severity": severity,
        "confidence": 1.0,
        "subject": subject,
        "checkpoint": checkpoint,
        "binding_strength": "exact",
        "summary": f"fixture {finding_id}",
        "evidence_refs": ["fixture:test_finding_retrieval.py"],
        "observed_at": "2026-09-19T13:00:00+00:00",
        "effect_contract": "advisory_only_no_automatic_action",
    }
    if recheck_of is not None:
        payload["recheck_of"] = recheck_of
        payload["conclusion"] = conclusion
    server._persist_finding(payload)


def _ids(count: int) -> list[str]:
    return [
        f"ga-20260919T130000Z-{index:012x}"
        for index in range(1, count + 1)
    ]


def test_cursor_pagination_roundtrips_without_duplicates_or_gaps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_state(tmp_path, monkeypatch)
    expected = _ids(7)
    for finding_id in expected:
        _persist(finding_id)

    seen: list[str] = []
    cursor = None
    while True:
        page = server.list_findings(limit=3, cursor=cursor)
        seen.extend(item["finding_id"] for item in page["findings"])
        assert len(page["findings"]) <= 3
        cursor = page["pagination"]["next_cursor"]
        if cursor is None:
            assert page["pagination"]["retrieval_complete"] is True
            break
        assert page["pagination"]["retrieval_complete"] is False

    assert seen == sorted(expected, reverse=True)
    assert len(seen) == len(set(seen))


def test_cursor_fails_closed_if_store_changes_between_pages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_state(tmp_path, monkeypatch)
    for finding_id in _ids(4):
        _persist(finding_id)

    first = server.list_findings(limit=2)
    cursor = first["pagination"]["next_cursor"]
    assert cursor is not None

    _persist("ga-20260919T130001Z-000000000005", subject="repo:later")
    with pytest.raises(ValueError, match="store membership changed"):
        server.list_findings(limit=2, cursor=cursor)


def test_exact_subject_checkpoint_kind_and_severity_filters_are_literal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_state(tmp_path, monkeypatch)
    rows = [
        (_ids(1)[0], "repo:alpha", OID_A, "risk", "high"),
        (_ids(2)[1], "repo:alpha-ish", OID_A, "risk", "high"),
        (_ids(3)[2], "repo:alpha", OID_B, "risk", "high"),
        (_ids(4)[3], "repo:alpha", OID_A, "observation", "high"),
        (_ids(5)[4], "repo:alpha", OID_A, "risk", "low"),
    ]
    for finding_id, subject, checkpoint, kind, severity in rows:
        _persist(
            finding_id,
            subject=subject,
            checkpoint=checkpoint,
            kind=kind,
            severity=severity,
        )

    page = server.list_findings(
        limit=10,
        exact_subject="repo:alpha",
        checkpoint=OID_A,
        kind="risk",
        severity="high",
    )
    assert [item["finding_id"] for item in page["findings"]] == [_ids(1)[0]]


def test_recheck_filter_preserves_history_without_current_truth_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_state(tmp_path, monkeypatch)
    root = "ga-20260919T130000Z-000000000001"
    recheck_one = "ga-20260919T130001Z-000000000002"
    recheck_two = "ga-20260919T130002Z-000000000003"
    _persist(root, subject="repo:recheck")
    _persist(
        recheck_one,
        subject="repo:recheck",
        recheck_of=root,
        conclusion="still_current",
    )
    _persist(
        recheck_two,
        subject="repo:recheck",
        recheck_of=root,
        conclusion="no_longer_reproduced",
    )

    history = server.list_findings(limit=10, exact_subject="repo:recheck")
    assert {item["finding_id"] for item in history["findings"]} == {
        root,
        recheck_one,
        recheck_two,
    }
    assert all("current_recheck" not in item for item in history["findings"])

    rechecks = server.list_findings(limit=10, recheck_of=root)
    assert [item["finding_id"] for item in rechecks["findings"]] == [
        recheck_two,
        recheck_one,
    ]
    assert all(item["recheck_of"] == root for item in rechecks["findings"])


def test_quarantine_remains_visible_and_valid_history_remains_retrievable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_state(tmp_path, monkeypatch)
    valid = _ids(1)[0]
    _persist(valid)
    corrupt = server.FINDINGS_ROOT / "ga-20260919T130001Z-000000000002.json"
    corrupt.write_text("{not-json", encoding="utf-8")

    page = server.list_findings(limit=10)
    assert [item["finding_id"] for item in page["findings"]] == [valid]
    assert page["source_complete"] is False
    assert page["source_error_count"] == 1
    assert page["quarantined_record_count"] == 1
    assert page["store_health"]["valid_record_count"] == 1
    assert page["store_health"]["quarantined_record_count"] == 1


def test_retrieval_source_bound_fails_before_record_loading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_state(tmp_path, monkeypatch)
    for finding_id in _ids(4):
        _persist(finding_id)
    monkeypatch.setattr(server, "MAX_FINDING_RETRIEVAL_SOURCE_RECORDS", 3)

    called = False

    def forbidden_loader(names=None):
        nonlocal called
        called = True
        raise AssertionError("record loader must not run beyond source bound")

    monkeypatch.setattr(server, "_load_finding_payloads", forbidden_loader)
    with pytest.raises(RuntimeError, match="source record bound exceeded"):
        server.list_findings(limit=2)
    assert called is False


def test_cursor_is_bound_to_filters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_state(tmp_path, monkeypatch)
    for finding_id in _ids(3):
        _persist(finding_id, subject="repo:alpha")

    first = server.list_findings(limit=1, exact_subject="repo:alpha")
    cursor = first["pagination"]["next_cursor"]
    assert cursor is not None

    with pytest.raises(ValueError, match="cursor filters do not match"):
        server.list_findings(
            limit=1,
            cursor=cursor,
            exact_subject="repo:beta",
        )


def test_retrieval_is_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_state(tmp_path, monkeypatch)
    for finding_id in _ids(3):
        _persist(finding_id)
    before = {
        path.name: path.read_bytes()
        for path in server.FINDINGS_ROOT.iterdir()
        if path.is_file()
    }

    page = server.list_findings(limit=2)
    assert page["findings"]

    after = {
        path.name: path.read_bytes()
        for path in server.FINDINGS_ROOT.iterdir()
        if path.is_file()
    }
    assert after == before


def test_invalid_filters_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_state(tmp_path, monkeypatch)
    _persist(_ids(1)[0])

    with pytest.raises(ValueError):
        server.list_findings(limit=10, kind="semantic-match")
    with pytest.raises(ValueError):
        server.list_findings(limit=10, severity="urgent")
    with pytest.raises(ValueError):
        server.list_findings(limit=10, recheck_of="not-a-finding-id")
    with pytest.raises(ValueError):
        server.list_findings(limit=10, exact_subject="")
