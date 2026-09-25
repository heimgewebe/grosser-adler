from __future__ import annotations

import json
import os
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
    gitignore = sidecar / ".gitignore"
    gitignore.write_bytes(b"*\n")
    gitignore.chmod(0o600)
    target = state / "worktree-inboxes" / f"{lane_id}.json"
    (sidecar / "inbox.json").symlink_to(target)
    return target


def _finding_args(**overrides):
    data = {
        "kind": "risk",
        "severity": "medium",
        "confidence": 0.9,
        "subject": "repo:fixture",
        "checkpoint": OID_A,
        "binding_strength": "exact",
        "summary": "fixture finding",
        "evidence_refs": ["fixture:test_sidecar.py"],
    }
    data.update(overrides)
    return data


def _target(worktree: Path, lane_id: str, *, checkpoint: str = OID_A) -> dict:
    return {
        "lane_id": lane_id,
        "repository": "fixture",
        "worktree": str(worktree),
        "branch": "feature/minimal",
        "purpose": "fixture",
        "base_head": OID_B,
        "checkpoint": checkpoint,
        "source": "fixture",
        "observed_at": "fixture",
    }


@pytest.mark.parametrize(
    ("subject_template", "explicit_target"),
    [
        ("grabowski lane {lane_id}", True),
        ("repo:fixture", True),
        ("lane:{lane_id}", True),
        ("lane:{lane_id}", False),
    ],
)
def test_v1_lane_delivery_and_full_rebuild_preserve_exact_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    subject_template: str, explicit_target: bool,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    lane_id = _work_target_fixture(tmp_path, monkeypatch)
    inbox_path = _install_pointer(tmp_path / "worktree", state, lane_id)
    subject = subject_template.format(lane_id=lane_id)
    args = _finding_args(subject=subject)
    if explicit_target:
        args["target_lane_id"] = lane_id

    first = server.submit_finding(**args)
    assert first["delivery"]["state"] == "published"
    assert first["delivery"]["source_scan_mode"] == "full-history-scan"
    inbox = json.loads(inbox_path.read_text(encoding="utf-8"))
    assert [item["finding_id"] for item in inbox["findings"]] == [first["finding_id"]]
    assert inbox["findings"][0]["legacy"] is False
    assert inbox["findings"][0]["subject"] == subject
    original_path = state / "findings" / f"{first['finding_id']}.json"
    original_bytes = original_path.read_bytes()
    original = json.loads(original_bytes)
    assert original["schema_version"] == inbox["findings"][0]["schema_version"] == 2
    assert original["finding_contract"] == "adler-finding-v1"
    assert original.get("target_lane_id") == (lane_id if explicit_target else None)
    assert ("target_lane_id" in original) is explicit_target
    core = dict(original)
    assert core.pop("finding_sha256") == first["finding_sha256"]
    assert server._sha256_json(core) == first["finding_sha256"]

    # Distinct finding IDs remain separate even when their content is identical.
    second = server.submit_finding(**args)
    assert second["delivery"]["source_scan_mode"] == "incremental-memory-index"
    expected_ids = sorted([first["finding_id"], second["finding_id"]])
    inbox = json.loads(inbox_path.read_text(encoding="utf-8"))
    assert [item["finding_id"] for item in inbox["findings"]] == expected_ids
    monkeypatch.setattr(server, "_FINDING_INDEX", None)
    inbox_path.unlink()
    rebuilt = server.publish_worktree_inbox(lane_id)
    assert rebuilt["source_scan_mode"] == "full-history-scan"
    assert rebuilt["source_complete"] is True
    inbox = json.loads(inbox_path.read_text(encoding="utf-8"))
    assert [item["finding_id"] for item in inbox["findings"]] == expected_ids
    assert inbox["finding_count"] == inbox["total_current_finding_count"] == 2
    assert original_path.read_bytes() == original_bytes
    assert server._current_lane_findings("e" * 32, OID_A) == []
    for item in server.list_findings(limit=10)["findings"]:
        assert item["schema_version"] == 2
        assert item.get("target_lane_id") == (lane_id if explicit_target else None)


def test_incremental_index_handles_mixed_lane_binding_forms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    lane_id = _work_target_fixture(tmp_path, monkeypatch)
    inbox_path = _install_pointer(tmp_path / "worktree", state, lane_id)

    fallback = server.submit_finding(**_finding_args(subject=f"lane:{lane_id}"))
    assert fallback["delivery"]["source_scan_mode"] == "full-history-scan"
    explicit = server.submit_finding(**_finding_args(
        subject="repo:fixture", target_lane_id=lane_id,
    ))
    assert explicit["delivery"]["source_scan_mode"] == "incremental-memory-index"

    findings = json.loads(inbox_path.read_text(encoding="utf-8"))["findings"]
    assert [item["finding_id"] for item in findings] == sorted([
        fallback["finding_id"], explicit["finding_id"],
    ])
    by_id = {item["finding_id"]: item for item in findings}
    assert "target_lane_id" not in by_id[fallback["finding_id"]]
    assert by_id[explicit["finding_id"]]["target_lane_id"] == lane_id


@pytest.mark.parametrize(
    "target_lane_id",
    ["", "A" * 32, "a" * 31, "a" * 33, "g" * 32, " " + "a" * 32,
     "a" * 32 + " ", "a" * 32 + "\n", "lane:" + "a" * 32, "../lane", 123, True, []],
)
def test_invalid_explicit_target_is_rejected_before_append_or_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target_lane_id,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    monkeypatch.setattr(server, "_publish_worktree_inbox", lambda *a, **kw: pytest.fail("delivery"))
    with pytest.raises(ValueError, match="target_lane_id"):
        server.submit_finding(**_finding_args(
            subject="lane:" + "a" * 32, target_lane_id=target_lane_id,
        ))
    assert list((state / "findings").glob("*.json")) == []
    assert list((state / "worktree-inboxes").glob("*.json")) == []


def test_explicit_target_subject_conflict_is_rejected_before_append_or_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    monkeypatch.setattr(server, "_publish_worktree_inbox", lambda *a, **kw: pytest.fail("delivery"))
    with pytest.raises(ValueError, match="conflicts"):
        server.submit_finding(**_finding_args(
            subject="lane:" + "a" * 32, target_lane_id="b" * 32,
        ))
    assert list((state / "findings").glob("*.json")) == []
    assert list((state / "worktree-inboxes").glob("*.json")) == []


@pytest.mark.parametrize(
    "subject_template",
    ["grabowski lane {lane_id}", "observe lane:{lane_id}", "{lane_id}", "unrelated observation"],
)
def test_unbound_v1_free_text_and_evidence_remain_durable_without_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, subject_template: str,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    lane_id = _work_target_fixture(tmp_path, monkeypatch)
    inbox_path = _install_pointer(tmp_path / "worktree", state, lane_id)
    with monkeypatch.context() as unbound:
        unbound.setattr(server, "_publish_worktree_inbox", lambda *a, **kw: pytest.fail("delivery"))
        result = server.submit_finding(**_finding_args(
            subject=subject_template.format(lane_id=lane_id),
            evidence_refs=[f"lane:{lane_id}", f"target_lane_id={lane_id}"],
        ))
    assert result["accepted"] is True
    assert result["delivery"]["state"] == "not_applicable"
    assert (state / "findings" / f"{result['finding_id']}.json").exists()
    assert not inbox_path.exists()
    rebuilt = server.publish_worktree_inbox(lane_id)
    assert rebuilt["source_complete"] is True
    assert rebuilt["finding_count"] == 0


def test_explicit_target_retains_server_side_lane_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    lane_id = _work_target_fixture(tmp_path, monkeypatch, registered=False)
    inbox_path = _install_pointer(tmp_path / "worktree", state, lane_id)
    result = server.submit_finding(**_finding_args(target_lane_id=lane_id))
    assert result["delivery"]["state"] == "delivery_failed"
    assert result["delivery"]["finding_remains_durable"] is True
    assert (state / "findings" / f"{result['finding_id']}.json").exists()
    assert not inbox_path.exists()


@pytest.mark.parametrize("stored_target", ["A" * 32, "e" * 32, False, [], None])
def test_full_rebuild_quarantines_invalid_or_conflicting_explicit_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stored_target,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    lane_id = _work_target_fixture(tmp_path, monkeypatch)
    inbox_path = _install_pointer(tmp_path / "worktree", state, lane_id)
    result = server.submit_finding(**_finding_args(subject=f"lane:{lane_id}"))
    path = state / "findings" / f"{result['finding_id']}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["target_lane_id"] = stored_target
    payload.pop("finding_sha256")
    payload["finding_sha256"] = server._sha256_json(payload)
    path.write_text(json.dumps(payload), encoding="utf-8")
    before = path.read_bytes()

    rebuilt = server.publish_worktree_inbox(lane_id)
    assert rebuilt["source_complete"] is False
    assert rebuilt["quarantined_record_count"] == 1
    assert json.loads(inbox_path.read_text(encoding="utf-8"))["findings"] == []
    assert path.read_bytes() == before


def test_explicit_target_is_covered_by_finding_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    lane_id = _work_target_fixture(tmp_path, monkeypatch)
    _install_pointer(tmp_path / "worktree", state, lane_id)
    result = server.submit_finding(**_finding_args(target_lane_id=lane_id))
    path = state / "findings" / f"{result['finding_id']}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["target_lane_id"] = "e" * 32
    with pytest.raises(RuntimeError, match="digest mismatch"):
        server._validate_v1_finding_payload(payload, path)


@pytest.mark.parametrize("root_schema", [1, 2])
@pytest.mark.parametrize("explicit_recheck_target", [False, True])
def test_historical_subject_binding_projects_and_accepts_schema2_recheck(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    root_schema: int, explicit_recheck_target: bool,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    lane_id = _work_target_fixture(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    inbox_path = _install_pointer(worktree, state, lane_id)
    server._ensure_state()
    finding_id = "ga-20260916T000000Z-aaaaaaaaaaaa"
    server._persist_finding({
        **_finding_args(subject=f"lane:{lane_id}"),
        "schema_version": root_schema,
        "finding_contract": server.FINDING_CONTRACT,
        "finding_id": finding_id,
        "adler_identity": server.IDENTITY,
        "observed_at": "2026-09-16T00:00:00Z",
        "effect_contract": "advisory_only_no_automatic_action",
    })
    root_path = state / "findings" / f"{finding_id}.json"
    root_bytes = root_path.read_bytes()
    initial = server.publish_worktree_inbox(lane_id)
    assert initial["source_complete"] is True
    assert initial["finding_count"] == 1
    item = json.loads(inbox_path.read_text(encoding="utf-8"))["findings"][0]
    assert item["schema_version"] == root_schema
    assert item["legacy"] is False

    monkeypatch.setattr(
        server, "_read_work_target", lambda lane: _target(worktree, lane, checkpoint=OID_B),
    )
    recheck = server.submit_finding(**_finding_args(
        subject=f"lane:{lane_id}", checkpoint=OID_B,
        target_lane_id=lane_id if explicit_recheck_target else None,
        recheck_of=finding_id, conclusion="still_current",
    ))
    assert recheck["delivery"]["state"] == "published"
    monkeypatch.setattr(server, "_FINDING_INDEX", None)
    rebuilt = server.publish_worktree_inbox(lane_id)
    assert rebuilt["source_complete"] is True
    items = json.loads(inbox_path.read_text(encoding="utf-8"))["findings"]
    assert [item["finding_id"] for item in items] == [finding_id]
    assert items[0]["schema_version"] == root_schema
    assert items[0]["current_recheck"]["schema_version"] == 2
    assert items[0]["current_recheck"]["finding_id"] == recheck["finding_id"]
    assert root_path.read_bytes() == root_bytes


@pytest.mark.parametrize("stored_schema", [1, 3, 999])
def test_rebuild_quarantines_unsupported_schema_with_explicit_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stored_schema: int,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    lane_id = _work_target_fixture(tmp_path, monkeypatch)
    inbox_path = _install_pointer(tmp_path / "worktree", state, lane_id)
    result = server.submit_finding(**_finding_args(target_lane_id=lane_id))
    path = state / "findings" / f"{result['finding_id']}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["schema_version"] = stored_schema
    payload.pop("finding_sha256")
    payload["finding_sha256"] = server._sha256_json(payload)
    path.write_text(json.dumps(payload), encoding="utf-8")
    before = path.read_bytes()

    monkeypatch.setattr(server, "_FINDING_INDEX", None)
    rebuilt = server.publish_worktree_inbox(lane_id)
    assert rebuilt["source_complete"] is False
    assert rebuilt["quarantined_record_count"] == 1
    assert json.loads(inbox_path.read_text(encoding="utf-8"))["findings"] == []
    listing = server.list_findings()
    assert listing["source_complete"] is False
    assert listing["source_error_count"] == 1
    assert listing["findings"] == []
    assert path.read_bytes() == before


@pytest.mark.parametrize("conclusion", ["still_current", "no_longer_reproduced"])
def test_explicit_target_rechecks_survive_full_rebuild(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, conclusion: str,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    lane_id = _work_target_fixture(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    inbox_path = _install_pointer(worktree, state, lane_id)
    root = server.submit_finding(**_finding_args(target_lane_id=lane_id))
    root_path = state / "findings" / f"{root['finding_id']}.json"
    original_bytes = root_path.read_bytes()
    monkeypatch.setattr(
        server, "_read_work_target", lambda lane: _target(worktree, lane, checkpoint=OID_B),
    )
    recheck = server.submit_finding(**_finding_args(
        target_lane_id=lane_id, checkpoint=OID_B,
        recheck_of=root["finding_id"], conclusion=conclusion,
    ))
    assert recheck["delivery"]["state"] == "published"
    monkeypatch.setattr(server, "_FINDING_INDEX", None)
    rebuilt = server.publish_worktree_inbox(lane_id)
    assert rebuilt["source_complete"] is True
    findings = json.loads(inbox_path.read_text(encoding="utf-8"))["findings"]
    if conclusion == "still_current":
        assert [item["finding_id"] for item in findings] == [root["finding_id"]]
        assert findings[0]["current_recheck"]["finding_id"] == recheck["finding_id"]
        assert findings[0]["current_recheck"]["target_lane_id"] == lane_id
    else:
        assert findings == []
    assert root_path.read_bytes() == original_bytes

    # Even a digest-valid stored recheck cannot reroute its root to another lane.
    recheck_path = state / "findings" / f"{recheck['finding_id']}.json"
    payload = json.loads(recheck_path.read_text(encoding="utf-8"))
    payload["target_lane_id"] = "e" * 32
    payload.pop("finding_sha256")
    payload["finding_sha256"] = server._sha256_json(payload)
    recheck_path.write_text(json.dumps(payload), encoding="utf-8")
    rebuilt = server.publish_worktree_inbox(lane_id)
    assert rebuilt["source_complete"] is False
    assert rebuilt["quarantined_record_count"] == 1
    assert rebuilt["finding_count"] == 0


@pytest.mark.parametrize("recheck_target", [None, "e" * 32])
def test_recheck_cannot_drop_or_change_explicit_lane_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recheck_target: str | None,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    lane_id = _work_target_fixture(tmp_path, monkeypatch)
    _install_pointer(tmp_path / "worktree", state, lane_id)
    root = server.submit_finding(**_finding_args(target_lane_id=lane_id))
    with pytest.raises(ValueError, match="recheck lane target"):
        server.submit_finding(**_finding_args(
            target_lane_id=recheck_target, recheck_of=root["finding_id"], conclusion="still_current",
        ))
    assert len(list((state / "findings").glob("*.json"))) == 1


def test_recheck_cannot_drop_explicit_target_when_subject_also_binds_lane(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    lane_id = _work_target_fixture(tmp_path, monkeypatch)
    _install_pointer(tmp_path / "worktree", state, lane_id)
    subject = f"lane:{lane_id}"
    root = server.submit_finding(**_finding_args(subject=subject, target_lane_id=lane_id))
    with pytest.raises(ValueError, match="recheck lane target"):
        server.submit_finding(**_finding_args(
            subject=subject,
            target_lane_id=None,
            recheck_of=root["finding_id"],
            conclusion="still_current",
        ))
    assert len(list((state / "findings").glob("*.json"))) == 1


def test_rebuild_quarantines_recheck_that_drops_explicit_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    lane_id = _work_target_fixture(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    _install_pointer(worktree, state, lane_id)
    subject = f"lane:{lane_id}"
    root = server.submit_finding(**_finding_args(subject=subject, target_lane_id=lane_id))
    monkeypatch.setattr(
        server, "_read_work_target", lambda lane: _target(worktree, lane, checkpoint=OID_B),
    )
    recheck = server.submit_finding(**_finding_args(
        subject=subject,
        target_lane_id=lane_id,
        checkpoint=OID_B,
        recheck_of=root["finding_id"],
        conclusion="still_current",
    ))
    recheck_path = state / "findings" / f"{recheck['finding_id']}.json"
    payload = json.loads(recheck_path.read_text(encoding="utf-8"))
    payload.pop("target_lane_id")
    payload.pop("finding_sha256")
    payload["finding_sha256"] = server._sha256_json(payload)
    recheck_path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(server, "_FINDING_INDEX", None)
    rebuilt = server.publish_worktree_inbox(lane_id)
    assert rebuilt["source_complete"] is False
    assert rebuilt["quarantined_record_count"] == 1
    assert rebuilt["finding_count"] == 0


def test_current_view_deduplicates_finding_ids_without_coalescing_legacy_and_v1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    lane_id = _work_target_fixture(tmp_path, monkeypatch)
    _install_pointer(tmp_path / "worktree", state, lane_id)
    v1 = server.submit_finding(**_finding_args(subject=f"lane:{lane_id}", target_lane_id=lane_id))
    legacy = server.submit_finding_legacy(
        subject_kind="grabowski_lane", subject=lane_id, checkpoint=OID_A,
        severity="medium", summary="legacy finding", evidence_refs=["fixture:legacy"],
    )
    loaded, errors, _ = server._load_finding_payloads()
    assert errors == []
    current = server._lane_findings_from_loaded(lane_id, OID_A, loaded + loaded)
    assert [item["finding_id"] for item in current] == sorted([v1["finding_id"], legacy["finding_id"]])
    legacy_view = next(item for item in current if item["finding_id"] == legacy["finding_id"])
    assert legacy_view["legacy"] is True
    assert legacy_view["binding_strength"] == "legacy-unbound"


def _seal_lane(lane: dict) -> dict:
    lane = json.loads(json.dumps(lane))
    lane["kind"] = "grabowski.work_lane"
    lane["schema_version"] = 1
    lane["inputs"].setdefault("lease_owner_id", f"lane:{lane['lane_id']}")
    lane["inputs_sha256"] = server._sha256_json(lane["inputs"])
    lane["receipt_sha256"] = server._sha256_json(lane)
    return lane


def _work_target_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    registered: bool = True,
    inventory_branch: str = "feature/minimal",
    inventory_head: str = OID_A,
    observed_branch: str = "feature/minimal",
    observed_head: str = OID_A,
) -> str:
    repo = tmp_path / "repo"
    worktree = tmp_path / "worktree"
    lanes = tmp_path / "lanes"
    repo.mkdir()
    worktree.mkdir()
    lanes.mkdir(mode=0o700)
    (repo / ".git").mkdir()
    (worktree / ".git").write_text("gitdir: fixture\n", encoding="utf-8")
    lane_id = "d" * 32
    lane = _seal_lane({
        "lane_id": lane_id,
        "state": "ready",
        "terminal_closeout": None,
        "inputs": {
            "lane_id": lane_id,
            "repo": str(repo),
            "target_path": str(worktree),
            "branch": "feature/minimal",
            "purpose": "fixture",
            "base_head": OID_B,
        },
    })
    lane_path = lanes / f"{lane_id}.json"
    lane_path.write_text(json.dumps(lane), encoding="utf-8")
    lane_path.chmod(0o600)
    monkeypatch.setattr(server, "REPO_ROOT", tmp_path.resolve())
    monkeypatch.setattr(server, "GRABOWSKI_WORK_LANES_ROOT", lanes.resolve())

    def fake_run(argv, **kwargs):
        if "worktree" in argv and "list" in argv:
            if registered:
                out = (
                    f"worktree {worktree.resolve()}\n"
                    f"HEAD {inventory_head}\n"
                    f"branch refs/heads/{inventory_branch}\n\n"
                )
            else:
                out = (
                    f"worktree {repo.resolve()}\n"
                    f"HEAD {OID_A}\n"
                    "branch refs/heads/main\n\n"
                )
        elif argv[-2:] == ["rev-parse", "HEAD"]:
            out = observed_head + "\n"
        elif argv[-2:] == ["branch", "--show-current"]:
            out = observed_branch + "\n"
        elif argv[-2:] == ["rev-parse", "--show-toplevel"]:
            out = str(worktree.resolve()) + "\n"
        else:
            raise AssertionError(argv)
        return {
            "returncode": 0,
            "stdout": out,
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

    monkeypatch.setattr(server, "_run", fake_run)
    return lane_id


def test_invalid_lane_id_is_rejected_before_lookup() -> None:
    with pytest.raises(ValueError, match="lane_id"):
        server.get_work_target("../not-a-lane")


def test_unregistered_worktree_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lane_id = _work_target_fixture(tmp_path, monkeypatch, registered=False)
    with pytest.raises(RuntimeError, match="not one registered Git worktree"):
        server.get_work_target(lane_id)


def test_registered_branch_drift_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lane_id = _work_target_fixture(tmp_path, monkeypatch, inventory_branch="other")
    with pytest.raises(RuntimeError, match="branch does not match lane"):
        server.get_work_target(lane_id)


def test_registered_head_drift_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lane_id = _work_target_fixture(tmp_path, monkeypatch, observed_head=OID_B)
    with pytest.raises(RuntimeError, match="identity drifted"):
        server.get_work_target(lane_id)


def test_missing_grabowski_pointer_is_not_created_by_adler(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    lane_id = "e" * 32
    monkeypatch.setattr(server, "_read_work_target", lambda lane: _target(worktree, lane))
    with pytest.raises(RuntimeError, match="sidecar directory is missing"):
        server.publish_worktree_inbox(lane_id)
    assert not (worktree / ".adler").exists()
    assert not (state / "worktree-inboxes").exists()


def test_wrong_pointer_target_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    lane_id = "f" * 32
    sidecar = worktree / ".adler"
    sidecar.mkdir(mode=0o700)
    (sidecar / "inbox.json").symlink_to(state / "wrong.json")
    monkeypatch.setattr(server, "_read_work_target", lambda lane: _target(worktree, lane))
    with pytest.raises(RuntimeError, match="wrong Adler inbox"):
        server.publish_worktree_inbox(lane_id)
    assert not (state / "worktree-inboxes").exists()


def test_regular_worktree_inbox_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    lane_id = "1" * 32
    sidecar = worktree / ".adler"
    sidecar.mkdir(mode=0o700)
    regular = sidecar / "inbox.json"
    regular.write_text("foreign", encoding="utf-8")
    before = regular.read_bytes()
    monkeypatch.setattr(server, "_read_work_target", lambda lane: _target(worktree, lane))
    with pytest.raises(RuntimeError, match="unsafe .adler/inbox.json pointer"):
        server.publish_worktree_inbox(lane_id)
    assert regular.read_bytes() == before
    assert not (state / "worktree-inboxes").exists()


def test_external_foreign_inbox_is_never_overwritten(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "2" * 32
    target = _install_pointer(worktree, state, lane_id)
    target.parent.mkdir(mode=0o700)
    foreign = (json.dumps({"writer_identity": "someone-else", "contract": server.SIDECAR_CONTRACT}) + "\n").encode()
    target.write_bytes(foreign)
    target.chmod(0o600)
    monkeypatch.setattr(server, "_read_work_target", lambda lane: _target(worktree, lane))
    with pytest.raises(RuntimeError, match="not Adler-owned"):
        server.publish_worktree_inbox(lane_id)
    assert target.read_bytes() == foreign


def test_inbox_short_write_does_not_replace_valid_view_with_truncated_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    inbox_dir = tmp_path / "inboxes"
    inbox_dir.mkdir(mode=0o700)
    name = "lane.json"
    old = (json.dumps({"writer_identity": server.IDENTITY, "contract": server.SIDECAR_CONTRACT}) + "\n").encode()
    path = inbox_dir / name
    path.write_bytes(old)
    path.chmod(0o600)
    new = (json.dumps({
        "writer_identity": server.IDENTITY,
        "contract": server.SIDECAR_CONTRACT,
        "findings": [{"finding_id": "fixture"}],
    }, sort_keys=True) + "\n").encode()
    real_write = server.os.write

    def short_write(fd: int, data) -> int:
        raw = bytes(data)
        if len(raw) > 1:
            raw = raw[: max(1, len(raw) // 2)]
        return real_write(fd, raw)

    monkeypatch.setattr(server.os, "write", short_write)
    dir_fd = os.open(inbox_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        server._atomic_write_inbox(dir_fd, name, new)
    finally:
        os.close(dir_fd)
    assert path.read_bytes() == new
    assert json.loads(path.read_text(encoding="utf-8"))["findings"] == [{"finding_id": "fixture"}]


def test_failed_external_atomic_exchange_preserves_old_and_cleans_temp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    inbox_dir = tmp_path / "inboxes"
    inbox_dir.mkdir(mode=0o700)
    name = "lane.json"
    old = (json.dumps({"writer_identity": server.IDENTITY, "contract": server.SIDECAR_CONTRACT}) + "\n").encode()
    (inbox_dir / name).write_bytes(old)
    (inbox_dir / name).chmod(0o600)
    dir_fd = os.open(inbox_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    monkeypatch.setattr(server, "_rename_exchange", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("exchange failed")))
    try:
        with pytest.raises(OSError, match="exchange failed"):
            server._atomic_write_inbox(dir_fd, name, b"new\n")
    finally:
        os.close(dir_fd)
    assert (inbox_dir / name).read_bytes() == old
    assert list(inbox_dir.glob(f".{name}.*.tmp")) == []


def test_publish_changes_only_external_inbox_not_worktree_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "3" * 32
    target = _install_pointer(worktree, state, lane_id)
    sidecar = worktree / ".adler"
    link_before = os.lstat(sidecar / "inbox.json")
    gitignore_before = (sidecar / ".gitignore").read_bytes()
    monkeypatch.setattr(server, "_read_work_target", lambda lane: _target(worktree, lane))
    result = server.publish_worktree_inbox(lane_id)
    link_after = os.lstat(sidecar / "inbox.json")
    assert result["state"] == "published"
    assert target.exists()
    assert os.readlink(sidecar / "inbox.json") == str(target)
    assert (link_before.st_dev, link_before.st_ino, link_before.st_mtime_ns) == (link_after.st_dev, link_after.st_ino, link_after.st_mtime_ns)
    assert (sidecar / ".gitignore").read_bytes() == gitignore_before


def test_sidecar_metadata_limit_still_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "4" * 32
    target = _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(server, "_read_work_target", lambda lane: _target(worktree, lane))
    monkeypatch.setattr(server, "MAX_OUTPUT_BYTES", 64)
    with pytest.raises(RuntimeError, match="metadata exceeds bounded size"):
        server.publish_worktree_inbox(lane_id)
    assert not target.exists()


def test_other_checkpoint_is_not_projected_as_current(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "5" * 32
    target = _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(server, "_read_work_target", lambda lane: _target(worktree, lane, checkpoint=OID_B))
    result = server.submit_finding(**_finding_args(subject=f"lane:{lane_id}", checkpoint=OID_A))
    assert result["delivery"]["state"] == "delivery_failed"
    assert result["delivery"]["error_type"] == "RuntimeError"
    assert result["delivery"]["finding_remains_durable"] is True
    finding_path = state / "findings" / f"{result['finding_id']}.json"
    persisted = json.loads(finding_path.read_text(encoding="utf-8"))
    assert persisted["checkpoint"] == OID_A
    assert not target.exists()


def test_inbox_findings_are_ordered_by_severity_meaning_not_alphabetically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "6" * 32
    target = _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(server, "_read_work_target", lambda lane: _target(worktree, lane))
    # Submitted in an order that alphabetical sorting would not repair.
    for severity in ("medium", "critical", "low", "high"):
        server.submit_finding(
            **_finding_args(
                severity=severity, subject=f"lane:{lane_id}", checkpoint=OID_A
            )
        )
    server.publish_worktree_inbox(lane_id)
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert [item["severity"] for item in payload["findings"]] == [
        "critical",
        "high",
        "medium",
        "low",
    ]


def test_equal_severity_stays_deterministically_ordered_by_finding_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "7" * 32
    target = _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(server, "_read_work_target", lambda lane: _target(worktree, lane))
    for _ in range(4):
        server.submit_finding(
            **_finding_args(
                severity="high", subject=f"lane:{lane_id}", checkpoint=OID_A
            )
        )
    server.publish_worktree_inbox(lane_id)
    payload = json.loads(target.read_text(encoding="utf-8"))
    ids = [item["finding_id"] for item in payload["findings"]]
    assert ids == sorted(ids)
    assert len(ids) == 4


def test_severity_rank_orders_every_contract_value_and_keeps_unknown_last() -> None:
    assert server._SEVERITIES == ("critical", "high", "medium", "low")
    ranks = [server._severity_rank(value) for value in server._SEVERITIES]
    assert ranks == sorted(ranks) == [0, 1, 2, 3]
    # Unknown or malformed values cannot reach the sort through a valid record;
    # if one ever does it sorts last and stays visible rather than disappearing.
    for unknown in ("moderate", "", None, 3, ["high"]):
        assert server._severity_rank(unknown) == server._UNKNOWN_SEVERITY_RANK
    assert server._UNKNOWN_SEVERITY_RANK > max(ranks)


def test_unknown_severity_is_not_dropped_from_the_current_view(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    lane_id = "8" * 32
    server.submit_finding(
        **_finding_args(severity="low", subject=f"lane:{lane_id}", checkpoint=OID_A)
    )
    findings = server._current_lane_findings(lane_id, OID_A)
    findings.append({"severity": "moderate", "finding_id": "ga-unknown"})
    findings.sort(
        key=lambda item: (
            server._severity_rank(item.get("severity")),
            str(item.get("finding_id", "")),
        )
    )
    assert findings[-1]["severity"] == "moderate"
    assert len(findings) == 2
    assert (state / "findings").is_dir()


def test_free_text_secrets_are_redacted_before_persistence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    secret = "sk-proj-" + "A" * 24
    result = server.submit_finding(**_finding_args(summary=f"observed {secret}", evidence_refs=[f"fixture:{secret}"]))
    raw = (state / "findings" / f"{result['finding_id']}.json").read_text(encoding="utf-8")
    assert secret not in raw
    assert "<REDACTED>" in raw


def test_minimal_surface_has_no_worktree_write_authority() -> None:
    status = server.adler_status()
    assert status["allowed_effects"] == ["append_finding", "publish_worktree_inbox"]
    assert "general_file_write" in status["forbidden_effects"]
    assert "worktree_write_root" not in status
    assert "inbox_store" in status
    assert not hasattr(server, "_ensure_sidecar_dir")
    assert not hasattr(server, "_ensure_sidecar_gitignore")
    assert not hasattr(server, "adler_probe")
    assert not hasattr(server, "write_file")
