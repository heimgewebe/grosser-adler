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
    monkeypatch.setattr(server, "WORKTREE_WRITE_ROOT", tmp_path.resolve())
    return state


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


def test_foreign_inbox_is_never_overwritten(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    sidecar = worktree / ".adler"
    sidecar.mkdir(parents=True, mode=0o700)
    (sidecar / ".gitignore").write_bytes(b"*\n")
    (sidecar / ".gitignore").chmod(0o600)
    foreign = json.dumps({"writer_identity": "someone-else", "contract": server.SIDECAR_CONTRACT}).encode()
    (sidecar / "inbox.json").write_bytes(foreign)
    (sidecar / "inbox.json").chmod(0o600)
    lane_id = "e" * 32
    monkeypatch.setattr(server, "_read_work_target", lambda lane: _target(worktree, lane))
    with pytest.raises(RuntimeError, match="not Adler-owned"):
        server.publish_worktree_inbox(lane_id)
    assert (sidecar / "inbox.json").read_bytes() == foreign


def test_sidecar_directory_wrong_owner_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    worktree = tmp_path / "worktree"
    sidecar = worktree / ".adler"
    sidecar.mkdir(parents=True, mode=0o700)
    real_uid = os.getuid()
    monkeypatch.setattr(server.os, "getuid", lambda: real_uid + 1)
    with pytest.raises(RuntimeError, match="unsafe .adler sidecar directory"):
        server._ensure_sidecar_dir(worktree)


def test_sidecar_directory_unsafe_permissions_are_rejected(tmp_path: Path) -> None:
    worktree = tmp_path / "worktree"
    sidecar = worktree / ".adler"
    sidecar.mkdir(parents=True, mode=0o700)
    sidecar.chmod(0o755)
    with pytest.raises(RuntimeError, match="unsafe .adler directory permissions"):
        server._ensure_sidecar_dir(worktree)


def test_existing_inbox_unsafe_permissions_are_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    sidecar = worktree / ".adler"
    sidecar.mkdir(parents=True, mode=0o700)
    (sidecar / ".gitignore").write_bytes(b"*\n")
    (sidecar / ".gitignore").chmod(0o600)
    payload = {"writer_identity": server.IDENTITY, "contract": server.SIDECAR_CONTRACT}
    (sidecar / "inbox.json").write_text(json.dumps(payload), encoding="utf-8")
    (sidecar / "inbox.json").chmod(0o644)
    lane_id = "f" * 32
    monkeypatch.setattr(server, "_read_work_target", lambda lane: _target(worktree, lane))
    with pytest.raises(RuntimeError, match="unsafe sidecar file permissions"):
        server.publish_worktree_inbox(lane_id)


def test_hardlinked_gitignore_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    sidecar = worktree / ".adler"
    sidecar.mkdir(parents=True, mode=0o700)
    outside = tmp_path / "outside-gitignore"
    outside.write_bytes(b"*\n")
    outside.chmod(0o600)
    (sidecar / ".gitignore").hardlink_to(outside)
    lane_id = "a" * 32
    monkeypatch.setattr(server, "_read_work_target", lambda lane: _target(worktree, lane))
    with pytest.raises(RuntimeError, match="unsafe existing sidecar file"):
        server.publish_worktree_inbox(lane_id)


def test_failed_atomic_replace_keeps_old_inbox_and_cleans_tempfile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sidecar = tmp_path / ".adler"
    sidecar.mkdir(mode=0o700)
    old = (json.dumps({"writer_identity": server.IDENTITY, "contract": server.SIDECAR_CONTRACT}) + "\n").encode()
    (sidecar / "inbox.json").write_bytes(old)
    (sidecar / "inbox.json").chmod(0o600)
    dir_fd = os.open(sidecar, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    monkeypatch.setattr(server.os, "replace", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("replace failed")))
    try:
        with pytest.raises(OSError, match="replace failed"):
            server._atomic_write_inbox(dir_fd, b"new\n")
    finally:
        os.close(dir_fd)
    assert (sidecar / "inbox.json").read_bytes() == old
    assert list(sidecar.glob(".inbox-*.tmp")) == []


def test_sidecar_size_limit_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    lane_id = "1" * 32
    monkeypatch.setattr(server, "_read_work_target", lambda lane: _target(worktree, lane))
    monkeypatch.setattr(server, "MAX_OUTPUT_BYTES", 64)
    with pytest.raises(RuntimeError, match="inbox exceeds bounded size"):
        server.publish_worktree_inbox(lane_id)
    assert not (worktree / ".adler" / "inbox.json").exists()


def test_other_checkpoint_is_not_projected_as_current(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    lane_id = "2" * 32
    monkeypatch.setattr(server, "_read_work_target", lambda lane: _target(worktree, lane, checkpoint=OID_B))
    result = server.submit_finding(**_finding_args(subject=f"lane:{lane_id}", checkpoint=OID_A))
    assert result["delivery"]["state"] == "published"
    inbox = json.loads((worktree / ".adler" / "inbox.json").read_text(encoding="utf-8"))
    assert inbox["checkpoint"] == OID_B
    assert inbox["findings"] == []


def test_free_text_secrets_are_redacted_before_persistence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    secret = "sk-proj-" + "A" * 24
    result = server.submit_finding(**_finding_args(
        summary=f"observed {secret}",
        evidence_refs=[f"fixture:{secret}"],
    ))
    raw = (state / "findings" / f"{result['finding_id']}.json").read_text(encoding="utf-8")
    assert secret not in raw
    assert "<REDACTED>" in raw


def test_minimal_surface_has_no_general_file_writer() -> None:
    status = server.adler_status()
    assert status["allowed_effects"] == ["append_finding", "publish_worktree_inbox"]
    assert "general_file_write" in status["forbidden_effects"]
    assert not hasattr(server, "adler_probe")
    assert not hasattr(server, "write_file")
