from __future__ import annotations

import os
from pathlib import Path

import pytest

import server


def _configure_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setattr(server, "STATE_ROOT", state)
    monkeypatch.setattr(server, "FINDINGS_ROOT", state / "findings")
    monkeypatch.setattr(server, "INBOX_ROOT", state / "worktree-inboxes")
    server._ensure_state()
    return state


def _finding_args() -> dict:
    return {
        "kind": "risk",
        "severity": "medium",
        "confidence": 0.9,
        "subject": "repo:fixture",
        "checkpoint": "a" * 40,
        "binding_strength": "exact",
        "summary": "fixture",
        "evidence_refs": ["fixture:test"],
    }


def test_status_exposes_worktree_root_as_delivery_scope() -> None:
    status = server.adler_status()
    assert status["worktree_delivery_root"] == str(server.WORKTREE_ROOT)
    assert "worktree_observation_root" not in status
    assert status["repository_root"] == str(server.REPO_ROOT)


def test_finding_final_install_never_replaces_racing_existing_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    real_link = server.os.link
    sentinel = b"foreign-writer-won-the-race\n"

    def collide_then_link(
        src: str,
        dst: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        assert src_dir_fd is not None
        assert dst_dir_fd is not None
        fd = os.open(
            dst,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
            dir_fd=dst_dir_fd,
        )
        try:
            os.write(fd, sentinel)
            os.fsync(fd)
        finally:
            os.close(fd)
        real_link(
            src,
            dst,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(server.os, "link", collide_then_link)

    with pytest.raises(FileExistsError):
        server.submit_finding(**_finding_args())

    finals = list((state / "findings").glob("*.json"))
    assert len(finals) == 1
    assert finals[0].read_bytes() == sentinel
    assert list((state / "findings").glob(".finding-*.tmp")) == []
