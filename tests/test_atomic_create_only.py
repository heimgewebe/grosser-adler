from __future__ import annotations

import json
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


def _owned_inbox(**extra) -> bytes:
    payload = {
        "writer_identity": server.IDENTITY,
        "contract": server.SIDECAR_CONTRACT,
    }
    payload.update(extra)
    return (json.dumps(payload, sort_keys=True) + "\n").encode()


def test_status_exposes_worktree_root_as_delivery_scope() -> None:
    status = server.adler_status()
    assert status["worktree_delivery_root"] == str(server.WORKTREE_ROOT)
    assert "worktree_observation_root" not in status
    assert status["repository_root"] == str(server.REPO_ROOT)


def test_finding_final_install_never_replaces_racing_existing_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    real_noreplace = server._rename_noreplace
    sentinel = b"foreign-writer-won-the-race\n"

    def collide_then_rename(dir_fd: int, left: str, right: str) -> None:
        fd = os.open(
            right,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
            dir_fd=dir_fd,
        )
        try:
            os.write(fd, sentinel)
            os.fsync(fd)
        finally:
            os.close(fd)
        real_noreplace(dir_fd, left, right)

    monkeypatch.setattr(server, "_rename_noreplace", collide_then_rename)

    with pytest.raises(FileExistsError):
        server.submit_finding(**_finding_args())

    finals = list((state / "findings").glob("*.json"))
    assert len(finals) == 1
    assert finals[0].read_bytes() == sentinel
    assert list((state / "findings").glob(".finding-*.tmp")) == []


def test_absent_inbox_install_never_replaces_racing_foreign_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inbox_dir = tmp_path / "inboxes"
    inbox_dir.mkdir(mode=0o700)
    name = "lane.json"
    sentinel = b"foreign-writer-won-the-inbox-race\n"
    real_noreplace = server._rename_noreplace

    def collide_then_rename(dir_fd: int, left: str, right: str) -> None:
        fd = os.open(
            right,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
            dir_fd=dir_fd,
        )
        try:
            os.write(fd, sentinel)
            os.fsync(fd)
        finally:
            os.close(fd)
        real_noreplace(dir_fd, left, right)

    monkeypatch.setattr(server, "_rename_noreplace", collide_then_rename)
    dir_fd = os.open(inbox_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        with pytest.raises(FileExistsError):
            server._atomic_write_inbox(dir_fd, name, _owned_inbox(generation=2))
    finally:
        os.close(dir_fd)

    assert (inbox_dir / name).read_bytes() == sentinel
    assert list(inbox_dir.glob(".*.tmp")) == []


def test_existing_inbox_swap_is_rolled_back_if_validated_inode_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inbox_dir = tmp_path / "inboxes"
    inbox_dir.mkdir(mode=0o700)
    name = "lane.json"
    path = inbox_dir / name
    path.write_bytes(_owned_inbox(generation=1))
    path.chmod(0o600)
    foreign = b"foreign-after-validation\n"
    real_exchange = server._rename_exchange
    calls = {"count": 0}

    def swap_before_first_exchange(dir_fd: int, left: str, right: str) -> None:
        calls["count"] += 1
        if calls["count"] == 1:
            os.unlink(right, dir_fd=dir_fd)
            fd = os.open(
                right,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600,
                dir_fd=dir_fd,
            )
            try:
                os.write(fd, foreign)
                os.fsync(fd)
            finally:
                os.close(fd)
        real_exchange(dir_fd, left, right)

    monkeypatch.setattr(server, "_rename_exchange", swap_before_first_exchange)
    dir_fd = os.open(inbox_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        with pytest.raises(RuntimeError, match="changed before atomic publication"):
            server._atomic_write_inbox(dir_fd, name, _owned_inbox(generation=2))
    finally:
        os.close(dir_fd)

    assert calls["count"] == 2
    assert path.read_bytes() == foreign
    assert list(inbox_dir.glob(".*.tmp")) == []


def test_finding_noreplace_install_has_no_hardlink_crash_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    real_noreplace = server._rename_noreplace

    def install_then_interrupt(dir_fd: int, left: str, right: str) -> None:
        real_noreplace(dir_fd, left, right)
        raise SystemExit("simulated process loss after rename")

    monkeypatch.setattr(server, "_rename_noreplace", install_then_interrupt)
    with pytest.raises(SystemExit, match="simulated process loss"):
        server.submit_finding(**_finding_args())

    finals = list((state / "findings").glob("*.json"))
    assert len(finals) == 1
    assert finals[0].stat().st_nlink == 1
    assert list((state / "findings").glob(".finding-*.tmp")) == []
    listing = server.list_findings(limit=10)
    assert listing["source_complete"] is True
    assert listing["count"] == 1


def test_absent_inbox_noreplace_install_is_restart_readable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inbox_dir = tmp_path / "inboxes"
    inbox_dir.mkdir(mode=0o700)
    name = "lane.json"
    path = inbox_dir / name
    real_noreplace = server._rename_noreplace

    def install_then_interrupt(dir_fd: int, left: str, right: str) -> None:
        real_noreplace(dir_fd, left, right)
        raise SystemExit("simulated process loss after rename")

    monkeypatch.setattr(server, "_rename_noreplace", install_then_interrupt)
    dir_fd = os.open(inbox_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        with pytest.raises(SystemExit, match="simulated process loss"):
            server._atomic_write_inbox(dir_fd, name, _owned_inbox(generation=1))
    finally:
        os.close(dir_fd)

    assert path.stat().st_nlink == 1
    assert path.read_bytes() == _owned_inbox(generation=1)
    assert list(inbox_dir.glob(".*.tmp")) == []

    monkeypatch.setattr(server, "_rename_noreplace", real_noreplace)
    dir_fd = os.open(inbox_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        server._atomic_write_inbox(dir_fd, name, _owned_inbox(generation=2))
    finally:
        os.close(dir_fd)
    assert path.read_bytes() == _owned_inbox(generation=2)
