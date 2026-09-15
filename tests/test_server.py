# Großer-Adler authority-boundary regression tests.
from __future__ import annotations

import json
from pathlib import Path

import pytest

import server


def test_status_declares_read_mostly_boundary() -> None:
    status = server.adler_status()
    assert status["identity"] == "grosser-adler-observer-v1"
    assert status["mode"] == "read-mostly"
    assert status["allowed_effects"] == ["append_finding"]
    assert "file_write" in status["forbidden_effects"]
    assert "bureau_mutation" in status["forbidden_effects"]


def test_repo_path_escape_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "repo"
    outside.mkdir()
    (outside / ".git").mkdir()
    with pytest.raises(PermissionError):
        server._resolve_repo(str(outside))


def test_unallowlisted_service_is_rejected() -> None:
    with pytest.raises(PermissionError):
        server._validate_unit("ssh.service")


def test_bad_revision_is_rejected() -> None:
    with pytest.raises(ValueError):
        server._validate_revision("HEAD;touch /tmp/nope")


def test_finding_is_create_only_and_advisory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = tmp_path / "state"
    findings = state / "findings"
    monkeypatch.setattr(server, "STATE_ROOT", state)
    monkeypatch.setattr(server, "FINDINGS_ROOT", findings)

    result = server.submit_finding(
        subject_kind="commit",
        subject="heimgewebe/grabowski",
        checkpoint="0123456789abcdef",
        severity="low",
        status="observation",
        summary="Controlled observer fixture; no action requested.",
        evidence_refs=["fixture:test_server.py"],
    )

    assert result["accepted"] is True
    assert result["automatic_effect"] is False
    files = list(findings.glob("*.json"))
    assert len(files) == 1
    payload = json.loads(files[0].read_text(encoding="utf-8"))
    assert payload["finding_id"] == result["finding_id"]
    assert payload["effect_contract"] == "advisory_only_no_automatic_action"
    assert files[0].stat().st_mode & 0o777 == 0o600

    listing = server.list_findings(limit=10)
    assert listing["count"] == 1
    assert listing["findings"][0]["finding_id"] == result["finding_id"]


def test_internal_runner_has_no_shell_escape() -> None:
    with pytest.raises(ValueError):
        server._run(["bash", "-lc", "true"])
