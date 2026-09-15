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
    assert payload["schema_version"] == 1
    assert payload["effect_contract"] == "advisory_only_no_automatic_action"
    assert files[0].stat().st_mode & 0o777 == 0o600

    listing = server.list_findings(limit=10)
    assert listing["count"] == 1
    assert listing["findings"][0]["finding_id"] == result["finding_id"]


def test_internal_runner_has_no_shell_escape() -> None:
    with pytest.raises(ValueError):
        server._run(["bash", "-lc", "true"])


def test_internal_runner_preserves_user_bus_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    class Completed:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(argv, **kwargs):
        captured.update(kwargs["env"])
        return Completed()

    monkeypatch.setattr(server.subprocess, "run", fake_run)
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
    server._run(["/usr/bin/systemctl", "--user", "show", "grabowski-transport-ingress.service"])
    assert captured["XDG_RUNTIME_DIR"] == "/run/user/1000"
    assert captured["DBUS_SESSION_BUS_ADDRESS"] == "unix:path=/run/user/1000/bus"


def test_github_token_is_scoped_to_gh_and_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}
    token = "opaque-dedicated-github-secret-not-matching-a-known-prefix"

    class Completed:
        returncode = 1
        stdout = f"stdout {token}"
        stderr = f"stderr {token}"

    def fake_run(argv, **kwargs):
        captured.update(kwargs["env"])
        return Completed()

    monkeypatch.setattr(server.subprocess, "run", fake_run)
    monkeypatch.setenv("GROSSER_ADLER_GITHUB_TOKEN", token)
    result = server._run(["/usr/bin/gh", "--version"])

    assert captured["GH_TOKEN"] == token
    assert "GROSSER_ADLER_GITHUB_TOKEN" not in captured
    assert token not in result["stdout"]
    assert token not in result["stderr"]


def test_github_token_is_not_forwarded_to_other_subprocesses(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    class Completed:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(argv, **kwargs):
        captured.update(kwargs["env"])
        return Completed()

    monkeypatch.setattr(server.subprocess, "run", fake_run)
    monkeypatch.setenv("GROSSER_ADLER_GITHUB_TOKEN", "dedicated-secret")
    server._run(["/usr/bin/git", "--version"])

    assert "GH_TOKEN" not in captured
    assert "GROSSER_ADLER_GITHUB_TOKEN" not in captured


def test_github_read_fails_closed_without_dedicated_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def fake_run(argv, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("subprocess must not run")

    monkeypatch.setattr(server.subprocess, "run", fake_run)
    monkeypatch.delenv("GROSSER_ADLER_GITHUB_TOKEN", raising=False)

    with pytest.raises(RuntimeError, match="GitHub credential is not configured"):
        server._run(["/usr/bin/gh", "--version"])
    assert called is False


def test_relational_checkpoint_binds_every_component(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = tmp_path / "state"
    findings = state / "findings"
    monkeypatch.setattr(server, "STATE_ROOT", state)
    monkeypatch.setattr(server, "FINDINGS_ROOT", findings)

    result = server.submit_finding(
        subject_kind="repo",
        subject="heimgewebe/grabowski",
        checkpoint="local-head-a",
        checkpoint_components=[
            {"name": "upstream_head", "value": "upstream-b"},
            {"name": "local_head", "value": "local-head-a"},
        ],
        severity="medium",
        summary="Relational fixture.",
        evidence_refs=["fixture:relational-checkpoint"],
    )

    payload = json.loads(next(findings.glob("*.json")).read_text(encoding="utf-8"))
    assert result["automatic_effect"] is False
    assert payload["schema_version"] == 2
    assert payload["checkpoint_components"] == [
        {"name": "local_head", "value": "local-head-a"},
        {"name": "upstream_head", "value": "upstream-b"},
    ]
    assert payload["checkpoint_contract"] == "all_components_must_match_or_recheck"

    changed = server._normalize_checkpoint_components([
        {"name": "local_head", "value": "local-head-a"},
        {"name": "upstream_head", "value": "upstream-c"},
    ])
    assert changed is not None
    assert server._checkpoint_set_sha256(changed) != payload["checkpoint_set_sha256"]


def test_deploy_templates_keep_credentials_separate() -> None:
    root = Path(__file__).parents[1]
    tunnel = (root / "deploy" / "tunnel-client-grosser-adler.service").read_text(encoding="utf-8")
    mcp = (root / "deploy" / "grosser-adler-mcp.service").read_text(encoding="utf-8")

    assert "grosser-adler-runtime.env" in tunnel
    assert "grabowski-runtime.env" not in tunnel
    assert ".config/grosser-adler/github.env" in mcp
