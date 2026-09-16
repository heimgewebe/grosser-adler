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


def test_service_validation_is_syntax_bound_not_name_allowlisted() -> None:
    assert server._validate_unit("nixer-mcp.service") == "nixer-mcp.service"
    assert server._validate_unit("future-observer-target.service") == "future-observer-target.service"
    with pytest.raises(ValueError): server._validate_unit("ssh.timer")


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


def test_github_pr_requests_base_oid(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return {"returncode": 0, "stdout": "{}", "stderr": ""}

    monkeypatch.setattr(server, "_run", fake_run)
    server.github_pr("heimgewebe/grosser-adler", 2)

    assert len(calls) == 2
    fields = calls[0][calls[0].index("--json") + 1].split(",")
    assert "headRefOid" in fields
    assert "baseRefOid" in fields


def test_relational_checkpoint_binds_every_component(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = tmp_path / "state"
    findings = state / "findings"
    monkeypatch.setattr(server, "STATE_ROOT", state)
    monkeypatch.setattr(server, "FINDINGS_ROOT", findings)

    result = server.submit_finding(
        subject_kind="repo",
        subject="heimgewebe/grabowski",
        checkpoint="local-head-a",
        checkpoint_mode="relational",
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
    assert payload["checkpoint_mode"] == "relational"
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


def test_relational_checkpoint_rejects_incomplete_component_set(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "FINDINGS_ROOT", tmp_path / "state" / "findings")

    with pytest.raises(ValueError, match="at least two checkpoint_components"):
        server.submit_finding(
            subject_kind="pr",
            subject="heimgewebe/grosser-adler#2",
            checkpoint_mode="relational",
            checkpoint_components=[{"name": "pr_head", "value": "head-a"}],
            severity="medium",
            summary="Incomplete relational fixture.",
            evidence_refs=["fixture:incomplete-relational"],
        )


def test_single_checkpoint_rejects_relational_components(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(server, "FINDINGS_ROOT", tmp_path / "state" / "findings")

    with pytest.raises(ValueError, match="checkpoint_mode='relational'"):
        server.submit_finding(
            subject_kind="repo",
            subject="heimgewebe/grosser-adler",
            checkpoint_components=[
                {"name": "local_head", "value": "a"},
                {"name": "upstream_head", "value": "b"},
            ],
            severity="medium",
            summary="Ambiguous mode fixture.",
            evidence_refs=["fixture:ambiguous-mode"],
        )


def test_deploy_templates_keep_credentials_separate() -> None:
    root = Path(__file__).parents[1]
    tunnel = (root / "deploy" / "tunnel-client-grosser-adler.service").read_text(encoding="utf-8")
    mcp = (root / "deploy" / "grosser-adler-mcp.service").read_text(encoding="utf-8")

    assert "grosser-adler-runtime.env" in tunnel
    assert "grabowski-runtime.env" not in tunnel
    assert ".config/grosser-adler/github.env" in mcp


def test_process_descendants_are_bounded_to_requested_root() -> None:
    rows = [{"pid":10,"ppid":1},{"pid":11,"ppid":10},{"pid":12,"ppid":11},{"pid":20,"ppid":1}]
    assert [row["pid"] for row in server._descendant_rows(rows,10)] == [10,11,12]


def test_service_runtime_correlates_children_and_listener(monkeypatch: pytest.MonkeyPatch) -> None:
    own_uid = server.os.getuid()
    def fake_run(argv, **kwargs):
        if argv[0]=="/usr/bin/systemctl" and "show" in argv: return {"returncode":0,"stdout":"LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=100\nNRestarts=2\nControlGroup=/user.slice/nixer\n","stderr":"","stdout_truncated":False,"stderr_truncated":False}
        if argv[0]=="/usr/bin/ps": return {"returncode":0,"stdout":f"100 1 {own_uid} S 120 2048 1.0 python\n101 100 {own_uid} S 60 1024 0.2 nix\n200 1 {own_uid} S 10 512 0.0 sleep\n","stderr":"","stdout_truncated":False,"stderr_truncated":False}
        if argv[0]=="/usr/bin/ss": return {"returncode":0,"stdout":'LISTEN 0 128 127.0.0.1:18187 0.0.0.0:* users:(("python",pid=100,fd=3))\n',"stderr":"","stdout_truncated":False,"stderr_truncated":False}
        raise AssertionError(argv)
    monkeypatch.setattr(server,"_run",fake_run); runtime=server.service_runtime("nixer-mcp.service")
    assert runtime["main_pid"]==100; assert [row["pid"] for row in runtime["processes"]]==[100,101]; assert "127.0.0.1:18187" in runtime["listeners"][0]; assert runtime["complete"] is True


def test_supervise_work_confirms_explicit_claim_without_persisting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server,"git_status",lambda repo:{"repo":repo,"head":{"returncode":0,"stdout":"abc123\n"},"status":{"returncode":0,"stdout":"## feature\n"},"observed_at":"fixture"})
    result=server.supervise_work(binding_kind="grabowski_lane",binding_id="lane:fixture",repo="/home/alex/repos/nixer",claimed_head="abc123",expect_clean=True)
    assert result["conclusion"]=="confirmed"; assert result["work_state_authority"] is False; assert result["persisted"] is False


def test_supervise_work_preserves_stale_remote_head(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server,"git_status",lambda repo:{"repo":repo,"head":{"returncode":0,"stdout":"newhead\n"},"status":{"returncode":0,"stdout":"## feature\n"},"observed_at":"fixture"})
    monkeypatch.setattr(server,"github_pr",lambda repo,pr:{"metadata":{"returncode":0,"stdout":json.dumps({"headRefOid":"oldhead","baseRefOid":"basehead"})},"reviews":{"returncode":0,"stdout":"[]"}})
    result=server.supervise_work(binding_kind="pr",binding_id="heimgewebe/nixer#1",repo="/home/alex/repos/nixer",claimed_head="newhead",github_repo="heimgewebe/nixer",pr=1)
    assert result["conclusion"]=="stale"; assert result["stale_evidence"]


def test_enriched_advice_stays_append_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state=tmp_path/"state"; findings=state/"findings"; monkeypatch.setattr(server,"STATE_ROOT",state); monkeypatch.setattr(server,"FINDINGS_ROOT",findings)
    result=server.submit_finding(subject_kind="work",subject="lane:fixture",severity="medium",status="advice",summary="Exact-head evidence is stale.",evidence_refs=["fixture:head"],target_actor="grabowski",binding="lane:fixture",recommendation="Recheck the current head before closeout.",rationale="The reviewed head differs from the current head.",confidence=0.95)
    payload=json.loads(next(findings.glob("*.json")).read_text(encoding="utf-8")); assert result["automatic_effect"] is False; assert payload["schema_version"]==3; assert payload["status"]=="advice"; assert payload["target_actor"]=="grabowski"; assert payload["confidence"]==0.95


def test_status_cleanliness_counts_untracked() -> None:
    assert server._status_is_clean("## feature\n") is True
    assert server._status_is_clean("## feature\n?? scratch.txt\n") is False


def test_process_snapshot_excludes_other_uid(monkeypatch: pytest.MonkeyPatch) -> None:
    own_uid = server.os.getuid()
    other_uid = own_uid + 1
    monkeypatch.setattr(server, "_run", lambda argv, **kwargs: {
        "returncode": 0,
        "stdout": f"100 1 {other_uid} S 10 512 0.0 foreign foreign-process\n",
        "stderr": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
    })
    result = server.process_snapshot(100)
    assert result["scope"] == "current_uid"
    assert result["processes"] == []
    assert result["complete"] is False


def test_process_snapshot_does_not_expose_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    own_uid = server.os.getuid()
    monkeypatch.setattr(server, "_run", lambda argv, **kwargs: {
        "returncode": 0,
        "stdout": f"100 1 {own_uid} S 10 512 0.0 python\n",
        "stderr": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
    })
    result = server.process_snapshot(100)
    assert result["processes"][0]["comm"] == "python"
    assert "args" not in result["processes"][0]
