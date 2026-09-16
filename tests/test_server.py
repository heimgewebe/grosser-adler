# Großer-Adler authority-boundary regression tests.
from __future__ import annotations

import json
from pathlib import Path

import pytest

import server


OID_A = "a" * 40
OID_B = "b" * 40
OID_C = "c" * 40
OID_D = "d" * 40


def test_status_declares_read_mostly_boundary() -> None:
    status = server.adler_status()
    assert status["identity"] == "grosser-adler-observer-v1"
    assert status["mode"] == "read-mostly"
    assert status["allowed_effects"] == ["append_finding"]
    assert "file_write" in status["forbidden_effects"]
    assert "bureau_mutation" in status["forbidden_effects"]
    assert "agent_start" in status["forbidden_effects"]


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
    with pytest.raises(ValueError):
        server._validate_revision("--textconv")


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


def test_relational_checkpoint_rejects_components_requiring_redaction_before_persisting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = tmp_path / "state"
    findings = state / "findings"
    monkeypatch.setattr(server, "STATE_ROOT", state)
    monkeypatch.setattr(server, "FINDINGS_ROOT", findings)

    for sensitive_value in ("sk-proj-" + "A" * 24, "sk-proj-" + "B" * 24):
        with pytest.raises(ValueError, match="requiring redaction"):
            server.submit_finding(
                subject_kind="work", subject="fixture", severity="medium", summary="fixture",
                evidence_refs=["fixture:redaction"], checkpoint_mode="relational",
                checkpoint_components=[
                    {"name": "local_head", "value": "a" * 40},
                    {"name": "runtime_token", "value": sensitive_value},
                ],
            )

    assert list(findings.glob("*.json")) == []


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


def _complete_git_fixture(head: str = OID_A, *, untracked: bool = False) -> dict:
    return {
        "repo": "/home/alex/repos/nixer",
        "head": {"returncode": 0, "stdout": head + "\n", "stdout_truncated": False},
        "status": {"returncode": 0, "stdout": "## feature\n", "stdout_truncated": False},
        "untracked_present": untracked,
        "observation_complete": True,
        "observed_at": "fixture",
    }


def _complete_service_show_fixture(
    *, main_pid: int = 100, control_group: str = "/user.slice/nixer", active_state: str = "active"
) -> str:
    values = {
        "LoadState": "loaded", "ActiveState": active_state,
        "SubState": "running" if active_state == "active" else "dead", "Result": "success",
        "ExecMainCode": "0", "ExecMainStatus": "0", "MainPID": str(main_pid),
        "FragmentPath": "/home/alex/.config/systemd/user/nixer-mcp.service", "NRestarts": "2",
        "ActiveEnterTimestamp": "now", "ExecMainStartTimestamp": "now", "ControlGroup": control_group,
        "MemoryCurrent": "2048", "TasksCurrent": "2", "CPUUsageNSec": "1000",
    }
    return "".join(f"{key}={values[key]}\n" for key in server._SYSTEMD_SERVICE_PROPERTIES)


def test_process_descendants_are_bounded_to_requested_root() -> None:
    rows = [
        {"pid": 10, "ppid": 1},
        {"pid": 11, "ppid": 10},
        {"pid": 12, "ppid": 11},
        {"pid": 20, "ppid": 1},
    ]
    assert [row["pid"] for row in server._descendant_rows(rows, 10)] == [10, 11, 12]


def test_process_reader_is_internal_and_cgroup_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    assert not hasattr(server, "process_snapshot")
    own_uid = server.os.getuid()

    def fake_run(argv, **kwargs):
        assert argv[:3] == ["/usr/bin/ps", "-ww", "-eo"]
        assert argv[3].endswith("comm=,cgroup=")
        return {
            "returncode": 0,
            "stdout": (
                f"100 1 {own_uid} S 10 512 0.0 python 0::/user.slice/nixer\n"
                f"101 100 {own_uid} S 8 256 0.0 Web Content 0::/user.slice/nixer/child\n"
                f"102 100 {own_uid} S 8 256 0.0 stray 0::/user.slice/other\n"
                f"103 1 {own_uid} S 8 256 0.0 reparented 0::/user.slice/nixer/detached\n"
                f"104 100 {own_uid} S 8 256 0.0 prefix 0::/user.slice/nixer-other\n"
            ),
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

    monkeypatch.setattr(server, "_run", fake_run)
    result = server._process_snapshot(100, "/user.slice/nixer")
    assert result["complete"] is True
    assert result["parse_complete"] is True
    assert [row["pid"] for row in result["processes"]] == [100, 101, 103]
    assert result["processes"][1]["comm"] == "Web Content"
    assert all("args" not in row for row in result["processes"])
    assert server._cgroup_within("/foo", "/foo") is True
    assert server._cgroup_within("/foo/child", "/foo") is True
    assert server._cgroup_within("/foobar", "/foo") is False


def test_process_reader_fails_closed_on_foreign_uid_cgroup_member(monkeypatch: pytest.MonkeyPatch) -> None:
    own_uid = server.os.getuid()
    monkeypatch.setattr(server, "_run", lambda argv, **kwargs: {
        "returncode": 0,
        "stdout": (
            f"100 1 {own_uid} S 10 512 0.0 python 0::/user.slice/nixer\n"
            f"101 1 {own_uid + 1} S 8 256 0.0 foreign 0::/user.slice/nixer/helper\n"
        ),
        "stderr": "", "stdout_truncated": False, "stderr_truncated": False,
    })
    result = server._process_snapshot(100, "/user.slice/nixer")
    assert result["uid_complete"] is False
    assert result["complete"] is False
    assert result["processes"] == []


def test_process_reader_marks_unparseable_rows_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    own_uid = server.os.getuid()
    monkeypatch.setattr(server, "_run", lambda argv, **kwargs: {
        "returncode": 0,
        "stdout": (
            f"100 1 {own_uid} S 10 512 0.0 python 0::/user.slice/nixer\n"
            "malformed process row\n"
        ),
        "stderr": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
    })
    result = server._process_snapshot(100, "/user.slice/nixer")
    assert result["parse_complete"] is False
    assert result["complete"] is False
    assert result["processes"] == []


def test_list_user_services_fails_closed_on_truncated_or_failed_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    observations = [
        {"returncode": 0, "stdout": "nixer-mcp.service loaded active running Nixer\n", "stderr": "", "stdout_truncated": True, "stderr_truncated": False},
        {"returncode": 1, "stdout": "", "stderr": "failed", "stdout_truncated": False, "stderr_truncated": False},
    ]
    for observation in observations:
        monkeypatch.setattr(server, "_run", lambda argv, **kwargs: observation)
        result = server.list_user_services()
        assert result["observation_complete"] is False
        assert result["services"] == []


def test_list_user_services_fails_closed_on_unparseable_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "_run", lambda argv, **kwargs: {
        "returncode": 0,
        "stdout": "nixer-mcp.service loaded active running Nixer\nmalformed-row\n",
        "stderr": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
    })
    result = server.list_user_services()
    assert result["parse_complete"] is False
    assert result["observation_complete"] is False
    assert result["services"] == []


def test_service_status_fails_closed_on_truncated_or_failed_show(monkeypatch: pytest.MonkeyPatch) -> None:
    observations = [
        {"returncode": 0, "stdout": "ActiveState=active\nMainPID=100\n", "stderr": "", "stdout_truncated": True, "stderr_truncated": False},
        {"returncode": 1, "stdout": "ActiveState=active\n", "stderr": "failed", "stdout_truncated": False, "stderr_truncated": False},
    ]
    for observation in observations:
        monkeypatch.setattr(server, "_run", lambda argv, **kwargs: observation)
        result = server.service_status("nixer-mcp.service")
        assert result["observation_complete"] is False
        assert result["properties"] == {}


def test_service_status_fails_closed_on_missing_or_malformed_properties(monkeypatch: pytest.MonkeyPatch) -> None:
    observations = [
        {"returncode": 0, "stdout": "ActiveState=active\n", "stderr": "", "stdout_truncated": False, "stderr_truncated": False},
        {"returncode": 0, "stdout": _complete_service_show_fixture() + "malformed-row\n", "stderr": "", "stdout_truncated": False, "stderr_truncated": False},
    ]
    for observation in observations:
        monkeypatch.setattr(server, "_run", lambda argv, **kwargs: observation)
        result = server.service_status("nixer-mcp.service")
        assert result["parse_complete"] is False
        assert result["observation_complete"] is False
        assert result["properties"] == {}


def test_service_runtime_correlates_cgroup_children_and_listener(monkeypatch: pytest.MonkeyPatch) -> None:
    own_uid = server.os.getuid()
    def fake_run(argv, **kwargs):
        if argv[0] == "/usr/bin/systemctl" and "show" in argv:
            return {
                "returncode": 0,
                "stdout": _complete_service_show_fixture(),
                "stderr": "", "stdout_truncated": False, "stderr_truncated": False,
            }
        if argv[0] == "/usr/bin/ps":
            return {
                "returncode": 0,
                "stdout": (
                    f"100 1 {own_uid} S 120 2048 1.0 python 0::/user.slice/nixer\n"
                    f"101 100 {own_uid} S 60 1024 0.2 nix 0::/user.slice/nixer/child\n"
                    f"102 100 {own_uid} S 60 1024 0.2 stray 0::/user.slice/other\n"
                ),
                "stderr": "", "stdout_truncated": False, "stderr_truncated": False,
            }
        if argv[0] == "/usr/bin/ss":
            assert argv == ["/usr/bin/ss", "-H", "-lntue"]
            assert all("p" not in argument for argument in argv[1:])
            return {
                "returncode": 0,
                "stdout": f'tcp LISTEN 0 128 127.0.0.1:18187 0.0.0.0:* uid:{own_uid} ino:42 cgroup:/user.slice/nixer <->\n',
                "stderr": "", "stdout_truncated": False, "stderr_truncated": False,
            }
        raise AssertionError(argv)
    monkeypatch.setattr(server, "_run", fake_run)
    runtime = server.service_runtime("nixer-mcp.service")
    assert runtime["main_pid"] == 100
    assert [row["pid"] for row in runtime["processes"]] == [100, 101]
    assert "127.0.0.1:18187" in runtime["listeners"][0]
    assert runtime["listener_observation_complete"] is True
    assert runtime["complete"] is True


def test_service_runtime_zero_listener_match_does_not_establish_absence(monkeypatch: pytest.MonkeyPatch) -> None:
    own_uid = server.os.getuid()
    def fake_run(argv, **kwargs):
        if argv[0] == "/usr/bin/systemctl":
            return {"returncode": 0, "stdout": _complete_service_show_fixture(control_group="/cg"), "stderr": "", "stdout_truncated": False, "stderr_truncated": False}
        if argv[0] == "/usr/bin/ps":
            return {"returncode": 0, "stdout": f"100 1 {own_uid} S 1 1 0.0 python 0::/cg\n", "stderr": "", "stdout_truncated": False, "stderr_truncated": False}
        if argv[0] == "/usr/bin/ss":
            assert argv == ["/usr/bin/ss", "-H", "-lntue"]
            return {"returncode": 0, "stdout": f"tcp LISTEN 0 128 127.0.0.1:9999 0.0.0.0:* uid:{own_uid} ino:9 cgroup:/other <->\n", "stderr": "", "stdout_truncated": False, "stderr_truncated": False}
        raise AssertionError(argv)
    monkeypatch.setattr(server, "_run", fake_run)
    runtime = server.service_runtime("nixer-mcp.service")
    assert runtime["listener_observation_complete"] is False
    assert runtime["listener_negative_claim_supported"] is False
    assert runtime["listener_scope"] == "tcp_udp_positive_cgroup_evidence"
    assert runtime["listeners"] == []
    assert runtime["complete"] is False
    assert "listener_absence_not_established" in runtime["missing_evidence"]
    assert "exhaustive_socket_inventory" in runtime["does_not_establish"]


def test_service_runtime_marks_mixed_attribution_socket_source_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    own_uid = server.os.getuid()
    def fake_run(argv, **kwargs):
        if argv[0] == "/usr/bin/systemctl":
            return {"returncode": 0, "stdout": _complete_service_show_fixture(control_group="/cg"), "stderr": "", "stdout_truncated": False, "stderr_truncated": False}
        if argv[0] == "/usr/bin/ps":
            return {"returncode": 0, "stdout": f"100 1 {own_uid} S 1 1 0.0 python 0::/cg\n", "stderr": "", "stdout_truncated": False, "stderr_truncated": False}
        if argv[0] == "/usr/bin/ss":
            return {
                "returncode": 0,
                "stdout": (
                    f"tcp LISTEN 0 128 127.0.0.1:18187 0.0.0.0:* uid:{own_uid} ino:42 cgroup:/cg <->\n"
                    "tcp LISTEN 0 128 127.0.0.1:9999 0.0.0.0:*\n"
                ),
                "stderr": "", "stdout_truncated": False, "stderr_truncated": False,
            }
        raise AssertionError(argv)
    monkeypatch.setattr(server, "_run", fake_run)
    runtime = server.service_runtime("nixer-mcp.service")
    assert runtime["listener_observation_complete"] is False
    assert runtime["complete"] is False
    assert len(runtime["listeners"]) == 1
    assert "127.0.0.1:18187" in runtime["listeners"][0]
    assert runtime["listener_unattributed_source_lines"] == 1
    assert "listeners" in runtime["missing_evidence"]


def test_service_runtime_marks_truncated_process_or_socket_sources_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    own_uid = server.os.getuid()
    def fake_run(argv, **kwargs):
        if argv[0] == "/usr/bin/systemctl":
            return {"returncode": 0, "stdout": _complete_service_show_fixture(control_group="/cg"), "stderr": "", "stdout_truncated": False, "stderr_truncated": False}
        if argv[0] == "/usr/bin/ps":
            return {"returncode": 0, "stdout": f"100 1 {own_uid} S 1 1 0.0 python 0::/cg\n", "stderr": "", "stdout_truncated": True, "stderr_truncated": False}
        if argv[0] == "/usr/bin/ss":
            return {"returncode": 0, "stdout": "", "stderr": "", "stdout_truncated": True, "stderr_truncated": False}
        raise AssertionError(argv)
    monkeypatch.setattr(server, "_run", fake_run)
    runtime = server.service_runtime("nixer-mcp.service")
    assert runtime["complete"] is False
    assert "process_tree" in runtime["missing_evidence"]
    assert "listeners" in runtime["missing_evidence"]


def test_supervise_work_rejects_symbolic_or_abbreviated_claimed_head() -> None:
    for claimed in ("HEAD", "abc123", "a" * 12):
        with pytest.raises(ValueError, match="full commit OID"):
            server.supervise_work(
                binding_kind="manual", binding_id="manual:fixture",
                repo="/home/alex/repos/nixer", claimed_head=claimed,
            )


def test_supervise_work_keeps_unverified_lane_top_level_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "git_status", lambda repo: _complete_git_fixture())
    result = server.supervise_work(
        binding_kind="grabowski_lane", binding_id="lane:fixture",
        repo="/home/alex/repos/nixer", claimed_head=OID_A, expect_clean=True,
    )
    assert result["evidence_conclusion"] == "confirmed"
    assert result["conclusion"] == "incomplete"
    assert result["binding"]["verification"] == "unverified"
    assert "binding_identity" in result["missing_evidence"]
    assert result["persisted"] is False


def test_supervise_work_manual_claim_can_confirm_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "git_status", lambda repo: _complete_git_fixture())
    result = server.supervise_work(
        binding_kind="manual", binding_id="manual:fixture",
        repo="/home/alex/repos/nixer", claimed_head=OID_A, expect_clean=True,
    )
    assert result["conclusion"] == "confirmed"
    assert result["binding"]["verification"] == "not_applicable"
    assert "stale_evidence" not in result


def test_supervise_work_truncated_git_is_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _complete_git_fixture()
    fixture["observation_complete"] = False
    fixture["status"]["stdout_truncated"] = True
    monkeypatch.setattr(server, "git_status", lambda repo: fixture)
    result = server.supervise_work(
        binding_kind="manual", binding_id="manual:fixture",
        repo="/home/alex/repos/nixer", claimed_head=OID_A, expect_clean=True,
    )
    assert result["conclusion"] == "incomplete"
    assert result["dimensions"]["cleanliness"]["status"] == "incomplete"


def test_supervise_work_service_expectation_requires_unit() -> None:
    with pytest.raises(ValueError, match="unit is required"):
        server.supervise_work(
            binding_kind="manual", binding_id="manual:fixture",
            repo="/home/alex/repos/nixer", expect_service_active=True,
        )


def test_supervise_work_missing_active_state_is_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "git_status", lambda repo: _complete_git_fixture())
    monkeypatch.setattr(server, "service_runtime", lambda unit: {
        "service": {}, "main_pid": 0, "control_group": None, "processes": [],
        "listeners": [], "missing_evidence": ["systemd_status"], "complete": False,
    })
    result = server.supervise_work(
        binding_kind="manual", binding_id="manual:fixture", repo="/home/alex/repos/nixer",
        claimed_head=OID_A, unit="nixer-mcp.service", expect_service_active=True,
    )
    assert result["conclusion"] == "incomplete"
    assert result["dimensions"]["runtime_active"]["status"] == "incomplete"
    assert not result["contradictions"]
    assert not any(item["name"].startswith("runtime_") for item in result["checkpoint_components"])


def test_supervise_work_checkpoint_components_bind_cleanliness_and_complete_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "git_status", lambda repo: _complete_git_fixture(OID_A))
    monkeypatch.setattr(server, "service_runtime", lambda unit: {
        "service": {
            "ActiveState": "active", "ExecMainStartTimestamp": "now", "NRestarts": "2",
        },
        "main_pid": 100, "control_group": "/cg", "processes": [{"pid": 100}],
        "listeners": ["tcp LISTEN ... cgroup:/cg"], "missing_evidence": [], "complete": True,
    })
    result = server.supervise_work(
        binding_kind="manual", binding_id="manual:fixture", repo="/home/alex/repos/nixer",
        claimed_head=OID_A, expect_clean=True, unit="nixer-mcp.service", expect_service_active=True,
    )
    components = {item["name"]: item["value"] for item in result["checkpoint_components"]}
    assert components["local_head"] == OID_A
    assert components["local_clean"] == "true"
    assert components["runtime_main_pid"] == "100"
    assert components["runtime_active_state"] == "active"
    assert components["runtime_start"] == "now"
    assert components["runtime_restarts"] == "2"
    assert components["runtime_cgroup"] == "/cg"


def test_supervise_work_pr_head_mismatch_is_contradicted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "git_status", lambda repo: _complete_git_fixture(OID_B))
    monkeypatch.setattr(server, "github_pr", lambda repo, pr: {
        "metadata": {"returncode": 0, "stdout": json.dumps({"number": 1, "headRefOid": OID_C, "baseRefOid": OID_D}), "stdout_truncated": False},
        "reviews": {"returncode": 0, "stdout": "[]"},
    })
    result = server.supervise_work(
        binding_kind="pr", binding_id="heimgewebe/nixer#1", repo="/home/alex/repos/nixer",
        claimed_head=OID_B, github_repo="heimgewebe/nixer", pr=1,
    )
    assert result["conclusion"] == "contradicted"
    assert result["dimensions"]["github_pr_head"]["status"] == "contradicted"


def test_supervise_work_missing_pr_head_is_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "git_status", lambda repo: _complete_git_fixture(OID_B))
    monkeypatch.setattr(server, "github_pr", lambda repo, pr: {
        "metadata": {"returncode": 0, "stdout": json.dumps({"number": 1, "baseRefOid": OID_D}), "stdout_truncated": False},
        "reviews": {"returncode": 0, "stdout": "[]"},
    })
    result = server.supervise_work(
        binding_kind="pr", binding_id="heimgewebe/nixer#1", repo="/home/alex/repos/nixer",
        claimed_head=OID_B, github_repo="heimgewebe/nixer", pr=1,
    )
    assert result["conclusion"] == "incomplete"
    assert "github_pr_head" in result["missing_evidence"]


def test_enriched_advice_rejects_huge_integer_confidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    monkeypatch.setattr(server, "STATE_ROOT", state)
    monkeypatch.setattr(server, "FINDINGS_ROOT", state / "findings")
    with pytest.raises(ValueError, match="finite number between 0 and 1"):
        server.submit_finding(
            subject_kind="work", subject="lane:fixture", severity="medium", status="advice",
            summary="Huge confidence fixture.", evidence_refs=["fixture:confidence"], confidence=10**10000,
        )
    assert list((state / "findings").glob("*.json")) == []


@pytest.mark.parametrize("confidence", [float("nan"), float("inf"), float("-inf")])
def test_enriched_advice_rejects_non_finite_confidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, confidence: float
) -> None:
    state = tmp_path / "state"
    monkeypatch.setattr(server, "STATE_ROOT", state)
    monkeypatch.setattr(server, "FINDINGS_ROOT", state / "findings")
    with pytest.raises(ValueError, match="finite number between 0 and 1"):
        server.submit_finding(
            subject_kind="work", subject="lane:fixture", severity="medium", status="advice",
            summary="Non-finite confidence fixture.", evidence_refs=["fixture:confidence"], confidence=confidence,
        )
    assert list((state / "findings").glob("*.json")) == []


def test_enriched_advice_stays_append_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = tmp_path / "state"
    findings = state / "findings"
    monkeypatch.setattr(server, "STATE_ROOT", state)
    monkeypatch.setattr(server, "FINDINGS_ROOT", findings)
    result = server.submit_finding(
        subject_kind="work", subject="lane:fixture", severity="medium", status="advice",
        summary="Exact-head evidence is stale.", evidence_refs=["fixture:head"],
        target_actor="grabowski", binding="lane:fixture",
        recommendation="Recheck the current head before closeout.",
        rationale="The reviewed head differs from the current head.", confidence=0.95,
    )
    payload = json.loads(next(findings.glob("*.json")).read_text(encoding="utf-8"))
    assert result["automatic_effect"] is False
    assert payload["schema_version"] == 3
    assert payload["status"] == "advice"
    assert payload["target_actor"] == "grabowski"
    assert payload["confidence"] == 0.95


def test_relational_enriched_advice_uses_schema_v3(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = tmp_path / "state"
    monkeypatch.setattr(server, "STATE_ROOT", state)
    monkeypatch.setattr(server, "FINDINGS_ROOT", state / "findings")
    server.submit_finding(
        subject_kind="work", subject="lane:fixture", severity="medium", status="advice",
        summary="Relational advice.", evidence_refs=["fixture:head"],
        checkpoint_mode="relational", checkpoint_components=[
            {"name": "local_head", "value": "head-a"},
            {"name": "runtime_main_pid", "value": "100"},
        ], recommendation="Recheck both components.",
    )
    payload = json.loads(next((state / "findings").glob("*.json")).read_text(encoding="utf-8"))
    assert payload["schema_version"] == 3
    assert payload["checkpoint_mode"] == "relational"
    assert payload["recommendation"] == "Recheck both components."


def test_git_status_hides_untracked_filenames_and_tracks_completeness(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(server, "_resolve_repo", lambda repo: tmp_path)
    def fake_run(argv, **kwargs):
        if "status" in argv:
            return {"returncode": 0, "stdout": "## feature\n", "stderr": "", "stdout_truncated": False, "stderr_truncated": False}
        if "ls-files" in argv:
            return {"returncode": 0, "stdout": "private-name.txt\0", "stderr": "", "stdout_truncated": False, "stderr_truncated": False}
        if "rev-parse" in argv:
            return {"returncode": 0, "stdout": "abc123\n", "stderr": "", "stdout_truncated": False, "stderr_truncated": False}
        raise AssertionError(argv)
    monkeypatch.setattr(server, "_run", fake_run)
    result = server.git_status("fixture")
    assert result["untracked_present"] is True
    assert result["observation_complete"] is True
    assert "private-name.txt" not in json.dumps(result)


def test_status_cleanliness_requires_observed_branch_line() -> None:
    assert server._status_is_clean("## feature\n") is True
    assert server._status_is_clean("") is False
    assert server._status_is_clean("## feature\n M server.py\n") is False


def test_finding_v3_redacts_new_advisory_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = tmp_path / "state"
    monkeypatch.setattr(server, "STATE_ROOT", state)
    monkeypatch.setattr(server, "FINDINGS_ROOT", state / "findings")
    secret = "token=opaque-sensitive-value"
    server.submit_finding(
        subject_kind="work", subject=f"work {secret}", severity="low", status="advice",
        summary=f"summary {secret}", evidence_refs=[f"evidence:{secret}"],
        recommendation=f"recommend {secret}",
    )
    payload = json.loads(next((state / "findings").glob("*.json")).read_text(encoding="utf-8"))
    encoded = json.dumps(payload)
    assert "opaque-sensitive-value" not in encoded
    assert "<REDACTED>" in encoded
