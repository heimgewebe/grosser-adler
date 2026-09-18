# Großer-Adler authority-boundary regression tests.
from __future__ import annotations

import concurrent.futures
import json
import os
import threading
from pathlib import Path

import pytest

import server


OID_A = "a" * 40
OID_B = "b" * 40
OID_C = "c" * 40
OID_D = "d" * 40


def test_status_declares_minimal_read_mostly_boundary() -> None:
    status = server.adler_status()
    assert status["identity"] == "grosser-adler-observer-v1"
    assert status["mode"] == "read-mostly"
    assert status["architecture_contract"] == "observer-evidence-finding-delivery-v1"
    assert status["allowed_effects"] == ["append_finding", "publish_worktree_inbox"]
    assert "general_file_write" in status["forbidden_effects"]
    assert "git_index_mutation" in status["forbidden_effects"]
    assert "bureau_mutation" in status["forbidden_effects"]
    assert "agent_start" in status["forbidden_effects"]
    assert "admission_policy" in status["forbidden_effects"]


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
    *, main_pid: int = 100, control_group: str = "/user.slice/nixer",
    active_state: str = "active", load_state: str = "loaded",
    fragment_path: str = "/home/alex/.config/systemd/user/nixer-mcp.service",
) -> str:
    values = {
        "LoadState": load_state, "ActiveState": active_state,
        "SubState": "running" if active_state == "active" else "dead", "Result": "success",
        "ExecMainCode": "0", "ExecMainStatus": "0", "MainPID": str(main_pid),
        "FragmentPath": fragment_path, "NRestarts": "2",
        "ActiveEnterTimestamp": "now", "ExecMainStartTimestamp": "now", "ControlGroup": control_group,
        "MemoryCurrent": "2048", "TasksCurrent": "2", "CPUUsageNSec": "1000",
    }
    return "".join(f"{key}={values[key]}\n" for key in server._SYSTEMD_SERVICE_PROPERTIES)


def _missing_system_service_show_fixture() -> str:
    return _complete_service_show_fixture(
        main_pid=0, control_group="", active_state="inactive", load_state="not-found", fragment_path=""
    )


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


def test_redact_can_preserve_canonical_grabowski_task_unit_without_weakening_default_redaction() -> None:
    unit = "grabowski-task-" + ("a" * 24) + "-a1.service"
    token = "sk-" + ("b" * 24)
    assert server._redact(unit) != unit
    for prefix in ("", "  ", "● "):
        assert server._redact(
            f"{prefix}{unit} {token}",
            protected_patterns=server._SAFE_REDACTION_LITERAL_PATTERNS,
        ) == f"{prefix}{unit} <REDACTED>"
    assert server._redact(
        unit,
        exact_secrets=(unit,),
        protected_patterns=server._SAFE_REDACTION_LITERAL_PATTERNS,
    ) == "<REDACTED>"


def test_list_user_services_protects_only_unit_column_from_redaction(monkeypatch: pytest.MonkeyPatch) -> None:
    unit = "grabowski-task-" + ("c" * 24) + "-a2.service"
    description_unit = "grabowski-task-" + ("e" * 24) + "-a3.service"
    token = "sk-" + ("d" * 24)
    raw_stdout = f"  {unit} loaded active running decoy {description_unit} token {token}\n"
    raw_stderr = f"warning {description_unit}\n"

    def fake_run(*args, **kwargs):
        return server.subprocess.CompletedProcess(
            args[0], 0, stdout=raw_stdout, stderr=raw_stderr
        )

    monkeypatch.setattr(server.subprocess, "run", fake_run)
    result = server.list_user_services()

    assert result["observation_complete"] is True
    assert result["services"] == [{
        "unit": unit,
        "load": "loaded",
        "active": "active",
        "sub": "running",
        "description": "decoy grabowski-ta<REDACTED>.service token <REDACTED>",
    }]
    assert result["source"]["stdout"].startswith("  " + unit + " ")
    assert description_unit not in result["source"]["stdout"]
    assert description_unit not in result["source"]["stderr"]
    assert token not in result["source"]["stdout"]


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


def test_service_status_selects_system_scope_when_user_shadow_is_inactive(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(argv, **kwargs):
        if "--user" in argv:
            stdout = _complete_service_show_fixture(
                main_pid=0, control_group="", active_state="inactive"
            )
        else:
            stdout = _complete_service_show_fixture(
                main_pid=653103,
                control_group="/system.slice/grabowski-operator.service",
                fragment_path="/etc/systemd/system/grabowski-operator.service",
            )
        return {
            "returncode": 0, "stdout": stdout, "stderr": "",
            "stdout_truncated": False, "stderr_truncated": False,
        }

    monkeypatch.setattr(server, "_run", fake_run)
    result = server.service_status("grabowski-operator.service")
    assert result["observation_complete"] is True
    assert result["scope"] == "system"
    assert result["scope_selection_reason"] == "single-running-scope"
    assert result["scope_ambiguous"] is False
    assert result["properties"]["MainPID"] == "653103"
    assert result["properties"]["ControlGroup"] == "/system.slice/grabowski-operator.service"
    assert [item["active_state"] for item in result["scope_candidates"]] == ["inactive", "active"]


def test_service_status_fails_closed_when_same_name_is_active_in_both_scopes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "_run", lambda argv, **kwargs: {
        "returncode": 0,
        "stdout": _complete_service_show_fixture(),
        "stderr": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
    })
    result = server.service_status("nixer-mcp.service")
    assert result["observation_complete"] is False
    assert result["scope"] is None
    assert result["scope_ambiguous"] is True
    assert result["scope_selection_reason"] == "multiple-running-scopes"
    assert result["properties"] == {}


@pytest.mark.parametrize(
    ("user_state", "system_state", "expected_reason"),
    [
        ("active", "reloading", "multiple-running-scopes"),
        ("reloading", "active", "multiple-running-scopes"),
        ("active", "activating", "loaded-transition-scope-conflict"),
        ("activating", "active", "loaded-transition-scope-conflict"),
        ("active", "deactivating", "loaded-transition-scope-conflict"),
        ("deactivating", "active", "loaded-transition-scope-conflict"),
    ],
)
def test_service_status_fails_closed_for_competing_running_or_transition_states(
    monkeypatch: pytest.MonkeyPatch,
    user_state: str,
    system_state: str,
    expected_reason: str,
) -> None:
    def fake_run(argv, **kwargs):
        if "--user" in argv:
            stdout = _complete_service_show_fixture(
                main_pid=101,
                control_group="/user.slice/competing.service",
                active_state=user_state,
            )
        else:
            stdout = _complete_service_show_fixture(
                main_pid=202,
                control_group="/system.slice/competing.service",
                active_state=system_state,
                fragment_path="/etc/systemd/system/competing.service",
            )
        return {
            "returncode": 0,
            "stdout": stdout,
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

    monkeypatch.setattr(server, "_run", fake_run)
    result = server.service_status("competing.service")
    assert result["observation_complete"] is False
    assert result["scope"] is None
    assert result["scope_ambiguous"] is True
    assert result["scope_selection_reason"] == expected_reason
    assert result["properties"] == {}
    assert [item["main_pid"] for item in result["scope_candidates"]] == ["101", "202"]


def test_service_logs_refuses_ambiguous_transition_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(argv, **kwargs):
        assert argv[0] == "/usr/bin/systemctl"
        state = "active" if "--user" in argv else "reloading"
        return {
            "returncode": 0,
            "stdout": _complete_service_show_fixture(main_pid=100, active_state=state),
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

    monkeypatch.setattr(server, "_run", fake_run)
    result = server.service_logs("competing.service", lines=5)
    assert result["scope"] is None
    assert result["scope_ambiguous"] is True
    assert result["logs"] is None
    assert result["observation_complete"] is False


def test_service_logs_uses_resolved_system_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[0] == "/usr/bin/systemctl":
            if "--user" in argv:
                stdout = _complete_service_show_fixture(main_pid=0, control_group="", active_state="inactive")
            else:
                stdout = _complete_service_show_fixture(
                    main_pid=653103,
                    control_group="/system.slice/grabowski-operator.service",
                    fragment_path="/etc/systemd/system/grabowski-operator.service",
                )
            return {
                "returncode": 0, "stdout": stdout, "stderr": "",
                "stdout_truncated": False, "stderr_truncated": False,
            }
        if argv[0] == "/usr/bin/journalctl":
            assert "--user" not in argv
            assert "--system" in argv
            return {
                "returncode": 0, "stdout": "system-log\n", "stderr": "",
                "stdout_truncated": False, "stderr_truncated": False,
            }
        raise AssertionError(argv)

    monkeypatch.setattr(server, "_run", fake_run)
    result = server.service_logs("grabowski-operator.service", lines=5)
    assert result["scope"] == "system"
    assert result["observation_complete"] is True
    assert result["journal_diagnostics_present"] is False
    assert result["logs"]["stdout"] == "system-log\n"
    assert len([argv for argv in calls if argv[0] == "/usr/bin/systemctl"]) == 2


def test_service_logs_fails_closed_on_successful_journal_access_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(argv, **kwargs):
        if argv[0] == "/usr/bin/systemctl":
            stdout = (
                _complete_service_show_fixture(main_pid=0, control_group="", active_state="inactive")
                if "--user" in argv
                else _complete_service_show_fixture(
                    main_pid=653103,
                    control_group="/system.slice/grabowski-operator.service",
                    fragment_path="/etc/systemd/system/grabowski-operator.service",
                )
            )
            return {
                "returncode": 0, "stdout": stdout, "stderr": "",
                "stdout_truncated": False, "stderr_truncated": False,
            }
        if argv[0] == "/usr/bin/journalctl":
            return {
                "returncode": 0,
                "stdout": "",
                "stderr": "Hint: journal access is restricted\n",
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
        raise AssertionError(argv)

    monkeypatch.setattr(server, "_run", fake_run)
    result = server.service_logs("grabowski-operator.service", lines=5)
    assert result["scope"] == "system"
    assert result["logs"]["returncode"] == 0
    assert result["journal_diagnostics_present"] is True
    assert result["observation_complete"] is False


def test_service_runtime_correlates_cgroup_children_and_listener(monkeypatch: pytest.MonkeyPatch) -> None:
    own_uid = server.os.getuid()
    def fake_run(argv, **kwargs):
        if argv[0] == "/usr/bin/systemctl" and "show" in argv:
            stdout = _complete_service_show_fixture() if "--user" in argv else _missing_system_service_show_fixture()
            return {
                "returncode": 0,
                "stdout": stdout,
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
    assert runtime["service_scope"] == "user"
    assert runtime["main_pid"] == 100
    assert [row["pid"] for row in runtime["processes"]] == [100, 101]
    assert "127.0.0.1:18187" in runtime["listeners"][0]
    assert runtime["listener_observation_complete"] is True
    assert runtime["complete"] is True


def test_service_runtime_zero_listener_match_does_not_establish_absence(monkeypatch: pytest.MonkeyPatch) -> None:
    own_uid = server.os.getuid()
    def fake_run(argv, **kwargs):
        if argv[0] == "/usr/bin/systemctl":
            stdout = (
                _complete_service_show_fixture(control_group="/cg") if "--user" in argv else _missing_system_service_show_fixture()
            )
            return {"returncode": 0, "stdout": stdout, "stderr": "", "stdout_truncated": False, "stderr_truncated": False}
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
            stdout = (
                _complete_service_show_fixture(control_group="/cg") if "--user" in argv else _missing_system_service_show_fixture()
            )
            return {"returncode": 0, "stdout": stdout, "stderr": "", "stdout_truncated": False, "stderr_truncated": False}
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
            stdout = (
                _complete_service_show_fixture(control_group="/cg") if "--user" in argv else _missing_system_service_show_fixture()
            )
            return {"returncode": 0, "stdout": stdout, "stderr": "", "stdout_truncated": False, "stderr_truncated": False}
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
    assert server._status_is_clean("## feature\n M server.py\n") is False

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


def _seal_lane(lane: dict) -> dict:
    lane = json.loads(json.dumps(lane))
    lane.setdefault("kind", "grabowski.work_lane")
    lane.setdefault("schema_version", 1)
    lane["inputs"].setdefault("lease_owner_id", f"lane:{lane['lane_id']}")
    lane["inputs_sha256"] = server._sha256_json(lane["inputs"])
    lane["receipt_sha256"] = server._sha256_json(lane)
    return lane


def _finding_args(**overrides):
    data = {
        "kind": "risk",
        "severity": "high",
        "confidence": 0.9,
        "subject": "repo:heimgewebe/grosser-adler",
        "checkpoint": OID_A,
        "binding_strength": "exact",
        "summary": "Evidence-bound fixture.",
        "evidence_refs": ["fixture:test_server.py"],
    }
    data.update(overrides)
    return data


def test_finding_v1_is_create_only_hashed_and_advisory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    result = server.submit_finding(**_finding_args())
    assert result["accepted"] is True
    assert result["automatic_effect"] is False
    assert result["delivery"]["state"] == "not_applicable"
    files = list((state / "findings").glob("*.json"))
    assert len(files) == 1
    payload = json.loads(files[0].read_text(encoding="utf-8"))
    assert payload["finding_contract"] == "adler-finding-v1"
    assert payload["kind"] == "risk"
    assert payload["binding_strength"] == "exact"
    assert payload["finding_sha256"] == result["finding_sha256"]
    core = dict(payload)
    core.pop("finding_sha256")
    import hashlib
    expected = hashlib.sha256(json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    assert expected == result["finding_sha256"]
    assert files[0].stat().st_mode & 0o777 == 0o600


def test_finding_identity_fields_requiring_redaction_are_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    secret = "sk-proj-" + "A" * 24
    for field in ("subject", "checkpoint"):
        args = _finding_args(**{field: secret})
        with pytest.raises(ValueError, match="requiring redaction"):
            server.submit_finding(**args)
    assert list((state / "findings").glob("*.json")) == []


@pytest.mark.parametrize("confidence", [float("nan"), float("inf"), float("-inf"), -0.1, 1.1])
def test_finding_rejects_invalid_confidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, confidence: float) -> None:
    _configure_state(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="finite number between 0 and 1"):
        server.submit_finding(**_finding_args(confidence=confidence))


def test_legacy_finding_remains_readable_without_driving_v1_semantics(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    findings = state / "findings"
    findings.mkdir(mode=0o700)
    legacy = {
        "schema_version": 3,
        "finding_id": "ga-20260916T000000Z-aaaaaaaaaaaa",
        "adler_identity": server.IDENTITY,
        "subject_kind": "work",
        "status": "advice",
        "severity": "medium",
        "subject": "legacy-subject",
        "checkpoint": "legacy-checkpoint",
        "summary": "legacy",
        "evidence_refs": ["fixture:legacy"],
        "observed_at": "2026-09-16T00:00:00Z",
        "effect_contract": "advisory_only_no_automatic_action",
        "target_actor": None,
        "binding": None,
        "recommendation": None,
        "rationale": None,
        "confidence": None,
    }
    (findings / f"{legacy['finding_id']}.json").write_text(json.dumps(legacy), encoding="utf-8")
    listing = server.list_findings(limit=10)
    assert listing["source_complete"] is True
    assert listing["count"] == 1
    assert listing["findings"][0]["legacy"] is True
    assert listing["findings"][0]["kind"] == "advice"
    assert listing["findings"][0]["status"] == "advice"
    assert listing["findings"][0]["binding_strength"] == "legacy-unbound"


def test_work_target_reads_exact_active_grabowski_lane(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    worktree = tmp_path / "worktree"
    lanes = tmp_path / "lanes"
    repo.mkdir(); worktree.mkdir(); lanes.mkdir()
    (repo / ".git").mkdir(); (worktree / ".git").write_text("gitdir: fixture", encoding="utf-8")
    lane_id = "1" * 32
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
    (lanes / f"{lane_id}.json").write_text(json.dumps(lane), encoding="utf-8")
    monkeypatch.setattr(server, "REPO_ROOT", tmp_path.resolve())
    monkeypatch.setattr(server, "GRABOWSKI_WORK_LANES_ROOT", lanes.resolve())
    def fake_run(argv, **kwargs):
        if "worktree" in argv and "list" in argv:
            out = f"worktree {worktree.resolve()}\nHEAD {OID_A}\nbranch refs/heads/feature/minimal\n\n"
        elif argv[-2:] == ["rev-parse", "HEAD"]:
            out = OID_A + "\n"
        elif argv[-2:] == ["branch", "--show-current"]:
            out = "feature/minimal\n"
        elif argv[-2:] == ["rev-parse", "--show-toplevel"]:
            out = str(worktree.resolve()) + "\n"
        else:
            raise AssertionError(argv)
        return {"returncode": 0, "stdout": out, "stderr": "", "stdout_truncated": False, "stderr_truncated": False}
    monkeypatch.setattr(server, "_run", fake_run)
    target = server.get_work_target(lane_id)
    assert target["worktree"] == str(worktree.resolve())
    assert target["branch"] == "feature/minimal"
    assert target["checkpoint"] == OID_A
    assert target["purpose"] == "fixture"


def test_work_target_rejects_terminal_lane(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lanes = tmp_path / "lanes"; lanes.mkdir()
    lane_id = "2" * 32
    lane = _seal_lane({"lane_id": lane_id, "state": "ready", "terminal_closeout": {"closeout_state": "no_change_proven"}, "inputs": {"lane_id": lane_id, "repo": str(tmp_path), "target_path": str(tmp_path), "branch": "fixture", "purpose": "fixture", "base_head": OID_A}})
    (lanes / f"{lane_id}.json").write_text(json.dumps(lane), encoding="utf-8")
    monkeypatch.setattr(server, "GRABOWSKI_WORK_LANES_ROOT", lanes.resolve())
    with pytest.raises(RuntimeError, match="not active"):
        server.get_work_target(lane_id)


def test_work_target_rejects_tampered_lane_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lanes = tmp_path / "lanes"; lanes.mkdir()
    lane_id = "8" * 32
    lane = _seal_lane({"lane_id": lane_id, "state": "ready", "terminal_closeout": None, "inputs": {"lane_id": lane_id, "repo": str(tmp_path), "target_path": str(tmp_path), "branch": "fixture", "purpose": "before", "base_head": OID_A}})
    lane["inputs"]["purpose"] = "tampered-after-seal"
    path = lanes / f"{lane_id}.json"
    path.write_text(json.dumps(lane), encoding="utf-8"); path.chmod(0o600)
    monkeypatch.setattr(server, "GRABOWSKI_WORK_LANES_ROOT", lanes.resolve())
    with pytest.raises(RuntimeError, match="receipt digest is invalid"):
        server.get_work_target(lane_id)


def test_lane_finding_automatically_publishes_external_current_view(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "3" * 32
    target = _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(server, "_read_work_target", lambda lane: {
        "lane_id": lane, "repository": str(tmp_path / "repo"), "worktree": str(worktree),
        "branch": "feature/minimal", "purpose": "fixture", "base_head": OID_B,
        "checkpoint": OID_A, "source": "fixture", "observed_at": "fixture",
    })
    result = server.submit_finding(**_finding_args(subject=f"lane:{lane_id}"))
    assert result["delivery"]["state"] == "published"
    assert result["delivery"]["inbox_store"] == str(target)
    inbox = json.loads(target.read_text(encoding="utf-8"))
    assert inbox["contract"] == "adler-worktree-inbox-v1"
    assert inbox["writer_identity"] == server.IDENTITY
    assert inbox["delivery_mode"] == "grabowski_owned_symlink_to_adler_state"
    assert inbox["checkpoint"] == OID_A
    assert [item["finding_id"] for item in inbox["findings"]] == [result["finding_id"]]
    assert os.readlink(worktree / ".adler" / "inbox.json") == str(target)


def test_sidecar_rejects_symlink_escape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"; worktree.mkdir()
    outside = tmp_path / "outside"; outside.mkdir()
    (worktree / ".adler").symlink_to(outside, target_is_directory=True)
    lane_id = "4" * 32
    monkeypatch.setattr(server, "_read_work_target", lambda lane: {
        "lane_id": lane, "repository": "fixture", "worktree": str(worktree), "branch": "feature",
        "purpose": "fixture", "base_head": OID_B, "checkpoint": OID_A, "source": "fixture", "observed_at": "fixture",
    })
    with pytest.raises(RuntimeError, match="unsafe .adler"):
        server.publish_worktree_inbox(lane_id)
    assert list(outside.iterdir()) == []


def test_recheck_preserves_history_and_removes_no_longer_current_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "6" * 32
    target = _install_pointer(worktree, state, lane_id)
    checkpoint = {"value": OID_A}
    monkeypatch.setattr(server, "_read_work_target", lambda lane: {
        "lane_id": lane, "repository": "fixture", "worktree": str(worktree), "branch": "feature",
        "purpose": "fixture", "base_head": OID_B, "checkpoint": checkpoint["value"], "source": "fixture", "observed_at": "fixture",
    })
    first = server.submit_finding(**_finding_args(subject=f"lane:{lane_id}", checkpoint=OID_A))
    original_path = state / "findings" / f"{first['finding_id']}.json"
    before = original_path.read_bytes()
    checkpoint["value"] = OID_B
    second = server.submit_finding(**_finding_args(
        kind="observation", severity="low", subject=f"lane:{lane_id}", checkpoint=OID_B,
        summary="Rechecked and no longer reproduced.", recheck_of=first["finding_id"], conclusion="no_longer_reproduced",
    ))
    assert second["delivery"]["state"] == "published"
    assert original_path.read_bytes() == before
    assert len(list((state / "findings").glob("*.json"))) == 2
    inbox = json.loads(target.read_text(encoding="utf-8"))
    assert inbox["checkpoint"] == OID_B
    assert inbox["findings"] == []


def test_incomplete_finding_store_refuses_complete_inbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "9" * 32
    target = _install_pointer(worktree, state, lane_id)
    findings = state / "findings"; findings.mkdir(mode=0o700)
    bad = findings / "broken.json"; bad.write_text("{broken", encoding="utf-8"); bad.chmod(0o600)
    monkeypatch.setattr(server, "_read_work_target", lambda lane: {
        "lane_id": lane, "repository": "fixture", "worktree": str(worktree), "branch": "feature",
        "purpose": "fixture", "base_head": OID_B, "checkpoint": OID_A, "source": "fixture", "observed_at": "fixture",
    })
    with pytest.raises(RuntimeError, match="finding store observation is incomplete"):
        server.publish_worktree_inbox(lane_id)
    assert not target.exists()


def test_worktree_root_limits_delivery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    allowed = tmp_path / "allowed"; allowed.mkdir()
    worktree = tmp_path / "outside"; worktree.mkdir()
    monkeypatch.setattr(server, "WORKTREE_ROOT", allowed.resolve())
    lane_id = "a" * 32
    monkeypatch.setattr(server, "_read_work_target", lambda lane: {
        "lane_id": lane, "repository": "fixture", "worktree": str(worktree), "branch": "feature",
        "purpose": "fixture", "base_head": OID_B, "checkpoint": OID_A, "source": "fixture", "observed_at": "fixture",
    })
    with pytest.raises(PermissionError, match="outside Adler's delivery worktree root"):
        server.publish_worktree_inbox(lane_id)
    assert not (worktree / ".adler").exists()
    assert not (state / "worktree-inboxes").exists()


def test_delivery_failure_keeps_finding_durable_and_does_not_create_pointer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"; worktree.mkdir()
    lane_id = "7" * 32
    monkeypatch.setattr(server, "_read_work_target", lambda lane: {
        "lane_id": lane, "repository": "fixture", "worktree": str(worktree), "branch": "feature",
        "purpose": "fixture", "base_head": OID_B, "checkpoint": OID_A, "source": "fixture", "observed_at": "fixture",
    })
    result = server.submit_finding(**_finding_args(subject=f"lane:{lane_id}"))
    assert result["accepted"] is True
    assert result["delivery"]["state"] == "delivery_failed"
    assert result["delivery"]["source_complete"] is False
    assert result["delivery"]["finding_remains_durable"] is True
    assert (state / "findings" / f"{result['finding_id']}.json").exists()
    assert not (worktree / ".adler").exists()


def test_finding_short_write_does_not_install_truncated_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    real_write = server.os.write

    def short_write(fd: int, data) -> int:
        raw = bytes(data)
        if len(raw) > 1:
            raw = raw[: max(1, len(raw) // 2)]
        return real_write(fd, raw)

    monkeypatch.setattr(server.os, "write", short_write)
    result = server.submit_finding(**_finding_args())
    path = state / "findings" / f"{result['finding_id']}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["finding_sha256"] == result["finding_sha256"]
    server._validate_v1_finding_payload(payload, path)


def test_finding_digest_mismatch_cannot_be_published_as_complete_empty_view(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "c" * 32
    target = _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(server, "_read_work_target", lambda lane: {
        "lane_id": lane, "repository": "fixture", "worktree": str(worktree), "branch": "feature",
        "purpose": "fixture", "base_head": OID_B, "checkpoint": OID_A, "source": "fixture", "observed_at": "fixture",
    })
    submitted = server.submit_finding(**_finding_args(subject=f"lane:{lane_id}", checkpoint=OID_A))
    before_inbox = target.read_bytes()
    finding = state / "findings" / f"{submitted['finding_id']}.json"
    payload = json.loads(finding.read_text(encoding="utf-8"))
    payload["checkpoint"] = OID_B
    finding.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    finding.chmod(0o600)

    with pytest.raises(RuntimeError, match="finding store observation is incomplete"):
        server.publish_worktree_inbox(lane_id)
    assert target.read_bytes() == before_inbox
    listing = server.list_findings(limit=10)
    assert listing["source_complete"] is False


def test_finding_install_is_atomic_when_final_noreplace_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)

    def fail_final_install(*args, **kwargs):
        raise OSError("fixture install failure")

    monkeypatch.setattr(server, "_rename_noreplace", fail_final_install)
    with pytest.raises(OSError, match="fixture install failure"):
        server.submit_finding(**_finding_args())
    findings = state / "findings"
    assert list(findings.glob("*.json")) == []
    assert list(findings.glob(".finding-*.tmp")) == []


def test_inbox_snapshot_waits_for_external_inbox_store_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "b" * 32
    target = _install_pointer(worktree, state, lane_id)
    target.parent.mkdir(mode=0o700)
    monkeypatch.setattr(server, "_read_work_target", lambda lane: {
        "lane_id": lane, "repository": "fixture", "worktree": str(worktree), "branch": "feature",
        "purpose": "fixture", "base_head": OID_B, "checkpoint": OID_A, "source": "fixture", "observed_at": "fixture",
    })
    entered_projection = threading.Event()
    real_projection = server._current_lane_findings
    def observed_projection(lane: str, checkpoint: str):
        entered_projection.set()
        return real_projection(lane, checkpoint)
    monkeypatch.setattr(server, "_current_lane_findings", observed_projection)
    lock_fd = server.os.open(target.parent, server.os.O_RDONLY | server.os.O_DIRECTORY | server.os.O_CLOEXEC)
    server.fcntl.flock(lock_fd, server.fcntl.LOCK_EX)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(server.publish_worktree_inbox, lane_id)
            assert entered_projection.wait(0.1) is False
            assert not target.exists()
            server.fcntl.flock(lock_fd, server.fcntl.LOCK_UN)
            result = future.result(timeout=2)
    finally:
        server.os.close(lock_fd)
    assert entered_projection.is_set()
    assert result["state"] == "published"


def test_recheck_chain_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_state(tmp_path, monkeypatch)
    root = server.submit_finding(**_finding_args(subject="repo:fixture"))
    recheck = server.submit_finding(**_finding_args(
        kind="observation", severity="low", subject="repo:fixture", checkpoint=OID_B,
        recheck_of=root["finding_id"], conclusion="still_current",
    ))
    with pytest.raises(ValueError, match="root finding"):
        server.submit_finding(**_finding_args(
            kind="observation", severity="low", subject="repo:fixture", checkpoint=OID_C,
            recheck_of=recheck["finding_id"], conclusion="still_current",
        ))