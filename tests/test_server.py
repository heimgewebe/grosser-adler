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
    with pytest.raises(ValueError):
        server._validate_unit("ssh.timer")


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


@pytest.mark.parametrize(
    "repo",
    [
        "heimgewebe/grosser-adler",
        "heimgewebe/.github",
        "a/b",
        "Owner-1/repo_name.v2",
    ],
)
def test_github_repo_accepts_canonical_owner_and_name(repo: str) -> None:
    owner, name = server._split_github_repo(repo)
    assert f"{owner}/{name}" == repo


@pytest.mark.parametrize(
    "repo",
    [
        "../..",
        "foo/..",
        "../bar",
        "./x",
        "foo/.",
        "-owner/repo",
        "owner/-repo",
        "owner/repo/extra",
        "owner//repo",
        "/owner/repo",
        "owner/repo/",
        "owner",
        "",
        "owner/re%2Fpo",
        "owner%2Frepo",
        "owner/repo%00",
        "own er/repo",
        "owner/repo\n",
        "owner/re\npo",
        "owner-/repo",
        "own/er/repo",
        "..%2F..",
    ],
)
def test_github_repo_rejects_traversal_and_boundary_tricks(repo: str) -> None:
    with pytest.raises(ValueError):
        server._split_github_repo(repo)


def test_github_repo_rejects_non_string() -> None:
    for value in (None, 7, ["heimgewebe", "grosser-adler"]):
        with pytest.raises(ValueError):
            server._split_github_repo(value)


def test_accepted_github_repo_cannot_escape_the_repos_api_prefix() -> None:
    # Every accepted identifier must expand to exactly repos/<owner>/<name>/...
    for repo in ("heimgewebe/grosser-adler", "heimgewebe/.github", "a/b"):
        owner, name = server._split_github_repo(repo)
        path = f"repos/{owner}/{name}/pulls/1/reviews"
        assert path.count("/") == 5
        assert ".." not in path.split("/")
        assert "." not in path.split("/")
        assert "%" not in path


def test_github_pr_rejects_traversal_before_any_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []
    monkeypatch.setattr(server, "_run", lambda argv, **kwargs: calls.append(argv))
    with pytest.raises(ValueError):
        server.github_pr("../..", 1)
    assert calls == []


def test_github_pr_requests_base_oid(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return {"returncode": 0, "stdout": "{}", "stderr": ""}

    monkeypatch.setattr(server, "_run", fake_run)
    result = server.github_pr("heimgewebe/grosser-adler", 2)

    assert len(calls) == 3
    fields = calls[0][calls[0].index("--json") + 1].split(",")
    assert "headRefOid" in fields
    assert "baseRefOid" in fields
    assert calls[1][2] == "repos/heimgewebe/grosser-adler/pulls/2/reviews"
    assert calls[1][-1] == "--paginate"
    assert calls[2][2] == "repos/heimgewebe/grosser-adler/pulls/2/comments"
    assert calls[2][-1] == "--paginate"
    assert result["review_comments"]["returncode"] == 0
    assert "inline review comments" in (server.github_pr.__doc__ or "")


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
            "stderr_truncated": False, "rows_intact": True,
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
        "stderr": "", "stdout_truncated": False, "stderr_truncated": False, "rows_intact": True,
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
        "stderr_truncated": False, "rows_intact": True,
    })
    result = server._process_snapshot(100, "/user.slice/nixer")
    assert result["parse_complete"] is False
    assert result["complete"] is False
    assert result["processes"] == []


def _systemctl_stdout(monkeypatch: pytest.MonkeyPatch, stdout: str, stderr: str = "") -> None:
    def fake_run(*args, **kwargs):
        return server.subprocess.CompletedProcess(args[0], 0, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(server.subprocess, "run", fake_run)


def test_redact_still_rewrites_secret_shaped_text_without_any_literal_exception() -> None:
    unit = "grabowski-task-" + ("a" * 24) + "-a1.service"
    token = "sk-" + ("b" * 24)
    # The unit name is only protected by structural parsing, never by _redact.
    assert server._redact(unit) != unit
    assert server._redact(f"api_key: {token}") == "<REDACTED>"
    assert server._redact(unit, exact_secrets=(unit,)) == "<REDACTED>"
    assert not hasattr(server, "_SAFE_REDACTION_LITERAL_PATTERNS")


def test_list_user_services_keeps_canonical_grabowski_unit_identity_exact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unit = "grabowski-task-" + ("c" * 24) + "-a1.service"
    _systemctl_stdout(monkeypatch, f"{unit} loaded active running Grabowski task\n")
    result = server.list_user_services()
    assert result["observation_complete"] is True
    assert [item["unit"] for item in result["services"]] == [unit]


@pytest.mark.parametrize(
    "unit",
    [
        # Not covered by the removed whitelist: different suffix, different id
        # length, and a name whose "sk-" run alone matches the OpenAI pattern.
        "grabowski-task-" + ("d" * 24) + "-b2.service",
        "grabowski-task-" + ("e" * 32) + "-a1.service",
        "my-desk-" + ("f" * 24) + ".service",
    ],
)
def test_list_user_services_preserves_secret_shaped_but_legitimate_unit_names(
    monkeypatch: pytest.MonkeyPatch, unit: str
) -> None:
    # Each of these is rewritten by raw secret redaction; structural parsing
    # must still report the whole listing with byte-exact unit identity.
    assert server._redact(unit) != unit
    _systemctl_stdout(monkeypatch, f"{unit} loaded active running Example unit\n")
    result = server.list_user_services()
    assert result["observation_complete"] is True
    assert result["parse_complete"] is True
    assert result["services"] == [{
        "unit": unit,
        "load": "loaded",
        "active": "active",
        "sub": "running",
        "description": "Example unit",
    }]


def test_list_user_services_redacts_secrets_in_the_description_column(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unit = "nixer-mcp.service"
    token = "ghp_" + ("g" * 24)
    _systemctl_stdout(
        monkeypatch,
        f"{unit} loaded active running Nixer token: {token}\n",
        stderr=f"warning {token}\n",
    )
    result = server.list_user_services()
    assert result["services"] == [{
        "unit": unit,
        "load": "loaded",
        "active": "active",
        "sub": "running",
        "description": "Nixer <REDACTED>",
    }]
    assert token not in result["source"]["stdout"]
    assert token not in result["source"]["stderr"]
    assert token not in json.dumps(result)


def test_list_user_services_marks_bullet_and_malformed_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unit = "nixer-mcp.service"
    _systemctl_stdout(monkeypatch, f"\u25cf {unit} loaded failed failed Nixer\n")
    result = server.list_user_services()
    assert result["observation_complete"] is True
    assert result["services"][0]["unit"] == unit
    assert result["services"][0]["active"] == "failed"

    _systemctl_stdout(monkeypatch, f"{unit} loaded active running Nixer\nmalformed-row\n")
    result = server.list_user_services()
    assert result["parse_complete"] is False
    assert result["observation_complete"] is False
    assert result["services"] == []


def test_list_user_services_fails_closed_on_non_structural_state_columns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A state column that is not systemd state vocabulary is never emitted.
    _systemctl_stdout(
        monkeypatch, "nixer-mcp.service loaded active token:leak Nixer\n"
    )
    result = server.list_user_services()
    assert result["parse_complete"] is False
    assert result["observation_complete"] is False
    assert result["services"] == []


def test_systemd_reads_preserve_unit_identity_in_every_column(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Regression for the sibling paths of audit finding 1: service_status and
    # service_logs parse the same redacted text list_user_services does.
    unit = "grabowski-task-" + ("a" * 24) + "-a1.service"
    assert server._redact(unit) != unit
    properties = "".join(
        f"{key}={value}\n"
        for key, value in (
            ("LoadState", "loaded"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("Result", "success"),
            ("ExecMainCode", "0"),
            ("ExecMainStatus", "0"),
            ("MainPID", "123"),
            ("FragmentPath", f"/home/alex/.config/systemd/user/{unit}"),
            ("NRestarts", "0"),
            ("ActiveEnterTimestamp", "x"),
            ("ExecMainStartTimestamp", "y"),
            ("ControlGroup", f"/user.slice/app.slice/{unit}"),
            ("MemoryCurrent", "1"),
            ("TasksCurrent", "1"),
            ("CPUUsageNSec", "1"),
        )
    )
    _systemctl_stdout(monkeypatch, properties)
    observation = server._observe_service_scope(unit, "user")
    assert observation["observation_complete"] is True
    assert observation["properties"]["FragmentPath"].endswith(unit)
    assert observation["properties"]["ControlGroup"].endswith(unit)

    _systemctl_stdout(monkeypatch, f"-- Logs begin --\nJan 01 00:00:00 host {unit}: started\n")
    logs = server._run(["/usr/bin/journalctl"], preserved_identity=(unit,))
    assert unit in logs["stdout"]


def test_structured_unit_claim_matches_the_raw_source_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An auditor must be able to cross-check services[].unit against source.stdout.
    unit = "grabowski-task-" + ("b" * 24) + "-a1.service"
    token = "sk-" + ("c" * 30)
    _systemctl_stdout(monkeypatch, f"{unit} loaded active running Task api_key: {token}\n")
    result = server.list_user_services()
    assert result["services"][0]["unit"] == unit
    assert unit in result["source"]["stdout"]
    assert result["services"][0]["description"] == "Task <REDACTED>"
    assert token not in json.dumps(result)


def test_redaction_never_merges_rows_across_a_newline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A description ending in "password:" used to swallow the next row, so a
    # unit disappeared while the listing still claimed to be complete.
    _systemctl_stdout(
        monkeypatch,
        "a.service loaded active running Nixer password:\n"
        "b.service loaded active running Second unit\n"
        "c.service loaded active running Third unit\n",
    )
    result = server.list_user_services()
    # The physical line break survives, but b.service's structured identity
    # does not. rows_intact therefore fails even though the newline count still
    # matches: physical line count alone is not a completeness proof.
    assert result["source"]["rows_intact"] is False
    assert len(result["source"]["stdout"].splitlines()) == 3
    assert result["observation_complete"] is False
    assert result["services"] == []
    # Journal text is affected by the same pattern. The value that follows the
    # keyword is still redacted even across the newline, but the newline is
    # re-emitted, so the second record stays a record instead of disappearing.
    redacted = server._redact("Jan 01 host: password:\nJan 02 host: next")
    assert len(redacted.splitlines()) == 2
    assert "<REDACTED>" in redacted
    assert "password:" not in redacted
    # Same-line assignments are still redacted, with or without whitespace.
    assert server._redact("password: hunter2") == "<REDACTED>"
    assert server._redact("api_key:abc123") == "<REDACTED>"
    assert server._redact("Authorization\t=\tBearer-xyz") == "<REDACTED>"


def test_list_user_services_preserves_rows_across_multiline_secret_redaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A multi-line private-key block legitimately collapses lines; the row-count
    # invariant must then refuse to publish a short inventory.
    key = "-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----"
    _systemctl_stdout(
        monkeypatch,
        f"a.service loaded active running {key}\nb.service loaded active running Second\n",
    )
    result = server.list_user_services()
    # The block spans three lines; re-emitting its newlines keeps both units
    # addressable instead of collapsing the listing.
    assert [item["unit"] for item in result["services"]] == ["a.service", "b.service"]
    assert result["observation_complete"] is True
    assert "MIIabc" not in json.dumps(result)


def test_list_user_services_fails_closed_if_private_key_spans_complete_unit_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Regression for a multi-line secret whose match starts in one unit row,
    # consumes complete following unit rows, and ends inside another unit row.
    raw = (
        "a.service loaded active running -----BEGIN PRIVATE KEY-----\n"
        "b.service loaded active running Second\n"
        "c.service loaded active running -----END PRIVATE KEY-----\n"
        "d.service loaded active running Fourth\n"
    )
    _systemctl_stdout(monkeypatch, raw)
    result = server.list_user_services()

    assert result["source"]["rows_intact"] is False
    assert result["parse_complete"] is False
    assert result["observation_complete"] is False
    assert result["services"] == []
    encoded = json.dumps(result)
    assert "PRIVATE KEY" not in encoded
    assert "b.service" not in result["source"]["stdout"]
    assert "c.service" not in result["source"]["stdout"]


def test_run_reports_the_raw_row_count_and_proves_rows_survived(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _systemctl_stdout(monkeypatch, "one\n\ntwo\nthree\n")
    result = server._run(["/usr/bin/true"])
    assert result["stdout_line_count"] == 4
    assert result["rows_intact"] is True

    key = "-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----"
    _systemctl_stdout(monkeypatch, f"first\n{key}\nlast\n")
    result = server._run(["/usr/bin/true"])
    assert result["rows_intact"] is True
    assert len(result["stdout"].splitlines()) == 5
    assert "MIIabc" not in result["stdout"]


def test_derived_identity_is_scoped_to_the_stream_it_was_read_from(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # list_user_services derives identity from the listing's first column.
    # stderr was never inspected by that extractor, so it must not inherit the
    # exemption.
    credential_named_unit = "ghp_" + ("A" * 24) + ".service"
    _systemctl_stdout(
        monkeypatch,
        f"{credential_named_unit} loaded active running desc\n",
        stderr=f"warning {credential_named_unit}\n",
    )
    result = server.list_user_services()
    assert credential_named_unit not in result["source"]["stderr"]
    assert "<REDACTED>" in result["source"]["stderr"]
    # Documented residual risk of the column-bound mode: a unit whose own name
    # is credential-shaped is reported verbatim in the identity column.
    assert result["services"][0]["unit"] == credential_named_unit


def test_service_logs_fails_closed_when_redaction_changes_the_row_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if "show" in argv:
            stdout = (
                _complete_service_show_fixture()
                if "--user" in argv
                else _missing_system_service_show_fixture()
            )
            return {
                "returncode": 0,
                "stdout": stdout,
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False, "rows_intact": True,
            }
        return {
            "returncode": 0,
            "stdout": "Jan 01 h u: a\n",
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
            "stdout_line_count": 3,
            "rows_intact": False,
        }

    monkeypatch.setattr(server, "_run", fake_run)
    result = server.service_logs("nixer-mcp.service")
    assert result["rows_intact"] is False
    assert result["observation_complete"] is False


def test_identity_exemption_is_bound_to_named_units_not_to_shape() -> None:
    unit = "grabowski-task-" + ("d" * 24) + "-a1.service"
    # The named, already-validated unit survives verbatim.
    assert server._redact(unit) != unit
    assert server._redact_preserving_identity(unit, preserved_identity=(unit,)) == unit
    assert (
        server._redact_preserving_identity(f"host {unit}: started", preserved_identity=(unit,))
        == f"host {unit}: started"
    )
    # Nothing is exempt merely for looking like a unit name. These reach the
    # caller through service_logs, which returns arbitrary application text.
    leaky = [
        "api_key:abc.service",
        "api_key: abc.service",
        "secret:sk-" + ("A" * 24) + ".service",
        "ghp_" + ("A" * 24) + ".service",
        "sk-" + ("A" * 24) + ".service",
        "github_pat_" + ("A" * 24) + ".service",
        "token=my-thing.service-secret",
    ]
    for probe in leaky:
        assert "<REDACTED>" in server._redact(probe)
        assert "<REDACTED>" in server._redact_preserving_identity(
            probe, preserved_identity=(unit,)
        )


def test_identity_exemption_yields_to_exact_and_spanning_secrets() -> None:
    unit = "grabowski-task-" + ("e" * 24) + "-a1.service"
    # A configured exact secret always wins, including one straddling the name.
    assert server._redact_preserving_identity(
        unit, exact_secrets=(unit,), preserved_identity=(unit,)
    ) == "<REDACTED>"
    straddling = f"tok-{unit}-tail"
    assert server._redact_preserving_identity(
        straddling, exact_secrets=(straddling,), preserved_identity=(unit,)
    ) == "<REDACTED>"
    # A pattern match reaching beyond the name is a real secret, not the
    # in-name false positive, so the name is not exempted out of it.
    spanning = f"password={unit}"
    assert "<REDACTED>" in server._redact_preserving_identity(
        spanning, preserved_identity=(unit,)
    )


def test_listed_unit_names_only_trusts_the_identity_column() -> None:
    unit = "grabowski-task-" + ("f" * 24) + "-a1.service"
    credential = "ghp_" + ("A" * 24) + ".service"
    text = f"{unit} loaded active running desc {credential}\n\u25cf {unit} loaded active running d\n"
    assert server._listed_unit_names(text) == (unit,)
    # A credential in the description column never becomes preserved identity.
    assert credential not in server._listed_unit_names(text)


def test_list_user_services_redacts_a_credential_in_the_description_column(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unit = "grabowski-task-" + ("g" * 24) + "-a1.service"
    credential = "ghp_" + ("A" * 24) + ".service"
    _systemctl_stdout(monkeypatch, f"{unit} loaded active running Task {credential}\n")
    result = server.list_user_services()
    assert result["services"][0]["unit"] == unit
    assert unit in result["source"]["stdout"]
    assert credential not in json.dumps(result)


def test_service_runtime_correlates_a_secret_shaped_unit_across_ps_and_ss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ControlGroup, the ps cgroup column and the ss cgroup field are compared
    # against each other, so all three must redact identically or the process
    # tree and listeners silently vanish for exactly the canonical task units.
    unit = "grabowski-task-" + ("a" * 24) + "-a1.service"
    assert server._redact(unit) != unit
    control_group = f"/user.slice/user-1000.slice/user@1000.service/app.slice/{unit}"
    properties = "".join(
        f"{key}={value}\n"
        for key, value in (
            ("LoadState", "loaded"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("Result", "success"),
            ("ExecMainCode", "0"),
            ("ExecMainStatus", "0"),
            ("MainPID", "4242"),
            ("FragmentPath", f"/home/alex/.config/systemd/user/{unit}"),
            ("NRestarts", "0"),
            ("ActiveEnterTimestamp", "x"),
            ("ExecMainStartTimestamp", "y"),
            ("ControlGroup", control_group),
            ("MemoryCurrent", "1"),
            ("TasksCurrent", "1"),
            ("CPUUsageNSec", "1"),
        )
    )
    absent = properties.replace("LoadState=loaded", "LoadState=not-found")
    process_row = f" 4242    1 {os.getuid()} Ss 10 100 0.1 python 0::{control_group}\n"
    socket_row = (
        f"tcp LISTEN 0 128 127.0.0.1:18186 0.0.0.0:* uid:1000 cgroup:{control_group}\n"
    )

    def fake_run(argv, **kwargs):
        joined = " ".join(argv)
        if "/usr/bin/ps" in joined:
            stdout = process_row
        elif "/usr/bin/ss" in joined:
            stdout = socket_row
        elif "--user" in argv:
            stdout = properties
        else:
            stdout = absent
        return server.subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(server.subprocess, "run", lambda *a, **k: fake_run(a[0], **k))
    result = server.service_runtime(unit)

    assert result["control_group"] == control_group
    assert len(result["processes"]) == 1
    assert result["processes"][0]["pid"] == 4242
    assert len(result["listeners"]) == 1
    assert result["missing_evidence"] == []
    assert result["complete"] is True


def test_service_runtime_fails_closed_when_socket_redaction_drops_a_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unit = "nixer-mcp.service"
    control_group = "/user.slice/app.slice/nixer-mcp.service"
    properties = "".join(
        f"{key}={value}\n"
        for key, value in (
            ("LoadState", "loaded"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("Result", "success"),
            ("ExecMainCode", "0"),
            ("ExecMainStatus", "0"),
            ("MainPID", "4242"),
            ("FragmentPath", f"/home/alex/.config/systemd/user/{unit}"),
            ("NRestarts", "0"),
            ("ActiveEnterTimestamp", "x"),
            ("ExecMainStartTimestamp", "y"),
            ("ControlGroup", control_group),
            ("MemoryCurrent", "1"),
            ("TasksCurrent", "1"),
            ("CPUUsageNSec", "1"),
        )
    )
    absent = properties.replace("LoadState=loaded", "LoadState=not-found")
    process_row = f"4242 1 {os.getuid()} Ss 10 100 0.1 python 0::{control_group}\n"
    socket_row = (
        f"tcp LISTEN 0 128 127.0.0.1:18186 0.0.0.0:* uid:1000 cgroup:{control_group}\n"
    )

    def fake_run(argv, **kwargs):
        if argv[0] == "/usr/bin/ps":
            return {
                "returncode": 0,
                "stdout": process_row,
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "rows_intact": True,
            }
        if argv[0] == "/usr/bin/ss":
            return {
                "returncode": 0,
                "stdout": socket_row,
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "rows_intact": False,
            }
        if argv[0] == "/usr/bin/systemctl":
            return {
                "returncode": 0,
                "stdout": properties if "--user" in argv else absent,
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "rows_intact": True,
            }
        raise AssertionError(argv)

    monkeypatch.setattr(server, "_run", fake_run)
    result = server.service_runtime(unit)

    assert result["processes"][0]["pid"] == 4242
    assert result["listeners"] == []
    assert result["listener_observation_complete"] is False
    assert "listeners" in result["missing_evidence"]
    assert result["complete"] is False


def test_list_user_services_never_returns_a_parsed_payload_past_the_output_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A parsed structure is evidence too: truncation must not be undone by it.
    rows = "".join(
        f"svc-{index:05d}.service loaded active running Description {index}\n"
        for index in range(4000)
    )
    assert len(rows.encode("utf-8")) > server.MAX_OUTPUT_BYTES
    _systemctl_stdout(monkeypatch, rows)
    result = server.list_user_services()

    assert result["source"]["stdout_truncated"] is True
    assert result["observation_complete"] is False
    assert result["parse_complete"] is False
    assert result["services"] == []
    # Nothing may reintroduce what truncation removed, in any field.
    encoded = len(json.dumps(result).encode("utf-8"))
    assert encoded < 2 * server.MAX_OUTPUT_BYTES
    assert "svc-03999.service" not in json.dumps(result)


def test_list_user_services_fails_closed_on_truncated_or_failed_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    observations = [
        {"returncode": 0, "stdout": "nixer-mcp.service loaded active running Nixer\n", "stderr": "", "stdout_truncated": True, "stderr_truncated": False, "rows_intact": True},
        {"returncode": 1, "stdout": "", "stderr": "failed", "stdout_truncated": False, "stderr_truncated": False, "rows_intact": True},
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
        "stderr_truncated": False, "rows_intact": True,
    })
    result = server.list_user_services()
    assert result["parse_complete"] is False
    assert result["observation_complete"] is False
    assert result["services"] == []


def test_service_status_fails_closed_on_truncated_or_failed_show(monkeypatch: pytest.MonkeyPatch) -> None:
    observations = [
        {"returncode": 0, "stdout": "ActiveState=active\nMainPID=100\n", "stderr": "", "stdout_truncated": True, "stderr_truncated": False, "rows_intact": True},
        {"returncode": 1, "stdout": "ActiveState=active\n", "stderr": "failed", "stdout_truncated": False, "stderr_truncated": False, "rows_intact": True},
    ]
    for observation in observations:
        monkeypatch.setattr(server, "_run", lambda argv, **kwargs: observation)
        result = server.service_status("nixer-mcp.service")
        assert result["observation_complete"] is False
        assert result["properties"] == {}


def test_service_status_fails_closed_on_missing_or_malformed_properties(monkeypatch: pytest.MonkeyPatch) -> None:
    observations = [
        {"returncode": 0, "stdout": "ActiveState=active\n", "stderr": "", "stdout_truncated": False, "stderr_truncated": False, "rows_intact": True},
        {"returncode": 0, "stdout": _complete_service_show_fixture() + "malformed-row\n", "stderr": "", "stdout_truncated": False, "stderr_truncated": False, "rows_intact": True},
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
            "stdout_truncated": False, "stderr_truncated": False, "rows_intact": True,
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
        "stderr_truncated": False, "rows_intact": True,
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
            "stderr_truncated": False, "rows_intact": True,
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
            "stderr_truncated": False, "rows_intact": True,
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
                "stdout_truncated": False, "stderr_truncated": False, "rows_intact": True,
            }
        if argv[0] == "/usr/bin/journalctl":
            assert "--user" not in argv
            assert "--system" in argv
            return {
                "returncode": 0, "stdout": "system-log\n", "stderr": "",
                "stdout_truncated": False, "stderr_truncated": False, "rows_intact": True,
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
                "stdout_truncated": False, "stderr_truncated": False, "rows_intact": True,
            }
        if argv[0] == "/usr/bin/journalctl":
            return {
                "returncode": 0,
                "stdout": "",
                "stderr": "Hint: journal access is restricted\n",
                "stdout_truncated": False,
                "stderr_truncated": False, "rows_intact": True,
            }
        raise AssertionError(argv)

    monkeypatch.setattr(server, "_run", fake_run)
    result = server.service_logs("grabowski-operator.service", lines=5)
    assert result["scope"] == "system"
    assert result["logs"]["returncode"] == 0
    assert result["journal_diagnostics_present"] is True
    assert result["observation_complete"] is False


def _proc_map_line(path: Path, *, permissions: str = "r-xp") -> str:
    metadata = path.stat()
    device = f"{os.major(metadata.st_dev):x}:{os.minor(metadata.st_dev):x}"
    return (
        f"7f000000-7f001000 {permissions} 00000000 {device} {metadata.st_ino} {path}\n"
    )


def _runtime_identity_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    release_attempt: int | None = None,
) -> dict[str, object]:
    release_id = (
        ("a" * 12)
        + "-srcset"
        + ("b" * 12)
        + "-lock"
        + ("c" * 12)
        + "-contract"
        + ("d" * 12)
    )
    if release_attempt is not None:
        release_id += f"-attempt{release_attempt}"
    repo_head = "a" * 40
    releases = tmp_path / "releases"
    release = releases / release_id
    mapped = (
        release
        / ".venv"
        / "lib"
        / "python3.10"
        / "site-packages"
        / "pydantic_core"
        / "_pydantic_core.so"
    )
    mapped.parent.mkdir(parents=True)
    mapped.write_bytes(b"mapped-runtime-fixture")
    mapped.chmod(0o644)

    executable = tmp_path / "python3.10"
    executable.write_bytes(b"python-fixture")
    executable.chmod(0o755)
    release_python = release / ".venv" / "bin" / "python"
    release_python.parent.mkdir(parents=True)
    release_python.symlink_to(executable)

    stable_runtime = tmp_path / "grabowski-mcp"
    stable_python = stable_runtime / ".venv" / "bin" / "python"
    stable_python.parent.mkdir(parents=True)
    stable_python.symlink_to(executable)

    entrypoint = (
        release
        / ".venv"
        / "lib"
        / "python3.10"
        / "site-packages"
        / "grabowski_operator.py"
    )
    entrypoint.write_text("# fixture\n", encoding="utf-8")
    entrypoint.chmod(0o644)

    manifest = {
        "schema_version": 1,
        "release_id": release_id,
        "repo_head": repo_head,
        "immutable_release_path": str(release),
        "executable": str(release_python),
        "entrypoint_path": str(entrypoint),
        "entrypoint_contract": {"mode": "module", "module": "grabowski_operator"},
        "module_paths": {"grabowski_operator": str(entrypoint)},
        "completion_status": "complete",
    }
    manifest_path = release / "deployment-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o600)

    proc_root = tmp_path / "proc"
    pid = 4242
    proc_pid = proc_root / str(pid)
    proc_pid.mkdir(parents=True)
    control_group = "/system.slice/grabowski-operator.service"
    (proc_pid / "cgroup").write_text(f"0::{control_group}\n", encoding="utf-8")
    (proc_pid / "maps").write_text(_proc_map_line(mapped), encoding="utf-8")
    (proc_pid / "exe").symlink_to(executable)
    (proc_pid / "cmdline").write_bytes(
        str(stable_python).encode("utf-8")
        + b"\x00-m\x00grabowski_operator"
        + b"\x00--transport\x00streamable-http"
        + b"\x00--host\x00127.0.0.1"
        + b"\x00--port\x0018181\x00"
    )

    monkeypatch.setattr(server, "PROC_ROOT", proc_root)
    monkeypatch.setattr(server, "GRABOWSKI_RELEASE_ROOT", releases)
    monkeypatch.setattr(server, "GRABOWSKI_STABLE_RUNTIME_ROOT", stable_runtime)
    return {
        "pid": pid,
        "proc_pid": proc_pid,
        "control_group": control_group,
        "release_id": release_id,
        "repo_head": repo_head,
        "release": release,
        "release_python": release_python,
        "stable_python": stable_python,
        "entrypoint": entrypoint,
        "manifest_path": manifest_path,
        "mapped": mapped,
        "executable": executable,
        "releases": releases,
    }


def test_runtime_identity_reports_process_bound_release_but_not_manifest_only_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _runtime_identity_fixture(tmp_path, monkeypatch)
    result = server._runtime_identity_observation(
        fixture["pid"],
        fixture["control_group"],
    )

    assert result["identity_complete"] is False
    assert result["release_id"] == fixture["release_id"]
    assert result["source_commit_or_repo_head"] is None
    assert result["executable_path_or_identity"] == str(fixture["executable"])
    assert result["identity_source"] == [
        "systemd_main_pid_control_group",
        "procfs_cgroup",
        "procfs_exe",
        "procfs_maps_immutable_release",
        "immutable_release_manifest",
        "procfs_cmdline_manifest_entrypoint",
        "release_manifest_commit_attestation_not_primary_evidence",
    ]
    assert result["missing_evidence"] == ["source_commit_primary_evidence"]


def test_runtime_identity_accepts_retry_release_identifier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _runtime_identity_fixture(
        tmp_path,
        monkeypatch,
        release_attempt=1,
    )

    result = server._runtime_identity_observation(
        fixture["pid"],
        fixture["control_group"],
    )

    assert result["identity_complete"] is False
    assert result["release_id"] == fixture["release_id"]
    assert result["source_commit_or_repo_head"] is None
    assert result["missing_evidence"] == ["source_commit_primary_evidence"]


def test_runtime_identity_rejects_same_release_with_different_module_entrypoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _runtime_identity_fixture(tmp_path, monkeypatch)
    (fixture["proc_pid"] / "cmdline").write_bytes(
        str(fixture["stable_python"]).encode("utf-8")
        + b"\x00-m\x00other_operator"
        + b"\x00--transport\x00streamable-http"
        + b"\x00--host\x00127.0.0.1"
        + b"\x00--port\x0018181\x00"
    )

    result = server._runtime_identity_observation(
        fixture["pid"],
        fixture["control_group"],
    )

    assert result["identity_complete"] is False
    assert result["release_id"] is None
    assert result["source_commit_or_repo_head"] is None
    assert result["missing_evidence"] == ["process_entrypoint_binding"]


def test_runtime_identity_rejects_missing_process_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _runtime_identity_fixture(tmp_path, monkeypatch)
    (fixture["proc_pid"] / "cmdline").unlink()

    result = server._runtime_identity_observation(
        fixture["pid"],
        fixture["control_group"],
    )

    assert result["identity_complete"] is False
    assert result["release_id"] is None
    assert result["missing_evidence"] == ["proc_cmdline"]


def test_runtime_identity_rejects_unrelated_service_unit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _runtime_identity_fixture(tmp_path, monkeypatch)

    result = server._runtime_identity_observation(
        fixture["pid"],
        fixture["control_group"],
        unit="nixer-mcp.service",
    )

    assert result["identity_complete"] is False
    assert result["release_id"] is None
    assert result["source_commit_or_repo_head"] is None
    assert result["missing_evidence"] == ["grabowski_runtime_unit"]


def test_runtime_identity_rejects_wrong_launcher_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _runtime_identity_fixture(tmp_path, monkeypatch)
    wrong_launcher = tmp_path / "mutable-checkout-python"
    (fixture["proc_pid"] / "cmdline").write_bytes(
        str(wrong_launcher).encode("utf-8")
        + b"\x00-m\x00grabowski_operator"
        + b"\x00--transport\x00streamable-http"
        + b"\x00--host\x00127.0.0.1"
        + b"\x00--port\x0018181\x00"
    )

    result = server._runtime_identity_observation(
        fixture["pid"],
        fixture["control_group"],
    )

    assert result["identity_complete"] is False
    assert result["release_id"] is None
    assert result["source_commit_or_repo_head"] is None
    assert result["missing_evidence"] == ["process_entrypoint_binding"]


def test_runtime_identity_accepts_green_release_launcher_as_partial_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _runtime_identity_fixture(tmp_path, monkeypatch)
    (fixture["proc_pid"] / "cmdline").write_bytes(
        str(fixture["release_python"]).encode("utf-8")
        + b"\x00-m\x00grabowski_operator"
        + b"\x00--transport\x00streamable-http"
        + b"\x00--host\x00127.0.0.1"
        + b"\x00--port\x0018182\x00"
    )

    result = server._runtime_identity_observation(
        fixture["pid"],
        fixture["control_group"],
        unit="grabowski-green-operator-deadbeefcafe.service",
    )

    assert result["identity_complete"] is False
    assert result["release_id"] == fixture["release_id"]
    assert result["source_commit_or_repo_head"] is None
    assert result["missing_evidence"] == ["source_commit_primary_evidence"]


def test_runtime_identity_rejects_unknown_extra_runtime_argument(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _runtime_identity_fixture(tmp_path, monkeypatch)
    cmdline = (fixture["proc_pid"] / "cmdline").read_bytes()
    (fixture["proc_pid"] / "cmdline").write_bytes(
        cmdline[:-1] + b"\x00--extra\x00unexpected\x00"
    )

    result = server._runtime_identity_observation(
        fixture["pid"],
        fixture["control_group"],
    )

    assert result["identity_complete"] is False
    assert result["release_id"] is None
    assert result["missing_evidence"] == ["process_entrypoint_binding"]


def test_runtime_identity_rejects_missing_expected_runtime_argument(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _runtime_identity_fixture(tmp_path, monkeypatch)
    (fixture["proc_pid"] / "cmdline").write_bytes(
        str(fixture["stable_python"]).encode("utf-8")
        + b"\x00-m\x00grabowski_operator"
        + b"\x00--transport\x00streamable-http"
        + b"\x00--host\x00127.0.0.1\x00"
    )

    result = server._runtime_identity_observation(
        fixture["pid"],
        fixture["control_group"],
    )

    assert result["identity_complete"] is False
    assert result["release_id"] is None
    assert result["missing_evidence"] == ["process_entrypoint_binding"]


def test_runtime_identity_rejects_non_executable_release_mapping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _runtime_identity_fixture(tmp_path, monkeypatch)
    (fixture["proc_pid"] / "maps").write_text(
        _proc_map_line(fixture["mapped"], permissions="r--p"),
        encoding="utf-8",
    )

    result = server._runtime_identity_observation(
        fixture["pid"],
        fixture["control_group"],
    )
    assert result["identity_complete"] is False
    assert result["release_id"] is None
    assert result["missing_evidence"] == [
        "immutable_release_mapping_invalid_or_ambiguous"
    ]


def test_runtime_identity_rejects_cgroup_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _runtime_identity_fixture(tmp_path, monkeypatch)
    (fixture["proc_pid"] / "cgroup").write_text(
        "0::/system.slice/other.service\n",
        encoding="utf-8",
    )

    result = server._runtime_identity_observation(
        fixture["pid"],
        fixture["control_group"],
    )
    assert result["identity_complete"] is False
    assert result["release_id"] is None
    assert result["missing_evidence"] == ["proc_cgroup"]


def test_runtime_identity_rejects_similar_but_invalid_release_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _runtime_identity_fixture(tmp_path, monkeypatch)
    invalid_release = fixture["releases"] / (fixture["release_id"] + "x")
    invalid_mapped = invalid_release / ".venv/lib/python3.10/site-packages/core.so"
    invalid_mapped.parent.mkdir(parents=True)
    invalid_mapped.write_bytes(b"invalid-release-name")
    invalid_mapped.chmod(0o644)
    (fixture["proc_pid"] / "maps").write_text(
        _proc_map_line(invalid_mapped),
        encoding="utf-8",
    )

    result = server._runtime_identity_observation(
        fixture["pid"],
        fixture["control_group"],
    )
    assert result["identity_complete"] is False
    assert result["release_id"] is None
    assert result["missing_evidence"] == [
        "immutable_release_mapping_invalid_or_ambiguous"
    ]


def test_runtime_identity_rejects_ambiguous_release_mappings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _runtime_identity_fixture(tmp_path, monkeypatch)
    second_id = (
        ("e" * 12)
        + "-srcset"
        + ("f" * 12)
        + "-lock"
        + ("1" * 12)
        + "-contract"
        + ("2" * 12)
    )
    second = fixture["releases"] / second_id / ".venv/lib/python3.10/site-packages/core.so"
    second.parent.mkdir(parents=True)
    second.write_bytes(b"second-release")
    second.chmod(0o644)
    maps = _proc_map_line(fixture["mapped"]) + _proc_map_line(second)
    (fixture["proc_pid"] / "maps").write_text(maps, encoding="utf-8")

    result = server._runtime_identity_observation(
        fixture["pid"],
        fixture["control_group"],
    )
    assert result["identity_complete"] is False
    assert result["missing_evidence"] == [
        "immutable_release_mapping_invalid_or_ambiguous"
    ]


@pytest.mark.parametrize(
    "variant",
    ["group_writable", "deleted", "non_executable", "replaced_inode"],
)
def test_runtime_identity_rejects_second_release_even_when_its_mapping_is_invalid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    variant: str,
) -> None:
    fixture = _runtime_identity_fixture(tmp_path, monkeypatch)
    second_id = (
        ("e" * 12)
        + "-srcset"
        + ("f" * 12)
        + "-lock"
        + ("1" * 12)
        + "-contract"
        + ("2" * 12)
    )
    second = fixture["releases"] / second_id / ".venv/lib/python3.10/site-packages/core.so"
    second.parent.mkdir(parents=True)
    second.write_bytes(b"second-release")
    second.chmod(0o644)

    permissions = "r-xp"
    if variant == "group_writable":
        second.chmod(0o664)
    elif variant == "non_executable":
        permissions = "rw-p"

    second_line = _proc_map_line(second, permissions=permissions)
    if variant == "deleted":
        second_line = second_line.rstrip("\n") + " (deleted)\n"
    elif variant == "replaced_inode":
        second.unlink()
        second.write_bytes(b"replacement-inode")
        second.chmod(0o644)

    maps = _proc_map_line(fixture["mapped"]) + second_line
    (fixture["proc_pid"] / "maps").write_text(maps, encoding="utf-8")

    result = server._runtime_identity_observation(
        fixture["pid"],
        fixture["control_group"],
    )

    assert result["identity_complete"] is False
    assert result["release_id"] is None
    assert result["source_commit_or_repo_head"] is None
    assert result["missing_evidence"] == [
        "immutable_release_mapping_invalid_or_ambiguous"
    ]


def test_runtime_identity_rejects_missing_release_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _runtime_identity_fixture(tmp_path, monkeypatch)
    fixture["manifest_path"].unlink()

    result = server._runtime_identity_observation(
        fixture["pid"],
        fixture["control_group"],
    )
    assert result["identity_complete"] is False
    assert result["missing_evidence"] == ["release_manifest"]


def test_runtime_identity_rejects_unexpected_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _runtime_identity_fixture(tmp_path, monkeypatch)
    other_executable = tmp_path / "other-python"
    other_executable.write_bytes(b"other")
    other_executable.chmod(0o755)
    proc_exe = fixture["proc_pid"] / "exe"
    proc_exe.unlink()
    proc_exe.symlink_to(other_executable)

    result = server._runtime_identity_observation(
        fixture["pid"],
        fixture["control_group"],
    )
    assert result["identity_complete"] is False
    assert result["release_id"] is None
    assert result["missing_evidence"] == ["release_manifest_paths"]


def test_runtime_identity_fails_closed_when_executable_identity_needs_redaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _runtime_identity_fixture(tmp_path, monkeypatch)
    secret_executable = tmp_path / ("token=" + ("s" * 32))
    secret_executable.write_bytes(b"secret-path")
    secret_executable.chmod(0o755)

    release_python = fixture["release_python"]
    release_python.unlink()
    release_python.symlink_to(secret_executable)
    proc_exe = fixture["proc_pid"] / "exe"
    proc_exe.unlink()
    proc_exe.symlink_to(secret_executable)

    result = server._runtime_identity_observation(
        fixture["pid"],
        fixture["control_group"],
    )
    assert result["identity_complete"] is False
    assert result["executable_path_or_identity"] is None
    assert result["missing_evidence"] == ["proc_executable"]
    assert str(secret_executable) not in json.dumps(result)


def test_runtime_identity_fails_closed_if_process_changes_between_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _runtime_identity_fixture(tmp_path, monkeypatch)
    original = server._proc_executable
    calls = 0

    def changing_executable(pid: int, *, proc_root: Path | None = None) -> str | None:
        nonlocal calls
        calls += 1
        if calls == 1:
            return original(pid, proc_root=proc_root)
        return None

    monkeypatch.setattr(server, "_proc_executable", changing_executable)
    result = server._runtime_identity_observation(
        fixture["pid"],
        fixture["control_group"],
    )
    assert result["identity_complete"] is False
    assert result["missing_evidence"] == ["process_changed_during_identity_observation"]


def test_runtime_identity_ignores_non_executable_anonymous_maps_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _runtime_identity_fixture(tmp_path, monkeypatch)
    original = server._read_proc_text
    map_reads = 0

    def changing_proc_text(
        pid: int,
        name: str,
        *,
        max_bytes: int,
        proc_root: Path | None = None,
    ) -> str | None:
        nonlocal map_reads
        value = original(
            pid,
            name,
            max_bytes=max_bytes,
            proc_root=proc_root,
        )
        if name == "maps":
            map_reads += 1
            if map_reads == 2 and value is not None:
                return value + "70000000-70001000 rw-p 00000000 00:00 0 [heap-drift]\n"
        return value

    monkeypatch.setattr(server, "_read_proc_text", changing_proc_text)
    result = server._runtime_identity_observation(
        fixture["pid"],
        fixture["control_group"],
    )

    assert result["release_id"] == fixture["release_id"]
    assert result["identity_complete"] is False
    assert result["missing_evidence"] == ["source_commit_primary_evidence"]


def test_runtime_identity_fails_closed_if_executable_maps_change_between_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _runtime_identity_fixture(tmp_path, monkeypatch)
    original = server._read_proc_text
    map_reads = 0

    def changing_proc_text(
        pid: int,
        name: str,
        *,
        max_bytes: int,
        proc_root: Path | None = None,
    ) -> str | None:
        nonlocal map_reads
        value = original(
            pid,
            name,
            max_bytes=max_bytes,
            proc_root=proc_root,
        )
        if name == "maps":
            map_reads += 1
            if map_reads == 2 and value is not None:
                return value + "70000000-70001000 r-xp 00000000 08:01 4242 /tmp/injected.so\n"
        return value

    monkeypatch.setattr(server, "_read_proc_text", changing_proc_text)
    result = server._runtime_identity_observation(
        fixture["pid"],
        fixture["control_group"],
    )

    assert result["identity_complete"] is False
    assert result["release_id"] is None
    assert result["missing_evidence"] == ["process_changed_during_identity_observation"]


def test_service_runtime_reports_bound_release_identity_and_listener(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _runtime_identity_fixture(tmp_path, monkeypatch)
    own_uid = server.os.getuid()
    control_group = fixture["control_group"]
    pid = fixture["pid"]

    def fake_run(argv, **kwargs):
        if argv[0] == "/usr/bin/systemctl":
            if "--user" in argv:
                stdout = _complete_service_show_fixture(
                    main_pid=0,
                    control_group="",
                    active_state="inactive",
                    fragment_path="/home/alex/.config/systemd/user/grabowski-operator.service",
                )
            else:
                stdout = _complete_service_show_fixture(
                    main_pid=pid,
                    control_group=control_group,
                    fragment_path="/etc/systemd/system/grabowski-operator.service",
                )
            return {
                "returncode": 0,
                "stdout": stdout,
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "rows_intact": True,
            }
        if argv[0] == "/usr/bin/ps":
            return {
                "returncode": 0,
                "stdout": (
                    f"{pid} 1 {own_uid} Ss 10 100 0.1 python "
                    f"0::{control_group}\n"
                ),
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "rows_intact": True,
            }
        if argv[0] == "/usr/bin/ss":
            return {
                "returncode": 0,
                "stdout": (
                    "tcp LISTEN 0 128 127.0.0.1:18181 0.0.0.0:* "
                    f"uid:{own_uid} ino:42 cgroup:{control_group} <->\n"
                ),
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "rows_intact": True,
            }
        raise AssertionError(argv)

    monkeypatch.setattr(server, "_run", fake_run)
    runtime = server.service_runtime("grabowski-operator.service")
    identity = runtime["runtime_identity"]

    assert runtime["service_scope"] == "system"
    assert runtime["main_pid"] == pid
    assert runtime["listener_observation_complete"] is True
    assert identity["identity_complete"] is False
    assert identity["release_id"] == fixture["release_id"]
    assert identity["source_commit_or_repo_head"] is None
    assert identity["missing_evidence"] == ["source_commit_primary_evidence"]


def test_service_runtime_identity_stays_unknown_on_wrong_main_pid(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    own_uid = server.os.getuid()
    proc_root = tmp_path / "proc-empty"
    release_root = tmp_path / "releases-empty"
    proc_root.mkdir()
    release_root.mkdir()
    monkeypatch.setattr(server, "PROC_ROOT", proc_root)
    monkeypatch.setattr(server, "GRABOWSKI_RELEASE_ROOT", release_root)

    def fake_run(argv, **kwargs):
        if argv[0] == "/usr/bin/systemctl":
            stdout = (
                _complete_service_show_fixture(main_pid=100, control_group="/cg")
                if "--user" in argv
                else _missing_system_service_show_fixture()
            )
            return {
                "returncode": 0,
                "stdout": stdout,
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "rows_intact": True,
            }
        if argv[0] == "/usr/bin/ps":
            return {
                "returncode": 0,
                "stdout": f"101 1 {own_uid} S 1 1 0.0 python 0::/cg\n",
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "rows_intact": True,
            }
        if argv[0] == "/usr/bin/ss":
            return {
                "returncode": 0,
                "stdout": "tcp LISTEN 0 1 127.0.0.1:1 0.0.0.0:* cgroup:/cg\n",
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "rows_intact": True,
            }
        raise AssertionError(argv)

    def must_not_observe(*args, **kwargs):
        raise AssertionError("identity must not run without a bound MainPID")

    monkeypatch.setattr(server, "_run", fake_run)
    monkeypatch.setattr(server, "_runtime_identity_observation", must_not_observe)
    runtime = server.service_runtime("nixer-mcp.service")
    assert runtime["runtime_identity"]["identity_complete"] is False
    assert runtime["runtime_identity"]["missing_evidence"] == [
        "service_process_binding"
    ]


def test_service_runtime_identity_stays_unknown_on_scope_ambiguity_or_absence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    proc_root = tmp_path / "proc-empty"
    release_root = tmp_path / "releases-empty"
    proc_root.mkdir()
    release_root.mkdir()
    monkeypatch.setattr(server, "PROC_ROOT", proc_root)
    monkeypatch.setattr(server, "GRABOWSKI_RELEASE_ROOT", release_root)

    def ambiguous_run(argv, **kwargs):
        if argv[0] == "/usr/bin/systemctl":
            return {
                "returncode": 0,
                "stdout": _complete_service_show_fixture(),
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "rows_intact": True,
            }
        if argv[0] == "/usr/bin/ss":
            return {
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "rows_intact": True,
            }
        raise AssertionError(argv)

    monkeypatch.setattr(server, "_run", ambiguous_run)
    ambiguous = server.service_runtime("nixer-mcp.service")
    assert ambiguous["service_scope"] is None
    assert ambiguous["runtime_identity"]["identity_complete"] is False

    def absent_run(argv, **kwargs):
        if argv[0] == "/usr/bin/systemctl":
            return {
                "returncode": 0,
                "stdout": _missing_system_service_show_fixture(),
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "rows_intact": True,
            }
        if argv[0] == "/usr/bin/ss":
            return {
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "rows_intact": True,
            }
        raise AssertionError(argv)

    monkeypatch.setattr(server, "_run", absent_run)
    absent = server.service_runtime("missing.service")
    assert absent["runtime_identity"]["identity_complete"] is False
    assert absent["runtime_identity"]["release_id"] is None

def test_service_runtime_correlates_cgroup_children_and_listener(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    own_uid = server.os.getuid()
    monkeypatch.setattr(server, "PROC_ROOT", tmp_path / "proc-empty")
    monkeypatch.setattr(server, "GRABOWSKI_RELEASE_ROOT", tmp_path / "releases-empty")
    def fake_run(argv, **kwargs):
        if argv[0] == "/usr/bin/systemctl" and "show" in argv:
            stdout = _complete_service_show_fixture() if "--user" in argv else _missing_system_service_show_fixture()
            return {
                "returncode": 0,
                "stdout": stdout,
                "stderr": "", "stdout_truncated": False, "stderr_truncated": False, "rows_intact": True,
            }
        if argv[0] == "/usr/bin/ps":
            return {
                "returncode": 0,
                "stdout": (
                    f"100 1 {own_uid} S 120 2048 1.0 python 0::/user.slice/nixer\n"
                    f"101 100 {own_uid} S 60 1024 0.2 nix 0::/user.slice/nixer/child\n"
                    f"102 100 {own_uid} S 60 1024 0.2 stray 0::/user.slice/other\n"
                ),
                "stderr": "", "stdout_truncated": False, "stderr_truncated": False, "rows_intact": True,
            }
        if argv[0] == "/usr/bin/ss":
            assert argv == ["/usr/bin/ss", "-H", "-lntue"]
            assert all("p" not in argument for argument in argv[1:])
            return {
                "returncode": 0,
                "stdout": f'tcp LISTEN 0 128 127.0.0.1:18187 0.0.0.0:* uid:{own_uid} ino:42 cgroup:/user.slice/nixer <->\n',
                "stderr": "", "stdout_truncated": False, "stderr_truncated": False, "rows_intact": True,
            }
        raise AssertionError(argv)
    monkeypatch.setattr(server, "_run", fake_run)
    runtime = server.service_runtime("nixer-mcp.service")
    assert runtime["service_scope"] == "user"
    assert runtime["main_pid"] == 100
    assert [row["pid"] for row in runtime["processes"]] == [100, 101]
    assert "127.0.0.1:18187" in runtime["listeners"][0]
    assert runtime["listener_observation_complete"] is True
    assert runtime["runtime_identity"]["identity_complete"] is False
    assert runtime["runtime_identity"]["release_id"] is None
    assert runtime["runtime_identity"]["missing_evidence"] == ["grabowski_runtime_unit"]
    assert runtime["complete"] is True


def test_service_runtime_zero_listener_match_does_not_establish_absence(monkeypatch: pytest.MonkeyPatch) -> None:
    own_uid = server.os.getuid()
    def fake_run(argv, **kwargs):
        if argv[0] == "/usr/bin/systemctl":
            stdout = (
                _complete_service_show_fixture(control_group="/cg") if "--user" in argv else _missing_system_service_show_fixture()
            )
            return {"returncode": 0, "stdout": stdout, "stderr": "", "stdout_truncated": False, "stderr_truncated": False, "rows_intact": True}
        if argv[0] == "/usr/bin/ps":
            return {"returncode": 0, "stdout": f"100 1 {own_uid} S 1 1 0.0 python 0::/cg\n", "stderr": "", "stdout_truncated": False, "stderr_truncated": False, "rows_intact": True}
        if argv[0] == "/usr/bin/ss":
            assert argv == ["/usr/bin/ss", "-H", "-lntue"]
            return {"returncode": 0, "stdout": f"tcp LISTEN 0 128 127.0.0.1:9999 0.0.0.0:* uid:{own_uid} ino:9 cgroup:/other <->\n", "stderr": "", "stdout_truncated": False, "stderr_truncated": False, "rows_intact": True}
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


def test_service_runtime_marks_mixed_attribution_socket_source_incomplete(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    own_uid = server.os.getuid()
    proc_root = tmp_path / "proc-empty"
    release_root = tmp_path / "releases-empty"
    proc_root.mkdir()
    release_root.mkdir()
    monkeypatch.setattr(server, "PROC_ROOT", proc_root)
    monkeypatch.setattr(server, "GRABOWSKI_RELEASE_ROOT", release_root)
    def fake_run(argv, **kwargs):
        if argv[0] == "/usr/bin/systemctl":
            stdout = (
                _complete_service_show_fixture(control_group="/cg") if "--user" in argv else _missing_system_service_show_fixture()
            )
            return {"returncode": 0, "stdout": stdout, "stderr": "", "stdout_truncated": False, "stderr_truncated": False, "rows_intact": True}
        if argv[0] == "/usr/bin/ps":
            return {"returncode": 0, "stdout": f"100 1 {own_uid} S 1 1 0.0 python 0::/cg\n", "stderr": "", "stdout_truncated": False, "stderr_truncated": False, "rows_intact": True}
        if argv[0] == "/usr/bin/ss":
            return {
                "returncode": 0,
                "stdout": (
                    f"tcp LISTEN 0 128 127.0.0.1:18187 0.0.0.0:* uid:{own_uid} ino:42 cgroup:/cg <->\n"                    "tcp LISTEN 0 128 127.0.0.1:9999 0.0.0.0:*\n"
                ),
                "stderr": "", "stdout_truncated": False, "stderr_truncated": False, "rows_intact": True,
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
            return {"returncode": 0, "stdout": stdout, "stderr": "", "stdout_truncated": False, "stderr_truncated": False, "rows_intact": True}
        if argv[0] == "/usr/bin/ps":
            return {"returncode": 0, "stdout": f"100 1 {own_uid} S 1 1 0.0 python 0::/cg\n", "stderr": "", "stdout_truncated": True, "stderr_truncated": False, "rows_intact": True}
        if argv[0] == "/usr/bin/ss":
            return {"returncode": 0, "stdout": "", "stderr": "", "stdout_truncated": True, "stderr_truncated": False, "rows_intact": True}
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
    repo.mkdir()
    worktree.mkdir()
    lanes.mkdir()
    (repo / ".git").mkdir()
    (worktree / ".git").write_text("gitdir: fixture", encoding="utf-8")
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
    lanes = tmp_path / "lanes"
    lanes.mkdir()
    lane_id = "2" * 32
    lane = _seal_lane({"lane_id": lane_id, "state": "ready", "terminal_closeout": {"closeout_state": "no_change_proven"}, "inputs": {"lane_id": lane_id, "repo": str(tmp_path), "target_path": str(tmp_path), "branch": "fixture", "purpose": "fixture", "base_head": OID_A}})
    (lanes / f"{lane_id}.json").write_text(json.dumps(lane), encoding="utf-8")
    monkeypatch.setattr(server, "GRABOWSKI_WORK_LANES_ROOT", lanes.resolve())
    with pytest.raises(RuntimeError, match="not active"):
        server.get_work_target(lane_id)


def test_work_target_rejects_tampered_lane_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lanes = tmp_path / "lanes"
    lanes.mkdir()
    lane_id = "8" * 32
    lane = _seal_lane({"lane_id": lane_id, "state": "ready", "terminal_closeout": None, "inputs": {"lane_id": lane_id, "repo": str(tmp_path), "target_path": str(tmp_path), "branch": "fixture", "purpose": "before", "base_head": OID_A}})
    lane["inputs"]["purpose"] = "tampered-after-seal"
    path = lanes / f"{lane_id}.json"
    path.write_text(json.dumps(lane), encoding="utf-8")
    path.chmod(0o600)
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
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
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


def test_incomplete_finding_store_publishes_degraded_visible_inbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "9" * 32
    target = _install_pointer(worktree, state, lane_id)
    findings = state / "findings"
    findings.mkdir(mode=0o700)
    bad = findings / "broken.json"
    bad.write_text("{broken", encoding="utf-8")
    bad.chmod(0o600)
    monkeypatch.setattr(server, "_read_work_target", lambda lane: {
        "lane_id": lane, "repository": "fixture", "worktree": str(worktree), "branch": "feature",
        "purpose": "fixture", "base_head": OID_B, "checkpoint": OID_A, "source": "fixture", "observed_at": "fixture",
    })
    result = server.publish_worktree_inbox(lane_id)
    assert result["state"] == "published"
    assert result["source_complete"] is False
    assert result["source_error_count"] == 1
    assert result["quarantined_record_count"] == 1
    inbox = json.loads(target.read_text(encoding="utf-8"))
    assert inbox["source_complete"] is False
    assert inbox["projection_complete"] is True
    assert inbox["findings"] == []
    assert inbox["quarantined_records"] == [
        {"record": "broken.json", "error_type": "RuntimeError"}
    ]


def test_worktree_root_limits_delivery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    worktree = tmp_path / "outside"
    worktree.mkdir()
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
    worktree = tmp_path / "worktree"
    worktree.mkdir()
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


def test_finding_digest_mismatch_is_visible_in_degraded_inbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _configure_state(tmp_path, monkeypatch)
    worktree = tmp_path / "worktree"
    lane_id = "c" * 32
    target = _install_pointer(worktree, state, lane_id)
    monkeypatch.setattr(server, "_read_work_target", lambda lane: {
        "lane_id": lane, "repository": "fixture", "worktree": str(worktree), "branch": "feature",
        "purpose": "fixture", "base_head": OID_B, "checkpoint": OID_A, "source": "fixture", "observed_at": "fixture",
    })
    submitted = server.submit_finding(
        **_finding_args(subject=f"lane:{lane_id}", checkpoint=OID_A)
    )
    finding = state / "findings" / f"{submitted['finding_id']}.json"
    payload = json.loads(finding.read_text(encoding="utf-8"))
    payload["checkpoint"] = OID_B
    finding.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    finding.chmod(0o600)

    result = server.publish_worktree_inbox(lane_id)
    assert result["state"] == "published"
    assert result["source_complete"] is False
    inbox = json.loads(target.read_text(encoding="utf-8"))
    assert inbox["source_complete"] is False
    assert inbox["findings"] == []
    assert inbox["quarantined_record_count"] == 1
    assert inbox["quarantined_records"][0]["record"] == finding.name
    listing = server.list_findings(limit=10)
    assert listing["source_complete"] is False
    assert listing["store_health"]["quarantined_record_count"] == 1


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
    real_projection = server._current_lane_projection
    def observed_projection(
        lane: str,
        checkpoint: str,
        *,
        incremental_record=None,
    ):
        entered_projection.set()
        return real_projection(
            lane,
            checkpoint,
            incremental_record=incremental_record,
        )
    monkeypatch.setattr(server, "_current_lane_projection", observed_projection)
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