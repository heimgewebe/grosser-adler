"""Focused regression tests for public-only GitHub PR observation."""
from __future__ import annotations

import json
import urllib.error
from email.message import Message

import pytest

import github_public
import server


HEAD = "a" * 40
BASE = "b" * 40


def _fake_public_data(monkeypatch: pytest.MonkeyPatch, *, comment_body: str = "public") -> list[str]:
    requested: list[str] = []

    def fake_get(path: str):
        requested.append(path)
        if path.endswith("/pulls/27"):
            return {
                "number": 27,
                "title": "Observer parser fix",
                "state": "closed",
                "merged_at": "2026-10-27T11:59:24Z",
                "draft": False,
                "head": {"ref": "fix/parser", "sha": HEAD},
                "base": {"ref": "main", "sha": BASE},
                "html_url": "https://github.com/heimgewebe/grosser-adler/pull/27",
            }, False
        if "/check-runs?" in path:
            return {"total_count": 1, "check_runs": [{
                "name": "validate",
                "status": "completed",
                "conclusion": "success",
                "head_sha": HEAD,
            }]}, False
        if "/statuses?" in path:
            return [
                {"context": "ci", "state": "success"},
                {"context": "ci", "state": "failure"},
            ], False
        if "/reviews?" in path:
            return [{"id": 1, "commit_id": HEAD, "state": "APPROVED"}], False
        if "/comments?" in path:
            return [{"id": 5, "body": comment_body, "path": "server.py"}], False
        raise AssertionError(path)

    monkeypatch.setattr(github_public, "_get_json", fake_get)
    return requested


def test_public_pr_no_token_reads_all_sources_without_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GROSSER_ADLER_GITHUB_TOKEN", raising=False)
    requested = _fake_public_data(monkeypatch)
    monkeypatch.setattr(
        server.subprocess, "run",
        lambda *args, **kwargs: pytest.fail("public fallback must never launch gh"),
    )
    result = server.github_pr("heimgewebe/grosser-adler", 27)

    assert result["github_access"]["principal"] == "anonymous"
    assert result["github_access"]["private_repository_access"] is False
    structured = result["structured"]
    assert structured["source_complete"] is True
    assert structured["observation_complete"] is True
    assert structured["facts"]["headRefOid"] == HEAD
    assert structured["facts"]["baseRefOid"] == BASE
    assert structured["facts"]["mergeStateStatus"] is None
    assert structured["facts"]["reviewDecision"] is None
    assert structured["review_head_bindings"][0]["current_head_binding"] is True
    assert len(structured["checks"]) == 2
    assert structured["checks"][1]["state"] == "success"  # newest per context
    assert len(requested) == 5
    assert all(path.startswith("/repos/heimgewebe/grosser-adler/") for path in requested)
    assert all("per_page=100&page=1" in path for path in requested[1:])


def test_private_or_unavailable_public_source_is_not_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GROSSER_ADLER_GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(
        github_public, "_get_json",
        lambda path: (_ for _ in ()).throw(github_public.PublicGithubIncomplete("public API HTTP 404")),
    )
    result = server.github_pr("heimgewebe/private-repository", 12)
    assert result["github_access"]["private_repository_access"] is False
    assert all(result[key]["returncode"] != 0 for key in ("metadata", "reviews", "review_comments"))
    assert result["structured"]["source_complete"] is False
    assert result["structured"]["observation_complete"] is False
    assert "metadata:command_failed" in result["structured"]["missing_evidence"]


def test_public_pr_retains_central_token_redaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GROSSER_ADLER_GITHUB_TOKEN", raising=False)
    secret = "ghp_" + "K" * 27
    _fake_public_data(monkeypatch, comment_body=secret)
    result = server.github_pr("heimgewebe/grosser-adler", 27)

    assert secret not in json.dumps(result)
    assert result["structured"]["inline_comments"][0]["body"] == "<REDACTED>"
    assert result["structured"]["observation_complete"] is True


def test_public_pagination_bound_is_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(github_public, "_get_json", lambda path: ([{"id": 1}], True))
    with pytest.raises(github_public.PublicGithubIncomplete, match="pagination bound"):
        github_public._array("/repos/heimgewebe/grosser-adler/pulls/27/reviews")


def test_check_run_count_must_match_full_pagination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        github_public, "_get_json",
        lambda path: ({"total_count": 2, "check_runs": [{"id": 1}]}, False),
    )
    with pytest.raises(github_public.PublicGithubIncomplete, match="count incomplete"):
        github_public._check_runs("/repos/heimgewebe/grosser-adler/commits/" + HEAD + "/check-runs")


def test_public_http_request_is_fixed_host_and_contains_no_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = []

    class Response:
        status = 200
        headers = Message()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            return b'{"ok":true}'

    Response.headers["Content-Type"] = "application/json"

    def fake_urlopen(request, timeout):
        requests.append(request)
        assert timeout == 12
        return Response()

    monkeypatch.setattr(github_public.urllib.request, "urlopen", fake_urlopen)
    data, next_page = github_public._get_json("/repos/heimgewebe/grosser-adler/pulls/27")

    assert data == {"ok": True}
    assert next_page is False
    assert requests[0].full_url == "https://api.github.com/repos/heimgewebe/grosser-adler/pulls/27"
    assert requests[0].get_header("Authorization") is None
    assert requests[0].get_header("Cookie") is None


def test_public_http_403_not_misreported_as_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 403, "rate limited", None, None)

    monkeypatch.setattr(github_public.urllib.request, "urlopen", denied)
    with pytest.raises(github_public.PublicGithubIncomplete, match="HTTP 403"):
        github_public._get_json("/repos/heimgewebe/grosser-adler/pulls/27")


def test_dedicated_token_keeps_existing_gh_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GROSSER_ADLER_GITHUB_TOKEN", "dedicated-test-read-token")
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return {
            "returncode": 0,
            "stdout": '{"headRefOid":"' + HEAD + '","statusCheckRollup":[]}' if len(calls) == 1 else "[]",
            "stderr": "",
            "stdout_truncated": False,
        }

    monkeypatch.setattr(server, "_run", fake_run)
    monkeypatch.setattr(
        github_public, "_get_json",
        lambda path: pytest.fail("dedicated credential must keep GH CLI route"),
    )
    result = server.github_pr("heimgewebe/grosser-adler", 27)

    assert len(calls) == 3
    assert calls[0][:2] == ["/usr/bin/gh", "pr"]
    assert "github_access" not in result
    assert result["structured"]["source_complete"] is True
