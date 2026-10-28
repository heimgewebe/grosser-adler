"""Bounded, unauthenticated public GitHub PR observation.

This path cannot read private resources and never accepts or forwards GitHub
credentials. The existing dedicated-token GitHub CLI path remains authoritative
when configured. Missing or incomplete public evidence is not a PASS.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

_API_ROOT = "https://api.github.com"
_API_HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "grosser-adler-read-only-observer",
    "X-GitHub-Api-Version": "2022-11-28",
}
_MAX_RESPONSE_BYTES = 1_000_000
_MAX_PAGES = 5
_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")


class PublicGithubIncomplete(RuntimeError):
    """No complete uncredentialed GitHub evidence was obtained."""


def _get_json(path: str) -> tuple[Any, bool]:
    # All callers construct paths from already validated owner/repo/PR and
    # server-generated integer page numbers. No caller-controlled URL.
    request = urllib.request.Request(_API_ROOT + path, headers=_API_HEADERS)
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            if response.status != 200:
                raise PublicGithubIncomplete(f"public API HTTP {response.status}")
            if "application/json" not in response.headers.get("Content-Type", ""):
                raise PublicGithubIncomplete("public API returned non-JSON")
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
            if len(raw) > _MAX_RESPONSE_BYTES:
                raise PublicGithubIncomplete("public API response exceeds byte bound")
            next_page = 'rel="next"' in response.headers.get("Link", "")
    except urllib.error.HTTPError as exc:
        raise PublicGithubIncomplete(f"public API HTTP {exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise PublicGithubIncomplete(f"public API transport {type(exc).__name__}") from None
    try:
        return json.loads(raw.decode("utf-8")), next_page
    except (UnicodeError, ValueError):
        raise PublicGithubIncomplete("public API returned invalid JSON") from None


def _array(path: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for page in range(1, _MAX_PAGES + 1):
        suffix = "&" if "?" in path else "?"
        payload, next_page = _get_json(f"{path}{suffix}per_page=100&page={page}")
        if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
            raise PublicGithubIncomplete("public API paginated rows are not objects")
        rows.extend(payload)
        if not next_page:
            return rows
    raise PublicGithubIncomplete("public API pagination bound exceeded")


def _check_runs(path: str) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    for page in range(1, _MAX_PAGES + 1):
        payload, next_page = _get_json(f"{path}?per_page=100&page={page}")
        if not isinstance(payload, dict):
            raise PublicGithubIncomplete("public API check runs are not an object")
        total = payload.get("total_count")
        batch = payload.get("check_runs")
        if (type(total) is not int or total < 0 or not isinstance(batch, list)
                or not all(isinstance(item, dict) for item in batch)):
            raise PublicGithubIncomplete("public API check run shape invalid")
        runs.extend(batch)
        if not next_page:
            if len(runs) != total:
                raise PublicGithubIncomplete("public API check-run count incomplete")
            return runs
    raise PublicGithubIncomplete("public API check-run pagination bound exceeded")


def _public_metadata(repo_path: str, pr: int) -> dict[str, Any]:
    payload, next_page = _get_json(f"{repo_path}/pulls/{pr}")
    if next_page or not isinstance(payload, dict):
        raise PublicGithubIncomplete("public API PR metadata invalid")
    head = payload.get("head")
    base = payload.get("base")
    if not isinstance(head, dict) or not isinstance(base, dict):
        raise PublicGithubIncomplete("public API PR revisions unavailable")
    head_sha, base_sha = head.get("sha"), base.get("sha")
    if (not isinstance(head_sha, str) or _SHA_RE.fullmatch(head_sha) is None
            or not isinstance(base_sha, str) or _SHA_RE.fullmatch(base_sha) is None):
        raise PublicGithubIncomplete("public API PR revision identity invalid")

    check_runs = _check_runs(f"{repo_path}/commits/{head_sha}/check-runs")
    contexts = _array(f"{repo_path}/commits/{head_sha}/statuses")
    latest_status: dict[str, dict[str, Any]] = {}
    for item in contexts:  # GitHub lists commit statuses newest first.
        context = item.get("context")
        if isinstance(context, str) and context and context not in latest_status:
            latest_status[context] = item
    checks = [
        {
            "__typename": "CheckRun",
            "name": run.get("name"),
            "status": run.get("status"),
            "conclusion": run.get("conclusion"),
            "detailsUrl": run.get("details_url"),
            "headSha": run.get("head_sha"),
            "source": "public_rest_check_runs",
        }
        for run in check_runs
    ]
    checks.extend({
        "__typename": "StatusContext",
        "context": status.get("context"),
        "state": status.get("state"),
        "targetUrl": status.get("target_url"),
        "source": "public_rest_commit_status",
    } for status in latest_status.values())
    return {
        "number": payload.get("number"),
        "title": payload.get("title"),
        "state": "MERGED" if payload.get("merged_at") else str(payload.get("state", "")).upper(),
        "isDraft": payload.get("draft"),
        "headRefName": head.get("ref"),
        "headRefOid": head_sha,
        "baseRefName": base.get("ref"),
        "baseRefOid": base_sha,
        "url": payload.get("html_url"),
        "mergeStateStatus": None,
        "reviewDecision": None,
        "statusCheckRollup": checks,
        "publicRestLimitations": [
            "reviewDecision and mergeStateStatus are not equivalent to GitHub GraphQL fields",
            "statusCheckRollup is a REST-derived latest-run/context observation",
        ],
        "evidenceSource": "github_public_rest_unauthenticated",
    }


def _receipt(value: Any, *, redactor: Callable[[str], str],
             bounded: Callable[[str], tuple[str, bool]]) -> dict[str, Any]:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    safe = redactor(raw)
    stdout, truncated = bounded(safe)
    return {
        "returncode": 0,
        "stdout": stdout,
        "stderr": "",
        "stdout_truncated": truncated,
        "stderr_truncated": False,
        "stdout_line_count": len(raw.splitlines()),
        "rows_intact": len(safe.splitlines()) == len(raw.splitlines()),
    }


def _failure(exc: PublicGithubIncomplete) -> dict[str, Any]:
    return {
        "returncode": 1,
        "stdout": "",
        "stderr": str(exc),
        "stdout_truncated": False,
        "stderr_truncated": False,
        "stdout_line_count": 0,
        "rows_intact": True,
    }


def read_public_pr(
    owner: str, repo: str, pr: int, *,
    redactor: Callable[[str], str],
    bounded: Callable[[str], tuple[str, bool]],
    projector: Callable[..., dict[str, Any]],
    now: Callable[[], str],
) -> dict[str, Any]:
    """Return receipt-compatible public data; never imply private access."""
    root = f"/repos/{owner}/{repo}"
    receipts: list[dict[str, Any]] = []
    for fetch in (
        lambda: _public_metadata(root, pr),
        lambda: _array(f"{root}/pulls/{pr}/reviews"),
        lambda: _array(f"{root}/pulls/{pr}/comments"),
    ):
        try:
            receipts.append(_receipt(fetch(), redactor=redactor, bounded=bounded))
        except PublicGithubIncomplete as exc:
            receipts.append(_failure(exc))
    observed_at = now()
    metadata, reviews, comments = receipts
    return {
        "repo": f"{owner}/{repo}",
        "pr": pr,
        "metadata": metadata,
        "reviews": reviews,
        "review_comments": comments,
        "structured": projector(metadata, reviews, comments, observed_at=observed_at),
        "github_access": {
            "mode": "public_unauthenticated",
            "principal": "anonymous",
            "private_repository_access": False,
            "does_not_establish": ["dedicated_github_principal", "merge_authorization"],
        },
        "observed_at": observed_at,
    }
