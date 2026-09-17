#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import fcntl
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

APP_NAME = "Großer Adler"
IDENTITY = "grosser-adler-observer-v1"
FINDING_CONTRACT = "adler-finding-v1"
SIDECAR_CONTRACT = "adler-worktree-inbox-v1"
ARCHITECTURE_CONTRACT = "observer-evidence-finding-delivery-v1"
REPO_ROOT = Path("/home/alex/repos").resolve()
STATE_ROOT = Path(os.environ.get("GROSSER_ADLER_STATE_ROOT", "/home/alex/.local/state/grosser-adler")).resolve()
FINDINGS_ROOT = STATE_ROOT / "findings"
INBOX_ROOT = STATE_ROOT / "worktree-inboxes"
GRABOWSKI_WORK_LANES_ROOT = Path(os.environ.get("GROSSER_ADLER_WORK_LANES_ROOT", "/home/alex/.local/state/grabowski/work-lanes")).resolve()
WORKTREE_ROOT = Path(os.environ.get("GROSSER_ADLER_WORKTREE_ROOT", "/home/alex/repos/.grabowski-worktrees")).resolve()
MAX_OUTPUT_BYTES = 160_000
MAX_JSON_SOURCE_BYTES = 1_000_000
MAX_SUMMARY_CHARS = 4_000
MAX_EVIDENCE_REFS = 32
MAX_EVIDENCE_REF_CHARS = 1_000
MAX_AFFECTED_EFFECTS = 16
MAX_AFFECTED_EFFECT_CHARS = 120
LEGACY_CONNECTOR_CONTRACT = "adler-legacy-connector-submit-v1"

READ_ANNOTATIONS = ToolAnnotations(
    title="Independent read-only observation",
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
FINDING_ANNOTATIONS = ToolAnnotations(
    title="Append advisory finding",
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=False,
)
SIDECAR_ANNOTATIONS = ToolAnnotations(
    title="Publish advisory worktree inbox",
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)

INSTRUCTIONS = """You are Großer Adler, an independent observer, auditor and advisor. Reconstruct relevant state from primary evidence whenever possible. You do not own work state, decisions, execution, admission or lifecycle. Your only writes are immutable advisory findings and computed inbox files inside your own state root. Grabowski owns the worktree-local .adler/inbox.json symlink that points at the exact external inbox file. Findings are facts or advice, never commands. Never create work, acquire leases, edit worktree or product files, commit, push, merge, deploy, control services, signal processes or mutate credentials. Partial evidence is incomplete, never absence. Prefer exact checkpoints and explicit uncertainty; do not manufacture findings."""

mcp = FastMCP(APP_NAME, instructions=INSTRUCTIONS)

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_REV_RE = re.compile(r"^[A-Za-z0-9_./@{}^~:+-]{1,200}$")
_UNIT_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,180}\.service$")
_LANE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_LANE_SUBJECT_RE = re.compile(r"^lane:([0-9a-f]{32})$")
_FINDING_ID_RE = re.compile(r"^ga-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$")
_LEGACY_SUBJECT_KINDS = {
    "repo", "pr", "commit", "runtime", "bureau_task", "grabowski_lane",
    "agent_run", "service", "work",
}
_LEGACY_STATUSES = {
    "observation", "finding", "recheck_suggested", "contradiction",
    "missing_evidence", "risk", "advice", "recheck_required",
}
_LEGACY_BASE_STATUSES = {"observation", "finding", "recheck_suggested"}
_LEGACY_ENRICHED_FIELDS = ("target_actor", "binding", "recommendation", "rationale", "confidence")
_LEGACY_RELATIONAL_FIELDS = (
    "checkpoint_mode", "checkpoint_components", "checkpoint_set_sha256", "checkpoint_contract",
)
_V1_ONLY_MARKERS = {
    "finding_contract", "finding_sha256", "kind", "binding_strength",
    "recheck_of", "conclusion", "affected_effects",
}
_SYSTEMD_SERVICE_PROPERTIES = (
    "LoadState",
    "ActiveState",
    "SubState",
    "Result",
    "ExecMainCode",
    "ExecMainStatus",
    "MainPID",
    "FragmentPath",
    "NRestarts",
    "ActiveEnterTimestamp",
    "ExecMainStartTimestamp",
    "ControlGroup",
    "MemoryCurrent",
    "TasksCurrent",
    "CPUUsageNSec",
)
_SYSTEMD_SCOPES: tuple[Literal["user", "system"], ...] = ("user", "system")
_SYSTEMD_RUNNING_ACTIVE_STATES = frozenset({"active", "reloading"})
_SYSTEMD_TRANSITIONAL_ACTIVE_STATES = frozenset({"activating", "deactivating"})
_SECRET_PATTERNS = (
    re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"(?i)(authorization|api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]+"),
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _redact(text: str, *, exact_secrets: tuple[str, ...] = ()) -> str:
    result = text
    for secret in exact_secrets:
        if secret:
            result = result.replace(secret, "<REDACTED>")
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub("<REDACTED>", result)
    return result


def _bounded(text: str, max_bytes: int = MAX_OUTPUT_BYTES) -> tuple[str, bool]:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text, False
    clipped = encoded[:max_bytes].decode("utf-8", errors="replace")
    return clipped + "\n<OUTPUT_TRUNCATED>", True


def _run(argv: list[str], *, cwd: Path | None = None, timeout: int = 15) -> dict[str, Any]:
    if not argv or not argv[0].startswith("/usr/bin/"):
        raise ValueError("only fixed absolute /usr/bin executables are allowed")
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/home/alex",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GH_PAGER": "cat",
        "PAGER": "cat",
        "NO_COLOR": "1",
        "XDG_RUNTIME_DIR": os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"),
        "DBUS_SESSION_BUS_ADDRESS": os.environ.get(
            "DBUS_SESSION_BUS_ADDRESS", f"unix:path=/run/user/{os.getuid()}/bus"
        ),
    }
    gh_token: str | None = None
    if argv[0] == "/usr/bin/gh":
        gh_token = os.environ.get("GROSSER_ADLER_GITHUB_TOKEN")
        if not gh_token or not gh_token.strip():
            raise RuntimeError("Großer Adler GitHub credential is not configured")
        env["GH_TOKEN"] = gh_token

    completed = subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    exact_secrets = (gh_token,) if gh_token else ()
    stdout, stdout_truncated = _bounded(_redact(completed.stdout, exact_secrets=exact_secrets))
    stderr, stderr_truncated = _bounded(
        _redact(completed.stderr, exact_secrets=exact_secrets), 32_000
    )
    return {
        "returncode": completed.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
    }


def _resolve_repo(repo: str) -> Path:
    if not isinstance(repo, str) or not repo.strip():
        raise ValueError("repo must be a non-empty string")
    raw = Path(repo).expanduser()
    candidate = raw if raw.is_absolute() else REPO_ROOT / raw
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(REPO_ROOT)
    except ValueError as exc:
        raise PermissionError("repository is outside /home/alex/repos") from exc
    if not resolved.is_dir():
        raise ValueError("repository must be a directory")
    marker = resolved / ".git"
    if not marker.exists():
        raise ValueError("repository has no .git marker")
    return resolved


def _validate_unit(unit: str) -> str:
    if not isinstance(unit, str) or not _UNIT_RE.fullmatch(unit):
        raise ValueError("invalid systemd service name")
    return unit


def _parse_key_value_lines(
    text: str, *, expected_keys: tuple[str, ...] | None = None
) -> tuple[dict[str, str], bool]:
    values: dict[str, str] = {}
    complete = True
    for raw in text.splitlines():
        if not raw.strip():
            continue
        if "=" not in raw:
            complete = False
            continue
        key, value = raw.split("=", 1)
        if not key or key in values:
            complete = False
            continue
        values[key] = value
    if expected_keys is not None and set(values) != set(expected_keys):
        complete = False
    return values, complete


def _parse_process_table(text: str) -> tuple[list[dict[str, Any]], bool]:
    rows: list[dict[str, Any]] = []
    complete = True
    for raw in text.splitlines():
        if not raw.strip():
            continue
        parts = raw.strip().split()
        if len(parts) < 9:
            complete = False
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
            uid = int(parts[2])
            elapsed_seconds = int(parts[4])
            rss_kib = int(parts[5])
            cpu_percent = float(parts[6])
        except ValueError:
            complete = False
            continue
        comm_parts = parts[7:-1]
        if not comm_parts:
            complete = False
            continue
        rows.append({
            "pid": pid,
            "ppid": ppid,
            "uid": uid,
            "stat": parts[3],
            "elapsed_seconds": elapsed_seconds,
            "rss_kib": rss_kib,
            "cpu_percent": cpu_percent,
            "cgroup": _normalize_cgroup(parts[-1]),
            "comm": " ".join(comm_parts),
        })
    return rows, complete


def _normalize_cgroup(value: str) -> str:
    if "::" in value:
        value = value.split("::", 1)[1]
    if not value.startswith("/"):
        value = "/" + value.lstrip("/")
    return value.rstrip("/") or "/"


def _cgroup_within(process_cgroup: str, service_cgroup: str) -> bool:
    process = _normalize_cgroup(process_cgroup)
    service = _normalize_cgroup(service_cgroup)
    return process == service or process.startswith(service.rstrip("/") + "/")


def _descendant_rows(rows: list[dict[str, Any]], root_pid: int) -> list[dict[str, Any]]:
    by_parent: dict[int, list[dict[str, Any]]] = {}
    by_pid: dict[int, dict[str, Any]] = {}
    for row in rows:
        by_pid[row["pid"]] = row
        by_parent.setdefault(row["ppid"], []).append(row)
    if root_pid not in by_pid:
        return []
    result: list[dict[str, Any]] = []
    queue = [root_pid]
    seen: set[int] = set()
    while queue:
        pid = queue.pop(0)
        if pid in seen:
            continue
        seen.add(pid)
        row = by_pid.get(pid)
        if row is not None:
            result.append(row)
        queue.extend(child["pid"] for child in by_parent.get(pid, []))
    return result


def _status_is_clean(status_stdout: str) -> bool:
    lines = [line for line in status_stdout.splitlines() if line.strip()]
    return bool(lines) and all(line.startswith("##") for line in lines)


def _validate_github_repo(repo: str) -> str:
    if not isinstance(repo, str) or not _REPO_RE.fullmatch(repo):
        raise ValueError("GitHub repo must be owner/name")
    return repo


def _validate_revision(revision: str) -> str:
    if (
        not isinstance(revision, str)
        or revision.startswith("-")
        or not _REV_RE.fullmatch(revision)
    ):
        raise ValueError("invalid Git revision")
    return revision


def _ensure_state() -> None:
    STATE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    FINDINGS_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    INBOX_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    for path in (STATE_ROOT, FINDINGS_ROOT, INBOX_ROOT):
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise RuntimeError(f"unsafe state directory permissions: {path}")


@mcp.tool(name="adler_status", annotations=READ_ANNOTATIONS)
def adler_status() -> dict[str, Any]:
    """Return observer identity and the enforced minimal authority boundary."""
    return {
        "schema_version": 2,
        "identity": IDENTITY,
        "service": APP_NAME,
        "healthy": True,
        "mode": "read-mostly",
        "architecture_contract": ARCHITECTURE_CONTRACT,
        "finding_contract": FINDING_CONTRACT,
        "worktree_sidecar_contract": SIDECAR_CONTRACT,
        "repository_root": str(REPO_ROOT),
        "finding_store": str(FINDINGS_ROOT),
        "inbox_store": str(INBOX_ROOT),
        "work_lane_store": str(GRABOWSKI_WORK_LANES_ROOT),
        "worktree_delivery_root": str(WORKTREE_ROOT),
        "work_state_authority": False,
        "allowed_effects": ["append_finding", "publish_worktree_inbox"],
        "forbidden_effects": [
            "shell",
            "general_file_write",
            "git_index_mutation",
            "git_commit",
            "git_push",
            "github_mutation",
            "merge",
            "deploy",
            "service_control",
            "process_signal",
            "bureau_mutation",
            "work_or_lease_acquisition",
            "agent_start",
            "secret_reveal",
            "admission_policy",
        ],
        "observed_at": _utc_now(),
    }


@mcp.tool(name="git_status", annotations=READ_ANNOTATIONS)
def git_status(repo: str) -> dict[str, Any]:
    """Read branch/head/cleanliness without exposing untracked filenames."""
    root = _resolve_repo(repo)
    status = _run([
        "/usr/bin/git", "-c", "core.fsmonitor=false", "-C", str(root),
        "status", "--short", "--branch", "--untracked-files=no",
    ])
    untracked = _run([
        "/usr/bin/git", "-c", "core.fsmonitor=false", "-C", str(root),
        "ls-files", "--others", "--exclude-standard", "-z",
    ])
    head = _run(["/usr/bin/git", "-C", str(root), "rev-parse", "HEAD"] )
    status_complete = status["returncode"] == 0 and not status["stdout_truncated"]
    untracked_complete = untracked["returncode"] == 0 and not untracked["stdout_truncated"]
    head_complete = head["returncode"] == 0 and not head["stdout_truncated"]
    return {
        "repo": str(root),
        "status": status,
        "head": head,
        "untracked_present": bool(untracked["stdout"]) if untracked_complete else None,
        "observation_complete": status_complete and untracked_complete and head_complete,
        "observed_at": _utc_now(),
    }


@mcp.tool(name="git_log", annotations=READ_ANNOTATIONS)
def git_log(repo: str, max_count: int = 20) -> dict[str, Any]:
    """Read a bounded commit log from one allowed local repository."""
    root = _resolve_repo(repo)
    if not isinstance(max_count, int) or isinstance(max_count, bool) or not 1 <= max_count <= 100:
        raise ValueError("max_count must be between 1 and 100")
    result = _run([
        "/usr/bin/git", "-C", str(root), "log", f"--max-count={max_count}",
        "--format=%H%x09%aI%x09%s",
    ])
    return {"repo": str(root), "log": result, "observed_at": _utc_now()}


@mcp.tool(name="git_show", annotations=READ_ANNOTATIONS)
def git_show(repo: str, revision: str = "HEAD") -> dict[str, Any]:
    """Read one bounded Git revision without shell or external diff helpers."""
    root = _resolve_repo(repo)
    rev = _validate_revision(revision)
    result = _run([
        "/usr/bin/git", "-c", "diff.external=", "-c", "core.pager=cat", "-C", str(root),
        "show", "--no-ext-diff", "--no-textconv", "--format=fuller", rev,
    ])
    return {"repo": str(root), "revision": rev, "show": result, "observed_at": _utc_now()}


@mcp.tool(name="github_pr", annotations=READ_ANNOTATIONS)
def github_pr(repo: str, pr: int) -> dict[str, Any]:
    """Read live GitHub pull-request metadata, reviews and checks without mutation authority."""
    gh_repo = _validate_github_repo(repo)
    if not isinstance(pr, int) or isinstance(pr, bool) or not 1 <= pr <= 2_147_483_647:
        raise ValueError("invalid pull request number")
    metadata = _run([
        "/usr/bin/gh", "pr", "view", str(pr), "--repo", gh_repo,
        "--json", "number,title,state,isDraft,headRefName,headRefOid,baseRefName,baseRefOid,mergeStateStatus,url,reviewDecision,statusCheckRollup",
    ], timeout=20)
    reviews = _run([
        "/usr/bin/gh", "api", f"repos/{gh_repo}/pulls/{pr}/reviews", "--paginate",
    ], timeout=20)
    return {"repo": gh_repo, "pr": pr, "metadata": metadata, "reviews": reviews, "observed_at": _utc_now()}


@mcp.tool(name="list_user_services", annotations=READ_ANNOTATIONS)
def list_user_services() -> dict[str, Any]:
    """Discover user-systemd services without a name allowlist or mutation authority."""
    result = _run(["/usr/bin/systemctl", "--user", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager"], timeout=20)
    source_complete = result["returncode"] == 0 and not result["stdout_truncated"]
    parse_complete = source_complete
    units: list[dict[str, str]] = []
    if source_complete:
        for raw in result["stdout"].splitlines():
            if not raw.strip():
                continue
            parts = raw.strip().split(None, 4)
            if parts and parts[0] == "●":
                parts = parts[1:]
            if len(parts) < 4 or not _UNIT_RE.fullmatch(parts[0]):
                parse_complete = False
                continue
            units.append({"unit": parts[0], "load": parts[1], "active": parts[2], "sub": parts[3], "description": parts[4] if len(parts) > 4 else ""})
    observation_complete = source_complete and parse_complete
    if not observation_complete:
        units = []
    return {
        "services": units,
        "observation_complete": observation_complete,
        "parse_complete": parse_complete,
        "source": result,
        "observed_at": _utc_now(),
    }


def _service_show_argv(unit: str, scope: Literal["user", "system"]) -> list[str]:
    argv = ["/usr/bin/systemctl"]
    if scope == "user":
        argv.append("--user")
    elif scope != "system":
        raise ValueError("invalid systemd scope")
    argv.extend([
        "show", unit, "--no-pager", "--property=LoadState", "--property=ActiveState",
        "--property=SubState", "--property=Result", "--property=ExecMainCode",
        "--property=ExecMainStatus", "--property=MainPID", "--property=FragmentPath",
        "--property=NRestarts", "--property=ActiveEnterTimestamp",
        "--property=ExecMainStartTimestamp", "--property=ControlGroup",
        "--property=MemoryCurrent", "--property=TasksCurrent", "--property=CPUUsageNSec",
    ])
    return argv


def _observe_service_scope(unit: str, scope: Literal["user", "system"]) -> dict[str, Any]:
    result = _run(_service_show_argv(unit, scope))
    source_complete = result["returncode"] == 0 and not result["stdout_truncated"]
    properties: dict[str, str] = {}
    parse_complete = False
    if source_complete:
        properties, parse_complete = _parse_key_value_lines(
            result["stdout"], expected_keys=_SYSTEMD_SERVICE_PROPERTIES
        )
    observation_complete = source_complete and parse_complete
    if not observation_complete:
        properties = {}
    return {
        "scope": scope,
        "status": result,
        "properties": properties,
        "source_complete": source_complete,
        "parse_complete": parse_complete,
        "observation_complete": observation_complete,
    }


def _service_scope_candidate(observation: dict[str, Any]) -> dict[str, Any]:
    properties = observation["properties"]
    return {
        "scope": observation["scope"],
        "source_complete": observation["source_complete"],
        "parse_complete": observation["parse_complete"],
        "observation_complete": observation["observation_complete"],
        "load_state": properties.get("LoadState"),
        "active_state": properties.get("ActiveState"),
        "sub_state": properties.get("SubState"),
        "main_pid": properties.get("MainPID"),
        "fragment_path": properties.get("FragmentPath"),
        "status": observation["status"],
    }


def _resolve_service_scope(unit: str) -> dict[str, Any]:
    observations = [_observe_service_scope(unit, scope) for scope in _SYSTEMD_SCOPES]
    source_complete = all(item["source_complete"] for item in observations)
    parse_complete = all(item["parse_complete"] for item in observations)
    selected: dict[str, Any] | None = None
    reason = "scope-observation-incomplete"
    ambiguous = False
    absent = False

    if source_complete and parse_complete:
        loaded = [
            item for item in observations
            if item["properties"].get("LoadState") != "not-found"
        ]
        running = [
            item for item in loaded
            if item["properties"].get("ActiveState") in _SYSTEMD_RUNNING_ACTIVE_STATES
        ]
        transitional = [
            item for item in loaded
            if item["properties"].get("ActiveState") in _SYSTEMD_TRANSITIONAL_ACTIVE_STATES
        ]
        if transitional and len(loaded) > 1:
            ambiguous = True
            reason = "loaded-transition-scope-conflict"
        elif len(running) == 1:
            selected = running[0]
            reason = "single-running-scope"
        elif len(running) > 1:
            ambiguous = True
            reason = "multiple-running-scopes"
        elif len(loaded) == 1:
            selected = loaded[0]
            reason = "single-loaded-scope"
        elif len(loaded) > 1:
            ambiguous = True
            reason = "multiple-loaded-inactive-scopes"
        else:
            absent = True
            reason = "absent-in-user-and-system-scopes"

    observation_complete = source_complete and parse_complete and not ambiguous
    return {
        "scope": selected["scope"] if selected is not None else None,
        "scope_selection_reason": reason,
        "scope_ambiguous": ambiguous,
        "scope_absent": absent,
        "scope_candidates": [_service_scope_candidate(item) for item in observations],
        "status": selected["status"] if selected is not None else {},
        "properties": selected["properties"] if selected is not None else {},
        "parse_complete": parse_complete,
        "observation_complete": observation_complete,
    }


@mcp.tool(name="service_status", annotations=READ_ANNOTATIONS)
def service_status(unit: str) -> dict[str, Any]:
    """Read one service across user and system systemd scopes without guessing on ambiguity."""
    safe_unit = _validate_unit(unit)
    resolution = _resolve_service_scope(safe_unit)
    return {
        "unit": safe_unit,
        **resolution,
        "observed_at": _utc_now(),
    }


def _process_snapshot(pid: int, control_group: str) -> dict[str, Any]:
    """Read all same-UID members of one service cgroup without argv or mutation authority."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise ValueError("pid must be a positive integer")
    if not isinstance(control_group, str) or not control_group.strip():
        raise ValueError("control_group must be non-empty")
    table = _run([
        "/usr/bin/ps", "-ww", "-eo",
        "pid=,ppid=,uid=,stat=,etimes=,rss=,pcpu=,comm=,cgroup=",
    ], timeout=20)
    source_complete = table["returncode"] == 0 and not table["stdout_truncated"]
    rows: list[dict[str, Any]] = []
    parse_complete = False
    if source_complete:
        rows, parse_complete = _parse_process_table(table["stdout"])
    cgroup_rows = [row for row in rows if _cgroup_within(row["cgroup"], control_group)]
    uid_complete = all(row["uid"] == os.getuid() for row in cgroup_rows)
    same_uid_rows = [row for row in cgroup_rows if row["uid"] == os.getuid()]
    root = next((row for row in same_uid_rows if row["pid"] == pid), None)
    complete = source_complete and parse_complete and uid_complete and root is not None
    return {
        "root_pid": pid,
        "scope": "service_cgroup_same_uid_all_members",
        "uid": os.getuid(),
        "control_group": _normalize_cgroup(control_group),
        "processes": same_uid_rows if complete else [],
        "source_returncode": table["returncode"],
        "source_truncated": table["stdout_truncated"],
        "parse_complete": parse_complete,
        "uid_complete": uid_complete,
        "complete": complete,
        "observed_at": _utc_now(),
    }


@mcp.tool(name="service_runtime", annotations=READ_ANNOTATIONS)
def service_runtime(unit: str) -> dict[str, Any]:
    """Correlate one resolved user/system service with its cgroup-bound process tree and listeners."""
    status = service_status(unit)
    props = status["properties"]
    status_complete = status["observation_complete"]
    missing: list[str] = []
    if not status_complete:
        missing.append("systemd_status")

    active_state = props.get("ActiveState")
    if status_complete and active_state is None:
        missing.append("active_state")
    if status.get("scope") not in _SYSTEMD_SCOPES:
        missing.append("systemd_scope")

    try:
        main_pid = int(props.get("MainPID", "0") or "0")
    except ValueError:
        main_pid = 0
        missing.append("main_pid")
    control_group = props.get("ControlGroup", "").strip()
    if active_state == "active" and main_pid <= 0:
        missing.append("main_pid")
    if main_pid > 0 and not control_group:
        missing.append("control_group")

    process_observation: dict[str, Any] = {
        "root_pid": main_pid,
        "scope": "service_cgroup_same_uid",
        "processes": [],
        "complete": False,
    }
    if main_pid > 0 and control_group:
        process_observation = _process_snapshot(main_pid, control_group)
        if not process_observation["complete"]:
            missing.append("process_tree")

    sockets = _run(["/usr/bin/ss", "-H", "-lntue"], timeout=20)
    socket_lines = [line for line in sockets["stdout"].splitlines() if line.strip()]
    sockets_source_complete = sockets["returncode"] == 0 and not sockets["stdout_truncated"]
    socket_cgroups: list[tuple[str, str]] = []
    unattributed_socket_lines = 0
    if sockets_source_complete:
        for line in socket_lines:
            match = re.search(r"(?:^|\s)cgroup:(\S+)", line)
            if match is None:
                unattributed_socket_lines += 1
                continue
            socket_cgroups.append((line, match.group(1)))

    listeners: list[str] = []
    if sockets_source_complete and control_group:
        listeners = [
            line for line, socket_cgroup in socket_cgroups
            if _cgroup_within(socket_cgroup, control_group)
        ]
    listener_observation_complete = (
        sockets_source_complete
        and bool(control_group)
        and bool(listeners)
        and unattributed_socket_lines == 0
    )
    if not sockets_source_complete or not control_group:
        missing.append("listeners")
    elif unattributed_socket_lines:
        missing.append("listeners")
    elif not listeners:
        missing.append("listener_absence_not_established")

    return {
        "unit": unit,
        "service_scope": status.get("scope"),
        "scope_selection_reason": status.get("scope_selection_reason"),
        "service": props,
        "main_pid": main_pid,
        "control_group": _normalize_cgroup(control_group) if control_group else None,
        "processes": process_observation.get("processes", []),
        "listeners": listeners,
        "listener_scope": "tcp_udp_positive_cgroup_evidence",
        "listener_observation_complete": listener_observation_complete,
        "listener_unattributed_source_lines": unattributed_socket_lines,
        "listener_negative_claim_supported": False,
        "missing_evidence": sorted(set(missing)),
        "complete": not missing,
        "does_not_establish": ["exhaustive_socket_inventory", "absence_of_other_listeners"],
        "observed_at": _utc_now(),
    }


@mcp.tool(name="service_logs", annotations=READ_ANNOTATIONS)
def service_logs(unit: str, lines: int = 120) -> dict[str, Any]:
    """Read bounded recent journal lines from the same resolved systemd scope as service_status."""
    safe_unit = _validate_unit(unit)
    if not isinstance(lines, int) or isinstance(lines, bool) or not 1 <= lines <= 500:
        raise ValueError("lines must be between 1 and 500")
    status = service_status(safe_unit)
    scope = status.get("scope")
    if not status["observation_complete"] or scope not in _SYSTEMD_SCOPES:
        return {
            "unit": safe_unit,
            "scope": scope,
            "scope_selection_reason": status.get("scope_selection_reason"),
            "scope_ambiguous": status.get("scope_ambiguous", False),
            "logs": None,
            "observation_complete": False,
            "observed_at": _utc_now(),
        }
    argv = ["/usr/bin/journalctl"]
    if scope == "user":
        argv.append("--user")
    else:
        argv.append("--system")
    argv.extend(["-u", safe_unit, "--no-pager", "-n", str(lines), "-o", "short-iso"])
    result = _run(argv, timeout=20)
    diagnostics_present = bool(result["stderr"].strip())
    observation_complete = (
        result["returncode"] == 0
        and not result["stdout_truncated"]
        and not result["stderr_truncated"]
        and not diagnostics_present
    )
    return {
        "unit": safe_unit,
        "scope": scope,
        "scope_selection_reason": status.get("scope_selection_reason"),
        "journal_diagnostics_present": diagnostics_present,
        "logs": result,
        "observation_complete": observation_complete,
        "observed_at": _utc_now(),
    }


def _validate_lane_id(lane_id: str) -> str:
    if not isinstance(lane_id, str) or _LANE_ID_RE.fullmatch(lane_id) is None:
        raise ValueError("lane_id must be a 32-character lowercase hex id")
    return lane_id


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _read_json_file_no_symlink(path: Path) -> dict[str, Any]:
    before = path.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) & 0o022
    ):
        raise RuntimeError(f"unsafe JSON source: {path}")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError(f"JSON source changed during open: {path}")
        chunks: list[bytes] = []
        remaining = MAX_JSON_SOURCE_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    if len(raw) > MAX_JSON_SOURCE_BYTES:
        raise RuntimeError(f"JSON source exceeds bounded size: {path}")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid JSON source: {path}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"JSON source is not an object: {path}")
    return payload


def _parse_worktree_porcelain(text: str) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            if current:
                items.append(current)
                current = {}
            continue
        key, _, value = line.partition(" ")
        current[key] = value
    if current:
        items.append(current)
    return items


def _read_work_target(lane_id: str) -> dict[str, Any]:
    safe_lane_id = _validate_lane_id(lane_id)
    lane_path = GRABOWSKI_WORK_LANES_ROOT / f"{safe_lane_id}.json"
    payload = _read_json_file_no_symlink(lane_path)
    if payload.get("kind") != "grabowski.work_lane" or payload.get("schema_version") != 1:
        raise RuntimeError("lane receipt contract is invalid")
    supplied_receipt = payload.get("receipt_sha256")
    receipt_material = {key: value for key, value in payload.items() if key != "receipt_sha256"}
    if not isinstance(supplied_receipt, str) or supplied_receipt != _sha256_json(receipt_material):
        raise RuntimeError("lane receipt digest is invalid")
    inputs = payload.get("inputs")
    if not isinstance(inputs, dict):
        raise RuntimeError("lane has no authoritative inputs")
    if payload.get("inputs_sha256") != _sha256_json(inputs):
        raise RuntimeError("lane input digest is invalid")
    if payload.get("lane_id") != safe_lane_id or inputs.get("lane_id") != safe_lane_id:
        raise RuntimeError("lane identity mismatch")
    if inputs.get("lease_owner_id") != f"lane:{safe_lane_id}":
        raise RuntimeError("lane lease-owner identity is invalid")
    if payload.get("state") != "ready" or payload.get("terminal_closeout") is not None:
        raise RuntimeError("lane is not active")

    repo_raw = inputs.get("repo")
    target_raw = inputs.get("target_path")
    branch = inputs.get("branch")
    if not all(isinstance(value, str) and value for value in (repo_raw, target_raw, branch)):
        raise RuntimeError("lane work target is incomplete")
    repo = Path(repo_raw).resolve(strict=True)
    target_input = Path(target_raw)
    if target_input.is_symlink():
        raise RuntimeError("worktree path may not be a symlink")
    target = target_input.resolve(strict=True)
    try:
        repo.relative_to(REPO_ROOT)
        target.relative_to(REPO_ROOT)
    except ValueError as exc:
        raise PermissionError("lane work target is outside repository root") from exc
    if not (repo / ".git").exists() or not (target / ".git").exists():
        raise RuntimeError("lane repository or worktree is not a Git checkout")

    inventory = _run(["/usr/bin/git", "-C", str(repo), "worktree", "list", "--porcelain"])
    if inventory["returncode"] != 0 or inventory["stdout_truncated"]:
        raise RuntimeError("Git worktree inventory is incomplete")
    matches = [
        item for item in _parse_worktree_porcelain(inventory["stdout"])
        if item.get("worktree") == str(target)
    ]
    if len(matches) != 1:
        raise RuntimeError("lane target is not one registered Git worktree")
    entry = matches[0]
    expected_ref = f"refs/heads/{branch}"
    if entry.get("branch") != expected_ref or not entry.get("HEAD"):
        raise RuntimeError("registered worktree branch does not match lane")

    head = _run(["/usr/bin/git", "-C", str(target), "rev-parse", "HEAD"])
    current_branch = _run(["/usr/bin/git", "-C", str(target), "branch", "--show-current"])
    top = _run(["/usr/bin/git", "-C", str(target), "rev-parse", "--show-toplevel"])
    reads = (head, current_branch, top)
    if any(item["returncode"] != 0 or item["stdout_truncated"] for item in reads):
        raise RuntimeError("worktree identity read is incomplete")
    checkpoint = head["stdout"].strip()
    if checkpoint != entry["HEAD"] or current_branch["stdout"].strip() != branch:
        raise RuntimeError("worktree identity drifted from registered lane")
    if Path(top["stdout"].strip()).resolve() != target:
        raise RuntimeError("worktree top-level does not match lane target")

    return {
        "lane_id": safe_lane_id,
        "repository": str(repo),
        "worktree": str(target),
        "branch": branch,
        "purpose": inputs.get("purpose"),
        "base_head": inputs.get("base_head"),
        "checkpoint": checkpoint,
        "source": str(lane_path),
        "observed_at": _utc_now(),
    }


@mcp.tool(name="get_work_target", annotations=READ_ANNOTATIONS)
def get_work_target(lane_id: str) -> dict[str, Any]:
    """Read one exact Grabowski lane target without building independent work state."""
    return _read_work_target(lane_id)


def _finding_record_view(payload: dict[str, Any], path: Path) -> dict[str, Any]:
    if payload.get("finding_contract") == FINDING_CONTRACT:
        fields = (
            "finding_id", "finding_sha256", "kind", "severity", "confidence",
            "subject", "checkpoint", "binding_strength", "summary", "evidence_refs",
            "recommendation", "affected_effects", "recheck_of", "conclusion", "observed_at",
        )
        view = {key: payload.get(key) for key in fields if key in payload}
        view["legacy"] = False
        return view

    legacy_status = payload["status"]
    return {
        "finding_id": payload["finding_id"],
        "finding_sha256": _sha256_json(payload),
        "compatibility_contract": payload.get("compatibility_contract"),
        "kind": legacy_status,
        "status": legacy_status,
        "subject_kind": payload["subject_kind"],
        "severity": payload["severity"],
        "confidence": payload.get("confidence"),
        "subject": payload["subject"],
        "checkpoint": payload.get("checkpoint"),
        "checkpoint_mode": payload.get("checkpoint_mode", "single"),
        "checkpoint_components": payload.get("checkpoint_components"),
        "checkpoint_set_sha256": payload.get("checkpoint_set_sha256"),
        "checkpoint_contract": payload.get("checkpoint_contract"),
        "binding_strength": "legacy-unbound",
        "summary": payload["summary"],
        "evidence_refs": payload["evidence_refs"],
        "target_actor": payload.get("target_actor"),
        "binding": payload.get("binding"),
        "recommendation": payload.get("recommendation"),
        "rationale": payload.get("rationale"),
        "observed_at": payload["observed_at"],
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "legacy": True,
    }


def _validate_legacy_finding_payload(payload: dict[str, Any], path: Path) -> None:
    if any(key in payload for key in _V1_ONLY_MARKERS):
        raise RuntimeError("finding contract is invalid or ambiguous")

    schema_version = payload.get("schema_version")
    if type(schema_version) is not int or schema_version not in {1, 2, 3}:
        raise RuntimeError("legacy finding schema version is invalid")
    if payload.get("adler_identity") != IDENTITY:
        raise RuntimeError("legacy finding Adler identity is invalid")
    if payload.get("effect_contract") != "advisory_only_no_automatic_action":
        raise RuntimeError("legacy finding effect contract is invalid")
    compatibility_contract = payload.get("compatibility_contract")
    if compatibility_contract is not None and compatibility_contract != LEGACY_CONNECTOR_CONTRACT:
        raise RuntimeError("legacy finding compatibility contract is invalid")

    finding_id = payload.get("finding_id")
    if (
        not isinstance(finding_id, str)
        or _FINDING_ID_RE.fullmatch(finding_id) is None
        or path.name != f"{finding_id}.json"
    ):
        raise RuntimeError("legacy finding file identity mismatch")
    if payload.get("subject_kind") not in _LEGACY_SUBJECT_KINDS:
        raise RuntimeError("legacy finding subject kind is invalid")

    subject = payload.get("subject")
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 500:
        raise RuntimeError("legacy finding subject is invalid")
    checkpoint = payload.get("checkpoint")
    if checkpoint is not None and (not isinstance(checkpoint, str) or len(checkpoint) > 500):
        raise RuntimeError("legacy finding checkpoint is invalid")
    if payload.get("severity") not in {"low", "medium", "high", "critical"}:
        raise RuntimeError("legacy finding severity is invalid")
    if payload.get("status") not in _LEGACY_STATUSES:
        raise RuntimeError("legacy finding status is invalid")

    summary = payload.get("summary")
    if not isinstance(summary, str) or not summary.strip() or len(summary) > MAX_SUMMARY_CHARS:
        raise RuntimeError("legacy finding summary is invalid")
    evidence_refs = payload.get("evidence_refs")
    if not isinstance(evidence_refs, list) or not 1 <= len(evidence_refs) <= MAX_EVIDENCE_REFS:
        raise RuntimeError("legacy finding evidence refs are invalid")
    if any(
        not isinstance(ref, str) or not ref.strip() or len(ref) > MAX_EVIDENCE_REF_CHARS
        for ref in evidence_refs
    ):
        raise RuntimeError("legacy finding evidence refs are invalid")
    observed_at = payload.get("observed_at")
    if not isinstance(observed_at, str) or not observed_at.strip() or len(observed_at) > 100:
        raise RuntimeError("legacy finding observed_at is invalid")

    relational_present = [field in payload for field in _LEGACY_RELATIONAL_FIELDS]
    relational = any(relational_present)
    if relational and not all(relational_present):
        raise RuntimeError("legacy relational checkpoint fields are incomplete")
    if relational:
        if payload.get("checkpoint_mode") != "relational":
            raise RuntimeError("legacy checkpoint mode is invalid")
        components = payload.get("checkpoint_components")
        if not isinstance(components, list) or not 2 <= len(components) <= 16:
            raise RuntimeError("legacy checkpoint components are invalid")
        names: set[str] = set()
        for component in components:
            if not isinstance(component, dict) or set(component) != {"name", "value"}:
                raise RuntimeError("legacy checkpoint component is invalid")
            name = component["name"]
            value = component["value"]
            if not isinstance(name, str) or not name.strip() or len(name) > 100:
                raise RuntimeError("legacy checkpoint component name is invalid")
            if not isinstance(value, str) or not value.strip() or len(value) > 500:
                raise RuntimeError("legacy checkpoint component value is invalid")
            if name in names:
                raise RuntimeError("legacy checkpoint component names are not unique")
            names.add(name)
        if components != sorted(components, key=lambda item: item["name"]):
            raise RuntimeError("legacy checkpoint components are not canonical")
        supplied_checkpoint_digest = payload.get("checkpoint_set_sha256")
        if (
            not isinstance(supplied_checkpoint_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", supplied_checkpoint_digest) is None
            or supplied_checkpoint_digest != _sha256_json(components)
        ):
            raise RuntimeError("legacy checkpoint set digest is invalid")
        if payload.get("checkpoint_contract") != "all_components_must_match_or_recheck":
            raise RuntimeError("legacy checkpoint contract is invalid")

    enriched_present = [field in payload for field in _LEGACY_ENRICHED_FIELDS]
    if schema_version == 3:
        if not all(enriched_present):
            raise RuntimeError("legacy enriched fields are incomplete")
        for field in ("target_actor", "binding", "recommendation", "rationale"):
            value = payload.get(field)
            if value is not None and (
                not isinstance(value, str) or not value.strip() or len(value) > MAX_SUMMARY_CHARS
            ):
                raise RuntimeError(f"legacy finding {field} is invalid")
        confidence = payload.get("confidence")
        if confidence is not None and (
            not isinstance(confidence, (int, float))
            or isinstance(confidence, bool)
            or not math.isfinite(float(confidence))
            or not 0 <= float(confidence) <= 1
        ):
            raise RuntimeError("legacy finding confidence is invalid")
        enriched = (
            payload["status"] not in _LEGACY_BASE_STATUSES
            or any(payload.get(field) is not None for field in ("target_actor", "binding", "recommendation", "rationale"))
            or confidence is not None
        )
        if not enriched:
            raise RuntimeError("legacy schema 3 finding is not enriched")
    else:
        if any(enriched_present):
            raise RuntimeError("legacy enriched fields are invalid for schema 1/2")
        if payload["status"] not in _LEGACY_BASE_STATUSES:
            raise RuntimeError("legacy status requires schema 3")

    if schema_version == 1 and relational:
        raise RuntimeError("legacy schema 1 cannot be relational")
    if schema_version == 2 and not relational:
        raise RuntimeError("legacy schema 2 must be relational")


def _validate_v1_finding_payload(payload: dict[str, Any], path: Path) -> None:
    if payload.get("finding_contract") != FINDING_CONTRACT:
        _validate_legacy_finding_payload(payload, path)
        return

    schema_version = payload.get("schema_version")
    if type(schema_version) is not int or schema_version != 1:
        raise RuntimeError("V1 finding schema version is invalid")
    if payload.get("adler_identity") != IDENTITY:
        raise RuntimeError("V1 finding Adler identity is invalid")
    if payload.get("effect_contract") != "advisory_only_no_automatic_action":
        raise RuntimeError("V1 finding effect contract is invalid")

    finding_id = payload.get("finding_id")
    if (
        not isinstance(finding_id, str)
        or _FINDING_ID_RE.fullmatch(finding_id) is None
        or path.name != f"{finding_id}.json"
    ):
        raise RuntimeError("V1 finding file identity mismatch")

    if payload.get("kind") not in {"observation", "risk", "contradiction", "missing_evidence", "advice"}:
        raise RuntimeError("V1 finding kind is invalid")
    if payload.get("severity") not in {"low", "medium", "high", "critical"}:
        raise RuntimeError("V1 finding severity is invalid")
    if payload.get("binding_strength") not in {"exact", "strong", "heuristic", "unbound"}:
        raise RuntimeError("V1 finding binding strength is invalid")

    confidence = payload.get("confidence")
    if (
        not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not math.isfinite(float(confidence))
        or not 0 <= float(confidence) <= 1
    ):
        raise RuntimeError("V1 finding confidence is invalid")

    for field in ("subject", "checkpoint"):
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip() or len(value) > 500:
            raise RuntimeError(f"V1 finding {field} is invalid")
        clean = value.strip()
        if clean != value or _redact(clean) != clean or "<REDACTED>" in clean:
            raise RuntimeError(f"V1 finding {field} is invalid")

    summary = payload.get("summary")
    if not isinstance(summary, str) or not summary.strip() or len(summary) > MAX_SUMMARY_CHARS:
        raise RuntimeError("V1 finding summary is invalid")

    evidence_refs = payload.get("evidence_refs")
    if not isinstance(evidence_refs, list) or not 1 <= len(evidence_refs) <= MAX_EVIDENCE_REFS:
        raise RuntimeError("V1 finding evidence refs are invalid")
    if any(
        not isinstance(ref, str) or not ref.strip() or len(ref) > MAX_EVIDENCE_REF_CHARS
        for ref in evidence_refs
    ):
        raise RuntimeError("V1 finding evidence refs are invalid")

    recommendation = payload.get("recommendation")
    if recommendation is not None and (
        not isinstance(recommendation, str)
        or not recommendation.strip()
        or len(recommendation) > MAX_SUMMARY_CHARS
    ):
        raise RuntimeError("V1 finding recommendation is invalid")

    affected_effects = payload.get("affected_effects")
    if affected_effects is not None:
        if not isinstance(affected_effects, list) or len(affected_effects) > MAX_AFFECTED_EFFECTS:
            raise RuntimeError("V1 finding affected effects are invalid")
        for effect in affected_effects:
            if not isinstance(effect, str) or not effect.strip() or len(effect) > MAX_AFFECTED_EFFECT_CHARS:
                raise RuntimeError("V1 finding affected effects are invalid")
            clean = effect.strip()
            if clean != effect or _redact(clean) != clean or "<REDACTED>" in clean:
                raise RuntimeError("V1 finding affected effects are invalid")

    observed_at = payload.get("observed_at")
    if not isinstance(observed_at, str) or not observed_at.strip() or len(observed_at) > 100:
        raise RuntimeError("V1 finding observed_at is invalid")

    recheck_of = payload.get("recheck_of")
    conclusion = payload.get("conclusion")
    if (recheck_of is None) != (conclusion is None):
        raise RuntimeError("V1 finding recheck fields are incomplete")
    if recheck_of is not None:
        if not isinstance(recheck_of, str) or _FINDING_ID_RE.fullmatch(recheck_of) is None:
            raise RuntimeError("V1 finding recheck target is invalid")
        if conclusion not in {"still_current", "no_longer_reproduced"}:
            raise RuntimeError("V1 finding recheck conclusion is invalid")

    supplied = payload.get("finding_sha256")
    if not isinstance(supplied, str) or not re.fullmatch(r"[0-9a-f]{64}", supplied):
        raise RuntimeError("V1 finding digest is missing or invalid")
    core = dict(payload)
    core.pop("finding_sha256", None)
    if supplied != _sha256_json(core):
        raise RuntimeError("V1 finding digest mismatch")


def _load_finding_payloads() -> tuple[list[tuple[Path, dict[str, Any]]], list[str]]:
    _ensure_state()
    records: list[tuple[Path, dict[str, Any]]] = []
    errors: list[str] = []
    for path in sorted(FINDINGS_ROOT.glob("*.json")):
        try:
            payload = _read_json_file_no_symlink(path)
            _validate_v1_finding_payload(payload, path)
        except Exception as exc:
            errors.append(type(exc).__name__)
            continue
        records.append((path, payload))

    v1_by_id = {
        str(payload["finding_id"]): payload
        for _, payload in records
        if payload.get("finding_contract") == FINDING_CONTRACT
    }
    for _, payload in records:
        if payload.get("finding_contract") != FINDING_CONTRACT:
            continue
        parent_id = payload.get("recheck_of")
        if parent_id is None:
            continue
        parent = v1_by_id.get(str(parent_id))
        if (
            parent is None
            or parent.get("recheck_of") is not None
            or parent.get("subject") != payload.get("subject")
        ):
            errors.append("RuntimeError")
    return records, errors


def _current_lane_findings(lane_id: str, checkpoint: str) -> list[dict[str, Any]]:
    subject = f"lane:{lane_id}"
    loaded, errors = _load_finding_payloads()
    if errors:
        raise RuntimeError("finding store observation is incomplete")
    records = [
        payload for _, payload in loaded
        if payload.get("finding_contract") == FINDING_CONTRACT and payload.get("subject") == subject
    ]
    legacy_subjects = {lane_id, subject}
    legacy_records = [
        (path, payload) for path, payload in loaded
        if payload.get("finding_contract") != FINDING_CONTRACT
        and payload.get("compatibility_contract") == LEGACY_CONNECTOR_CONTRACT
        and payload.get("subject_kind") == "grabowski_lane"
        and payload.get("subject") in legacy_subjects
        and payload.get("checkpoint") == checkpoint
    ]
    records.sort(key=lambda item: (str(item.get("observed_at", "")), str(item.get("finding_id", ""))))
    roots = {str(item["finding_id"]): item for item in records if not item.get("recheck_of")}
    rechecks: dict[str, list[dict[str, Any]]] = {}
    for item in records:
        parent = item.get("recheck_of")
        if isinstance(parent, str):
            rechecks.setdefault(parent, []).append(item)

    current: list[dict[str, Any]] = []
    for finding_id, root in roots.items():
        matching_rechecks = [
            item for item in rechecks.get(finding_id, []) if item.get("checkpoint") == checkpoint
        ]
        latest_recheck = matching_rechecks[-1] if matching_rechecks else None
        if latest_recheck is not None:
            if latest_recheck.get("conclusion") == "no_longer_reproduced":
                continue
            if latest_recheck.get("conclusion") != "still_current":
                continue
        elif root.get("checkpoint") != checkpoint:
            continue
        item = _finding_record_view(root, FINDINGS_ROOT / f"{finding_id}.json")
        if latest_recheck is not None:
            item["current_recheck"] = {
                key: latest_recheck.get(key)
                for key in ("finding_id", "finding_sha256", "checkpoint", "conclusion", "summary", "evidence_refs", "observed_at")
            }
        current.append(item)
    for path, payload in legacy_records:
        current.append(_finding_record_view(payload, path))
    current.sort(key=lambda item: (str(item.get("severity", "")), str(item.get("finding_id", ""))))
    return current


def _worktree_inbox_path(lane_id: str) -> Path:
    return INBOX_ROOT / f"{lane_id}.json"


def _validate_worktree_inbox_pointer(worktree: Path, lane_id: str) -> Path:
    try:
        worktree.relative_to(WORKTREE_ROOT)
    except ValueError as exc:
        raise PermissionError("lane worktree is outside Adler's delivery worktree root") from exc

    expected = _worktree_inbox_path(lane_id)
    worktree_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        worktree_flags |= os.O_NOFOLLOW
    root_fd = os.open(worktree, worktree_flags)
    try:
        try:
            sidecar_st = os.stat(".adler", dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise RuntimeError("Grabowski-owned .adler sidecar directory is missing") from exc
        if not stat.S_ISDIR(sidecar_st.st_mode) or sidecar_st.st_uid != os.getuid():
            raise RuntimeError("unsafe .adler sidecar directory")
        if stat.S_IMODE(sidecar_st.st_mode) & 0o077:
            raise RuntimeError("unsafe .adler directory permissions")
        sidecar_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            sidecar_flags |= os.O_NOFOLLOW
        dir_fd = os.open(".adler", sidecar_flags, dir_fd=root_fd)
        try:
            unexpected = set(os.listdir(dir_fd)) - {"inbox.json", ".gitignore"}
            if unexpected:
                raise RuntimeError(".adler contains files outside the inbox pointer contract")
            try:
                inbox_st = os.stat("inbox.json", dir_fd=dir_fd, follow_symlinks=False)
            except FileNotFoundError as exc:
                raise RuntimeError("Grabowski-owned .adler/inbox.json pointer is missing") from exc
            if (
                not stat.S_ISLNK(inbox_st.st_mode)
                or inbox_st.st_uid != os.getuid()
                or inbox_st.st_nlink != 1
            ):
                raise RuntimeError("unsafe .adler/inbox.json pointer")
            target = os.readlink("inbox.json", dir_fd=dir_fd)
            if target != str(expected):
                raise RuntimeError(".adler/inbox.json pointer targets the wrong Adler inbox")
        finally:
            os.close(dir_fd)
    finally:
        os.close(root_fd)
    return expected


def _open_secure_state_inbox(dir_fd: int, name: str) -> tuple[int, bytes] | None:
    try:
        before = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1:
        raise RuntimeError("unsafe existing external inbox file")
    if stat.S_IMODE(before.st_mode) & 0o077:
        raise RuntimeError("unsafe external inbox file permissions")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(name, flags, dir_fd=dir_fd)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError("external inbox changed during open")
        raw = os.read(fd, MAX_OUTPUT_BYTES + 1)
        if len(raw) > MAX_OUTPUT_BYTES:
            raise RuntimeError("external inbox is unexpectedly large")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("existing external inbox is not Adler-owned JSON") from exc
        if payload.get("writer_identity") != IDENTITY or payload.get("contract") != SIDECAR_CONTRACT:
            raise RuntimeError("existing external inbox is not Adler-owned")
        return fd, raw
    except BaseException:
        os.close(fd)
        raise


def _revalidate_open_state_inbox(fd: int, expected_raw: bytes) -> os.stat_result:
    opened = os.fstat(fd)
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_uid != os.getuid()
        or opened.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) & 0o077
    ):
        raise RuntimeError("external inbox changed before atomic publication")
    os.lseek(fd, 0, os.SEEK_SET)
    raw = os.read(fd, MAX_OUTPUT_BYTES + 1)
    if len(raw) > MAX_OUTPUT_BYTES or raw != expected_raw:
        raise RuntimeError("external inbox changed before atomic publication")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("external inbox changed before atomic publication") from exc
    if payload.get("writer_identity") != IDENTITY or payload.get("contract") != SIDECAR_CONTRACT:
        raise RuntimeError("external inbox changed before atomic publication")
    return opened


def _renameat2(dir_fd: int, left: str, right: str, flags: int) -> None:
    renameat2 = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if renameat2 is None:
        raise RuntimeError("atomic renameat2 is unavailable")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        dir_fd,
        os.fsencode(left),
        dir_fd,
        os.fsencode(right),
        flags,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), right)


def _rename_exchange(dir_fd: int, left: str, right: str) -> None:
    _renameat2(dir_fd, left, right, 2)  # RENAME_EXCHANGE


def _rename_noreplace(dir_fd: int, left: str, right: str) -> None:
    _renameat2(dir_fd, left, right, 1)  # RENAME_NOREPLACE


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write made no progress")
        view = view[written:]


def _atomic_write_inbox(dir_fd: int, name: str, encoded: bytes) -> None:
    existing = _open_secure_state_inbox(dir_fd, name)
    existing_fd: int | None = None
    existing_raw: bytes | None = None
    if existing is not None:
        existing_fd, existing_raw = existing

    tmp_name = f".{name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(tmp_name, flags, 0o600, dir_fd=dir_fd)
    our_temp_at_tmp = True
    try:
        _write_all(fd, encoded)
        os.fsync(fd)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1:
            raise RuntimeError("unsafe external inbox temporary file")
    except BaseException:
        try:
            os.unlink(tmp_name, dir_fd=dir_fd)
            our_temp_at_tmp = False
        finally:
            os.close(fd)
            if existing_fd is not None:
                os.close(existing_fd)
        raise
    else:
        os.close(fd)

    try:
        if existing_fd is None:
            _rename_noreplace(dir_fd, tmp_name, name)
            our_temp_at_tmp = False
            os.fsync(dir_fd)
            return

        assert existing_raw is not None
        _rename_exchange(dir_fd, tmp_name, name)
        our_temp_at_tmp = False
        try:
            displaced = os.stat(tmp_name, dir_fd=dir_fd, follow_symlinks=False)
            validated = _revalidate_open_state_inbox(existing_fd, existing_raw)
            if (displaced.st_dev, displaced.st_ino) != (validated.st_dev, validated.st_ino):
                raise RuntimeError("external inbox changed before atomic publication")
        except BaseException:
            try:
                _rename_exchange(dir_fd, tmp_name, name)
                our_temp_at_tmp = True
            except BaseException as rollback_exc:
                raise RuntimeError("external inbox changed and atomic rollback failed") from rollback_exc
            raise

        os.fsync(dir_fd)
        os.unlink(tmp_name, dir_fd=dir_fd)
        os.fsync(dir_fd)
    finally:
        if our_temp_at_tmp:
            try:
                os.unlink(tmp_name, dir_fd=dir_fd)
            except FileNotFoundError:
                pass
        if existing_fd is not None:
            os.close(existing_fd)


def _publish_worktree_inbox(
    lane_id: str, *, expected_checkpoint: str | None = None
) -> dict[str, Any]:
    initial_target = _read_work_target(lane_id)
    if expected_checkpoint is not None and initial_target["checkpoint"] != expected_checkpoint:
        raise RuntimeError("lane checkpoint changed before inbox publication")
    worktree = Path(initial_target["worktree"])
    inbox_path = _validate_worktree_inbox_pointer(worktree, lane_id)
    _ensure_state()
    inbox_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        inbox_flags |= os.O_NOFOLLOW
    inbox_dir_fd = os.open(INBOX_ROOT, inbox_flags)
    locked = False
    try:
        fcntl.flock(inbox_dir_fd, fcntl.LOCK_EX)
        locked = True
        target = _read_work_target(lane_id)
        if Path(target["worktree"]) != worktree:
            raise RuntimeError("lane worktree changed during inbox publication")
        if expected_checkpoint is not None and target["checkpoint"] != expected_checkpoint:
            raise RuntimeError("lane checkpoint changed during inbox publication")
        if _validate_worktree_inbox_pointer(worktree, lane_id) != inbox_path:
            raise RuntimeError("worktree inbox pointer changed during publication")
        findings = _current_lane_findings(lane_id, target["checkpoint"])
        payload = {
            "schema_version": 1,
            "contract": SIDECAR_CONTRACT,
            "writer_identity": IDENTITY,
            "delivery_mode": "grabowski_owned_symlink_to_adler_state",
            "lane_id": lane_id,
            "repository": target["repository"],
            "worktree": target["worktree"],
            "branch": target["branch"],
            "checkpoint": target["checkpoint"],
            "source_complete": True,
            "source_store": str(FINDINGS_ROOT),
            "inbox_store": str(inbox_path),
            "findings": findings,
            "generated_at": _utc_now(),
            "effect_contract": "advisory_only_no_automatic_action",
            "does_not_establish": [
                "absence_of_findings_after_generated_at",
                "work_state_authority",
                "decision_authority",
                "effect_permission",
            ],
        }
        encoded = (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        if len(encoded) > MAX_OUTPUT_BYTES:
            raise RuntimeError("worktree inbox exceeds bounded size")
        _atomic_write_inbox(inbox_dir_fd, inbox_path.name, encoded)
        published_target = _read_work_target(lane_id)
        if Path(published_target["worktree"]) != worktree:
            raise RuntimeError("lane worktree changed after inbox publication")
        if published_target["checkpoint"] != target["checkpoint"]:
            raise RuntimeError("lane checkpoint changed after inbox publication")
        if _validate_worktree_inbox_pointer(worktree, lane_id) != inbox_path:
            raise RuntimeError("worktree inbox pointer changed after publication")
    finally:
        if locked:
            fcntl.flock(inbox_dir_fd, fcntl.LOCK_UN)
        os.close(inbox_dir_fd)
    return {
        "state": "published",
        "lane_id": lane_id,
        "checkpoint": target["checkpoint"],
        "finding_count": len(findings),
        "sidecar": str(worktree / ".adler" / "inbox.json"),
        "inbox_store": str(inbox_path),
        "source_complete": True,
        "observed_at": _utc_now(),
    }


@mcp.tool(name="publish_worktree_inbox", annotations=SIDECAR_ANNOTATIONS)
def publish_worktree_inbox(lane_id: str) -> dict[str, Any]:
    """Rebuild one current advisory inbox for an exact active Grabowski lane."""
    return _publish_worktree_inbox(_validate_lane_id(lane_id))


@mcp.tool(name="list_findings", annotations=READ_ANNOTATIONS)
def list_findings(limit: int = 20) -> dict[str, Any]:
    """List recent immutable findings while keeping legacy records readable."""
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    records, errors = _load_finding_payloads()
    selected = records[-limit:]
    items = [_finding_record_view(payload, path) for path, payload in reversed(selected)]
    return {
        "count": len(items),
        "findings": items,
        "source_complete": not errors,
        "source_error_count": len(errors),
        "observed_at": _utc_now(),
    }


def _clean_required_identity_text(value: str, field: str, *, max_chars: int = 500) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_chars:
        raise ValueError(f"{field} must be 1..{max_chars} characters")
    clean = value.strip()
    if _redact(clean) != clean or "<REDACTED>" in clean:
        raise ValueError(f"{field} requiring redaction cannot be persisted")
    return clean


def _clean_optional_text(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_SUMMARY_CHARS:
        raise ValueError(f"{field} must be 1..{MAX_SUMMARY_CHARS} characters when supplied")
    return _redact(value.strip())


def _persist_finding(payload: dict[str, Any]) -> tuple[str, str]:
    payload = dict(payload)
    target_name = f"{payload['finding_id']}.json"
    target_path = FINDINGS_ROOT / target_name
    if payload.get("finding_contract") == FINDING_CONTRACT:
        finding_sha256 = _sha256_json(payload)
        payload["finding_sha256"] = finding_sha256
        _validate_v1_finding_payload(payload, target_path)
    else:
        _validate_legacy_finding_payload(payload, target_path)
        finding_sha256 = _sha256_json(payload)
    encoded = (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    tmp_name = f".finding-{payload['finding_id']}-{uuid.uuid4().hex}.tmp"
    dir_fd = os.open(FINDINGS_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    locked = False
    tmp_created = False
    try:
        fcntl.flock(dir_fd, fcntl.LOCK_EX)
        locked = True
        try:
            os.stat(target_name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(f"finding already exists: {target_name}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(tmp_name, flags, 0o600, dir_fd=dir_fd)
        tmp_created = True
        try:
            _write_all(fd, encoded)
            os.fsync(fd)
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1:
                raise RuntimeError("unsafe finding temporary file")
        finally:
            os.close(fd)
        _rename_noreplace(dir_fd, tmp_name, target_name)
        tmp_created = False
        os.fsync(dir_fd)
    finally:
        if tmp_created:
            try:
                os.unlink(tmp_name, dir_fd=dir_fd)
            except FileNotFoundError:
                pass
        if locked:
            fcntl.flock(dir_fd, fcntl.LOCK_UN)
        os.close(dir_fd)
    return finding_sha256, hashlib.sha256(encoded).hexdigest()


@mcp.tool(name="submit_finding_v1", annotations=FINDING_ANNOTATIONS)
def submit_finding(
    kind: Literal["observation", "risk", "contradiction", "missing_evidence", "advice"],
    severity: Literal["low", "medium", "high", "critical"],
    confidence: float,
    subject: str,
    checkpoint: str,
    binding_strength: Literal["exact", "strong", "heuristic", "unbound"],
    summary: str,
    evidence_refs: list[str],
    recommendation: str | None = None,
    affected_effects: list[str] | None = None,
    recheck_of: str | None = None,
    conclusion: Literal["still_current", "no_longer_reproduced"] | None = None,
) -> dict[str, Any]:
    """Append one strict adler-finding-v1 record and best-effort project exact lane findings."""
    _ensure_state()
    subject_clean = _clean_required_identity_text(subject, "subject")
    checkpoint_clean = _clean_required_identity_text(checkpoint, "checkpoint")
    if not isinstance(summary, str) or not summary.strip() or len(summary) > MAX_SUMMARY_CHARS:
        raise ValueError(f"summary must be 1..{MAX_SUMMARY_CHARS} characters")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not math.isfinite(float(confidence)) or not 0 <= float(confidence) <= 1:
        raise ValueError("confidence must be a finite number between 0 and 1")
    if not isinstance(evidence_refs, list) or not 1 <= len(evidence_refs) <= MAX_EVIDENCE_REFS:
        raise ValueError(f"evidence_refs must contain 1..{MAX_EVIDENCE_REFS} entries")
    cleaned_refs: list[str] = []
    for ref in evidence_refs:
        if not isinstance(ref, str) or not ref.strip() or len(ref) > MAX_EVIDENCE_REF_CHARS:
            raise ValueError("invalid evidence reference")
        cleaned_refs.append(_redact(ref.strip()))
    recommendation_clean = _clean_optional_text(recommendation, "recommendation")

    effects: list[str] = []
    if affected_effects is not None:
        if not isinstance(affected_effects, list) or len(affected_effects) > MAX_AFFECTED_EFFECTS:
            raise ValueError(f"affected_effects must contain at most {MAX_AFFECTED_EFFECTS} entries")
        for effect in affected_effects:
            effects.append(_clean_required_identity_text(effect, "affected_effect", max_chars=MAX_AFFECTED_EFFECT_CHARS))
    if (recheck_of is None) != (conclusion is None):
        raise ValueError("recheck_of and conclusion must be supplied together")
    if recheck_of is not None:
        if not isinstance(recheck_of, str) or _FINDING_ID_RE.fullmatch(recheck_of) is None:
            raise ValueError("invalid recheck_of finding id")
        parent_path = FINDINGS_ROOT / f"{recheck_of}.json"
        if not parent_path.exists():
            raise ValueError("recheck_of finding does not exist")
        parent = _read_json_file_no_symlink(parent_path)
        try:
            _validate_v1_finding_payload(parent, parent_path)
        except (RuntimeError, ValueError) as exc:
            raise ValueError("recheck_of must reference a valid V1 finding") from exc
        if parent.get("finding_contract") != FINDING_CONTRACT:
            raise ValueError("recheck_of must reference a V1 finding")
        if parent.get("recheck_of") is not None:
            raise ValueError("recheck_of must reference a root finding")
        if parent.get("subject") != subject_clean:
            raise ValueError("recheck subject must match original finding")

    observed_at = _utc_now()
    finding_id = f"ga-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:12]}"
    payload: dict[str, Any] = {
        "schema_version": 1,
        "finding_contract": FINDING_CONTRACT,
        "finding_id": finding_id,
        "adler_identity": IDENTITY,
        "kind": kind,
        "severity": severity,
        "confidence": float(confidence),
        "subject": subject_clean,
        "checkpoint": checkpoint_clean,
        "binding_strength": binding_strength,
        "summary": _redact(summary.strip()),
        "evidence_refs": cleaned_refs,
        "observed_at": observed_at,
        "effect_contract": "advisory_only_no_automatic_action",
    }
    if recommendation_clean is not None:
        payload["recommendation"] = recommendation_clean
    if effects:
        payload["affected_effects"] = effects
    if recheck_of is not None:
        payload["recheck_of"] = recheck_of
        payload["conclusion"] = conclusion

    finding_sha256, record_sha256 = _persist_finding(payload)
    delivery: dict[str, Any] = {"state": "not_applicable"}
    lane_match = _LANE_SUBJECT_RE.fullmatch(subject_clean)
    if lane_match is not None:
        try:
            delivery = _publish_worktree_inbox(
                lane_match.group(1),
                expected_checkpoint=checkpoint_clean,
            )
        except Exception as exc:
            delivery = {
                "state": "delivery_failed",
                "error_type": type(exc).__name__,
                "source_complete": False,
                "finding_remains_durable": True,
            }
    return {
        "accepted": True,
        "finding_id": finding_id,
        "finding_sha256": finding_sha256,
        "record_sha256": record_sha256,
        "observed_at": observed_at,
        "automatic_effect": False,
        "delivery": delivery,
        "next_action": "Grabowski or the working agent may read the advisory view and independently decide what to do.",
    }


@mcp.tool(name="submit_finding", annotations=FINDING_ANNOTATIONS)
def submit_finding_legacy(
    subject_kind: Literal["repo", "pr", "commit", "runtime", "bureau_task", "grabowski_lane"],
    subject: str,
    severity: Literal["low", "medium", "high", "critical"],
    summary: str,
    evidence_refs: list[str],
    checkpoint: str | None = None,
    status: Literal["observation", "finding", "recheck_suggested"] = "finding",
) -> dict[str, Any]:
    """Accept the historical connector shape; grabowski_lane subjects are exact lane ids or lane:<id>."""
    _ensure_state()
    if subject_kind not in {"repo", "pr", "commit", "runtime", "bureau_task", "grabowski_lane"}:
        raise ValueError("unsupported legacy subject_kind")
    if severity not in {"low", "medium", "high", "critical"}:
        raise ValueError("invalid severity")
    if status not in _LEGACY_BASE_STATUSES:
        raise ValueError("unsupported legacy status")

    subject_clean = _clean_required_identity_text(subject, "subject")
    if checkpoint is None:
        checkpoint_clean = None
    elif not isinstance(checkpoint, str) or len(checkpoint) > 500:
        raise ValueError("checkpoint must be a string of at most 500 characters")
    else:
        checkpoint_clean = _redact(checkpoint)
    if not isinstance(summary, str) or not summary.strip() or len(summary) > MAX_SUMMARY_CHARS:
        raise ValueError(f"summary must be 1..{MAX_SUMMARY_CHARS} characters")
    if not isinstance(evidence_refs, list) or not 1 <= len(evidence_refs) <= MAX_EVIDENCE_REFS:
        raise ValueError(f"evidence_refs must contain 1..{MAX_EVIDENCE_REFS} entries")
    cleaned_refs: list[str] = []
    for ref in evidence_refs:
        if not isinstance(ref, str) or not ref.strip() or len(ref) > MAX_EVIDENCE_REF_CHARS:
            raise ValueError("invalid evidence reference")
        cleaned_refs.append(_redact(ref.strip()))

    lane_id: str | None = None
    if subject_kind == "grabowski_lane":
        direct_lane = subject_clean if _LANE_ID_RE.fullmatch(subject_clean) is not None else None
        prefixed_lane = _LANE_SUBJECT_RE.fullmatch(subject_clean)
        lane_id = direct_lane or (prefixed_lane.group(1) if prefixed_lane is not None else None)

    observed_at = _utc_now()
    finding_id = f"ga-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:12]}"
    payload: dict[str, Any] = {
        "schema_version": 1,
        "finding_id": finding_id,
        "adler_identity": IDENTITY,
        "compatibility_contract": LEGACY_CONNECTOR_CONTRACT,
        "subject_kind": subject_kind,
        "subject": subject_clean,
        "checkpoint": checkpoint_clean,
        "severity": severity,
        "status": status,
        "summary": _redact(summary.strip()),
        "evidence_refs": cleaned_refs,
        "observed_at": observed_at,
        "effect_contract": "advisory_only_no_automatic_action",
    }
    finding_sha256, record_sha256 = _persist_finding(payload)

    delivery: dict[str, Any] = {"state": "not_applicable"}
    if lane_id is not None and checkpoint_clean not in {None, ""}:
        try:
            delivery = _publish_worktree_inbox(
                lane_id, expected_checkpoint=checkpoint_clean
            )
        except Exception as exc:
            delivery = {
                "state": "delivery_failed",
                "error_type": type(exc).__name__,
                "source_complete": False,
                "finding_remains_durable": True,
            }
    return {
        "accepted": True,
        "finding_id": finding_id,
        "finding_sha256": finding_sha256,
        "record_sha256": record_sha256,
        "sha256": record_sha256,
        "legacy": True,
        "compatibility_contract": LEGACY_CONNECTOR_CONTRACT,
        "observed_at": observed_at,
        "automatic_effect": False,
        "delivery": delivery,
        "next_action": "Grabowski or the working agent may read the advisory view and independently decide what to do.",
    }


@mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
async def healthz(_request: Any) -> Any:
    from starlette.responses import JSONResponse
    return JSONResponse({"healthy": True, "identity": IDENTITY}, headers={"Cache-Control": "no-store"})


@mcp.custom_route("/readyz", methods=["GET"], include_in_schema=False)
async def readyz(_request: Any) -> Any:
    from starlette.responses import JSONResponse
    try:
        _ensure_state()
        ready = REPO_ROOT.is_dir() and FINDINGS_ROOT.is_dir()
    except Exception:
        ready = False
    return JSONResponse(
        {"ready": ready, "identity": IDENTITY},
        status_code=200 if ready else 503,
        headers={"Cache-Control": "no-store"},
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Großer Adler observer MCP service.")
    parser.add_argument("--transport", choices=("stdio", "streamable-http"), default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18186)
    args = parser.parse_args()
    _ensure_state()
    if args.transport == "streamable-http":
        if args.host != "127.0.0.1":
            raise SystemExit("Großer Adler HTTP transport must bind to 127.0.0.1")
        if not 1024 <= args.port <= 65535:
            raise SystemExit("port must be between 1024 and 65535")
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        mcp.settings.stateless_http = True
        if hasattr(mcp.settings, "session_idle_timeout"):
            mcp.settings.session_idle_timeout = None
        if hasattr(mcp.settings, "max_sessions"):
            mcp.settings.max_sessions = None
        mcp.settings.log_level = "WARNING"
        mcp.streamable_http_app()
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
