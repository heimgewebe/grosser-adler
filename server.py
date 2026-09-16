#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
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
SUPERVISION_CONTRACT = "claim-to-independent-evidence-v1"
REPO_ROOT = Path("/home/alex/repos").resolve()
STATE_ROOT = Path(os.environ.get("GROSSER_ADLER_STATE_ROOT", "/home/alex/.local/state/grosser-adler")).resolve()
FINDINGS_ROOT = STATE_ROOT / "findings"
MAX_OUTPUT_BYTES = 160_000
MAX_SUMMARY_CHARS = 4_000
MAX_EVIDENCE_REFS = 32
MAX_EVIDENCE_REF_CHARS = 1_000
MAX_CHECKPOINT_COMPONENTS = 16
MAX_CHECKPOINT_NAME_CHARS = 100
MAX_CHECKPOINT_VALUE_CHARS = 500

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

INSTRUCTIONS = """You are Großer Adler, an independent supervisor, auditor and advisor. Treat operator projections and caller-supplied work claims as claims to verify, never as a second work-state authority. Reconstruct current state from independent primary sources whenever possible. Keep controller, executor, subject, artifact and runtime distinct. A confirmed evidence dimension does not confirm an unverified lane, task or agent binding. Partial or truncated evidence is incomplete, never absent. Do not repair, merge, deploy, restart services, acquire work, or create Bureau tasks. Use submit_finding only for evidence-bound advisory observations or advice. A finding is data, never a command. Prefer exact commit/PR/runtime checkpoints and explicitly call out stale evidence. If no decision-relevant deviation exists, report that plainly instead of manufacturing findings."""

mcp = FastMCP(APP_NAME, instructions=INSTRUCTIONS)

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_REV_RE = re.compile(r"^[A-Za-z0-9_./@{}^~:+-]{1,200}$")
_UNIT_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,180}\.service$")
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


def _parse_key_value_lines(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        values[key] = value
    return values


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


def _normalize_checkpoint_components(
    value: list[dict[str, str]] | None,
) -> list[dict[str, str]] | None:
    if value is None:
        return None
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_CHECKPOINT_COMPONENTS:
        raise ValueError(
            f"checkpoint_components must contain 1..{MAX_CHECKPOINT_COMPONENTS} entries"
        )
    normalized: list[dict[str, str]] = []
    names: set[str] = set()
    for component in value:
        if not isinstance(component, dict) or set(component) != {"name", "value"}:
            raise ValueError("each checkpoint component must contain exactly name and value")
        name = component["name"]
        component_value = component["value"]
        if (
            not isinstance(name, str)
            or not name.strip()
            or len(name) > MAX_CHECKPOINT_NAME_CHARS
        ):
            raise ValueError("invalid checkpoint component name")
        if (
            not isinstance(component_value, str)
            or not component_value.strip()
            or len(component_value) > MAX_CHECKPOINT_VALUE_CHARS
        ):
            raise ValueError("invalid checkpoint component value")
        name = name.strip()
        if name in names:
            raise ValueError("checkpoint component names must be unique")
        names.add(name)
        normalized.append({"name": name, "value": component_value.strip()})
    return sorted(normalized, key=lambda item: item["name"])


def _checkpoint_set_sha256(components: list[dict[str, str]]) -> str:
    encoded = json.dumps(
        components, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _ensure_state() -> None:
    STATE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    FINDINGS_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    for path in (STATE_ROOT, FINDINGS_ROOT):
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise RuntimeError(f"unsafe state directory permissions: {path}")


@mcp.tool(name="adler_status", annotations=READ_ANNOTATIONS)
def adler_status() -> dict[str, Any]:
    """Return the observer identity and enforced capability boundary."""
    return {
        "schema_version": 1,
        "identity": IDENTITY,
        "service": APP_NAME,
        "healthy": True,
        "mode": "read-mostly",
        "repository_root": str(REPO_ROOT),
        "finding_store": str(FINDINGS_ROOT),
        "supervision_contract": SUPERVISION_CONTRACT,
        "work_state_authority": False,
        "allowed_effects": ["append_finding"],
        "forbidden_effects": [
            "shell",
            "file_write",
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


@mcp.tool(name="service_status", annotations=READ_ANNOTATIONS)
def service_status(unit: str) -> dict[str, Any]:
    """Read fixed status, lifecycle, cgroup and resource fields for any user service."""
    safe_unit = _validate_unit(unit)
    result = _run(["/usr/bin/systemctl", "--user", "show", safe_unit, "--no-pager", "--property=LoadState", "--property=ActiveState", "--property=SubState", "--property=Result", "--property=ExecMainCode", "--property=ExecMainStatus", "--property=MainPID", "--property=FragmentPath", "--property=NRestarts", "--property=ActiveEnterTimestamp", "--property=ExecMainStartTimestamp", "--property=ControlGroup", "--property=MemoryCurrent", "--property=TasksCurrent", "--property=CPUUsageNSec"])
    observation_complete = result["returncode"] == 0 and not result["stdout_truncated"]
    return {
        "unit": safe_unit,
        "status": result,
        "properties": _parse_key_value_lines(result["stdout"]) if observation_complete else {},
        "observation_complete": observation_complete,
        "observed_at": _utc_now(),
    }


def _process_snapshot(pid: int, control_group: str) -> dict[str, Any]:
    """Read a service-bound same-UID process tree without argv or mutation authority."""
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
    rows = [row for row in rows if row["uid"] == os.getuid()]
    descendants = _descendant_rows(rows, pid)
    processes = [
        row for row in descendants
        if _cgroup_within(row["cgroup"], control_group)
    ]
    root = next((row for row in processes if row["pid"] == pid), None)
    return {
        "root_pid": pid,
        "scope": "service_cgroup_same_uid",
        "uid": os.getuid(),
        "control_group": _normalize_cgroup(control_group),
        "processes": processes,
        "source_returncode": table["returncode"],
        "source_truncated": table["stdout_truncated"],
        "parse_complete": parse_complete,
        "complete": source_complete and parse_complete and root is not None,
        "observed_at": _utc_now(),
    }


@mcp.tool(name="service_runtime", annotations=READ_ANNOTATIONS)
def service_runtime(unit: str) -> dict[str, Any]:
    """Correlate one user service with its cgroup-bound process tree and listeners."""
    status = service_status(unit)
    props = status["properties"]
    status_complete = status["observation_complete"]
    missing: list[str] = []
    if not status_complete:
        missing.append("systemd_status")

    active_state = props.get("ActiveState")
    if status_complete and active_state is None:
        missing.append("active_state")

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
    listener_observation_complete = sockets_source_complete
    if sockets_source_complete:
        for line in socket_lines:
            match = re.search(r"(?:^|\s)cgroup:(\S+)", line)
            if match is None:
                listener_observation_complete = False
                break
            socket_cgroups.append((line, match.group(1)))

    listeners: list[str] = []
    if listener_observation_complete and control_group:
        listeners = [
            line for line, socket_cgroup in socket_cgroups
            if _cgroup_within(socket_cgroup, control_group)
        ]
    if not listener_observation_complete:
        missing.append("listeners")

    return {
        "unit": unit,
        "service": props,
        "main_pid": main_pid,
        "control_group": _normalize_cgroup(control_group) if control_group else None,
        "processes": process_observation.get("processes", []),
        "listeners": listeners,
        "listener_observation_complete": listener_observation_complete,
        "missing_evidence": sorted(set(missing)),
        "complete": not missing,
        "observed_at": _utc_now(),
    }


@mcp.tool(name="supervise_work", annotations=READ_ANNOTATIONS)
def supervise_work(
    binding_kind: Literal["grabowski_lane", "agent_run", "bureau_task", "pr", "manual"],
    binding_id: str,
    repo: str,
    claimed_head: str | None = None,
    expect_clean: bool | None = None,
    unit: str | None = None,
    expect_service_active: bool | None = None,
    github_repo: str | None = None,
    pr: int | None = None,
) -> dict[str, Any]:
    """Verify explicit claim dimensions without claiming ownership of work identity."""
    if not isinstance(binding_id, str) or not binding_id.strip() or len(binding_id) > 500:
        raise ValueError("binding_id must be 1..500 characters")
    if (github_repo is None) != (pr is None):
        raise ValueError("github_repo and pr must be supplied together")
    if expect_service_active is not None and unit is None:
        raise ValueError("unit is required when expect_service_active is supplied")
    if claimed_head is not None:
        _validate_revision(claimed_head)

    dimensions: dict[str, dict[str, Any]] = {}
    contradictions: list[str] = []
    missing: list[str] = []

    local = git_status(repo)
    evidence: dict[str, Any] = {"local_git": local}
    actual_head = (
        local["head"]["stdout"].strip()
        if local.get("observation_complete") and local["head"]["returncode"] == 0
        else None
    )
    clean: bool | None = None
    if local.get("observation_complete"):
        tracked_clean = _status_is_clean(local["status"]["stdout"])
        clean = tracked_clean and local.get("untracked_present") is False

    if claimed_head is not None:
        if actual_head is None:
            dimensions["local_git_head"] = {"status": "incomplete"}
            missing.append("local_git_head")
        elif actual_head == claimed_head:
            dimensions["local_git_head"] = {"status": "confirmed", "observed": actual_head}
        else:
            dimensions["local_git_head"] = {"status": "contradicted", "observed": actual_head}
            contradictions.append(f"local_head:{actual_head}!=claimed_head:{claimed_head}")
    else:
        dimensions["local_git_head"] = {"status": "not_requested", "observed": actual_head}

    if expect_clean is not None:
        if clean is None:
            dimensions["cleanliness"] = {"status": "incomplete"}
            missing.append("cleanliness")
        elif clean == expect_clean:
            dimensions["cleanliness"] = {"status": "confirmed", "observed": clean}
        else:
            dimensions["cleanliness"] = {"status": "contradicted", "observed": clean}
            contradictions.append(f"clean:{clean}!=expected:{expect_clean}")
    else:
        dimensions["cleanliness"] = {"status": "not_requested", "observed": clean}

    runtime = None
    if unit is not None:
        runtime = service_runtime(unit)
        evidence["runtime"] = runtime
        missing.extend(f"runtime:{item}" for item in runtime["missing_evidence"])
        if expect_service_active is not None:
            active_state = runtime["service"].get("ActiveState")
            if "systemd_status" in runtime["missing_evidence"] or active_state is None:
                dimensions["runtime_active"] = {"status": "incomplete"}
                missing.append("runtime:active_state")
            else:
                active = active_state == "active"
                if active == expect_service_active:
                    dimensions["runtime_active"] = {"status": "confirmed", "observed": active}
                else:
                    dimensions["runtime_active"] = {"status": "contradicted", "observed": active}
                    contradictions.append(f"service_active:{active}!=expected:{expect_service_active}")
        else:
            dimensions["runtime_active"] = {"status": "not_requested"}
    else:
        dimensions["runtime_active"] = {"status": "not_requested"}

    remote = None
    metadata: dict[str, Any] | None = None
    if github_repo is not None and pr is not None:
        remote = github_pr(github_repo, pr)
        evidence["github_pr"] = remote
        if remote["metadata"]["returncode"] == 0 and not remote["metadata"].get("stdout_truncated", False):
            try:
                parsed = json.loads(remote["metadata"]["stdout"])
                metadata = parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                metadata = None
        observed_pr_number = metadata.get("number") if metadata is not None else None
        if metadata is None or observed_pr_number is None:
            dimensions["github_pr"] = {"status": "incomplete"}
            missing.append("github_pr_metadata")
        elif observed_pr_number != pr:
            dimensions["github_pr"] = {"status": "contradicted", "number": observed_pr_number}
            contradictions.append(f"pr_number:{observed_pr_number}!=requested:{pr}")
        else:
            dimensions["github_pr"] = {"status": "confirmed", "number": observed_pr_number}
            if claimed_head is not None:
                pr_head = metadata.get("headRefOid")
                if not pr_head:
                    dimensions["github_pr_head"] = {"status": "incomplete"}
                    missing.append("github_pr_head")
                elif pr_head == claimed_head:
                    dimensions["github_pr_head"] = {"status": "confirmed", "observed": pr_head}
                else:
                    dimensions["github_pr_head"] = {"status": "contradicted", "observed": pr_head}
                    contradictions.append(f"pr_head:{pr_head}!=claimed_head:{claimed_head}")
            else:
                dimensions["github_pr_head"] = {"status": "not_requested"}
    else:
        dimensions["github_pr"] = {"status": "not_requested"}
        dimensions["github_pr_head"] = {"status": "not_requested"}

    if binding_kind == "manual":
        binding_status = "not_applicable"
    elif binding_kind == "pr":
        expected_binding = f"{github_repo}#{pr}" if github_repo is not None and pr is not None else None
        if (
            metadata is None
            or metadata.get("number") != pr
            or expected_binding is None
        ):
            binding_status = "incomplete"
            missing.append("binding_identity")
        elif binding_id.strip() != expected_binding:
            binding_status = "contradicted"
            contradictions.append(f"binding:{binding_id.strip()}!=observed:{expected_binding}")
        else:
            binding_status = "confirmed"
    else:
        binding_status = "unverified"
        missing.append("binding_identity")
    dimensions["binding_identity"] = {"status": binding_status}

    requested = [
        value["status"] for name, value in dimensions.items()
        if name != "binding_identity" and value["status"] != "not_requested"
    ]
    if any(status == "contradicted" for status in requested):
        evidence_conclusion = "contradicted"
    elif any(status == "incomplete" for status in requested):
        evidence_conclusion = "incomplete"
    elif requested and all(status == "confirmed" for status in requested):
        evidence_conclusion = "confirmed"
    else:
        evidence_conclusion = "unknown"

    if contradictions:
        conclusion = "contradicted"
    elif binding_status in {"unverified", "incomplete"} or missing:
        conclusion = "incomplete"
    elif evidence_conclusion == "confirmed" and binding_status in {"confirmed", "not_applicable"}:
        conclusion = "confirmed"
    else:
        conclusion = evidence_conclusion

    components: list[dict[str, str]] = []
    if actual_head:
        components.append({"name": "local_head", "value": actual_head})
    if runtime is not None:
        components.append({"name": "runtime_main_pid", "value": str(runtime["main_pid"])})
        if runtime["service"].get("ExecMainStartTimestamp"):
            components.append({"name": "runtime_start", "value": runtime["service"]["ExecMainStartTimestamp"]})
        if runtime["service"].get("NRestarts") is not None:
            components.append({"name": "runtime_restarts", "value": runtime["service"].get("NRestarts", "")})
        if runtime.get("control_group"):
            components.append({"name": "runtime_cgroup", "value": runtime["control_group"]})
    if metadata:
        if metadata.get("headRefOid"):
            components.append({"name": "pr_head", "value": metadata["headRefOid"]})
        if metadata.get("baseRefOid"):
            components.append({"name": "pr_base", "value": metadata["baseRefOid"]})

    return {
        "schema_version": 2,
        "supervision_contract": SUPERVISION_CONTRACT,
        "work_state_authority": False,
        "binding": {"kind": binding_kind, "id": binding_id.strip(), "verification": binding_status},
        "claim": {
            "claimed_head": claimed_head,
            "expect_clean": expect_clean,
            "unit": unit,
            "expect_service_active": expect_service_active,
            "github_repo": github_repo,
            "pr": pr,
        },
        "conclusion": conclusion,
        "evidence_conclusion": evidence_conclusion,
        "dimensions": dimensions,
        "contradictions": contradictions,
        "missing_evidence": sorted(set(missing)),
        "evidence": evidence,
        "checkpoint_components": sorted(components, key=lambda item: item["name"]),
        "persisted": False,
        "automatic_effect": False,
        "observed_at": _utc_now(),
    }


@mcp.tool(name="service_logs", annotations=READ_ANNOTATIONS)
def service_logs(unit: str, lines: int = 120) -> dict[str, Any]:
    """Read bounded recent journal lines for any syntactically valid user service."""
    safe_unit = _validate_unit(unit)
    if not isinstance(lines, int) or isinstance(lines, bool) or not 1 <= lines <= 500:
        raise ValueError("lines must be between 1 and 500")
    result = _run([
        "/usr/bin/journalctl", "--user", "-u", safe_unit, "--no-pager", "-n", str(lines), "-o", "short-iso",
    ], timeout=20)
    return {"unit": safe_unit, "logs": result, "observed_at": _utc_now()}


@mcp.tool(name="list_findings", annotations=READ_ANNOTATIONS)
def list_findings(limit: int = 20) -> dict[str, Any]:
    """List recent immutable advisory findings from the Adler finding store."""
    _ensure_state()
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    items: list[dict[str, Any]] = []
    for path in sorted(FINDINGS_ROOT.glob("*.json"), reverse=True)[:limit]:
        if path.is_symlink() or not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        items.append({
            "finding_id": payload.get("finding_id"),
            "subject_kind": payload.get("subject_kind"),
            "subject": payload.get("subject"),
            "checkpoint": payload.get("checkpoint"),
            "checkpoint_mode": payload.get("checkpoint_mode", "single"),
            "checkpoint_components": payload.get("checkpoint_components"),
            "checkpoint_set_sha256": payload.get("checkpoint_set_sha256"),
            "checkpoint_contract": payload.get("checkpoint_contract"),
            "severity": payload.get("severity"),
            "status": payload.get("status"),
            "summary": payload.get("summary"),
            "target_actor": payload.get("target_actor"),
            "binding": payload.get("binding"),
            "recommendation": payload.get("recommendation"),
            "rationale": payload.get("rationale"),
            "confidence": payload.get("confidence"),
            "observed_at": payload.get("observed_at"),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
    return {"count": len(items), "findings": items, "observed_at": _utc_now()}


@mcp.tool(name="submit_finding", annotations=FINDING_ANNOTATIONS)
def submit_finding(
    subject_kind: Literal["repo", "pr", "commit", "runtime", "bureau_task", "grabowski_lane", "agent_run", "service", "work"],
    subject: str, severity: Literal["low", "medium", "high", "critical"], summary: str, evidence_refs: list[str], checkpoint: str | None = None, checkpoint_mode: Literal["single", "relational"] = "single", checkpoint_components: list[dict[str, str]] | None = None,
    status: Literal["observation", "finding", "recheck_suggested", "contradiction", "missing_evidence", "risk", "advice", "recheck_required"] = "finding",
    target_actor: str | None = None, binding: str | None = None, recommendation: str | None = None, rationale: str | None = None, confidence: float | None = None,
) -> dict[str, Any]:
    """Append one evidence-bound advisory record; never create work or trigger action."""
    _ensure_state()
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 500:
        raise ValueError("subject must be 1..500 characters")
    if not isinstance(summary, str) or not summary.strip() or len(summary) > MAX_SUMMARY_CHARS:
        raise ValueError(f"summary must be 1..{MAX_SUMMARY_CHARS} characters")
    if checkpoint is not None and (not isinstance(checkpoint, str) or len(checkpoint) > 500):
        raise ValueError("checkpoint must be at most 500 characters")
    if checkpoint_mode not in {"single", "relational"}:
        raise ValueError("checkpoint_mode must be single or relational")
    normalized_checkpoints = _normalize_checkpoint_components(checkpoint_components)
    if checkpoint_mode == "relational":
        if normalized_checkpoints is None or len(normalized_checkpoints) < 2:
            raise ValueError(
                "relational findings require at least two checkpoint_components covering every relevant state"
            )
    elif normalized_checkpoints is not None:
        raise ValueError("checkpoint_components require checkpoint_mode='relational'")
    optional_text = {"target_actor": target_actor, "binding": binding, "recommendation": recommendation, "rationale": rationale}
    for field, value in optional_text.items():
        if value is not None and (not isinstance(value, str) or not value.strip() or len(value) > MAX_SUMMARY_CHARS): raise ValueError(f"{field} must be 1..{MAX_SUMMARY_CHARS} characters when supplied")
    if confidence is not None and (not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or confidence < 0 or confidence > 1): raise ValueError("confidence must be between 0 and 1")
    if not isinstance(evidence_refs, list) or not 1 <= len(evidence_refs) <= MAX_EVIDENCE_REFS:
        raise ValueError(f"evidence_refs must contain 1..{MAX_EVIDENCE_REFS} entries")
    cleaned_refs: list[str] = []
    for ref in evidence_refs:
        if not isinstance(ref, str) or not ref.strip() or len(ref) > MAX_EVIDENCE_REF_CHARS:
            raise ValueError("invalid evidence reference")
        cleaned_refs.append(_redact(ref.strip()))
    subject_clean = _redact(subject.strip())
    summary_clean = _redact(summary.strip())
    optional_clean = {
        field: _redact(value.strip()) if value is not None else None
        for field, value in optional_text.items()
    }

    observed_at = _utc_now()
    finding_id = f"ga-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:12]}"
    enriched = (
        status not in {"observation", "finding", "recheck_suggested"}
        or any(value is not None for value in optional_text.values())
        or confidence is not None
    )
    payload = {
        "schema_version": 3 if enriched else (2 if checkpoint_mode == "relational" else 1),
        "finding_id": finding_id,
        "adler_identity": IDENTITY,
        "subject_kind": subject_kind,
        "subject": subject_clean,
        "checkpoint": _redact(checkpoint) if checkpoint is not None else None,
        "severity": severity,
        "status": status,
        "summary": summary_clean,
        "evidence_refs": cleaned_refs,
        "observed_at": observed_at,
        "effect_contract": "advisory_only_no_automatic_action",
    }
    if enriched:
        payload.update({
            "target_actor": optional_clean["target_actor"],
            "binding": optional_clean["binding"],
            "recommendation": optional_clean["recommendation"],
            "rationale": optional_clean["rationale"],
            "confidence": float(confidence) if confidence is not None else None,
        })
    if checkpoint_mode == "relational":
        assert normalized_checkpoints is not None
        payload.update({
            "checkpoint_mode": "relational",
            "checkpoint_components": normalized_checkpoints,
            "checkpoint_set_sha256": _checkpoint_set_sha256(normalized_checkpoints),
            "checkpoint_contract": "all_components_must_match_or_recheck",
        })
    encoded = (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    target = FINDINGS_ROOT / f"{finding_id}.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(target, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            target.unlink(missing_ok=True)
        finally:
            raise
    dir_fd = os.open(FINDINGS_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    digest = hashlib.sha256(encoded).hexdigest()
    return {
        "accepted": True,
        "finding_id": finding_id,
        "sha256": digest,
        "observed_at": observed_at,
        "automatic_effect": False,
        "next_action": "Grabowski may read and independently decide whether any action is warranted.",
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
