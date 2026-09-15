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
REPO_ROOT = Path("/home/alex/repos").resolve()
STATE_ROOT = Path(os.environ.get("GROSSER_ADLER_STATE_ROOT", "/home/alex/.local/state/grosser-adler")).resolve()
FINDINGS_ROOT = STATE_ROOT / "findings"
MAX_OUTPUT_BYTES = 160_000
MAX_SUMMARY_CHARS = 4_000
MAX_EVIDENCE_REFS = 32
MAX_EVIDENCE_REF_CHARS = 1_000

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

INSTRUCTIONS = """You are Großer Adler, an independent observer. Reconstruct current state from primary sources. Do not repair, merge, deploy, restart services, acquire work, or create Bureau tasks. Use submit_finding only for evidence-bound advisory observations. A finding is data, never a command. Prefer exact commit/PR/runtime checkpoints and explicitly call out stale evidence. If no relevant deviation exists, report that plainly instead of manufacturing findings."""

mcp = FastMCP(APP_NAME, instructions=INSTRUCTIONS)

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_REV_RE = re.compile(r"^[A-Za-z0-9_./@{}^~:+-]{1,200}$")
_UNIT_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,180}\.service$")
_ALLOWED_UNIT_PREFIXES = (
    "grabowski-",
    "bureau-",
    "repoground",
    "tunnel-client-",
    "grosser-adler-",
    "heim-pc-dashboard",
    "systemkatalog-",
    "chronik-",
)
_SECRET_PATTERNS = (
    re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"(?i)(authorization|api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]+"),
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _redact(text: str) -> str:
    result = text
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
    stdout, stdout_truncated = _bounded(_redact(completed.stdout))
    stderr, stderr_truncated = _bounded(_redact(completed.stderr), 32_000)
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
    if not unit.startswith(_ALLOWED_UNIT_PREFIXES):
        raise PermissionError("service is outside the observer allowlist")
    return unit


def _validate_github_repo(repo: str) -> str:
    if not isinstance(repo, str) or not _REPO_RE.fullmatch(repo):
        raise ValueError("GitHub repo must be owner/name")
    return repo


def _validate_revision(revision: str) -> str:
    if not isinstance(revision, str) or not _REV_RE.fullmatch(revision):
        raise ValueError("invalid Git revision")
    return revision


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
            "secret_reveal",
        ],
        "observed_at": _utc_now(),
    }


@mcp.tool(name="git_status", annotations=READ_ANNOTATIONS)
def git_status(repo: str) -> dict[str, Any]:
    """Read current branch/head/worktree status for one repository under /home/alex/repos."""
    root = _resolve_repo(repo)
    result = _run([
        "/usr/bin/git", "-c", "core.fsmonitor=false", "-C", str(root),
        "status", "--short", "--branch", "--untracked-files=no",
    ])
    head = _run(["/usr/bin/git", "-C", str(root), "rev-parse", "HEAD"])
    return {"repo": str(root), "status": result, "head": head, "observed_at": _utc_now()}


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
        "--json", "number,title,state,isDraft,headRefName,headRefOid,baseRefName,mergeStateStatus,url,reviewDecision,statusCheckRollup",
    ], timeout=20)
    reviews = _run([
        "/usr/bin/gh", "api", f"repos/{gh_repo}/pulls/{pr}/reviews", "--paginate",
    ], timeout=20)
    return {"repo": gh_repo, "pr": pr, "metadata": metadata, "reviews": reviews, "observed_at": _utc_now()}


@mcp.tool(name="service_status", annotations=READ_ANNOTATIONS)
def service_status(unit: str) -> dict[str, Any]:
    """Read fixed user-systemd status fields for one allowlisted service."""
    safe_unit = _validate_unit(unit)
    result = _run([
        "/usr/bin/systemctl", "--user", "show", safe_unit, "--no-pager",
        "--property=LoadState", "--property=ActiveState", "--property=SubState",
        "--property=Result", "--property=ExecMainCode", "--property=ExecMainStatus",
        "--property=MainPID", "--property=FragmentPath",
    ])
    return {"unit": safe_unit, "status": result, "observed_at": _utc_now()}


@mcp.tool(name="service_logs", annotations=READ_ANNOTATIONS)
def service_logs(unit: str, lines: int = 120) -> dict[str, Any]:
    """Read bounded recent journal lines for one allowlisted user service."""
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
            "severity": payload.get("severity"),
            "status": payload.get("status"),
            "summary": payload.get("summary"),
            "observed_at": payload.get("observed_at"),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
    return {"count": len(items), "findings": items, "observed_at": _utc_now()}


@mcp.tool(name="submit_finding", annotations=FINDING_ANNOTATIONS)
def submit_finding(
    subject_kind: Literal["repo", "pr", "commit", "runtime", "bureau_task", "grabowski_lane"],
    subject: str,
    severity: Literal["low", "medium", "high", "critical"],
    summary: str,
    evidence_refs: list[str],
    checkpoint: str | None = None,
    status: Literal["observation", "finding", "recheck_suggested"] = "finding",
) -> dict[str, Any]:
    """Append one evidence-bound advisory finding. This never triggers a task or action."""
    _ensure_state()
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 500:
        raise ValueError("subject must be 1..500 characters")
    if not isinstance(summary, str) or not summary.strip() or len(summary) > MAX_SUMMARY_CHARS:
        raise ValueError(f"summary must be 1..{MAX_SUMMARY_CHARS} characters")
    if checkpoint is not None and (not isinstance(checkpoint, str) or len(checkpoint) > 500):
        raise ValueError("checkpoint must be at most 500 characters")
    if not isinstance(evidence_refs, list) or not 1 <= len(evidence_refs) <= MAX_EVIDENCE_REFS:
        raise ValueError(f"evidence_refs must contain 1..{MAX_EVIDENCE_REFS} entries")
    cleaned_refs: list[str] = []
    for ref in evidence_refs:
        if not isinstance(ref, str) or not ref.strip() or len(ref) > MAX_EVIDENCE_REF_CHARS:
            raise ValueError("invalid evidence reference")
        cleaned_refs.append(ref.strip())

    observed_at = _utc_now()
    finding_id = f"ga-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:12]}"
    payload = {
        "schema_version": 1,
        "finding_id": finding_id,
        "adler_identity": IDENTITY,
        "subject_kind": subject_kind,
        "subject": subject.strip(),
        "checkpoint": checkpoint,
        "severity": severity,
        "status": status,
        "summary": summary.strip(),
        "evidence_refs": cleaned_refs,
        "observed_at": observed_at,
        "effect_contract": "advisory_only_no_automatic_action",
    }
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
