#!/usr/bin/env python3
from __future__ import annotations

import argparse
import bisect
import ctypes
import errno
import fcntl
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import threading
import uuid
from collections.abc import Callable
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
LAB_ROOT = Path("/home/alex/labs")
STATE_ROOT = Path(os.environ.get("GROSSER_ADLER_STATE_ROOT", "/home/alex/.local/state/grosser-adler")).resolve()
FINDINGS_ROOT = STATE_ROOT / "findings"
INBOX_ROOT = STATE_ROOT / "worktree-inboxes"
GRABOWSKI_WORK_LANES_ROOT = Path(os.environ.get("GROSSER_ADLER_WORK_LANES_ROOT", "/home/alex/.local/state/grabowski/work-lanes")).resolve()
WORKTREE_ROOT = Path(os.environ.get("GROSSER_ADLER_WORKTREE_ROOT", "/home/alex/repos/.grabowski-worktrees")).resolve()
MAX_LAB_TEXT_BYTES = 1_000_000
MAX_LAB_DIRECTORY_SCAN = 5_000
MAX_LAB_LIST_ENTRIES = 500
MAX_LAB_READ_LINES = 2_000
MAX_OUTPUT_BYTES = 160_000
MAX_JSON_SOURCE_BYTES = 1_000_000
MAX_SUMMARY_CHARS = 4_000
MAX_EVIDENCE_REFS = 32
MAX_EVIDENCE_REF_CHARS = 1_000
MAX_AFFECTED_EFFECTS = 16
MAX_AFFECTED_EFFECT_CHARS = 120
MAX_QUARANTINE_RECORDS = 20
MAX_FINDING_RETRIEVAL_SOURCE_RECORDS = 2048
LEGACY_CONNECTOR_CONTRACT = "adler-legacy-connector-submit-v1"

_FINDING_INDEX_LOCK = threading.RLock()
_FINDING_INDEX: dict[str, Any] | None = None

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

INSTRUCTIONS = """You are Großer Adler, an independent observer, auditor and advisor. Operator statements are claims, not primary evidence: reconstruct relevant state from the responsible primary sources whenever possible. Look for contradictions and missing evidence without optimizing to produce a contradiction. Independent observation is not independent decision review; a same-turn Adler observation is not cognitive independence. You do not own work state, decisions, execution, admission or lifecycle. Your only writes are immutable advisory findings and computed inbox files inside your own state root. Grabowski owns the worktree-local .adler/inbox.json symlink that points at the exact external inbox file. Findings are facts or advice, never commands. Never create work, acquire leases, edit worktree or product files, commit, push, merge, deploy, control services, signal processes or mutate credentials. Partial evidence is incomplete, never absence. Prefer exact checkpoints and explicit uncertainty; do not manufacture findings."""

mcp = FastMCP(APP_NAME, instructions=INSTRUCTIONS)

_GITHUB_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_GITHUB_REPO_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_REV_RE = re.compile(r"^[A-Za-z0-9_./@{}^~:+-]{1,200}$")
_UNIT_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,180}\.service$")
_RELEASE_ID_RE = re.compile(
    r"^(?P<head>[0-9a-f]{12})-srcset[0-9a-f]{12}-lock[0-9a-f]{12}-contract[0-9a-f]{12}"
    r"(?:-attempt[1-9][0-9]{0,2})?$"
)
_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_PYTHON_MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_GRABOWSKI_RUNTIME_UNIT_RE = re.compile(
    r"^(?:grabowski-operator|grabowski-green-operator-[0-9a-f]{12})\.service$"
)
PROC_ROOT = Path("/proc")
GRABOWSKI_RELEASE_ROOT = Path("/home/alex/.local/share/grabowski-mcp-releases")
GRABOWSKI_STABLE_RUNTIME_ROOT = Path("/home/alex/.local/share/grabowski-mcp")
MAX_PROC_RUNTIME_BYTES = 2_000_000
MAX_RUNTIME_MANIFEST_BYTES = 1_000_000
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
_SEVERITIES = ("critical", "high", "medium", "low")
_SEVERITY_ORDER = {value: index for index, value in enumerate(_SEVERITIES)}
_UNKNOWN_SEVERITY_RANK = len(_SEVERITIES)
_LEGACY_ENRICHED_FIELDS = ("target_actor", "binding", "recommendation", "rationale", "confidence")
_LEGACY_RELATIONAL_FIELDS = (
    "checkpoint_mode", "checkpoint_components", "checkpoint_set_sha256", "checkpoint_contract",
)
_V1_ONLY_MARKERS = {
    "finding_contract", "finding_sha256", "kind", "binding_strength",
    "recheck_of", "conclusion", "affected_effects", "target_lane_id",
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
_SYSTEMD_STATE_RE = re.compile(r"^[a-z][a-z-]{0,31}$")
_SECRET_PATTERNS = (
    re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"(?i)(authorization|api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]+"),
)
_LOGICAL_LINE_SEPARATOR_RE = re.compile(
    r"\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]"
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _configured_exact_secrets() -> tuple[str, ...]:
    """Return configured observer secrets that must never appear in output."""
    github_token = os.environ.get("GROSSER_ADLER_GITHUB_TOKEN")
    if github_token is None or not github_token.strip():
        return ()
    return (github_token,)


def _redaction_marker(text: str) -> str:
    """Return one marker while preserving every logical line separator."""
    separators = "".join(
        separator.group(0)
        for separator in _LOGICAL_LINE_SEPARATOR_RE.finditer(text)
    )
    return "<REDACTED>" + separators


def _line_preserving_redaction_marker(text: str) -> str:
    """Redact every logical line while preserving its exact line separator."""
    lines = text.splitlines(keepends=True)
    if not lines:
        return "<REDACTED>"

    redacted: list[str] = []
    for line in lines:
        separator_match = _LOGICAL_LINE_SEPARATOR_RE.search(line)
        separator = (
            separator_match.group(0)
            if separator_match is not None and separator_match.end() == len(line)
            else ""
        )
        redacted.append("<REDACTED>" + separator)
    return "".join(redacted)


def _redaction_for(match: re.Match[str]) -> str:
    """Replace a secret while preserving separator positions for general output.

    General structured subprocess output keeps one marker at the match origin and
    re-emits the separators as blank continuation rows. This preserves physical
    row boundaries without inventing parseable pseudo-records.
    """
    return _redaction_marker(match.group(0))


def _line_preserving_redaction_for(match: re.Match[str]) -> str:
    """Replace a secret while keeping every logical line addressable."""
    return _line_preserving_redaction_marker(match.group(0))


def _redact(text: str, *, exact_secrets: tuple[str, ...] = ()) -> str:
    result = text
    for secret in exact_secrets:
        if secret:
            result = result.replace(secret, _redaction_marker(secret))
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(_redaction_for, result)
    return result


def _redact_preserving_logical_lines(
    text: str, *, exact_secrets: tuple[str, ...] = ()
) -> str:
    """Redact text without changing its splitlines-addressable line structure."""
    result = text
    for secret in exact_secrets:
        if secret:
            result = result.replace(secret, _line_preserving_redaction_marker(secret))
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(_line_preserving_redaction_for, result)
    return result


def _secret_spans(
    text: str, exact_secrets: tuple[str, ...]
) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    pattern_spans = [
        match.span()
        for pattern in _SECRET_PATTERNS
        for match in pattern.finditer(text)
    ]
    exact_spans: list[tuple[int, int]] = []
    for secret in exact_secrets:
        if not secret:
            continue
        start = text.find(secret)
        while start != -1:
            exact_spans.append((start, start + len(secret)))
            start = text.find(secret, start + 1)
    return pattern_spans, exact_spans


def _literal_spans(text: str, literals: tuple[str, ...]) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for literal in literals:
        if not literal:
            continue
        start = text.find(literal)
        while start != -1:
            spans.append((start, start + len(literal)))
            start = text.find(literal, start + 1)
    spans.sort()
    merged: list[tuple[int, int]] = []
    for span in spans:
        if merged and span[0] < merged[-1][1]:
            continue
        merged.append(span)
    return merged


class _SpanIndex:
    """Sorted span lookup, so identity checks stay linear on large outputs.

    A flat scan per candidate is quadratic: `ps` over a busy host produces one
    secret-pattern false positive per row *and* one identity occurrence per row.
    Spans are sorted by start and queried through a window bounded by the
    longest span, so only spans that can actually overlap are examined.
    """

    __slots__ = ("_spans", "_starts", "_longest")

    def __init__(self, spans: list[tuple[int, int]]) -> None:
        self._spans = sorted(spans)
        self._starts = [span[0] for span in self._spans]
        self._longest = max((end - begin for begin, end in self._spans), default=0)

    def overlaps(self, start: int, stop: int, *, must_exceed: bool = False) -> bool:
        if not self._spans:
            return False
        first = bisect.bisect_left(self._starts, start - self._longest)
        last = bisect.bisect_left(self._starts, stop)
        for index in range(first, last):
            begin, end = self._spans[index]
            if begin < stop and end > start:
                if not must_exceed or begin < start or end > stop:
                    return True
        return False


def _redact_preserving_identity(
    text: str,
    *,
    exact_secrets: tuple[str, ...] = (),
    preserved_identity: tuple[str, ...] = (),
) -> str:
    """Redact free text while keeping named, already-validated identity intact.

    Secret patterns match inside legitimate unit names (`sk-` matches inside
    `grabowski-task-...`), and rewriting a unit name destroys the identity the
    observer exists to report: it would no longer match `_UNIT_RE`, no longer
    agree between a structured claim and its raw receipt, and no longer
    cross-check against `FragmentPath`, `ControlGroup` or the cgroup column of
    the process and socket views.

    The exemption is bound to named identity, never to shape found anywhere in
    the text: callers pass exact strings and only literal occurrences of those
    are preserved. A credential in arbitrary journal output therefore stays
    redacted even when it is followed by `.service`.

    Two binding modes exist. Most callers pass identity they validated before
    the read - the unit under observation, or the exact control-group path they
    are about to compare against. `list_user_services` cannot know the names in
    advance and derives them from the identity column of the listing, which is
    positional: only the first field of a row can be a unit name, so a
    credential anywhere else on the line never becomes preserved identity.
    Residual risk of that second mode, accepted deliberately: a unit whose own
    name is credential-shaped is reported verbatim in that column. Creating
    such a unit already requires code execution as this user, and a configured
    exact secret still overrides the exemption.

    An occurrence is still dropped from the exemption when a configured exact
    secret overlaps it, or when a secret pattern match reaches beyond it, since
    such a match is a real secret rather than the in-name false positive.
    """
    if not preserved_identity:
        return _redact(text, exact_secrets=exact_secrets)
    pattern_spans, exact_spans = _secret_spans(text, exact_secrets)
    exact_index = _SpanIndex(exact_spans)
    pattern_index = _SpanIndex(pattern_spans)
    parts: list[str] = []
    last = 0
    for start, stop in _literal_spans(text, preserved_identity):
        if exact_index.overlaps(start, stop):
            continue
        if pattern_index.overlaps(start, stop, must_exceed=True):
            continue
        parts.append(_redact(text[last:start], exact_secrets=exact_secrets))
        parts.append(text[start:stop])
        last = stop
    parts.append(_redact(text[last:], exact_secrets=exact_secrets))
    return "".join(parts)


def _listed_unit_names(text: str) -> tuple[str, ...]:
    """Collect unit names from the identity column of `systemctl list-units`.

    Only the first column of a row can be a unit name, so a credential
    elsewhere on the line is never turned into preserved identity.
    """
    names: list[str] = []
    for raw in text.splitlines():
        row = raw.strip()
        if not row:
            continue
        if row.startswith("\u25cf"):
            row = row[1:].lstrip()
        candidate = row.split(None, 1)[0] if row.split(None, 1) else ""
        if _UNIT_RE.fullmatch(candidate) is not None:
            names.append(candidate)
    return tuple(dict.fromkeys(names))


def _bounded(text: str, max_bytes: int = MAX_OUTPUT_BYTES) -> tuple[str, bool]:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text, False
    clipped = encoded[:max_bytes].decode("utf-8", errors="replace")
    return clipped + "\n<OUTPUT_TRUNCATED>", True


def _run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 15,
    preserved_identity: tuple[str, ...] = (),
    identity_extractor: Callable[[str], tuple[str, ...]] | None = None,
) -> dict[str, Any]:
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
    exact_secrets = _configured_exact_secrets()
    if argv[0] == "/usr/bin/gh":
        if not exact_secrets:
            raise RuntimeError("Großer Adler GitHub credential is not configured")
        env["GH_TOKEN"] = exact_secrets[0]

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
    # systemd and journal reads name the exact units whose identity must
    # survive; everything else in those streams stays under normal redaction.
    stdout_identity = preserved_identity
    derived_stdout_identity: tuple[str, ...] = ()
    structured_rows_intact = True
    if identity_extractor is not None:
        # Derived names are scoped to the stream they were read from; stderr
        # was never inspected by the extractor, so it keeps caller-supplied
        # identity only. Nothing derived is returned to the caller.
        try:
            derived_stdout_identity = tuple(identity_extractor(completed.stdout))
            stdout_identity = preserved_identity + derived_stdout_identity
        except Exception:
            stdout_identity = preserved_identity
            structured_rows_intact = False

    def redact(value: str, identity: tuple[str, ...]) -> str:
        return _redact_preserving_identity(
            value,
            exact_secrets=exact_secrets,
            preserved_identity=identity,
        )

    redacted_stdout = redact(completed.stdout, stdout_identity)
    if identity_extractor is not None and structured_rows_intact:
        # Equal newline counts are not a structural completeness proof: one
        # multi-line secret can consume whole rows and re-emit their newlines
        # as blanks. For structured streams, require the exact identity
        # sequence seen before redaction to remain observable afterwards.
        try:
            structured_rows_intact = (
                tuple(identity_extractor(redacted_stdout)) == derived_stdout_identity
            )
        except Exception:
            structured_rows_intact = False
    physical_rows_intact = (
        len(redacted_stdout.splitlines()) == len(completed.stdout.splitlines())
    )
    stdout, stdout_truncated = _bounded(redacted_stdout)
    stderr, stderr_truncated = _bounded(
        redact(completed.stderr, preserved_identity), 32_000
    )
    return {
        "returncode": completed.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        # The structured proof is internal only; raw identities are never
        # returned as an unbounded side channel.
        "stdout_line_count": len(completed.stdout.splitlines()),
        "rows_intact": physical_rows_intact and structured_rows_intact,
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


def _lab_path_parts(path: str) -> tuple[str, ...]:
    if not isinstance(path, str) or not path.strip() or "\x00" in path:
        raise ValueError("path must be non-empty text without NUL")
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("path must be valid UTF-8 text") from None
    raw = Path(path).expanduser()
    if raw.is_absolute():
        try:
            relative = raw.relative_to(LAB_ROOT)
        except ValueError as exc:
            raise PermissionError(f"path is outside {LAB_ROOT}") from exc
    else:
        relative = raw
    parts = tuple(part for part in relative.parts if part not in {"", "."})
    if any(part == ".." for part in parts):
        raise PermissionError(f"path is outside {LAB_ROOT}")
    return parts


def _lab_root_available() -> bool:
    try:
        metadata = LAB_ROOT.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(metadata.st_mode)


def _lab_open_flags(*, directory: bool, nonblocking: bool = False) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if directory:
        flags |= os.O_DIRECTORY
    if nonblocking and hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _lab_open_component(
    name: str, *, dir_fd: int, directory: bool, nonblocking: bool = False
) -> int:
    try:
        return os.open(
            name,
            _lab_open_flags(directory=directory, nonblocking=nonblocking),
            dir_fd=dir_fd,
        )
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise PermissionError("lab path contains a symlink or non-directory component") from exc
        if exc.errno is None:
            raise OSError("lab path component open failed") from None
        raise OSError(exc.errno, os.strerror(exc.errno)) from None


def _open_lab_directory(path: str) -> tuple[int, Path]:
    parts = _lab_path_parts(path)
    try:
        fd = os.open(LAB_ROOT, _lab_open_flags(directory=True))
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise PermissionError("lab root must be a real directory") from exc
        raise
    try:
        for part in parts:
            next_fd = _lab_open_component(part, dir_fd=fd, directory=True)
            os.close(fd)
            fd = next_fd
        return fd, LAB_ROOT.joinpath(*parts)
    except Exception:
        os.close(fd)
        raise


def _read_lab_bytes(path: str) -> tuple[Path, bytes]:
    parts = _lab_path_parts(path)
    if not parts:
        raise ValueError("lab text path must name a file")
    try:
        parent_fd = os.open(LAB_ROOT, _lab_open_flags(directory=True))
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise PermissionError("lab root must be a real directory") from exc
        raise
    fd: int | None = None
    try:
        for part in parts[:-1]:
            next_fd = _lab_open_component(part, dir_fd=parent_fd, directory=True)
            os.close(parent_fd)
            parent_fd = next_fd
        fd = _lab_open_component(
            parts[-1],
            dir_fd=parent_fd,
            directory=False,
            nonblocking=True,
        )
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("lab text path must be a regular file")
        if metadata.st_size > MAX_LAB_TEXT_BYTES:
            raise ValueError("lab text file exceeds the observation byte limit")
        chunks: list[bytes] = []
        remaining = MAX_LAB_TEXT_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > MAX_LAB_TEXT_BYTES:
            raise ValueError("lab text file exceeds the observation byte limit")
        return LAB_ROOT.joinpath(*parts), payload
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent_fd)


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


def _runtime_identity_unknown(
    missing_evidence: list[str],
    *,
    executable_path_or_identity: str | None = None,
    identity_source: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "executable_path_or_identity": executable_path_or_identity,
        "release_id": None,
        "source_commit_or_repo_head": None,
        "identity_source": list(dict.fromkeys(identity_source)),
        "identity_complete": False,
        "missing_evidence": sorted(set(missing_evidence)),
    }


def _safe_identity_text(value: str) -> str | None:
    if not isinstance(value, str) or not value or "\x00" in value:
        return None
    return value if _redact(value) == value else None


def _read_proc_text(
    pid: int,
    name: str,
    *,
    max_bytes: int,
    proc_root: Path | None = None,
) -> str | None:
    root = PROC_ROOT if proc_root is None else proc_root
    path = root / str(pid) / name
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd: int | None = None
    try:
        fd = os.open(path, flags)
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > max_bytes:
            return None
        return payload.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    finally:
        if fd is not None:
            os.close(fd)


def _proc_cgroup(pid: int, *, proc_root: Path | None = None) -> str | None:
    raw = _read_proc_text(pid, "cgroup", max_bytes=64_000, proc_root=proc_root)
    if raw is None:
        return None
    groups: set[str] = set()
    for line in raw.splitlines():
        if not line:
            continue
        parts = line.split(":", 2)
        if len(parts) != 3 or not parts[2]:
            return None
        groups.add(_normalize_cgroup(parts[2]))
    return next(iter(groups)) if len(groups) == 1 else None


def _proc_executable(pid: int, *, proc_root: Path | None = None) -> str | None:
    root = PROC_ROOT if proc_root is None else proc_root
    try:
        value = os.readlink(root / str(pid) / "exe")
    except OSError:
        return None
    if not value.startswith("/") or value.endswith(" (deleted)"):
        return None
    return _safe_identity_text(value)


def _proc_launch_argv(
    pid: int,
    *,
    proc_root: Path | None = None,
) -> tuple[str, ...] | None:
    raw = _read_proc_text(pid, "cmdline", max_bytes=64_000, proc_root=proc_root)
    if raw is None or not raw.endswith("\x00"):
        return None
    parts = raw[:-1].split("\x00")
    if len(parts) < 3 or any(_safe_identity_text(part) is None for part in parts):
        return None
    return tuple(parts)


def _mapped_release_root(
    maps_text: str,
    *,
    release_root: Path | None = None,
) -> tuple[Path | None, str | None]:
    root = GRABOWSKI_RELEASE_ROOT if release_root is None else release_root
    prefix = str(root) + "/"
    candidate_roots: set[Path] = set()
    candidate_mappings: list[tuple[str, str, str, Path, Path, bool]] = []
    invalid_under_root = False

    for raw in maps_text.splitlines():
        parts = raw.split(None, 5)
        if len(parts) != 6:
            continue
        permissions, device, inode_text, pathname = parts[1], parts[3], parts[4], parts[5]
        if not pathname.startswith(prefix):
            continue
        deleted = pathname.endswith(" (deleted)")
        candidate_pathname = pathname[:-10] if deleted else pathname
        if not candidate_pathname.startswith(prefix):
            invalid_under_root = True
            continue
        relative = candidate_pathname[len(prefix):]
        release_name = relative.split("/", 1)[0]
        if _RELEASE_ID_RE.fullmatch(release_name) is None:
            invalid_under_root = True
            continue
        release = root / release_name
        path = Path(candidate_pathname)
        if ".." in path.parts or not path.is_relative_to(release):
            invalid_under_root = True
            continue
        candidate_roots.add(release)
        candidate_mappings.append(
            (permissions, device, inode_text, path, release, deleted)
        )

    if invalid_under_root or len(candidate_roots) != 1:
        if not candidate_roots and not invalid_under_root:
            return None, "immutable_release_mapping"
        return None, "immutable_release_mapping_invalid_or_ambiguous"

    release = next(iter(candidate_roots))
    executable_mappings = [
        item for item in candidate_mappings if "x" in item[0]
    ]
    if not executable_mappings:
        return None, "immutable_release_mapping_invalid_or_ambiguous"

    for _permissions, device, inode_text, path, mapped_release, deleted in executable_mappings:
        if mapped_release != release or deleted:
            return None, "immutable_release_mapping_invalid_or_ambiguous"
        try:
            linked = path.lstat()
            current = path.stat()
            major_text, minor_text = device.split(":", 1)
            mapped_inode = int(inode_text)
            mapped_major = int(major_text, 16)
            mapped_minor = int(minor_text, 16)
        except (OSError, ValueError):
            return None, "immutable_release_mapping_invalid_or_ambiguous"
        if (
            not stat.S_ISREG(linked.st_mode)
            or linked.st_uid != os.getuid()
            or linked.st_mode & 0o022
            or current.st_ino != mapped_inode
            or os.major(current.st_dev) != mapped_major
            or os.minor(current.st_dev) != mapped_minor
        ):
            return None, "immutable_release_mapping_invalid_or_ambiguous"

    return release, None


def _runtime_maps_observation(
    maps_text: str,
    *,
    release_root: Path | None = None,
) -> tuple[str, ...]:
    root = GRABOWSKI_RELEASE_ROOT if release_root is None else release_root
    release_prefix = str(root) + "/"
    relevant: list[str] = []
    for raw in maps_text.splitlines():
        parts = raw.split(None, 5)
        if len(parts) < 5:
            continue
        permissions = parts[1]
        pathname = parts[5] if len(parts) == 6 else ""
        if "x" in permissions or pathname.startswith(release_prefix):
            relevant.append(" ".join(parts))
    return tuple(relevant)


def _read_bound_runtime_manifest(path: Path) -> dict[str, Any] | None:
    fd: int | None = None
    try:
        linked = path.lstat()
        if (
            not stat.S_ISREG(linked.st_mode)
            or linked.st_uid != os.getuid()
            or linked.st_nlink != 1
            or linked.st_mode & 0o022
            or linked.st_size > MAX_RUNTIME_MANIFEST_BYTES
        ):
            return None
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != linked.st_dev
            or opened.st_ino != linked.st_ino
            or opened.st_nlink != 1
            or opened.st_size > MAX_RUNTIME_MANIFEST_BYTES
        ):
            return None
        chunks: list[bytes] = []
        remaining = MAX_RUNTIME_MANIFEST_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > MAX_RUNTIME_MANIFEST_BYTES:
            return None
        value = json.loads(payload.decode("utf-8"))
        return value if isinstance(value, dict) else None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    finally:
        if fd is not None:
            os.close(fd)


def _release_manifest_identity(
    release: Path,
    observed_executable: str,
) -> tuple[
    str | None,
    str | None,
    tuple[str, str] | None,
    str | None,
]:
    try:
        release_meta = release.lstat()
    except OSError:
        return None, None, None, "immutable_release_path"
    if (
        not stat.S_ISDIR(release_meta.st_mode)
        or release_meta.st_uid != os.getuid()
        or release_meta.st_mode & 0o022
        or _RELEASE_ID_RE.fullmatch(release.name) is None
    ):
        return None, None, None, "immutable_release_path"

    manifest = _read_bound_runtime_manifest(release / "deployment-manifest.json")
    if manifest is None:
        return None, None, None, "release_manifest"
    release_id = manifest.get("release_id")
    repo_head = manifest.get("repo_head")
    immutable_path = manifest.get("immutable_release_path")
    release_python_raw = manifest.get("executable")
    entrypoint_raw = manifest.get("entrypoint_path")
    entrypoint_contract = manifest.get("entrypoint_contract")
    module_paths = manifest.get("module_paths")
    match = _RELEASE_ID_RE.fullmatch(release_id) if isinstance(release_id, str) else None
    if (
        match is None
        or release_id != release.name
        or not isinstance(repo_head, str)
        or _COMMIT_SHA_RE.fullmatch(repo_head) is None
        or match.group("head") != repo_head[:12]
        or immutable_path != str(release)
        or manifest.get("completion_status") != "complete"
        or not isinstance(release_python_raw, str)
        or not isinstance(entrypoint_raw, str)
        or not isinstance(entrypoint_contract, dict)
        or not isinstance(module_paths, dict)
    ):
        return None, None, None, "release_manifest_identity"

    release_python = Path(release_python_raw)
    entrypoint = Path(entrypoint_raw)
    if (
        not release_python.is_absolute()
        or not entrypoint.is_absolute()
        or ".." in release_python.parts
        or ".." in entrypoint.parts
        or not release_python.is_relative_to(release)
        or not entrypoint.is_relative_to(release)
    ):
        return None, None, None, "release_manifest_paths"
    try:
        python_real = release_python.resolve(strict=True)
        entrypoint_meta = entrypoint.lstat()
    except OSError:
        return None, None, None, "release_manifest_paths"
    if (
        str(python_real) != observed_executable
        or not stat.S_ISREG(entrypoint_meta.st_mode)
        or entrypoint_meta.st_uid != os.getuid()
        or entrypoint_meta.st_mode & 0o022
    ):
        return None, None, None, "release_manifest_paths"

    launch_mode = entrypoint_contract.get("mode")
    launch_module = entrypoint_contract.get("module")
    if (
        launch_mode != "module"
        or not isinstance(launch_module, str)
        or _PYTHON_MODULE_RE.fullmatch(launch_module) is None
        or module_paths.get(launch_module) != str(entrypoint)
    ):
        return None, None, None, "release_manifest_entrypoint_contract"
    return release_id, repo_head, ("module", launch_module), None


def _launch_argv_matches(
    argv: tuple[str, ...],
    launch_identity: tuple[str, str],
    *,
    unit: str,
    release: Path,
) -> bool:
    mode, value = launch_identity
    if mode != "module":
        return False
    if unit == "grabowski-operator.service":
        expected_launcher = GRABOWSKI_STABLE_RUNTIME_ROOT / ".venv/bin/python"
        expected_port = "18181"
    else:
        expected_launcher = release / ".venv/bin/python"
        expected_port = "18182"
    return argv == (
        str(expected_launcher),
        "-m",
        value,
        "--transport",
        "streamable-http",
        "--host",
        "127.0.0.1",
        "--port",
        expected_port,
    )

def _runtime_identity_observation(
    pid: int,
    control_group: str,
    *,
    unit: str = "grabowski-operator.service",
    proc_root: Path | None = None,
    release_root: Path | None = None,
) -> dict[str, Any]:
    sources = ["systemd_main_pid_control_group"]
    if _GRABOWSKI_RUNTIME_UNIT_RE.fullmatch(unit) is None:
        return _runtime_identity_unknown(
            ["grabowski_runtime_unit"],
            identity_source=tuple(sources),
        )
    expected_cgroup = _normalize_cgroup(control_group)
    before_cgroup = _proc_cgroup(pid, proc_root=proc_root)
    if before_cgroup != expected_cgroup:
        return _runtime_identity_unknown(
            ["proc_cgroup"],
            identity_source=tuple(sources),
        )
    sources.append("procfs_cgroup")

    executable_before = _proc_executable(pid, proc_root=proc_root)
    if executable_before is None:
        return _runtime_identity_unknown(
            ["proc_executable"],
            identity_source=tuple(sources),
        )
    sources.append("procfs_exe")

    maps_text = _read_proc_text(
        pid,
        "maps",
        max_bytes=MAX_PROC_RUNTIME_BYTES,
        proc_root=proc_root,
    )
    if maps_text is None:
        return _runtime_identity_unknown(
            ["proc_maps"],
            executable_path_or_identity=executable_before,
            identity_source=tuple(sources),
        )
    maps_observation = _runtime_maps_observation(
        maps_text,
        release_root=release_root,
    )
    release, release_reason = _mapped_release_root(
        maps_text,
        release_root=release_root,
    )
    if release is None:
        return _runtime_identity_unknown(
            [release_reason or "immutable_release_mapping"],
            executable_path_or_identity=executable_before,
            identity_source=tuple(sources + ["procfs_maps"]),
        )
    sources.append("procfs_maps_immutable_release")

    release_id, repo_head, launch_identity, manifest_reason = _release_manifest_identity(
        release,
        executable_before,
    )
    if manifest_reason is not None or launch_identity is None:
        return _runtime_identity_unknown(
            [manifest_reason or "release_manifest_entrypoint_contract"],
            executable_path_or_identity=executable_before,
            identity_source=tuple(sources),
        )
    sources.append("immutable_release_manifest")

    launch_argv_before = _proc_launch_argv(pid, proc_root=proc_root)
    if launch_argv_before is None:
        return _runtime_identity_unknown(
            ["proc_cmdline"],
            executable_path_or_identity=executable_before,
            identity_source=tuple(sources),
        )
    if not _launch_argv_matches(
        launch_argv_before,
        launch_identity,
        unit=unit,
        release=release,
    ):
        return _runtime_identity_unknown(
            ["process_entrypoint_binding"],
            executable_path_or_identity=executable_before,
            identity_source=tuple(sources + ["procfs_cmdline"]),
        )
    sources.append("procfs_cmdline_manifest_entrypoint")

    after_cgroup = _proc_cgroup(pid, proc_root=proc_root)
    executable_after = _proc_executable(pid, proc_root=proc_root)
    launch_argv_after = _proc_launch_argv(pid, proc_root=proc_root)
    maps_text_after = _read_proc_text(
        pid,
        "maps",
        max_bytes=MAX_PROC_RUNTIME_BYTES,
        proc_root=proc_root,
    )
    if (
        after_cgroup != expected_cgroup
        or executable_after != executable_before
        or launch_argv_after != launch_argv_before
        or maps_text_after is None
        or _runtime_maps_observation(
            maps_text_after,
            release_root=release_root,
        )
        != maps_observation
    ):
        return _runtime_identity_unknown(
            ["process_changed_during_identity_observation"],
            executable_path_or_identity=executable_before,
            identity_source=tuple(sources),
        )

    return {
        "executable_path_or_identity": executable_before,
        "release_id": release_id,
        "source_commit_or_repo_head": None,
        "identity_source": [
            *sources,
            "release_manifest_commit_attestation_not_primary_evidence",
        ],
        "identity_complete": False,
        "missing_evidence": ["source_commit_primary_evidence"],
    }

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


def _split_github_repo(repo: str) -> tuple[str, str]:
    """Validate owner and name as separate path segments, never as one string.

    Every accepted value must expand to exactly `repos/<owner>/<name>/...`:
    the input carries exactly one separator, neither segment may traverse
    (`.`, `..`), start an option (`-`), or contain an escape (`%`) that could
    re-cross a segment boundary after URL handling.
    """
    if not isinstance(repo, str):
        raise ValueError("GitHub repo must be owner/name")
    segments = repo.split("/")
    if len(segments) != 2:
        raise ValueError("GitHub repo must be owner/name")
    owner, name = segments
    if _GITHUB_OWNER_RE.fullmatch(owner) is None:
        raise ValueError("GitHub owner segment is invalid")
    if _GITHUB_REPO_NAME_RE.fullmatch(name) is None:
        raise ValueError("GitHub repository segment is invalid")
    if name.startswith("-") or set(name) <= {"."}:
        raise ValueError("GitHub repository segment is invalid")
    return owner, name



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
        "lab_root": str(LAB_ROOT),
        "lab_root_available": _lab_root_available(),
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


@mcp.tool(name="lab_list_directory", annotations=READ_ANNOTATIONS)
def lab_list_directory(path: str = ".", max_entries: int = 200) -> dict[str, Any]:
    """List one bounded directory under the fixed lab observation root."""
    if (
        not isinstance(max_entries, int)
        or isinstance(max_entries, bool)
        or not 1 <= max_entries <= MAX_LAB_LIST_ENTRIES
    ):
        raise ValueError(f"max_entries must be between 1 and {MAX_LAB_LIST_ENTRIES}")

    entries: list[dict[str, Any]] = []
    scan_complete = True
    exact_secrets = _configured_exact_secrets()
    dir_fd, root = _open_lab_directory(path)
    try:
        with os.scandir(dir_fd) as iterator:
            for index, entry in enumerate(iterator):
                if index >= MAX_LAB_DIRECTORY_SCAN:
                    scan_complete = False
                    break
                safe_name = _redact(entry.name, exact_secrets=exact_secrets)
                try:
                    safe_name.encode("utf-8")
                except UnicodeEncodeError:
                    scan_complete = False
                    continue
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    stale_errnos = (errno.ENOENT, getattr(errno, "ESTALE", errno.ENOENT))
                    if exc.errno not in stale_errnos:
                        raise OSError(exc.errno, "lab directory entry stat failed") from None
                    scan_complete = False
                    continue
                mode = metadata.st_mode
                if stat.S_ISDIR(mode):
                    entry_type = "directory"
                elif stat.S_ISREG(mode):
                    entry_type = "file"
                elif stat.S_ISLNK(mode):
                    entry_type = "symlink"
                else:
                    entry_type = "other"
                entries.append(
                    {
                        "name": safe_name,
                        "name_redacted": safe_name != entry.name,
                        "type": entry_type,
                        "size": metadata.st_size if entry_type == "file" else None,
                    }
                )
    finally:
        os.close(dir_fd)

    entries.sort(key=lambda item: item["name"])
    returned = entries[:max_entries]
    safe_path = _redact(str(root), exact_secrets=exact_secrets)
    return {
        "root": str(LAB_ROOT),
        "path": safe_path,
        "entries": returned,
        "returned": len(returned),
        "truncated": len(entries) > max_entries or not scan_complete,
        "scan_complete": scan_complete,
        "scan_limit": MAX_LAB_DIRECTORY_SCAN,
        "observed_at": _utc_now(),
    }


@mcp.tool(name="lab_read_text", annotations=READ_ANNOTATIONS)
def lab_read_text(
    path: str,
    start_line: int = 1,
    max_lines: int = 400,
) -> dict[str, Any]:
    """Read one bounded, secret-redacted UTF-8 text window under the lab root."""
    if (
        not isinstance(start_line, int)
        or isinstance(start_line, bool)
        or start_line < 1
    ):
        raise ValueError("start_line must be a positive integer")
    if (
        not isinstance(max_lines, int)
        or isinstance(max_lines, bool)
        or not 1 <= max_lines <= MAX_LAB_READ_LINES
    ):
        raise ValueError(f"max_lines must be between 1 and {MAX_LAB_READ_LINES}")

    root, payload = _read_lab_bytes(path)
    try:
        source_text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("lab text file must be valid UTF-8") from exc

    exact_secrets = _configured_exact_secrets()
    redacted_source = _redact_preserving_logical_lines(
        source_text,
        exact_secrets=exact_secrets,
    )
    safe_path = _redact(str(root), exact_secrets=exact_secrets)
    lines = redacted_source.splitlines(keepends=True)
    start_index = start_line - 1
    selected_lines = lines[start_index : start_index + max_lines]
    excerpt = "".join(selected_lines)
    bounded, output_truncated = _bounded(excerpt)
    end_line = start_line + len(selected_lines) - 1 if selected_lines else None
    has_more = end_line is not None and end_line < len(lines)
    return {
        "root": str(LAB_ROOT),
        "path": safe_path,
        "redacted_content_sha256": hashlib.sha256(
            redacted_source.encode("utf-8")
        ).hexdigest(),
        "start_line": start_line,
        "end_line": end_line,
        "total_lines": len(lines),
        "text": bounded,
        "redaction_applied": redacted_source != source_text,
        "output_truncated": output_truncated,
        "has_more": has_more,
        "requested_window_complete": not output_truncated,
        "source_complete": start_line == 1 and not has_more and not output_truncated,
        "observed_at": _utc_now(),
    }


def _decode_json_documents(text: str) -> list[Any]:
    """Decode one or more adjacent JSON documents without accepting trailing junk."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("empty JSON evidence")
    decoder = json.JSONDecoder()
    values: list[Any] = []
    cursor = 0
    while cursor < len(text):
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if cursor >= len(text):
            break
        value, cursor = decoder.raw_decode(text, cursor)
        values.append(value)
    if not values:
        raise ValueError("empty JSON evidence")
    return values


def _project_github_json(
    receipt: dict[str, Any], *, source: str, paginated_array: bool
) -> tuple[Any | None, dict[str, bool], list[str]]:
    """Project one bounded gh receipt only when its complete JSON shape is known."""
    missing: list[str] = []
    transport_complete = (
        receipt.get("returncode") == 0
        and not bool(receipt.get("stdout_truncated", False))
        and isinstance(receipt.get("stdout"), str)
    )
    if receipt.get("returncode") != 0:
        missing.append(f"{source}:command_failed")
    if bool(receipt.get("stdout_truncated", False)):
        missing.append(f"{source}:stdout_truncated")
    if not isinstance(receipt.get("stdout"), str):
        missing.append(f"{source}:stdout_unavailable")

    payload: Any | None = None
    parse_complete = False
    if transport_complete:
        try:
            documents = _decode_json_documents(receipt["stdout"])
            if paginated_array:
                if not all(isinstance(document, list) for document in documents):
                    raise ValueError("paginated GitHub source must contain JSON arrays")
                rows = [row for document in documents for row in document]
                if not all(isinstance(row, dict) for row in rows):
                    raise ValueError("GitHub array rows must be objects")
                payload = rows
            else:
                if len(documents) != 1 or not isinstance(documents[0], dict):
                    raise ValueError("GitHub metadata must be one JSON object")
                payload = documents[0]
            parse_complete = True
        except (json.JSONDecodeError, ValueError, TypeError):
            missing.append(f"{source}:invalid_json")

    source_complete = transport_complete and parse_complete
    return payload if source_complete else None, {
        "transport_complete": transport_complete,
        "parse_complete": parse_complete,
        "source_complete": source_complete,
    }, missing


def _structured_github_pr(
    metadata: dict[str, Any],
    reviews: dict[str, Any],
    review_comments: dict[str, Any],
    *,
    observed_at: str,
) -> dict[str, Any]:
    facts, metadata_state, missing = _project_github_json(
        metadata, source="metadata", paginated_array=False
    )
    review_rows, reviews_state, review_missing = _project_github_json(
        reviews, source="reviews", paginated_array=True
    )
    inline_comments, comments_state, comments_missing = _project_github_json(
        review_comments, source="inline_comments", paginated_array=True
    )
    missing.extend(review_missing)
    missing.extend(comments_missing)

    checks: list[Any] | None = None
    head_oid: str | None = None
    if facts is not None:
        raw_checks = facts.get("statusCheckRollup")
        if isinstance(raw_checks, list):
            checks = raw_checks
        else:
            missing.append("metadata.statusCheckRollup")
        raw_head = facts.get("headRefOid")
        if isinstance(raw_head, str) and raw_head:
            head_oid = raw_head
        else:
            missing.append("metadata.headRefOid")

    review_head_bindings: list[dict[str, Any]] | None = None
    if review_rows is not None:
        review_head_bindings = []
        for index, review in enumerate(review_rows):
            raw_commit = review.get("commit_id")
            review_commit = raw_commit if isinstance(raw_commit, str) and raw_commit else None
            if head_oid is not None and review_commit is not None:
                current_head_binding: bool | str = review_commit == head_oid
            else:
                current_head_binding = "unknown"
                if review_commit is None:
                    missing.append(f"reviews[{index}].commit_id")
            review_head_bindings.append({
                "review_id": review.get("id"),
                "review_commit_id": review_commit,
                "pr_head_oid": head_oid,
                "current_head_binding": current_head_binding,
            })

    missing_evidence = sorted(set(missing))
    sources = {
        "metadata": metadata_state,
        "reviews": reviews_state,
        "inline_comments": comments_state,
    }
    source_complete = all(state["source_complete"] for state in sources.values())
    observation_complete = source_complete and not missing_evidence
    return {
        "facts": facts,
        "checks": checks,
        "reviews": review_rows,
        "inline_comments": inline_comments,
        "review_head_bindings": review_head_bindings,
        "sources": sources,
        "source_complete": source_complete,
        "observation_complete": observation_complete,
        "missing_evidence": missing_evidence,
        "observed_at": observed_at,
        "does_not_establish": [
            "review_validity",
            "review_sufficiency",
            "approval",
            "merge_readiness",
            "merge_authorization",
        ],
    }


@mcp.tool(name="github_pr", annotations=READ_ANNOTATIONS)
def github_pr(repo: str, pr: int) -> dict[str, Any]:
    """Read raw GitHub PR evidence plus a source-local deterministic projection."""
    owner, name = _split_github_repo(repo)
    gh_repo = f"{owner}/{name}"
    if not isinstance(pr, int) or isinstance(pr, bool) or not 1 <= pr <= 2_147_483_647:
        raise ValueError("invalid pull request number")
    metadata = _run([
        "/usr/bin/gh", "pr", "view", str(pr), "--repo", gh_repo,
        "--json", "number,title,state,isDraft,headRefName,headRefOid,baseRefName,baseRefOid,mergeStateStatus,url,reviewDecision,statusCheckRollup",
    ], timeout=20)
    reviews = _run([
        "/usr/bin/gh", "api", f"repos/{owner}/{name}/pulls/{pr}/reviews", "--paginate",
    ], timeout=20)
    review_comments = _run([
        "/usr/bin/gh", "api", f"repos/{owner}/{name}/pulls/{pr}/comments", "--paginate",
    ], timeout=20)
    observed_at = _utc_now()
    return {
        "repo": gh_repo,
        "pr": pr,
        "metadata": metadata,
        "reviews": reviews,
        "review_comments": review_comments,
        "structured": _structured_github_pr(
            metadata, reviews, review_comments, observed_at=observed_at
        ),
        "observed_at": observed_at,
    }

def _parse_service_units(text: str) -> tuple[list[dict[str, str]], bool]:
    """Parse bounded, already-redacted `systemctl list-units` rows.

    `_run` performs redaction first and preserves only the identities extracted
    from the raw listing's first column. This parser never receives privileged
    raw stdout: it parses the bounded redacted receipt returned by `_run`.
    The unit identity therefore remains byte-exact only because
    `_redact_preserving_identity` left that validated first-column identity
    intact. Load, active and sub are structural systemd state tokens and are
    checked against that vocabulary; the description remains ordinary redacted
    free text.
    """
    units: list[dict[str, str]] = []
    complete = True
    for raw in text.splitlines():
        if not raw.strip():
            continue
        row = raw.strip()
        if row.startswith("\u25cf"):
            row = row[1:].lstrip()
        parts = row.split(None, 4)
        if len(parts) < 4 or not _UNIT_RE.fullmatch(parts[0]):
            complete = False
            continue
        if any(_SYSTEMD_STATE_RE.fullmatch(part) is None for part in parts[1:4]):
            complete = False
            continue
        units.append({
            "unit": parts[0],
            "load": parts[1],
            "active": parts[2],
            "sub": parts[3],
            "description": parts[4] if len(parts) > 4 else "",
        })
    return units, complete


@mcp.tool(name="list_user_services", annotations=READ_ANNOTATIONS)
def list_user_services() -> dict[str, Any]:
    """Discover user-systemd services without a name allowlist or mutation authority."""
    result = _run(
        ["/usr/bin/systemctl", "--user", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager"],
        timeout=20,
        identity_extractor=_listed_unit_names,
    )
    source_complete = result["returncode"] == 0 and not result["stdout_truncated"]
    # Redaction must never merge rows: a dropped unit would otherwise be
    # indistinguishable from a unit that does not exist.
    rows_intact = result["rows_intact"]
    units: list[dict[str, str]] = []
    parse_complete = False
    if source_complete and rows_intact:
        units, parse_complete = _parse_service_units(result["stdout"])
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
    result = _run(_service_show_argv(unit, scope), preserved_identity=(unit,))
    source_complete = (
        result["returncode"] == 0
        and not result["stdout_truncated"]
        and result["rows_intact"]
    )
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
    # The cgroup column is compared against systemd's ControlGroup, so both
    # sides must preserve that exact path or _cgroup_within never matches.
    table = _run([
        "/usr/bin/ps", "-ww", "-eo",
        "pid=,ppid=,uid=,stat=,etimes=,rss=,pcpu=,comm=,cgroup=",
    ], timeout=20, preserved_identity=(control_group,))
    source_complete = (
        table["returncode"] == 0
        and not table["stdout_truncated"]
        and table["rows_intact"]
    )
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

    runtime_identity = _runtime_identity_unknown(
        ["service_process_binding"],
        identity_source=("systemd_main_pid_control_group",) if main_pid > 0 and control_group else (),
    )
    if (
        status_complete
        and active_state == "active"
        and status.get("scope") in _SYSTEMD_SCOPES
        and main_pid > 0
        and bool(control_group)
        and process_observation.get("complete") is True
    ):
        runtime_identity = _runtime_identity_observation(
            main_pid,
            control_group,
            unit=unit,
        )

    # Same cgroup comparison, same requirement.
    sockets = _run(
        ["/usr/bin/ss", "-H", "-lntue"],
        timeout=20,
        preserved_identity=(control_group,) if control_group else (),
    )
    socket_lines = [line for line in sockets["stdout"].splitlines() if line.strip()]
    sockets_source_complete = (
        sockets["returncode"] == 0
        and not sockets["stdout_truncated"]
        and sockets["rows_intact"]
    )
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
        "runtime_identity": runtime_identity,
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
    # Do not force ``--system`` for a resolved system unit. A system service
    # running as an unprivileged user can have stdout/stderr records stored in
    # that user's journal. ``-u`` remains the system-unit selector; journalctl
    # uses the distinct ``--user-unit`` selector for user units.
    argv.extend(["-u", safe_unit, "--no-pager", "-n", str(lines), "-o", "short-iso"])
    result = _run(argv, timeout=20, preserved_identity=(safe_unit,))
    diagnostics_present = bool(result["stderr"].strip())
    rows_intact = result["rows_intact"]
    observation_complete = (
        result["returncode"] == 0
        and not result["stdout_truncated"]
        and not result["stderr_truncated"]
        and not diagnostics_present
        and rows_intact
    )
    return {
        "unit": safe_unit,
        "scope": scope,
        "scope_selection_reason": status.get("scope_selection_reason"),
        "journal_diagnostics_present": diagnostics_present,
        "rows_intact": rows_intact,
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


def _contains_unicode_surrogate(value: Any) -> bool:
    if isinstance(value, str):
        return any(0xD800 <= ord(char) <= 0xDFFF for char in value)
    if isinstance(value, list):
        return any(_contains_unicode_surrogate(item) for item in value)
    if isinstance(value, dict):
        return any(
            _contains_unicode_surrogate(key)
            or _contains_unicode_surrogate(item)
            for key, item in value.items()
        )
    return False


def _read_json_file_no_symlink_with_sha256(
    path: Path,
) -> tuple[dict[str, Any], str]:
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
    return payload, hashlib.sha256(raw).hexdigest()


def _read_json_file_no_symlink(path: Path) -> dict[str, Any]:
    payload, _record_sha256 = _read_json_file_no_symlink_with_sha256(path)
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


def _v1_target_lane_id(subject: str, target_lane_id: str | None = None) -> str | None:
    """Resolve an explicit V1 target or the exact compatibility subject only."""
    if target_lane_id is not None and (
        not isinstance(target_lane_id, str)
        or _LANE_ID_RE.fullmatch(target_lane_id) is None
    ):
        raise ValueError("target_lane_id must be exactly 32 lowercase hexadecimal characters")
    match = _LANE_SUBJECT_RE.fullmatch(subject)
    subject_lane_id = match.group(1) if match is not None else None
    if (
        target_lane_id is not None
        and subject_lane_id is not None
        and target_lane_id != subject_lane_id
    ):
        raise ValueError("target_lane_id conflicts with canonical lane subject")
    return target_lane_id if target_lane_id is not None else subject_lane_id


def _finding_record_view(
    payload: dict[str, Any],
    path: Path,
    *,
    record_sha256: str | None = None,
) -> dict[str, Any]:
    if payload.get("finding_contract") == FINDING_CONTRACT:
        fields = (
            "schema_version", "finding_id", "finding_sha256", "kind", "severity", "confidence",
            "subject", "target_lane_id", "checkpoint", "binding_strength", "summary", "evidence_refs",
            "recommendation", "affected_effects", "recheck_of", "conclusion", "observed_at",
        )
        view = {key: payload.get(key) for key in fields if key in payload}
        view["legacy"] = False
        return view

    legacy_status = payload["status"]
    return {
        "schema_version": payload["schema_version"],
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
        "sha256": (
            record_sha256
            if record_sha256 is not None
            else hashlib.sha256(path.read_bytes()).hexdigest()
        ),
        "legacy": True,
    }


def _validate_legacy_finding_payload(payload: dict[str, Any], path: Path) -> None:
    if _contains_unicode_surrogate(payload):
        raise RuntimeError("legacy finding contains non-transportable Unicode surrogate")
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
    if payload.get("severity") not in _SEVERITY_ORDER:
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
    if type(schema_version) is not int or schema_version not in {1, 2}:
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
    if payload.get("severity") not in _SEVERITY_ORDER:
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

    target_lane_id = payload.get("target_lane_id")
    if "target_lane_id" in payload and (
        schema_version == 1 or not isinstance(target_lane_id, str)
    ):
        raise RuntimeError("V1 finding lane target is invalid for schema")
    try:
        _v1_target_lane_id(payload["subject"], target_lane_id)
    except ValueError as exc:
        raise RuntimeError("V1 finding lane target is invalid") from exc

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


def _finding_record_name_hash_identity(name: str) -> str | dict[str, str]:
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        return {"filesystem_bytes_hex": os.fsencode(name).hex()}
    return name


def _finding_store_names_sha256(names: list[str]) -> str:
    return _sha256_json([
        _finding_record_name_hash_identity(name)
        for name in names
    ])


def _finding_record_name_for_evidence(name: str) -> str:
    identity = _finding_record_name_hash_identity(name)
    if isinstance(identity, str):
        return identity
    return f"<filesystem-bytes-hex:{identity['filesystem_bytes_hex']}>"


def _finding_quarantine_evidence(path: Path, exc: BaseException) -> dict[str, str]:
    return {
        "record": _finding_record_name_for_evidence(path.name),
        "error_type": type(exc).__name__,
    }


def _load_finding_payloads(
    names: list[str] | None = None,
) -> tuple[
    list[tuple[Path, dict[str, Any]]],
    list[dict[str, str]],
    dict[str, str],
]:
    """Read immutable history while keeping malformed records explicit and isolated."""
    _ensure_state()
    if names is None:
        names = sorted(
            name
            for name in os.listdir(FINDINGS_ROOT)
            if isinstance(name, str) and name.endswith(".json")
        )
    records: list[tuple[Path, dict[str, Any]]] = []
    errors: list[dict[str, str]] = []
    record_sha256s: dict[str, str] = {}
    for name in names:
        path = FINDINGS_ROOT / name
        try:
            payload, record_sha256 = _read_json_file_no_symlink_with_sha256(path)
            _validate_v1_finding_payload(payload, path)
        except Exception as exc:
            errors.append(_finding_quarantine_evidence(path, exc))
            continue
        records.append((path, payload))
        record_sha256s[path.name] = record_sha256

    v1_by_id = {
        str(payload["finding_id"]): payload
        for _, payload in records
        if payload.get("finding_contract") == FINDING_CONTRACT
    }
    invalid_paths: set[Path] = set()
    for path, payload in records:
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
            or _v1_target_lane_id(parent["subject"], parent.get("target_lane_id"))
            != _v1_target_lane_id(payload["subject"], payload.get("target_lane_id"))
        ):
            errors.append({"record": path.name, "error_type": "RuntimeError"})
            invalid_paths.add(path)
    if invalid_paths:
        records = [
            (path, payload)
            for path, payload in records
            if path not in invalid_paths
        ]
    valid_names = {path.name for path, _payload in records}
    record_sha256s = {
        name: digest
        for name, digest in record_sha256s.items()
        if name in valid_names
    }
    return records, errors, record_sha256s


def _severity_rank(value: Any) -> int:
    """Order severities by meaning, never by string comparison.

    Alphabetical ordering would place `medium` below `low`. Stored findings are
    contract-validated against `_SEVERITIES`, so an unknown value cannot reach
    this function through a valid record; should one appear, it sorts last and
    stays visible rather than being silently dropped.
    """
    if not isinstance(value, str):
        return _UNKNOWN_SEVERITY_RANK
    return _SEVERITY_ORDER.get(value, _UNKNOWN_SEVERITY_RANK)


def _lane_findings_from_loaded(
    lane_id: str,
    checkpoint: str,
    loaded: list[tuple[Path, dict[str, Any]]],
) -> list[dict[str, Any]]:
    subject = f"lane:{lane_id}"
    v1_records = [
        (path, payload)
        for path, payload in loaded
        if payload.get("finding_contract") == FINDING_CONTRACT
        and _v1_target_lane_id(payload["subject"], payload.get("target_lane_id")) == lane_id
    ]
    legacy_subjects = {lane_id, subject}
    legacy_records = [
        (path, payload)
        for path, payload in loaded
        if payload.get("finding_contract") != FINDING_CONTRACT
        and payload.get("compatibility_contract") == LEGACY_CONNECTOR_CONTRACT
        and payload.get("subject_kind") == "grabowski_lane"
        and payload.get("subject") in legacy_subjects
        and payload.get("checkpoint") == checkpoint
    ]
    v1_records.sort(
        key=lambda pair: (
            str(pair[1].get("observed_at", "")),
            str(pair[1].get("finding_id", "")),
        )
    )
    roots = {
        str(payload["finding_id"]): (path, payload)
        for path, payload in v1_records
        if not payload.get("recheck_of")
    }
    rechecks: dict[str, list[tuple[Path, dict[str, Any]]]] = {}
    for path, payload in v1_records:
        parent = payload.get("recheck_of")
        if isinstance(parent, str):
            rechecks.setdefault(parent, []).append((path, payload))

    current: dict[str, dict[str, Any]] = {}
    for finding_id, (root_path, root) in roots.items():
        matching_rechecks = [
            pair
            for pair in rechecks.get(finding_id, [])
            if pair[1].get("checkpoint") == checkpoint
        ]
        latest_pair = matching_rechecks[-1] if matching_rechecks else None
        latest_recheck = latest_pair[1] if latest_pair is not None else None
        if latest_recheck is not None:
            if latest_recheck.get("conclusion") == "no_longer_reproduced":
                continue
            if latest_recheck.get("conclusion") != "still_current":
                continue
        elif root.get("checkpoint") != checkpoint:
            continue
        item = _finding_record_view(root, root_path)
        if latest_recheck is not None:
            item["current_recheck"] = {
                key: latest_recheck.get(key)
                for key in (
                    "schema_version",
                    "finding_id",
                    "finding_sha256",
                    "checkpoint",
                    "conclusion",
                    "summary",
                    "evidence_refs",
                    "observed_at",
                )
            }
        current[finding_id] = item
    for path, payload in legacy_records:
        current.setdefault(str(payload["finding_id"]), _finding_record_view(payload, path))
    return sorted(
        current.values(),
        key=lambda item: (
            _severity_rank(item.get("severity")),
            str(item.get("finding_id", "")),
        )
    )


def _finding_store_name_snapshot(dir_fd: int) -> tuple[list[str], str]:
    names = sorted(
        name
        for name in os.listdir(dir_fd)
        if isinstance(name, str) and name.endswith(".json")
    )
    return names, _finding_store_names_sha256(names)


def _scan_finding_store_index() -> dict[str, Any]:
    """Build one canonical process-local index under the cooperative store lock."""
    _ensure_state()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    dir_fd = os.open(FINDINGS_ROOT, flags)
    locked = False
    try:
        fcntl.flock(dir_fd, fcntl.LOCK_SH)
        locked = True
        before_names, before_digest = _finding_store_name_snapshot(dir_fd)
        loaded, errors, _record_sha256s = _load_finding_payloads(before_names)
        after_names, after_digest = _finding_store_name_snapshot(dir_fd)
    finally:
        if locked:
            fcntl.flock(dir_fd, fcntl.LOCK_UN)
        os.close(dir_fd)

    membership_stable = before_names == after_names and before_digest == after_digest
    name_reconciliation_complete = (
        membership_stable
        and len(loaded) + len(errors) == len(after_names)
    )
    if not membership_stable:
        errors = [
            *errors,
            {
                "record": "<finding-store>",
                "error_type": "ConcurrentMutation",
            },
        ]
    elif not name_reconciliation_complete:
        errors = [
            *errors,
            {
                "record": "<finding-store>",
                "error_type": "NameReconciliationIncomplete",
            },
        ]
    return {
        "root": str(FINDINGS_ROOT),
        "records": loaded,
        "errors": errors,
        "store_record_names": after_names if membership_stable else [],
        "store_record_name_count": len(after_names) if membership_stable else None,
        "store_names_sha256": after_digest if membership_stable else None,
        "membership_stable": membership_stable,
        "name_reconciliation_complete": name_reconciliation_complete,
        "full_scan_observed_at": _utc_now(),
    }


def _try_increment_finding_store_index(
    path: Path,
    payload: dict[str, Any],
) -> dict[str, Any] | None:
    """Advance the validated in-memory index only for exactly one appended root."""
    global _FINDING_INDEX
    existing = _FINDING_INDEX
    if (
        not isinstance(existing, dict)
        or existing.get("root") != str(FINDINGS_ROOT)
        or existing.get("membership_stable") is not True
        or existing.get("name_reconciliation_complete") is not True
        or existing.get("errors")
        or not isinstance(existing.get("store_names_sha256"), str)
        or type(existing.get("store_record_name_count")) is not int
    ):
        return None

    if payload.get("finding_contract") == FINDING_CONTRACT:
        if payload.get("recheck_of") is not None:
            return None
    elif payload.get("compatibility_contract") != LEGACY_CONNECTOR_CONTRACT:
        return None

    finding_id = payload.get("finding_id")
    if (
        not isinstance(finding_id, str)
        or _FINDING_ID_RE.fullmatch(finding_id) is None
        or path != FINDINGS_ROOT / f"{finding_id}.json"
    ):
        return None

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    dir_fd = os.open(FINDINGS_ROOT, flags)
    locked = False
    try:
        fcntl.flock(dir_fd, fcntl.LOCK_SH)
        locked = True
        names, names_digest = _finding_store_name_snapshot(dir_fd)
        if (
            names.count(path.name) != 1
            or len(names) != existing["store_record_name_count"] + 1
        ):
            return None
        prior_names = [name for name in names if name != path.name]
        if _finding_store_names_sha256(prior_names) != existing["store_names_sha256"]:
            return None

        try:
            canonical = _read_json_file_no_symlink(path)
            _validate_v1_finding_payload(canonical, path)
        except Exception:
            return None
        if canonical != payload:
            return None

        after_names, after_digest = _finding_store_name_snapshot(dir_fd)
        if after_names != names or after_digest != names_digest:
            return None

        records = [*existing["records"], (path, canonical)]
        advanced = {
            "root": str(FINDINGS_ROOT),
            "records": records,
            "errors": [],
            "store_record_names": after_names,
            "store_record_name_count": len(after_names),
            "store_names_sha256": after_digest,
            "membership_stable": True,
            "name_reconciliation_complete": True,
            "full_scan_observed_at": existing.get("full_scan_observed_at"),
        }
        _FINDING_INDEX = advanced
        return advanced
    finally:
        if locked:
            fcntl.flock(dir_fd, fcntl.LOCK_UN)
        os.close(dir_fd)


def _projection_from_finding_index(
    index: dict[str, Any],
    lane_id: str,
    checkpoint: str,
    *,
    source_scan_mode: str,
) -> dict[str, Any]:
    loaded = index["records"]
    errors = index["errors"]
    findings = _lane_findings_from_loaded(lane_id, checkpoint, loaded)
    quarantined = errors[:MAX_QUARANTINE_RECORDS]
    incremental = source_scan_mode == "incremental-memory-index"
    return {
        "findings": findings,
        "total_current_finding_count": len(findings),
        "source_complete": bool(
            not incremental
            and index.get("membership_stable") is True
            and index.get("name_reconciliation_complete") is True
            and not errors
        ),
        "source_error_count": len(errors),
        "quarantined_record_count": len(errors),
        "quarantined_records": quarantined,
        "quarantine_details_truncated": len(errors) > len(quarantined),
        "valid_history_record_count": len(loaded),
        "store_record_name_count": index.get("store_record_name_count"),
        "store_names_sha256": index.get("store_names_sha256"),
        "source_scan_mode": source_scan_mode,
        "source_health_inherited": incremental,
        "source_rescan_required": incremental,
        "store_health_observed_at": index.get("full_scan_observed_at"),
    }


def _current_lane_projection(
    lane_id: str,
    checkpoint: str,
    *,
    incremental_record: tuple[Path, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Project current findings from validated canonical history, never from sidecar bytes."""
    global _FINDING_INDEX
    with _FINDING_INDEX_LOCK:
        index: dict[str, Any] | None = None
        mode = "full-history-scan"
        if incremental_record is not None:
            index = _try_increment_finding_store_index(
                incremental_record[0],
                incremental_record[1],
            )
            if index is not None:
                mode = "incremental-memory-index"
        if index is None:
            index = _scan_finding_store_index()
            _FINDING_INDEX = index
        return _projection_from_finding_index(
            index,
            lane_id,
            checkpoint,
            source_scan_mode=mode,
        )


def _current_lane_findings(lane_id: str, checkpoint: str) -> list[dict[str, Any]]:
    """Reconstruct current valid lane findings from canonical history."""
    return _current_lane_projection(lane_id, checkpoint)["findings"]


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


def _open_secure_state_inbox(
    dir_fd: int,
    name: str,
    *,
    allow_corrupt_json: bool = False,
) -> tuple[int, bytes] | None:
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
        except (UnicodeDecodeError, json.JSONDecodeError):
            if allow_corrupt_json:
                return fd, raw
            raise RuntimeError("existing external inbox is not Adler-owned JSON")
        if not isinstance(payload, dict):
            if allow_corrupt_json:
                return fd, raw
            raise RuntimeError("existing external inbox is not Adler-owned JSON")
        if payload.get("writer_identity") != IDENTITY or payload.get("contract") != SIDECAR_CONTRACT:
            raise RuntimeError("existing external inbox is not Adler-owned")
        return fd, raw
    except BaseException:
        os.close(fd)
        raise


def _revalidate_open_state_inbox(
    fd: int,
    expected_raw: bytes,
    *,
    allow_corrupt_json: bool = False,
) -> os.stat_result:
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
    except (UnicodeDecodeError, json.JSONDecodeError):
        if allow_corrupt_json:
            return opened
        raise RuntimeError("external inbox changed before atomic publication")
    if not isinstance(payload, dict):
        if allow_corrupt_json:
            return opened
        raise RuntimeError("external inbox changed before atomic publication")
    if payload.get("writer_identity") != IDENTITY or payload.get("contract") != SIDECAR_CONTRACT:
        raise RuntimeError("external inbox changed before atomic publication")
    return opened


def _encode_bounded_inbox_payload(
    base_payload: dict[str, Any],
    findings: list[dict[str, Any]],
    *,
    total_current_finding_count: int,
) -> tuple[dict[str, Any], bytes]:
    visible = list(findings)
    while True:
        omitted = max(0, total_current_finding_count - len(visible))
        payload = {
            **base_payload,
            "findings": visible,
            "finding_count": len(visible),
            "total_current_finding_count": total_current_finding_count,
            "projection_complete": omitted == 0,
            "omitted_finding_count": omitted,
            "omission_reason": (
                None if omitted == 0 else "bounded_current_view"
            ),
            "omitted_identity_complete": omitted == 0,
        }
        payload["projection_sha256"] = _sha256_json(payload)
        encoded = (
            json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)
            + "\n"
        ).encode("utf-8")
        if len(encoded) <= MAX_OUTPUT_BYTES:
            return payload, encoded
        if visible:
            visible.pop()
            continue
        raise RuntimeError("worktree inbox metadata exceeds bounded size")


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


def _atomic_write_inbox(
    dir_fd: int,
    name: str,
    encoded: bytes,
    *,
    allow_corrupt_json: bool = False,
) -> None:
    existing = _open_secure_state_inbox(
        dir_fd,
        name,
        allow_corrupt_json=allow_corrupt_json,
    )
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
            validated = _revalidate_open_state_inbox(
                existing_fd,
                existing_raw,
                allow_corrupt_json=allow_corrupt_json,
            )
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
    lane_id: str,
    *,
    expected_checkpoint: str | None = None,
    incremental_record: tuple[Path, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    initial_target = _read_work_target(lane_id)
    if (
        expected_checkpoint is not None
        and initial_target["checkpoint"] != expected_checkpoint
    ):
        raise RuntimeError("lane checkpoint changed before inbox publication")
    worktree = Path(initial_target["worktree"])
    inbox_path = _validate_worktree_inbox_pointer(worktree, lane_id)
    _ensure_state()
    inbox_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        inbox_flags |= os.O_NOFOLLOW
    inbox_dir_fd = os.open(INBOX_ROOT, inbox_flags)
    store_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        store_flags |= os.O_NOFOLLOW
    store_dir_fd = os.open(FINDINGS_ROOT, store_flags)
    locked = False
    store_locked = False
    try:
        fcntl.flock(inbox_dir_fd, fcntl.LOCK_EX)
        locked = True
        fcntl.flock(store_dir_fd, fcntl.LOCK_SH)
        store_locked = True
        target = _read_work_target(lane_id)
        if Path(target["worktree"]) != worktree:
            raise RuntimeError("lane worktree changed during inbox publication")
        if (
            expected_checkpoint is not None
            and target["checkpoint"] != expected_checkpoint
        ):
            raise RuntimeError("lane checkpoint changed during inbox publication")
        if _validate_worktree_inbox_pointer(worktree, lane_id) != inbox_path:
            raise RuntimeError("worktree inbox pointer changed during publication")

        projection = _current_lane_projection(
            lane_id,
            target["checkpoint"],
            incremental_record=incremental_record,
        )

        base_payload = {
            "schema_version": 1,
            "contract": SIDECAR_CONTRACT,
            "writer_identity": IDENTITY,
            "delivery_mode": "grabowski_owned_symlink_to_adler_state",
            "lane_id": lane_id,
            "repository": target["repository"],
            "worktree": target["worktree"],
            "branch": target["branch"],
            "checkpoint": target["checkpoint"],
            "source_complete": projection["source_complete"],
            "source_error_count": projection["source_error_count"],
            "quarantined_record_count": projection[
                "quarantined_record_count"
            ],
            "quarantined_records": projection["quarantined_records"],
            "quarantine_details_truncated": projection[
                "quarantine_details_truncated"
            ],
            "valid_history_record_count": projection[
                "valid_history_record_count"
            ],
            "store_record_name_count": projection[
                "store_record_name_count"
            ],
            "store_names_sha256": projection["store_names_sha256"],
            "source_scan_mode": projection["source_scan_mode"],
            "source_health_inherited": projection[
                "source_health_inherited"
            ],
            "source_rescan_required": projection[
                "source_rescan_required"
            ],
            "store_health_observed_at": projection[
                "store_health_observed_at"
            ],
            "history_mutation_model": "immutable_append_only",
            "current_view_model": "bounded_reconstructible_projection",
            "source_store": str(FINDINGS_ROOT),
            "inbox_store": str(inbox_path),
            "generated_at": _utc_now(),
            "effect_contract": "advisory_only_no_automatic_action",
            "does_not_establish": [
                "absence_of_findings_after_generated_at",
                "work_state_authority",
                "decision_authority",
                "effect_permission",
            ],
        }
        payload, encoded = _encode_bounded_inbox_payload(
            base_payload,
            projection["findings"],
            total_current_finding_count=projection[
                "total_current_finding_count"
            ],
        )
        _atomic_write_inbox(
            inbox_dir_fd,
            inbox_path.name,
            encoded,
            allow_corrupt_json=True,
        )
        published_target = _read_work_target(lane_id)
        if Path(published_target["worktree"]) != worktree:
            raise RuntimeError("lane worktree changed after inbox publication")
        if published_target["checkpoint"] != target["checkpoint"]:
            raise RuntimeError("lane checkpoint changed after inbox publication")
        if _validate_worktree_inbox_pointer(worktree, lane_id) != inbox_path:
            raise RuntimeError("worktree inbox pointer changed after publication")
    finally:
        if store_locked:
            fcntl.flock(store_dir_fd, fcntl.LOCK_UN)
        os.close(store_dir_fd)
        if locked:
            fcntl.flock(inbox_dir_fd, fcntl.LOCK_UN)
        os.close(inbox_dir_fd)
    return {
        "state": "published",
        "lane_id": lane_id,
        "checkpoint": target["checkpoint"],
        "finding_count": payload["finding_count"],
        "total_current_finding_count": payload[
            "total_current_finding_count"
        ],
        "projection_complete": payload["projection_complete"],
        "omitted_finding_count": payload["omitted_finding_count"],
        "sidecar": str(worktree / ".adler" / "inbox.json"),
        "inbox_store": str(inbox_path),
        "source_complete": payload["source_complete"],
        "source_error_count": payload["source_error_count"],
        "quarantined_record_count": payload[
            "quarantined_record_count"
        ],
        "source_scan_mode": payload["source_scan_mode"],
        "source_rescan_required": payload["source_rescan_required"],
        "observed_at": _utc_now(),
    }


@mcp.tool(name="publish_worktree_inbox", annotations=SIDECAR_ANNOTATIONS)
def publish_worktree_inbox(lane_id: str) -> dict[str, Any]:
    """Rebuild one current advisory inbox for an exact active Grabowski lane."""
    return _publish_worktree_inbox(_validate_lane_id(lane_id))


_FINDING_CURSOR_RE = re.compile(
    r"^af1\.([0-9a-f]{64})\.([0-9]{1,4})\.([0-9a-f]{64})$"
)
_V1_FINDING_KINDS = {
    "observation",
    "risk",
    "contradiction",
    "missing_evidence",
    "advice",
}


def _bounded_finding_record_names() -> list[str]:
    names: list[str] = []
    with os.scandir(FINDINGS_ROOT) as entries:
        for entry in entries:
            name = entry.name
            if not isinstance(name, str) or not name.endswith(".json"):
                continue
            names.append(name)
            if len(names) > MAX_FINDING_RETRIEVAL_SOURCE_RECORDS:
                raise RuntimeError(
                    "finding retrieval source record bound exceeded; "
                    f"maximum is {MAX_FINDING_RETRIEVAL_SOURCE_RECORDS}"
                )
    names.sort()
    return names


def _load_bounded_finding_history() -> dict[str, Any]:
    _ensure_state()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    dir_fd = os.open(FINDINGS_ROOT, flags)
    locked = False
    try:
        fcntl.flock(dir_fd, fcntl.LOCK_SH)
        locked = True
        before_names = _bounded_finding_record_names()
        records, errors, record_sha256s = _load_finding_payloads(before_names)
        after_names = _bounded_finding_record_names()
    finally:
        if locked:
            fcntl.flock(dir_fd, fcntl.LOCK_UN)
        os.close(dir_fd)

    membership_stable = before_names == after_names
    name_reconciliation_complete = (
        membership_stable
        and len(records) + len(errors) == len(before_names)
    )
    if not membership_stable:
        errors = [
            *errors,
            {"record": "<finding-store>", "error_type": "ConcurrentMutation"},
        ]
    elif not name_reconciliation_complete:
        errors = [
            *errors,
            {
                "record": "<finding-store>",
                "error_type": "NameReconciliationIncomplete",
            },
        ]
    snapshot_sha256 = _sha256_json(
        {
            "record_names": [
                _finding_record_name_hash_identity(name)
                for name in before_names
            ],
            "records": [
                [
                    _finding_record_name_hash_identity(path.name),
                    record_sha256s[path.name],
                ]
                for path, _payload in records
            ],
            "errors": errors,
        }
    )
    return {
        "records": records,
        "errors": errors,
        "record_names": before_names,
        "record_sha256s": record_sha256s,
        "membership_stable": membership_stable,
        "name_reconciliation_complete": name_reconciliation_complete,
        "store_names_sha256": _finding_store_names_sha256(before_names),
        "history_snapshot_sha256": snapshot_sha256,
    }


def _finding_filter_text(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 500
        or _contains_unicode_surrogate(value)
    ):
        raise ValueError(f"{field} must be an exact non-blank 1..500 character string")
    return value


def _finding_checkpoint_filter(value: str | None) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) > 500
        or _contains_unicode_surrogate(value)
    ):
        raise ValueError("checkpoint must be an exact transportable 0..500 character string")
    return value


def _finding_filters_sha256(
    *,
    exact_subject: str | None,
    checkpoint: str | None,
    checkpoint_is_null: bool,
    kind: str | None,
    severity: str | None,
    recheck_of: str | None,
) -> str:
    return _sha256_json(
        {
            "exact_subject": exact_subject,
            "checkpoint": checkpoint,
            "checkpoint_is_null": checkpoint_is_null,
            "kind": kind,
            "severity": severity,
            "recheck_of": recheck_of,
        }
    )


def _encode_finding_cursor(
    *,
    history_snapshot_sha256: str,
    offset: int,
    filters_sha256: str,
) -> str:
    return (
        f"af1.{history_snapshot_sha256}.{offset}.{filters_sha256}"
    )


def _decode_finding_cursor(cursor: str) -> tuple[str, int, str]:
    if not isinstance(cursor, str):
        raise ValueError("invalid finding cursor")
    match = _FINDING_CURSOR_RE.fullmatch(cursor)
    if match is None:
        raise ValueError("invalid finding cursor")
    snapshot_sha256, offset_raw, filters_sha256 = match.groups()
    offset = int(offset_raw)
    if offset > MAX_FINDING_RETRIEVAL_SOURCE_RECORDS:
        raise ValueError("invalid finding cursor offset")
    return snapshot_sha256, offset, filters_sha256


def _finding_matches_filters(
    payload: dict[str, Any],
    *,
    exact_subject: str | None,
    checkpoint: str | None,
    checkpoint_is_null: bool,
    kind: str | None,
    severity: str | None,
    recheck_of: str | None,
) -> bool:
    if exact_subject is not None and payload.get("subject") != exact_subject:
        return False
    if checkpoint_is_null:
        if payload.get("checkpoint") is not None:
            return False
    elif checkpoint is not None and payload.get("checkpoint") != checkpoint:
        return False
    payload_kind = (
        payload.get("kind")
        if payload.get("finding_contract") == FINDING_CONTRACT
        else payload.get("status")
    )
    if kind is not None and payload_kind != kind:
        return False
    if severity is not None and payload.get("severity") != severity:
        return False
    if recheck_of is not None and payload.get("recheck_of") != recheck_of:
        return False
    return True


@mcp.tool(name="list_findings", annotations=READ_ANNOTATIONS)
def list_findings(
    limit: int = 20,
    cursor: str | None = None,
    exact_subject: str | None = None,
    checkpoint: str | None = None,
    checkpoint_is_null: bool = False,
    kind: str | None = None,
    severity: str | None = None,
    recheck_of: str | None = None,
) -> dict[str, Any]:
    """Page immutable finding history with exact filters and no current-truth projection."""
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    exact_subject = _finding_filter_text(exact_subject, "exact_subject")
    checkpoint = _finding_checkpoint_filter(checkpoint)
    if not isinstance(checkpoint_is_null, bool):
        raise ValueError("checkpoint_is_null must be a boolean")
    if checkpoint_is_null and checkpoint is not None:
        raise ValueError("checkpoint and checkpoint_is_null are mutually exclusive")
    if kind is not None and kind not in (_V1_FINDING_KINDS | _LEGACY_STATUSES):
        raise ValueError("kind is not a supported finding contract value")
    if severity is not None and severity not in _SEVERITY_ORDER:
        raise ValueError("severity is not a supported finding contract value")
    if recheck_of is not None and (
        not isinstance(recheck_of, str)
        or _FINDING_ID_RE.fullmatch(recheck_of) is None
    ):
        raise ValueError("recheck_of must be an exact finding id")

    filters_sha256 = _finding_filters_sha256(
        exact_subject=exact_subject,
        checkpoint=checkpoint,
        checkpoint_is_null=checkpoint_is_null,
        kind=kind,
        severity=severity,
        recheck_of=recheck_of,
    )
    cursor_snapshot = None
    offset = 0
    if cursor is not None:
        cursor_snapshot, offset, cursor_filters = _decode_finding_cursor(cursor)
        if cursor_filters != filters_sha256:
            raise ValueError("finding cursor filters do not match")

    history = _load_bounded_finding_history()
    history_snapshot_sha256 = history["history_snapshot_sha256"]
    if cursor_snapshot is not None and cursor_snapshot != history_snapshot_sha256:
        raise ValueError("finding cursor store membership changed; restart retrieval")

    ordered = sorted(
        (
            (path, payload)
            for path, payload in history["records"]
            if _finding_matches_filters(
                payload,
                exact_subject=exact_subject,
                checkpoint=checkpoint,
                checkpoint_is_null=checkpoint_is_null,
                kind=kind,
                severity=severity,
                recheck_of=recheck_of,
            )
        ),
        key=lambda pair: str(pair[1].get("finding_id", "")),
        reverse=True,
    )
    if offset > len(ordered):
        raise ValueError("finding cursor offset is outside the filtered snapshot")

    selected = ordered[offset : offset + limit]
    items = [
        _finding_record_view(
            payload,
            path,
            record_sha256=history["record_sha256s"][path.name],
        )
        for path, payload in selected
    ]
    next_offset = offset + len(items)
    has_more = next_offset < len(ordered)
    next_cursor = None
    if has_more:
        next_cursor = _encode_finding_cursor(
            history_snapshot_sha256=history_snapshot_sha256,
            offset=next_offset,
            filters_sha256=filters_sha256,
        )

    errors = history["errors"]
    source_complete = bool(
        history["membership_stable"]
        and history["name_reconciliation_complete"]
        and not errors
    )
    quarantined = errors[:MAX_QUARANTINE_RECORDS]
    store_health = {
        "source_complete": source_complete,
        "valid_record_count": len(history["records"]),
        "store_record_name_count": len(history["record_names"]),
        "quarantined_record_count": len(errors),
        "quarantined_records": quarantined,
        "quarantine_details_truncated": len(errors) > len(quarantined),
        "history_mutation_model": "immutable_append_only",
        "current_view_model": "bounded_reconstructible_projection",
        "retrieval_model": "bounded_snapshot_history",
        "retrieval_source_record_limit": MAX_FINDING_RETRIEVAL_SOURCE_RECORDS,
        "membership_stable": history["membership_stable"],
        "name_reconciliation_complete": history["name_reconciliation_complete"],
        "store_names_sha256": history["store_names_sha256"],
        "observed_at": _utc_now(),
    }
    return {
        "count": len(items),
        "findings": items,
        "pagination": {
            "limit": limit,
            "offset": offset,
            "order": "finding_id_desc",
            "history_snapshot_sha256": history_snapshot_sha256,
            "matching_snapshot_record_count": len(ordered),
            "has_more": has_more,
            "next_cursor": next_cursor,
            "retrieval_complete": not has_more,
        },
        "source_complete": source_complete,
        "source_error_count": len(errors),
        "quarantined_record_count": len(errors),
        "store_health": store_health,
        "historical_retrieval_only": True,
        "does_not_establish": [
            "current_truth",
            "latest_state_of_subject",
            "semantic_subject_equivalence",
            "task_or_work_authority",
            "decision_authority",
        ],
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
    encoded = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
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
    target_lane_id: str | None = None,
) -> dict[str, Any]:
    """Append adler-finding-v1 schema 2; target_lane_id is exactly 32 lowercase hex.

    The exact lane:<id> subject is a compatibility fallback when no target is supplied.
    """
    _ensure_state()
    subject_clean = _clean_required_identity_text(subject, "subject")
    checkpoint_clean = _clean_required_identity_text(checkpoint, "checkpoint")
    lane_id = _v1_target_lane_id(subject_clean, target_lane_id)
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
        if _v1_target_lane_id(parent["subject"], parent.get("target_lane_id")) != lane_id:
            raise ValueError("recheck lane target must match original finding")

    observed_at = _utc_now()
    finding_id = f"ga-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:12]}"
    payload: dict[str, Any] = {
        "schema_version": 2,
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
    if target_lane_id is not None:
        payload["target_lane_id"] = target_lane_id
    if recommendation_clean is not None:
        payload["recommendation"] = recommendation_clean
    if effects:
        payload["affected_effects"] = effects
    if recheck_of is not None:
        payload["recheck_of"] = recheck_of
        payload["conclusion"] = conclusion

    finding_sha256, record_sha256 = _persist_finding(payload)
    persisted_payload = dict(payload)
    persisted_payload["finding_sha256"] = finding_sha256
    persisted_path = FINDINGS_ROOT / f"{finding_id}.json"
    delivery: dict[str, Any] = {"state": "not_applicable"}
    if lane_id is not None:
        try:
            delivery = _publish_worktree_inbox(
                lane_id,
                expected_checkpoint=checkpoint_clean,
                incremental_record=(persisted_path, persisted_payload),
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
    """Persist the historical connector shape; only exact lane ids are eligible for optional delivery."""
    _ensure_state()
    if subject_kind not in {"repo", "pr", "commit", "runtime", "bureau_task", "grabowski_lane"}:
        raise ValueError("unsupported legacy subject_kind")
    if severity not in _SEVERITY_ORDER:
        raise ValueError("invalid severity")
    if status not in _LEGACY_BASE_STATUSES:
        raise ValueError("unsupported legacy status")

    if not isinstance(subject, str) or not subject.strip() or len(subject) > 500:
        raise ValueError("subject must be 1..500 characters")
    subject_clean = _redact(subject.strip())
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
    persisted_path = FINDINGS_ROOT / f"{finding_id}.json"

    delivery: dict[str, Any] = {"state": "not_applicable"}
    if lane_id is not None and checkpoint_clean not in {None, ""}:
        try:
            delivery = _publish_worktree_inbox(
                lane_id,
                expected_checkpoint=checkpoint_clean,
                incremental_record=(persisted_path, payload),
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
