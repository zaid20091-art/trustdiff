"""Hardened primitives shared by every TrustDiff module that touches untrusted repository data.

* bounded_run   - subprocess with hard time and output limits and whole-process-group kill
* run_git       - git with execution-capable configuration neutralised and output bounded
* git_config_risks - refuses repositories whose local config makes plain `git status/diff` run commands
* regular_file_sha256 / read_regular_text - never block on or buffer special/huge files

Nothing here trusts the repository: a candidate (human or agent) controls .git/config, file names,
file sizes and file types.
"""
from __future__ import annotations

import hashlib
import ctypes
import os
import re
import shutil
import signal
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_OUTPUT_BYTES = 16 * 1024 * 1024      # strict ceiling for machine-consumed output (git diff, etc.)
HARD_STREAM_LIMIT = 64 * 1024 * 1024     # tail mode: kill the child after this many bytes
MAX_SOURCE_FILE = 1_000_000
MAX_HASHED_FILE = 256 * 1024 * 1024

# Overflow / timeout exit codes shared with the rest of the code base (124 = timeout, 125 = runner failure).
RC_TIMEOUT = 124
RC_OVERFLOW = 125
RC_UNAVAILABLE = 127
RC_UNSAFE_CONFIG = 126
CREATE_SUSPENDED = 0x00000004


@dataclass
class BoundedResult:
    rc: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    truncated: bool = False


class WindowsJob:
    """Kill all processes assigned to this run, including children retaining its pipes."""

    def __init__(self, proc: subprocess.Popen):
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel = kernel
        self.handle = kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        process = wintypes.HANDLE(int(proc._handle))
        if not kernel.AssignProcessToJobObject(self.handle, process):
            error = ctypes.get_last_error()
            self.close()
            raise ctypes.WinError(error)
        # Popen closes the primary thread handle before returning it to callers.
        resume = ctypes.WinDLL("ntdll").NtResumeProcess
        resume.argtypes = [wintypes.HANDLE]
        resume.restype = wintypes.LONG
        if resume(process) != 0:
            self.kill()
            self.close()
            raise OSError("cannot resume supervised process")

    def kill(self) -> None:
        if self.handle:
            self.kernel.TerminateJobObject(self.handle, 1)

    def close(self) -> None:
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def _kill_group(proc: subprocess.Popen, job: WindowsJob | None = None) -> None:
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        elif job is not None:
            job.kill()
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def bounded_run(argv: list[str], *, cwd: Path | str | None = None, env: dict[str, str] | None = None,
                timeout: float = 30, max_output: int = MAX_OUTPUT_BYTES, tail: bool = False,
                hard_limit: int = HARD_STREAM_LIMIT, stdin_data: bytes | None = None) -> BoundedResult:
    """Run a command with a wall-clock limit and bounded memory.

    strict mode (default): output above `max_output` kills the child and sets truncated=True; callers must treat that as an error.
    tail mode: keep only the LAST `max_output` bytes per stream (useful for test logs); kill the child above `hard_limit` total bytes.
    """
    deadline = time.monotonic() + timeout
    try:
        if os.name == "nt" and argv[0] in {"git", "docker"}:
            search_env = env if env is not None else os.environ
            for directory in search_env.get("PATH", os.defpath).split(os.pathsep):
                if os.path.isabs(directory):
                    executable = shutil.which(os.path.join(directory, argv[0] + ".exe"))
                    if executable:
                        argv = [executable, *argv[1:]]
                        break
            else:
                raise FileNotFoundError(argv[0])
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=(os.name == "posix"),
                                creationflags=CREATE_SUSPENDED if os.name == "nt" else 0)
    except OSError as exc:
        return BoundedResult(RC_UNAVAILABLE, b"", f"cannot start {argv[0]!r}: {exc}".encode())
    try:
        job = WindowsJob(proc) if os.name == "nt" else None
    except OSError:
        proc.kill()
        proc.wait()
        return BoundedResult(RC_UNAVAILABLE, b"", b"cannot supervise Windows process tree")

    buffers = {"out": bytearray(), "err": bytearray()}
    totals = {"out": 0, "err": 0}
    flags = {"truncated": False}
    lock = threading.Lock()

    def pump(stream, key: str) -> None:
        buf = buffers[key]
        try:
            while True:
                chunk = stream.read1(65536)
                if not chunk:
                    return
                with lock:
                    totals[key] += len(chunk)
                    if tail:
                        buf.extend(chunk)
                        if len(buf) > max_output:
                            del buf[: len(buf) - max_output]
                        over = sum(totals.values()) > hard_limit
                    else:
                        room = max_output - len(buf)
                        buf.extend(chunk[: max(room, 0)])
                        over = len(chunk) > room
                    if over:
                        flags["truncated"] = True
                if flags["truncated"]:
                    _kill_group(proc, job)
                    return
        except (OSError, ValueError):
            return

    threads = [threading.Thread(target=pump, args=(proc.stdout, "out"), daemon=True),
               threading.Thread(target=pump, args=(proc.stderr, "err"), daemon=True)]
    def send_input() -> None:
        try:
            with proc.stdin:
                proc.stdin.write(stdin_data)
        except OSError:
            pass

    if stdin_data is not None:
        threads.append(threading.Thread(target=send_input, daemon=True))
    for t in threads:
        t.start()
    timed_out = False
    try:
        proc.wait(timeout=max(0, deadline - time.monotonic()))
        for t in threads:
            t.join(timeout=max(0, deadline - time.monotonic()))
        timed_out = any(t.is_alive() for t in threads)
    except subprocess.TimeoutExpired:
        timed_out = True
    finally:
        _kill_group(proc, job)
        if job is not None:
            job.close()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            timed_out = True
        for t in threads:
            t.join(timeout=0.25)
        for t, pipe in zip(threads, (proc.stdout, proc.stderr, proc.stdin)):
            if not t.is_alive():
                pipe.close()
    rc = RC_TIMEOUT if timed_out else RC_OVERFLOW if flags["truncated"] else proc.returncode
    return BoundedResult(rc, bytes(buffers["out"]), bytes(buffers["err"]), timed_out, flags["truncated"])


# --------------------------------------------------------------------------- git

# Applied with -c, which outranks every config file. Do not add anything here that changes git's output format.
GIT_HARDENING = ["-c", "core.fsmonitor=false", "-c", f"core.hooksPath={os.devnull}", "-c", "core.quotepath=false",
                 "-c", "core.pager=cat", "-c", "protocol.allow=never", "-c", "submodule.recurse=false",
                 "-c", "diff.astextplain.textconv=", "-c", "credential.helper=",
                 "-c", "filter.lfs.clean=", "-c", "filter.lfs.smudge=", "-c", "filter.lfs.process=", "-c", "filter.lfs.required=false"]
_SCRUB_ENV = {"GIT_EXTERNAL_DIFF", "GIT_PAGER", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_ASKPASS", "GIT_PROXY_COMMAND",
              "GIT_EXEC_PATH", "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
              "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_GLOBAL",
              "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_NAMESPACE", "GIT_COMMON_DIR", "GIT_ATTR_SOURCE"}


def git_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in _SCRUB_ENV and not k.startswith("GIT_CONFIG_KEY_") and not k.startswith("GIT_CONFIG_VALUE_")}
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_NOSYSTEM": "0", "LC_ALL": "C",
                "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": ""})
    return env


def run_git(root: Path | str, *args: str, timeout: float = 60, max_output: int = MAX_OUTPUT_BYTES) -> tuple[int, str, str]:
    """git with execution-capable options neutralised. rc 125 means output exceeded the limit (never a partial success)."""
    result = bounded_run(["git", *GIT_HARDENING, *args], cwd=root, env=git_env(), timeout=timeout, max_output=max_output)
    err = result.stderr.decode("utf-8", "replace")
    if result.rc == RC_OVERFLOW:
        err = f"git output exceeded the {max_output} byte limit"
    return result.rc, result.stdout.decode("utf-8", "replace"), err


def run_git_bytes(root: Path | str, *args: str, timeout: float = 60, max_output: int = MAX_OUTPUT_BYTES) -> tuple[int, bytes, str]:
    result = bounded_run(["git", *GIT_HARDENING, *args], cwd=root, env=git_env(), timeout=timeout, max_output=max_output)
    err = "git output exceeded the byte limit" if result.rc == RC_OVERFLOW else result.stderr.decode("utf-8", "replace")
    return result.rc, result.stdout, err


_EXEC_KEYS = [
    (re.compile(r"^core\.fsmonitor$"), lambda v: v.strip().lower() not in {"", "false", "0", "no", "off"}),
    (re.compile(r"^diff\.external$"), lambda v: bool(v.strip())),
    (re.compile(r"^diff\..+\.(command|textconv)$"), lambda v: bool(v.strip())),
    (re.compile(r"^filter\..+\.(clean|smudge|process)$"), lambda v: bool(v.strip())),
    (re.compile(r"^core\.(sshcommand|gitproxy|askpass)$"), lambda v: bool(v.strip())),
    (re.compile(r"^(credential\..*helper|gpg\..*program|gpg\.program)$"), lambda v: bool(v.strip())),
]
_STANDARD_LFS_CONFIG = {
    "filter.lfs.clean": {"git-lfs clean -- %f"},
    "filter.lfs.smudge": {"git-lfs smudge -- %f", "git-lfs smudge --skip -- %f"},
    "filter.lfs.process": {"git-lfs filter-process", "git-lfs filter-process --skip"},
}


def git_config_risks(root: Path | str) -> list[str]:
    """Names of configuration entries that would make our git calls execute a command. Reading config never executes anything."""
    result = bounded_run(["git", "-c", "core.fsmonitor=false", "config", "--list", "--show-origin", "--show-scope", "-z", "--includes"],
                         cwd=root, env=git_env(), timeout=30, max_output=2 * 1024 * 1024)
    if result.rc != 0:
        return [f"cannot read git configuration (rc={result.rc})"]
    risks: list[str] = []
    records = result.stdout.decode("utf-8", "replace").split("\0")[:-1]
    if len(records) % 3:
        return ["unexpected Git configuration output"]
    for scope, origin, record in zip(records[::3], records[1::3], records[2::3]):
        key, _, value = record.partition("\n")
        key = key.lower()
        if value in _STANDARD_LFS_CONFIG.get(key, ()) or (
            scope == "system" and (key, value) in {("diff.astextplain.textconv", "astextplain"), ("credential.helper", "manager")}
        ):
            continue  # these commands are explicitly neutralised on every invocation
        for pattern, dangerous in _EXEC_KEYS:
            if pattern.match(key) and dangerous(value):
                risks.append(f"{key} (from {origin})")
    return sorted(set(risks))


class UnsafeGitConfig(RuntimeError):
    pass


def require_safe_git_config(root: Path | str) -> None:
    if os.environ.get("TRUSTDIFF_TRUST_GIT_CONFIG") == "1":
        return
    risks = git_config_risks(root)
    if risks:
        raise UnsafeGitConfig("Repository git configuration can execute commands during verification: " + "; ".join(risks[:5])
                              + ". Verify a fresh clone/CI checkout instead (or set TRUSTDIFF_TRUST_GIT_CONFIG=1 for a repository you control).")


# --------------------------------------------------------------------------- files

def is_regular_file(path: Path) -> bool:
    try:
        entry = os.lstat(path)
        return stat.S_ISREG(entry.st_mode) and not getattr(entry, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    except OSError:
        return False


def regular_file_sha256(path: Path, limit: int = MAX_HASHED_FILE) -> tuple[str | None, str]:
    """Stream-hash a regular file. Returns (digest, note); digest is None for special, oversized or unreadable files."""
    try:
        st = os.lstat(path)
    except OSError as exc:
        return None, f"unreadable:{type(exc).__name__}"
    if stat.S_ISLNK(st.st_mode):
        return hashlib.sha256(b"<symlink>" + os.fsencode(os.readlink(path))).hexdigest(), "symlink"
    if not stat.S_ISREG(st.st_mode):
        return None, "not-a-regular-file"
    if st.st_size > limit:
        return None, "too-large"
    h = hashlib.sha256()
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                return None, "not-a-regular-file"
            while chunk := handle.read(1 << 20):
                limit -= len(chunk)
                if limit < 0:
                    return None, "too-large"
                h.update(chunk)
    except OSError as exc:
        return None, f"unreadable:{type(exc).__name__}"
    return h.hexdigest(), "file"


def read_regular_text(path: Path, limit: int = MAX_SOURCE_FILE) -> str | None:
    """Bounded UTF-8 read of a regular, non-symlink file; None otherwise."""
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            return None
        with open(path, "rb") as handle:
            raw = handle.read(limit + 1)
        return raw.decode("utf-8") if len(raw) <= limit else None
    except (OSError, UnicodeError):
        return None


def clean_repo_path(value: str) -> bool:
    """True for a normalised relative POSIX path with no traversal, control characters or backslashes."""
    if not value or len(value) > 4096 or value.startswith("/") or "\\" in value or ":" in value:
        return False
    if any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def git_path(raw: bytes) -> str:
    """Keep legal non-UTF-8 names distinguishable on POSIX and in JSON on Windows."""
    return raw.decode("utf-8", "surrogateescape")


def parse_name_status_z(raw: bytes) -> list[dict[str, str]]:
    """Parse `git diff --name-status -z --no-renames` exactly (no quoting, no tab/newline ambiguity)."""
    parts = raw.split(b"\0")
    out: list[dict[str, str]] = []
    i = 0
    while i + 1 < len(parts):
        status, path = parts[i].decode("utf-8", "replace"), parts[i + 1]
        if not status:
            break
        out.append({"status": status, "path": git_path(path)})
        i += 2
    return out


# --------------------------------------------------------------------------- untrusted-regex evaluation

_REGEX_WORKER = r'''
import json, re, sys
data = json.load(sys.stdin)
try:
    rx = re.compile(data["pattern"])
except re.error as exc:
    print(json.dumps({"error": "invalid regular expression: " + str(exc)[:200]})); sys.exit(0)
hits = []
for line in data["lines"]:
    if rx.search(line[:4096]):
        hits.append(line[:500])
        if len(hits) >= 200:
            break
print(json.dumps({"hits": hits}))
'''


def regex_hits(pattern: str, lines: list[str], timeout: float = 5.0) -> tuple[list[str] | None, str | None]:
    """Search lines with an untrusted pattern in an isolated child with a hard time limit (Python's `re` cannot be interrupted).

    Returns (hits, error). error is set for invalid patterns, timeouts (catastrophic backtracking) or worker failure.
    """
    import json
    import sys
    payload = json.dumps({"pattern": pattern, "lines": lines}).encode("utf-8")
    result = bounded_run([sys.executable, "-I", "-c", _REGEX_WORKER], timeout=timeout, max_output=1_000_000, stdin_data=payload)
    if result.timed_out:
        return None, f"pattern evaluation exceeded {timeout:g}s (possible catastrophic backtracking)"
    if result.rc != 0:
        return None, "pattern evaluation failed"
    try:
        data = json.loads(result.stdout.decode("utf-8"))
    except ValueError:
        return None, "pattern evaluation returned malformed output"
    if "error" in data:
        return None, data["error"]
    return data["hits"], None
