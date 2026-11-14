"""Constrained Docker contract runner. Docker is defense in depth, not a VM boundary.

What the container can see
  * a clean, read-only export of the target COMMIT (tracked files only): no .git, no .trustdiff state,
    no untracked files such as .env, no verifier keys, no other job's data;
  * tmpfs /tmp (64 MiB, noexec);
  * nothing else - never the Docker socket, host namespaces, devices or extra capabilities.

What the host guarantees
  * every job has a unique name, label and workspace; all are torn down in `finally`;
  * on timeout or output overflow the CONTAINER is killed by name (killing the docker CLI alone does not stop it);
  * captured output is bounded (tail kept), so a chatty test cannot exhaust verifier memory.
"""
from __future__ import annotations

import os
import hashlib
import re
import shutil
import stat
import sys
import tempfile
import uuid
from pathlib import Path, PurePosixPath

import trustdiff_safe as safe

IMAGE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:@-]*")
PINNED_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64}$")
MAX_SNAPSHOT_BYTES = 512 * 1024 * 1024
MAX_SNAPSHOT_FILES = 100_000
MAX_BLOB_BYTES = 32 * 1024 * 1024
LFS_HEADER = b"version https://git-lfs.github.com/spec/v1"
LFS_POINTER = re.compile(rb"version https://git-lfs.github.com/spec/v1\noid sha256:([a-f0-9]{64})\nsize (0|[1-9][0-9]{0,17})\n")
WINDOWS_DEVICES = {"con", "prn", "aux", "nul", "conin$", "conout$"} | {
    prefix + digit for prefix in ("com", "lpt") for digit in "123456789¹²³"
}
LOG_CHARS = 12000
STARTUP_SLACK = 10   # seconds allowed for container start/stop on top of the contract timeout
_DOCKER_ENV_KEYS = {"PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG"}

# Stronger isolation = a different OCI runtime behind the SAME constrained flags. The runtime must already be installed and
# registered with the Docker daemon (gVisor: `runsc`; Kata Containers: a lightweight VM per container). TrustDiff checks that
# the daemon lists it and fails closed otherwise; it never falls back to plain runc.
ALLOWED_RUNTIMES = {"runsc", "runsc-kvm", "io.containerd.kata.v2", "kata", "kata-runtime", "kata-qemu", "kata-clh", "kata-fc"}
_RUNTIME_CACHE: dict[tuple[str, str], bool] = {}


def isolation_class(runtime: str | None) -> str:
    if not runtime:
        return "docker-container"
    return "gvisor-userspace-kernel" if runtime.startswith("runsc") else "microvm"


def runtime_available(docker: str, runtime: str) -> bool:
    key = (docker, runtime)
    if key not in _RUNTIME_CACHE:
        info = safe.bounded_run([docker, "info", "--format", "{{json .Runtimes}}"], env=_docker_env(), timeout=30, max_output=65536)
        try:
            import json
            _RUNTIME_CACHE[key] = info.rc == 0 and runtime in json.loads(info.stdout.decode("utf-8", "replace") or "{}")
        except ValueError:
            _RUNTIME_CACHE[key] = False
    return _RUNTIME_CACHE[key]

# Anything here appearing before the image name is a sandbox escape or a widening of access.
FORBIDDEN_RUN_FLAGS = ("--privileged", "--pid=host", "--network=host", "--net=host", "--ipc=host", "--uts=host", "--userns=host",
                       "--volumes-from", "-v", "--volume", "--device", "--cap-add", "--security-opt=seccomp=unconfined",
                       "--security-opt=apparmor=unconfined", "--cgroupns=host", "--add-host", "--env-file", "--publish", "-p")


def image_is_pinned(image: str) -> bool:
    return bool(isinstance(image, str) and PINNED_RE.match(image))


def forbidden_mount_source(path: Path) -> str | None:
    """Reason a path must never be mounted into a verification container, or None."""
    try:
        st = os.lstat(path)
    except OSError:
        return "mount source does not exist"
    if stat.S_ISLNK(st.st_mode):
        return "mount source is a symlink"
    if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
        return "mount source is a socket, device or FIFO"
    real = os.path.realpath(path)
    if real.endswith(".sock") or "docker.sock" in real or Path(real) == Path(real).parent or real in {"/var/run", "/run"}:
        return "mount source exposes a daemon socket or the host root"
    if any(character in real for character in ',="\r\n'):
        return "mount source contains characters that would alter the --mount option"
    return None


def container_flags(name: str, job: str, runtime: str | None = None) -> list[str]:
    return ([f"--runtime={runtime}"] if runtime else []) + [
        "--rm", "--pull=never", f"--name={name}", f"--label=trustdiff.job={job}", "--network=none", "--read-only",
        "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=512m", "--memory-swap=512m",
        "--cpus=1", "--user=65534:65534", "--ipc=none", "--ulimit=nofile=256:256", "--ulimit=fsize=67108864", "--ulimit=core=0",
        "--stop-timeout=1", "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m", "--workdir=/workspace",
        "--env=PYTHONDONTWRITEBYTECODE=1", "--env=PYTHONPATH=/workspace", "--env=HOME=/tmp",
    ]


def build_argv(docker: str, name: str, job: str, workspace: Path, image: str, command: list[str], challenge: Path | None = None, runtime: str | None = None) -> list[str]:
    if runtime is not None and runtime not in ALLOWED_RUNTIMES:
        raise ValueError(f"runtime {runtime!r} is not an allowed isolation runtime")
    for source in [workspace] + ([challenge] if challenge else []):
        problem = forbidden_mount_source(source)
        if problem:
            raise ValueError(f"{problem}: {source}")
    argv = [docker, "run", *container_flags(name, job, runtime), "--mount", f"type=bind,src={os.path.realpath(workspace)},dst=/workspace,readonly"]
    if challenge is not None:
        argv += ["--mount", f"type=bind,src={os.path.realpath(challenge)},dst=/trustdiff-challenge.py,readonly"]
    bad = [a for a in argv if a in FORBIDDEN_RUN_FLAGS or "docker.sock" in a]
    if bad:
        raise ValueError("refusing unsafe container flag: " + bad[0])
    return argv + [image, *command]


def lfs_pointer(blob: bytes) -> tuple[str, int] | None:
    if not blob.startswith(LFS_HEADER):
        return None
    match = LFS_POINTER.fullmatch(blob)
    if match is None:
        raise ValueError("unsupported or malformed Git LFS pointer")
    return match[1].decode("ascii"), int(match[2])


def clean_candidate(root: Path, state: Path) -> bool | None:
    """Check Git status without filters and recognize verified hydrated LFS content."""
    if root == state:
        return None
    rc, index, _ = safe.run_git_bytes(root, "ls-files", "-v", "-z")
    if rc:
        return None
    if any(record[:1] == b"S" or record[:1].islower() for record in index.split(b"\0") if record):
        return False  # Skip-worktree and assume-unchanged can conceal modifications from status.
    paths = ["."]
    if state.resolve().is_relative_to(root.resolve()):
        paths.append(":(exclude,literal)" + state.resolve().relative_to(root.resolve()).as_posix())
    args = ["status", "--porcelain=v1", "-z", "--no-renames", "--untracked-files=all", "--ignore-submodules=dirty", "--", *paths]
    rc, output, _ = safe.run_git_bytes(root, *args)
    if rc:
        return None
    for record in output.split(b"\0"):
        if not record:
            continue
        name = safe.git_path(record[3:])
        if not record.startswith(b" M ") or not _portable_path(name):
            return False
        rc, blob, _ = safe.run_git_bytes(root, "show", f"HEAD:{name}", max_output=1024)
        if rc:
            return False
        try:
            pointer = lfs_pointer(blob)
            local = root / name
            if pointer is None or not safe.is_regular_file(local) or local.resolve() != local.absolute():
                return False
            oid, size = pointer
            if local.stat().st_size != size or safe.regular_file_sha256(local, limit=MAX_SNAPSHOT_BYTES)[0] != oid:
                return False
        except (OSError, ValueError):
            return False
    return True


def _copy_lfs(cache: Path, pointer: tuple[str, int], path: Path) -> None:
    oid, size = pointer
    source = cache / oid[:2] / oid[2:4] / oid
    if not safe.is_regular_file(source) or source.resolve() != source:
        raise ValueError(f"Git LFS object missing from approved local cache: {oid}")
    digest = hashlib.sha256()
    remaining = size
    with source.open("rb") as reader, path.open("xb") as writer:
        while remaining:
            chunk = reader.read(min(remaining, 1024 * 1024))
            if not chunk:
                break
            remaining -= len(chunk)
            digest.update(chunk)
            writer.write(chunk)
        if remaining or reader.read(1) or digest.hexdigest() != oid:
            raise ValueError(f"Git LFS object failed size or SHA-256 validation: {oid}")


def _portable_path(path: str) -> bool:
    names = path.split("/")
    return safe.clean_repo_path(path) and all(
        name.casefold() not in {".git", ".trustdiff"} and not name.endswith((" ", "."))
        and not any(char in name for char in ':<>|?*"')
        and name.split(".", 1)[0].rstrip().casefold() not in WINDOWS_DEVICES for name in names
    )


def _blob_batches(entries):
    batch, size = [], 0
    for entry in entries:
        if batch and size + entry[2] > MAX_BLOB_BYTES:
            yield batch, size
            batch, size = [], 0
        batch.append(entry)
        size += entry[2]
    if batch:
        yield batch, size


def export_snapshot(root: Path, commit: str, dest: Path, lfs_cache: Path | None = None) -> None:
    """Materialise regular committed blobs without checkout filters, hooks or export attributes."""
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}|HEAD", commit):
        raise ValueError("snapshot commit must be a full object id or HEAD")
    rc, listing, err = safe.run_git_bytes(root, "ls-tree", "-r", "-l", "-z", "--full-tree", commit, max_output=64 * 1024 * 1024)
    if rc:
        raise RuntimeError("cannot list tree: " + err.strip()[:200])
    total = 0
    entries = []
    names: dict[str, str] = {}
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        meta, raw_path = entry.split(b"\t", 1)
        mode, kind, oid, raw_size = meta.split()
        path = safe.git_path(raw_path)
        if kind != b"blob" or mode not in (b"100644", b"100755") or not _portable_path(path):
            raise ValueError(f"unsupported snapshot path or Git entry: {path!r}")
        for parent in PurePosixPath(path).parents:
            if parent == PurePosixPath("."):
                break
            name = parent.as_posix()
            if names.setdefault(name.casefold(), name) != name:
                raise ValueError(f"case-colliding snapshot path: {name!r}")
        if names.setdefault(path.casefold(), path) != path:
            raise ValueError(f"case-colliding snapshot path: {path!r}")
        size = int(raw_size)
        if size > MAX_BLOB_BYTES:
            raise ValueError(f"committed file exceeds {MAX_BLOB_BYTES} bytes: {path!r}")
        total += size
        entries.append((mode, oid, size, path))
        if len(entries) > MAX_SNAPSHOT_FILES or total > MAX_SNAPSHOT_BYTES:
            raise ValueError(f"snapshot exceeds limits ({MAX_SNAPSHOT_FILES} files / {MAX_SNAPSHOT_BYTES} bytes)")
    dest.mkdir(parents=True, exist_ok=False)
    os.chmod(dest, 0o755)
    if lfs_cache is not None:
        lfs_cache = lfs_cache.absolute()
        if lfs_cache.resolve() != lfs_cache or lfs_cache.is_relative_to(root.resolve()):
            raise ValueError("Git LFS cache must be a direct path outside the candidate repository")
    for batch, size in _blob_batches(entries):
        requests = b"".join(oid + b"\n" for _, oid, _, _ in batch)
        result = safe.bounded_run(["git", *safe.GIT_HARDENING, "cat-file", "--batch"], cwd=root, env=safe.git_env(),
                                  timeout=60, max_output=size + 100 * len(batch), stdin_data=requests)
        if result.rc:
            raise RuntimeError("cannot read committed blobs: " + result.stderr.decode("utf-8", "replace")[:200])
        cursor = 0
        for mode, oid, blob_size, name in batch:
            header = oid + b" blob " + str(blob_size).encode("ascii") + b"\n"
            start = cursor + len(header)
            end = start + blob_size
            if result.stdout[cursor:start] != header or result.stdout[end:end + 1] != b"\n":
                raise RuntimeError("Git returned an invalid blob batch")
            cursor = end + 1
            blob = result.stdout[start:end]
            path = dest / name
            path.parent.mkdir(parents=True, exist_ok=True)
            pointer = lfs_pointer(blob)
            if pointer is None:
                with path.open("xb") as handle:
                    handle.write(blob)
            else:
                if lfs_cache is None:
                    raise ValueError(f"Git LFS content required for {name!r}; supply --lfs-cache")
                total += pointer[1] - blob_size
                if total > MAX_SNAPSHOT_BYTES:
                    raise ValueError("hydrated snapshot exceeds the byte limit")
                _copy_lfs(lfs_cache, pointer, path)
            os.chmod(path, 0o755 if mode == b"100755" else 0o644)
        if cursor != len(result.stdout):
            raise RuntimeError("Git returned trailing data in the blob batch")
    if os.name == "posix":
        for directory, _, _ in os.walk(dest):
            os.chmod(directory, 0o755)


def _docker_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k.upper() in _DOCKER_ENV_KEYS}


def _cleanup(docker: str, name: str, job: str, env: dict[str, str]) -> str:
    """Kill and remove the job's container; return a warning when something may still be running."""
    safe.bounded_run([docker, "kill", name], env=env, timeout=20, max_output=4096)
    safe.bounded_run([docker, "rm", "-f", name], env=env, timeout=30, max_output=4096)
    query = [docker, "ps", "-aq", "--filter", f"label=trustdiff.job={job}"]
    listing = safe.bounded_run(query, env=env, timeout=20, max_output=65536)
    leftover = [x for x in listing.stdout.decode("utf-8", "replace").split() if re.fullmatch(r"[0-9a-f]{6,64}", x)]
    for cid in leftover:
        safe.bounded_run([docker, "rm", "-f", cid], env=env, timeout=30, max_output=4096)
    if leftover and safe.bounded_run(query, env=env, timeout=20, max_output=65536).stdout.strip():
        return f"WARNING: container for job {job} may still be running; remove it manually (docker rm -f {name})"
    return ""


def run_docker(command: list[str], root: Path, image: str, timeout: int, challenge_script: Path | None = None,
               commit: str | None = None, docker: str = "docker", runtime: str | None = None,
               lfs_cache: Path | None = None) -> tuple[int, str, str]:
    if not image or not IMAGE_RE.fullmatch(image):
        return 127, "", "Docker image reference is missing or malformed"
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 600:
        return 127, "", "Timeout must be between 1 and 600 seconds"
    if not isinstance(command, list) or not command or len(command) > 64 or any(not isinstance(c, str) or "\0" in c or len(c) > 4096 for c in command):
        return 127, "", "Command must be a non-empty array of at most 64 strings"
    if runtime is not None:
        if runtime not in ALLOWED_RUNTIMES:
            return 127, "", f"Runtime {runtime!r} is not an allowed isolation runtime ({', '.join(sorted(ALLOWED_RUNTIMES))})"
        if not runtime_available(docker, runtime):
            return 127, "", f"Isolation runtime {runtime!r} is not registered with the Docker daemon; refusing to fall back to the default runtime"
    job = uuid.uuid4().hex[:16]
    name = f"trustdiff-{job}"
    env = _docker_env()
    workdir = Path(tempfile.mkdtemp(prefix="trustdiff-job-"))
    needs_cleanup = False
    try:
        os.chmod(workdir, 0o755)
        try:
            export_snapshot(Path(root), commit or "HEAD", workdir / "workspace", lfs_cache)
        except (RuntimeError, ValueError, OSError) as exc:
            return 127, "", f"Workspace snapshot failed: {exc}"
        challenge = None
        if challenge_script is not None:
            source = Path(challenge_script)
            if not safe.is_regular_file(source) or source.stat().st_size > 1_000_000:
                return 127, "", "Challenge script must be a regular file under 1 MB"
            challenge = workdir / "trustdiff-challenge.py"
            shutil.copyfile(source, challenge)     # copy a verifier-owned script before mounting it
            os.chmod(challenge, 0o444)
        try:
            argv = build_argv(docker, name, job, workdir / "workspace", image, command, challenge, runtime)
        except ValueError as exc:
            return 127, "", f"Runner refused unsafe configuration: {exc}"
        needs_cleanup = True
        result = safe.bounded_run(argv, env=env, timeout=timeout + STARTUP_SLACK, max_output=1024 * 1024, tail=True)
        out = result.stdout.decode("utf-8", "replace")[-LOG_CHARS:]
        err = result.stderr.decode("utf-8", "replace")[-LOG_CHARS:]
        if result.timed_out:
            return 124, out, f"Docker runner exceeded timeout {timeout + STARTUP_SLACK}s; container killed"
        if result.truncated:
            return safe.RC_OVERFLOW, out, "Test output exceeded the runner limit; container killed"
        needs_cleanup = result.rc in (125, 126, 127) or result.rc < 0   # docker itself failed or was signalled
        return result.rc, out, err
    finally:
        warning = _cleanup(docker, name, job, env) if needs_cleanup else ""
        shutil.rmtree(workdir, ignore_errors=True)
        if warning:
            print(warning, file=sys.stderr)
