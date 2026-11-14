"""P0-03: runner isolation, cleanup and resource limits.

Most tests use a FAKE `docker` executable that records every invocation, so the host-side behaviour
(snapshot contents, kill-by-name on timeout, output limits, argv hardening) is tested exactly.
That is NOT a substitute for the real-Docker tests below, which only run where Docker and an image exist
(the repository CI job `docker-integration` provides both).
"""
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock
from support import symlink_or_skip

import trustdiff_runner as R
import trustdiff_safe as S

REAL_DOCKER = shutil.which("docker")
REAL_IMAGE = os.environ.get("TRUSTDIFF_TEST_IMAGE", "")


def sh(*args, cwd, **kw):
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=True, **kw)


def make_repo(base: Path) -> tuple[Path, str]:
    repo = base / "repo"; repo.mkdir()
    sh("git", "init", "-q", "-b", "main", cwd=repo)
    (repo / "app.py").write_text("print('hi')\n")
    (repo / "tests").mkdir(); (repo / "tests" / "test_app.py").write_text("assert True\n")
    (repo / ".gitattributes").write_text("tests/test_app.py export-ignore\n")
    sh("git", "add", "-A", cwd=repo)
    sh("git", "-c", "user.name=T", "-c", "user.email=t@x.invalid", "commit", "-qm", "c", cwd=repo)
    head = sh("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()
    (repo / ".env").write_text("TOKEN=super-secret\n")                       # untracked secret
    (repo / ".trustdiff").mkdir(); (repo / ".trustdiff" / "ledger.jsonl").write_text("{}\n")
    (repo / "app.py").write_text("print('UNCOMMITTED EDIT')\n")             # worktree differs from commit
    return repo, head


FAKE_DOCKER = textwrap.dedent('''\
    #!/usr/bin/env python3
    import json, os, sys, time
    conf = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake.json")))
    log = conf["log"]
    with open(log, "a") as f: f.write(json.dumps(sys.argv[1:]) + "\\n")
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    mode = conf.get("mode", "ok")
    if cmd == "run":
        if mode == "hang": time.sleep(120)
        elif mode == "flood":
            while True: sys.stdout.write("A" * 65536); sys.stdout.flush()
        else: print("ran ok")
    elif cmd == "info":
        print(json.dumps(conf.get("runtimes", {"runc": {}})))
    elif cmd == "ps":
        if conf.get("leftover"): print("deadbeef0123")
''')


class FakeDockerCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(); self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name).resolve()
        self.repo, self.head = make_repo(self.base)
        self.fake = self.base / "docker.py"; self.fake.write_text(FAKE_DOCKER)
        original_run = S.bounded_run

        def portable_fake(argv, **kwargs):
            if argv[0] == str(self.fake):
                argv = [sys.executable, str(self.fake), *argv[1:]]
            return original_run(argv, **kwargs)

        patcher = mock.patch.object(S, "bounded_run", side_effect=portable_fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.log = self.base / "docker.log"
        self.configure()
        old = R.STARTUP_SLACK; R.STARTUP_SLACK = 1
        self.addCleanup(setattr, R, "STARTUP_SLACK", old)

    def configure(self, **conf):
        (self.base / "fake.json").write_text(json.dumps({"log": str(self.log), **conf}))

    def calls(self):
        return [json.loads(l) for l in self.log.read_text().splitlines()] if self.log.exists() else []

    def run_job(self, timeout=10, **kw):
        return R.run_docker(["python3", "-m", "unittest"], self.repo, "python@sha256:" + "a" * 64, timeout, commit=self.head, docker=str(self.fake), **kw)



class SnapshotTests(FakeDockerCase):
    def test_snapshot_is_exactly_the_tracked_commit(self):
        dest = self.base / "snap" / "workspace"; dest.parent.mkdir()
        R.export_snapshot(self.repo, self.head, dest)
        names = {p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file()}
        self.assertIn("app.py", names)
        self.assertEqual((dest / "app.py").read_text(), "print('hi')\n")                       # the COMMIT, not the dirty worktree
        self.assertIn("tests/test_app.py", names)                                              # export-ignore cannot drop tests
        self.assertFalse({".env", ".trustdiff/ledger.jsonl"} & names)                          # untracked secrets and state are absent
        self.assertFalse(any(n.startswith(".git/") or n == ".git" for n in names))
        if os.name == "posix":
            self.assertTrue(os.stat(dest / "app.py").st_mode & stat.S_IROTH)
            self.assertFalse(os.stat(dest / "app.py").st_mode & stat.S_IWOTH)

    def test_snapshot_uses_the_requested_commit_not_head(self):
        (self.repo / "app.py").write_text("print('second commit')\n")
        sh("git", "add", "app.py", cwd=self.repo)
        sh("git", "-c", "user.name=T", "-c", "user.email=t@x.invalid", "commit", "-qm", "second", cwd=self.repo)
        dest = self.base / "snap2" / "workspace"; dest.parent.mkdir()
        R.export_snapshot(self.repo, self.head, dest)                      # the FIRST commit, while HEAD is the second
        self.assertEqual((dest / "app.py").read_text(), "print('hi')\n")
        dest2 = self.base / "snap3" / "workspace"; dest2.parent.mkdir()
        R.export_snapshot(self.repo, "HEAD", dest2)
        self.assertEqual((dest2 / "app.py").read_text(), "print('second commit')\n")

    def test_snapshot_rejects_bad_commit_argument(self):
        for bad in ("--output=/tmp/x", "main", "HEAD~1", "x" * 40, ""):
            with self.subTest(bad), self.assertRaises(ValueError):
                R.export_snapshot(self.repo, bad, self.base / "s" / "w")

    def test_workspace_contains_no_secret_when_container_would_run(self):
        seen = {}
        original = R.build_argv
        def spy(docker, name, job, workspace, image, command, challenge=None, runtime=None):
            seen["files"] = {p.relative_to(workspace).as_posix() for p in Path(workspace).rglob("*") if p.is_file()}
            return original(docker, name, job, workspace, image, command, challenge, runtime)
        R.build_argv = spy
        try:
            self.run_job()
        finally:
            R.build_argv = original
        self.assertIn("app.py", seen["files"]); self.assertNotIn(".env", seen["files"])


class ArgvTests(FakeDockerCase):
    def test_argv_has_required_flags_and_no_escape_flags(self):
        ws = self.base / "ws"; ws.mkdir()
        argv = R.build_argv("docker", "trustdiff-a", "a", ws, "img@sha256:" + "b" * 64, ["true"])
        head = argv[: argv.index("img@sha256:" + "b" * 64)]
        for needed in ("--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pull=never", "--user=65534:65534", "--ipc=none"):
            self.assertIn(needed, head)
        for forbidden in R.FORBIDDEN_RUN_FLAGS:
            self.assertNotIn(forbidden, head)
        self.assertFalse(any("docker.sock" in a for a in argv))
        self.assertEqual(sum(1 for a in argv if a == "--mount"), 1)
        self.assertIn("readonly", argv[argv.index("--mount") + 1])
        self.assertTrue(any(a.startswith("--name=trustdiff-") for a in head))

    def test_mount_sources_that_expose_the_host_are_refused(self):
        special = []
        if os.name == "posix":
            sock = self.base / "s.sock"
            server = socket.socket(socket.AF_UNIX); server.bind(str(sock)); self.addCleanup(server.close)
            fifo = self.base / "fifo"; os.mkfifo(fifo)
            special.extend([sock, fifo])
        comma = self.base / "a,b"; comma.mkdir()
        named_file = self.base / "docker.sock"; named_file.write_text("not a real socket, but must never be mounted")
        named_dir = self.base / "sub"; named_dir.mkdir(); (named_dir / "docker.sock").mkdir()
        for path in (*special, comma, named_file, named_dir / "docker.sock", Path("/var/run/docker.sock"), self.base / "missing"):
            with self.subTest(path=str(path)):
                self.assertIsNotNone(R.forbidden_mount_source(path))
        self.assertIsNone(R.forbidden_mount_source(self.base))

    def test_symlink_mount_is_refused(self):
        link = self.base / "link"
        symlink_or_skip(self, self.base, link, directory=True)
        self.assertIsNotNone(R.forbidden_mount_source(link))

    def test_challenge_script_is_copied_before_mount(self):
        script = self.base / "gen.py"; script.write_text("print(1)\n")
        self.run_job(challenge_script=script)
        run = next(c for c in self.calls() if c[0] == "run")
        mount = [a for a in run if "trustdiff-challenge.py" in a][0]
        self.assertNotIn(str(script), mount)                                                  # mounts the private copy, not the agent-writable path

    def test_non_regular_challenge_is_refused(self):
        directory = self.base / "f"; directory.mkdir()
        rc, _, err = self.run_job(challenge_script=directory)
        self.assertEqual(rc, 127); self.assertEqual([c for c in self.calls() if c[0] == "run"], [])

    def test_input_validation(self):
        img = "python@sha256:" + "a" * 64
        self.assertEqual(R.run_docker(["x"], self.repo, "bad image;rm", 5, docker=str(self.fake))[0], 127)
        for t in (0, 601, -1, True, "5", None):
            self.assertEqual(R.run_docker(["x"], self.repo, img, t, docker=str(self.fake))[0], 127)
        for cmd in ([], "python", ["a\0b"], ["x"] * 65, [1]):
            self.assertEqual(R.run_docker(cmd, self.repo, img, 5, docker=str(self.fake))[0], 127)

    def test_image_pinning_helper(self):
        self.assertTrue(R.image_is_pinned("python@sha256:" + "a" * 64))
        for bad in ("python:3.11-slim", "python@sha256:abc", "python@sha256:" + "A" * 64, "", None):
            self.assertFalse(R.image_is_pinned(bad))


class IsolationRuntimeTests(FakeDockerCase):
    def setUp(self):
        super().setUp(); R._RUNTIME_CACHE.clear(); self.addCleanup(R._RUNTIME_CACHE.clear)

    def test_microvm_and_gvisor_runtimes_are_passed_through_when_registered(self):
        self.configure(runtimes={"runc": {}, "runsc": {}, "io.containerd.kata.v2": {}})
        for runtime in ("runsc", "io.containerd.kata.v2"):
            self.log.unlink(missing_ok=True)
            rc, out, _ = self.run_job(runtime=runtime)
            self.assertEqual(rc, 0, runtime)
            run = next(c for c in self.calls() if c[0] == "run")
            self.assertIn(f"--runtime={runtime}", run)
            for needed in ("--network=none", "--read-only", "--cap-drop=ALL"):       # the same constraints still apply
                self.assertIn(needed, run)

    def test_missing_runtime_fails_closed_without_falling_back_to_runc(self):
        self.configure(runtimes={"runc": {}})
        rc, _, err = self.run_job(runtime="runsc")
        self.assertEqual(rc, 127); self.assertIn("refusing to fall back", err)
        self.assertEqual([c for c in self.calls() if c[0] == "run"], [])

    def test_only_allowlisted_runtimes_are_accepted(self):
        self.configure(runtimes={"runc": {}, "evil": {}})
        for runtime in ("evil", "runc", "runsc --privileged", "", "host"):
            rc, _, err = self.run_job(runtime=runtime)
            self.assertEqual(rc, 127, runtime)
        self.assertEqual([c for c in self.calls() if c[0] == "run"], [])
        with self.assertRaises(ValueError):
            R.build_argv("docker", "n", "j", self.base, "img@sha256:" + "a" * 64, ["x"], runtime="runc")

    def test_isolation_class_names(self):
        self.assertEqual(R.isolation_class(None), "docker-container")
        self.assertEqual(R.isolation_class("runsc"), "gvisor-userspace-kernel")
        self.assertEqual(R.isolation_class("io.containerd.kata.v2"), "microvm")

    def test_cli_rejects_unknown_runtime(self):
        p = subprocess.run([sys.executable, str(Path(R.__file__).with_name("trustdiff.py")), "check", "--baseline", "HEAD", "--runtime", "runc"], cwd=self.repo, capture_output=True, text=True)
        self.assertEqual(p.returncode, 2); self.assertIn("invalid choice", p.stderr)


class CleanupTests(FakeDockerCase):
    def test_timeout_kills_the_container_by_name_and_sweeps_by_label(self):
        self.configure(mode="hang")
        t = time.time(); rc, _, err = self.run_job(timeout=1)
        self.assertEqual(rc, 124); self.assertIn("container killed", err); self.assertLess(time.time() - t, 30)
        calls = self.calls()
        run = next(c for c in calls if c[0] == "run")
        name = next(a for a in run if a.startswith("--name=")).split("=", 1)[1]
        self.assertIn(["kill", name], calls); self.assertIn(["rm", "-f", name], calls)
        self.assertTrue(any(c[0] == "ps" and f"label=trustdiff.job={name.split('-', 1)[1]}" in c for c in calls))

    def test_output_flood_is_bounded_and_kills_the_container(self):
        self.configure(mode="flood")
        t = time.time(); rc, out, err = self.run_job(timeout=60)
        self.assertEqual(rc, S.RC_OVERFLOW); self.assertLess(len(out), 20000); self.assertLess(time.time() - t, 30)
        self.assertTrue(any(c[0] == "kill" for c in self.calls()))

    def test_workspace_is_deleted_even_after_failure(self):
        self.configure(mode="hang")
        before = {p.name for p in Path(tempfile.gettempdir()).glob("trustdiff-job-*")}
        self.run_job(timeout=1)
        self.assertEqual({p.name for p in Path(tempfile.gettempdir()).glob("trustdiff-job-*")} - before, set())

    def test_leftover_container_is_reported_not_hidden(self):
        self.configure(mode="hang", leftover=True)
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            self.run_job(timeout=1)
        self.assertIn("may still be running", buf.getvalue())

    def test_each_job_gets_a_unique_identity(self):
        self.run_job(); self.run_job()
        names = [next(a for a in c if a.startswith("--name=")) for c in self.calls() if c[0] == "run"]
        self.assertEqual(len(set(names)), 2)


class BoundedRunTests(unittest.TestCase):
    def test_strict_overflow_kills_and_flags(self):
        r = S.bounded_run([sys.executable, "-c", "import sys\nwhile True: sys.stdout.write('A'*100000)"], max_output=500_000, timeout=20)
        self.assertTrue(r.truncated); self.assertEqual(r.rc, S.RC_OVERFLOW); self.assertLessEqual(len(r.stdout), 500_000)

    def test_tail_keeps_the_end(self):
        r = S.bounded_run([sys.executable, "-c", "print('x'*3000000); print('FINAL-LINE')"], max_output=1000, tail=True, timeout=20)
        self.assertEqual(r.rc, 0); self.assertTrue(r.stdout.replace(b"\r\n", b"\n").endswith(b"FINAL-LINE\n")); self.assertEqual(len(r.stdout), 1000)

    def test_timeout_kills_grandchildren(self):
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "alive"
            child = f"import time; from pathlib import Path; time.sleep(3); Path({str(marker)!r}).touch()"
            parent = f"import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', {child!r}]); time.sleep(60)"
            r = S.bounded_run([sys.executable, "-c", parent], timeout=1)
            time.sleep(3)
            self.assertTrue(r.timed_out); self.assertEqual(r.rc, S.RC_TIMEOUT); self.assertFalse(marker.exists())

    def test_missing_binary_is_reported_not_raised(self):
        self.assertEqual(S.bounded_run(["definitely-not-a-binary-xyz"]).rc, S.RC_UNAVAILABLE)


@unittest.skipUnless(REAL_DOCKER and REAL_IMAGE and os.environ.get("TRUSTDIFF_TEST_RUNTIME"), "needs Docker, TRUSTDIFF_TEST_IMAGE and a registered TRUSTDIFF_TEST_RUNTIME (runsc or kata)")
class RealIsolationRuntimeTests(unittest.TestCase):
    def test_workload_runs_under_the_stronger_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, head = make_repo(Path(tmp).resolve())
            rc, out, err = R.run_docker(["python3", "-c", "print(open('/proc/version').read())"], repo, REAL_IMAGE, 60, commit=head, runtime=os.environ["TRUSTDIFF_TEST_RUNTIME"])
            self.assertEqual(rc, 0, err)


@unittest.skipUnless(REAL_DOCKER and REAL_IMAGE, "needs Docker and TRUSTDIFF_TEST_IMAGE (digest-pinned image present locally); provided by the docker-integration CI job")
class RealDockerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(); self.addCleanup(self._tmp.cleanup)
        self.repo, self.head = make_repo(Path(self._tmp.name).resolve())

    def probe(self, code, timeout=30):
        return R.run_docker(["python3", "-c", code], self.repo, REAL_IMAGE, timeout, commit=self.head)

    def test_network_is_disabled(self):
        rc, out, _ = self.probe("import socket\ntry:\n    socket.create_connection(('1.1.1.1', 53), 3); print('NETWORK')\nexcept OSError: print('BLOCKED')")
        self.assertEqual(rc, 0); self.assertIn("BLOCKED", out)

    def test_workspace_is_read_only_and_clean(self):
        rc, out, _ = self.probe("import os\nprint(sorted(os.listdir('/workspace')))\ntry:\n    open('/workspace/x','w'); print('WRITABLE')\nexcept OSError: print('RO')")
        self.assertIn("RO", out); self.assertNotIn(".env", out); self.assertNotIn(".git'", out); self.assertNotIn(".trustdiff", out)

    def test_docker_socket_and_devices_absent(self):
        rc, out, _ = self.probe("import os\nprint(os.path.exists('/var/run/docker.sock'), os.path.exists('/run/docker.sock'))")
        self.assertIn("False False", out)

    def test_runs_as_unprivileged_user_without_capabilities(self):
        rc, out, _ = self.probe("import os\nprint(os.getuid()); print(open('/proc/self/status').read().split('CapEff:')[1].split()[0])")
        self.assertTrue(out.split()[0] == "65534" and out.split()[1] == "0000000000000000")

    def test_host_secret_env_is_not_inherited(self):
        os.environ["TRUSTDIFF_TEST_SECRET"] = "leak"
        self.addCleanup(os.environ.pop, "TRUSTDIFF_TEST_SECRET", None)
        _, out, _ = self.probe("import os\nprint('LEAK' if 'TRUSTDIFF_TEST_SECRET' in os.environ else 'CLEAN')")
        self.assertIn("CLEAN", out)

    def test_timeout_removes_container_and_processes(self):
        before = subprocess.run([REAL_DOCKER, "ps", "-aq", "--filter", "label=trustdiff.job"], capture_output=True, text=True).stdout.split()
        old = R.STARTUP_SLACK; R.STARTUP_SLACK = 2
        try:
            rc, _, err = self.probe("import time\ntime.sleep(300)", timeout=2)
        finally:
            R.STARTUP_SLACK = old
        self.assertEqual(rc, 124)
        after = subprocess.run([REAL_DOCKER, "ps", "-aq", "--filter", "label=trustdiff.job"], capture_output=True, text=True).stdout.split()
        self.assertEqual(set(after) - set(before), set())

    def test_fork_bomb_is_contained_by_pids_limit(self):
        rc, out, _ = self.probe("import os\nn=0\nfor _ in range(500):\n    try:\n        if os.fork()==0:\n            import time; time.sleep(20); os._exit(0)\n        n+=1\n    except OSError:\n        break\nprint('forks', n)", timeout=30)
        self.assertLess(int(out.split()[-1]), 200)


if __name__ == "__main__":
    unittest.main()
