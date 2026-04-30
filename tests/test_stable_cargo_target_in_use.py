"""
Tests for _stable_cargo_target_in_use and _is_cargo_build_process.

We simulate /proc by building a temporary directory tree that mirrors the
subset of /proc/<pid>/{comm,exe,cwd,environ} that the functions read.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Allow importing from the project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from loop import _is_cargo_build_process, _stable_cargo_target_in_use, _path_within_tree


def _make_fake_proc_entry(
    proc_root: Path,
    pid: int,
    *,
    comm: str = "",
    exe: str = "",
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> Path:
    """Create a fake /proc/<pid> directory with the requested files."""
    pid_dir = proc_root / str(pid)
    pid_dir.mkdir(parents=True, exist_ok=True)

    if comm:
        (pid_dir / "comm").write_text(comm + "\n")

    if exe:
        exe_link = pid_dir / "exe"
        try:
            exe_link.symlink_to(exe)
        except FileExistsError:
            pass

    if cwd is not None:
        cwd_link = pid_dir / "cwd"
        try:
            cwd_link.symlink_to(cwd)
        except FileExistsError:
            pass

    if env is not None:
        raw = b"\0".join(f"{k}={v}".encode() for k, v in env.items()) + b"\0"
        (pid_dir / "environ").write_bytes(raw)
    else:
        (pid_dir / "environ").write_bytes(b"")

    return pid_dir


class TestIsCargoBuildProcess(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.proc_root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_cargo_comm_detected(self):
        pid_dir = _make_fake_proc_entry(self.proc_root, 1, comm="cargo")
        self.assertTrue(_is_cargo_build_process(pid_dir))

    def test_rustc_comm_detected(self):
        pid_dir = _make_fake_proc_entry(self.proc_root, 2, comm="rustc")
        self.assertTrue(_is_cargo_build_process(pid_dir))

    def test_nextest_comm_detected(self):
        pid_dir = _make_fake_proc_entry(self.proc_root, 3, comm="nextest")
        self.assertTrue(_is_cargo_build_process(pid_dir))

    def test_build_script_truncated_comm_detected(self):
        # build-script-build truncates to 15 chars in /proc/comm
        pid_dir = _make_fake_proc_entry(self.proc_root, 4, comm="build-script-bui")
        self.assertTrue(_is_cargo_build_process(pid_dir))

    def test_shell_not_detected(self):
        pid_dir = _make_fake_proc_entry(self.proc_root, 5, comm="bash")
        self.assertFalse(_is_cargo_build_process(pid_dir))

    def test_editor_not_detected(self):
        pid_dir = _make_fake_proc_entry(self.proc_root, 6, comm="vim")
        self.assertFalse(_is_cargo_build_process(pid_dir))

    def test_test_binary_not_detected(self):
        pid_dir = _make_fake_proc_entry(self.proc_root, 7, comm="teamserver-tests")
        self.assertFalse(_is_cargo_build_process(pid_dir))

    def test_find_not_detected(self):
        pid_dir = _make_fake_proc_entry(self.proc_root, 8, comm="find")
        self.assertFalse(_is_cargo_build_process(pid_dir))

    def test_missing_comm_no_exe_returns_false(self):
        pid_dir = self.proc_root / "99"
        pid_dir.mkdir()
        self.assertFalse(_is_cargo_build_process(pid_dir))


class TestStableCargoTargetInUse(unittest.TestCase):
    """
    _stable_cargo_target_in_use accepts an optional _proc_root parameter;
    tests inject a temporary directory to simulate /proc without touching
    the real filesystem.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.target_dir = self.tmp / "red-cell-target-abc123" / "debug"
        self.target_dir.mkdir(parents=True)
        self.proc_root = self.tmp / "proc"
        self.proc_root.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self) -> bool:
        """Run _stable_cargo_target_in_use with the fake proc tree injected."""
        import loop
        return loop._stable_cargo_target_in_use(self.target_dir, _proc_root=self.proc_root)

    # --- CWD-based tests ---

    def test_cargo_cwd_inside_target_blocks(self):
        """cargo process with CWD inside target → must block."""
        _make_fake_proc_entry(
            self.proc_root, 10,
            comm="cargo",
            cwd=self.target_dir,
        )
        self.assertTrue(self._run())

    def test_shell_cwd_inside_target_does_not_block(self):
        """Shell process with CWD inside target → must NOT block (regression fix)."""
        _make_fake_proc_entry(
            self.proc_root, 11,
            comm="bash",
            cwd=self.target_dir,
        )
        self.assertFalse(self._run())

    def test_editor_cwd_inside_target_does_not_block(self):
        """Editor process with CWD inside target → must NOT block."""
        _make_fake_proc_entry(
            self.proc_root, 12,
            comm="vim",
            cwd=self.target_dir,
        )
        self.assertFalse(self._run())

    def test_find_cwd_inside_target_does_not_block(self):
        """find process with CWD inside target → must NOT block."""
        _make_fake_proc_entry(
            self.proc_root, 13,
            comm="find",
            cwd=self.target_dir,
        )
        self.assertFalse(self._run())

    # --- nextest double-spawn scenario (red-cell-c2-sl2cm repro) ---

    def test_nextest_process_with_cargo_target_env_blocks(self):
        """
        cargo nextest holds CARGO_TARGET_DIR in its env and is a cargo build process.
        Cleanup must be deferred while it is alive — even after .cargo-lock is released.
        """
        _make_fake_proc_entry(
            self.proc_root, 20,
            comm="cargo",
            env={"CARGO_TARGET_DIR": str(self.target_dir)},
        )
        self.assertTrue(self._run())

    def test_test_binary_cwd_inside_target_does_not_block(self):
        """
        nextest-spawned test binary has CWD inside target dir but is NOT a cargo tool.
        Must NOT block on its own — the parent cargo nextest process will block instead.
        """
        _make_fake_proc_entry(
            self.proc_root, 21,
            comm="teamserver-tests",
            cwd=self.target_dir,
        )
        self.assertFalse(self._run())

    def test_test_binary_plus_cargo_parent_blocks(self):
        """
        When both a test binary (non-cargo) and the cargo nextest process coexist,
        cleanup must still be deferred because the cargo process is present.
        """
        # test binary: non-cargo, CWD inside target
        _make_fake_proc_entry(
            self.proc_root, 30,
            comm="teamserver-tests",
            cwd=self.target_dir,
        )
        # cargo nextest: cargo binary, CARGO_TARGET_DIR pointing to target
        _make_fake_proc_entry(
            self.proc_root, 31,
            comm="cargo",
            env={"CARGO_TARGET_DIR": str(self.target_dir)},
        )
        self.assertTrue(self._run())

    # --- env-based tests ---

    def test_shell_with_cargo_target_env_does_not_block(self):
        """
        A shell that inherited CARGO_TARGET_DIR must NOT block cleanup.
        """
        _make_fake_proc_entry(
            self.proc_root, 40,
            comm="bash",
            env={"CARGO_TARGET_DIR": str(self.target_dir)},
        )
        self.assertFalse(self._run())

    def test_rustc_with_cargo_target_env_blocks(self):
        """rustc with CARGO_TARGET_DIR pointing to target → must block."""
        _make_fake_proc_entry(
            self.proc_root, 41,
            comm="rustc",
            env={"CARGO_TARGET_DIR": str(self.target_dir)},
        )
        self.assertTrue(self._run())

    def test_no_processes_returns_false(self):
        """Empty proc tree → no block."""
        self.assertFalse(self._run())

    def test_cwd_outside_target_does_not_block(self):
        """cargo process with CWD outside the target dir → must NOT block."""
        other_dir = self.tmp / "some-other-dir"
        other_dir.mkdir()
        _make_fake_proc_entry(
            self.proc_root, 50,
            comm="cargo",
            cwd=other_dir,
        )
        self.assertFalse(self._run())


if __name__ == "__main__":
    unittest.main()
