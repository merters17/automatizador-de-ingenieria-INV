import sys
from pathlib import Path

from rea_automator.runner import run_bounded

FAKE = str(Path(__file__).parent / "fake_rea.py")


def _run(tmp_path, mode, *, timeout=20, max_out=10**9, max_err=10**9):
    import os
    os.environ["FAKE_REA_MODE"] = mode
    try:
        return run_bounded(
            [sys.executable, FAKE, "x"],
            stdout_path=tmp_path / "o.json",
            stderr_path=tmp_path / "e.log",
            timeout_s=timeout,
            max_stdout_bytes=max_out,
            max_stderr_bytes=max_err,
        )
    finally:
        os.environ.pop("FAKE_REA_MODE", None)


def test_captures_exit_and_files(tmp_path):
    r = _run(tmp_path, "ok")
    assert r.returncode == 0 and not r.timed_out
    assert "ev_test" in (tmp_path / "o.json").read_text()


def test_stdout_is_truncated_at_limit_not_loaded_whole(tmp_path):
    r = _run(tmp_path, "bigout", max_out=1000)
    assert r.stdout_truncated is True
    assert (tmp_path / "o.json").stat().st_size == 1000


def test_timeout_kills_and_reports(tmp_path):
    r = _run(tmp_path, "sleep", timeout=1)
    assert r.timed_out is True and r.returncode is None
    assert r.duration_s < 30


def test_negative_returncode_on_self_kill(tmp_path):
    r = _run(tmp_path, "selfkill")
    assert r.returncode == -9 and not r.timed_out
