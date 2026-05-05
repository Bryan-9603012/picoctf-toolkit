import subprocess
from pathlib import Path

from artifactscope import fs_analyzer


def test_run_timeout_returns_completed_process(monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=1, output=b"out", stderr=b"err")

    monkeypatch.setattr(fs_analyzer.subprocess, "run", fake_run)
    proc = fs_analyzer._run(["sudo", "mount"], timeout=1)
    assert proc.returncode == 124
    assert "out" in proc.stdout
    assert "err" in proc.stderr


def test_access_partition_does_not_raise_when_mount_times_out(monkeypatch, tmp_path):
    def fake_run(cmd, timeout=20):
        if "mount" in cmd:
            return subprocess.CompletedProcess(cmd, 124, "", "Command timed out")
        return subprocess.CompletedProcess(cmd, 1, "", "failed")

    monkeypatch.setattr(fs_analyzer, "_run", fake_run)
    monkeypatch.setattr(fs_analyzer, "_is_mounted", lambda path: False)
    monkeypatch.setattr(fs_analyzer, "tsk_recover_partition", lambda *args, **kwargs: {"status": "failed", "error": "tsk failed"})
    monkeypatch.setattr(fs_analyzer, "targeted_icat_extraction", lambda *args, **kwargs: {"status": "failed", "error": "icat failed"})

    img = tmp_path / "disk.img"
    img.write_bytes(b"fake")
    result = fs_analyzer.access_partition_three_level(
        img,
        {"partition": 1, "offset_bytes": 1048576, "fs_type": "Linux"},
        tmp_path / "out",
    )

    assert result["access_status"] == "failed"
    assert "tsk failed" in result["error"]
