import json
import shutil

import pytest

from capsight.cli import main

needs_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")


def test_missing_capture_returns_error(tmp_path, capsys):
    assert main(["analyze", str(tmp_path / "nope.pcap")]) == 2
    assert "capture not found" in capsys.readouterr().err


@needs_tshark
def test_analyze_json(plain_udp_capture, capsys):
    assert main(["analyze", str(plain_udp_capture), "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["packets"] == 3
    assert out["core_protocols"] == {}
    assert out["findings"] == []
