import json

from conftest import needs_tshark

from capsight.cli import main


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


@needs_tshark
def test_analyze_text_shows_finding(ula_user_unknown, capsys):
    assert main(["analyze", str(ula_user_unknown)]) == 0
    out = capsys.readouterr().out
    assert "FAILURE   ULR rejected: DIAMETER_ERROR_USER_UNKNOWN." in out
    assert "WHERE     packets #3, #4" in out


@needs_tshark
def test_fail_on_failure_sets_exit_code(ula_user_unknown, healthy_attach):
    assert main(["analyze", str(ula_user_unknown), "--fail-on", "failure"]) == 1
    assert main(["analyze", str(healthy_attach), "--fail-on", "failure"]) == 0
    assert main(["analyze", str(ula_user_unknown)]) == 0
