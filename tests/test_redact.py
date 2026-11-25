"""--redact / --redact-all."""

import json

from conftest import needs_tshark

from capsight.cli import main
from capsight.redact import Redactor


def test_imsi_keeps_plmn_and_is_stable():
    r = Redactor()
    out = r.text("WHO 001010000000001, 001010000000002 and 001010000000001 again")
    assert out == "WHO 00101-sub1, 00101-sub2 and 00101-sub1 again"


def test_redact_all_hides_plmn():
    assert Redactor(keep_plmn=False).text("001010000000001") == "sub1"


def test_msisdn_ip_and_realm():
    r = Redactor()
    out = r.text(
        "MSISDN 15550100123 from 192.0.2.7 via 2001:db8::1 at "
        "epc.mnc001.mcc001.3gppnetwork.org and mme1.example.org"
    )
    assert "15550100123" not in out and "192.0.2.7" not in out and "2001:db8::1" not in out
    assert "3gppnetwork" not in out and "example.org" not in out
    assert out == "MSISDN sub1 from ip1 via ip2 at host1.invalid and host2.invalid"


def test_leaves_normal_text_alone():
    text = (
        "packets #1, #4 (0.03 s) cause 92 2026-11-18 16:25 wrong-apn.pcap "
        "e.g. Framed-IP 28,384x EMM cause #8"
    )
    assert Redactor().text(text) == text


def test_json_structures():
    r = Redactor()
    doc = r.data(
        {"subscribers": ["001010000000001"], "top": [{"imsi": "001010000000001"}], "count": 3}
    )
    assert doc == {"subscribers": ["00101-sub1"], "top": [{"imsi": "00101-sub1"}], "count": 3}


@needs_tshark
def test_cli_redact_text(ula_user_unknown, capsys):
    main(["analyze", str(ula_user_unknown), "--redact"])
    out = capsys.readouterr().out
    assert "001010000000001" not in out
    assert "WHO       00101-sub1" in out
    assert "redacted  1 subscriber numbers" in out


@needs_tshark
def test_cli_redact_json_with_imsi_and_summary(ula_user_unknown, capsys):
    main(
        [
            "analyze",
            str(ula_user_unknown),
            "--redact",
            "--format",
            "json",
            "--summary",
            "--imsi",
            "001010000000001",
        ]
    )
    raw = capsys.readouterr().out
    assert "001010000000001" not in raw
    doc = json.loads(raw)
    assert doc["redacted"] is True
    assert doc["subscriber"] == "00101-sub1"
    assert doc["capture"] == "capture.pcap"
