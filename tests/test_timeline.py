"""Per-subscriber view (--imsi)."""

import json

from conftest import T0, needs_tshark
from pcapgen import (
    HOST_A,
    HOST_B,
    TcpFlow,
    gtpv2,
    gtpv2_frame,
    ie_apn,
    ie_cause,
    ie_imsi,
    s6a_answer,
    s6a_request,
    write_pcap,
)

from capsight.cli import main
from capsight.engine import analyze, analyze_packets
from capsight.model import Packet
from capsight.timeline import normalize_imsi

GOOD = "001010000000001"
BAD = "001010000000002"


def two_subscribers(tmp_path):
    """GOOD attaches and gets a session; BAD is rejected by the HSS on ULR."""
    flow = TcpFlow(HOST_A, HOST_B, 40010, 3868)
    frames = [
        (T0, flow.frame(True, s6a_request(318, 0x10, GOOD))),
        (T0 + 0.01, flow.frame(False, s6a_answer(318, 0x10))),
        (T0 + 0.02, flow.frame(True, s6a_request(318, 0x20, BAD))),
        (T0 + 0.03, flow.frame(False, s6a_answer(318, 0x20))),
        (T0 + 0.04, flow.frame(True, s6a_request(316, 0x11, GOOD))),
        (T0 + 0.05, flow.frame(False, s6a_answer(316, 0x11))),
        (T0 + 0.06, flow.frame(True, s6a_request(316, 0x21, BAD))),
        (T0 + 0.07, flow.frame(False, s6a_answer(316, 0x21, experimental=5420))),
        (T0 + 0.08, gtpv2_frame(True, gtpv2(32, 5, [ie_imsi(GOOD), ie_apn("internet")]))),
        (T0 + 0.09, gtpv2_frame(False, gtpv2(33, 5, [ie_cause(16)], teid=0x99))),
    ]
    return write_pcap(tmp_path / "two.pcap", frames)


def test_normalize_imsi():
    assert normalize_imsi("imsi-001010000000001") == GOOD
    assert normalize_imsi("001 01 0000000001") == GOOD


@needs_tshark
def test_healthy_subscriber_timeline(tmp_path):
    report = analyze(two_subscribers(tmp_path), imsi=GOOD)
    steps = [(s.name, s.status) for s in report.timeline]
    assert steps == [
        ("AIR -> AIA", "ok"),
        ("ULR -> ULA", "ok"),
        ("Create Session", "ok"),
    ]
    assert report.findings == []


@needs_tshark
def test_failing_subscriber_stops_at_ulr(tmp_path, capsys):
    capture = two_subscribers(tmp_path)
    assert main(["analyze", str(capture), "--imsi", BAD]) == 0
    out = capsys.readouterr().out
    assert "subscriber 001010000000002" in out
    assert "ULR -> ULA" in out and "FAILED" in out
    assert "stopped at: ULR -> ULA (packet #8), DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION" in out
    assert "Create Session" not in out  # GOOD's session is not shown
    assert "ULR rejected: DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION." in out


@needs_tshark
def test_other_subscribers_findings_are_hidden(tmp_path):
    report = analyze(two_subscribers(tmp_path), imsi=GOOD)
    assert all(GOOD in f.subscribers for f in report.findings)
    full = analyze(two_subscribers(tmp_path))
    assert len(full.findings) == 1


@needs_tshark
def test_unknown_imsi_lists_who_is_there(tmp_path, capsys):
    capture = two_subscribers(tmp_path)
    main(["analyze", str(capture), "--imsi", "001010000000009"])
    out = capsys.readouterr().out
    assert "not found in this capture" in out
    assert "subscribers in this capture: 001010000000001, 001010000000002" in out


@needs_tshark
def test_json_includes_timeline(tmp_path, capsys):
    main(["analyze", str(two_subscribers(tmp_path)), "--imsi", BAD, "--format", "json"])
    out = json.loads(capsys.readouterr().out)
    assert out["subscriber"] == BAD
    assert [s["status"] for s in out["timeline"]] == ["ok", "failed"]


def test_5g_timeline_from_suci_and_ngap_id():
    n2 = ("eth", "ip", "sctp", "ngap", "nas-5gs")
    ue = {"ngap.RAN_UE_NGAP_ID": ["1"]}
    packets = [
        Packet(
            1,
            1.0,
            n2,
            {
                **ue,
                "nas-5gs.mm.message_type": ["0x41"],
                "nas-5gs.mm.suci.scheme_id": ["0"],
                "nas-5gs.mm.suci.msin": ["0000000001"],
                "e212.mcc": ["001"],
                "e212.mnc": ["01"],
            },
        ),
        Packet(2, 2.0, n2, {**ue, "nas-5gs.mm.message_type": ["0x56"]}),
        Packet(
            3, 3.0, n2, {**ue, "nas-5gs.mm.message_type": ["0x59"], "nas-5gs.mm.5gmm_cause": ["20"]}
        ),
        Packet(4, 4.0, n2, {**ue, "nas-5gs.mm.message_type": ["0x58"]}),
    ]
    report = analyze_packets("x", packets, imsi=GOOD)
    assert [(s.name, s.status) for s in report.timeline] == [
        ("Registration Request", "ok"),
        ("Authentication Request", "ok"),
        ("Authentication Failure", "failed"),
        ("Authentication Reject", "failed"),
    ]
    assert report.timeline[2].detail == "5GMM cause #20 (MAC failure)"


def test_sync_failure_is_a_note_not_a_stop():
    n2 = ("eth", "ip", "sctp", "s1ap", "nas-eps")
    imsi = {"e212.imsi": [GOOD]}
    packets = [
        Packet(1, 1.0, n2, {**imsi, "nas-eps.nas_msg_emm_type": ["0x41"]}),
        Packet(
            2, 2.0, n2, {**imsi, "nas-eps.nas_msg_emm_type": ["0x5c"], "nas-eps.emm.cause": ["21"]}
        ),
        Packet(3, 3.0, n2, {**imsi, "nas-eps.nas_msg_emm_type": ["0x53"]}),
        Packet(4, 4.0, n2, {**imsi, "nas-eps.nas_msg_emm_type": ["0x42"]}),
    ]
    report = analyze_packets("x", packets, imsi=GOOD)
    assert [s.status for s in report.timeline] == ["ok", "info", "ok", "ok"]
    assert report.timeline[1].detail == "cause #21 (Synch failure)"
    assert report.timeline[3].name == "Attach Accept"
