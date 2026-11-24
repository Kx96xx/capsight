"""Failure patterns seen in a production operator core, rebuilt from scratch.

No bytes come from production: every capture is generated here with test-network IMSIs
(MCC 001 / MNC 01), RFC 5737 addresses and example.org names. Only the *shape* of each
failure (which message, which cause, what came before it) is reproduced.
"""

from conftest import T0, needs_tshark
from pcapgen import (
    gtpv2,
    gtpv2_frame,
    ie_apn,
    ie_cause,
    ie_imsi,
    ie_pdn_type,
    radius,
    radius_frame,
    write_pcap,
)

from capsight.engine import analyze, analyze_packets
from capsight.model import Packet, Severity

pytestmark = needs_tshark
IMSI = "001010000000042"


def csr(seq, pdn_type=1, apn="internet", imsi=IMSI):
    return gtpv2(32, seq, [ie_imsi(imsi), ie_apn(apn), ie_pdn_type(pdn_type)])


def csresp(seq, cause, remote=False):
    return gtpv2(33, seq, [ie_cause(cause, remote)], teid=0x1234)


def test_user_auth_failed_after_radius_accept(tmp_path):
    """Gateway rejects with cause 92 even though RADIUS accepted the user."""
    frames = [
        (T0, gtpv2_frame(True, csr(1))),
        (T0 + 0.01, radius_frame(True, radius(1, 7))),  # Access-Request
        (T0 + 0.02, radius_frame(False, radius(2, 7))),  # Access-Accept
        (T0 + 0.03, gtpv2_frame(False, csresp(1, 92))),
    ]
    report = analyze(write_pcap(tmp_path / "cs92.pcap", frames))
    [finding] = report.findings
    assert "User authentication failed" in finding.verdict
    assert "Access-Accept (packet #3)" in finding.why
    assert "responding node raised the cause itself" in finding.why
    assert "Not a credential problem" in finding.fix


def test_user_auth_failed_without_radius_keeps_default_hint(tmp_path):
    frames = [
        (T0, gtpv2_frame(True, csr(1))),
        (T0 + 0.03, gtpv2_frame(False, csresp(1, 92, remote=True))),
    ]
    [finding] = analyze(write_pcap(tmp_path / "cs92b.pcap", frames)).findings
    assert "Access-Accept" not in finding.why
    assert "further down the path" in finding.why


def test_pdn_type_split(tmp_path):
    """IPv4v6 rejected with cause 83 while IPv4 on the same APN is accepted."""
    frames = [
        (T0, gtpv2_frame(True, csr(1, pdn_type=3))),
        (T0 + 0.01, gtpv2_frame(False, csresp(1, 83))),
        (T0 + 3, gtpv2_frame(True, csr(2, pdn_type=1))),
        (T0 + 3.01, gtpv2_frame(False, csresp(2, 16))),
    ]
    findings = analyze(write_pcap(tmp_path / "cs83.pcap", frames)).findings
    split = [f for f in findings if f.rule_id == "gtpv2.pdn_type"]
    assert len(split) == 1
    assert split[0].verdict == "IPv4v6 sessions rejected while IPv4 works."
    assert "follows the PDN type, not the APN" in split[0].why
    assert [f.rule_id for f in findings] == ["gtpv2.pdn_type"]  # generic reject superseded


def test_retransmission_storm_is_one_failure(tmp_path):
    """A peer retransmits a rejected request; the reject is repeated each time."""
    frames = []
    for i in range(6):
        frames.append((T0 + i * 0.5, gtpv2_frame(True, csr(5))))
        frames.append((T0 + i * 0.5 + 0.01, gtpv2_frame(False, csresp(5, 72))))
    [finding] = analyze(write_pcap(tmp_path / "storm.pcap", frames)).findings
    assert finding.count == 1
    assert "5 retransmitted copies" in finding.why


def test_reject_loop_with_new_sequence_numbers_counts_each(tmp_path):
    """A device that retries with fresh requests is a real loop: count every attempt."""
    frames = []
    for i in range(4):
        frames.append((T0 + i * 3, gtpv2_frame(True, csr(10 + i, apn="other"))))
        frames.append((T0 + i * 3 + 0.01, gtpv2_frame(False, csresp(10 + i, 93))))
    [finding] = analyze(write_pcap(tmp_path / "loop.pcap", frames)).findings
    assert finding.count == 4
    assert "Seen 4 times" in finding.why
    assert "APN access denied" in finding.verdict


NAS = ("eth", "ip", "sctp", "s1ap", "nas-eps")


def _nas(n, **fields):
    data = {"s1ap.ENB_UE_S1AP_ID": ["1"]}
    data.update({k: [v] for k, v in fields.items()})
    return Packet(n, float(n), NAS, data)


def test_extra_pdn_rejected_after_successful_attach_is_warning():
    """Default bearer works; a second APN request is rejected (ESM #33)."""
    packets = [
        _nas(1, **{"nas-eps.nas_msg_emm_type": "0x41", "e212.imsi": IMSI}),
        _nas(2, **{"nas-eps.nas_msg_emm_type": "0x42"}),  # Attach Accept
        _nas(3, **{"nas-eps.nas_msg_esm_type": "0xd1", "nas-eps.esm.cause": "33"}),
    ]
    [finding] = analyze_packets("x", packets).findings
    assert finding.severity == Severity.WARNING
    assert finding.verdict.startswith("Extra PDN connection rejected")
    assert "Data on the default APN works" in finding.why
    assert finding.subscribers == (IMSI,)


def test_pdn_reject_during_attach_is_failure():
    packets = [
        _nas(1, **{"nas-eps.nas_msg_emm_type": "0x41", "e212.imsi": IMSI}),
        _nas(2, **{"nas-eps.nas_msg_esm_type": "0xd1", "nas-eps.esm.cause": "29"}),
    ]
    [finding] = analyze_packets("x", packets).findings
    assert finding.severity == Severity.FAILURE
