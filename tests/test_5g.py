"""5G SA rules.

PFCP and GTP-U are generated as real packets and decoded by tshark. NGAP and 5G NAS are
ASN.1/PER-encoded and awkward to synthesize by hand, so those rules are tested on decoded
packets built here; docs/VALIDATION.md covers them end-to-end on public 5G captures.
"""

from conftest import T0, needs_tshark
from pcapgen import (
    DN_IP,
    UE_IP,
    gtpu_frame,
    icmp_echo,
    pfcp,
    pfcp_frame,
    plain_ip_frame,
    write_pcap,
)

from capsight.engine import analyze, analyze_packets
from capsight.model import Packet, Severity

N2 = ("eth", "ip", "sctp", "ngap", "nas-5gs")
SUPI_FIELDS = {
    "nas-5gs.mm.suci.scheme_id": ["0"],
    "nas-5gs.mm.suci.msin": ["0000000001"],
    "e212.mcc": ["001"],
    "e212.mnc": ["01"],
}


def n2(number: int, ue: str | None = "1", **fields) -> Packet:
    data = {k.replace("__", "."): v if isinstance(v, list) else [v] for k, v in fields.items()}
    if ue is not None:
        data["ngap.RAN_UE_NGAP_ID"] = [ue]
    return Packet(number, float(number), N2, data)


def registration(number: int, ue: str = "1") -> Packet:
    packet = n2(number, ue, **{"nas-5gs.mm.message_type": "0x41"})
    packet.fields.update(SUPI_FIELDS)
    return packet


# ---- NGAP ------------------------------------------------------------------------------


def test_ng_setup_failure_unknown_plmn():
    packet = Packet(
        7,
        7.0,
        ("eth", "ip", "sctp", "ngap"),
        {
            "ngap.procedureCode": ["21"],
            "ngap.NGAP_PDU": ["2"],
            "ngap.Cause": ["4"],
            "ngap.misc": ["4"],
        },
    )
    [finding] = analyze_packets("x", [packet]).findings
    assert finding.verdict == "NG Setup failed: misc=unknown-PLMN-or-SNPN."
    assert "TAI" in finding.fix


def test_ngap_successful_outcome_is_not_a_failure():
    packet = Packet(
        7,
        7.0,
        ("eth", "ip", "sctp", "ngap"),
        {
            "ngap.procedureCode": ["21"],
            "ngap.NGAP_PDU": ["1"],
        },
    )
    assert analyze_packets("x", [packet]).findings == []


# ---- 5GMM ------------------------------------------------------------------------------


def test_registration_reject_links_supi():
    packets = [
        registration(1),
        n2(2, **{"nas-5gs.mm.message_type": "0x44", "nas-5gs.mm.5gmm_cause": "62"}),
    ]
    [finding] = analyze_packets("x", packets).findings
    assert finding.verdict == "Registration Reject: No network slices available."
    assert finding.subscribers == ("001010000000001",)


def test_concealed_suci_does_not_invent_an_imsi():
    reg = registration(1)
    reg.fields["nas-5gs.mm.suci.scheme_id"] = ["1"]  # ECIES profile A: MSIN is concealed
    packets = [reg, n2(2, **{"nas-5gs.mm.message_type": "0x44", "nas-5gs.mm.5gmm_cause": "7"})]
    [finding] = analyze_packets("x", packets).findings
    assert finding.subscribers == ()


def test_mac_failure_followed_by_auth_reject():
    packets = [
        registration(1),
        n2(2, **{"nas-5gs.mm.message_type": "0x56"}),
        n2(3, **{"nas-5gs.mm.message_type": "0x59", "nas-5gs.mm.5gmm_cause": "20"}),
        n2(4, **{"nas-5gs.mm.message_type": "0x58"}),
    ]
    [finding] = analyze_packets("x", packets).findings
    assert finding.severity == Severity.FAILURE
    assert "MAC failure" in finding.verdict
    assert "Authentication Reject (packet #4)" in finding.why


def test_sync_failure_then_success_is_info():
    packets = [
        registration(1),
        n2(2, **{"nas-5gs.mm.message_type": "0x59", "nas-5gs.mm.5gmm_cause": "21"}),
        n2(3, **{"nas-5gs.mm.message_type": "0x57"}),
    ]
    [finding] = analyze_packets("x", packets).findings
    assert finding.severity == Severity.INFO


def test_dnn_not_subscribed_names_the_dnn():
    packets = [
        registration(1),
        n2(
            5,
            **{
                "nas-5gs.mm.message_type": ["0x43", "0x67"],
                "nas-5gs.sm.message_type": "0xc1",
                "nas-5gs.cmn.dnn": "wrongdnn",
            },
        ),
        n2(6, **{"nas-5gs.mm.message_type": "0x64", "nas-5gs.mm.5gmm_cause": "91"}),
    ]
    [finding] = analyze_packets("x", packets).findings
    assert "refused by the AMF" in finding.verdict
    assert "DNN 'wrongdnn'" in finding.why
    assert "never reached an SMF" in finding.why
    assert finding.evidence == (5, 6)


# ---- 5GSM ------------------------------------------------------------------------------


def test_pdu_session_reject_from_smf():
    packets = [
        registration(1),
        n2(5, **{"nas-5gs.sm.message_type": "0xc1", "nas-5gs.cmn.dnn": "internet"}),
        n2(6, **{"nas-5gs.sm.message_type": "0xc3", "nas-5gs.sm.5gsm_cause": "29"}),
    ]
    [finding] = analyze_packets("x", packets).findings
    assert finding.verdict.startswith("PDU Session Establishment Reject: User authentication")
    assert "DNN 'internet'" in finding.why


# ---- PFCP (real packets through tshark) ------------------------------------------------


@needs_tshark
def test_pfcp_session_establishment_rejected(tmp_path):
    frames = [
        (T0, pfcp_frame(True, pfcp(50, 31, seid=0))),
        (T0 + 0.01, pfcp_frame(False, pfcp(51, 31, seid=0x65E, cause=73))),
    ]
    report = analyze(write_pcap(tmp_path / "pfcp73.pcap", frames))
    assert report.transactions["pfcp"] == 1
    [finding] = report.findings
    assert finding.verdict == (
        "PFCP Session Establishment rejected: Rule creation/modification Failure."
    )


@needs_tshark
def test_pfcp_accepted_and_heartbeat_ok(tmp_path):
    frames = [
        (T0, pfcp_frame(True, pfcp(1, 1))),
        (T0 + 0.01, pfcp_frame(False, pfcp(2, 1))),
        (T0 + 0.02, pfcp_frame(True, pfcp(50, 2, seid=0))),
        (T0 + 0.03, pfcp_frame(False, pfcp(51, 2, seid=0x65E, cause=1))),
    ]
    report = analyze(write_pcap(tmp_path / "pfcp-ok.pcap", frames))
    assert report.transactions["pfcp"] == 2
    assert report.findings == []


@needs_tshark
def test_pfcp_unanswered(tmp_path):
    frames = [
        (T0, pfcp_frame(True, pfcp(50, 9, seid=0))),
        (T0 + 0.5, pfcp_frame(True, pfcp(50, 9, seid=0))),  # retransmission
        (T0 + 10, pfcp_frame(True, pfcp(1, 10))),
        (T0 + 10.01, pfcp_frame(False, pfcp(2, 10))),
    ]
    [finding] = analyze(write_pcap(tmp_path / "pfcp-timeout.pcap", frames)).findings
    assert finding.verdict == "Session Establishment never answered."


# ---- GTP-U user plane (real packets through tshark) -------------------------------------


@needs_tshark
def test_missing_nat_on_n6(tmp_path):
    frames = []
    for i in range(3):
        frames.append((T0 + i, gtpu_frame(True, icmp_echo(UE_IP, DN_IP))))
        frames.append((T0 + i + 0.001, plain_ip_frame(icmp_echo(UE_IP, DN_IP))))
    report = analyze(write_pcap(tmp_path / "n6.pcap", frames))
    assert report.core_protocols == {"gtp": 3}
    [finding] = report.findings
    assert finding.severity == Severity.FAILURE
    assert "one-way" in finding.verdict
    assert "NAT/masquerade" in finding.fix


@needs_tshark
def test_user_plane_with_replies_is_healthy(tmp_path):
    frames = []
    for i in range(3):
        frames.append((T0 + i, gtpu_frame(True, icmp_echo(UE_IP, DN_IP))))
        frames.append((T0 + i + 0.02, gtpu_frame(False, icmp_echo(DN_IP, UE_IP, True), 1)))
    assert analyze(write_pcap(tmp_path / "n6-ok.pcap", frames)).findings == []
