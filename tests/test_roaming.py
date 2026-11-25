"""Roaming: S8 Create Session rejects and S6a Visited-PLMN-Id."""

from pathlib import Path

from conftest import T0, needs_tshark
from pcapgen import (
    HOST_A,
    HOST_B,
    S8_SGW_GTPC,
    S11_MME_GTPC,
    VENDOR_3GPP,
    TcpFlow,
    avp,
    avp_str,
    avp_u32,
    diameter,
    gtpv2,
    gtpv2_frame,
    ie_apn,
    ie_cause,
    ie_fteid,
    ie_imsi,
    ie_rat_type,
    ie_serving_network,
    plmn,
    s6a_answer,
    write_pcap,
)

from capsight.engine import analyze
from capsight.roaming import decode_plmn, is_visiting

IMSI = "001010000000001"  # home network 001-01


def csr(seq: int, mnc: str = "02", interface: int = S8_SGW_GTPC, apn: str = "internet"):
    return gtpv2(
        32,
        seq,
        [
            ie_imsi(IMSI),
            ie_apn(apn),
            ie_serving_network("001", mnc),
            ie_rat_type(),
            ie_fteid(interface, 0x100 + seq),
        ],
    )


def problems(path: Path):
    return [f for f in analyze(path).findings if f.severity != "info"]


def test_decode_plmn():
    assert decode_plmn("00f120") == ("001", "02")
    assert decode_plmn("130062") == ("310", "260")
    assert decode_plmn("130026") == ("310", "620")  # 3-digit MNC: digit order per TS 24.008
    assert decode_plmn("zz") is None
    assert is_visiting(IMSI, ("001", "02"))
    assert not is_visiting(IMSI, ("001", "01"))
    assert not is_visiting(None, ("001", "02"))


@needs_tshark
def test_s8_reject_names_visited_network(tmp_path):
    cap = write_pcap(
        tmp_path / "s8-93.pcap",
        [
            (T0, gtpv2_frame(True, csr(1))),
            (T0 + 0.05, gtpv2_frame(False, gtpv2(33, 1, [ie_cause(93)], teid=0x101))),
        ],
    )
    [f] = problems(cap)
    assert f.rule_id == "roaming.s8"
    assert (
        f.verdict
        == "Roaming session rejected by the home network: APN access denied - no subscription."
    )
    assert "SGW in visited network MCC 001 MNC 02 over S8 for APN internet" in f.why
    assert "roaming policy" in f.fix


@needs_tshark
def test_s8_unanswered(tmp_path):
    cap = write_pcap(
        tmp_path / "s8-timeout.pcap",
        [
            (T0, gtpv2_frame(True, csr(2))),
            (T0 + 3, gtpv2_frame(True, csr(2))),
            (T0 + 30, gtpv2_frame(True, gtpv2(1, 99, [], teid=0))),  # echo, extends the capture
        ],
    )
    found = [f for f in problems(cap) if "Echo" not in f.verdict]
    assert [f.rule_id for f in found] == ["roaming.s8"]
    assert found[0].verdict == "Roaming session request never answered by the home network."
    assert "IPX/GRX" in found[0].fix
    assert "1 retransmitted" in found[0].why


@needs_tshark
def test_home_network_session_is_not_roaming(tmp_path):
    cap = write_pcap(
        tmp_path / "home.pcap",
        [
            (T0, gtpv2_frame(True, csr(3, mnc="01"))),
            (T0 + 0.05, gtpv2_frame(False, gtpv2(33, 3, [ie_cause(93)], teid=0x103))),
        ],
    )
    [f] = problems(cap)
    assert f.rule_id == "gtpv2.cause"


@needs_tshark
def test_s11_from_mme_is_not_s8(tmp_path):
    cap = write_pcap(
        tmp_path / "s11.pcap",
        [
            (T0, gtpv2_frame(True, csr(4, interface=S11_MME_GTPC))),
            (T0 + 0.05, gtpv2_frame(False, gtpv2(33, 4, [ie_cause(93)], teid=0x104))),
        ],
    )
    [f] = problems(cap)
    assert f.rule_id == "gtpv2.cause"


@needs_tshark
def test_s6a_roaming_not_allowed_names_visited_plmn(tmp_path):
    flow = TcpFlow(HOST_A, HOST_B, 40001, 3868)
    ulr = diameter(
        316,
        True,
        0x60,
        0x61,
        [
            avp_str(263, "mme.example.net;1"),
            avp_str(264, "mme.example.net"),
            avp_str(296, "example.net"),
            avp_str(283, "example.org"),
            avp_u32(277, 1),
            avp_str(1, IMSI),
            avp(1407, plmn("001", "02"), VENDOR_3GPP),
        ],
    )
    cap = write_pcap(
        tmp_path / "ulr-5004.pcap",
        [
            (T0, flow.frame(True, ulr)),
            (T0 + 0.02, flow.frame(False, s6a_answer(316, 0x60, experimental=5004))),
        ],
    )
    [f] = problems(cap)
    assert f.verdict == "ULR rejected: DIAMETER_ERROR_ROAMING_NOT_ALLOWED."
    assert "visited network MCC 001 MNC 02 (Visited-PLMN-Id)" in f.why
    assert f.why.startswith("ULA carried Experimental-Result-Code 5004")


@needs_tshark
def test_roaming_pdn_type_split_reported_once(tmp_path):
    from pcapgen import ie_pdn_type  # noqa: PLC0415

    def req(seq, pdn):
        return gtpv2(
            32,
            seq,
            [
                ie_imsi(IMSI),
                ie_apn("internet"),
                ie_serving_network("001", "02"),
                ie_fteid(S8_SGW_GTPC, seq),
                ie_pdn_type(pdn),
            ],
        )

    cap = write_pcap(
        tmp_path / "s8-split.pcap",
        [
            (T0, gtpv2_frame(True, req(1, 3))),
            (T0 + 0.01, gtpv2_frame(False, gtpv2(33, 1, [ie_cause(83)], teid=1))),
            (T0 + 0.02, gtpv2_frame(True, req(2, 1))),
            (T0 + 0.03, gtpv2_frame(False, gtpv2(33, 2, [ie_cause(16)], teid=2))),
        ],
    )
    assert [f.rule_id for f in problems(cap)] == ["gtpv2.pdn_type"]


@needs_tshark
def test_s8_same_cause_from_two_visited_networks_is_one_finding(tmp_path):
    frames = []
    for seq, mnc in ((1, "02"), (2, "03"), (3, "02")):
        frames += [
            (T0 + seq, gtpv2_frame(True, csr(seq, mnc=mnc))),
            (T0 + seq + 0.01, gtpv2_frame(False, gtpv2(33, seq, [ie_cause(72)], teid=seq))),
        ]
    [f] = problems(write_pcap(tmp_path / "s8-two.pcap", frames))
    assert f.count == 3
    assert "visited networks MCC 001 MNC 02, MCC 001 MNC 03" in f.why


@needs_tshark
def test_home_rejects_kept_next_to_roaming_rejects_with_same_cause(tmp_path):
    # Roaming rejects come first, so they fill the generic finding's evidence; the home
    # rejects with the same cause must still be reported, not swallowed by roaming.s8.
    frames = []
    for seq in (1, 2, 3):
        frames += [
            (T0 + seq, gtpv2_frame(True, csr(seq))),
            (T0 + seq + 0.01, gtpv2_frame(False, gtpv2(33, seq, [ie_cause(73)], teid=seq))),
        ]
    for seq in (4, 5):
        frames += [
            (T0 + seq, gtpv2_frame(True, csr(seq, interface=S11_MME_GTPC))),
            (T0 + seq + 0.01, gtpv2_frame(False, gtpv2(33, seq, [ie_cause(73)], teid=seq))),
        ]
    found = {f.rule_id: f.count for f in problems(write_pcap(tmp_path / "mix.pcap", frames))}
    assert found == {"roaming.s8": 3, "gtpv2.cause": 2}


@needs_tshark
def test_one_directional_roaming_capture_is_a_warning_not_timeouts(tmp_path):
    frames = [(T0 + seq, gtpv2_frame(True, csr(seq))) for seq in range(1, 26)]
    frames.append((T0 + 60, gtpv2_frame(True, gtpv2(1, 99, [], teid=0))))
    found = [f for f in analyze(write_pcap(tmp_path / "oneway.pcap", frames)).findings]
    rules = {f.rule_id for f in found if "Create Session" in f.verdict or f.rule_id == "roaming.s8"}
    assert rules == {"gtpv2.unanswered"}
    assert all(f.severity == "warning" for f in found if f.rule_id == "gtpv2.unanswered")
