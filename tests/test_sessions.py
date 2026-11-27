"""GTP-C + PFCP session rules: say where a session refusal came from, not only its code."""

from __future__ import annotations

from conftest import needs_tshark
from pcapgen import (
    PFCP_DELETED_BY_UP,
    S8_SGW_GTPC,
    UE_IP,
    gtpv2,
    gtpv2_frame,
    ie_apn,
    ie_cause,
    ie_fteid,
    ie_imsi,
    ie_serving_network,
    pfcp,
    pfcp_create_pdr,
    pfcp_frame,
    pfcp_fseid,
    write_pcap,
)

from capsight.engine import analyze
from capsight.session_links import _labels

pytestmark = needs_tshark

IMSI = "001010000000042"
CS_REQ, CS_RESP, EST_REQ, EST_RESP, REPORT_REQ, REPORT_RESP = 32, 33, 50, 51, 56, 57
ACCEPTED, SYSTEM_FAILURE_GTP, SYSTEM_FAILURE_PFCP = 16, 72, 77


class Core:
    """A gateway (GTP-C towards the SGW) with its UPF (PFCP)."""

    def __init__(self) -> None:
        self.frames: list[tuple[float, bytes]] = []
        self.gtp_seq = 0x100
        self.pfcp_seq = 1
        self.seid = 0x5000

    def _pfcp_seq(self) -> int:
        self.pfcp_seq += 1
        return self.pfcp_seq

    def create_session(
        self,
        t: float,
        apn: str,
        upf_cause: int = 1,
        deletes: int | None = None,
        report_first: bool = False,
        answer: bool = True,
        ue_ip: bytes = UE_IP,
        visited: str | None = None,
    ) -> int:
        """One Create Session; returns the session's CP SEID. `deletes`: SEID the UPF drops."""
        self.gtp_seq += 1
        self.seid += 1
        seq = self._pfcp_seq()
        ies = [ie_imsi(IMSI), ie_apn(apn)]
        if visited:  # a visited network's SGW over S8 (IMSI home is 001/01)
            ies += [ie_serving_network("001", visited), ie_fteid(S8_SGW_GTPC, self.gtp_seq)]
        self.frames.append((t, gtpv2_frame(True, gtpv2(CS_REQ, self.gtp_seq, ies))))
        est = pfcp(EST_REQ, seq, seid=0, ies=[pfcp_fseid(self.seid), pfcp_create_pdr(ue_ip)])
        self.frames.append((t + 0.05, pfcp_frame(True, est)))
        self.frames.append(
            (t + 0.0510, pfcp_frame(False, pfcp(EST_RESP, seq, self.seid, upf_cause)))
        )
        if deletes is not None:
            rseq = self._pfcp_seq()
            at = t + (0.0505 if report_first else 0.0512)
            report = pfcp(REPORT_REQ, rseq, seid=deletes, ies=list(PFCP_DELETED_BY_UP))
            self.frames.append((at, pfcp_frame(False, report)))
            self.frames.append((t + 0.062, pfcp_frame(True, pfcp(REPORT_RESP, rseq, 0x99, 1))))
        if answer:
            cause = ACCEPTED if upf_cause == 1 else SYSTEM_FAILURE_GTP
            response = gtpv2(CS_RESP, self.gtp_seq, [ie_cause(cause)], teid=0x1234)
            self.frames.append((t + 0.06, gtpv2_frame(False, response)))
        return self.seid

    def write(self, tmp_path):
        return write_pcap(tmp_path / "s.pcap", sorted(self.frames, key=lambda f: f[0]))


def ping_pong(core: Core, rounds: int = 4, report_first: bool = False, apns=("a.apn", "b.apn")):
    """Two APNs, one address: each new session is refused and knocks out the other; the retry
    succeeds."""
    t = 1_700_000_000.0
    current = core.create_session(t, apns[0])
    for i in range(1, rounds):
        t += 2
        apn = apns[i % 2]
        core.create_session(
            t, apn, upf_cause=SYSTEM_FAILURE_PFCP, deletes=current, report_first=report_first
        )
        current = core.create_session(t + 0.3, apn)


def by_rule(path):
    return {f.rule_id: f for f in analyze(path).findings}


def test_two_apns_sharing_one_address(tmp_path):
    core = Core()
    ping_pong(core)
    found = by_rule(core.write(tmp_path))
    f = found["session.address_conflict"]
    assert f.verdict == (
        "Two PDN sessions (APNs a.apn and b.apn) share UE address 10.45.0.5: each new one is "
        "refused and the other is deleted."
    )
    assert f.count == 3 and f.subscribers == (IMSI,)
    assert "cause 72 (System failure), which only passes on the UPF's refusal" in f.why
    assert "keep alternating" in f.why
    assert "a.apn and b.apn their own addresses" in f.fix
    # the plain code lookups are not repeated for the same packets
    assert not {"gtpv2.cause", "pfcp.cause", "session.upf_reject"} & set(found)


def test_report_sent_just_before_the_reject(tmp_path):
    core = Core()
    ping_pong(core, report_first=True)
    assert by_rule(core.write(tmp_path))["session.address_conflict"].count == 3


def test_same_apn_collision(tmp_path):
    core = Core()
    ping_pong(core, rounds=2, apns=("a.apn", "a.apn"))
    f = by_rule(core.write(tmp_path))["session.address_conflict"]
    assert f.verdict.startswith("A new session for APN a.apn collides with an older one")
    assert "keep alternating" not in f.why  # it happened once


def test_upf_refusal_without_a_deleted_session(tmp_path):
    core = Core()
    core.create_session(1_700_000_000.0, "a.apn", upf_cause=SYSTEM_FAILURE_PFCP)
    found = by_rule(core.write(tmp_path))
    f = found["session.upf_reject"]
    assert (
        f.verdict == "Create Session refused because the UPF refused the session: System failure."
    )
    assert f.fix.startswith("Look at the UPF, not the gateway")
    assert not {"gtpv2.cause", "pfcp.cause", "session.address_conflict"} & set(found)


def test_ambiguous_overlap_is_not_linked(tmp_path):
    """Two Create Sessions overlap but only one PFCP exchange is seen: no guessing."""
    core = Core()
    t = 1_700_000_000.0
    core.create_session(t, "a.apn", upf_cause=SYSTEM_FAILURE_PFCP)
    core.gtp_seq += 1
    request = gtpv2(CS_REQ, core.gtp_seq, [ie_imsi(IMSI), ie_apn("b.apn")])
    core.frames.append((t + 0.01, gtpv2_frame(True, request)))
    response = gtpv2(CS_RESP, core.gtp_seq, [ie_cause(SYSTEM_FAILURE_GTP)], teid=0x1234)
    core.frames.append((t + 0.07, gtpv2_frame(False, response)))
    found = by_rule(core.write(tmp_path))
    assert "session.upf_reject" not in found
    assert found["gtpv2.cause"].count == 2 and "pfcp.cause" in found


def test_answer_to_a_retransmission_is_timed_from_the_retransmission(tmp_path):
    """The first attempt goes unanswered and is resent; the window starts at the resend."""
    core = Core()
    t = 1_700_000_000.0
    core.create_session(t, "a.apn", answer=False)  # refused silently, retransmitted later
    seq = core.gtp_seq
    resend = gtpv2(CS_REQ, seq, [ie_imsi(IMSI), ie_apn("a.apn")])
    core.frames.append((t + 6.0, gtpv2_frame(True, resend)))
    core.create_session(t + 1.0, "b.apn", upf_cause=SYSTEM_FAILURE_PFCP)  # inside the long window
    sseq = core._pfcp_seq()
    est = pfcp(EST_REQ, sseq, seid=0, ies=[pfcp_fseid(0x7777), pfcp_create_pdr(UE_IP)])
    core.frames.append((t + 6.05, pfcp_frame(True, est)))
    core.frames.append((t + 6.051, pfcp_frame(False, pfcp(EST_RESP, sseq, 0x7777, 1))))
    response = gtpv2(CS_RESP, seq, [ie_cause(ACCEPTED)], teid=0x1234)
    core.frames.append((t + 6.06, gtpv2_frame(False, response)))
    assert by_rule(core.write(tmp_path))["session.upf_reject"].count == 1


def test_network_instance_labels():
    assert _labels("\x04core\x06mnc001\x04gprs") == "core.mnc001.gprs"
    assert _labels("internet") == "internet"


def test_roaming_requests_are_counted(tmp_path):
    core = Core()
    t = 1_700_000_000.0
    core.create_session(t, "a.apn", upf_cause=SYSTEM_FAILURE_PFCP, visited="02")
    core.create_session(t + 2, "a.apn", upf_cause=SYSTEM_FAILURE_PFCP)
    f = by_rule(core.write(tmp_path))["session.upf_reject"]
    assert "1 of them came over S8 from visited network MCC 001 MNC 02." in f.why
    assert "roaming.s8" not in by_rule(core.write(tmp_path))


def test_most_likely_cause_is_the_chain_not_the_loudest_symptom(tmp_path):
    """Four unanswered Create Sessions come first and outnumber the conflict (3), but the
    conflict explains its failures, so it is the cause to read first."""
    from capsight.cli import render_text
    from capsight.rules import most_likely_cause

    core = Core()
    for i in range(4):
        core.create_session(1_699_999_900.0 + i, "c.apn", answer=False, ue_ip=bytes([10, 45, 0, 9]))
    ping_pong(core)
    report = analyze(core.write(tmp_path))
    assert {"gtpv2.unanswered", "session.address_conflict"} <= {f.rule_id for f in report.findings}
    assert report.findings[0].rule_id == "gtpv2.unanswered"  # the list itself is unchanged
    assert most_likely_cause(report.findings).rule_id == "session.address_conflict"
    text = render_text(report)
    head = text.split("\n\n")[1].splitlines()
    assert head[0].startswith("MOST LIKELY CAUSE (seen 3 times; 2 problems in total")
    assert head[1] == "  Two PDN sessions (APNs a.apn and b.apn) share UE address 10.45.0.5: " + (
        "each new one is refused and the other is deleted."
    )


def test_no_most_likely_block_for_a_single_problem(tmp_path):
    from capsight.cli import render_text

    core = Core()
    ping_pong(core)
    assert "MOST LIKELY CAUSE" not in render_text(analyze(core.write(tmp_path)))
