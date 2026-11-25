"""Policy and charging (Gx / Gy) rules on synthetic captures."""

from pathlib import Path

import pytest
from conftest import T0, needs_tshark
from pcapgen import (
    CC_TERMINATION,
    CC_UPDATE,
    GX_APP,
    GY_APP,
    HOST_A,
    HOST_B,
    TcpFlow,
    cca,
    ccr,
    charging_rule_report,
    gtpv2,
    gtpv2_frame,
    ie_apn,
    ie_cause,
    ie_imsi,
    mscc,
    write_pcap,
)

from capsight.engine import analyze

pytestmark = needs_tshark


def _write(tmp_path: Path, name: str, messages: list[tuple[bool, bytes]], extra=()) -> Path:
    flow = TcpFlow(HOST_A, HOST_B, 40001, 3868)
    frames = [(T0 + i * 0.01, flow.frame(up, m)) for i, (up, m) in enumerate(messages)]
    return write_pcap(tmp_path / name, sorted([*frames, *extra]))


def _only(report):
    problems = [f for f in report.findings if f.severity != "info"]
    assert len(problems) == 1, [f.verdict for f in problems]
    return problems[0]


def test_gy_credit_limit_on_initial(tmp_path):
    cap = _write(tmp_path, "gy-4012.pcap", [(True, ccr(0x10)), (False, cca(0x10, result=4012))])
    f = _only(analyze(cap))
    assert f.rule_id == "pcc.result"
    assert f.verdict == "Gy CCR-I rejected: DIAMETER_CREDIT_LIMIT_REACHED."
    assert "for APN internet" in f.why and "refused at setup" in f.why
    assert "balance or data allowance" in f.fix
    assert f.subscribers == ("001010000000001",)


def test_gx_initial_parameters_links_gtp_reject(tmp_path):
    csr = gtpv2(32, 9, [ie_imsi("001010000000001"), ie_apn("internet")])
    csresp = gtpv2(33, 9, [ie_cause(73)], teid=0x1)  # 73 = No resources available
    gtp = [(T0 - 0.01, gtpv2_frame(True, csr)), (T0 + 0.05, gtpv2_frame(False, csresp))]
    cap = _write(
        tmp_path,
        "gx-5140.pcap",
        [(True, ccr(0x20, app=GX_APP)), (False, cca(0x20, app=GX_APP, experimental=5140))],
        gtp,
    )
    report = analyze(cap)
    pcc = [f for f in report.findings if f.rule_id == "pcc.result"]
    assert len(pcc) == 1
    assert pcc[0].verdict == "Gx CCR-I rejected: DIAMETER_ERROR_INITIAL_PARAMETERS."
    assert "consequence of this Gx answer" in pcc[0].why
    assert "PCRF" in pcc[0].fix
    # the generic Diameter rule must not report the same answer again
    assert not [f for f in report.findings if f.rule_id == "diameter.result"]


def test_user_unknown_names_the_right_server(tmp_path):
    gx = _write(
        tmp_path, "gx.pcap", [(True, ccr(1, app=GX_APP)), (False, cca(1, app=GX_APP, result=5030))]
    )
    gy = _write(tmp_path, "gy.pcap", [(True, ccr(2)), (False, cca(2, result=5030))])
    assert "policy server (PCRF)" in _only(analyze(gx)).fix
    assert "online charging system (OCS)" in _only(analyze(gy)).fix


def test_update_reject_means_session_stays_up(tmp_path):
    cap = _write(
        tmp_path,
        "gy-u.pcap",
        [(True, ccr(3, req_type=CC_UPDATE)), (False, cca(3, req_type=CC_UPDATE, result=4010))],
    )
    f = _only(analyze(cap))
    assert f.verdict.startswith("Gy CCR-U rejected: DIAMETER_END_USER_SERVICE_DENIED")
    assert "stays attached" in f.why


def test_termination_reject_is_only_a_warning(tmp_path):
    cap = _write(
        tmp_path,
        "gy-t.pcap",
        [
            (True, ccr(4, req_type=CC_TERMINATION)),
            (False, cca(4, req_type=CC_TERMINATION, result=5002)),
        ],
    )
    f = _only(analyze(cap))
    assert f.severity == "warning"
    assert "DIAMETER_UNKNOWN_SESSION_ID" in f.verdict


def test_rating_group_out_of_credit(tmp_path):
    answer = cca(5, result=2001, extra=[mscc(10, 4012, final_action=0), mscc(20, 2001)])
    cap = _write(tmp_path, "gy-mscc.pcap", [(True, ccr(5)), (False, answer)])
    f = _only(analyze(cap))
    assert f.rule_id == "pcc.credit"
    assert f.verdict == "Gy: no service for rating group 10: DIAMETER_CREDIT_LIMIT_REACHED."
    assert "TERMINATE" in f.why and "Other services" in f.why


def test_credit_control_not_applicable_is_not_a_failure(tmp_path):
    cap = _write(tmp_path, "gy-4011.pcap", [(True, ccr(6)), (False, cca(6, result=4011))])
    assert [f for f in analyze(cap).findings if f.severity != "info"] == []


@pytest.mark.parametrize(
    "code,name", [(10, "RESOURCE_ALLOCATION_FAILURE"), (1, "UNKNOWN_RULE_NAME")]
)
def test_charging_rule_report(tmp_path, code, name):
    request = ccr(
        7, app=GX_APP, req_type=CC_UPDATE, extra=[charging_rule_report("video_boost", code)]
    )
    cap = _write(
        tmp_path, "gx-crr.pcap", [(True, request), (False, cca(7, app=GX_APP, req_type=CC_UPDATE))]
    )
    f = _only(analyze(cap))
    assert f.rule_id == "pcc.rule"
    assert f.verdict == f"Policy rule 'video_boost' not installed: {name}."
    assert "rule status INACTIVE" in f.why


def test_successful_gx_and_gy_are_clean(tmp_path):
    cap = _write(
        tmp_path,
        "ok.pcap",
        [
            (True, ccr(8, app=GX_APP)),
            (False, cca(8, app=GX_APP)),
            (True, ccr(9, app=GY_APP)),
            (False, cca(9, extra=[mscc(10, 2001)])),
        ],
    )
    report = analyze(cap)
    assert [f for f in report.findings if f.severity != "info"] == []
    assert report.transactions["diameter"] == 2


def test_imsi_timeline_shows_gx_gy_steps(tmp_path):
    cap = _write(
        tmp_path,
        "tl.pcap",
        [
            (True, ccr(10, app=GX_APP)),
            (False, cca(10, app=GX_APP)),
            (True, ccr(11)),
            (False, cca(11, result=4012)),
        ],
    )
    report = analyze(cap, imsi="001010000000001")
    names = [(s.name, s.status) for s in report.timeline]
    assert names[0][0] == "Gx CCR-I" and names[1][0] == "Gy CCR-I"
    assert "DIAMETER_CREDIT_LIMIT_REACHED (4012)" in report.timeline[1].detail
