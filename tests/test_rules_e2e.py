"""End-to-end: synthetic capture -> tshark -> correlation -> rules."""

from conftest import needs_tshark

from capsight.engine import analyze

pytestmark = needs_tshark


def test_ula_user_unknown(ula_user_unknown):
    report = analyze(ula_user_unknown)
    assert report.transactions["diameter"] == 2
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.rule_id == "diameter.result"
    assert "ULR rejected" in finding.verdict
    assert "DIAMETER_ERROR_USER_UNKNOWN" in finding.verdict
    assert finding.subscribers == ("001010000000001",)
    assert finding.evidence == (3, 4)


def test_diameter_timeout(diameter_timeout):
    report = analyze(diameter_timeout)
    [finding] = report.findings
    assert finding.rule_id == "diameter.unanswered"
    assert finding.verdict == "AIR never answered."
    assert finding.evidence == (1,)


def test_diameter_timeout_respects_threshold(diameter_timeout):
    assert analyze(diameter_timeout, answer_timeout=30).findings == []


def test_csr_unknown_apn(csr_unknown_apn):
    report = analyze(csr_unknown_apn)
    [finding] = report.findings
    assert finding.rule_id == "gtpv2.cause"
    assert "Missing or unknown APN" in finding.verdict
    assert "wrong.apn" in finding.why
    assert finding.subscribers == ("001010000000001",)


def test_healthy_attach_has_no_findings(healthy_attach):
    report = analyze(healthy_attach)
    assert report.transactions == {"diameter": 2, "gtpv2": 1, "pfcp": 0}
    assert report.findings == []


def test_one_directional_capture_is_a_warning_not_timeouts(tmp_path):
    from conftest import T0
    from pcapgen import HOST_A, HOST_B, TcpFlow, s6a_request, udp_frame, write_pcap

    from capsight.model import Severity

    flow = TcpFlow(HOST_A, HOST_B, 40005, 3868)
    frames = [(T0 + i * 0.1, flow.frame(True, s6a_request(316, 0x500 + i))) for i in range(30)]
    frames.append((T0 + 20, udp_frame(HOST_A, HOST_B, 40000, 9999, b"x")))
    report = analyze(write_pcap(tmp_path / "oneway.pcap", frames))
    [finding] = report.findings
    assert finding.severity == Severity.WARNING
    assert "one-directional" in finding.verdict
    assert finding.count == 30
