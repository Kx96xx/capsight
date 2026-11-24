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
    assert report.transactions == {"diameter": 2, "gtpv2": 1}
    assert report.findings == []
