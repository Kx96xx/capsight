"""Rule tests on hand-built packets, for protocols that are awkward to synthesize."""

from capsight.engine import analyze_packets
from capsight.model import Packet, Severity

NAS = ("eth", "ip", "sctp", "s1ap", "nas-eps")


def nas_packet(
    number: int,
    emm_type: int | None = None,
    emm_cause: int | None = None,
    esm_type: int | None = None,
    esm_cause: int | None = None,
    imsi: str | None = "001010000000001",
    enb_id: str | None = None,
) -> Packet:
    fields: dict[str, list[str]] = {}
    if imsi:
        fields["e212.imsi"] = [imsi]
    if enb_id:
        fields["s1ap.ENB_UE_S1AP_ID"] = [enb_id]
    if emm_type is not None:
        fields["nas-eps.nas_msg_emm_type"] = [hex(emm_type)]
    if emm_cause is not None:
        fields["nas-eps.emm.cause"] = [str(emm_cause)]
    if esm_type is not None:
        fields["nas-eps.nas_msg_esm_type"] = [hex(esm_type)]
    if esm_cause is not None:
        fields["nas-eps.esm.cause"] = [str(esm_cause)]
    return Packet(number, float(number), NAS, fields)


def test_attach_reject_grouped():
    packets = [nas_packet(n, emm_type=0x44, emm_cause=8) for n in (1, 2, 3)]
    [finding] = analyze_packets("x", packets).findings
    assert finding.verdict.startswith("Attach Reject: EPS services and non-EPS")
    assert finding.count == 3
    assert "Seen 3 times" in finding.why


def test_auth_sync_failure_is_warning():
    [finding] = analyze_packets("x", [nas_packet(1, emm_type=0x5C, emm_cause=21)]).findings
    assert finding.severity == Severity.WARNING
    assert "Synch failure" in finding.verdict


def test_auth_mac_failure_is_failure():
    [finding] = analyze_packets("x", [nas_packet(1, emm_type=0x5C, emm_cause=20)]).findings
    assert finding.severity == Severity.FAILURE
    assert "Ki/OPc" in finding.fix


def test_pdn_connectivity_reject():
    [finding] = analyze_packets("x", [nas_packet(1, esm_type=0xD1, esm_cause=27)]).findings
    assert "Missing or unknown APN" in finding.verdict


def test_unknown_cause_still_reported():
    [finding] = analyze_packets("x", [nas_packet(1, emm_type=0x44, emm_cause=99)]).findings
    assert "code 99" in finding.verdict


def test_imsi_inferred_from_s1ap_id():
    packets = [
        nas_packet(1, emm_type=0x41, enb_id="7"),  # Attach Request carries the IMSI
        nas_packet(2, emm_type=0x44, emm_cause=8, imsi=None, enb_id="7"),
    ]
    [finding] = analyze_packets("x", packets).findings
    assert finding.subscribers == ("001010000000001",)


def test_imsi_not_inferred_across_ue_ids():
    packets = [
        nas_packet(1, emm_type=0x41, enb_id="7"),
        nas_packet(2, emm_type=0x44, emm_cause=8, imsi=None, enb_id="8"),
    ]
    [finding] = analyze_packets("x", packets).findings
    assert finding.subscribers == ()


def test_sync_failure_followed_by_success_is_info():
    packets = [
        nas_packet(1, emm_type=0x41, enb_id="3"),
        nas_packet(2, emm_type=0x5C, emm_cause=21, imsi=None, enb_id="3"),
        nas_packet(3, emm_type=0x53, imsi=None, enb_id="3"),
    ]
    [finding] = analyze_packets("x", packets).findings
    assert finding.severity == Severity.INFO
    assert "resync" in finding.verdict
