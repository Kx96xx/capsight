"""Ciphered 5G NAS: report what could not be seen, infer outcomes from NGAP.

NGAP is PER-encoded, so like test_5g.py these tests use decoded packets. docs/VALIDATION.md
covers the rules end-to-end on the public 5G lab captures read with deciphering turned off.
"""

from capsight.engine import analyze_packets
from capsight.model import Packet
from capsight.rules_5g_ciphered import unreadable_nas

N2 = ("eth", "ip", "sctp", "ngap", "nas-5gs")
INITIATING, SUCCESSFUL = "0", "1"


def n2(number: int, proc: int, nas_headers: str = "", pdu: str = INITIATING, **extra) -> Packet:
    fields = {
        "ngap.procedureCode": [str(proc)],
        "ngap.NGAP_PDU": [pdu],
        "ngap.RAN_UE_NGAP_ID": ["1"],
    }
    if nas_headers:
        fields["nas-5gs.security_header_type"] = nas_headers.split(",")
    for k, v in extra.items():
        fields[k.replace("__", ".")] = v if isinstance(v, list) else [v]
    protocols = N2 if nas_headers else N2[:-1]
    return Packet(number, float(number), protocols, fields)


def security_setup(algorithm: str = "2") -> list[Packet]:
    """Registration request, authentication and Security Mode Command, all readable."""
    return [
        n2(1, 15, "0", **{"nas-5gs.mm.message_type": "0x41"}),
        n2(2, 4, "0", **{"nas-5gs.mm.message_type": "0x56"}),
        n2(3, 46, "0", **{"nas-5gs.mm.message_type": "0x57"}),
        n2(
            4,
            4,
            "3,0",
            **{"nas-5gs.mm.message_type": "0x5d", "nas-5gs.mm.nas_sec_algo_enc": algorithm},
        ),
        n2(5, 46, "4"),  # Security Mode Complete, ciphered
    ]


def findings(packets: list[Packet]) -> dict[str, object]:
    return {f.rule_id: f for f in analyze_packets("x", packets).findings}


def test_unreadable_count():
    def packet(headers):
        return n2(1, 46, headers)

    assert unreadable_nas(packet("2,2")) == 2
    assert unreadable_nas(packet("2,0,2")) == 1
    assert unreadable_nas(packet("2,0,2,0")) == 0  # deciphered (NEA0): readable
    assert unreadable_nas(packet("3,0")) == 0  # Security Mode Command is not ciphered
    assert unreadable_nas(packet("4")) == 1


def test_registration_rejected_inside_ciphered_nas():
    packets = [
        *security_setup(),
        n2(6, 4, "2"),  # the reject, encrypted
        n2(7, 41, **{"ngap.Cause": "2", "ngap.nas": "3"}),  # UE Context Release Command
        n2(8, 41, pdu=SUCCESSFUL),
    ]
    found = findings(packets)
    reg = found["nas5g.ciphered.registration"]
    assert reg.severity == "failure"
    assert reg.verdict == "Registration did not complete (NAS ciphered; the reject is not visible)."
    assert "cause nas=unspecified" in reg.why
    assert reg.evidence == (5, 7)
    info = found["nas5g.ciphered"]
    assert info.severity == "info"
    assert "128-NEA2" in info.why
    assert "nas5g.ciphered.session" not in found


def test_registered_but_no_pdu_session():
    packets = [
        *security_setup(),
        n2(6, 14, "2"),  # Initial Context Setup with Registration Accept
        n2(7, 14, pdu=SUCCESSFUL),
        n2(8, 46, "2,2"),  # Registration Complete + PDU Session Establishment Request
        n2(9, 4, "2"),  # the answer, encrypted
        n2(10, 42),  # UE Context Release Request
    ]
    found = findings(packets)
    session = found["nas5g.ciphered.session"]
    assert session.severity == "warning"
    assert session.verdict == "Registered, but no PDU session was set up (NAS ciphered)."
    assert session.evidence == (6, 8)
    assert "nas5g.ciphered.registration" not in found


def test_healthy_ciphered_flow_is_info_only():
    packets = [
        *security_setup(),
        n2(6, 14, "2"),
        n2(7, 14, pdu=SUCCESSFUL),
        n2(8, 46, "2,2"),
        n2(9, 4, "2"),
        n2(10, 29, "2"),  # PDU Session Resource Setup: the session was created
        n2(11, 29, pdu=SUCCESSFUL),
    ]
    found = analyze_packets("x", packets).findings
    assert [(f.rule_id, f.severity) for f in found] == [("nas5g.ciphered", "info")]


def test_registration_only_is_not_a_missing_session():
    packets = [
        *security_setup(),
        n2(6, 14, "2"),
        n2(7, 14, pdu=SUCCESSFUL),
        n2(8, 46, "2"),  # Registration Complete only
        n2(9, 4, "2"),  # e.g. Configuration Update Command
    ]
    assert "nas5g.ciphered.session" not in findings(packets)


def test_null_ciphering_read_by_tshark_reports_nothing():
    packets = [
        *security_setup(algorithm="0")[:4],
        n2(5, 46, "4,0", **{"nas-5gs.mm.message_type": "0x5e"}),
        n2(6, 14, "2,0", **{"nas-5gs.mm.message_type": "0x42"}),
    ]
    assert not [f for f in analyze_packets("x", packets).findings if "ciphered" in f.rule_id]
