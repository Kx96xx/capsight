"""Ciphered 5G NAS: say what could not be seen, and infer the outcome from NGAP.

After the Security Mode Command, NAS messages are encrypted (security header type 2 or 4)
unless the network uses null ciphering (NEA0). tshark cannot read them, so Registration
Accept/Reject and PDU session accepts/rejects are invisible. NGAP is not encrypted, and the
AMF's NGAP procedures reveal the outcome:

- Initial Context Setup for a UE means the AMF accepted its registration.
- PDU Session Resource Setup for a UE means a PDU session was created.
- A UE released without Initial Context Setup did not complete registration.

Every inference names the NGAP evidence it rests on and where to look for the rest.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

from capsight.model import Finding, Packet, Severity
from capsight.rules import Context, _add, _emit, _Group, rule
from capsight.rules_5g import _ints, _ue_key, ngap_cause

CIPHERED_HEADERS = frozenset({"2", "4"})  # integrity protected and ciphered (TS 24.501 9.3)
PLAIN_HEADER = "0"
NGAP_INITIATING = 0
PROC_DL_NAS, PROC_ICS, PROC_INITIAL_UE, PROC_PDU_SETUP = 4, 14, 15, 29
PROC_UE_RELEASE, PROC_UL_NAS = 41, 46
UPLINK = frozenset({PROC_INITIAL_UE, PROC_UL_NAS})
DOWNLINK = frozenset({PROC_DL_NAS, PROC_ICS, PROC_PDU_SETUP})
MM_SECURITY_MODE_COMMAND = 0x5D
NEA = {0: "NEA0 (null)", 1: "128-NEA1", 2: "128-NEA2", 3: "128-NEA3"}
# Registration Complete is one uplink message after registration; a PDU session request
# needs at least one more.
MIN_UPLINK_AFTER_REGISTRATION = 2


def unreadable_nas(packet: Packet) -> int:
    """Ciphered NAS messages in this packet that tshark could not decrypt.

    tshark lists the outer security header, then the inner plain header (0) when it could
    read the message. A ciphered header with no plain header after it was not read.
    """
    headers = packet.fields.get("nas-5gs.security_header_type", [])
    return sum(
        1
        for i, h in enumerate(headers)
        if h in CIPHERED_HEADERS and (i + 1 >= len(headers) or headers[i + 1] != PLAIN_HEADER)
    )


@dataclass
class _Ue:
    first: Packet
    unreadable: int = 0
    first_unreadable: Packet | None = None
    smc: Packet | None = None
    ics: Packet | None = None
    pdu_setup: Packet | None = None
    release: Packet | None = None
    uplink_after_ics: list[Packet] = field(default_factory=list)
    uplink_count_after_ics: int = 0
    downlink_after_uplink: int = 0
    last: Packet | None = None


def _initiating(packet: Packet, proc: int) -> bool:
    return proc in _ints(packet, "ngap.procedureCode") and NGAP_INITIATING in _ints(
        packet, "ngap.NGAP_PDU"
    )


def _ues(ctx: Context) -> dict[str, _Ue]:
    ues: dict[str, _Ue] = {}
    for packet in ctx.packets:
        if not packet.has("ngap"):
            continue
        key = _ue_key(packet)
        if key is None:
            continue
        ue = ues.setdefault(key, _Ue(first=packet))
        ue.last = packet
        procs = set(_ints(packet, "ngap.procedureCode"))
        if MM_SECURITY_MODE_COMMAND in _ints(packet, "nas-5gs.mm.message_type"):
            ue.smc = packet
        if _initiating(packet, PROC_ICS) and ue.ics is None:
            ue.ics = packet
        if _initiating(packet, PROC_PDU_SETUP) and ue.pdu_setup is None:
            ue.pdu_setup = packet
        if _initiating(packet, PROC_UE_RELEASE) and ue.release is None:
            ue.release = packet
        n = unreadable_nas(packet)
        if not n:
            continue
        ue.unreadable += n
        ue.first_unreadable = ue.first_unreadable or packet
        if ue.ics is not None and ue.ics.number < packet.number:
            if procs & UPLINK:
                ue.uplink_after_ics.append(packet)
                ue.uplink_count_after_ics += n
            elif procs & DOWNLINK and ue.uplink_count_after_ics >= MIN_UPLINK_AFTER_REGISTRATION:
                ue.downlink_after_uplink += n
    return ues


def _algorithm(ue: _Ue) -> str:
    if ue.smc is None:
        return "an algorithm set up outside this capture"
    algos = _ints(ue.smc, "nas-5gs.mm.nas_sec_algo_enc")
    return NEA.get(algos[0], f"algorithm {algos[0]}") if algos else "an unknown algorithm"


@rule("nas5g.ciphered")
def ciphered_nas(ctx: Context) -> Iterator[Finding]:
    ues = {k: ue for k, ue in _ues(ctx).items() if ue.unreadable}
    if not ues:
        return
    total = sum(ue.unreadable for ue in ues.values())
    algorithms = sorted({_algorithm(ue) for ue in ues.values()})
    group = _Group(
        verdict=f"5G NAS is ciphered: {total} NAS message{'s' if total > 1 else ''} could "
        "not be read.",
        why=f"After security setup the NAS messages of {len(ues)} UE"
        f"{'s are' if len(ues) > 1 else ' is'} encrypted ({', '.join(algorithms)}), so "
        "Registration and PDU session accepts or rejects inside them cannot be seen. "
        "Findings about these UEs are inferred from NGAP, which is not encrypted.",
        fix="To read the NAS messages, capture in a lab with null ciphering (NEA0), or use the "
        "AMF/SMF logs or NAS traces for the UE.",
        severity=Severity.INFO,
    )
    if any("NEA0" in a for a in algorithms):
        group.fix = (
            "The network uses null ciphering (NEA0), so these messages are readable: use "
            "Wireshark/tshark 4.x, which has the 'nas-5gs.null_decipher' preference capsight "
            "turns on."
        )
    for ue in ues.values():
        evidence = [p for p in (ue.smc, ue.first_unreadable) if p is not None]
        _add(group, evidence, ctx.imsi_of(ue.first))
    group.count = 1  # one observation about the capture
    yield from _emit("nas5g.ciphered", {"ciphered": group})


@rule("nas5g.ciphered.registration")
def registration_not_completed(ctx: Context) -> Iterator[Finding]:
    groups: dict[object, _Group] = {}
    for ue in _ues(ctx).values():
        if not ue.unreadable or ue.ics is not None or ue.release is None:
            continue
        if ue.first_unreadable is None or ue.release.number < ue.first_unreadable.number:
            continue
        cause, _ = ngap_cause(ue.release)
        if cause not in groups:
            groups[cause] = _Group(
                verdict="Registration did not complete (NAS ciphered; the reject is not visible).",
                why="The UE passed security setup and exchanged ciphered NAS messages, but "
                "the AMF never set up its context (no Initial Context Setup) and released it "
                f"(UE Context Release Command, cause {cause}).",
                fix="The Registration Reject, if any, is inside the ciphered NAS. Check the "
                "AMF log for this UE at that time: after security setup, typical causes are "
                "the subscription in the UDM (not allowed in this PLMN or tracking area) or "
                "the requested slices (S-NSSAI not allowed).",
                severity=Severity.FAILURE,
            )
        _add(groups[cause], [ue.first_unreadable, ue.release], ctx.imsi_of(ue.first))
    yield from _emit("nas5g.ciphered.registration", groups)


@rule("nas5g.ciphered.session")
def no_pdu_session(ctx: Context) -> Iterator[Finding]:
    group: _Group | None = None
    for ue in _ues(ctx).values():
        if ue.ics is None or ue.pdu_setup is not None:
            continue
        if ue.uplink_count_after_ics < MIN_UPLINK_AFTER_REGISTRATION:
            continue
        if not ue.downlink_after_uplink:
            continue
        if group is None:
            group = _Group(
                verdict="Registered, but no PDU session was set up (NAS ciphered).",
                why="The AMF accepted the registration (Initial Context Setup), then the UE "
                "sent more ciphered NAS messages, where a PDU Session Establishment Request "
                "travels, and the network answered in ciphered NAS. No PDU Session Resource "
                "Setup followed, so no data session was created.",
                fix="The answer was most likely a PDU session reject inside the ciphered NAS. "
                "Check the AMF and SMF logs for this UE: a DNN not in the subscription, a "
                "slice not allowed, or no SMF selected are typical causes.",
                severity=Severity.WARNING,
            )
        evidence = [ue.ics, *ue.uplink_after_ics[:2]]
        _add(group, evidence, ctx.imsi_of(ue.first))
    if group is not None:
        yield from _emit("nas5g.ciphered.session", {"session": group})
