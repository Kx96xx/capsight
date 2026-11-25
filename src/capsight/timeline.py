"""Per-subscriber view: one subscriber's procedures in order, and where they broke."""

from __future__ import annotations

import re
from dataclasses import dataclass

from capsight.codes import (
    AUTH_FAILURE_CAUSE,
    DIAMETER_EXPERIMENTAL,
    DIAMETER_RESULT,
    EMM_CAUSE,
    EMM_MESSAGES,
    EMM_REJECTS,
    ESM_CAUSE,
    GTPV2_CAUSE,
    lookup,
)
from capsight.codes_5g import MM_CAUSE, MM_MESSAGES, MM_REJECTS, SM_CAUSE, SM_REJECTS
from capsight.correlate import Transaction, to_int
from capsight.model import Finding, Packet
from capsight.rules import Context, is_pcc
from capsight.rules_pcc import _result as pcc_result
from capsight.rules_pcc import interface as pcc_interface
from capsight.rules_pcc import label as pcc_label

OK, FAILED, NO_ANSWER, INFO = "ok", "failed", "no answer", "info"

ESM_MESSAGES: dict[int, str] = {
    0xC1: "Activate Default EPS Bearer Context Request",
    0xC2: "Activate Default EPS Bearer Context Accept",
    0xC3: "Activate Default EPS Bearer Context Reject",
    0xC5: "Activate Dedicated EPS Bearer Context Request",
    0xCD: "Deactivate EPS Bearer Context Request",
    0xD0: "PDN Connectivity Request",
    0xD1: "PDN Connectivity Reject",
    0xD2: "PDN Disconnect Request",
    0xD9: "ESM Information Request",
    0xDA: "ESM Information Response",
}
ESM_REJECTS = {0xC3, 0xD1}

SM_MESSAGES: dict[int, str] = {
    0xC1: "PDU Session Establishment Request",
    0xC2: "PDU Session Establishment Accept",
    0xC9: "PDU Session Modification Request",
    0xCC: "PDU Session Modification Command",
    0xD1: "PDU Session Release Request",
    0xD3: "PDU Session Release Command",
    **SM_REJECTS,
}

EMM_AUTH_FAILURE = 0x5C
MM_AUTH_FAILURE = 0x59
MM_STATUS_LIKE = {0x64, 0x68}
SYNC_FAILURE = 21  # same value in EMM and 5GMM; the network normally resyncs and retries


@dataclass(frozen=True)
class Step:
    """One procedure (request/answer pair) or one NAS message for the subscriber."""

    time: float
    packets: tuple[int, ...]
    protocol: str
    name: str
    status: str
    detail: str = ""


def _pcc_step(tx: Transaction, ctx: Context, packets: tuple[int, ...]) -> Step:
    """Gx/Gy step, named by interface and request type (e.g. "Gy CCR-I")."""
    first = tx.first_packet
    name = pcc_label(tx)
    if tx.answer is None:
        return Step(first.time, packets, "diameter", name, _missing(ctx, first), "")
    failed = pcc_result(tx.answer, pcc_interface(tx))
    if failed is not None:
        value, _kind, code = failed
        return Step(first.time, packets, "diameter", name, FAILED, f"{code.name} ({value})")
    return Step(first.time, packets, "diameter", name, OK, "")


def normalize_imsi(value: str) -> str:
    """Accept 001010000000001, imsi-001010000000001 or 001 01 0000000001."""
    return re.sub(r"\D", "", value.removeprefix("imsi-"))


def _diameter_step(tx: Transaction, ctx: Context) -> Step:
    request = tx.request
    first = tx.first_packet
    answer_name = tx.name[:-1] + "A" if tx.name.endswith("R") else "answer"
    packets = tuple(p.number for p in (request, tx.answer) if p)
    if is_pcc(tx):
        return _pcc_step(tx, ctx, packets)
    if tx.answer is None:
        return Step(first.time, packets, "diameter", tx.name, _missing(ctx, first), "")
    exp = to_int(tx.answer.first("diameter.Experimental-Result-Code"))
    res = to_int(tx.answer.first("diameter.Result-Code"))
    if exp is not None and exp >= 3000:
        code = lookup(DIAMETER_EXPERIMENTAL, exp)
        return Step(
            first.time,
            packets,
            "diameter",
            f"{tx.name} -> {answer_name}",
            FAILED,
            f"{code.name} ({exp})",
        )
    if res is not None and res >= 3000:
        code = lookup(DIAMETER_RESULT, res)
        return Step(
            first.time,
            packets,
            "diameter",
            f"{tx.name} -> {answer_name}",
            FAILED,
            f"{code.name} ({res})",
        )
    value = exp if exp is not None else res
    return Step(
        first.time,
        packets,
        "diameter",
        f"{tx.name} -> {answer_name}",
        OK,
        str(value) if value is not None else "",
    )


def _gtpv2_step(tx: Transaction, ctx: Context) -> Step:
    first = tx.first_packet
    packets = tuple(p.number for p in (tx.request, tx.answer) if p)
    name = tx.name.removesuffix(" Request")
    n = tx.retransmissions
    retx = f", {n} retransmission{'s' if n != 1 else ''}" if n else ""
    apn = tx.request.first("gtpv2.apn") if tx.request else None
    apn_text = f"APN {apn}" if apn else ""
    if tx.answer is None:
        detail = ", ".join(x for x in (apn_text, retx.lstrip(", ")) if x)
        return Step(first.time, packets, "gtpv2", name, _missing(ctx, first), detail)
    cause = to_int(tx.answer.first("gtpv2.cause"))
    if cause is None:
        return Step(first.time, packets, "gtpv2", name, INFO, apn_text)
    code = lookup(GTPV2_CAUSE, cause)
    status = OK if 16 <= cause <= 63 else FAILED
    detail = f"cause {cause} ({code.name})"
    if apn_text:
        detail = f"{apn_text}, {detail}"
    return Step(first.time, packets, "gtpv2", name, status, detail + retx)


def _missing(ctx: Context, request: Packet) -> str:
    waited = ctx.capture_end - request.time
    return NO_ANSWER if waited >= ctx.answer_timeout else INFO


def _nas_eps_steps(packet: Packet) -> list[Step]:
    steps = []
    emm = to_int(packet.first("nas-eps.nas_msg_emm_type"))
    if emm is not None:
        name = EMM_MESSAGES.get(emm, f"EMM message 0x{emm:02x}")
        cause = to_int(packet.first("nas-eps.emm.cause"))
        if emm in EMM_REJECTS or emm == 0x54:
            detail = f"EMM cause #{cause} ({lookup(EMM_CAUSE, cause).name})" if cause else ""
            steps.append(Step(packet.time, (packet.number,), "nas", name, FAILED, detail))
        elif emm == EMM_AUTH_FAILURE:
            detail = f"cause #{cause} ({lookup(AUTH_FAILURE_CAUSE, cause).name})" if cause else ""
            status = INFO if cause == SYNC_FAILURE else FAILED
            steps.append(Step(packet.time, (packet.number,), "nas", name, status, detail))
        else:
            steps.append(Step(packet.time, (packet.number,), "nas", name, OK))
    esm = to_int(packet.first("nas-eps.nas_msg_esm_type"))
    if esm is not None:
        name = ESM_MESSAGES.get(esm, f"ESM message 0x{esm:02x}")
        cause = to_int(packet.first("nas-eps.esm.cause"))
        if esm in ESM_REJECTS:
            detail = f"ESM cause #{cause} ({lookup(ESM_CAUSE, cause).name})" if cause else ""
            steps.append(Step(packet.time, (packet.number,), "nas", name, FAILED, detail))
        else:
            steps.append(Step(packet.time, (packet.number,), "nas", name, OK))
    return steps


def _nas_5gs_steps(packet: Packet) -> list[Step]:
    steps = []
    mm_causes = packet.fields.get("nas-5gs.mm.5gmm_cause", [])
    mm_cause = to_int(mm_causes[0]) if mm_causes else None
    for raw in packet.fields.get("nas-5gs.mm.message_type", []):
        mtype = to_int(raw)
        if mtype is None or mtype in (0x67, 0x68) and mm_cause is None:
            continue  # NAS transport containers: the 5GSM message inside is listed instead
        name = MM_MESSAGES.get(mtype, f"5GMM message 0x{mtype:02x}")
        failed = (
            mtype in MM_REJECTS
            or mtype in (0x58, MM_AUTH_FAILURE)
            or (mtype in MM_STATUS_LIKE and mm_cause is not None)
        )
        detail = ""
        if failed and mm_cause is not None:
            detail = f"5GMM cause #{mm_cause} ({lookup(MM_CAUSE, mm_cause).name})"
        steps.append(
            Step(packet.time, (packet.number,), "nas-5g", name, FAILED if failed else OK, detail)
        )
    sm_causes = packet.fields.get("nas-5gs.sm.5gsm_cause", [])
    for raw in packet.fields.get("nas-5gs.sm.message_type", []):
        mtype = to_int(raw)
        if mtype is None:
            continue
        name = SM_MESSAGES.get(mtype, f"5GSM message 0x{mtype:02x}")
        dnn = packet.first("nas-5gs.cmn.dnn")
        detail = f"DNN {dnn}" if dnn else ""
        if mtype in SM_REJECTS:
            cause = to_int(sm_causes[0]) if sm_causes else None
            if cause is not None:
                detail = f"5GSM cause #{cause} ({lookup(SM_CAUSE, cause).name})"
            steps.append(Step(packet.time, (packet.number,), "nas-5g", name, FAILED, detail))
        else:
            steps.append(Step(packet.time, (packet.number,), "nas-5g", name, OK, detail))
    return steps


def subscriber_timeline(ctx: Context, imsi: str) -> list[Step]:
    steps: list[Step] = []
    for tx in ctx.diameter:
        if tx.imsi == imsi:
            steps.append(_diameter_step(tx, ctx))
    for tx in ctx.gtpv2:
        if tx.imsi == imsi:
            steps.append(_gtpv2_step(tx, ctx))
    for packet in ctx.packets:
        if ctx.imsi_of(packet) != imsi:
            continue
        if packet.has("nas-eps"):
            steps.extend(_nas_eps_steps(packet))
        if packet.has("nas-5gs"):
            steps.extend(_nas_5gs_steps(packet))
    return sorted(steps, key=lambda s: (s.packets[0], s.time))


def subscribers_seen(ctx: Context) -> list[str]:
    seen: dict[str, None] = {}
    for tx in (*ctx.diameter, *ctx.gtpv2):
        if tx.imsi:
            seen.setdefault(tx.imsi)
    for packet in ctx.packets:
        imsi = ctx.imsi_of(packet)
        if imsi:
            seen.setdefault(imsi)
    return [i for i in seen if i.isdigit()]


def findings_for(findings: list[Finding], imsi: str, steps: list[Step]) -> list[Finding]:
    """Findings that name the subscriber, or that cite one of its packets."""
    own = {n for s in steps for n in s.packets}
    return [f for f in findings if imsi in f.subscribers or own & set(f.evidence)]
