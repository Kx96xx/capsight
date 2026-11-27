"""Policy and charging rules: Gx (PCRF) and Gy (online charging).

A session can be fully authorised by the HSS and still get no data because the policy server
or the charging system said no. These rules explain those answers:

- pcc.result      the PCRF/OCS rejected a CCR (or the gateway rejected a Gx RAR)
- pcc.credit      the answer was accepted overall, but a service (rating group) got no credit
- pcc.rule        the gateway could not install a policy rule the PCRF sent
"""

from __future__ import annotations

from collections.abc import Iterator

from capsight.codes import DIAMETER_EXPERIMENTAL, DIAMETER_RESULT, Code, lookup
from capsight.codes_pcc import (
    CC_INITIAL,
    CC_REQUEST_TYPE,
    FINAL_UNIT_ACTION,
    IMPACT,
    INTERFACE,
    NOT_A_FAILURE,
    PCC_RULE_STATUS,
    RAR,
    RULE_FAILURE,
    pcc_code,
)
from capsight.correlate import Transaction, to_int
from capsight.model import Finding, Packet, Severity
from capsight.rules import Context, _add, _emit, _Group, application_of, is_pcc, rule
from capsight.session_links import claimed

GTP_LINK_WINDOW_S = 5.0
CREATE_SESSION = "Create Session Request"


def interface(tx: Transaction) -> str:
    return INTERFACE.get(application_of(tx) or 0, "Diameter")


def request_type(tx: Transaction) -> int | None:
    for packet in (tx.request, tx.answer):
        if packet is not None:
            value = to_int(packet.first("diameter.CC-Request-Type"))
            if value is not None:
                return value
    return None


def label(tx: Transaction) -> str:
    """e.g. "Gy CCR-I", "Gx CCR-U", "Gx RAR"."""
    kind = CC_REQUEST_TYPE.get(request_type(tx) or 0) if tx.name == "CCR" else None
    return f"{interface(tx)} {kind or tx.name}"


def _result(answer: Packet, interface_name: str) -> tuple[int, str, Code] | None:
    """The answer's top-level failure: (value, kind, code), or None when it succeeded."""
    exp = to_int(answer.first("diameter.Experimental-Result-Code"))
    if exp is not None and exp >= 3000:
        return (
            exp,
            "Experimental-Result-Code",
            pcc_code(exp, interface_name) or lookup(DIAMETER_EXPERIMENTAL, exp),
        )
    res = to_int(answer.first("diameter.Result-Code"))
    if res is not None and res >= 3000 and res not in NOT_A_FAILURE:
        return res, "Result-Code", pcc_code(res, interface_name) or lookup(DIAMETER_RESULT, res)
    return None


def _gtp_reject_after(ctx: Context, tx: Transaction) -> Transaction | None:
    """The Create Session reject the gateway sent because of this failed CCR-I, if captured."""
    answer = tx.answer
    if answer is None:
        return None
    for gtp in ctx.gtpv2:
        if gtp.name != CREATE_SESSION or gtp.answer is None:
            continue
        if tx.imsi and gtp.imsi and gtp.imsi != tx.imsi:
            continue
        cause = to_int(gtp.answer.first("gtpv2.cause"))
        if cause is None or 16 <= cause <= 63:
            continue
        if 0 <= gtp.answer.time - answer.time <= GTP_LINK_WINDOW_S:
            return gtp
    return None


def _apn(tx: Transaction) -> str | None:
    return tx.request.first("diameter.Called-Station-Id") if tx.request else None


@rule("pcc.result")
def pcc_rejects(ctx: Context) -> Iterator[Finding]:
    groups: dict[object, _Group] = {}
    for tx in ctx.diameter:
        if tx.answer is None or not is_pcc(tx) or claimed(ctx, tx):
            continue
        name = interface(tx)
        failed = _result(tx.answer, name)
        if failed is None:
            continue
        value, kind, code = failed
        what = label(tx)
        rtype = request_type(tx)
        gtp = _gtp_reject_after(ctx, tx) if rtype == CC_INITIAL else None
        key = (what, value, gtp is not None)
        if key not in groups:
            answer = "RAA from the gateway" if tx.name == "RAR" else f"{name} answer"
            why = f"The {answer} carried {kind} {value} ({code.name})"
            apn = _apn(tx)
            why += f" for APN {apn}." if apn else "."
            if rtype in IMPACT:
                why += " " + IMPACT[rtype]
            if gtp is not None and gtp.answer is not None:
                cause = to_int(gtp.answer.first("gtpv2.cause"))
                why += (
                    f" The gateway then rejected the session (Create Session Response cause "
                    f"{cause}, packet #{gtp.answer.number}): that reject is a consequence of "
                    f"this {name} answer, not a separate problem."
                )
            groups[key] = _Group(
                verdict=f"{what} rejected: {code.name}.",
                why=why,
                fix=code.hint,
                severity=Severity.WARNING if rtype == 3 else Severity.FAILURE,
            )
        _add(groups[key], [p for p in (tx.request, tx.answer) if p], tx.imsi)
    yield from _emit("pcc.result", groups)


def _service_results(answer: Packet) -> list[tuple[int | None, int]]:
    """(rating group, result code) for each service in a credit-control answer.

    tshark lists Result-Code values in message order: the top-level one first (RFC 4006
    puts it before Multiple-Services-Credit-Control), then one per service that carries
    its own. Only an unambiguous layout is paired with rating groups.
    """
    results = [to_int(v) for v in answer.fields.get("diameter.Result-Code", [])]
    groups = [to_int(v) for v in answer.fields.get("diameter.Rating-Group", [])]
    has_top = answer.first("diameter.Experimental-Result-Code") is None
    per_service = results[1:] if has_top else results
    if len(per_service) == len(groups):
        return [(g, r) for g, r in zip(groups, per_service, strict=True) if r is not None]
    return [(None, r) for r in per_service if r is not None]


@rule("pcc.credit")
def pcc_service_credit(ctx: Context) -> Iterator[Finding]:
    groups: dict[object, _Group] = {}
    for tx in ctx.diameter:
        if tx.answer is None or interface(tx) != "Gy" or _result(tx.answer, "Gy"):
            continue  # whole-answer rejects are reported by pcc.result
        actions = {to_int(v) for v in tx.answer.fields.get("diameter.Final-Unit-Action", [])}
        for group_id, value in _service_results(tx.answer):
            if value < 3000 or value in NOT_A_FAILURE:
                continue
            code = pcc_code(value, "Gy") or lookup(DIAMETER_RESULT, value)
            service = f"rating group {group_id}" if group_id is not None else "a service"
            key = (group_id, value)
            if key not in groups:
                why = (
                    f"The Gy answer succeeded overall, but {service} got Result-Code {value} "
                    f"({code.name}) inside Multiple-Services-Credit-Control. Other services "
                    "on the same session keep working; traffic charged to this one is "
                    "blocked or restricted."
                )
                notes = [
                    FINAL_UNIT_ACTION[a] for a in sorted(actions - {None}) if a in FINAL_UNIT_ACTION
                ]
                if notes:
                    why += " Final-Unit-Action " + "; ".join(f"{n}: {d}" for n, d in notes) + "."
                groups[key] = _Group(
                    verdict=f"Gy: no service for {service}: {code.name}.",
                    why=why,
                    fix=code.hint,
                    severity=Severity.FAILURE,
                )
            _add(groups[key], [p for p in (tx.request, tx.answer) if p], tx.imsi)
    yield from _emit("pcc.credit", groups)


def _rule_name(raw: str) -> str:
    """Charging-Rule-Name is an OctetString: tshark shows it as hex."""
    try:
        text = bytes.fromhex(raw).decode()
    except ValueError:
        return raw
    return text if text.isprintable() else raw


@rule("pcc.rule")
def pcc_rule_failures(ctx: Context) -> Iterator[Finding]:
    groups: dict[object, _Group] = {}
    for tx in ctx.diameter:
        if interface(tx) != "Gx":
            continue
        for packet in (tx.request, tx.answer):
            if packet is None:
                continue
            codes = [to_int(v) for v in packet.fields.get("diameter.Rule-Failure-Code", [])]
            if not codes:
                continue
            names = [_rule_name(v) for v in packet.fields.get("diameter.Charging-Rule-Name", [])]
            status = to_int(packet.first("diameter.PCC-Rule-Status"))
            paired = names if len(names) == len(codes) else [None] * len(codes)
            for rule_name, value in zip(paired, codes, strict=True):
                if value is None:
                    continue
                code = lookup(RULE_FAILURE, value)
                key = (rule_name, value)
                if key not in groups:
                    which = f"'{rule_name}'" if rule_name else "(name not in the report)"
                    why = (
                        f"The gateway reported Charging-Rule-Report for rule {which} with "
                        f"Rule-Failure-Code {value} ({code.name})"
                    )
                    if status in PCC_RULE_STATUS:
                        why += f", rule status {PCC_RULE_STATUS[status]}"
                    why += (
                        ". The PCRF decided on this rule, but the gateway could not enforce "
                        "it, so the service it was for (often a dedicated bearer such as "
                        "voice) does not get its QoS or does not work."
                    )
                    groups[key] = _Group(
                        verdict=f"Policy rule {which} not installed: {code.name}.",
                        why=why,
                        fix=code.hint,
                        severity=Severity.FAILURE,
                    )
                _add(groups[key], [packet], tx.imsi)
    yield from _emit("pcc.rule", groups)


__all__ = ["label", "RAR"]
