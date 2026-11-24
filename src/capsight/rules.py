"""Deterministic diagnosis rules. Rules decide; nothing here guesses.

Each rule takes the analysis context and yields Findings that cite packet numbers.
Repeated occurrences of the same failure are grouped into one Finding.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

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
from capsight.correlate import Transaction, to_int
from capsight.model import Finding, Packet, Severity

MAX_EVIDENCE = 5
ESM_PDN_CONNECTIVITY_REJECT = 0xD1


@dataclass
class Context:
    packets: list[Packet]
    diameter: list[Transaction]
    gtpv2: list[Transaction]
    capture_end: float
    answer_timeout: float = 5.0
    inferred_imsi: dict[int, str] = field(default_factory=dict)

    def imsi_of(self, packet: Packet) -> str | None:
        return packet.first("e212.imsi") or self.inferred_imsi.get(packet.number)


@dataclass
class _Group:
    verdict: str
    why: str
    fix: str
    severity: Severity
    evidence: list[int] = field(default_factory=list)
    imsis: set[str] = field(default_factory=set)
    count: int = 0


Rule = Callable[[Context], Iterator[Finding]]
RULES: list[tuple[str, Rule]] = []


def rule(rule_id: str) -> Callable[[Rule], Rule]:
    def register(fn: Rule) -> Rule:
        RULES.append((rule_id, fn))
        return fn

    return register


def _emit(rule_id: str, groups: dict[object, _Group]) -> Iterator[Finding]:
    for group in groups.values():
        why = group.why
        if group.count > 1:
            why += f" Seen {group.count} times"
            if len(group.imsis) > 1:
                why += f" across {len(group.imsis)} subscribers"
            why += "."
        yield Finding(
            rule_id=rule_id,
            severity=group.severity,
            verdict=group.verdict,
            why=why,
            evidence=tuple(group.evidence[:MAX_EVIDENCE]),
            fix=group.fix,
            subscribers=tuple(sorted(group.imsis)),
            count=group.count,
        )


def _add(group: _Group, packets: list[Packet], imsi: str | None) -> None:
    group.count += 1
    group.evidence.extend(p.number for p in packets)
    if imsi:
        group.imsis.add(imsi)


@rule("diameter.result")
def diameter_failures(ctx: Context) -> Iterator[Finding]:
    groups: dict[object, _Group] = {}
    for tx in ctx.diameter:
        if tx.answer is None:
            continue
        exp = to_int(tx.answer.first("diameter.Experimental-Result-Code"))
        res = to_int(tx.answer.first("diameter.Result-Code"))
        if exp is not None and exp >= 3000:
            code, kind = lookup(DIAMETER_EXPERIMENTAL, exp), "Experimental-Result-Code"
            value = exp
        elif res is not None and res >= 3000:
            code, kind = lookup(DIAMETER_RESULT, res), "Result-Code"
            value = res
        else:
            continue
        answer_name = tx.name[:-1] + "A" if tx.name.endswith("R") else tx.name
        key = (tx.name, kind, value)
        if key not in groups:
            groups[key] = _Group(
                verdict=f"{tx.name} rejected: {code.name}.",
                why=f"{answer_name} carried {kind} {value} ({code.name}).",
                fix=code.hint,
                severity=Severity.FAILURE,
            )
        _add(groups[key], [p for p in (tx.request, tx.answer) if p], tx.imsi)
    yield from _emit("diameter.result", groups)


@rule("diameter.unanswered")
def diameter_unanswered(ctx: Context) -> Iterator[Finding]:
    groups: dict[object, _Group] = {}
    for tx in ctx.diameter:
        if tx.answer is not None or tx.request is None:
            continue
        if ctx.capture_end - tx.request.time < ctx.answer_timeout:
            continue  # capture ended too soon to call it a timeout
        if tx.name not in groups:
            groups[tx.name] = _Group(
                verdict=f"{tx.name} never answered.",
                why=f"No answer to {tx.name} within {ctx.answer_timeout:g} s.",
                fix="The peer or a routing agent dropped the request. Check the Diameter "
                "connection state and routing for the destination realm.",
                severity=Severity.FAILURE,
            )
        _add(groups[tx.name], [tx.request], tx.imsi)
    yield from _emit("diameter.unanswered", groups)


@rule("gtpv2.cause")
def gtpv2_rejects(ctx: Context) -> Iterator[Finding]:
    groups: dict[object, _Group] = {}
    for tx in ctx.gtpv2:
        if tx.answer is None:
            continue
        cause = to_int(tx.answer.first("gtpv2.cause"))
        if cause is None or 16 <= cause <= 63:
            continue
        code = lookup(GTPV2_CAUSE, cause)
        key = (tx.name, cause)
        if key not in groups:
            apn = tx.request.first("gtpv2.apn") if tx.request else None
            why = f"Response carried cause {cause} ({code.name})"
            why += f" for APN {apn}." if apn else "."
            groups[key] = _Group(
                verdict=f"{tx.name} rejected: {code.name}.",
                why=why,
                fix=code.hint,
                severity=Severity.FAILURE,
            )
        _add(groups[key], [p for p in (tx.request, tx.answer) if p], tx.imsi)
    yield from _emit("gtpv2.cause", groups)


@rule("gtpv2.unanswered")
def gtpv2_unanswered(ctx: Context) -> Iterator[Finding]:
    groups: dict[object, _Group] = {}
    for tx in ctx.gtpv2:
        if tx.answer is not None or tx.request is None:
            continue
        if ctx.capture_end - tx.request.time < ctx.answer_timeout:
            continue
        if tx.name not in groups:
            groups[tx.name] = _Group(
                verdict=f"{tx.name} never answered.",
                why=f"No response within {ctx.answer_timeout:g} s.",
                fix="The peer gateway is unreachable or dropping requests. Check the path "
                "(GTP-C on UDP 2123) and the peer's health.",
                severity=Severity.FAILURE,
            )
        _add(groups[tx.name], [tx.request], tx.imsi)
    yield from _emit("gtpv2.unanswered", groups)


@rule("nas.emm.reject")
def nas_rejects(ctx: Context) -> Iterator[Finding]:
    groups: dict[object, _Group] = {}
    for packet in ctx.packets:
        if not packet.has("nas-eps"):
            continue
        mtype = to_int(packet.first("nas-eps.nas_msg_emm_type"))
        if mtype in EMM_REJECTS:
            cause = to_int(packet.first("nas-eps.emm.cause"))
            if cause is None:
                continue
            code = lookup(EMM_CAUSE, cause)
            name = EMM_MESSAGES[mtype]
            key = (mtype, cause)
            if key not in groups:
                groups[key] = _Group(
                    verdict=f"{name}: {code.name}.",
                    why=f"The network sent {name} with EMM cause #{cause} ({code.name}).",
                    fix=code.hint,
                    severity=Severity.FAILURE,
                )
            _add(groups[key], [packet], ctx.imsi_of(packet))
        elif mtype == 0x5C:  # Authentication Failure, sent by the UE
            cause = to_int(packet.first("nas-eps.emm.cause"))
            if cause is None:
                continue
            code = lookup(AUTH_FAILURE_CAUSE, cause)
            imsi = ctx.imsi_of(packet)
            recovered = cause == 21 and _auth_recovered(ctx, packet, imsi)
            key = ("auth", cause, recovered)
            if key not in groups:
                if recovered:
                    groups[key] = _Group(
                        verdict="Sequence-number resync, then authentication succeeded.",
                        why=f"The device sent Authentication Failure, cause #{cause} "
                        f"({code.name}), and the next Authentication Response succeeded.",
                        fix="No action. This is normal on a SIM's first attach to a network "
                        "and after the HSS loses SQN state.",
                        severity=Severity.INFO,
                    )
                else:
                    groups[key] = _Group(
                        verdict=f"Device rejected network authentication: {code.name}.",
                        why=f"The device sent Authentication Failure, cause #{cause} "
                        f"({code.name}).",
                        fix=code.hint,
                        severity=Severity.WARNING if cause == 21 else Severity.FAILURE,
                    )
            _add(groups[key], [packet], imsi)
    yield from _emit("nas.emm.reject", groups)


@rule("nas.esm.reject")
def esm_rejects(ctx: Context) -> Iterator[Finding]:
    groups: dict[object, _Group] = {}
    for packet in ctx.packets:
        if not packet.has("nas-eps"):
            continue
        if to_int(packet.first("nas-eps.nas_msg_esm_type")) != ESM_PDN_CONNECTIVITY_REJECT:
            continue
        cause = to_int(packet.first("nas-eps.esm.cause"))
        if cause is None:
            continue
        code = lookup(ESM_CAUSE, cause)
        if cause not in groups:
            groups[cause] = _Group(
                verdict=f"PDN connectivity rejected: {code.name}.",
                why=f"The network sent PDN Connectivity Reject, ESM cause #{cause} ({code.name}).",
                fix=code.hint,
                severity=Severity.FAILURE,
            )
        _add(groups[cause], [packet], ctx.imsi_of(packet))
    yield from _emit("nas.esm.reject", groups)


AUTH_RESPONSE = 0x53


def _auth_recovered(ctx: Context, failure: Packet, imsi: str | None) -> bool:
    """True if the same UE sends a successful Authentication Response after `failure`."""
    enb_id = failure.first("s1ap.ENB_UE_S1AP_ID")
    for packet in ctx.packets:
        if packet.number <= failure.number or not packet.has("nas-eps"):
            continue
        if to_int(packet.first("nas-eps.nas_msg_emm_type")) != AUTH_RESPONSE:
            continue
        same_ue = (imsi is not None and ctx.imsi_of(packet) == imsi) or (
            enb_id is not None and packet.first("s1ap.ENB_UE_S1AP_ID") == enb_id
        )
        if same_ue:
            return True
    return False


def run_rules(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for _rule_id, fn in RULES:
        findings.extend(fn(ctx))
    order = {Severity.FAILURE: 0, Severity.WARNING: 1, Severity.INFO: 2}
    return sorted(findings, key=lambda f: (order[f.severity], f.evidence[0] if f.evidence else 0))
