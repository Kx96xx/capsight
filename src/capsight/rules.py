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
from capsight.correlate import Transaction, to_bool, to_int
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
    retransmissions: int = 0


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
        if group.retransmissions:
            why += (
                f" Plus {group.retransmissions} retransmitted copies, not counted as "
                "separate failures."
            )
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


ONE_WAY_MIN_REQUESTS = 20
ONE_WAY_MAX_ANSWER_RATIO = 0.05


def _unanswered(
    ctx: Context,
    txs: list[Transaction],
    rule_id: str,
    fix: str,
) -> Iterator[Finding]:
    """Requests with no answer, unless the capture simply does not contain the answers.

    If a command type has many requests and almost no answers at all, the capture is most
    likely one-directional (filtered on one host, one side of a mirror port). Reporting
    thousands of timeouts would be wrong, so that case becomes a single warning.
    """
    requests: dict[str, int] = {}
    answers: dict[str, int] = {}
    for tx in txs:
        if tx.request is not None:
            requests[tx.name] = requests.get(tx.name, 0) + 1
            if tx.answer is not None:
                answers[tx.name] = answers.get(tx.name, 0) + 1
    one_way = {
        name
        for name, n in requests.items()
        if n >= ONE_WAY_MIN_REQUESTS and answers.get(name, 0) / n <= ONE_WAY_MAX_ANSWER_RATIO
    }
    groups: dict[object, _Group] = {}
    for tx in txs:
        if tx.answer is not None or tx.request is None:
            continue
        if ctx.capture_end - tx.request.time < ctx.answer_timeout:
            continue  # capture ended too soon to call it a timeout
        if tx.name in one_way:
            key = ("one_way", tx.name)
            if key not in groups:
                n, a = requests[tx.name], answers.get(tx.name, 0)
                groups[key] = _Group(
                    verdict=f"Capture looks one-directional for {tx.name}: answers are missing.",
                    why=f"{n} {tx.name} requests but only {a} answers in the whole capture. "
                    "That pattern means the answers were not captured (capture filtered on "
                    "one host or one direction), not that the peer stopped answering.",
                    fix="Capture both directions (both peers' addresses) before concluding "
                    "requests timed out.",
                    severity=Severity.WARNING,
                )
            _add(groups[key], [tx.request], tx.imsi)
            continue
        if tx.name not in groups:
            groups[tx.name] = _Group(
                verdict=f"{tx.name} never answered.",
                why=f"No answer to {tx.name} within {ctx.answer_timeout:g} s.",
                fix=fix,
                severity=Severity.FAILURE,
            )
        _add(groups[tx.name], [tx.request], tx.imsi)
    yield from _emit(rule_id, groups)


@rule("diameter.unanswered")
def diameter_unanswered(ctx: Context) -> Iterator[Finding]:
    yield from _unanswered(
        ctx,
        ctx.diameter,
        "diameter.unanswered",
        "The peer or a routing agent dropped the request. Check the Diameter connection "
        "state and routing for the destination realm.",
    )


PDN_TYPES = {1: "IPv4", 2: "IPv6", 3: "IPv4v6", 4: "non-IP", 5: "Ethernet"}
GTP_USER_AUTH_FAILED = 92
GTP_PDN_TYPE_NOT_SUPPORTED = 83
RADIUS_ACCESS_ACCEPT = 2
RADIUS_LOOKBACK_S = 2.0


def _cause_source(answer: Packet) -> str:
    """GTPv2 CS bit: 1 = the cause came from a node further down the path."""
    return "remote" if to_bool(answer.first("gtpv2.cs")) else "local"


def _radius_accept_before(ctx: Context, answer: Packet) -> Packet | None:
    """Most recent RADIUS Access-Accept within RADIUS_LOOKBACK_S before `answer`."""
    best = None
    for packet in ctx.packets:
        if packet.number >= answer.number:
            break
        if not packet.has("radius") or answer.time - packet.time > RADIUS_LOOKBACK_S:
            continue
        if to_int(packet.first("radius.code")) == RADIUS_ACCESS_ACCEPT:
            best = packet
    return best


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
        source = _cause_source(tx.answer)
        accept = _radius_accept_before(ctx, tx.answer) if cause == GTP_USER_AUTH_FAILED else None
        key = (tx.name, cause, source, accept is not None)
        if key not in groups:
            apn = tx.request.first("gtpv2.apn") if tx.request else None
            why = f"Response carried cause {cause} ({code.name})"
            why += f" for APN {apn}." if apn else "."
            why += (
                " The cause was raised by a node further down the path, not by the responder."
                if source == "remote"
                else " The responding node raised the cause itself."
            )
            fix = code.hint
            if accept is not None:
                why += (
                    f" RADIUS returned Access-Accept (packet #{accept.number}) just before, so "
                    "the credentials were accepted."
                )
                fix = (
                    "Not a credential problem: RADIUS accepted the user but the gateway still "
                    "refused the session. Compare this Access-Accept with one from a working "
                    "session on the same gateway; look for a missing or different attribute "
                    "(e.g. Framed-IP, Called-Station-Id, a vendor-specific policy)."
                )
            groups[key] = _Group(
                verdict=f"{tx.name} rejected: {code.name}.",
                why=why,
                fix=fix,
                severity=Severity.FAILURE,
            )
        group = groups[key]
        _add(group, [p for p in (tx.request, tx.answer) if p], tx.imsi)
        group.retransmissions += tx.retransmissions
    yield from _emit("gtpv2.cause", groups)


@rule("gtpv2.pdn_type")
def pdn_type_split(ctx: Context) -> Iterator[Finding]:
    """Same subscriber: one PDN type accepted, another rejected with cause 83."""
    accepted: dict[str, set[int]] = {}
    rejected: dict[str, list[Transaction]] = {}
    for tx in ctx.gtpv2:
        if tx.request is None or tx.answer is None or not tx.imsi:
            continue
        pdn_type = to_int(tx.request.first("gtpv2.pdn_type"))
        cause = to_int(tx.answer.first("gtpv2.cause"))
        if pdn_type is None or cause is None:
            continue
        if 16 <= cause <= 63:
            accepted.setdefault(tx.imsi, set()).add(pdn_type)
        elif cause == GTP_PDN_TYPE_NOT_SUPPORTED:
            rejected.setdefault(tx.imsi, []).append(tx)
    groups: dict[object, _Group] = {}
    for imsi, txs in rejected.items():
        ok_types = accepted.get(imsi, set())
        for tx in txs:
            assert tx.request is not None and tx.answer is not None
            bad = to_int(tx.request.first("gtpv2.pdn_type"))
            if bad in ok_types or not ok_types:
                continue
            ok_names = "/".join(PDN_TYPES.get(t, str(t)) for t in sorted(ok_types))
            bad_name = PDN_TYPES.get(bad, str(bad))
            key = (bad, tuple(sorted(ok_types)))
            if key not in groups:
                groups[key] = _Group(
                    verdict=f"{bad_name} sessions rejected while {ok_names} works.",
                    why=f"The same subscriber got cause 83 (Preferred PDN Type not supported) "
                    f"when requesting {bad_name}, and acceptance when requesting {ok_names}. "
                    "The failure follows the PDN type, not the APN or the subscription.",
                    fix=f"Either enable {bad_name} for this APN on the gateway, or set the "
                    f"device/APN profile to request {ok_names}.",
                    severity=Severity.FAILURE,
                )
            _add(groups[key], [tx.request, tx.answer], imsi)
    yield from _emit("gtpv2.pdn_type", groups)


@rule("gtpv2.unanswered")
def gtpv2_unanswered(ctx: Context) -> Iterator[Finding]:
    yield from _unanswered(
        ctx,
        ctx.gtpv2,
        "gtpv2.unanswered",
        "The peer gateway is unreachable or dropping requests. Check the path (GTP-C on "
        "UDP 2123) and the peer's health.",
    )


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
        imsi = ctx.imsi_of(packet)
        after_attach = _attach_accepted_before(ctx, packet, imsi)
        key = (cause, after_attach)
        if key not in groups:
            if after_attach:
                groups[key] = _Group(
                    verdict=f"Extra PDN connection rejected: {code.name}.",
                    why=f"The device attached and got its default bearer, then asked for an "
                    f"additional PDN connection, which was rejected with ESM cause #{cause} "
                    f"({code.name}). Data on the default APN works.",
                    fix=code.hint
                    or "Check which extra APN the device requests and whether the subscription "
                    "includes it.",
                    severity=Severity.WARNING,
                )
            else:
                groups[key] = _Group(
                    verdict=f"PDN connectivity rejected: {code.name}.",
                    why=f"The network sent PDN Connectivity Reject, ESM cause #{cause} "
                    f"({code.name}).",
                    fix=code.hint,
                    severity=Severity.FAILURE,
                )
        _add(groups[key], [packet], imsi)
    yield from _emit("nas.esm.reject", groups)


AUTH_RESPONSE = 0x53
ATTACH_ACCEPT = 0x42

# A more specific finding replaces a generic one that cites only the same packets.
SUPERSEDES = {"gtpv2.pdn_type": "gtpv2.cause"}


def _drop_superseded(findings: list[Finding]) -> list[Finding]:
    covered: dict[str, set[int]] = {}
    for f in findings:
        if f.rule_id in SUPERSEDES:
            covered.setdefault(SUPERSEDES[f.rule_id], set()).update(f.evidence)
    return [
        f for f in findings if not (f.rule_id in covered and set(f.evidence) <= covered[f.rule_id])
    ]


def _same_ue(ctx: Context, a: Packet, b: Packet, imsi: str | None) -> bool:
    enb_id = a.first("s1ap.ENB_UE_S1AP_ID")
    return (imsi is not None and ctx.imsi_of(b) == imsi) or (
        enb_id is not None and b.first("s1ap.ENB_UE_S1AP_ID") == enb_id
    )


def _attach_accepted_before(ctx: Context, packet: Packet, imsi: str | None) -> bool:
    for other in ctx.packets:
        if other.number >= packet.number:
            return False
        if (
            other.has("nas-eps")
            and to_int(other.first("nas-eps.nas_msg_emm_type")) == ATTACH_ACCEPT
            and _same_ue(ctx, packet, other, imsi)
        ):
            return True
    return False


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
    findings = _drop_superseded(findings)
    order = {Severity.FAILURE: 0, Severity.WARNING: 1, Severity.INFO: 2}
    return sorted(findings, key=lambda f: (order[f.severity], f.evidence[0] if f.evidence else 0))
