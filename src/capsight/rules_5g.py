"""5G SA rules: NGAP, 5G NAS (5GMM/5GSM), PFCP and GTP-U user plane."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterator

from capsight.codes import Code, lookup
from capsight.codes_5g import (
    MM_AUTH_FAILURE,
    MM_AUTH_REJECT,
    MM_AUTH_RESPONSE,
    MM_CAUSE,
    MM_DL_NAS_TRANSPORT,
    MM_MESSAGES,
    MM_REJECTS,
    MM_STATUS,
    NGAP_CAUSE,
    NGAP_CAUSE_GROUPS,
    NGAP_PROCEDURES,
    NGAP_UNSUCCESSFUL_OUTCOME,
    PFCP_CAUSE,
    SM_CAUSE,
    SM_ESTABLISHMENT_REQUEST,
    SM_REJECTS,
)
from capsight.correlate import to_int
from capsight.model import Finding, Packet, Severity
from capsight.rules import Context, _add, _emit, _Group, _unanswered, rule


def _ints(packet: Packet, name: str) -> list[int]:
    return [v for v in (to_int(x) for x in packet.fields.get(name, [])) if v is not None]


def _ue_key(packet: Packet) -> str | None:
    ids = packet.fields.get("ngap.RAN_UE_NGAP_ID", [])
    return ids[0] if ids else None


def _later(ctx: Context, after: Packet, ue: str | None, predicate) -> Packet | None:
    for packet in ctx.packets:
        if packet.number <= after.number or not packet.has("nas-5gs"):
            continue
        if ue is not None and _ue_key(packet) != ue:
            continue
        if predicate(packet):
            return packet
    return None


def _earlier(ctx: Context, before: Packet, ue: str | None, predicate) -> Packet | None:
    found = None
    for packet in ctx.packets:
        if packet.number >= before.number:
            break
        if packet.has("nas-5gs") and (ue is None or _ue_key(packet) == ue) and predicate(packet):
            found = packet
    return found


def ngap_cause(packet: Packet) -> tuple[str, Code | None]:
    """NGAP cause as "group=name" (e.g. "nas=deregister"), plus its code entry."""
    group_idx = (_ints(packet, "ngap.Cause") or [-1])[0]
    cause_group = NGAP_CAUSE_GROUPS[group_idx] if 0 <= group_idx < len(NGAP_CAUSE_GROUPS) else None
    value = (_ints(packet, f"ngap.{cause_group}") or [None])[0] if cause_group else None
    if cause_group and value is not None:
        code = lookup(NGAP_CAUSE.get(cause_group, {}), value)
        return f"{cause_group}={code.name}", code
    return "no cause decoded", None


@rule("ngap.failure")
def ngap_failures(ctx: Context) -> Iterator[Finding]:
    groups: dict[object, _Group] = {}
    for packet in ctx.packets:
        if not packet.has("ngap"):
            continue
        if NGAP_UNSUCCESSFUL_OUTCOME not in _ints(packet, "ngap.NGAP_PDU"):
            continue
        proc = (_ints(packet, "ngap.procedureCode") or [-1])[0]
        name = NGAP_PROCEDURES.get(proc, f"NGAP procedure {proc}")
        cause_text, code = ngap_cause(packet)
        key = (proc, cause_text)
        if key not in groups:
            groups[key] = _Group(
                verdict=f"{name} failed: {cause_text}.",
                why=f"The peer answered {name} with an unsuccessful outcome ({cause_text}).",
                fix=(code.hint if code else "")
                or "Compare the gNB and AMF configuration for this procedure.",
                severity=Severity.FAILURE,
            )
        _add(groups[key], [packet], None)
    yield from _emit("ngap.failure", groups)


@rule("nas5g.mm.reject")
def mm_rejects(ctx: Context) -> Iterator[Finding]:
    groups: dict[object, _Group] = {}
    for packet in ctx.packets:
        if not packet.has("nas-5gs"):
            continue
        types = _ints(packet, "nas-5gs.mm.message_type")
        causes = _ints(packet, "nas-5gs.mm.5gmm_cause")
        imsi = ctx.imsi_of(packet)
        ue = _ue_key(packet)
        for mtype in types:
            if mtype in MM_REJECTS and causes:
                cause = causes[0]
                code = lookup(MM_CAUSE, cause)
                name = MM_MESSAGES[mtype]
                key = ("reject", mtype, cause)
                if key not in groups:
                    groups[key] = _Group(
                        verdict=f"{name}: {code.name}.",
                        why=f"The AMF sent {name} with 5GMM cause #{cause} ({code.name}).",
                        fix=code.hint,
                        severity=Severity.FAILURE,
                    )
                _add(groups[key], [packet], imsi)
            elif mtype == MM_AUTH_FAILURE and causes:
                cause = causes[0]
                code = lookup(MM_CAUSE, cause)
                rejected = _later(
                    ctx, packet, ue, lambda p: MM_AUTH_REJECT in _ints(p, "nas-5gs.mm.message_type")
                )
                recovered = cause == 21 and _later(
                    ctx,
                    packet,
                    ue,
                    lambda p: MM_AUTH_RESPONSE in _ints(p, "nas-5gs.mm.message_type"),
                )
                key = ("auth", cause, bool(recovered))
                if key not in groups:
                    if recovered:
                        groups[key] = _Group(
                            verdict="Sequence-number resync, then authentication succeeded.",
                            why=f"The device sent Authentication Failure, cause #{cause} "
                            f"({code.name}), and the next Authentication Response succeeded.",
                            fix="No action. This is normal on a SIM's first registration and "
                            "after the UDM loses SQN state.",
                            severity=Severity.INFO,
                        )
                    else:
                        why = (
                            f"The device sent Authentication Failure, cause #{cause} ({code.name})."
                        )
                        if rejected is not None:
                            why += (
                                f" The network then sent Authentication Reject "
                                f"(packet #{rejected.number})."
                            )
                        groups[key] = _Group(
                            verdict=f"Device rejected network authentication: {code.name}.",
                            why=why,
                            fix=code.hint,
                            severity=Severity.WARNING if cause == 21 else Severity.FAILURE,
                        )
                _add(groups[key], [packet], imsi)
            elif mtype in (MM_STATUS, MM_DL_NAS_TRANSPORT) and causes:
                cause = causes[0]
                code = lookup(MM_CAUSE, cause)
                request = _earlier(
                    ctx,
                    packet,
                    ue,
                    lambda p: SM_ESTABLISHMENT_REQUEST in _ints(p, "nas-5gs.sm.message_type"),
                )
                dnn = request.first("nas-5gs.cmn.dnn") if request else None
                key = ("not_forwarded", cause, dnn)
                if key not in groups:
                    subject = "PDU session request" if request else "NAS message"
                    why = f"The AMF answered with {MM_MESSAGES[mtype]}, 5GMM cause #{cause} "
                    why += f"({code.name})"
                    if request is not None:
                        why += " to the PDU Session Establishment Request in packet "
                        why += f"#{request.number}"
                        if dnn:
                            why += f" for DNN {dnn!r}"
                    why += ". The request never reached an SMF."
                    groups[key] = _Group(
                        verdict=f"{subject} refused by the AMF: {code.name}.",
                        why=why,
                        fix=code.hint,
                        severity=Severity.FAILURE,
                    )
                group = groups[key]
                evidence = [request, packet] if request else [packet]
                _add(group, evidence, imsi)
    yield from _emit("nas5g.mm.reject", groups)


@rule("nas5g.sm.reject")
def sm_rejects(ctx: Context) -> Iterator[Finding]:
    groups: dict[object, _Group] = {}
    for packet in ctx.packets:
        if not packet.has("nas-5gs"):
            continue
        causes = _ints(packet, "nas-5gs.sm.5gsm_cause")
        for mtype in _ints(packet, "nas-5gs.sm.message_type"):
            if mtype not in SM_REJECTS or not causes:
                continue
            cause = causes[0]
            code = lookup(SM_CAUSE, cause)
            name = SM_REJECTS[mtype]
            request = _earlier(
                ctx,
                packet,
                _ue_key(packet),
                lambda p: SM_ESTABLISHMENT_REQUEST in _ints(p, "nas-5gs.sm.message_type"),
            )
            dnn = request.first("nas-5gs.cmn.dnn") if request else None
            key = (mtype, cause, dnn)
            if key not in groups:
                why = f"The SMF sent {name}, 5GSM cause #{cause} ({code.name})"
                why += f" for DNN {dnn!r}." if dnn else "."
                groups[key] = _Group(
                    verdict=f"{name}: {code.name}.",
                    why=why,
                    fix=code.hint,
                    severity=Severity.FAILURE,
                )
            _add(groups[key], [packet], ctx.imsi_of(packet))
    yield from _emit("nas5g.sm.reject", groups)


@rule("pfcp.cause")
def pfcp_rejects(ctx: Context) -> Iterator[Finding]:
    groups: dict[object, _Group] = {}
    for tx in ctx.pfcp:
        if tx.answer is None:
            continue
        cause = to_int(tx.answer.first("pfcp.cause"))
        if cause is None or cause < 64:
            continue
        code = lookup(PFCP_CAUSE, cause)
        key = (tx.name, cause)
        if key not in groups:
            groups[key] = _Group(
                verdict=f"PFCP {tx.name} rejected: {code.name}.",
                why=f"The UPF answered PFCP {tx.name} with cause {cause} ({code.name}).",
                fix=code.hint,
                severity=Severity.FAILURE,
            )
        group = groups[key]
        _add(group, [p for p in (tx.request, tx.answer) if p], None)
        group.retransmissions += tx.retransmissions
    yield from _emit("pfcp.cause", groups)


@rule("pfcp.unanswered")
def pfcp_unanswered(ctx: Context) -> Iterator[Finding]:
    yield from _unanswered(
        ctx,
        ctx.pfcp,
        "pfcp.unanswered",
        "The UPF (or SMF) did not answer. Check that the PFCP association is up, the peer is "
        "reachable on UDP 8805, and its health.",
    )


ONE_WAY_MIN_PACKETS = 3


UE_POOL_RANGES = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)


def _private(addr: str) -> bool:
    """RFC 1918 / CGNAT / ULA: addresses that need NAT to reach the internet."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip.version == net.version and ip in net for net in UE_POOL_RANGES)


@rule("gtpu.one_way")
def gtpu_one_way(ctx: Context) -> Iterator[Finding]:
    """Uplink user traffic enters the tunnel but nothing ever comes back."""
    tunneled = ctx.flows.tunneled
    plain = ctx.flows.plain
    first_seen = ctx.flows.first_seen
    groups: dict[object, _Group] = {}
    for (src, dst), n in tunneled.items():
        if n < ONE_WAY_MIN_PACKETS or tunneled.get((dst, src)) or plain.get((dst, src)):
            continue
        left_n6 = plain.get((src, dst), 0)
        why = (
            f"{n} GTP-U packets from {src} to {dst} went into the tunnel and none came back "
            "(no reply inside or outside the tunnel)."
        )
        if left_n6:
            why += (
                f" The same packets were seen leaving towards the data network ({left_n6}x) "
                f"still using the device's address {src} as source."
            )
            if _private(src) and not _private(dst):
                fix = (
                    f"{src} is a private address, so replies from {dst} cannot route back. "
                    "Add NAT/masquerade for the UE address pool on the UPF's N6/SGi side, or "
                    "a return route for the pool."
                )
            else:
                fix = "Check the return route from the data network to the UE address pool."
            severity = Severity.FAILURE
        else:
            fix = (
                "Check the UPF's N6/SGi side (routing and NAT for the UE pool). If the capture "
                "only covers one direction, capture both before concluding."
            )
            severity = Severity.WARNING
        key = (src, dst)
        groups[key] = _Group(
            verdict=f"User plane one-way: traffic from {src} to {dst} gets no reply.",
            why=why,
            fix=fix,
            severity=severity,
            evidence=[first_seen[key]],
            count=1,
        )
    yield from _emit("gtpu.one_way", groups)
