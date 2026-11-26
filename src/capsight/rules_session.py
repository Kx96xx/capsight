"""Session rules across GTP-C and PFCP: why the gateway refused a session.

See session_links.py for how a Create Session is tied to the PFCP exchange behind it.
"""

from __future__ import annotations

from collections.abc import Iterator

from capsight.codes import GTPV2_CAUSE, lookup
from capsight.codes_5g import PFCP_CAUSE
from capsight.correlate import Transaction, to_int
from capsight.model import Finding, Packet, Severity
from capsight.roaming import visited_network
from capsight.rules import Context, _add, _emit, _Group, rule
from capsight.rules_roaming import _networks
from capsight.session_links import Conflict, links, network_instance, pfcp_cause


def _apn(tx: Transaction | None) -> str | None:
    if tx is None or tx.request is None:
        return None
    apn = tx.request.first("gtpv2.apn")
    return apn or None


def _gtp_cause(tx: Transaction | None) -> str | None:
    cause = to_int(tx.answer.first("gtpv2.cause")) if tx and tx.answer else None
    return None if cause is None else f"{cause} ({lookup(GTPV2_CAUSE, cause).name})"


def _roaming_note(txs: list[Transaction | None]) -> str:
    known = [tx for tx in txs if tx is not None]
    visited = [v for tx in known if (v := visited_network(tx)) is not None]
    if not visited:
        return ""
    who = "The requests" if len(visited) == len(known) else f"{len(visited)} of them"
    return f" {who} came over S8 from {_networks(set(visited))}."


def _packets(*txs_or_packets: Packet | None) -> list[Packet]:
    return [p for p in txs_or_packets if p is not None]


@rule("session.address_conflict")
def address_conflict(ctx: Context) -> Iterator[Finding]:
    by_address: dict[str, list[Conflict]] = {}
    for c in links(ctx).conflicts:
        by_address.setdefault(c.address, []).append(c)
    groups: dict[object, _Group] = {}
    for address, conflicts in by_address.items():
        group = _conflict_group(address, conflicts)
        for c in conflicts:
            imsi = (c.new_gtp.imsi if c.new_gtp else None) or (
                c.old_gtp.imsi if c.old_gtp else None
            )
            _add(
                group,
                _packets(
                    c.rejected.answer,
                    c.report.request,
                    c.deleted.request,
                    c.new_gtp.answer if c.new_gtp else None,
                ),
                imsi,
            )
        groups[address] = group
    yield from _emit("session.address_conflict", groups)


def _conflict_group(address: str, conflicts: list[Conflict]) -> _Group:
    first = conflicts[0]
    cause = pfcp_cause(first.rejected) or 0
    pcode = lookup(PFCP_CAUSE, cause)
    instance = network_instance(first.rejected)
    where = f" in the same network instance ({instance})" if instance else ""
    deleted = "(Session Report Request: session deleted by the UP function)"
    # Which APNs were involved: only pairs where both sides are linked say "same" or "two".
    pairs = [(_apn(c.new_gtp), _apn(c.old_gtp)) for c in conflicts]
    known = [(new, old) for new, old in pairs if new and old]
    apns = sorted({a for pair in pairs for a in pair if a})
    two_apns = [(new, old) for new, old in known if new != old]
    if two_apns and len(apns) == 2:
        new, old = two_apns[0]
        verdict = (
            f"Two PDN sessions (APNs {apns[0]} and {apns[1]}) share UE address {address}: "
            "each new one is refused and the other is deleted."
        )
        why = (
            f"The UPF refused the session for APN {new} (PFCP cause {cause}, {pcode.name}) and "
            f"in the same moment deleted the session for APN {old} {deleted}. Both use UE "
            f"address {address}{where}."
        )
        fix = (
            f"Do not give one address to two APNs in the same network instance: give {apns[0]} "
            f"and {apns[1]} their own addresses or network instances, remove one of them from "
            "the subscription, or set the device to use one APN."
        )
    elif known and not two_apns and len(apns) == 1:
        verdict = (
            f"A new session for APN {apns[0]} collides with an older one on UE address "
            f"{address}: the new one is refused and the old one deleted."
        )
        why = (
            f"The UPF refused a new session for APN {apns[0]} (PFCP cause {cause}, "
            f"{pcode.name}) and in the same moment deleted the earlier session for the same APN "
            f"{deleted}. Both use UE address {address}{where}."
        )
        fix = (
            "The old session was still in place when the new one was requested. Check why it "
            "was not deleted first (look for its Delete Session), and whether the gateway should "
            "replace a session on the same address instead of refusing the new one."
        )
    else:
        verdict = (
            f"Sessions collide on UE address {address}: each new one is refused and an existing "
            "one deleted."
        )
        why = (
            f"The UPF refused a new session (PFCP cause {cause}, {pcode.name}) and in the same "
            f"moment deleted an earlier session that uses the same UE address {address}{where} "
            f"{deleted}."
        )
        if apns:
            why += f" APNs seen in these sessions: {', '.join(apns)}."
        fix = (
            "Two sessions are using one UE address. Check whether the subscription gives the "
            "same static address to more than one APN, or an old session is left in place when "
            "a new one is requested."
        )
    why += _roaming_note([c.new_gtp for c in conflicts])
    gtp = _gtp_cause(first.new_gtp)
    if gtp:
        why += (
            f" The gateway answered Create Session with cause {gtp}, which only passes on the "
            "UPF's refusal."
        )
    if len(conflicts) > 1:
        why += (
            " The lost session is requested again, so sessions keep alternating between "
            "accepted and refused; a retry right after each refusal usually succeeds, which makes "
            "this look intermittent."
        )
    return _Group(verdict=verdict, why=why, fix=fix, severity=Severity.FAILURE)


@rule("session.upf_reject")
def upf_reject(ctx: Context) -> Iterator[Finding]:
    lk = links(ctx)
    in_conflict = {c.rejected.request.number for c in lk.conflicts}
    groups: dict[object, _Group] = {}
    sessions: dict[object, list[Transaction]] = {}
    for g, p in lk.upf_rejects(ctx.gtpv2):
        if p.request.number in in_conflict:
            continue
        cause = pfcp_cause(p) or 0
        pcode = lookup(PFCP_CAUSE, cause)
        gcause = to_int(g.answer.first("gtpv2.cause")) if g.answer else None
        key = (cause, gcause)
        if key not in groups:
            why = (
                "The gateway answered Create Session"
                + f" with cause {_gtp_cause(g)} right after its UPF refused the PFCP Session "
                f"Establishment for it with cause {cause} ({pcode.name}). The gateway's "
                "cause only passes on the UPF's refusal."
            )
            groups[key] = _Group(
                verdict=f"Create Session refused because the UPF refused the session: "
                f"{pcode.name}.",
                why=why,
                fix=f"Look at the UPF, not the gateway: {pcode.hint}",
                severity=Severity.FAILURE,
            )
        _add(groups[key], _packets(p.request, p.answer, g.answer), g.imsi)
        sessions.setdefault(key, []).append(g)
    for key, group in groups.items():
        group.why += _roaming_note(sessions[key])
    yield from _emit("session.upf_reject", groups)
