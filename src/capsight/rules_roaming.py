"""Roaming (S8): session requests from a visited network's SGW to the home PGW.

A Create Session Request is treated as roaming only when the capture proves it: the request
came from an SGW (F-TEID interface S5/S8 SGW) and its Serving Network is not the IMSI's home
network. The visited network is shown as MCC/MNC from that IE, never from names or IPs.
"""

from __future__ import annotations

from collections.abc import Iterator

from capsight.codes import GTPV2_CAUSE, lookup
from capsight.correlate import to_bool, to_int
from capsight.model import Finding, Severity
from capsight.roaming import plmn_text, visited_network
from capsight.rules import (
    GTP_USER_AUTH_FAILED,
    Context,
    _add,
    _emit,
    _Group,
    _radius_accept_before,
    one_way_commands,
    rule,
)
from capsight.session_links import claimed

# Roaming-specific reading of common causes; anything else falls back to the cause table.
ROAMING_HINT = {
    64: "The home gateway has no session for this tunnel: usually a session the visited "
    "side still believes is up after the home side dropped it (restart or a lost Delete).",
    72: "Internal failure on the home PGW. Check its logs for this IMSI and time.",
    73: "The home PGW is out of capacity (sessions or addresses) for roaming traffic.",
    78: "The APN the device asked for is not known in the home network. Check the APN the "
    "device uses and the subscriber's APN profile; a visited-network APN rewrite "
    "(APN Operator Identifier) can also produce this.",
    92: "The home network's authentication (often RADIUS/AAA behind the PGW) rejected the "
    "user. It is not a roaming-agreement problem.",
    93: "The home network does not allow this subscriber on this APN while roaming (or at "
    "all). Check the subscriber's APN profile and the roaming policy for the visited network.",
    94: "The home PGW refused without a specific reason. Check its logs for this IMSI.",
    100: "A node behind the home side did not answer (often the PGW or its AAA). Check the "
    "home core, not the visited network.",
    110: "A mobility procedure was in progress; usually transient. The device retries.",
}


def _networks(plmns: set[tuple[str, str]]) -> str:
    names = ", ".join(plmn_text(p) for p in sorted(plmns)[:5])
    more = f" and {len(plmns) - 5} more" if len(plmns) > 5 else ""
    plural = "s" if len(plmns) > 1 else ""
    return f"visited network{plural} {names}{more}"


@rule("roaming.s8")
def s8_rejects(ctx: Context) -> Iterator[Finding]:
    groups: dict[object, _Group] = {}
    seen: dict[object, dict[str, set]] = {}
    one_way = one_way_commands(ctx.gtpv2)  # gtpv2.unanswered warns about those instead
    for tx in ctx.gtpv2:
        visited = visited_network(tx)
        if visited is None:
            continue
        if tx.answer is None:
            if tx.name in one_way or ctx.capture_end - tx.request.time < ctx.answer_timeout:
                continue
            key: tuple = ("unanswered",)
            cause = None
            packets = [tx.request]
        else:
            cause = to_int(tx.answer.first("gtpv2.cause"))
            if cause is None or 16 <= cause <= 63:
                continue
            if cause == GTP_USER_AUTH_FAILED and _radius_accept_before(ctx, tx.answer):
                continue  # gtpv2.cause explains a reject after RADIUS accepted the user
            if claimed(ctx, tx):
                continue  # session.* explains where the refusal came from
            key = ("reject", cause)
            packets = [p for p in (tx.request, tx.answer) if p]
        info = seen.setdefault(key, {"plmns": set(), "apns": set(), "remote": set()})
        info["plmns"].add(visited)
        apn = tx.request.first("gtpv2.apn")
        if apn:
            info["apns"].add(apn)
        if tx.answer is not None:
            info["remote"].add(to_bool(tx.answer.first("gtpv2.cs")))
        if key not in groups:
            if cause is None:
                groups[key] = _Group(
                    verdict="Roaming session request never answered by the home network.",
                    why="",
                    fix="Check reachability of the home PGW from the visited SGW over the "
                    "roaming exchange (IPX/GRX): routing, firewall rules and the PGW address "
                    "the visited network resolved for this APN. Capture on both sides to see "
                    "which leg drops it.",
                    severity=Severity.FAILURE,
                )
            else:
                code = lookup(GTPV2_CAUSE, cause)
                groups[key] = _Group(
                    verdict=f"Roaming session rejected by the home network: {code.name}.",
                    why="",
                    fix=ROAMING_HINT.get(cause, code.hint),
                    severity=Severity.FAILURE,
                )
        _add(groups[key], packets, tx.imsi)
        groups[key].retransmissions += tx.retransmissions
    for key, group in groups.items():
        info = seen[key]
        where = _networks(info["plmns"])
        apns = sorted(info["apns"])
        for_apn = f" for APN {', '.join(apns[:3])}" if apns else ""
        if key[0] == "unanswered":
            group.why = (
                f"Create Session Request from the SGW in {where} over S8{for_apn} got no "
                f"response within {ctx.answer_timeout:g} s."
            )
            continue
        cause = key[1]
        code = lookup(GTPV2_CAUSE, cause)
        why = (
            f"Create Session Request from the SGW in {where} over S8{for_apn} was rejected "
            f"by the home network with cause {cause} ({code.name})."
        )
        if info["remote"] == {True}:
            why += " The cause was raised by a node behind the home PGW."
        elif info["remote"] == {False}:
            why += " The home PGW raised it itself."
        else:
            why += " Some were raised by the home PGW, some by a node behind it."
        group.why = why
    yield from _emit("roaming.s8", groups)
