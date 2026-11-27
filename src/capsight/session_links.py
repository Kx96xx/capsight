"""Link a gateway's GTP-C answer to the PFCP exchange behind it, and find sessions that fight
over one UE address.

A PGW-C/SMF that gets Create Session asks its UPF for the session over PFCP before it
answers. When the UPF refuses, the gateway answers with its own, vaguer cause (often 72
System failure), so a code lookup on either message says "check the logs". Linking the two
says where the refusal came from; the UPF's Session Report says what it did next.

The pattern found here: the UPF refuses a new session (cause 77 and similar) and, in the same
moment, deletes an existing session (Session Report Request with PSDBU, "PFCP session deleted
by the UP function") that uses the same UE address. With two APNs sharing one static address
in one network instance, each new session knocks the other out and the device re-requests
the lost one, so sessions alternate between accepted and rejected.

Linking is by time only (the GTP-C and PFCP addresses of one gateway differ). A PFCP
Session Establishment is linked to a Create Session when it is the only one inside that
Create Session's request-to-answer window and that window is the only one containing it.
Anything ambiguous stays unlinked, and the plain per-message rules report it.

The same holds for policy and charging: before it answers Create Session the gateway asks the
PCRF (Gx) and the online charging system (Gy) with a CCR-I. When one of them refuses, the
gateway's cause again only passes the refusal on. A failed CCR-I is linked to a rejected
Create Session when it is the only failed CCR-I inside that request-to-answer window (for
the same IMSI when both carry one) and that window is the only one containing it.

When the upstream request is never answered at all, the gateway gives up and rejects the
Create Session with a generic cause. An unanswered PFCP Session Establishment or Gx/Gy CCR-I
is linked to a rejected Create Session under the same rule: it is the only unanswered
upstream request sent inside that window, and that window is the only one containing it.

Rules use :func:`links`, which computes everything once per analysis (cached on the context).
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Any

from capsight.correlate import Transaction, to_bool, to_int

CREATE_SESSION = "Create Session Request"  # GTPv2 transaction name
PFCP_ESTABLISHMENT = "Session Establishment"  # PFCP transaction names
PFCP_REPORT = "Session Report"
REPORT_WINDOW_S = 1.0  # the UPF's Session Report comes within this time of its reject
PFCP_ACCEPTED = 1
PFCP_FIRST_REJECT = 64  # PFCP causes 64 and up are rejections (TS 29.244 8.2.1)


def gtp_rejected(tx: Transaction) -> bool:
    cause = to_int(tx.answer.first("gtpv2.cause")) if tx.answer else None
    return cause is not None and not 16 <= cause <= 63


def pfcp_cause(tx: Transaction) -> int | None:
    return to_int(tx.answer.first("pfcp.cause")) if tx.answer else None


def cp_seid(tx: Transaction) -> int | None:
    """The CP F-SEID a Session Establishment Request asks the UPF to use towards the SMF.

    tshark lists the header SEID (0 in an establishment request) first, then the F-SEID."""
    if tx.request is None:
        return None
    seids = [to_int(s) for s in tx.request.fields.get("pfcp.seid", [])]
    seids = [s for s in seids if s]
    return seids[-1] if seids else None


def ue_addresses(tx: Transaction) -> set[str]:
    if tx.request is None:
        return set()
    f = tx.request.fields
    return set(f.get("pfcp.ue_ip_addr_ipv4", [])) | set(f.get("pfcp.ue_ip_addr_ipv6", []))


def _labels(raw: str) -> str:
    """'\\x04core\\x06mnc001...' (DNS-label encoding, as in an APN) -> 'core.mnc001...'."""
    out, i = [], 0
    while i < len(raw):
        n = ord(raw[i])
        if not 0 < n < 64 or i + 1 + n > len(raw):
            return raw.strip()
        out.append(raw[i + 1 : i + 1 + n])
        i += 1 + n
    return ".".join(out)


def network_instance(tx: Transaction) -> str | None:
    if tx.request is None:
        return None
    values = tx.request.fields.get("pfcp.network_instance", [])
    return _labels(values[0]) if values else None


@dataclass
class Conflict:
    rejected: Transaction  # the refused PFCP Session Establishment
    report: Transaction  # the UPF's Session Report: session deleted by the UP function
    deleted: Transaction  # the earlier, accepted Session Establishment it deleted
    address: str
    new_gtp: Transaction | None = None
    old_gtp: Transaction | None = None


@dataclass
class Links:
    gtp_of: dict[int, Transaction] = field(default_factory=dict)  # PFCP request # -> GTP tx
    pfcp_of: dict[int, Transaction] = field(default_factory=dict)  # GTP request # -> PFCP tx
    conflicts: list[Conflict] = field(default_factory=list)
    claimed_gtp: set[int] = field(default_factory=set)  # GTP request numbers explained here
    claimed_pfcp: set[int] = field(default_factory=set)  # PFCP request numbers explained here
    # (rejected Create Session, the failed Gx/Gy CCR-I behind it)
    policy_rejects: list[tuple[Transaction, Transaction]] = field(default_factory=list)
    claimed_diameter: set[int] = field(default_factory=set)  # CCR request numbers explained
    # (rejected Create Session, the unanswered PFCP establishment or Gx/Gy CCR-I behind it)
    upstream_timeouts: list[tuple[Transaction, Transaction]] = field(default_factory=list)

    def upf_rejects(self, gtpv2: list[Transaction]) -> list[tuple[Transaction, Transaction]]:
        """Rejected Create Sessions whose linked PFCP establishment the UPF rejected."""
        out = []
        for tx in gtpv2:
            if tx.request is None or not gtp_rejected(tx):
                continue
            p = self.pfcp_of.get(tx.request.number)
            cause = pfcp_cause(p) if p else None
            if p is not None and cause is not None and cause >= PFCP_FIRST_REJECT:
                out.append((tx, p))
        return out


def _start(tx: Transaction) -> float:
    """When the answered attempt was sent: an answer belongs to the last retransmission."""
    return tx.resent if tx.resent is not None else tx.request.time


def _complete(txs: list[Transaction], name: str) -> list[Transaction]:
    return [t for t in txs if t.name == name and t.request is not None and t.answer is not None]


def _link(gtpv2: list[Transaction], pfcp: list[Transaction], links: Links) -> None:
    """Pair Create Sessions with Session Establishments, cluster by cluster.

    A cluster is a run of Create Sessions whose request-to-answer windows overlap. The gateway
    asks the UPF in the order the requests arrived, so inside a cluster the n-th Create
    Session goes with the n-th Session Establishment, provided the counts match and every
    pair fits inside its window. Otherwise the cluster stays unlinked.
    """
    sessions = sorted(_complete(gtpv2, CREATE_SESSION), key=_start)
    establishments = sorted(_complete(pfcp, PFCP_ESTABLISHMENT), key=_start)
    starts = [_start(t) for t in establishments]
    clusters: list[list[Transaction]] = []
    end = float("-inf")
    for g in sessions:
        if clusters and _start(g) <= end:
            clusters[-1].append(g)
            end = max(end, g.answer.time)
        else:
            clusters.append([g])
            end = g.answer.time
    for cluster in clusters:
        lo = bisect.bisect_left(starts, _start(cluster[0]))
        hi = bisect.bisect_right(starts, max(g.answer.time for g in cluster))
        found = establishments[lo:hi]
        if len(found) != len(cluster):
            continue
        pairs = list(zip(cluster, found, strict=True))
        if all(_start(g) <= _start(p) and p.answer.time <= g.answer.time for g, p in pairs):
            for g, p in pairs:
                links.pfcp_of[g.request.number] = p
                links.gtp_of[p.request.number] = g


def _conflicts(pfcp: list[Transaction], links: Links) -> None:
    accepted_by_seid: dict[int, Transaction] = {}
    reports = sorted(
        (
            t
            for t in pfcp
            if t.name == PFCP_REPORT
            and t.request is not None
            and to_bool(t.request.first("pfcp.srreq_flags.psdbu"))
        ),
        key=lambda t: t.request.time,
    )
    used: set[int] = set()
    for tx in sorted(_complete(pfcp, PFCP_ESTABLISHMENT), key=lambda t: t.request.time):
        cause = pfcp_cause(tx)
        if cause == PFCP_ACCEPTED:
            seid = cp_seid(tx)
            if seid:
                accepted_by_seid[seid] = tx
            continue
        if cause is None or cause < PFCP_FIRST_REJECT:
            continue
        for report in reports:
            t = report.request.time
            # the UPF may send the report just before or just after its reject
            if t < tx.request.time or report.request.number in used:
                continue
            if t - tx.answer.time > REPORT_WINDOW_S:
                break
            deleted = accepted_by_seid.get(to_int(report.request.first("pfcp.seid")) or -1)
            if deleted is None or deleted.request.time >= tx.request.time:
                continue
            shared = ue_addresses(tx) & ue_addresses(deleted)
            if not shared:
                continue
            used.add(report.request.number)
            links.conflicts.append(
                Conflict(
                    rejected=tx,
                    report=report,
                    deleted=deleted,
                    address=sorted(shared)[0],
                    new_gtp=links.gtp_of.get(tx.request.number),
                    old_gtp=links.gtp_of.get(deleted.request.number),
                )
            )
            break


def _same_subscriber(a: Transaction, b: Transaction) -> bool:
    return a.imsi is None or b.imsi is None or a.imsi == b.imsi


def _link_policy(gtpv2: list[Transaction], diameter: list[Transaction], links: Links) -> None:
    # rules and rules_pcc import this module; import them here to avoid a cycle
    from capsight.codes_pcc import CC_INITIAL
    from capsight.rules import is_pcc
    from capsight.rules_pcc import _result, interface, request_type

    explained = {g.request.number for g, _ in links.upf_rejects(gtpv2)}
    explained |= {c.new_gtp.request.number for c in links.conflicts if c.new_gtp is not None}
    sessions = [
        g
        for g in _complete(gtpv2, CREATE_SESSION)
        if gtp_rejected(g) and g.request.number not in explained
    ]
    failed = [
        d
        for d in diameter
        if d.name == "CCR"
        and d.request is not None
        and d.answer is not None
        and is_pcc(d)
        and request_type(d) == CC_INITIAL
        and _result(d.answer, interface(d)) is not None
    ]

    def inside(g: Transaction, d: Transaction) -> bool:
        return (
            _start(g) <= d.request.time
            and d.answer.time <= g.answer.time
            and _same_subscriber(g, d)
        )

    for g in sessions:
        found = [d for d in failed if inside(g, d)]
        if len(found) != 1:
            continue
        d = found[0]
        if sum(1 for other in sessions if inside(other, d)) == 1:
            links.policy_rejects.append((g, d))


def _link_timeouts(
    gtpv2: list[Transaction],
    pfcp: list[Transaction],
    diameter: list[Transaction],
    links: Links,
) -> None:
    from capsight.codes_pcc import CC_INITIAL
    from capsight.rules import is_pcc
    from capsight.rules_pcc import request_type

    explained = {g.request.number for g, _ in links.upf_rejects(gtpv2)}
    explained |= {c.new_gtp.request.number for c in links.conflicts if c.new_gtp is not None}
    explained |= {g.request.number for g, _ in links.policy_rejects}
    sessions = [
        g
        for g in _complete(gtpv2, CREATE_SESSION)
        if gtp_rejected(g) and g.request.number not in explained
    ]
    unanswered = [
        t
        for t in pfcp
        if t.name == PFCP_ESTABLISHMENT and t.request is not None and t.answer is None
    ] + [
        t
        for t in diameter
        if t.name == "CCR"
        and t.request is not None
        and t.answer is None
        and is_pcc(t)
        and request_type(t) == CC_INITIAL
    ]

    def inside(g: Transaction, u: Transaction) -> bool:
        return _start(g) <= u.request.time <= g.answer.time and _same_subscriber(g, u)

    for g in sessions:
        found = [u for u in unanswered if inside(g, u)]
        if len(found) != 1:
            continue
        u = found[0]
        if sum(1 for other in sessions if inside(other, u)) == 1:
            links.upstream_timeouts.append((g, u))


def links(ctx: Any) -> Links:
    """Links for this analysis; `ctx` is a rules.Context (needs gtpv2, pfcp, cache)."""
    cached = ctx.cache.get("session_links")
    if cached is not None:
        return cached
    result = Links()
    _link(ctx.gtpv2, ctx.pfcp, result)
    _conflicts(ctx.pfcp, result)
    for c in result.conflicts:
        result.claimed_pfcp.update({c.rejected.request.number, c.report.request.number})
        if c.new_gtp is not None:
            result.claimed_gtp.add(c.new_gtp.request.number)
    for g, p in result.upf_rejects(ctx.gtpv2):
        result.claimed_gtp.add(g.request.number)
        result.claimed_pfcp.add(p.request.number)
    _link_policy(ctx.gtpv2, ctx.diameter, result)
    for g, d in result.policy_rejects:
        result.claimed_gtp.add(g.request.number)
        result.claimed_diameter.add(d.request.number)
    _link_timeouts(ctx.gtpv2, ctx.pfcp, ctx.diameter, result)
    for g, u in result.upstream_timeouts:
        result.claimed_gtp.add(g.request.number)
        pool = result.claimed_pfcp if u.protocol == "pfcp" else result.claimed_diameter
        pool.add(u.request.number)
    ctx.cache["session_links"] = result
    return result


def claimed(ctx: Any, tx: Transaction) -> bool:
    """True when a session rule explains this transaction better than its code alone."""
    if tx.request is None or not (ctx.gtpv2 or ctx.pfcp):
        return False
    lk = links(ctx)
    pool = {
        "gtpv2": lk.claimed_gtp,
        "pfcp": lk.claimed_pfcp,
        "diameter": lk.claimed_diameter,
    }.get(tx.protocol, set())
    return tx.request.number in pool
