"""MAP (2G/3G over SS7): operation errors, dialogue aborts, rejects and timeouts.

Covers authentication (SendAuthenticationInfo), location update (UpdateLocation,
UpdateGprsLocation) and SMS routing and delivery (SendRoutingInfoForSM, MO/MT-ForwardSM),
plus any other operation with a known error code.
"""

from __future__ import annotations

from collections.abc import Iterator

from capsight.codes import Code, lookup
from capsight.codes_map import (
    DIALOGUE_SERVICE_USER,
    MAP_DIAGNOSTICS,
    MAP_ERROR_HINTS,
    MAP_ERRORS,
    MAP_PROCEDURE_CANCELLATION,
    MAP_RESOURCE_UNAVAILABLE,
    MAP_USER_ABORT,
    SUBSCRIBER_STATE_ERRORS,
    TCAP_P_ABORT,
    TCAP_REJECT_PROBLEMS,
    responder,
)
from capsight.correlate import Transaction, to_int
from capsight.model import Finding, Packet, Severity
from capsight.rules import Context, _add, _emit, _Group, _unanswered, rule

# MAP operation timers are 15 s to minutes (TS 29.002 17.1.2); never call a timeout sooner.
MAP_MIN_TIMEOUT = 30.0


def _packets(tx: Transaction) -> list[Packet]:
    return [p for p in (tx.request, tx.answer) if p]


def _opcode(tx: Transaction) -> int | None:
    return to_int(tx.request.first("map.op")) if tx.request else None


def _diagnostic(answer: Packet) -> str:
    parts = []
    for name, (label, values) in MAP_DIAGNOSTICS.items():
        value = to_int(answer.first(name))
        if value is not None:
            parts.append(f"{label}: {values.get(value, f'value {value}')}")
    return "; ".join(parts)


@rule("map.error")
def map_errors(ctx: Context) -> Iterator[Finding]:
    groups: dict[object, _Group] = {}
    for tx in ctx.map:
        if tx.answer is None or tx.answer.first("map.component") != "error":
            continue
        code = to_int(tx.answer.first("map.error"))
        if code is None:
            continue
        op = _opcode(tx)
        diag = _diagnostic(tx.answer)
        key = (tx.name, code, diag)
        if key not in groups:
            error = lookup(MAP_ERRORS, code)
            who = responder(op) if tx.request else "peer"
            why = f"The {who} returned MAP error {code} ({error.name})"
            why += f", {diag}." if diag else "."
            if tx.request is None:
                why += " The request is not in the capture."
            groups[key] = _Group(
                verdict=f"{tx.name} rejected: {error.name}" + (f" ({diag})." if diag else "."),
                why=why,
                fix=MAP_ERROR_HINTS.get((op, code), error.hint) if op is not None else error.hint,
                severity=Severity.WARNING if code in SUBSCRIBER_STATE_ERRORS else Severity.FAILURE,
            )
        _add(groups[key], _packets(tx), tx.imsi)
    yield from _emit("map.error", groups)


PROVIDER_ABORT = {0: "abnormal dialogue", 1: "invalid PDU"}


def _named(table: dict[int, str], number: int | None, raw: str) -> str:
    return table.get(number, raw) if number is not None else raw


def describe_abort(answer: Packet) -> Code:
    kind = answer.first("map.abort") or "u-abort"
    value = answer.first("map.abort.value") or ""
    number = to_int(value)
    if kind == "p-abort":
        cause = lookup(TCAP_P_ABORT, number if number is not None else -1)
        return Code(f"TCAP provider abort, {cause.name}", cause.hint)
    if kind == "refused":
        diag = _named(DIALOGUE_SERVICE_USER, number, f"diagnostic {value}" if value else "")
        hint = "The peer refused to open the dialogue."
        if number == 2:
            hint = (
                "The peer does not support this MAP version (application context). The "
                "sender should retry with a lower version; if it does not, check the version "
                "configured for this peer."
            )
        return Code(f"dialogue refused, {diag}" if diag else "dialogue refused", hint)
    if kind == "user":
        return MAP_USER_ABORT.get(value, Code("MAP user abort"))
    if kind == "resource":
        what = _named(MAP_RESOURCE_UNAVAILABLE, number, value)
        return Code(f"resource unavailable ({what})", "The peer application is out of resources.")
    if kind == "procedure":
        what = _named(MAP_PROCEDURE_CANCELLATION, number, value)
        hint = "The peer cancelled the procedure."
        if number == 4:
            hint = (
                "A procedure this one depended on failed (for example InsertSubscriberData "
                "during a location update). Look for that failure in the same dialogue."
            )
        return Code(f"procedure cancelled ({what})", hint)
    if kind == "provider":
        what = _named(PROVIDER_ABORT, number, value)
        return Code(f"MAP provider abort ({what})", "The peer's MAP layer could not continue.")
    if kind == "unknown":
        return Code(
            "aborted (reason not decoded)",
            "Several aborts were bundled in one packet and their reasons could not be told "
            "apart. Open the packet in Wireshark to read each reason.",
        )
    return Code("aborted by the peer (no reason given)", "Check the peer's logs.")


@rule("map.abort")
def map_aborts(ctx: Context) -> Iterator[Finding]:
    groups: dict[object, _Group] = {}
    for tx in ctx.map:
        if tx.answer is None or tx.answer.first("map.component") != "abort":
            continue
        reason = describe_abort(tx.answer)
        key = (tx.name, reason.name)
        if key not in groups:
            subject = f"{tx.name} dialogue" if tx.request is not None else "MAP dialogue"
            why = f"The TCAP dialogue was aborted: {reason.name}."
            if tx.request is None:
                why += " The request that opened it is not in the capture."
            groups[key] = _Group(
                verdict=f"{subject} aborted: {reason.name}.",
                why=why,
                fix=reason.hint,
                severity=Severity.FAILURE,
            )
        _add(groups[key], _packets(tx), tx.imsi)
    yield from _emit("map.abort", groups)


@rule("map.reject")
def map_rejects(ctx: Context) -> Iterator[Finding]:
    groups: dict[object, _Group] = {}
    for tx in ctx.map:
        if tx.answer is None or tx.answer.first("map.component") != "reject":
            continue
        field = tx.answer.first("map.reject") or ""
        value = to_int(tx.answer.first("map.reject.value"))
        problem = TCAP_REJECT_PROBLEMS.get(field, {}).get(value, "unknown problem")
        key = (tx.name, problem)
        if key not in groups:
            groups[key] = _Group(
                verdict=f"{tx.name} rejected by TCAP: {problem}.",
                why=f"The peer could not process the component: {problem}.",
                fix="An encoding or protocol mismatch between the two nodes (often MAP "
                "version or vendor interworking). Compare with a request that works.",
                severity=Severity.FAILURE,
            )
        _add(groups[key], _packets(tx), tx.imsi)
    yield from _emit("map.reject", groups)


# A capture filtered on the IMSI keeps MAP requests but drops most answers (they carry no
# IMSI); a one-directional capture drops them too. Below this answer ratio the timeouts are
# not trusted.
MISSING_ANSWERS_MIN_REQUESTS = 3
MISSING_ANSWERS_MAX_RATIO = 0.10


def _missing_answers(name: str, txs: list[Transaction], answered: int) -> _Group:
    group = _Group(
        verdict=f"{name} answers are missing from this capture.",
        why=f"{len(txs)} {name} requests but only {answered} of them answered. Either the "
        "capture was filtered (most MAP answers carry no IMSI, so a filter on the IMSI drops "
        "them) or captured in one direction only, or the peer answers nothing at all.",
        fix="Capture without an IMSI filter and in both directions to tell which. If the "
        "answers are still missing, check SCCP routing toward the peer and back.",
        severity=Severity.WARNING,
    )
    for tx in txs:
        _add(group, [tx.request], tx.imsi)
    return group


def _too_few_answers(txs: list[Transaction]) -> int | None:
    """Answered count when too few requests were answered to trust timeouts, else None."""
    answered = sum(1 for tx in txs if tx.answer is not None)
    if len(txs) >= MISSING_ANSWERS_MIN_REQUESTS and answered <= (
        MISSING_ANSWERS_MAX_RATIO * len(txs)
    ):
        return answered
    return None


@rule("map.unanswered")
def map_unanswered(ctx: Context) -> Iterator[Finding]:
    requests = [tx for tx in ctx.map if tx.request is not None]
    answered = _too_few_answers(requests)
    if answered is not None:  # the whole capture: one warning
        yield from _emit("map.unanswered", {"all": _missing_answers("MAP", requests, answered)})
        return
    by_op: dict[str, list[Transaction]] = {}
    for tx in requests:
        by_op.setdefault(tx.name, []).append(tx)
    groups = {}
    for name, txs in by_op.items():
        answered = _too_few_answers(txs)
        if answered is not None:
            groups[name] = _missing_answers(name, txs, answered)
    yield from _emit("map.unanswered", groups)
    yield from _unanswered(
        ctx,
        ctx.map,
        "map.unanswered",
        "The peer did not answer: check SCCP routing (global title translation) toward it "
        "and back, and the peer's health. If only some operations time out, the peer may "
        "be dropping them.",
        claimed=lambda tx: tx.name in groups,
        timeout=max(ctx.answer_timeout, MAP_MIN_TIMEOUT),
    )


PARTIAL_MIN_ANSWERS = 20


@rule("map.partial")
def map_partial_capture(ctx: Context) -> Iterator[Finding]:
    """Answers whose request is not in the capture, beyond what a late start explains."""
    if not ctx.map:
        return
    start = ctx.capture_start
    orphans = [
        tx
        for tx in ctx.map
        if tx.request is None
        and tx.answer is not None
        and tx.answer.first("map.component") in ("result", "partial", "error", "reject")
        and tx.answer.time - start >= MAP_MIN_TIMEOUT
    ]
    if len(orphans) < PARTIAL_MIN_ANSWERS:
        return
    group = _Group(
        verdict="Capture holds only part of the MAP traffic: answers without their request.",
        why=f"{len(orphans)} MAP answers (results or errors) arrived more than "
        f"{MAP_MIN_TIMEOUT:g} s into the capture with no matching request in it. The "
        "requests took a path this capture does not see (another signalling link, STP or "
        "interface). Requests that look unanswered may have been answered on that path.",
        fix="Capture on every link and STP that carries this traffic (both directions) "
        "before concluding that requests timed out.",
        severity=Severity.WARNING,
    )
    for tx in orphans:
        _add(group, _packets(tx), None)
    group.count = 1  # one observation about the capture, not one per answer
    yield from _emit("map.partial", {"partial": group})
