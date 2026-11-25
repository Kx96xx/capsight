"""Pair MAP operations with their outcome across TCAP dialogues.

A MAP request is an *invoke* component inside a TCAP BEGIN or CONTINUE. Its outcome comes
back in a later CONTINUE or END (result, error or reject) carrying the invoker's
transaction ID as destination ID and the same invoke ID, or as an ABORT of the dialogue.

SIGTRAN bundles several TCAP messages into one SCTP packet, and tshark then lists each
field's values for the whole frame. The messages are recovered from the order of the
transaction IDs (`tcap.tid`: one per BEGIN, END or ABORT, otid then dtid per CONTINUE),
the per-message component counts and the component kinds. Only a frame with exactly one
consistent reading is used; for any other frame the transaction IDs are remembered, so a
request whose outcome was in it is never reported as unanswered.
"""

from __future__ import annotations

from collections.abc import Iterator

from capsight.codes_map import MAP_DIAGNOSTICS, operation_name
from capsight.correlate import Correlator, Transaction, to_int
from capsight.model import Packet

MESSAGE_TYPES = {
    "tcap.begin_element": "begin",
    "tcap.continue_element": "continue",
    "tcap.end_element": "end",
    "tcap.abort_element": "abort",
}
# gsm_map.old.Component values (TS 29.002 / Q.773 component types)
COMPONENT_KINDS = {"1": "invoke", "2": "result", "3": "error", "4": "reject", "7": "partial"}
CARRIES = {
    "begin": frozenset({"invoke"}),
    "continue": frozenset({"invoke", "result", "partial", "error", "reject"}),
    "end": frozenset({"result", "partial", "error", "reject"}),
    "abort": frozenset(),
}
REJECT_PROBLEMS = (
    "gsm_old.generalProblem",
    "gsm_old.invokeProblem",
    "gsm_old.returnResultProblem",
    "gsm_old.returnErrorProblem",
)
USER_ABORT_ELEMENTS = (
    "gsm_map.dialogue.userSpecificReason_element",
    "gsm_map.dialogue.userResourceLimitation_element",
)
MAX_SEQUENCES = 512  # candidate message orders tried per frame before giving up
DUPLICATE_WINDOW = 10.0  # s; the same message seen on both legs of an STP
PROTOCOLS = ("tcap", "gsm_map")


class _Component:
    __slots__ = ("kind", "invoke_id", "value", "message")

    def __init__(self, kind: str, message: int) -> None:
        self.kind, self.message = kind, message
        self.invoke_id: int | None = None
        self.value: int | None = None


class _Message:
    __slots__ = ("type", "otid", "dtid", "imsi", "extra")

    def __init__(self, mtype: str, otid: str | None, dtid: str | None) -> None:
        self.type, self.otid, self.dtid = mtype, otid, dtid
        self.imsi: str | None = None
        self.extra: dict[str, list[str]] = {}  # error diagnostics, abort or reject details


def _tid(value: str) -> str:
    return value.replace(":", "").lower()


def _count(packet: Packet, name: str) -> int:
    return len(packet.fields.get(name, ()))


def _abort_details(packet: Packet) -> dict[str, list[str]]:
    """Why a dialogue was aborted, from a frame holding exactly one ABORT."""
    cause = packet.first("tcap.p_abortCause")
    if cause is not None:
        return {"map.abort": ["p-abort"], "map.abort.value": [cause]}
    results = packet.fields.get("tcap.result", [])
    if "1" in results:  # AARE reject-permanent: the dialogue was refused
        diags = packet.fields.get("tcap.dialogue_service_user", [])
        diag = diags[results.index("1")] if len(diags) == len(results) else ""
        return {"map.abort": ["refused"], "map.abort.value": [diag]}
    for name in USER_ABORT_ELEMENTS:
        if name in packet.fields:
            return {"map.abort": ["user"], "map.abort.value": [name]}
    for name, kind in (
        ("gsm_map.dialogue.resourceUnavailable", "resource"),
        ("gsm_map.dialogue.applicationProcedureCancellation", "procedure"),
        ("gsm_map.dialogue.map_ProviderAbortReason", "provider"),
    ):
        value = packet.first(name)
        if value is not None:
            return {"map.abort": [kind], "map.abort.value": [value]}
    return {"map.abort": ["u-abort"], "map.abort.value": [""]}


def _sequences(
    tids: list[str], otids: list[str], dtids: list[str], left: dict[str, int]
) -> Iterator[list[tuple[str, str | None, str | None]]]:
    """Message sequences (type, otid, dtid) that explain the frame's transaction IDs."""
    seq: list[tuple[str, str | None, str | None]] = []

    def walk(i: int, io: int, idd: int) -> Iterator[list[tuple[str, str | None, str | None]]]:
        if i == len(tids):
            if io == len(otids) and idd == len(dtids) and not any(left.values()):
                yield list(seq)
            return
        tid = tids[i]
        steps = []
        if io < len(otids) and tid == otids[io]:
            steps.append(("begin", 1, 1, 0))
            if i + 1 < len(tids) and idd < len(dtids) and tids[i + 1] == dtids[idd]:
                steps.append(("continue", 2, 1, 1))
        if idd < len(dtids) and tid == dtids[idd]:
            steps += [("end", 1, 0, 1), ("abort", 1, 0, 1)]
        for mtype, used, do, dd in steps:
            if not left[mtype]:
                continue
            left[mtype] -= 1
            seq.append((mtype, otids[io] if do else None, dtids[idd] if dd else None))
            yield from walk(i + used, io + do, idd + dd)
            seq.pop()
            left[mtype] += 1

    yield from walk(0, 0, 0)


def _place(
    sequence: list[tuple[str, str | None, str | None]], counts: list[int], kinds: list[str]
) -> list[int] | None:
    """Message index of each component, or None if this reading cannot hold them."""
    carriers = [i for i, (mtype, _, _) in enumerate(sequence) if mtype != "abort"]
    if not kinds:
        return [] if not counts else None
    if len(counts) != len(carriers) or sum(counts) != len(kinds):
        return None
    owner: list[int] = []
    for message, n in zip(carriers, counts, strict=True):
        owner += [message] * n
    for kind, message in zip(kinds, owner, strict=True):
        if kind not in CARRIES[sequence[message][0]]:
            return None
    return owner


def split_messages(packet: Packet) -> tuple[list[_Message], list[_Component]] | None:
    """The TCAP messages and components in a frame, or None when they cannot be told apart."""
    left = {t: _count(packet, name) for name, t in MESSAGE_TYPES.items()}
    if not any(left.values()):
        return [], []
    tids = [_tid(v) for v in packet.fields.get("tcap.tid", [])]
    otids = [_tid(v) for v in packet.fields.get("tcap.otid", [])]
    dtids = [_tid(v) for v in packet.fields.get("tcap.dtid", [])]
    kinds = [
        COMPONENT_KINDS.get(v, "other") for v in packet.fields.get("gsm_map.old.Component", [])
    ]
    counts = [to_int(v) or 0 for v in packet.fields.get("tcap.components", [])]
    if "other" in kinds:
        return None

    # Every reading that fits is collected; a second one means the frame is ambiguous.
    readings = []
    for tried, sequence in enumerate(_sequences(tids, otids, dtids, left)):
        if tried >= MAX_SEQUENCES:
            return None
        owner = _place(sequence, counts, kinds)
        if owner is not None:
            readings.append((sequence, owner))
            if len(readings) > 1:
                return None
    if not readings:
        return None
    sequence, owner = readings[0]
    messages = [_Message(*m) for m in sequence]
    components = [_Component(kind, message) for kind, message in zip(kinds, owner, strict=True)]

    # Invoke IDs: one per invoke/result/error; a reject carries a derivable ID or none.
    with_id = [c for c in components if c.kind != "reject"]
    ids = packet.fields.get("gsm_old.invokeID", [])
    if len(ids) != len(with_id):
        return None
    for comp, value in zip(with_id, ids, strict=True):
        comp.invoke_id = to_int(value)
    rejects = [c for c in components if c.kind == "reject"]
    derivable = packet.fields.get("gsm_old.derivable", [])
    if len(derivable) == len(rejects):
        for comp, value in zip(rejects, derivable, strict=True):
            comp.invoke_id = to_int(value)

    # Operation and error codes share gsm_old.localValue, in component order. Results
    # carry an operation code only when they return data.
    coded = [c for c in components if c.kind in ("invoke", "error")]
    results = [c for c in components if c.kind in ("result", "partial")]
    values = packet.fields.get("gsm_old.localValue", [])
    if len(values) == len(coded) + len(results):
        coded = [c for c in components if c.kind in ("invoke", "error", "result", "partial")]
    elif len(values) != len(coded):
        return None
    for comp, value in zip(coded, values, strict=True):
        comp.value = to_int(value)

    _attach_details(packet, messages, components)
    return messages, components


def _attach_details(packet: Packet, messages: list[_Message], components: list[_Component]):
    """Error diagnostics, reject problems, abort reasons and IMSIs, where unambiguous."""
    errors = [c for c in components if c.kind == "error"]
    if len(errors) == 1:
        extra = messages[errors[0].message].extra
        for name in MAP_DIAGNOSTICS:
            value = packet.first(name)
            if value is not None:
                extra[name] = [value]
    rejects = [c for c in components if c.kind == "reject"]
    if len(rejects) == 1:
        for name in REJECT_PROBLEMS:
            value = packet.first(name)
            if value is not None:
                extra = messages[rejects[0].message].extra
                extra["map.reject"] = [name]
                extra["map.reject.value"] = [value]
    aborts = [m for m in messages if m.type == "abort"]
    if len(aborts) == 1:
        aborts[0].extra.update(_abort_details(packet))
    elif aborts:
        causes = packet.fields.get("tcap.p_abortCause", [])
        for i, message in enumerate(aborts):
            if len(causes) == len(aborts):
                message.extra.update({"map.abort": ["p-abort"], "map.abort.value": [causes[i]]})
            else:
                message.extra.update({"map.abort": ["unknown"], "map.abort.value": [""]})

    imsis = packet.fields.get("e212.imsi", [])
    if len(messages) == 1:
        messages[0].imsi = imsis[0] if imsis else None
        return
    invokes = [c for c in components if c.kind == "invoke"]
    if imsis and len(imsis) == len(invokes) == len(components):
        for comp, imsi in zip(invokes, imsis, strict=True):
            messages[comp.message].imsi = imsi
    elif len(imsis) == 1 and len(invokes) == 1 and len(components) == 1:
        messages[invokes[0].message].imsi = imsis[0]


class MapCorrelator(Correlator):
    """Streaming MAP correlator; see the module docstring."""

    protocol = "map"

    def __init__(self) -> None:
        super().__init__()
        self.open: dict[tuple[str, int], Transaction] = {}
        self.peer: dict[str, str] = {}
        self.dialogue_imsi: dict[str, str] = {}
        self.recent: dict[tuple, float] = {}  # answered keys / ended dialogues -> time
        self.blind: set[str] = set()
        self.skipped_messages = 0

    # -- helpers ------------------------------------------------------------------------

    def _seen_recently(self, key: tuple, now: float) -> bool:
        seen = self.recent.get(key)
        return seen is not None and now - seen < DUPLICATE_WINDOW

    def _mark(self, key: tuple, now: float) -> None:
        self.recent[key] = now
        if len(self.recent) > 200_000:
            self.recent = {k: t for k, t in self.recent.items() if now - t < DUPLICATE_WINDOW}

    def _imsi(self, tid: str | None) -> str | None:
        if tid is None:
            return None
        return self.dialogue_imsi.get(tid) or self.dialogue_imsi.get(self.peer.get(tid, ""))

    @staticmethod
    def _packet(packet: Packet, fields: dict[str, list[str]]) -> Packet:
        return Packet(packet.number, packet.time, PROTOCOLS, fields)

    def _close(self, key: tuple[str, int], answer: Packet) -> Transaction | None:
        tx = self.open.pop(key, None)
        if tx is not None:
            tx.answer = answer
            self.done.append(tx)
        return tx

    def _end_dialogue(self, packet: Packet, message: _Message) -> None:
        tid = message.dtid
        if tid is None:
            return
        ends = {tid}
        if tid in self.peer:
            ends.add(self.peer[tid])
        aborted = message.type == "abort"
        if aborted and self._seen_recently(("ended", tid), packet.time):
            return  # the same ABORT seen again on another leg
        answer = self._packet(
            packet,
            {"map.component": ["abort" if aborted else "closed"], **message.extra},
        )
        closed = [key for key in self.open if key[0] in ends]
        for key in closed:
            self._close(key, answer)
        if aborted and not closed:
            orphan = Transaction("map", "MAP dialogue", None, imsi=self._imsi(tid))
            orphan.answer = answer
            self.done.append(orphan)
        self._mark(("ended", tid), packet.time)
        for t in ends:
            self.peer.pop(t, None)
            self.dialogue_imsi.pop(t, None)

    # -- Correlator -------------------------------------------------------------------

    def _open(self) -> list[Transaction]:
        return [
            tx
            for key, tx in self.open.items()
            if key[0] not in self.blind and self.peer.get(key[0]) not in self.blind
        ]

    def feed(self, packet: Packet) -> None:
        if not packet.has("tcap"):
            return
        split = split_messages(packet)
        if split is None:
            for name in ("tcap.otid", "tcap.dtid"):
                self.blind.update(_tid(v) for v in packet.fields.get(name, []))
            self.skipped_messages += sum(_count(packet, n) for n in MESSAGE_TYPES)
            return
        messages, components = split
        for message in messages:
            if message.type == "continue" and message.otid and message.dtid:
                self.peer[message.otid] = message.dtid
                self.peer[message.dtid] = message.otid
            if message.imsi and message.otid:
                self.dialogue_imsi[message.otid] = message.imsi
        for comp in components:
            message = messages[comp.message]
            if comp.kind == "invoke":
                self._invoke(packet, message, comp)
            elif comp.kind in ("result", "error", "reject"):
                self._outcome(packet, message, comp)
        for message in messages:
            if message.type in ("end", "abort"):
                self._end_dialogue(packet, message)

    def _invoke(self, packet: Packet, message: _Message, comp: _Component) -> None:
        if message.otid is None or comp.invoke_id is None:
            return
        key = (message.otid, comp.invoke_id)
        existing = self.open.get(key)
        if existing is not None and existing.request is not None:
            if (
                existing.request.first("map.op") == str(comp.value)
                and packet.time - existing.request.time < DUPLICATE_WINDOW
            ):
                return  # the same invoke seen again on another leg
            self._close(key, self._packet(packet, {"map.component": ["closed"]}))
        fields = {"map.op": [str(comp.value)]} if comp.value is not None else {}
        self.open[key] = Transaction(
            "map",
            operation_name(comp.value),
            self._packet(packet, fields),
            imsi=message.imsi or self._imsi(message.otid),
        )

    def _outcome(self, packet: Packet, message: _Message, comp: _Component) -> None:
        if message.dtid is None:
            return
        fields: dict[str, list[str]] = {"map.component": [comp.kind]}
        if comp.kind == "error" and comp.value is not None:
            fields["map.error"] = [str(comp.value)]
        fields.update(message.extra)
        answer = self._packet(packet, fields)
        if comp.invoke_id is not None:
            key = (message.dtid, comp.invoke_id)
            if self._close(key, answer) is not None:
                self._mark(key, packet.time)
                return
            if self._seen_recently(key, packet.time):
                return  # the same answer seen again on another leg
            self._mark(key, packet.time)
        name = operation_name(comp.value) if comp.kind == "result" else "MAP operation"
        orphan = Transaction("map", name, None, imsi=self._imsi(message.dtid))
        orphan.answer = answer
        self.done.append(orphan)
