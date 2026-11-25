"""Pair requests with answers so rules reason about transactions, not single packets."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from capsight.codes import DIAMETER_COMMANDS, GTPV2_MESSAGES, GTPV2_PAIRS
from capsight.codes_5g import PFCP_MESSAGES, PFCP_PAIRS
from capsight.model import Packet


def to_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value, 0)
    except ValueError:
        try:
            return int(float(value))
        except ValueError:
            return None


def to_bool(value: str | None) -> bool:
    return str(value).lower() in {"1", "true", "yes"}


@dataclass(slots=True)
class Transaction:
    protocol: str
    name: str
    request: Packet | None
    answer: Packet | None = None
    imsi: str | None = None
    retransmissions: int = 0

    @property
    def first_packet(self) -> Packet:
        packet = self.request or self.answer
        assert packet is not None
        return packet


# Fields rules read from a transaction's request/answer after pairing. Pairing keys
# (hop-by-hop ids, sequence numbers, Session-Id, ...) are dropped once used, so a capture
# with millions of transactions stays small in memory.
TX_FIELDS = frozenset(
    (
        "diameter.Result-Code",
        "diameter.Experimental-Result-Code",
        "diameter.applicationId",
        "diameter.Auth-Application-Id",
        "diameter.CC-Request-Type",
        "diameter.Called-Station-Id",
        "diameter.Rating-Group",
        "diameter.Final-Unit-Action",
        "diameter.Charging-Rule-Name",
        "diameter.PCC-Rule-Status",
        "diameter.Rule-Failure-Code",
        "gtpv2.cause",
        "gtpv2.f_teid_interface_type",
        "gtpv2.rat_type",
        "e212.serv_net.mcc",
        "e212.serv_net.mnc",
        "diameter.Visited-PLMN-Id",
        "gtpv2.cs",
        "gtpv2.apn",
        "gtpv2.pdn_type",
        "e212.imsi",
        "pfcp.cause",
    )
)


def slim(packet: Packet, keep: frozenset[str] = TX_FIELDS) -> Packet:
    return Packet(
        packet.number,
        packet.time,
        packet.protocols,
        {k: v for k, v in packet.fields.items() if k in keep},
    )


SUBSCRIPTION_ID_IMSI = "1"  # Subscription-Id-Type END_USER_IMSI (RFC 4006)


def diameter_imsi(packet: Packet) -> str | None:
    """IMSI from User-Name (S6a) or from Subscription-Id of type END_USER_IMSI (Gx/Gy)."""
    user = packet.first("diameter.User-Name")
    if user:
        return user
    types = packet.fields.get("diameter.Subscription-Id-Type", [])
    data = packet.fields.get("diameter.Subscription-Id-Data", [])
    for kind, value in zip(types, data, strict=False):
        if kind == SUBSCRIPTION_ID_IMSI and value.isdigit():
            return value
    return None


def diameter_name(cmd: int, is_request: bool) -> str:
    names = DIAMETER_COMMANDS.get(cmd)
    if names is None:
        return f"Diameter cmd {cmd} {'request' if is_request else 'answer'}"
    return names[0] if is_request else names[1]


class Correlator:
    """Pairs requests with answers one packet at a time (streaming)."""

    protocol = ""

    def __init__(self) -> None:
        self.done: list[Transaction] = []

    def feed(self, packet: Packet) -> None:
        raise NotImplementedError

    def _open(self) -> list[Transaction]:
        raise NotImplementedError

    def finish(self) -> list[Transaction]:
        txs = self.done + self._open()
        return sorted(txs, key=lambda t: t.first_packet.number)


class DiameterCorrelator(Correlator):
    """Pair Diameter requests and answers by (hop-by-hop id, end-to-end id, command).

    Frames carrying several Diameter messages are paired on the per-message header fields;
    result codes are only trusted when the frame carries a single message.
    """

    protocol = "diameter"

    def __init__(self) -> None:
        super().__init__()
        self.open_requests: dict[tuple[int, int, int], Transaction] = {}

    def _open(self) -> list[Transaction]:
        return list(self.open_requests.values())

    def feed(self, packet: Packet) -> None:
        if not packet.has("diameter"):
            return
        cmds = packet.fields.get("diameter.cmd.code", [])
        flags = packet.fields.get("diameter.flags.request", [])
        hbhs = packet.fields.get("diameter.hopbyhopid", [])
        e2es = packet.fields.get("diameter.endtoendid", [])
        stored = slim(packet)
        for i, raw_cmd in enumerate(cmds):
            cmd = to_int(raw_cmd)
            hbh = to_int(hbhs[i]) if i < len(hbhs) else None
            e2e = to_int(e2es[i]) if i < len(e2es) else None
            if cmd is None or hbh is None or e2e is None:
                continue
            is_request = to_bool(flags[i]) if i < len(flags) else False
            key = (hbh, e2e, cmd)
            if is_request:
                self.open_requests[key] = Transaction(
                    "diameter",
                    diameter_name(cmd, True),
                    stored,
                    imsi=diameter_imsi(packet),
                )
            else:
                tx = self.open_requests.pop(key, None)
                if tx is None:
                    tx = Transaction("diameter", diameter_name(cmd, True), None)
                tx.answer = stored
                self.done.append(tx)


RETRANSMIT_WINDOW = 10.0  # seconds; GTPv2-C sequence numbers wrap far slower than this


class Gtpv2Correlator(Correlator):
    """Pair GTPv2-C requests and responses by sequence number and message type.

    Retransmitted requests and repeated responses (same sequence number) are folded into
    one transaction and counted, so a retransmission storm is not mistaken for many failures.
    """

    protocol = "gtpv2"

    def __init__(self) -> None:
        super().__init__()
        self.responses = {v: k for k, v in GTPV2_PAIRS.items()}
        self.open_requests: dict[tuple[int, int], Transaction] = {}
        self.answered: dict[tuple[int, int], Transaction] = {}

    def _open(self) -> list[Transaction]:
        return list(self.open_requests.values())

    def feed(self, packet: Packet) -> None:
        if not packet.has("gtpv2"):
            return
        mtype = to_int(packet.first("gtpv2.message_type"))
        seq = to_int(packet.first("gtpv2.seq"))
        if mtype is None or seq is None:
            return
        if mtype in GTPV2_PAIRS:
            key = (seq, GTPV2_PAIRS[mtype])
            if key in self.open_requests:
                self.open_requests[key].retransmissions += 1
                return
            previous = self.answered.get(key)
            if (
                previous is not None
                and previous.request is not None
                and packet.time - previous.request.time < RETRANSMIT_WINDOW
                and packet.first("e212.imsi") == previous.imsi
            ):
                # retransmitted request after the answer was already sent
                previous.retransmissions += 1
                return
            self.open_requests[key] = Transaction(
                "gtpv2",
                GTPV2_MESSAGES.get(mtype, f"GTPv2 type {mtype}"),
                slim(packet),
                imsi=packet.first("e212.imsi"),
            )
        elif mtype in self.responses:
            key = (seq, mtype)
            tx = self.open_requests.pop(key, None)
            if tx is None:
                previous = self.answered.get(key)
                if (
                    previous is not None
                    and previous.answer is not None
                    and packet.time - previous.answer.time < RETRANSMIT_WINDOW
                ):
                    # repeated answer to a retransmitted request; already counted there
                    return
                req_type = self.responses[mtype]
                tx = Transaction("gtpv2", GTPV2_MESSAGES.get(req_type, str(req_type)), None)
            tx.answer = slim(packet)
            self.answered[key] = tx
            self.done.append(tx)


class PfcpCorrelator(Correlator):
    """Pair PFCP requests and responses by sequence number and message type.

    Retransmissions (same sequence number while still open) are counted, not duplicated.
    """

    protocol = "pfcp"

    def __init__(self) -> None:
        super().__init__()
        self.responses = {v: k for k, v in PFCP_PAIRS.items()}
        self.open_requests: dict[tuple[int, int], Transaction] = {}

    def _open(self) -> list[Transaction]:
        return list(self.open_requests.values())

    def feed(self, packet: Packet) -> None:
        if not packet.has("pfcp"):
            return
        mtype = to_int(packet.first("pfcp.msg_type"))
        seq = to_int(packet.first("pfcp.seqno"))
        if mtype is None or seq is None:
            return
        if mtype in PFCP_PAIRS:
            key = (seq, PFCP_PAIRS[mtype])
            if key in self.open_requests:
                self.open_requests[key].retransmissions += 1
                return
            name = PFCP_MESSAGES.get(mtype, f"type {mtype}").removesuffix(" Request")
            self.open_requests[key] = Transaction("pfcp", name, slim(packet))
        elif mtype in self.responses:
            tx = self.open_requests.pop((seq, mtype), None)
            if tx is None:
                req = self.responses[mtype]
                tx = Transaction(
                    "pfcp", PFCP_MESSAGES.get(req, str(req)).removesuffix(" Request"), None
                )
            tx.answer = slim(packet)
            self.done.append(tx)


def _run(correlator: Correlator, packets: Iterable[Packet]) -> list[Transaction]:
    for packet in packets:
        correlator.feed(packet)
    return correlator.finish()


def correlate_diameter(packets: Iterable[Packet]) -> list[Transaction]:
    return _run(DiameterCorrelator(), packets)


def correlate_gtpv2(packets: Iterable[Packet]) -> list[Transaction]:
    return _run(Gtpv2Correlator(), packets)


def correlate_pfcp(packets: Iterable[Packet]) -> list[Transaction]:
    return _run(PfcpCorrelator(), packets)
