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


@dataclass
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


def diameter_name(cmd: int, is_request: bool) -> str:
    names = DIAMETER_COMMANDS.get(cmd)
    if names is None:
        return f"Diameter cmd {cmd} {'request' if is_request else 'answer'}"
    return names[0] if is_request else names[1]


def correlate_diameter(packets: Iterable[Packet]) -> list[Transaction]:
    """Pair Diameter requests and answers by (hop-by-hop id, end-to-end id, command).

    Frames carrying several Diameter messages are paired on the per-message header fields;
    result codes are only trusted when the frame carries a single message.
    """
    open_requests: dict[tuple[int, int, int], Transaction] = {}
    done: list[Transaction] = []
    for packet in packets:
        if not packet.has("diameter"):
            continue
        cmds = packet.fields.get("diameter.cmd.code", [])
        flags = packet.fields.get("diameter.flags.request", [])
        hbhs = packet.fields.get("diameter.hopbyhopid", [])
        e2es = packet.fields.get("diameter.endtoendid", [])
        for i, raw_cmd in enumerate(cmds):
            cmd = to_int(raw_cmd)
            hbh = to_int(hbhs[i]) if i < len(hbhs) else None
            e2e = to_int(e2es[i]) if i < len(e2es) else None
            if cmd is None or hbh is None or e2e is None:
                continue
            is_request = to_bool(flags[i]) if i < len(flags) else False
            key = (hbh, e2e, cmd)
            if is_request:
                tx = Transaction(
                    "diameter",
                    diameter_name(cmd, True),
                    packet,
                    imsi=packet.first("diameter.User-Name"),
                )
                open_requests[key] = tx
            else:
                tx = open_requests.pop(key, None)
                if tx is None:
                    tx = Transaction("diameter", diameter_name(cmd, True), None)
                tx.answer = packet
                done.append(tx)
    done.extend(open_requests.values())
    return sorted(done, key=lambda t: t.first_packet.number)


RETRANSMIT_WINDOW = 10.0  # seconds; GTPv2-C sequence numbers wrap far slower than this


def correlate_gtpv2(packets: Iterable[Packet]) -> list[Transaction]:
    """Pair GTPv2-C requests and responses by sequence number and message type.

    Retransmitted requests and repeated responses (same sequence number) are folded into
    one transaction and counted, so a retransmission storm is not mistaken for many failures.
    """
    responses = {v: k for k, v in GTPV2_PAIRS.items()}
    open_requests: dict[tuple[int, int], Transaction] = {}
    answered: dict[tuple[int, int], Transaction] = {}
    done: list[Transaction] = []
    for packet in packets:
        if not packet.has("gtpv2"):
            continue
        mtype = to_int(packet.first("gtpv2.message_type"))
        seq = to_int(packet.first("gtpv2.seq"))
        if mtype is None or seq is None:
            continue
        if mtype in GTPV2_PAIRS:
            key = (seq, GTPV2_PAIRS[mtype])
            if key in open_requests:
                open_requests[key].retransmissions += 1
                continue
            previous = answered.get(key)
            if (
                previous is not None
                and previous.request is not None
                and packet.time - previous.request.time < RETRANSMIT_WINDOW
                and packet.first("e212.imsi") == previous.imsi
            ):
                # retransmitted request after the answer was already sent
                previous.retransmissions += 1
                continue
            tx = Transaction(
                "gtpv2",
                GTPV2_MESSAGES.get(mtype, f"GTPv2 type {mtype}"),
                packet,
                imsi=packet.first("e212.imsi"),
            )
            open_requests[key] = tx
        elif mtype in responses:
            key = (seq, mtype)
            tx = open_requests.pop(key, None)
            if tx is None:
                previous = answered.get(key)
                if (
                    previous is not None
                    and previous.answer is not None
                    and packet.time - previous.answer.time < RETRANSMIT_WINDOW
                ):
                    # repeated answer to a retransmitted request; already counted there
                    continue
                req_type = responses[mtype]
                tx = Transaction("gtpv2", GTPV2_MESSAGES.get(req_type, str(req_type)), None)
            tx.answer = packet
            answered[key] = tx
            done.append(tx)
    done.extend(open_requests.values())
    return sorted(done, key=lambda t: t.first_packet.number)


def correlate_pfcp(packets: Iterable[Packet]) -> list[Transaction]:
    """Pair PFCP requests and responses by sequence number and message type.

    Retransmissions (same sequence number while still open) are counted, not duplicated.
    """
    responses = {v: k for k, v in PFCP_PAIRS.items()}
    open_requests: dict[tuple[int, int], Transaction] = {}
    done: list[Transaction] = []
    for packet in packets:
        if not packet.has("pfcp"):
            continue
        mtype = to_int(packet.first("pfcp.msg_type"))
        seq = to_int(packet.first("pfcp.seqno"))
        if mtype is None or seq is None:
            continue
        if mtype in PFCP_PAIRS:
            key = (seq, PFCP_PAIRS[mtype])
            if key in open_requests:
                open_requests[key].retransmissions += 1
                continue
            name = PFCP_MESSAGES.get(mtype, f"type {mtype}").removesuffix(" Request")
            open_requests[key] = Transaction("pfcp", name, packet)
        elif mtype in responses:
            tx = open_requests.pop((seq, mtype), None)
            if tx is None:
                req = responses[mtype]
                tx = Transaction(
                    "pfcp", PFCP_MESSAGES.get(req, str(req)).removesuffix(" Request"), None
                )
            tx.answer = packet
            done.append(tx)
    done.extend(open_requests.values())
    return sorted(done, key=lambda t: t.first_packet.number)
