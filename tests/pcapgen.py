"""Build small synthetic captures for tests.

Everything is generated: test-network IMSIs (MCC 001 / MNC 01), RFC 5737 addresses and
example.org realms. No real traffic is ever committed.
"""

from __future__ import annotations

import struct
from pathlib import Path

TEST_IMSI = "001010000000001"
HOST_A = bytes([192, 0, 2, 10])  # e.g. MME
HOST_B = bytes([192, 0, 2, 20])  # e.g. HSS / SGW

# ---- link / network / transport --------------------------------------------------------


def _ipv4(src: bytes, dst: bytes, proto: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, src, dst)
    return header + payload


def _eth(payload: bytes) -> bytes:
    return b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00" + payload


def udp_frame(src: bytes, dst: bytes, sport: int, dport: int, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return _eth(_ipv4(src, dst, 17, udp))


class TcpFlow:
    """Minimal TCP stream (no handshake) so tshark dissects payloads by port."""

    def __init__(self, a: bytes, b: bytes, aport: int, bport: int) -> None:
        self.a, self.b, self.aport, self.bport = a, b, aport, bport
        self.seq = {True: 1000, False: 5000}

    def frame(self, from_a: bool, payload: bytes) -> bytes:
        src, dst = (self.a, self.b) if from_a else (self.b, self.a)
        sport, dport = (self.aport, self.bport) if from_a else (self.bport, self.aport)
        seq, ack = self.seq[from_a], self.seq[not from_a]
        tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, 0x18, 65535, 0, 0)
        self.seq[from_a] += len(payload)
        return _eth(_ipv4(src, dst, 6, tcp + payload))


def write_pcap(path: Path, frames: list[tuple[float, bytes]]) -> Path:
    with path.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in frames:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            fh.write(frame)
    return path


# ---- Diameter ---------------------------------------------------------------------------

VENDOR_3GPP = 10415
S6A_APP = 16777251


def avp(code: int, data: bytes, vendor: int | None = None, mandatory: bool = True) -> bytes:
    flags = (0x40 if mandatory else 0) | (0x80 if vendor else 0)
    header_len = 12 if vendor else 8
    length = header_len + len(data)
    out = struct.pack("!IB", code, flags) + length.to_bytes(3, "big")
    if vendor:
        out += struct.pack("!I", vendor)
    out += data
    return out + b"\x00" * (-len(out) % 4)


def avp_u32(code: int, value: int, vendor: int | None = None) -> bytes:
    return avp(code, struct.pack("!I", value), vendor)


def avp_str(code: int, value: str, vendor: int | None = None) -> bytes:
    return avp(code, value.encode(), vendor)


def diameter(
    cmd: int, request: bool, hbh: int, e2e: int, avps: list[bytes], app: int = S6A_APP
) -> bytes:
    body = b"".join(avps)
    flags = 0xC0 if request else 0x40
    length = 20 + len(body)
    return (
        bytes([1])
        + length.to_bytes(3, "big")
        + bytes([flags])
        + cmd.to_bytes(3, "big")
        + struct.pack("!III", app, hbh, e2e)
        + body
    )


def _common(session: str, host: str) -> list[bytes]:
    return [
        avp_str(263, session),
        avp_str(264, host),
        avp_str(296, "example.org"),
    ]


def s6a_request(cmd: int, hbh: int, imsi: str = TEST_IMSI) -> bytes:
    return diameter(
        cmd,
        True,
        hbh,
        hbh + 1,
        [
            *_common(f"mme.example.org;{hbh}", "mme.example.org"),
            avp_str(283, "example.org"),
            avp_u32(277, 1),
            avp_str(1, imsi),
        ],
    )


def s6a_answer(
    cmd: int, hbh: int, result: int | None = 2001, experimental: int | None = None
) -> bytes:
    avps = _common(f"mme.example.org;{hbh}", "hss.example.org")
    if experimental is not None:
        avps.append(avp(297, avp_u32(266, VENDOR_3GPP) + avp_u32(298, experimental)))
    elif result is not None:
        avps.append(avp_u32(268, result))
    avps.append(avp_u32(277, 1))
    return diameter(cmd, False, hbh, hbh + 1, avps)


# ---- Gx / Gy (policy and charging) --------------------------------------------------------

GX_APP = 16777238
GY_APP = 4  # Diameter Credit-Control (Gy/Ro)
CC_INITIAL, CC_UPDATE, CC_TERMINATION = 1, 2, 3


def avp_group(code: int, children: list[bytes], vendor: int | None = None) -> bytes:
    return avp(code, b"".join(children), vendor)


def _experimental(code: int) -> bytes:
    return avp_group(297, [avp_u32(266, VENDOR_3GPP), avp_u32(298, code)])


def ccr(
    hbh: int,
    app: int = GY_APP,
    req_type: int = CC_INITIAL,
    imsi: str | None = TEST_IMSI,
    apn: str = "internet",
    extra: list[bytes] | None = None,
) -> bytes:
    avps = [
        *_common(f"pgw.example.org;{hbh}", "pgw.example.org"),
        avp_str(283, "example.org"),
        avp_u32(258, app),
        avp_u32(416, req_type),
        avp_u32(415, 0),
    ]
    if imsi:
        avps.append(avp_group(443, [avp_u32(450, 1), avp_str(444, imsi)]))
    avps.append(avp_str(30, apn))
    avps += extra or []
    return diameter(272, True, hbh, hbh + 1, avps, app=app)


def cca(
    hbh: int,
    app: int = GY_APP,
    req_type: int = CC_INITIAL,
    result: int | None = 2001,
    experimental: int | None = None,
    extra: list[bytes] | None = None,
) -> bytes:
    server = "ocs.example.org" if app == GY_APP else "pcrf.example.org"
    avps = [*_common(f"pgw.example.org;{hbh}", server), avp_u32(258, app)]
    if experimental is not None:
        avps.append(_experimental(experimental))
    elif result is not None:
        avps.append(avp_u32(268, result))
    avps += [avp_u32(416, req_type), avp_u32(415, 0)]
    avps += extra or []
    return diameter(272, False, hbh, hbh + 1, avps, app=app)


def mscc(rating_group: int, result: int | None = None, final_action: int | None = None) -> bytes:
    children = [avp_u32(432, rating_group)]
    if final_action is not None:
        children.append(avp_group(430, [avp_u32(449, final_action)]))
    if result is not None:
        children.append(avp_u32(268, result))
    return avp_group(456, children)


def charging_rule_report(rule: str, failure_code: int, status: int = 1) -> bytes:
    return avp_group(
        1018,
        [
            avp_str(1005, rule, VENDOR_3GPP),
            avp_u32(1019, status, VENDOR_3GPP),
            avp_u32(1031, failure_code, VENDOR_3GPP),
        ],
        VENDOR_3GPP,
    )


# ---- GTPv2-C ----------------------------------------------------------------------------


def _ie(ie_type: int, data: bytes, instance: int = 0) -> bytes:
    return struct.pack("!BHB", ie_type, len(data), instance & 0x0F) + data


def tbcd(digits: str) -> bytes:
    if len(digits) % 2:
        digits += "F"
    return bytes(int(digits[i + 1], 16) << 4 | int(digits[i], 16) for i in range(0, len(digits), 2))


def ie_imsi(imsi: str) -> bytes:
    return _ie(1, tbcd(imsi))


def ie_apn(apn: str) -> bytes:
    data = b"".join(bytes([len(label)]) + label.encode() for label in apn.split("."))
    return _ie(71, data)


def ie_cause(cause: int, remote: bool = False) -> bytes:
    # flags octet: bit 0 = CS (cause source: 1 = originated by a remote node)
    return _ie(2, bytes([cause, 0x01 if remote else 0x00]))


def ie_pdn_type(pdn_type: int) -> bytes:
    """1 = IPv4, 2 = IPv6, 3 = IPv4v6."""
    return _ie(99, bytes([pdn_type]))


def gtpv2(msg_type: int, seq: int, ies: list[bytes], teid: int = 0) -> bytes:
    body = b"".join(ies)
    length = 8 + len(body)  # TEID + seq + spare + IEs
    return (
        bytes([0x48, msg_type])
        + struct.pack("!H", length)
        + struct.pack("!I", teid)
        + seq.to_bytes(3, "big")
        + b"\x00"
        + body
    )


def gtpv2_frame(from_a: bool, payload: bytes) -> bytes:
    src, dst = (HOST_A, HOST_B) if from_a else (HOST_B, HOST_A)
    return udp_frame(src, dst, 2123, 2123, payload)


# ---- RADIUS -----------------------------------------------------------------------------

AAA_HOST = bytes([192, 0, 2, 30])


def radius(code: int, ident: int, attrs: list[tuple[int, bytes]] = ()) -> bytes:
    body = b"".join(bytes([t, 2 + len(v)]) + v for t, v in attrs)
    return struct.pack("!BBH", code, ident, 20 + len(body)) + b"\x00" * 16 + body


def radius_frame(from_gateway: bool, payload: bytes) -> bytes:
    src, dst = (HOST_B, AAA_HOST) if from_gateway else (AAA_HOST, HOST_B)
    sport, dport = (40100, 1812) if from_gateway else (1812, 40100)
    return udp_frame(src, dst, sport, dport, payload)


# ---- PFCP -------------------------------------------------------------------------------

UPF_HOST = bytes([192, 0, 2, 40])


def _pfcp_ie(ie_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ie_type, len(data)) + data


def pfcp(msg_type: int, seq: int, seid: int | None = None, cause: int | None = None) -> bytes:
    body = _pfcp_ie(19, bytes([cause])) if cause is not None else b""
    if seid is None:
        header_rest = seq.to_bytes(3, "big") + b"\x00"
        flags = 0x20
    else:
        header_rest = struct.pack("!Q", seid) + seq.to_bytes(3, "big") + b"\x00"
        flags = 0x21
    length = len(header_rest) + len(body)
    return bytes([flags, msg_type]) + struct.pack("!H", length) + header_rest + body


def pfcp_frame(from_smf: bool, payload: bytes) -> bytes:
    src, dst = (HOST_B, UPF_HOST) if from_smf else (UPF_HOST, HOST_B)
    return udp_frame(src, dst, 8805, 8805, payload)


# ---- GTP-U ------------------------------------------------------------------------------

UE_IP = bytes([10, 45, 0, 5])
DN_IP = bytes([203, 0, 113, 8])  # RFC 5737 TEST-NET-3, stands in for an internet host


def icmp_echo(src: bytes, dst: bytes, reply: bool = False) -> bytes:
    icmp = bytes([0 if reply else 8, 0]) + b"\x00\x00" + b"\x00\x01\x00\x01" + b"ping"
    return _ipv4(src, dst, 1, icmp)


def gtpu_frame(uplink: bool, inner: bytes, teid: int = 0xA002) -> bytes:
    gtp = bytes([0x30, 0xFF]) + struct.pack("!HI", len(inner), teid) + inner
    src, dst = (HOST_A, UPF_HOST) if uplink else (UPF_HOST, HOST_A)
    return udp_frame(src, dst, 2152, 2152, gtp)


def plain_ip_frame(inner: bytes) -> bytes:
    return _eth(inner)
