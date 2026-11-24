"""Test fixtures. Captures are synthesized at test time so no real traffic is ever committed."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest


def _udp_frame(src_port: int, dst_port: int, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        1,
        0,
        64,
        17,
        0,
        bytes([192, 0, 2, 1]),
        bytes([192, 0, 2, 2]),  # RFC 5737 documentation range
    )
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    return eth + ip_header + udp


def write_pcap(path: Path, frames: list[bytes]) -> Path:
    with path.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, frame in enumerate(frames):
            fh.write(struct.pack("<IIII", 1_700_000_000 + i, 0, len(frame), len(frame)))
            fh.write(frame)
    return path


@pytest.fixture
def plain_udp_capture(tmp_path: Path) -> Path:
    return write_pcap(tmp_path / "udp.pcap", [_udp_frame(40000, 9999, b"hello")] * 3)
