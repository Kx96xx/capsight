"""Shared fixtures. Captures are synthesized at test time; see tests/pcapgen.py."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from pcapgen import (
    HOST_A,
    HOST_B,
    TcpFlow,
    gtpv2,
    gtpv2_frame,
    ie_apn,
    ie_cause,
    ie_imsi,
    s6a_answer,
    s6a_request,
    udp_frame,
    write_pcap,
)

needs_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")

T0 = 1_700_000_000.0


@pytest.fixture
def plain_udp_capture(tmp_path: Path) -> Path:
    frame = udp_frame(HOST_A, HOST_B, 40000, 9999, b"hello")
    return write_pcap(tmp_path / "udp.pcap", [(T0 + i, frame) for i in range(3)])


@pytest.fixture
def ula_user_unknown(tmp_path: Path) -> Path:
    """AIR ok, then ULR answered with Experimental-Result-Code 5001."""
    flow = TcpFlow(HOST_A, HOST_B, 40001, 3868)
    frames = [
        (T0, flow.frame(True, s6a_request(318, 0x100))),
        (T0 + 0.01, flow.frame(False, s6a_answer(318, 0x100, result=2001))),
        (T0 + 0.10, flow.frame(True, s6a_request(316, 0x101))),
        (T0 + 0.11, flow.frame(False, s6a_answer(316, 0x101, experimental=5001))),
    ]
    return write_pcap(tmp_path / "ula-5001.pcap", frames)


@pytest.fixture
def diameter_timeout(tmp_path: Path) -> Path:
    """An AIR that is never answered, followed by unrelated traffic 10 s later."""
    flow = TcpFlow(HOST_A, HOST_B, 40002, 3868)
    frames = [
        (T0, flow.frame(True, s6a_request(318, 0x200))),
        (T0 + 10, udp_frame(HOST_A, HOST_B, 40000, 9999, b"x")),
    ]
    return write_pcap(tmp_path / "air-timeout.pcap", frames)


@pytest.fixture
def healthy_attach(tmp_path: Path) -> Path:
    flow = TcpFlow(HOST_A, HOST_B, 40003, 3868)
    frames = [
        (T0, flow.frame(True, s6a_request(318, 0x300))),
        (T0 + 0.01, flow.frame(False, s6a_answer(318, 0x300))),
        (T0 + 0.02, flow.frame(True, s6a_request(316, 0x301))),
        (T0 + 0.03, flow.frame(False, s6a_answer(316, 0x301))),
        (
            T0 + 0.04,
            gtpv2_frame(True, gtpv2(32, 7, [ie_imsi("001010000000001"), ie_apn("internet")])),
        ),
        (T0 + 0.05, gtpv2_frame(False, gtpv2(33, 7, [ie_cause(16)], teid=0x1234))),
    ]
    return write_pcap(tmp_path / "healthy.pcap", frames)


@pytest.fixture
def csr_unknown_apn(tmp_path: Path) -> Path:
    frames = [
        (T0, gtpv2_frame(True, gtpv2(32, 9, [ie_imsi("001010000000001"), ie_apn("wrong.apn")]))),
        (T0 + 0.02, gtpv2_frame(False, gtpv2(33, 9, [ie_cause(78)], teid=0x1234))),
    ]
    return write_pcap(tmp_path / "csr-78.pcap", frames)
