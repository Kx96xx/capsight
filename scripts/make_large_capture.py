"""Generate a large synthetic capture for performance measurements.

    uv run python scripts/make_large_capture.py --packets 1000000 --out /tmp/large.pcap
    /usr/bin/time -l uv run capsight analyze --format json /tmp/large.pcap > /dev/null

Busy-core traffic: each subscriber authenticates and updates location over S6a, then opens
a session over GTPv2-C. About 1% of authentications get user unknown (5001) and 1% of
sessions get missing or unknown APN (78), so the findings are grouped, not flooded. Every
capture is synthetic: test-network IMSIs (001/01), RFC 5737 addresses, example.org.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from pcapgen import (  # noqa: E402
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
)

T0 = 1_700_000_000.0
AIR, ULR, CS_REQ, CS_RESP = 318, 316, 32, 33
FRAMES_PER_SUBSCRIBER = 6


def subscriber_frames(i: int, flow: TcpFlow, t: float) -> list[tuple[float, bytes]]:
    imsi = f"00101{i:010d}"
    hbh = (2 * i) & 0xFFFFFFFF
    unknown = i % 100 == 7
    frames = [
        (t, flow.frame(True, s6a_request(AIR, hbh, imsi))),
        (t + 0.01, flow.frame(False, s6a_answer(AIR, hbh, experimental=5001 if unknown else None))),
    ]
    if unknown:
        return frames
    hbh += 1
    seq = i & 0xFFFFFF
    cause = 78 if i % 100 == 42 else 16
    return frames + [
        (t + 0.1, flow.frame(True, s6a_request(ULR, hbh, imsi))),
        (t + 0.11, flow.frame(False, s6a_answer(ULR, hbh))),
        (t + 0.2, gtpv2_frame(True, gtpv2(CS_REQ, seq, [ie_imsi(imsi), ie_apn("internet")]))),
        (t + 0.23, gtpv2_frame(False, gtpv2(CS_RESP, seq, [ie_cause(cause)], teid=0x1000))),
    ]


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--packets", type=int, default=1_000_000)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    flow = TcpFlow(HOST_A, HOST_B, 40001, 3868)
    written = 0
    with args.out.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        i = 0
        while written < args.packets:
            # one new subscriber every 5 ms: about 1,200 packets per second
            for ts, frame in subscriber_frames(i, flow, T0 + i * 0.005):
                sec = int(ts)
                fh.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(frame), len(frame)))
                fh.write(frame)
                written += 1
            i += 1
    print(f"{args.out}: {written} packets, {i} subscribers")


if __name__ == "__main__":
    main()
