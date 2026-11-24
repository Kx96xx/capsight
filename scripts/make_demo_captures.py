"""Generate small demo captures into samples/synthetic/ so you can try capsight immediately.

    uv run python scripts/make_demo_captures.py
    uv run capsight analyze samples/synthetic/attach-user-unknown.pcap

Every capture is synthetic: test-network IMSIs (001/01), RFC 5737 addresses, example.org.
"""

from __future__ import annotations

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
    ie_pdn_type,
    radius,
    radius_frame,
    s6a_answer,
    s6a_request,
    write_pcap,
)

T0 = 1_700_000_000.0
OUT = ROOT / "samples" / "synthetic"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    flow = TcpFlow(HOST_A, HOST_B, 40001, 3868)
    demos = {
        "attach-user-unknown.pcap": [
            (T0, flow.frame(True, s6a_request(318, 0x100))),
            (T0 + 0.01, flow.frame(False, s6a_answer(318, 0x100))),
            (T0 + 0.10, flow.frame(True, s6a_request(316, 0x101))),
            (T0 + 0.11, flow.frame(False, s6a_answer(316, 0x101, experimental=5001))),
        ],
        "wrong-apn.pcap": [
            (
                T0,
                gtpv2_frame(True, gtpv2(32, 9, [ie_imsi("001010000000002"), ie_apn("wrong.apn")])),
            ),
            (T0 + 0.02, gtpv2_frame(False, gtpv2(33, 9, [ie_cause(78)], teid=0x1234))),
        ],
        "radius-accept-then-reject.pcap": [
            (T0, gtpv2_frame(True, gtpv2(32, 1, [ie_imsi("001010000000003"), ie_apn("internet")]))),
            (T0 + 0.01, radius_frame(True, radius(1, 7))),
            (T0 + 0.02, radius_frame(False, radius(2, 7))),
            (T0 + 0.03, gtpv2_frame(False, gtpv2(33, 1, [ie_cause(92)], teid=0x1234))),
        ],
        "ipv4v6-rejected.pcap": [
            (
                T0,
                gtpv2_frame(
                    True,
                    gtpv2(32, 1, [ie_imsi("001010000000004"), ie_apn("internet"), ie_pdn_type(3)]),
                ),
            ),
            (T0 + 0.01, gtpv2_frame(False, gtpv2(33, 1, [ie_cause(83)], teid=0x1234))),
            (
                T0 + 3,
                gtpv2_frame(
                    True,
                    gtpv2(32, 2, [ie_imsi("001010000000004"), ie_apn("internet"), ie_pdn_type(1)]),
                ),
            ),
            (T0 + 3.01, gtpv2_frame(False, gtpv2(33, 2, [ie_cause(16)], teid=0x1234))),
        ],
    }
    for name, frames in demos.items():
        write_pcap(OUT / name, frames)
        print(OUT / name)


if __name__ == "__main__":
    main()
