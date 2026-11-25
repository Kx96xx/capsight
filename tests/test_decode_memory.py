"""Large-capture memory savings in the decoder."""

import json

from capsight.decode import parse_ek_line


def ek(fields: dict) -> str:
    return json.dumps({"timestamp": "0", "layers": fields})


def test_non_core_packet_keeps_only_ip():
    line = ek(
        {
            "frame_number": ["5"],
            "frame_time_epoch": ["1.5"],
            "frame_protocols": ["eth:ethertype:ip:tcp:tls"],
            "ip_src": ["192.0.2.1"],
            "ip_dst": ["192.0.2.2"],
            "tcp_srcport": ["443"],
        }
    )
    packet = parse_ek_line(line, ("ip.src", "ip.dst", "tcp.srcport"))
    assert packet.fields == {"ip.src": ["192.0.2.1"], "ip.dst": ["192.0.2.2"]}


def test_core_packet_keeps_everything_and_shares_values():
    def line(n):
        return ek(
            {
                "frame_number": [str(n)],
                "frame_time_epoch": ["1.0"],
                "frame_protocols": ["eth:ethertype:ip:sctp:diameter"],
                "diameter_Result-Code": ["2001"],
                "diameter_User-Name": ["001010000000001"],
            }
        )

    names = ("diameter.Result-Code", "diameter.User-Name")
    a, b = parse_ek_line(line(1), names), parse_ek_line(line(2), names)
    assert a.fields["diameter.User-Name"] == ["001010000000001"]
    assert a.fields["diameter.User-Name"][0] is b.fields["diameter.User-Name"][0]
    assert a.protocols is b.protocols


def test_scalar_values_become_lists():
    packet = parse_ek_line(
        ek(
            {
                "frame_number": "1",
                "frame_time_epoch": "1.0",
                "frame_protocols": "eth:ip:udp:gtpv2",
                "gtpv2_cause": "16",
            }
        ),
        ("gtpv2.cause",),
    )
    assert packet.number == 1
    assert packet.fields == {"gtpv2.cause": ["16"]}
