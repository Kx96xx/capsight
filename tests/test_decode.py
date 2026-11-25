import json

from conftest import needs_tshark

from capsight.decode import build_command, parse_ek_line, read_packets


def test_index_lines_are_skipped():
    assert parse_ek_line('{"index":{"_index":"packets-2026-01-01"}}') is None
    assert parse_ek_line("") is None


def test_parse_ek_line():
    doc = {
        "timestamp": "1700000000000",
        "layers": {
            "frame_number": ["7"],
            "frame_time_epoch": ["1700000000.5"],
            "frame_protocols": ["eth:ethertype:ip:sctp:diameter"],
            "diameter_cmd_code": ["316"],
        },
    }
    packet = parse_ek_line(json.dumps(doc))
    assert packet is not None
    assert packet.number == 7
    assert packet.time == 1700000000.5
    assert packet.has("diameter")
    assert packet.first("diameter.cmd.code") == "316"


def test_build_command_includes_filter_and_fields(tmp_path):
    cmd = build_command("tshark", tmp_path / "x.pcap", ["diameter.flags.request"], "diameter")
    assert cmd[-2:] == ["-Y", "diameter"]
    assert "diameter.flags.request" in cmd


@needs_tshark
def test_read_packets_from_synthetic_capture(plain_udp_capture):
    packets = list(read_packets(plain_udp_capture))
    assert [p.number for p in packets] == [1, 2, 3]
    assert all(p.has("udp") for p in packets)


def test_underscore_field_names_round_trip():
    doc = {
        "layers": {
            "frame_number": ["1"],
            "frame_time_epoch": ["1.0"],
            "frame_protocols": ["eth:ip:sctp:s1ap:nas-eps"],
            "nas_eps_emm_cause": ["8"],
        }
    }
    packet = parse_ek_line(json.dumps(doc), ["nas_eps.emm.cause"])
    assert packet is not None
    assert packet.first("nas_eps.emm.cause") == "8"


def test_packet_without_timestamp_does_not_crash():
    # tshark opens some non-capture files (e.g. MP4) as one record with no frame.time_epoch.
    doc = {"layers": {"frame_number": ["1"], "frame_protocols": ["mp4"]}}
    packet = parse_ek_line(json.dumps(doc))
    assert packet is not None
    assert packet.number == 1
    assert packet.time == 0.0
