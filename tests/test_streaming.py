"""The engine consumes a one-shot iterator and keeps only signalling packets whole."""

from capsight.engine import Collector, analyze_packets
from capsight.model import Packet


def diameter(n, request, hbh, code=None):
    fields = {
        "diameter.cmd.code": ["316"],
        "diameter.flags.request": ["1" if request else "0"],
        "diameter.hopbyhopid": [str(hbh)],
        "diameter.endtoendid": [str(hbh)],
        "diameter.Session-Id": [f"s;{hbh}"],
        "diameter.User-Name": ["001010000000001"],
    }
    if code:
        fields["diameter.Experimental-Result-Code"] = [str(code)]
    return Packet(n, float(n), ("eth", "ip", "sctp", "diameter"), fields)


def test_generator_input_is_consumed_once():
    def packets():
        yield diameter(1, True, 7)
        yield diameter(2, False, 7, 5001)

    report = analyze_packets("x", packets())
    assert report.packets == 2
    [finding] = report.findings
    assert finding.evidence == (1, 2)


def test_only_signalling_is_kept_whole_and_tx_packets_are_slim():
    c = Collector()
    c.feed(diameter(1, True, 7))
    c.feed(diameter(2, False, 7, 5001))
    c.feed(Packet(3, 3.0, ("eth", "ip", "tcp"), {"ip.src": ["192.0.2.1"], "ip.dst": ["192.0.2.2"]}))
    c.feed(Packet(4, 4.0, ("eth", "ip", "sctp", "s1ap", "nas-eps"), {"e212.imsi": ["1"]}))
    assert [p.number for p in c.kept] == [4]
    [tx] = c.diameter.finish()
    assert "diameter.Session-Id" not in tx.request.fields
    assert tx.answer.fields["diameter.Experimental-Result-Code"] == ["5001"]
