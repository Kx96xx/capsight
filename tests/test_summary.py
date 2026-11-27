"""Summary mode (--summary)."""

from capsight.cli import render_text
from capsight.engine import analyze_packets
from capsight.model import Packet
from capsight.summary import build_summary

NAS = ("eth", "ip", "sctp", "s1ap", "nas-eps")
T0 = 1_700_000_000.0  # 2023-11-14 22:13:20 UTC


def reject(n, t, imsi, cause):
    return Packet(
        n,
        t,
        NAS,
        {
            "e212.imsi": [imsi],
            "nas-eps.nas_msg_emm_type": ["0x44"],
            "nas-eps.emm.cause": [str(cause)],
        },
    )


def busy_capture():
    packets = []
    n = 0
    # cause 8: 3 subscribers, 150 rejects over ~3 minutes; subscriber ...001 is the worst
    for i in range(150):
        n += 1
        imsi = "001010000000001" if i % 3 else f"00101000000000{2 + i % 2}"
        packets.append(reject(n, T0 + i, imsi, 8))
    # cause 15: one subscriber, 4 rejects in the last minute
    for i in range(4):
        n += 1
        packets.append(reject(n, T0 + 170 + i, "001010000000009", 15))
    return analyze_packets("busy", packets)


def test_summary_counts_and_order():
    s = build_summary(busy_capture())
    assert s["most_likely_cause"]["count"] == 150
    assert s["most_likely_cause"]["rule_id"] == "nas.emm.reject"
    assert s["problems"] == 2
    assert s["occurrences"] == 154
    assert s["subscribers_affected"] == 4
    first, second = s["top_problems"]
    assert first["count"] == 150 and "EPS services" in first["verdict"]
    assert second["count"] == 4
    assert first["first"] == "2023-11-14 22:13:20"


def test_most_affected_subscribers():
    s = build_summary(busy_capture())
    top = s["top_subscribers"][0]
    assert top == {
        "imsi": "001010000000001",
        "count": 100,
        "problems": [s["top_problems"][0]["verdict"]],
    }


def test_over_time_per_minute():
    s = build_summary(busy_capture())
    assert s["bucket_minutes"] == 1
    assert sum(n for _, n in s["over_time"]) == 154
    assert [t for t, _ in s["over_time"]][0] == "2023-11-14 22:13"


def test_text_render_and_hint():
    report = busy_capture()
    plain = render_text(report)
    assert "tip: add --summary" in plain
    text = render_text(report, build_summary(report))
    assert "summary   2 problems, 154 occurrences, 4 subscribers affected" in text
    assert "TOP PROBLEMS" in text and "MOST AFFECTED SUBSCRIBERS" in text
    assert "OVER TIME (UTC, per 1 min)" in text
    assert "001010000000001       100x" in text
    assert text.index("MOST LIKELY CAUSE") < text.index("TOP PROBLEMS")


def test_long_capture_uses_bigger_buckets():
    packets = [reject(i + 1, T0 + i * 600, "001010000000001", 8) for i in range(72)]  # 12 h
    s = build_summary(analyze_packets("long", packets))
    assert s["bucket_minutes"] == 60  # 12 h span, aligned to whole hours, in <= 24 rows
    assert len(s["over_time"]) <= 24


def test_clean_capture():
    s = build_summary(analyze_packets("clean", []))
    assert s["problems"] == 0
    assert "no problems found" in render_text(analyze_packets("clean", []), s)
