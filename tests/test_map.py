"""MAP (2G/3G over SS7/SIGTRAN): errors, aborts, rejects, timeouts and TCAP splitting."""

from pathlib import Path

from conftest import T0, needs_tshark
from pcapgen import (
    AC_GPRS_LOC_UP,
    AC_INFO_RETRIEVAL,
    AC_NETWORK_LOC_UP,
    AC_SM_MO_RELAY,
    AC_SM_MT_RELAY,
    OP_ISD,
    OP_MO_FSM,
    OP_MT_FSM,
    OP_SAI,
    OP_UGL,
    OP_UL,
    SSN_MSC,
    TEST_IMSI,
    ber,
    ber_int,
    dialogue_request,
    dialogue_response,
    error,
    invoke,
    map_frame,
    map_imsi,
    map_user_abort,
    reject,
    result,
    sai_arg,
    tc_abort,
    tc_begin,
    tc_continue,
    tc_end,
    ul_arg,
    write_pcap,
)

from capsight.correlate_map import MapCorrelator, split_messages
from capsight.engine import analyze
from capsight.model import Packet

ENUM, INT = 0x0A, 0x02


def param(tag: int, value: int) -> bytes:
    return ber(0x30, ber_int(tag, value))


def problems(path: Path):
    return [f for f in analyze(path).findings if f.severity != "info"]


def sai_exchange(tid: int, answer: bytes, t: float = T0) -> list[tuple[float, bytes]]:
    return [
        (
            t,
            map_frame(
                True,
                tc_begin(tid, [invoke(1, OP_SAI, sai_arg())], dialogue_request(AC_INFO_RETRIEVAL)),
            ),
        ),
        (t + 0.05, map_frame(False, answer)),
    ]


@needs_tshark
def test_sai_unknown_subscriber_with_diagnostic(tmp_path):
    frames = sai_exchange(0x1001, tc_end(0x1001, [error(1, 1, param(ENUM, 0))]))
    [f] = problems(write_pcap(tmp_path / "sai-unknown.pcap", frames))
    assert f.rule_id == "map.error"
    assert f.verdict == (
        "SendAuthenticationInfo rejected: unknown subscriber (diagnostic: IMSI unknown)."
    )
    assert f.why.startswith("The HLR returned MAP error 1 (unknown subscriber)")
    assert "no authentication vectors" in f.fix
    assert f.subscribers == (TEST_IMSI,)
    assert f.evidence == (1, 2)


@needs_tshark
def test_update_location_roaming_not_allowed(tmp_path):
    frames = [
        (
            T0,
            map_frame(
                True,
                tc_begin(0x2001, [invoke(1, OP_UL, ul_arg())], dialogue_request(AC_NETWORK_LOC_UP)),
            ),
        ),
        (T0 + 0.05, map_frame(False, tc_end(0x2001, [error(1, 8, param(ENUM, 0))]))),
    ]
    [f] = problems(write_pcap(tmp_path / "ul-rna.pcap", frames))
    assert f.verdict == (
        "UpdateLocation rejected: roaming not allowed (cause: PLMN roaming not allowed)."
    )
    assert "roaming agreement" in f.fix


@needs_tshark
def test_gprs_location_unknown_subscriber_no_gprs_subscription(tmp_path):
    arg = ber(0x30, map_imsi() + ber(0x04, b"\x91\x21\x43"))
    frames = [
        (
            T0,
            map_frame(
                True, tc_begin(0x2101, [invoke(1, OP_UGL, arg)], dialogue_request(AC_GPRS_LOC_UP))
            ),
        ),
        (T0 + 0.05, map_frame(False, tc_end(0x2101, [error(1, 1, param(ENUM, 1))]))),
    ]
    [f] = problems(write_pcap(tmp_path / "ugl.pcap", frames))
    assert "IMSI known, but no GPRS/EPS subscription" in f.verdict
    assert "packet data" in f.fix


@needs_tshark
def test_mt_sms_subscriber_absent_is_a_warning(tmp_path):
    arg = ber(0x30, map_imsi(tag=0x80) + ber(0x84, b"\x91\x21\x43") + ber(0x04, b"\x00"))
    frames = [
        (
            T0,
            map_frame(
                True,
                tc_begin(0x3001, [invoke(1, OP_MT_FSM, arg)], dialogue_request(AC_SM_MT_RELAY)),
                called=SSN_MSC,
            ),
        ),
        (T0 + 0.05, map_frame(False, tc_end(0x3001, [error(1, 6, param(INT, 1))]), called=SSN_MSC)),
    ]
    [f] = analyze(write_pcap(tmp_path / "mt-absent.pcap", frames)).findings
    assert f.severity == "warning"
    assert (
        f.verdict == "MT-ForwardSM rejected: subscriber absent for SMS (diagnostic: IMSI detached)."
    )
    assert f.why.startswith("The MSC/SGSN returned")


@needs_tshark
def test_mo_sms_unknown_service_centre(tmp_path):
    arg = ber(0x30, ber(0x84, b"\x91\x21\x43") + ber(0x82, b"\x91\x21\x43") + ber(0x04, b"\x00"))
    frames = [
        (
            T0,
            map_frame(
                True,
                tc_begin(0x3101, [invoke(1, OP_MO_FSM, arg)], dialogue_request(AC_SM_MO_RELAY)),
            ),
        ),
        (T0 + 0.05, map_frame(False, tc_end(0x3101, [error(1, 32, param(ENUM, 3))]))),
    ]
    [f] = problems(write_pcap(tmp_path / "mo-sc.pcap", frames))
    assert (
        f.verdict == "MO-ForwardSM rejected: SMS delivery failure (cause: unknown service centre)."
    )
    assert "SMSC address" in f.fix


@needs_tshark
def test_p_abort_unrecognized_transaction_id(tmp_path):
    frames = sai_exchange(0x4001, tc_abort(0x4001, p_abort=1))
    [f] = problems(write_pcap(tmp_path / "p-abort.pcap", frames))
    assert f.rule_id == "map.abort"
    assert f.verdict == (
        "SendAuthenticationInfo dialogue aborted: TCAP provider abort, unrecognized transaction ID."
    )
    assert "symmetric" in f.fix


@needs_tshark
def test_map_user_abort(tmp_path):
    frames = sai_exchange(0x4101, tc_abort(0x4101, dialogue=map_user_abort(0)))
    [f] = problems(write_pcap(tmp_path / "u-abort.pcap", frames))
    assert f.verdict == "SendAuthenticationInfo dialogue aborted: user specific reason."


@needs_tshark
def test_dialogue_refused_application_context_not_supported(tmp_path):
    refuse = dialogue_response(AC_INFO_RETRIEVAL, 3, result=1, user_diag=2)
    frames = sai_exchange(0x4201, tc_abort(0x4201, dialogue=refuse))
    [f] = problems(write_pcap(tmp_path / "refused.pcap", frames))
    assert f.verdict == (
        "SendAuthenticationInfo dialogue aborted: dialogue refused, application context "
        "name not supported."
    )
    assert "MAP version" in f.fix


@needs_tshark
def test_tcap_reject(tmp_path):
    frames = sai_exchange(0x4301, tc_end(0x4301, [reject(1, 0x81, 2)]))
    [f] = problems(write_pcap(tmp_path / "reject.pcap", frames))
    assert f.rule_id == "map.reject"
    assert f.verdict == "SendAuthenticationInfo rejected by TCAP: mistyped parameter."


@needs_tshark
def test_unanswered_only_after_the_map_timer(tmp_path):
    begin = tc_begin(0x5001, [invoke(1, OP_SAI, sai_arg())], dialogue_request(AC_INFO_RETRIEVAL))
    later = tc_begin(0x5002, [invoke(1, OP_SAI, sai_arg())], dialogue_request(AC_INFO_RETRIEVAL))
    short = write_pcap(
        tmp_path / "short.pcap", [(T0, map_frame(True, begin)), (T0 + 10, map_frame(True, later))]
    )
    assert problems(short) == []  # 10 s is within the MAP operation timer
    long = write_pcap(
        tmp_path / "long.pcap", [(T0, map_frame(True, begin)), (T0 + 40, map_frame(True, later))]
    )
    [f] = problems(long)
    assert f.rule_id == "map.unanswered"
    assert f.verdict == "SendAuthenticationInfo never answered."
    assert f.evidence == (1,)


@needs_tshark
def test_location_update_with_insert_subscriber_data_is_clean(tmp_path):
    frames = [
        (
            T0,
            map_frame(
                True,
                tc_begin(0x6001, [invoke(1, OP_UL, ul_arg())], dialogue_request(AC_NETWORK_LOC_UP)),
            ),
        ),
        (
            T0 + 0.1,
            map_frame(
                False,
                tc_continue(
                    0x7001,
                    0x6001,
                    [invoke(1, OP_ISD, ber(0x30, map_imsi(tag=0x80)))],
                    dialogue_response(AC_NETWORK_LOC_UP),
                ),
            ),
        ),
        (T0 + 0.2, map_frame(True, tc_continue(0x6001, 0x7001, [result(1)]))),
        (T0 + 0.3, map_frame(False, tc_end(0x6001, [result(1, OP_UL, ber(0x04, b"\x91\x21"))]))),
        (T0 + 60, map_frame(True, tc_begin(0x6002, [], dialogue_request(AC_NETWORK_LOC_UP)))),
    ]
    report = analyze(write_pcap(tmp_path / "ul-ok.pcap", frames))
    assert [f for f in report.findings if f.severity != "info"] == []
    assert report.transactions["map"] == 2


@needs_tshark
def test_bundled_begin_and_end_in_one_packet_are_paired(tmp_path):
    frames = [
        (
            T0,
            map_frame(
                True,
                tc_begin(
                    0x8001, [invoke(1, OP_SAI, sai_arg())], dialogue_request(AC_INFO_RETRIEVAL)
                ),
            ),
        ),
        # one SCTP packet: the answer to 0x8001 and a new request, in that order
        (
            T0 + 0.1,
            map_frame(
                False,
                tc_end(0x8001, [error(1, 1, param(ENUM, 0))]),
                tc_begin(
                    0x8002, [invoke(1, OP_SAI, sai_arg())], dialogue_request(AC_INFO_RETRIEVAL)
                ),
            ),
        ),
        (T0 + 0.2, map_frame(True, tc_end(0x8002, [result(1)]))),
        (T0 + 60, map_frame(True, tc_begin(0x8003, [], dialogue_request(AC_INFO_RETRIEVAL)))),
    ]
    [f] = problems(write_pcap(tmp_path / "bundled.pcap", frames))
    assert f.rule_id == "map.error"
    assert f.count == 1
    assert f.evidence == (1, 2)


@needs_tshark
def test_same_messages_on_both_stp_legs_count_once(tmp_path):
    begin = tc_begin(0x9001, [invoke(1, OP_SAI, sai_arg())], dialogue_request(AC_INFO_RETRIEVAL))
    end = tc_end(0x9001, [error(1, 1, param(ENUM, 0))])
    frames = [
        (T0, map_frame(True, begin)),
        (T0 + 0.001, map_frame(True, begin)),  # forwarded copy
        (T0 + 0.05, map_frame(False, end)),
        (T0 + 0.051, map_frame(False, end)),  # forwarded copy
    ]
    [f] = problems(write_pcap(tmp_path / "two-legs.pcap", frames))
    assert f.count == 1


@needs_tshark
def test_answers_without_requests_warn_about_a_partial_capture(tmp_path):
    frames = [(T0, map_frame(True, tc_begin(0xA000, [], dialogue_request(AC_INFO_RETRIEVAL))))]
    for i in range(25):
        frames.append((T0 + 40 + i, map_frame(False, tc_end(0xA100 + i, [result(1)]))))
    found = problems(write_pcap(tmp_path / "partial.pcap", frames))
    assert [f.rule_id for f in found] == ["map.partial"]
    assert found[0].severity == "warning"
    assert "25 MAP answers" in found[0].why


# ---- frame splitting (no tshark needed) -----------------------------------------------


def tcap_packet(number: int, **fields: list[str]) -> Packet:
    return Packet(
        number,
        T0 + number,
        ("sctp", "tcap", "gsm_map"),
        {k.replace("__", "."): v for k, v in fields.items()},
    )


def test_ambiguous_bundle_is_not_guessed():
    # BEGIN followed by END looks like one CONTINUE; this bundle has two readings.
    packet = tcap_packet(
        1,
        tcap__tid=["a1", "d1", "a2", "d2", "d3", "a4", "d4", "a5", "d5", "a6", "a7", "d7"],
        tcap__otid=["a1", "a2", "a4", "a5", "a6", "a7"],
        tcap__dtid=["d1", "d2", "d3", "d4", "d5", "d7"],
        tcap__begin_element=["", ""],
        tcap__continue_element=["", "", "", ""],
        tcap__end_element=["", ""],
        tcap__components=["1"] * 8,
        **{"gsm_map__old__Component": ["2", "1", "2", "2", "2", "1", "1", "2"]},
        gsm_old__invokeID=["1", "2", "0", "0", "0", "1", "0", "0"],
        gsm_old__localValue=["56", "56", "56"],
    )
    assert split_messages(packet) is None


def test_request_answered_in_an_unreadable_bundle_is_not_unanswered():
    correlator = MapCorrelator()
    correlator.feed(
        tcap_packet(
            1,
            tcap__tid=["a1"],
            tcap__otid=["a1"],
            tcap__begin_element=[""],
            tcap__components=["1"],
            gsm_map__old__Component=["1"],
            gsm_old__invokeID=["1"],
            gsm_old__localValue=["56"],
        )
    )
    # a bundle whose components cannot be placed (count mismatch): left blind
    correlator.feed(
        tcap_packet(
            2,
            tcap__tid=["a1", "b2"],
            tcap__dtid=["a1"],
            tcap__otid=["b2"],
            tcap__end_element=[""],
            tcap__begin_element=[""],
            tcap__components=["1"],
            gsm_map__old__Component=["2", "1"],
            gsm_old__invokeID=["1", "1"],
            gsm_old__localValue=["56"],
        )
    )
    assert correlator.finish() == []


@needs_tshark
def test_imsi_filtered_capture_warns_instead_of_timeouts(tmp_path):
    # Filtering a capture on the IMSI keeps the requests but drops most MAP answers, which
    # carry no IMSI. That must not read as a dead HLR.
    frames = [
        (
            T0 + i,
            map_frame(
                True,
                tc_begin(
                    0xB000 + i, [invoke(1, OP_SAI, sai_arg())], dialogue_request(AC_INFO_RETRIEVAL)
                ),
            ),
        )
        for i in range(8)
    ]
    frames.append(
        (T0 + 60, map_frame(True, tc_begin(0xBFFF, [], dialogue_request(AC_INFO_RETRIEVAL))))
    )
    [f] = problems(write_pcap(tmp_path / "imsi-filtered.pcap", frames))
    assert f.rule_id == "map.unanswered"
    assert f.severity == "warning"
    assert f.verdict == "MAP answers are missing from this capture."
    assert f.count == 8
    assert "only 0 of them answered" in f.why


@needs_tshark
def test_one_operation_without_answers_warns_for_that_operation(tmp_path):
    frames = []
    for i in range(4):  # SAI: requests only
        sai = tc_begin(
            0xC000 + i, [invoke(1, OP_SAI, sai_arg())], dialogue_request(AC_INFO_RETRIEVAL)
        )
        frames.append((T0 + i, map_frame(True, sai)))
    for i in range(4):  # UpdateLocation: answered
        ul = tc_begin(0xC100 + i, [invoke(1, OP_UL, ul_arg())], dialogue_request(AC_NETWORK_LOC_UP))
        frames.append((T0 + 10 + i, map_frame(True, ul)))
        frames.append((T0 + 10.1 + i, map_frame(False, tc_end(0xC100 + i, [result(1)]))))
    frames.append(
        (T0 + 60, map_frame(True, tc_begin(0xCFFF, [], dialogue_request(AC_INFO_RETRIEVAL))))
    )
    [f] = problems(write_pcap(tmp_path / "sai-missing.pcap", frames))
    assert f.severity == "warning"
    assert f.verdict == "SendAuthenticationInfo answers are missing from this capture."
