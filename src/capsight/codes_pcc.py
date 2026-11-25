"""Policy and charging (Gx, Gy) codes with operator-facing hints.

Sources: RFC 4006 (Diameter Credit-Control), 3GPP TS 29.212 (Gx), TS 32.299 (Gy/Ro).
"""

from __future__ import annotations

from capsight.codes import Code

GX_APP = 16777238
GY_APP = 4  # Diameter Credit-Control application, used for Gy and Ro
INTERFACE = {GX_APP: "Gx", GY_APP: "Gy"}
SERVER = {"Gx": "policy server (PCRF)", "Gy": "online charging system (OCS)"}

CCR, RAR = 272, 258
CC_REQUEST_TYPE = {1: "CCR-I", 2: "CCR-U", 3: "CCR-T", 4: "CCR-E"}
CC_INITIAL, CC_UPDATE, CC_TERMINATION, CC_EVENT = 1, 2, 3, 4

# What a rejected request means for the user, by CC-Request-Type.
IMPACT = {
    CC_INITIAL: "This was the initial request, so the data session is refused at setup; the "
    "gateway then rejects the session request that triggered it.",
    CC_UPDATE: "This was an update on a live session: the device stays attached, but data "
    "for the affected service stops or is restricted.",
    CC_TERMINATION: "This was the final report at session end: the data session was already "
    "over, so this mostly affects charging records and cleanup.",
    CC_EVENT: "This was a one-off charging event.",
}

# Result codes that are not failures for credit control.
NOT_A_FAILURE = {4011}  # DIAMETER_CREDIT_CONTROL_NOT_APPLICABLE: serve without credit control

# Result-Code / Experimental-Result-Code values with Gx/Gy-specific hints.
# Values not listed here fall back to the generic Diameter tables.
PCC_RESULT: dict[int, Code] = {
    3002: Code(
        "DIAMETER_UNABLE_TO_DELIVER",
        "No route from the gateway to the {server}. Check the Diameter routing agent's realm "
        "and peer table for the {interface} realm, and that the {server} peer is connected.",
    ),
    3004: Code("DIAMETER_TOO_BUSY", "The {server} is overloaded. Check its load and capacity."),
    4010: Code(
        "DIAMETER_END_USER_SERVICE_DENIED",
        "The {server} refused service to this subscriber (barred, suspended or not allowed "
        "this service). Check the subscriber's status and plan in the {server}.",
    ),
    4012: Code(
        "DIAMETER_CREDIT_LIMIT_REACHED",
        "The subscriber's balance or data allowance is used up. Top up, raise the limit or "
        "check which plan/bucket the rating group draws from.",
    ),
    5002: Code(
        "DIAMETER_UNKNOWN_SESSION_ID",
        "The receiver no longer has this session. Usually a session that ended on one side "
        "only (a lost CCR-T or a gateway restart), so the other side keeps a stale session.",
    ),
    5003: Code(
        "DIAMETER_AUTHORIZATION_REJECTED",
        "The {server} does not authorize this subscriber for the requested service.",
    ),
    5030: Code(
        "DIAMETER_USER_UNKNOWN",
        "The {server} does not know this subscriber. The SIM can be provisioned in the HSS "
        "and still be missing in the {server}: provision it there too.",
    ),
    5031: Code(
        "DIAMETER_RATING_FAILED",
        "The {server} cannot rate this service: the rating group or service identifier the "
        "gateway sent is not configured in the tariff. Compare the gateway's charging rule "
        "with the {server}'s rating configuration.",
    ),
    4141: Code(
        "DIAMETER_PCC_BEARER_EVENT",
        "The PCRF could not apply a policy decision to the bearer.",
    ),
    4144: Code(
        "DIAMETER_PENDING_TRANSACTION",
        "Two policy transactions for the same session crossed. The sender should retry.",
    ),
    5140: Code(
        "DIAMETER_ERROR_INITIAL_PARAMETERS",
        "The PCRF could not decide on a policy from the CCR-I it received: for example no "
        "policy for this APN/subscriber combination, or a missing or unexpected parameter "
        "(RAT type, IP-CAN type, subscriber identity). Check the PCRF's policy for this APN.",
    ),
    5141: Code(
        "DIAMETER_ERROR_TRIGGER_EVENT",
        "The PCRF does not accept the event trigger values the gateway reported.",
    ),
    5142: Code(
        "DIAMETER_PCC_RULE_EVENT",
        "The gateway could not install the PCC rules the PCRF sent. See the Charging-Rule-"
        "Report for which rule and why.",
    ),
    5143: Code(
        "DIAMETER_ERROR_BEARER_NOT_AUTHORIZED",
        "The PCRF did not authorize the requested bearer (QoS or bearer binding).",
    ),
    5144: Code(
        "DIAMETER_ERROR_TRAFFIC_MAPPING_INFO_REJECTED",
        "The PCRF rejected the traffic filters (TFT) the device asked for.",
    ),
    5147: Code(
        "DIAMETER_ERROR_CONFLICTING_REQUEST",
        "The PCRF could not handle this request because it conflicts with one in progress.",
    ),
}

RULE_FAILURE: dict[int, Code] = {
    1: Code(
        "UNKNOWN_RULE_NAME",
        "The gateway has no predefined rule with this name: add it "
        "to the gateway or fix the name the PCRF sends.",
    ),
    2: Code("RATING_GROUP_ERROR", "The rule's rating group is invalid or not allowed."),
    3: Code("SERVICE_IDENTIFIER_ERROR", "The rule's service identifier is invalid."),
    4: Code("GW/PCEF_MALFUNCTION", "The gateway failed internally while installing the rule."),
    5: Code("RESOURCES_LIMITATION", "The gateway lacks resources to enforce the rule."),
    6: Code("MAX_NR_BEARERS_REACHED", "The device already has the maximum number of bearers."),
    7: Code("UNKNOWN_BEARER_ID", "The rule refers to a bearer the gateway does not know."),
    8: Code("MISSING_BEARER_ID", "The rule needs a bearer identifier and none was given."),
    9: Code("MISSING_FLOW_DESCRIPTION", "The dynamic rule has no flow description."),
    10: Code(
        "RESOURCE_ALLOCATION_FAILURE",
        "The bearer for the rule could not be set up: the "
        "radio side or the device refused the dedicated bearer (often its QoS).",
    ),
    11: Code(
        "UNSUCCESSFUL_QOS_VALIDATION",
        "The rule's QoS exceeds what the subscriber or APN allows (e.g. APN-AMBR / max bitrate).",
    ),
    12: Code("INCORRECT_FLOW_INFORMATION", "The rule's flow description is malformed."),
    13: Code(
        "PS_TO_CS_HANDOVER",
        "The rule was removed because the call moved to the circuit domain (SRVCC).",
    ),
    14: Code("TDF_APPLICATION_IDENTIFIER_ERROR", "The application identifier is unknown."),
    15: Code("NO_BEARER_BOUND", "No bearer could be bound to the rule."),
    16: Code("FILTER_RESTRICTIONS", "The rule's packet filters cannot be enforced."),
    17: Code("AN_GW_FAILED", "The access gateway (SGW) failed."),
    18: Code("MISSING_REDIRECT_SERVER_ADDRESS", "Redirect requested without a redirect address."),
    19: Code("CM_END_USER_SERVICE_DENIED", "The OCS denied service for this rule."),
    20: Code("CM_CREDIT_CONTROL_NOT_APPLICABLE", "The OCS says no credit control is needed."),
    21: Code("CM_AUTHORIZATION_REJECTED", "The OCS rejected authorization for this rule."),
    22: Code("CM_USER_UNKNOWN", "The OCS does not know this subscriber."),
    23: Code("CM_RATING_FAILED", "The OCS cannot rate this rule's rating group."),
    24: Code("ROUTING_RULE_REJECTION", "The routing rule was rejected."),
}

PCC_RULE_STATUS = {0: "ACTIVE", 1: "INACTIVE", 2: "TEMPORARILY INACTIVE"}

FINAL_UNIT_ACTION = {
    0: ("TERMINATE", "data for this service stops when the last granted units are used"),
    1: (
        "REDIRECT",
        "traffic is redirected (usually to a top-up portal) when the last units are used",
    ),
    2: ("RESTRICT_ACCESS", "access is restricted to a whitelist when the last units are used"),
}


def pcc_code(value: int, interface: str) -> Code | None:
    code = PCC_RESULT.get(value)
    if code is None:
        return None
    server = SERVER.get(interface, "server")
    return Code(code.name, code.hint.format(server=server, interface=interface))
