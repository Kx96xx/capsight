"""tshark fields capsight requests. Field names verified against Wireshark 4.x."""

DIAMETER = (
    "diameter.flags.request",
    "diameter.cmd.code",
    "diameter.applicationId",
    "diameter.hopbyhopid",
    "diameter.endtoendid",
    "diameter.Session-Id",
    "diameter.User-Name",
    "diameter.Result-Code",
    "diameter.Experimental-Result-Code",
)

GTPV2 = (
    "gtpv2.message_type",
    "gtpv2.seq",
    "gtpv2.teid",
    "gtpv2.cause",
    "gtpv2.apn",
    "gtpv2.cs",
    "gtpv2.pdn_type",
)

RADIUS = ("radius.code", "radius.id")

NAS_EPS = (
    "nas-eps.nas_msg_emm_type",
    "nas-eps.nas_msg_esm_type",
    "nas-eps.emm.cause",
    "nas-eps.esm.cause",
)

IDENTITY = ("e212.imsi", "s1ap.ENB_UE_S1AP_ID", "s1ap.MME_UE_S1AP_ID")

ALL = (*DIAMETER, *GTPV2, *RADIUS, *NAS_EPS, *IDENTITY)

DISPLAY_FILTER = "diameter or gtpv2 or nas-eps or s1ap or radius"
