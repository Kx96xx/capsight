# Validation against public captures

capsight is tested in CI on synthetic captures. This page records runs against real,
publicly published captures. The captures are not redistributed here; follow the source
link to download them.

## CoLTE PCAP library

Source: <https://blog.colte.network/pcap-library> (`pcaps.zip`). A single-machine LTE core
(MME, HSS, SGW, PGW, PCRF) with one eNB and a real handset. capsight 0.0.1, tshark 4.6.

| Capture | What the source says happened | capsight verdict | Match |
|---|---|---|---|
| `0_nouserinfo.pcap` | Phone not in the database, attach rejected | AIR rejected: DIAMETER_ERROR_USER_UNKNOWN (5001), then Attach Reject EMM #8, same IMSI | yes |
| `1_wrongkey.pcap` | Phone provisioned with the wrong key, authentication fails | Device rejected network authentication: MAC failure (keys mismatch) | yes |
| `2_firstattach.pcap` | Successful first attach; the sync failure is normal on a first attach | Info: sequence-number resync, then authentication succeeded. No failures | yes |
| `3_reattach.pcap` | Successful re-attach | No known failure patterns | yes |
| `4_sip.pcap` | Successful attach, IMS PDN and SIP REGISTER | No known failure patterns | yes |

5 of 5 match the documented outcome, with no false alarms on the three healthy captures.

## Wanted

More public captures, especially: roaming rejects, GTPv2 rejections from a real gateway,
Diameter timeouts, and 5G SA registration. Open an issue with a link.
