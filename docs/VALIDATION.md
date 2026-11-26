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

## 5G SA protocol lab (Open5GS + UERANSIM)

Source: <https://github.com/abdelrahman-fawaz18/5g-sa-core-protocol-lab> (MIT), `captures/`.
Open5GS 2.8 with UERANSIM; each fault case has a documented cause plus a recovery capture.
capsight run with tshark 4.6.

| Capture | What the source says happened | capsight verdict | Match |
|---|---|---|---|
| `fault-injection/plmn-mismatch/fault.pcap` | gNB PLMN not served by the AMF | NG Setup failed: misc=unknown-PLMN-or-SNPN; fix names PLMN and TAI lists | yes |
| `fault-injection/tac-mismatch/fault.pcap` | gNB tracking area not served | NG Setup failed: misc=unknown-PLMN-or-SNPN; fix names PLMN and TAI lists | yes |
| `fault-injection/authentication-key-mismatch/fault.pcap` | Wrong subscriber key, 5G-AKA fails | MAC failure (K/OPc mismatch), then Authentication Reject, SUPI shown | yes |
| `fault-injection/unsupported-dnn/fault.pcap` | UE asks for an unsubscribed DNN; no session | PDU session refused by the AMF: 5GMM #91, names DNN `unsupported`, never reached an SMF | yes |
| `fault-injection/missing-n6-nat/fault.pcap` | No NAT on N6: uplink leaves, nothing returns | User plane one-way from the UE address, private source left on N6; fix: NAT/masquerade | yes |
| `baseline/registration-resynchronization.pcap` | Normal registration with an SQN resync | Info: resync, then authentication succeeded | yes |
| `baseline/full-lifecycle.pcap`, `baseline/pdu-session-user-plane.pcap` | Healthy | No known failure patterns | yes |
| 4 `recovery.pcap` files | Healthy after the fix | No known failure patterns | yes |

12 of 12 match, with no false alarms on the 6 healthy captures.

Notes:
- 5G NAS after security mode is ciphered. These lab captures use the null cipher (NEA0);
  capsight asks tshark to decode that case, which is how the DNN and 5GMM #91 become visible.
  With a real cipher the NAS payload is opaque and capsight falls back to NGAP/PFCP evidence.
- The SUPI is shown only when the SUCI uses the null scheme. A concealed SUCI is never guessed.

### Ciphered NAS (v0.3)

The lab runs with null ciphering (NEA0), which tshark can read. Reading the same captures
with that turned off makes every NAS message after security setup look exactly like a
ciphered one (NEA1/2/3), so the expected answer is known.

| Capture | NAS readable | NAS ciphered |
|---|---|---|
| `unsupported-dnn/fault.pcap` | PDU session refused by the AMF: DNN not supported or not subscribed | Registered, but no PDU session was set up (inferred from NGAP: Initial Context Setup, no PDU Session Resource Setup) |
| 3 baselines, and the 2 recoveries that include registration | No failures (resync info on one) | Info only: NAS ciphered, 6 messages unread (plus the same resync info) |
| the 3 recoveries without NAS (`missing-n6-nat`, `plmn-mismatch`, `tac-mismatch`) | No failures | No failures |
| `authentication-key-mismatch`, `plmn-mismatch`, `tac-mismatch`, `missing-n6-nat` faults | Their failure | The same failure (it happens before ciphering, or outside NAS) |

No false failures on the healthy captures in either mode. A registration rejected after
security setup is covered by unit tests only: none of these captures has one.

## Operator failure patterns

The tests in `tests/test_operator_patterns.py` reproduce failure shapes common in mobile
cores: the message, the cause and what preceded it. Every capture is generated from scratch
with test-network identities.

| Pattern | What capsight now reports |
|---|---|
| Gateway rejects a session with GTPv2 cause 92 right after RADIUS returned Access-Accept | Points out the credentials were accepted, so the problem is an authorization attribute mismatch, not a password/key |
| The same subscriber's IPv4v6 request gets cause 83 while IPv4 is accepted | "IPv4v6 sessions rejected while IPv4 works": the failure follows the PDN type, not the APN |
| A peer retransmits a rejected request many times | One failure plus a retransmission count, instead of a storm of findings |
| A device keeps retrying with fresh requests and keeps getting rejected | Every attempt counted, as a real loop |
| Attach and default bearer succeed, then an extra APN is rejected (ESM #33) | Warning, not failure: data on the default APN works |
| GTPv2 cause source bit set | Says whether the responder or a node further down the path raised the cause |

## Large captures

Measured on synthetic captures from `scripts/make_large_capture.py` (busy-core S6a and
GTPv2-C traffic, about 1% of authentications and sessions rejected), so anyone can repeat
it. Apple M-series laptop, tshark 4.6, `capsight analyze --format json`, peak memory of the
largest process.

| Packets | File size | Time | Peak memory | Findings |
|---|---|---|---|---|
| 100,000 | 17 MB | 3.4 s | 233 MB | 2 |
| 1,000,000 | 166 MB | 27 s | 769 MB | 2 |
| 6,000,000 | 996 MB | 150 s | 4.0 GB | 2 |

Each run produced two grouped findings (user unknown and unknown APN) with the exact
expected counts (10,068 and 10,067 at 6M packets), not one finding per packet. capsight
streams: Diameter, GTPv2-C and PFCP are paired as tshark emits packets and only the fields
the rules read are kept, so memory grows with the number of signalling procedures, not with
packets or file size. These captures are a worst case for that: every subscriber is new
(one million at 6M packets, about three million procedures). Time is dominated by
tshark's own decode.

## Wanted

More public captures, especially: roaming rejects, GTPv2 rejections from a real gateway,
Diameter timeouts, and 5G SA registration. Open an issue with a link.
