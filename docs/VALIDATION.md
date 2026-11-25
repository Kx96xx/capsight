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

## Operator failure patterns

The tests in `tests/test_operator_patterns.py` reproduce failure shapes seen in a production
mobile core. They were derived by reading production traces locally; only the pattern was
kept (message, cause, what preceded it). The captures are generated from scratch with
test-network identities, so no production data is in this repository.

| Pattern | What capsight now reports |
|---|---|
| Gateway rejects a session with GTPv2 cause 92 right after RADIUS returned Access-Accept | Points out the credentials were accepted, so the problem is an authorization attribute mismatch, not a password/key |
| The same subscriber's IPv4v6 request gets cause 83 while IPv4 is accepted | "IPv4v6 sessions rejected while IPv4 works": the failure follows the PDN type, not the APN |
| A peer retransmits a rejected request many times | One failure plus a retransmission count, instead of a storm of findings |
| A device keeps retrying with fresh requests and keeps getting rejected | Every attempt counted, as a real loop |
| Attach and default bearer succeed, then an extra APN is rejected (ESM #33) | Warning, not failure: data on the default APN works |
| GTPv2 cause source bit set | Says whether the responder or a node further down the path raised the cause |

## Large-scale run on operator captures (local only)

capsight was run locally on 93 production captures (Diameter S6a, GTPv2-C, MAP; 1 KB to
200 MB each, about 500k packets total). The captures and results never left the machine.
Every capsight count was compared with an independent `tshark` display-filter count.

- No crashes or decode errors on any of the 93 files.
- **Diameter failures**: capsight's grouped counts matched tshark's failed-answer count on
  every file, except where one frame carries several Diameter messages (SCTP bundling); there
  capsight counts each message, tshark counts the frame once.
- **GTPv2-C rejects**: every file tshark flagged was flagged by capsight, and no extra ones.
  Where the raw count was double, capsight's lower number is correct: those were
  retransmitted responses (same sequence number), folded into one failure each.
- **Bug found and fixed**: captures filtered on one host (requests captured, answers not)
  produced tens of thousands of false "never answered" failures. capsight now detects a
  one-directional capture and reports one warning instead.
- **Not yet covered**: these captures had no S1AP/NAS (no EMM/ESM rejects to check) and
  include MAP (2G/3G) signalling, which capsight does not analyse yet.

## Wanted

More public captures, especially: roaming rejects, GTPv2 rejections from a real gateway,
Diameter timeouts, and 5G SA registration. Open an issue with a link.


## Large captures (v0.2)

Eight real-world Diameter/S6a captures, 92 MB to 1.1 GB, kept local and never committed.
Apple M-series laptop, tshark 4.6, `capsight analyze --format json`. All eight completed with
exit code 0; the largest produced 13 grouped findings (no flood of per-packet findings).

| File size | Packets | Time | Peak memory | Findings |
|---|---|---|---|---|
| 92 MB | 201,101 | 6.3 s | 419 MB | 11 |
| 109 MB | 107,861 | 4.1 s | 660 MB | 0 |
| 159 MB | 303,026 | 9.6 s | 589 MB | 6 |
| 398 MB | 802,326 | 27.2 s | 1.3 GB | 12 |
| 474 MB | 1,184,913 | 32.2 s | 1.5 GB | 10 |
| 543 MB | 875,453 | 38.8 s | 1.7 GB | 12 |
| 610 MB | 1,213,392 | 37.7 s | 1.9 GB | 12 |
| 1.1 GB | 2,398,305 | 83.2 s | 3.3 GB | 13 |

Before this change the 92 MB and 159 MB files peaked at 606 MB and 857 MB (-31%). The saving
comes from dropping all but the IP addresses of non-core packets and sharing repeated short
values (IMSIs, hosts, causes) across packets. Time is dominated by tshark's own decode
(about 5 s of the 6.3 s for the 92 MB file).

### Streaming

capsight now analyzes packets as tshark emits them. Diameter, GTPv2-C and PFCP are paired
on the fly and only the fields the rules read are kept; user plane is reduced to flow
counters; only NAS / S1AP / NGAP / RADIUS packets are kept whole. Memory now grows with the
number of signalling procedures, not with the number of packets.

| File size | Peak memory before | Peak memory streaming | Time streaming |
|---|---|---|---|
| 92 MB | 419 MB | 216 MB | 5.6 s |
| 159 MB | 589 MB | 255 MB | 8.7 s |
| 398 MB | 1.3 GB | 431 MB | 26.2 s |
| 474 MB | 1.5 GB | 411 MB | 30.8 s |
| 543 MB | 1.7 GB | 491 MB | 36.3 s |
| 610 MB | 1.9 GB | 508 MB | 34.3 s |
| 1.1 GB | 3.3 GB | 844 MB | 76.1 s |

Parity: 476 captures (17 public plus 459 local real-world captures, a few KB to 1.1 GB) were
run through the previous version and the streaming version, comparing packet counts, protocol
counts, transaction counts and every finding (rule, severity, verdict, count, evidence
packets, subscribers). All 476 were identical. (5 more files in the set were macOS `._*`
metadata files, not captures; both versions reject them with tshark's "isn't a capture file"
error.)
