# Roadmap

Each version has one theme and an exit test. A version ships only when its exit test passes.

Rules for every version:
- Every rule has a test capture (synthetic or public) and cites packet numbers in its finding.
- No real subscriber traffic is ever committed.
- `docs/VALIDATION.md` is updated with each release.

## v0.1: first public release

- 4G: Diameter S6a, GTPv2-C, EPS NAS, RADIUS. 5G SA: NGAP, 5G NAS, PFCP, GTP-U.
- CLI with text/JSON output and `--fail-on`; web demo (`capsight[web]`).
- Validated on 17 public captures (17/17).

Exit test: `pip install capsight` works and the hosted web demo is live.

## v0.2: usable on real captures

- [x] **Per-subscriber view**: `capsight analyze file --imsi X` prints that subscriber's attach,
  authentication, session and data steps in order and marks where it broke.
- [x] **Large captures** (streaming; 1.1 GB in 844 MB, see VALIDATION.md): stream packets instead of loading them all, pre-filter in tshark, and
  publish timings for 100 MB / 1 GB files.
- [x] **Summary mode** for busy captures: top failures, most affected subscribers, failures over
  time. Thousands of identical rejects become one line with a count.
- [x] **`--redact`**: mask IMSI, MSISDN, IP addresses and realms in all output formats.

Exit test: a corpus of large real-world captures (kept local, never committed) runs to
completion with no crash and no flood of false findings; timings recorded in VALIDATION.md.

## v0.3: operator network coverage

- [x] **Roaming (S8)**: GTPv2-C rejects between visited and home network; the visited network is
  named only from the Visited-PLMN-Id field, never guessed from a hostname or realm.
- [x] **Policy and charging (Gx / Gy)**: credit-control rejects (no credit, user unknown,
  rating failed) and policy rejects explained.
- **MAP (2G/3G)**: authentication, update location and SMS routing errors.
- **Ciphered 5G NAS**: when NAS is encrypted, diagnose from NGAP and PFCP instead and say what
  could not be seen.

Exit test: the local real-world corpus has no unexplained failure types; every new rule has
its own synthetic test.

## v0.4: voice and SMS

- **VoLTE**: SIP REGISTER / INVITE failures with the response code explained, plus the IMS
  Diameter interfaces (Cx, Sh).
- **SMS**: SMS over IMS, and SMS over SGs (needs a combined EPS/IMSI attach so the HLR knows
  where to deliver).
- **5G SBI**: HTTP/2 problem details between core functions, once a cleartext capture is
  available to validate against.

From this version the tagline can say "call flow" accurately.

Exit test: public VoLTE and SMS captures validated in VALIDATION.md.

## v0.5: presentation and integrations

- **Ladder diagrams**: the message sequence rendered as Mermaid / SVG.
- **HTML report**: one self-contained file to attach to a ticket.
- **MCP server**: lets AI agents call capsight as a tool.
- **Optional AI explanation**: rewords the findings. Rules still decide every verdict; the
  model never sees the raw capture.

Exit test: the same capture produces matching CLI, JSON, HTML and MCP output.

## v1.0: dependable

- Stable JSON schema and CLI flags (semantic versioning from here on).
- A rule catalog: every rule, what triggers it, its test capture.
- Docker image and a documentation site.
- Issues from outside users reported and closed.

Exit test: no breaking change needed for one month after the release candidate.
