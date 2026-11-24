# capsight

**Drop in a 4G/5G packet capture, get a plain-English diagnosis of why the call flow failed.**

> Status: early development. 4G core (Diameter S6a, GTPv2-C, NAS, RADIUS) works today. 5G is next. See [docs/PLAN.md](docs/PLAN.md).

Debugging a mobile core usually means scrolling through thousands of Diameter, GTP and NAS packets in Wireshark and looking up result codes and cause values by hand. capsight does that part: it pairs requests with answers, matches known failure patterns and tells you what broke, for whom, where in the capture, and what to check next.

```
$ capsight analyze attach-failure.pcap
capture   attach-failure.pcap
packets   4  (0.11 s)
protocols diameter=4

FAILURE   ULR rejected: DIAMETER_ERROR_USER_UNKNOWN.
WHY       ULA carried Experimental-Result-Code 5001 (DIAMETER_ERROR_USER_UNKNOWN).
WHO       001010000000001
WHERE     packets #3, #4
FIX       The subscriber is not provisioned in the HSS/UDM, or the IMSI on the SIM does not match the provisioned one.
```

## Who it is for

- **Core / NOC engineers**: a customer says "my device won't connect". Grab a capture, run capsight, get the reject and the subscriber in seconds instead of reading packets.
- **Private LTE/5G and lab builders** (Open5GS, free5GC, srsRAN): find out why your phone won't attach to the network you just set up.
- **Students and people learning telecom**: see what a failure means in plain words, with the packet numbers to open in Wireshark.
- **Automation**: run it in a script or CI job on captures from a test lab and fail the build if a reject appears.

## Install

You need Python 3.11+ and `tshark` (comes with Wireshark).

```bash
# tshark
brew install wireshark          # macOS
sudo apt install tshark         # Debian/Ubuntu

# capsight
git clone https://github.com/Kx96xx/capsight.git
cd capsight
uv sync                          # or: pip install -e .
```

## Quick start

Generate a few demo captures (synthetic, safe to share) and analyze them:

```bash
uv run python scripts/make_demo_captures.py
uv run capsight analyze samples/synthetic/attach-user-unknown.pcap
uv run capsight analyze samples/synthetic/radius-accept-then-reject.pcap
uv run capsight analyze samples/synthetic/ipv4v6-rejected.pcap
```

## How to use it

### 1. Get a capture

capsight reads `.pcap` / `.pcapng` files. Capture on the interface that carries the signalling you care about:

| Problem | Capture where | Filter example |
|---|---|---|
| Device won't attach | MME (S1-MME + S6a) | `sctp or port 3868` |
| Attached but no data | MME/SGW/PGW GTP-C | `udp port 2123` |
| Session rejected by AAA | PGW + RADIUS | `udp port 2123 or udp port 1812 or udp port 1813` |

```bash
tshark -i any -f "sctp or port 3868 or udp port 2123" -w attach.pcapng
```

Reproduce the problem (power-cycle the device, toggle airplane mode), then stop the capture.

### 2. Analyze

```bash
capsight analyze attach.pcapng
```

Each finding has:

- **Severity**: `FAILURE` (it broke), `WARNING` (degraded or partially working), `INFO` (looks odd but is normal, e.g. a first-attach SQN resync)
- **WHY**: the exact code or cause and what it means
- **WHO**: the subscriber(s) affected (IMSI)
- **WHERE**: packet numbers. Open the capture in Wireshark and jump there with `Ctrl+G`
- **FIX**: what to check next

Repeated failures are grouped into one finding with a count. Retransmissions of the same request are counted once, so a retransmission storm does not look like a thousand failures.

### 3. Options

```bash
capsight analyze FILE [--format text|json] [--timeout SECONDS] [--fail-on failure|warning|never]
```

| Option | What it does |
|---|---|
| `--format json` | machine-readable output, for scripts and dashboards |
| `--timeout 5` | seconds without an answer before a request counts as unanswered (default 5) |
| `--fail-on failure` | exit code 1 if any failure is found (use in CI or scripts) |

Exit codes: `0` ok, `1` findings at the `--fail-on` level, `2` the capture could not be read.

### 4. Use it in scripts / CI

```bash
for f in captures/*.pcapng; do
  capsight analyze "$f" --fail-on failure > "${f%.pcapng}.txt" || echo "FAILED: $f"
done

capsight analyze attach.pcapng --format json | jq '.findings[] | {severity, verdict, count}'
```

## What it detects today

**Diameter (S6a and base protocol)**
- Failure Result-Code / Experimental-Result-Code: user unknown, roaming not allowed, RAT not allowed, unknown EPS subscription, auth data unavailable, unable to deliver, too busy, ...
- Requests that never got an answer

**GTPv2-C**
- Rejections with the cause and the APN: missing or unknown APN, APN access denied, IP pool exhausted, context not found, system failure, ...
- Whether the cause came from the responder or a node further down the path
- **User authentication failed right after RADIUS Access-Accept**: credentials were fine, the gateway refused on policy
- **PDN type split**: IPv4v6 rejected while IPv4 works for the same subscriber
- Requests with no response, and retransmission folding

**NAS (EPS)**
- Attach / TAU / Service Reject with EMM cause, linked to the subscriber even when the reject carries no IMSI
- Authentication failure: MAC failure (SIM and HSS keys differ) vs sync failure (and whether it recovered)
- PDN Connectivity Reject, and whether it happened during attach (failure) or for an extra APN after a working attach (warning)

Checked against real public captures: [docs/VALIDATION.md](docs/VALIDATION.md).

## How it works

1. **Decode**: `tshark` turns the capture into structured fields. capsight never writes its own dissectors.
2. **Correlate**: requests are paired with answers (Diameter hop-by-hop + end-to-end ID, GTPv2 sequence number), and NAS messages are linked to a subscriber through the S1AP UE ID.
3. **Diagnose**: deterministic rules match known failure patterns. Every verdict cites packet numbers. Nothing is guessed.

## Privacy

Captures contain subscriber identities. capsight runs entirely on your machine, sends nothing anywhere, and stores nothing. Do not commit real captures: the repo's `.gitignore` blocks `*.pcap` / `*.pcapng` outside `samples/`.

## Roadmap

| Protocol | Interface | Status |
|---|---|---|
| Diameter S6a | MME - HSS | done |
| GTPv2-C | S11 / S5 / S8 | done |
| NAS EMM/ESM | UE - MME | done |
| RADIUS | PGW - AAA | done (correlation with GTP rejects) |
| PFCP | N4 | next |
| NGAP / 5G NAS | N2 / N1 | next |
| HTTP/2 SBI | 5GC NFs | planned |
| SIP / Diameter Cx, Rx | IMS / VoLTE | planned |

Also planned: `--redact` (mask IMSI/MSISDN/IP in reports), a web page to drop a capture in, and an MCP server so AI agents can call capsight as a tool.

## Contributing

Public captures that show a failure are the most useful contribution. Open an issue with a link (never attach captures with real subscriber data).

```bash
uv run pytest        # tests generate their own captures; tshark required
uv run ruff check .
```

## License

MIT
