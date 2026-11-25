# capsight

**Drop in a 4G/5G packet capture, get a plain-English diagnosis of why a device couldn't attach, register or get data.**

> Status: early development. 4G core (Diameter S6a, GTPv2-C, EPS NAS, RADIUS) and 5G SA (NGAP, 5G NAS, PFCP, GTP-U) work today. See [docs/PLAN.md](docs/PLAN.md).

![capsight diagnosing two captures](docs/img/demo.svg)

Debugging a mobile core usually means scrolling through thousands of Diameter, GTP and NAS packets in Wireshark and looking up result codes and cause values by hand. capsight does that part: it pairs requests with answers, matches known failure patterns and tells you what broke, for whom, where in the capture, and what to check next.


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
pip install capsight             # from PyPI (after the first release)

# or from source
git clone https://github.com/Kx96xx/capsight.git
cd capsight
uv sync
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
| 4G: device won't attach | MME (S1-MME + S6a) | `sctp or port 3868` |
| 4G: attached but no data | MME/SGW/PGW GTP-C | `udp port 2123` |
| 4G: session rejected by AAA | PGW + RADIUS | `udp port 2123 or udp port 1812 or udp port 1813` |
| 5G: gNB or phone won't register | AMF (N2) | `sctp port 38412` |
| 5G: registered but no PDU session | AMF + SMF/UPF (N2, N4) | `sctp port 38412 or udp port 8805` |
| 5G: session up but no internet | UPF (N3 + N6) | `udp port 2152 or icmp` |

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

### 4. Web demo

A small upload page, for people who would rather not use a terminal:

```bash
pip install "capsight[web]"
capsight-web                     # http://127.0.0.1:7860
```

Uploads are analyzed in a temporary folder and deleted right after. `web/Dockerfile` builds
the same page as a container (it is what the hosted demo runs).

### 5. Use it in scripts / CI

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

**5G SA**
- NGAP failures with the cause, e.g. NG Setup rejected for an unknown PLMN or tracking area
- Registration / Service / Security Mode Reject with 5GMM cause (no slices available, PLMN not allowed, ...)
- 5G-AKA authentication failure: MAC failure (keys mismatch) vs sync failure, and whether the network then rejected
- PDU session request refused by the AMF (e.g. 5GMM #91, DNN not subscribed), naming the DNN
- PDU Session Establishment Reject from the SMF with 5GSM cause and DNN
- PFCP rejects between SMF and UPF (rule creation failure, no association, no resources, ...) and unanswered PFCP requests
- One-way user plane: uplink enters the GTP-U tunnel and nothing comes back, with a NAT hint when a private UE address leaks onto N6
- SUPI shown when the SUCI is not concealed; never guessed when it is

Checked against real public captures, 4G and 5G: [docs/VALIDATION.md](docs/VALIDATION.md).

## How it works

1. **Decode**: `tshark` turns the capture into structured fields. capsight never writes its own dissectors.
2. **Correlate**: requests are paired with answers (Diameter hop-by-hop + end-to-end ID, GTPv2 and PFCP sequence numbers), and NAS messages are linked to a subscriber through the S1AP / NGAP UE ID.
3. **Diagnose**: deterministic rules match known failure patterns. Every verdict cites packet numbers. Nothing is guessed.

## Privacy

Captures contain subscriber identities. capsight runs entirely on your machine, sends nothing anywhere, and stores nothing. Do not commit real captures: the repo's `.gitignore` blocks `*.pcap` / `*.pcapng` outside `samples/`.

## Roadmap

v0.2 real-capture usability, v0.3 operator coverage (roaming, Gx/Gy, MAP), v0.4 voice and SMS, v0.5 diagrams/HTML/MCP, v1.0 stable. Details and exit tests: [docs/ROADMAP.md](docs/ROADMAP.md).

## Contributing

Public captures that show a failure are the most useful contribution. Open an issue with a link (never attach captures with real subscriber data).

```bash
uv run pytest        # tests generate their own captures; tshark required
uv run ruff check .
```

## License

MIT
