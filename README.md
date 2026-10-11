# labscan

An educational, defensive Python port scanner with a fixed authorization boundary:
**your own isolated Docker lab at 172.30.0.0/24**. Do not scan other systems. Unauthorized
scanning can be illegal, including under India's IT Act; this is general information,
not legal advice. Read [SAFETY.md](SAFETY.md) first.

## Quick start (Linux / WSL2)

Use Python 3.10+ and Docker Engine with Compose v2. On Windows, install WSL2 and Docker
Desktop with WSL integration, open this checkout with VS Code's WSL extension, and run
commands inside its Linux terminal. No GPU or external compute service is needed.

```sh
cd Port-Scanner-
make install
make check
.venv/bin/python lab/preflight.py
# Also check Windows Get-NetRoute -AddressFamily IPv4 in PowerShell before proceeding.
# Stop if any nondefault route overlaps 172.30.0.0/24. Do not override the scope guard.
mkdir -p results
make lab-up
.venv/bin/python lab/verify_isolation.py
.venv/bin/labscan 172.30.0.10 --dry-run
# Actual scans belong inside the lab, not in the host terminal:
docker compose -f lab/docker-compose.lab.yml run --rm -T scanner \
  172.30.0.10,172.30.0.11,172.30.0.12,172.30.0.13,172.30.0.14 \
  --banners --output-format json > results/connect.json
.venv/bin/python eval/ground_truth.py results/connect.json
make lab-down
```

See [the complete phase guide](docs/phases.md) for all 16 phases, exact commands,
expected observations, packet-capture instructions, commit commands and full source
references. [How scanning works](docs/how_scanning_works.md) explains the packet semantics.
[Validation results](docs/results.md) separates executed cloud measurements from laptop
experiments. The checkout contains full implementations, not code fragments.

## Capabilities and architecture

```text
CLI -> scope + pinned target parser -> bounded worker pool + token bucket
                                      -> connect / SYN / UDP
                                      -> discovery and safe banner probes
                                      -> sorted models -> table / JSON / CSV / XML
saved results -> truth metrics / Nmap comparison / ablations / netem / offline detector
```

TCP connect uses asyncio sockets; SYN uses Scapy with NET_RAW; UDP uses connected sockets
and a lab DNS probe. Discovery is optional TCP or ARP. Readable Rich tables treat banners as
literal text. JSON, CSV and an Nmap-style XML subset contain timestamps, duration,
settings and scanner version. Rows are numerically sorted. Unknown products and versions
remain null. The XML is explicitly marked labscan; it is not a full Nmap schema clone.

Defaults: 20 transport attempts/s, 10 workers, 1s timeout, zero explicit retries, 32 hosts,
128 ports and 1024 banner bytes. Hard ceilings prevent unbounded configuration. DNS is
resolved once and every answer must pass scope; numeric addresses are rechecked at every
transport send. The dry run is packet-free and accepts numeric specifications only,
so it cannot accidentally trigger DNS traffic. Invalid input exits 2; runtime failure exits 1;
a completed scan exits 0 regardless of open-port count. Ctrl-C follows the CLI's interrupt
handling. IPv6 is explicitly rejected because the lab is IPv4-only.

Examples inside the scanner container:

```sh
docker compose -f lab/docker-compose.lab.yml run --rm -T scanner \
  172.30.0.10 --ports 22,80,8000-8002 --rate 5 --concurrency 2 --timeout 2 --retries 1
docker compose -f lab/docker-compose.lab.yml run --rm -T raw \
  172.30.0.10 --scan-type syn --output-format csv > results/syn.csv
docker compose -f lab/docker-compose.lab.yml run --rm -T scanner \
  172.30.0.12 --scan-type udp --ports 53 --output-format xml > results/dns.xml
```

## Lab and limits

Five targets, no published ports, internal bridge, and small memory limits. The HTTP and
DNS responders and echo listener are original bounded fixtures. SSH is OpenSSH with login
disabled; Redis has persistence disabled and is accessible only inside the lab. The firewall
host drops TCP/UDP 81 and serves a banner on TCP 8000; unused ports reject connections.
Ground truth describes the service/firewall configuration and the measured seven-port
sample. It must be updated with any fixture change. A configuration declaration is not
proof that every port was independently observed.

This project does not perform exploitation, stealth, OS fingerprinting or vulnerability
detection. TCP timeout is an inference; UDP silence cannot distinguish open from filtered.
Version strings can be fabricated, and identification is not an authenticated assertion.
The rate limiter counts application attempts; kernel retransmits/ARP add wire packets.
Base Docker images are pinned by digest; Debian package repositories can change; direct Python dependencies
and resolved dependencies are pinned in requirements.lock. See the recorded image digests
in results documentation for the measured environment, and check upstream documentation
when a command/API fails. Never disable TLS or package-signature verification to fix setup.

The benchmark measures CPU time and peak RSS of the scanner process in Linux, not Docker
Desktop overhead or total laptop memory. Run the same commands locally to measure your i3
and monitor Docker Desktop/WSL memory separately. Netem's loss uses kernel randomness;
replicates are reported without claiming an unsupported fixed seed.

## Reproducibility and contribution

`make install` installs the pinned dependency set. `make check` runs Ruff, strict mypy, and
pytest. CI starts its own loopback servers and never runs the Docker lab or sends raw
packets. The detector's PCAP tests synthesize packets offline. Hypothesis uses deterministic
example generation for the scope tests. No Nmap service/probe database is copied;
the common-port list and signatures are original. MIT applies to project code; third-party
tools retain their own licenses. Nmap is used only as a reference on this lab.

No GitHub push is performed automatically. The phase guide gives review, commit and push
commands for the already-existing GaurikMehrotra/Port-Scanner- repository.
