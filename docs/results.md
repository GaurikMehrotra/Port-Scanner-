# Executed validation and remaining work
Measurement date: 2026-10-12 00:10 IST. Linux cloud kernel 6.18.44; Python 3.12.11 in scanner images. These are **cloud measurements**, not measurements on the requested Intel i3 laptop.
## Verification

- Python 3.12.14: 96 tests passed; Python 3.10.22: 96 tests passed.
- Ruff checks and formatting passed; strict mypy covers scanner, evaluation, lab helpers, tests, and source renderer.
- Python wheel built; pinned install commands exercised repeatedly.
- Scope: 56 table-driven hostile address/DNS-answer cases rejected, plus 2,012 deterministic property examples (IPv4, text, positive lab addresses and rejected IPv6). Property examples are not all hostile or necessarily unique.
- Direct calls to TCP, UDP, SYN and ARP transports reject a documentation-only unauthorized destination before send. A live loopback test confirms DNS pinning survives a resolver-answer change.
- Docker: internal bridge, exact subnet, no published ports, single network per target, and no scanner default route verified. The CLI additionally requires the directly connected lab route.
- TCP and ARP discovery each retained the web fixture. Actual CSV and XML output were parsed/inspected; JSON is used by all metrics.
- GitHub Actions is configured for Python 3.10/3.12 with loopback-only networking; local checks passed; check GitHub for the hosted Actions outcome after publication.

## Baseline truth comparison

Each scan observed all 35 entries (five hosts × seven ports). No missing or unexpected entries. Defaults: concurrency 10, timeout 1s, no explicit retries, rate 20 attempts/s, discovery skipped. Connect banner identification was separately checked. The YAML defaults describe all remaining ports as closed, but **only this seven-port sample was measured**, not all 65,535 ports.

| Scan | Exact state matches | Open precision | Open recall | Observed ambiguity |
|---|---:|---:|---:|---|
| TCP connect | 100.00% | 100.00% | 100.00% | 0 closed reported uncertain; 0 filtered reported uncertain |
| TCP SYN | 100.00% | 100.00% | 100.00% | 0 closed reported uncertain; 0 filtered reported uncertain |
| UDP, 20/s | 88.57% | 100.00% | 100.00% | 3 closed reported uncertain; 1 filtered reported uncertain |
| UDP, 1/s | 97.14% | 100.00% | 100.00% | 0 closed reported uncertain; 1 filtered reported uncertain |

Confusion matrices (true -> reported):

- `connect`: `{"closed -> closed": 30, "filtered -> filtered": 1, "open -> open": 4}`
- `syn`: `{"closed -> closed": 30, "filtered -> filtered": 1, "open -> open": 4}`
- `udp`: `{"closed -> closed": 30, "closed -> open|filtered": 3, "filtered -> open|filtered": 1, "open -> open": 1}`
- `udp-slow`: `{"closed -> closed": 33, "filtered -> open|filtered": 1, "open -> open": 1}`

The UDP filtered port's `open|filtered` result is the correct uncertainty-preserving observation, even though it reduces exact physical-state accuracy. Do not count it as an unexplained implementation failure. At 20/s, three closed ports were also uncertain; at 1/s all 33 closed ports produced refusal. The target kernel reported `icmp_ratelimit=1000` milliseconds. This rate comparison and packet evidence support an ICMP rate-limit explanation; silence itself does not prove its cause.

## Every Nmap disagreement

Nmap 7.93 used the same target/port sample, discovery disabled, name resolution disabled, zero retries, and a maximum rate of 20. TCP connect and SYN had **zero disagreements** (35 observations each). There were five UDP disagreements:

| Host | Port | labscan | Nmap | Fixture truth | Investigation |
|---|---:|---|---|---|---|
| 172.30.0.10 | 6379 | closed | open|filtered | closed | Both scanners report closed at 1/s. Different probe timing and ICMP error limiting explain uncertainty at higher rate; silence is retained honestly. |
| 172.30.0.12 | 53 | open | open|filtered | open | Packet capture shows Nmap sends version.bind TXT/CHAOS; fixture answers only lab.test A/IN. Our protocol-specific query receives a reply. |
| 172.30.0.13 | 6379 | closed | open|filtered | closed | Both scanners report closed at 1/s. Different probe timing and ICMP error limiting explain uncertainty at higher rate; silence is retained honestly. |
| 172.30.0.13 | 8000 | open|filtered | closed | closed | Both scanners report closed at 1/s. Different probe timing and ICMP error limiting explain uncertainty at higher rate; silence is retained honestly. |
| 172.30.0.14 | 6379 | closed | open|filtered | closed | Both scanners report closed at 1/s. Different probe timing and ICMP error limiting explain uncertainty at higher rate; silence is retained honestly. |

At 1/s Nmap reported 33 closed and two open|filtered (the actual DNS service and the deliberately dropped port). The only remaining cross-scanner difference was DNS. The fixture is a **restricted synthetic DNS responder**, not a full general-purpose DNS server; this query-specific disagreement is expected and is not evidence that labscan outperforms Nmap on real networks. [Diagnostic DNS queries](evidence/nmap-dns-queries.tsv) and [Nmap UDP capture](evidence/nmap-udp.pcap) retain the evidence. Nmap is a reference, not the source of truth.

## Speed, resources and ablations

72 completed runs: 3 transports × 8 one-factor configurations × 3 repeats, each with 35 observed results (2,520 total observations). Configurations vary concurrency 1/10/20, timeout 0.25/1/2s, retries 0/1 and rate 5/20/50. Source code was refined during validation (metadata, Python 3.10 compatibility and containment checks); this small dataset is exploratory validation, not a controlled release benchmark. Re-run the harness from a committed release before claiming release-to-release performance differences.

Baseline means (n=3):

| Transport | Ports/s | Scanner CPU seconds | Peak RSS MiB | Exact accuracy |
|---|---:|---:|---:|---:|
| connect | 13.61 | 0.0208 | 78.95 | 100.00% |
| syn | 13.40 | 0.1279 | 79.69 | 100.00% |
| udp | 13.62 | 0.0179 | 79.20 | 88.57% |

The resource worker measures scan-phase CPU time, process lifetime peak RSS, and scan duration inside Linux. Docker startup/image build overhead and total WSL/Docker Desktop memory are excluded. Higher SYN CPU reflects Scapy work; changing timeout primarily changes waits on the one dropped TCP port. UDP accuracy decreases as ICMP error responses become limiting. These small samples do not establish broad performance claims or confidence intervals.

![Measured means and sample standard deviations](evidence/benchmarks/measurements.png)

[Raw benchmark JSONs, settings, CSV and SVG](evidence/benchmarks/) preserve all 72 runs, including uncertain outcomes. Plots use Matplotlib; error bars are sample SD, not standard error or a confidence interval. Hypothesis examples are deterministic; Scapy source ports and kernel behavior are not given a fictitious random seed.

## Impairment: blocked, no fabricated results

The kernel rejects `tc qdisc replace dev eth0 root netem delay 0ms` with **Specified qdisc kind is unknown**. No netem measurements ran. The original `noqueue` qdisc was checked after the failure. Cleanup tests verify that failed installation leaves it alone and that an installed qdisc is removed after scan failure. [Machine-readable blocked status](evidence/impairment-status.json).

The harness implements control, 200ms delay, and 200ms + 10% loss, comparing two transports, three timeout/retry settings and three repeats (54 planned runs). It is **not validated experimentally** on this kernel. Required next step: run `python eval/impairment.py --trials 3` on a Linux/WSL2 kernel with sch_netem support, inspect cleanup, and add the resulting table/plots. Do not use privileged mode as a substitute for a missing qdisc. Laptop subnet checks and laptop CPU/memory measurements also remain local work.

## Packet and defensive view

One actual lab SYN capture contained 35 SYNs, four SYN-ACKs, 30 RST/ACK refusals and four kernel RSTs following SYN-ACKs. This directly demonstrates the unexpected-SYN-ACK kernel behavior. The dropped TCP port produced no reply.

The detector (ten distinct destination host/port pairs within five seconds) alerted on **1/1 scan captures** and **0/1 benign captures**. The benign trace contains six ordinary HTTP HEAD connections to one service. Synthetic PCAP unit tests also cover positive and negative controls. This tiny sample does not estimate deployment-wide false-positive rates; slow scans and normal fan-out applications can respectively cause false negatives and false positives.

[Scan PCAP](evidence/scan.pcap), [benign PCAP](evidence/benign.pcap), [packet summary](evidence/scan-packets.tsv), and alert JSONs are retained. The initial PCAPs also contain local IPv6 router/multicast background traffic from their own Docker namespace; the scanner itself sends no IPv6 probes. Future captures use a lab IPv4/ARP capture filter. No global unicast addresses occur in the evidence. No Wireshark GUI was available here; tshark inspected the actual packets. Use the phase guide to inspect the same files in Wireshark locally.

## Reproduction provenance

Base Python image: `python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7`.
Redis: `redis:7.4.4-alpine@sha256:ee9e8748ace004102a267f7b8265dab2c618317df22507b89d16a8add7154273`.
Docker Engine 28.4.0, Compose 2.40.3; iproute2/tc 6.1.0. Final SSH/reference images also use the pinned Python/Debian base; initial reference measurements used Debian bookworm with the same Nmap version. Debian package repositories are live, so exact package revisions can change on a future rebuild. Direct/resolved Python packages are pinned in the two requirements files.

TLS, image checksums and apt signature verification remained enabled. Cloud builds needed the platform proxy and its trusted CA as a temporary BuildKit secret; these machine-specific addresses and trust files are not copied into repository instructions or images. A saved cloud setup draft reproduces this environment-specific wiring.
