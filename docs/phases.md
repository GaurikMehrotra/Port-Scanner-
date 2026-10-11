# Sixteen-phase terminal guide

All commands below run from the checkout root in a WSL2/Linux terminal with Docker
available, unless marked PowerShell. They are presented as learning phases, but the
implementation was built without waiting between phases as requested. Full code is in
[the source reference](source_reference.md) and in each linked repository file; no omitted
implementation fragments. Run `git diff --stat` and review before each suggested commit.
Because all phases are already present, use one final commit unless deliberately replaying
the development history in a separate learning copy. Commit commands are suggestions,
not claims that commits have been created.

## 1. Environment and safety scaffolding

```sh
python3 --version
docker version
docker compose version
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock -r requirements-eval.lock
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
cat SAFETY.md
.venv/bin/pytest -q tests/test_connect.py::test_open_closed_banner
# Suggested learning commit:
git add .gitignore pyproject.toml requirements.lock requirements-eval.lock README.md SAFETY.md LICENSE
git commit -m "Document authorized scope and scaffold labscan development"
```

On Windows install WSL2 and enable Docker Desktop integration with your distribution.
Use VS Code's WSL extension. Do not assume Windows/WSL host access to internal containers.
For a harmless handshake primer, capture the `lo` interface with Wireshark while running
the loopback test above. Filter `tcp.flags.syn == 1 || tcp.flags.reset == 1`; follow the
loopback stream and observe SYN, SYN-ACK, ACK, then banner/close. Test ports are ephemeral,
so use the observed loopback flow rather than a hardcoded port.

## 2. Scope guard first

```sh
.venv/bin/pytest -q tests/test_scope.py tests/test_scope_property.py
git add configs/scope.yaml src/labscan/scope.py tests/test_scope*.py
git commit -m "Enforce fixed lab scope and test hostile targets before transports"
```

Tests reject documentation-only out-of-scope ranges, IPv6, mapped IPv6, hex/octal/integer
aliases, Unicode, whitespace, wide CIDRs, and mixed DNS answers. 2,012 deterministic
property examples exercise arbitrary IPv4 values/text; not all are hostile or unique.
DNS unit tests use injected fake resolvers and send no packets. No scope override exists.
Production YAML cannot authorize loopback. Positive lab IP tests verify useful acceptance.

## 3. Isolated lab and ground truth

In **PowerShell**, inspect Windows routes:

```powershell
Get-NetRoute -AddressFamily IPv4 | Sort-Object DestinationPrefix
```

In WSL:

```sh
.venv/bin/python lab/preflight.py
ip -4 route
mkdir -p results
docker compose -f lab/docker-compose.lab.yml config --quiet
docker compose --parallel 2 -f lab/docker-compose.lab.yml --profile tools build
docker compose -f lab/docker-compose.lab.yml up -d
.venv/bin/python lab/verify_isolation.py
docker compose -f lab/docker-compose.lab.yml logs --tail 30
git add lab docker .dockerignore
git commit -m "Add internal low-memory lab with service and firewall ground truth"
```

Stop on any overlapping nondefault LAN/VPN/WSL/Docker route. This machine cannot inspect
your laptop's physical LAN. A collision requires redesigning the compiled lab boundary in
a separate code change, not a bypass flag. Isolation checks confirm the internal bridge,
single network per service, no published ports, and no scanner default IPv4 route; they
do not send an external probe. Host-side privileged access to Docker remains possible.
Container logs must show all five services running; ground truth is the expected configuration,
not Nmap output. Builds download dependencies **before** targets run on the internal network.

## 4. Parsing

```sh
.venv/bin/pytest -q tests/test_targets.py
.venv/bin/labscan 172.30.0.8/30 --ports 22,80,8000-8002 --dry-run
git add src/labscan/targets.py src/labscan/ports.py tests/test_targets.py
git commit -m "Parse and bound target and port specifications"
```

Expected: sorted, deduplicated numeric targets and ports, no packets. /24 exceeds the
safe host cap. DNS pinning belongs to real runs; dry-run rejects names rather than resolving.
The common list is an original lab list, not a service database.

## 5. Connect scan and token bucket

```sh
.venv/bin/pytest -q tests/test_connect.py tests/test_ratelimit.py
docker compose -f lab/docker-compose.lab.yml run --rm -T scanner \
  172.30.0.10,172.30.0.11,172.30.0.12,172.30.0.13,172.30.0.14 \
  --output-format json > results/connect.json
git add src/labscan/scanners/connect.py src/labscan/ratelimit.py src/labscan/runner.py tests/test_connect.py tests/test_ratelimit.py
git commit -m "Add bounded async connect scans and shared rate limiting"
```

Expected at baseline: four open TCP ports, 30 closed, one filtered (81 on the firewall).
A timeout does not prove a firewall. Tests verify that a transport blocks an unauthorized
IP even when handed it directly, bypassing target parsing.

## 6. Safe banners and service identification

```sh
.venv/bin/pytest -q tests/test_sanitize.py tests/test_connect.py
docker compose -f lab/docker-compose.lab.yml run --rm -T scanner \
  172.30.0.10,172.30.0.11,172.30.0.13,172.30.0.14 --banners --output-format json \
  > results/banners.json
git add src/labscan/fingerprint src/labscan/output/sanitize.py tests/test_sanitize.py
git commit -m "Identify explicit banner products and sanitize untrusted responses"
```

HTTP identifies LabWeb/1.0; SSH identifies the actual installed OpenSSH version; echo
identifies lab-echo/1.0. Redis PONG identifies a compatible service, not a product/version.
Inspect HTTP HEAD in the capture. No redirects or response URLs are followed. Terminal
escapes, controls, bidirectional format characters and overlong content are neutralized.

## 7. Discovery

```sh
docker compose -f lab/docker-compose.lab.yml run --rm -T scanner \
  172.30.0.10 --discovery tcp --ports 80
docker compose -f lab/docker-compose.lab.yml run --rm -T raw \
  172.30.0.10 --discovery arp --ports 80
git add src/labscan/scanners/discovery.py
git commit -m "Add scoped TCP and on-link ARP discovery"
```

Both should retain the web host. Capture ARP who-has/is-at exchanges. A silent discovery
result can hide a real host, so evaluation always uses the default `--discovery skip`.

## 8. SYN and packet capture

```sh
docker compose -f lab/docker-compose.lab.yml run --rm -T raw \
  172.30.0.10,172.30.0.11,172.30.0.12,172.30.0.13,172.30.0.14 \
  --scan-type syn --output-format json > results/syn.json
.venv/bin/pytest -q tests/test_syn.py
# For a capture, keep a raw-scanner namespace alive:
docker compose -f lab/docker-compose.lab.yml run -d --name labscan-capture \
  --entrypoint sleep raw 300
# Terminal A; this captures ONLY the scanner's network namespace:
docker run --rm --network container:labscan-capture --cap-drop ALL --cap-add NET_RAW \
  --entrypoint tshark labscan-reference -i eth0 -p -a duration:20 -w - > results/syn.pcap
# Terminal B, while capture is running:
docker exec labscan-capture labscan 172.30.0.10 --ports 80,81 --scan-type syn
# Then:
docker rm -f labscan-capture
git add src/labscan/scanners/syn.py tests/test_syn.py
git commit -m "Add capability-limited SYN scans with explicit reply classification"
```

Open `results/syn.pcap` in Wireshark. SYN-ACK on 80 means open; RST on 81 means closed
on the web host. Linux normally sends its own RST after the raw SYN-ACK. The firewall's
81 should instead be silent. We do not suppress kernel RSTs. Random local source ports
are for response matching, not spoofing; no evasion features are implemented.

## 9. UDP and ICMP rate limiting

```sh
.venv/bin/pytest -q tests/test_udp.py
docker compose -f lab/docker-compose.lab.yml run --rm -T scanner \
  172.30.0.10,172.30.0.11,172.30.0.12,172.30.0.13,172.30.0.14 \
  --scan-type udp --output-format json > results/udp.json
# Repeat more slowly to expose ICMP rate-limit effects:
docker compose -f lab/docker-compose.lab.yml run --rm -T scanner \
  172.30.0.10,172.30.0.11,172.30.0.12,172.30.0.13,172.30.0.14 \
  --scan-type udp --rate 1 --output-format json > results/udp-slow.json
.venv/bin/python eval/ground_truth.py results/udp.json
.venv/bin/python eval/ground_truth.py results/udp-slow.json
git add src/labscan/scanners/udp.py tests/test_udp.py
git commit -m "Classify UDP replies, ICMP refusal and unresolved silence"
```

Capture using the same scanner namespace method and filter `udp || icmp` in Wireshark.
DNS should reply. ICMP type 3 code 3 means closed. Silence is open|filtered. Compare
closed->open|filtered counts at both rates; do not relabel silence as definitively closed.

## 10. CLI and output

```sh
.venv/bin/labscan --help
.venv/bin/labscan 172.30.0.10 --dry-run --output-format json
.venv/bin/pytest -q tests/test_output_cli.py
docker compose -f lab/docker-compose.lab.yml run --rm -T scanner \
  172.30.0.10 --output-format csv > results/web.csv
docker compose -f lab/docker-compose.lab.yml run --rm -T scanner \
  172.30.0.10 --output-format xml > results/web.xml
git add src/labscan/cli.py src/labscan/models.py src/labscan/output tests/test_output_cli.py
git commit -m "Expose validated CLI and sorted table JSON CSV XML output"
```

Progress goes to stderr, so redirected JSON stays parseable. CSV includes metadata per
result; XML is an explicitly labeled subset. Output timestamps and durations vary.
Use host redirection for container files rather than adding filesystem capabilities.

## 11. Accuracy, Nmap reference, speed and resources

```sh
.venv/bin/python eval/ground_truth.py results/connect.json
.venv/bin/python eval/ground_truth.py results/syn.json
.venv/bin/python eval/ground_truth.py results/udp.json
docker compose -f lab/docker-compose.lab.yml run --rm -T reference -sT -Pn -n \
  --reason --max-rate 20 --max-retries 0 -p 22,53,80,81,82,6379,8000 -oX - \
  172.30.0.10 172.30.0.11 172.30.0.12 172.30.0.13 172.30.0.14 > results/nmap-connect.xml
docker compose -f lab/docker-compose.lab.yml run --rm -T reference -sS -Pn -n \
  --reason --max-rate 20 --max-retries 0 -p 22,53,80,81,82,6379,8000 -oX - \
  172.30.0.10 172.30.0.11 172.30.0.12 172.30.0.13 172.30.0.14 > results/nmap-syn.xml
docker compose -f lab/docker-compose.lab.yml run --rm -T reference -sU -Pn -n \
  --reason --max-rate 20 --max-retries 0 -p 22,53,80,81,82,6379,8000 -oX - \
  172.30.0.10 172.30.0.11 172.30.0.12 172.30.0.13 172.30.0.14 > results/nmap-udp.xml
.venv/bin/python eval/compare_nmap.py results/connect.json results/nmap-connect.xml
.venv/bin/python eval/compare_nmap.py results/syn.json results/nmap-syn.xml
.venv/bin/python eval/compare_nmap.py results/udp.json results/nmap-udp.xml
.venv/bin/python eval/benchmarks.py --trials 3
git add eval/ground_truth.py eval/metrics.py eval/compare_nmap.py eval/benchmarks.py eval/worker.py
git commit -m "Add truth metrics reference comparison and resource benchmarks"
```

Nmap is a reference, not truth. Missing observations remain missing. Precision has a null
value when no open prediction exists, rather than fabricating a zero denominator result.
Do not count a zero-result run as validation. Benchmark JSON saves complete settings and
results; CSV/SVG summarizes throughput, CPU and peak RSS. These are scanner-process
measurements; use Windows Task Manager/Docker stats to examine WSL/Docker overhead locally.
Inspect every disagreement against fixture policy and packet evidence.

## 12. Impairment and ablations

```sh
docker compose -f lab/docker-compose.lab.yml exec -T firewall tc -V
.venv/bin/python eval/impairment.py --trials 3
# Confirm cleanup:
docker compose -f lab/docker-compose.lab.yml exec -T firewall tc qdisc show dev eth0
git add eval/impairment.py lab/netem
git commit -m "Evaluate latency loss timeouts retries and transport ablations"
```

The target has NET_ADMIN. This cloud kernel currently lacks the netem qdisc; the harness
reports a blocked outcome in results/impairment/status.json and leaves noqueue unchanged.
Run this required experiment on a Linux/WSL2 kernel that supports sch_netem. Do not claim
phase 12 was validated until its measured results exist.

The target has NET_ADMIN. The harness uses tc qdisc replace ... netem delay 200ms loss 10%,
then deletes the qdisc in a finally block. It compares control/delay/loss and short/long
timeout/retry settings for connect/SYN, with three repeats. Only target egress is impaired;
TCP retransmission can mask some loss. Kernel random loss is not given an invented seed.
A too-short timeout can turn an open service into inferred filtered. Three repeats are a
small demonstration, not a statistically powered generalization.

## 13. Optional defensive view

```sh
.venv/bin/python eval/detect.py results/syn.pcap --window 5 --threshold 10
.venv/bin/pytest -q tests/test_detector.py
git add eval/detect.py tests/test_detector.py
git commit -m "Add lab-only offline SYN fan-out detector and benign controls"
```

Automated captures with verified readiness and cleanup are also available:

```sh
.venv/bin/python eval/capture.py syn --output results/scan.pcap
.venv/bin/python eval/capture.py benign --output results/benign.pcap
.venv/bin/python eval/capture.py nmap-udp --output results/nmap-udp.pcap
```

The two-port capture from Phase 8 should not alert at threshold 10. To capture a detectable
scan, use all seven ports across the five targets while the namespace capture is active.
Capture benign repeated HTTP connections separately with the same technique. Report the
number of captures and alerts; synthetic unit controls do not establish a real-world
false-positive rate. A low/slow scan can fall below this simple threshold; do not generalize.

## 14. Packaging, tests, CI

```sh
make install
make check
.venv/bin/python -m pip wheel --no-deps --no-build-isolation . -w dist
git add Makefile pyproject.toml requirements.lock requirements-eval.lock .github tests src/labscan/py.typed
git commit -m "Finalize typing lint packaging and loopback-only CI"
```

Expected: executed tests pass, Ruff is clean, strict mypy is clean, and a wheel builds.
CI tests Python 3.10 and 3.12. No raw packets are sent in CI; SYN reply tests construct
packets offline and network tests start their own ephemeral loopback services.

## 15. Documentation and honest results

```sh
cat docs/results.md
cat docs/how_scanning_works.md
git add README.md SAFETY.md docs
git commit -m "Document packet semantics reproduction results and limitations"
```

Read results as measurements of this specific small lab. Product/version fields are
observations, not trust or vulnerability claims. Laptop-specific results remain unmeasured
until you run the harness there. Direct and resolved dependencies are pinned, while Debian
package updates mean an exact future image rebuild may differ; record image IDs/digests.

## 16. Review and publish to the existing GitHub repository

```sh
make check
.venv/bin/python eval/audit.py
.venv/bin/python lab/verify_isolation.py
git status --short
# The repo already exists. Do not create a duplicate with gh repo create.
git add .
git commit -m "Build authorized labscan with isolated lab and reproducible evaluation"
git branch -M main
git push -u origin main
make lab-down
```

Review all changes before committing/pushing. The implementation task does not
push automatically. If starting a separate repository instead, run `gh repo create` with
your chosen name only after reviewing GitHub's current CLI documentation and authentication.
The audit checks IP literals, protected scope examples and CI commands; it complements
unit/property tests and review, not a formal proof against source modification.
