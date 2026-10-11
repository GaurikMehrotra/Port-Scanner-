# Publication checklist

- [x] Implemented fixed lab scope, no bypass option, strict target parsing and DNS pinning.
- [x] Built and tested the scope guard before scanner transport code.
- [x] 56 hostile input/DNS cases rejected; 2,012 deterministic property examples exercised.
- [x] TCP, UDP, SYN and ARP transport-level rechecks reject an unauthorized target.
- [x] Live loopback test confirms a changed DNS answer cannot change the pinned destination.
- [x] 96 tests pass on Python 3.10.22 and 3.12.14.
- [x] Ruff check/format and strict mypy pass; package wheel builds.
- [x] IP literal audit and retained PCAP address audit pass: no real global unicast targets.
- [x] CI runs only the test suite's own loopback servers; raw and detector tests are offline.
- [x] Docker isolation and final HTTP service/version smoke verified.
- [x] Actual TCP/ARP discovery, CSV and XML outputs verified; JSON drives evaluation.
- [x] Ground-truth matrices, every Nmap disagreement and low-rate UDP follow-up recorded.
- [x] 72 complete ablation/benchmark reports retained, with CSV/JSON and Matplotlib plots.
- [x] Packet capture confirms expected SYN/SYN-ACK/RST behavior.
- [x] Detector alerts on the scan trace and stays quiet on the benign HTTP trace.
- [x] README and results distinguish observations, inference, restricted DNS behavior,
      preliminary cloud performance, and unmeasured laptop results.
- [x] Full phase commands, expected observations, suggested commits and complete source supplied.
- [x] Reusable cloud install/start instructions saved as a configuration draft.
- [ ] Run the 54 planned netem experiments on a kernel supporting sch_netem. This cloud
      kernel rejects netem; no impairment table or accuracy claims have been invented.
- [ ] Check Windows/LAN/VPN subnet collisions on the actual laptop before starting its lab.
- [ ] Run laptop CPU/memory benchmarks and account for WSL/Docker Desktop overhead.
- [ ] Inspect the retained captures in Wireshark; tshark inspection was completed here.
- [ ] Review, commit and push to the existing GitHub repository using Phase 16 commands.
      Check the hosted GitHub Actions outcome after publication.
- [ ] Review/save the cloud configuration draft in environment settings, then publish.
      Publication and restoration in a new cloud task have not been tested.

Core functionality is implemented and validated. The required netem experiment is a known
external blocker, so the entire requested evaluation is not yet complete. Start with
[phases.md](phases.md) and [results.md](results.md); the final commit/push commands are in
Phase 16. Do not create a duplicate GitHub repository.
