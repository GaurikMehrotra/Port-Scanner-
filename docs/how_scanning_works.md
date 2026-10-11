# How scanning works

## TCP connect

```text
scanner                           lab service
  | -------- SYN --------------------> |
  | <------- SYN-ACK ----------------- |
  | -------- ACK --------------------> |  open: connection succeeds
  | <------- banner / reply ---------- |
  | -------- FIN / ACK --------------> |  close normally
```

TCP establishes a connection with a three-way handshake. SYN proposes a connection,
SYN-ACK acknowledges it and proposes the responder's sequence number; ACK completes it.
A refusal (normally RST) means closed at that instant. Timeout or unreachable is reported
as filtered, an inference rather than proof of a firewall. Loss, latency, overload, routing
failure, or a disappearing host can give the same observation. Retries reduce some random
loss errors but do not establish ground truth. Unexpected local errors abort the run.

## SYN

```text
scanner                           lab service
  | -------- SYN --------------------> |
  | <------- SYN-ACK ----------------- |  open
kernel -------- RST -----------------> |  no socket owns this handshake
  | <------- RST (on closed port) ---- |  closed
  |             silence               |  filtered (inference)
```

Scapy sends one scoped SYN at a time per worker, with randomized local ephemeral source
ports and sequence numbers. This is normal correlation, not spoofing. It does not finish
the handshake. Linux normally sends a RST when an unexpected SYN-ACK has no owning socket.
We leave that behavior enabled: no RST-suppression rule, stealth, or evasion. Capture and
inspect it; kernel behavior and NAT on WSL2 must be verified rather than assumed. Scapy
matches replies to requests. ICMP unreachable is recorded as filtered. A packet classifier
can only describe the observation, not the underlying firewall policy.

## UDP

```text
scanner -- DNS lab.test A query --> DNS fixture
scanner <-- validated DNS reply -- fixture       open
scanner -- datagram -------------> closed port
scanner <-- ICMP type 3 code 3 --- kernel         closed
scanner -- datagram -------------> silent port
scanner         (timeout)                        open|filtered
```

UDP has no handshake. Any matching UDP reply proves a responder is present. A connected
UDP socket on Linux surfaces an ICMP port-unreachable as ECONNREFUSED. Other unreachable
messages produce filtered; silence remains open|filtered because a legitimate application
may ignore an unfamiliar probe. Only port 53 receives our DNS query; it requests a lab-only
record with a fixed transaction ID and no recursion. Generic ports receive a small labscan
marker. Closed UDP ports can look silent when the kernel limits ICMP error responses.
This makes UDP slower and less certain; compare low versus high rates and inspect ICMP
counts. A lower exact state accuracy is not automatically an implementation defect.

## Discovery and banners

TCP discovery tries three lab service ports and accepts either success or refusal as proof
of a responding host. ARP is on-link only and requires NET_RAW; no ARP reply does not prove
a host is absent. Default discovery is skip so it cannot hide silent but real hosts from
evaluation. ARP Ethernet broadcast stays within the isolated bridge.

HTTP HEAD does not follow redirects or fetch external resources. SSH reads a greeting;
Redis-compatible probes use PING. Text is bounded and terminal escapes/controls removed.
Product and version are reported only when present in a recognized response; a service
label or banner can be fabricated by a target. Redis PONG alone does not prove a Redis
product/version. DNS does not imply a particular DNS implementation. This is identification,
not OS fingerprinting or vulnerability detection.

## Rate and uncertainty

A shared one-token-capacity token bucket limits outbound transport attempts; concurrency
limits in-flight operations, not packet rate. Retries consume tokens. The kernel may
retransmit TCP segments and Scapy may resolve ARP, so this is an attempt rate limit, not an
exact wire-packet budget. Banner writes are additionally rate limited. Defaults are 20
attempts/s, 10 workers, 1s timeouts and no explicit retries; hard ceilings are defined in
validated Limits. Deterministic ordering applies to result rows, not timestamps or network
measurements. Network observations and random source ports are intentionally not deterministic.
