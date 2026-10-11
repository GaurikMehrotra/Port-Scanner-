# Authorization and containment

Use labscan only on your own isolated Docker lab with written authorization. Scanning
systems without ownership or authorization can be illegal in many countries, including
under India's IT Act. This is general information, not legal advice.

The production CLI boundary is fixed to 172.30.0.0/24. configs/scope.yaml can narrow
this boundary, never widen it. Loopback policies are constructed only by Python tests;
the production CLI cannot enable them. There is no force option or environment override.
DNS answers are resolved once and pinned; one unauthorized answer rejects the whole name.
IPv6 (including mapped IPv4), legacy numeric encodings, whitespace, Unicode addresses,
and oversized CIDRs are rejected. Each transport checks its numeric destination again
immediately before sending. These guards protect against accidental misuse, not an owner
editing Python source. Do not edit them to scan other networks.

Run scanner and targets on an internal Docker network without published ports. Verify
routes on your own OS and check for subnet collisions before creating the lab. Raw scans
need NET_RAW, not privileged mode. Only firewall/impairment targets need NET_ADMIN.
Network capability does not itself prove isolation. Do not attach a scanner to any second
network. There are no stealth, spoofing, decoy, fragmentation, exploitation, vulnerability
or OS fingerprinting features. Service probes are bounded and benign. Response bytes are
untrusted, truncated, and stripped of terminal controls before output or storage.

Rate, concurrency, host and port caps apply to every run, with hard ceilings. Stop the lab
after use. CI operates exclusively against loopback services that tests start themselves.

The Linux CLI checks that the directly connected lab route is present and no default
IPv4 route exists before resolving names or scanning. This is a containment check, not
proof of Docker configuration: the separate isolation script checks the internal bridge.
Dry-run is numeric-only and emits no packets.
