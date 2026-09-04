# localnetwork: the outbound-connection broker

A program that can call `socket(2)` and `connect(2)` holds the authority to
reach *any* address the routing table can — exactly the authority an attacker
wants in a compromised component (the classic server-side request forgery
pivot). `localnetwork` exposes `system.Network` as a socket-free provider and
hands a component a *connected, hardened* socket scoped to the network rights
its session actually carries — never general-purpose networking privilege.
It brokers name resolution, TCP connections, and connected UDP sockets —
deliberately no listen, no bind, no raw sockets; their absence is a contract,
not an oversight.

A delivered socket is narrowed before the client touches it: rights-limited
to what a network client does — send, receive, poll, shut down — and
transfer-confined so it cannot be re-pointed elsewhere, turned into a
listener, or handed onward (see
[Capability Transfer](../security/mac-capability.md)).

Policy is **derived from the rights stamped on the session** — by `serviced`
at lookup and by the [auth-agent](../security/authority-model.md) at the
authentication boundary — not from a table inside the daemon, so two clients
of the same broker can have genuinely different network reach with no
per-client configuration. Independently of those rights, a non-admin session
is blocked from sensitive internal destination ranges — loopback,
link-local, private networks — including addresses that resolve there via
DNS. This is the SSRF defense: a brokered connection cannot be steered at a
loopback or metadata address without an explicitly granted internal right.

One honest limitation: today only the admin right is scoped (to
administrative login sessions); the other rights are granted in full until a
finer-grained per-component policy lands, so the broker is the complete
mechanism awaiting stricter policy.

Reference: `localnetwork(8)`, `libnetworkcmp(3)`.
