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

A TCP `CONNECT` may carry a bounded `timeout_ms`: the broker connects
non-blocking and, if the handshake has not completed within that deadline,
closes the socket and fails the request with `ETIMEDOUT` rather than stalling
the session on an unresponsive host. Zero selects the historical fully-blocking
connect (the kernel's own default timeout); a UDP "connect" only assigns the
peer and never blocks, so it ignores the field.

A delivered socket is narrowed before the client touches it: rights-limited
to what a network client does — send, receive, poll, shut down — and
transfer-confined so it cannot be re-pointed elsewhere, turned into a
listener, or handed onward (see
[Capability Transfer](../security/mac-capability.md)).

Policy is **keyed by the session's unforgeable identity**: an admin session
(rights stamped on the channel by `serviced` and the
[auth-agent](../security/authority-model.md)) receives full reach, and every
other session is scoped by the broker's own per-client table. Independently
of that, a non-admin session is blocked from sensitive internal destination
ranges — loopback, link-local, private networks — including addresses that
resolve there via DNS. This is the SSRF defense: a brokered connection cannot
be steered at a loopback or metadata address without an explicitly granted
internal right.

Per-component policy lives in the provider's own configuration, keyed by the
component's manifest label: a `clients{}` entry can narrow any dimension
(resolve, TCP, UDP, address family) for one label or grant it internal reach,
while unlisted labels get the configured default — and a malformed file
fails soft to the built-in default rather than taking the network down. See
`localnetwork(8)` for the schema.

Reference: `localnetwork(8)`, `libnetworkcmp(3)`.
