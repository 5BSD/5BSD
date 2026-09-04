# Endpoint Security (OES)

OpenEndpointSecurity is 5BSD's endpoint monitoring and authorization
framework. It follows the client and event model of Apple's Endpoint
Security API while using the 5BSD MAC framework for enforcement and Capsicum
descriptors for delegation. EDR agents, integrity monitors, and audit
collectors subscribe through `/dev/oes`: **AUTH** clients decide whether
selected operations proceed, while **NOTIFY** clients observe without
blocking them. The alignment with Apple's API is behavioral, not source or
event-catalog compatibility: OES events are native vnode, credential, jail,
Capsicum, socket, mount, and system-configuration operations, and opening
`/dev/oes` is privileged — 5BSD has no equivalent of Apple's code-signing
entitlement.

Every client is independent, owning its own subscriptions, mutes, queue,
deadline policy, and decision cache; a client can be created
descendants-scoped — restricted to its own process subtree — and that
restriction can never be widened. AUTH events must be answered before a
deadline, with per-client policy selecting fail-open or fail-closed when an
answer cannot arrive in time; NOTIFY events never block the originating
operation. Messages are self-describing and versioned, carry sequence
numbers that expose drops rather than hiding them, and treat metadata as a
snapshot with explicit missing/truncated flags — never a silent guess.

Two design points are worth knowing even at this altitude. Delivery is
close-safe by construction: events raised where sleeping is forbidden take a
deferred path, and OES adds a MACF close hook so close observation happens
with a valid credential even for descriptors discarded in unusual ways. And
noise policy is first-class: new clients self-mute by default and
administrators can configure default path mutes, because an endpoint
framework that drowns its consumers gets turned off.

`oeslogger(8)` is the installed passive inspection tool — it streams NOTIFY
events as newline-delimited JSON.

Reference: `oes(4)`, `liboes(3)`, `oeslogger(8)`.
