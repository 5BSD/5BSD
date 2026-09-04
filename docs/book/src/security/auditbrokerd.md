# auditbrokerd: the BSM Audit Broker

`audit(2)` writes a record into the kernel's BSM audit trail. Traditionally
the caller must be privileged, and it may write *any* record — the event
class and contents are entirely the caller's to state. That is unacceptable
in the capability plane, where the point is that a component holds narrow
authority and cannot forge the identity of another: a service that could
submit an arbitrary BSM record could forge the audit trail itself.

`auditbrokerd` is 5BSD's **submit-only** audit broker, exposed as
`system.Audit`. It accepts submissions only from a small, closed allow-list
of authenticated system providers, and derives each record's BSM event class
from the caller's [unforgeable channel label](authority-model.md) — never
from anything on the wire. The wire message carries the record's variable
content, but its class and claimed origin are facts the broker establishes
itself. There is deliberately no query API: the broker writes the trail and
never reads it back.

It is an ordinary socket-free provider (see
[serviced](../system/serviced.md)): demand-launched, one capability-mode
worker per client. One design detail matters for trust: each provider is
rate-limited by a token bucket kept in the long-lived parent, keyed by label,
so a compromised submitter cannot recover its burst allowance by cycling its
session.

One honest caveat: a submission carries a caller-asserted subject/operation
string. The broker validates its form, but only the event class and
originating provider are authenticated — the operation text is a descriptive
hint, not an authenticated assertion.

Reference: `auditbrokerd(8)`.
