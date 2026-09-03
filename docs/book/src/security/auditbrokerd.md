# auditbrokerd: the BSM audit broker

`audit(2)` writes a record into the kernel's BSM audit trail. On stock FreeBSD
the caller must be privileged, and it may write *any* record — the event class
and the record's contents are entirely the caller's to state. That is fine when
the only callers are `login(1)`, `sshd(8)`, and a handful of trusted base
programs. It is unacceptable in the capability plane, where the point is that a
component holds narrow authority and cannot forge the identity of another. A
capability service that could submit an arbitrary BSM record could forge the
audit trail itself.

`auditbrokerd(8)` is 5BSD's submit-only audit broker. It exposes `system.Audit`
as a socket-free service provider, accepts audit-record submissions **only from
a whitelist of authenticated provider labels**, and derives the record's BSM
event class from the *authenticated* label rather than from anything the client
puts on the wire. A component can contribute to the audit trail without holding
the audit privilege, and it cannot lie about which subsystem it is.

| Component | Location |
|-----------|----------|
| Provider, policy, rate limiter, and worker | `usr.sbin/auditbrokerd/` |
| Client path | `lib/libaudit/` (submission helpers) |
| Service bundle | `usr.sbin/auditbrokerd/capbundle/` |
| Tests | `usr.sbin/auditbrokerd/tests/` |

## Why the class comes from the label, not the wire

The security property that makes an audit trail worth trusting is that a record
attributes an action to a subsystem that actually performed it. If any client
could submit a record and stamp it "this is a `system.Network` event," the trail
would record fiction. `auditbrokerd` closes this by making the **event class a
function of the authenticated channel label**, which the caller cannot forge
(see the [authority model](../security/authority-model.md)). The broker knows a
session is `system.Log` because the label on its unforgeable channel says so;
the class of every record that session submits is derived from that fact. The
wire message carries the record's variable content, never its class or its
claimed origin.

The whitelist is deliberately small and closed. Only a fixed set of
authenticated provider labels may submit at all:

- `system.Log`
- `system.Network`
- `system.Notify`

A connection whose label is not one of these is refused (`EACCES`) — fail-closed,
before any record is accepted. There is no wildcard and no "unknown submitter"
path: an arbitrary client cannot inject records or choose the class under which
they are filed.

## The service model

`auditbrokerd` is an ordinary socket-free provider (see
[serviced](../system/serviced.md) and
[Writing a Service Provider](../development/writing-components.md)): it publishes
`system.Audit` in `activation.ipc`, stays stopped until first lookup, and
`pdfork(2)`s one worker per client. Each worker `cap_enter(2)`s. Crucially,
`audit(2)` is one of the syscalls marked **CAPENABLED**, so record submission
works from inside capability mode — the worker needs no ambient filesystem or
device authority to write to the trail, only the ability to make the audit
syscall it is already permitted.

Authority for the whole exchange is the caller's channel label; the worker
authenticates it once at admission, maps it to the whitelisted provider identity
and its BSM class, and thereafter every record that session submits is filed
under that class.

## Rate limiting is enforced in the parent

Each whitelisted provider is rate-limited with a token bucket. The subtle and
important design choice is **where** the bucket lives: in the **parent**, keyed
by provider label — not in the per-client worker. If the bucket lived in the
worker, a provider could reset its burst allowance simply by disconnecting and
reconnecting, since a fresh worker would start with a fresh bucket.
Reconnect-churn would defeat the limit entirely. By keeping the token bucket in
the long-lived parent and charging it per provider label, the limit survives
reconnection: a provider that has spent its burst cannot recover it by cycling
its session. The rate limit therefore bounds a provider's real contribution to
the trail over time, which is what protects the trail (and its consumers) from a
compromised or runaway submitter flooding it.

## The subject/operation field is caller-asserted

One field needs a clear caveat for anyone reading the resulting trail. Alongside
the label-derived class, a submission carries a client-supplied
**subject/operation** string — a short human-meaningful description of what the
record is about. `auditbrokerd` records it as **restricted-charset free text**
(it validates the character set and length, so it cannot smuggle control bytes
or overrun a field), but its *content* is **caller-asserted, not
authenticated**. The broker vouches that the record came from, say, `system.Log`
and belongs to `system.Log`'s class; it does **not** vouch that the operation
text is accurate.

Trail consumers should read the two parts accordingly: the event class and
originating provider are trustworthy (they are derived from the unforgeable
label), while the subject/operation string is a descriptive hint supplied by the
provider and should be treated as such — useful context, not an authenticated
assertion.
