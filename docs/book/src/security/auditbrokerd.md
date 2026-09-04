# auditbrokerd: the BSM Audit Broker

`audit(2)` writes a record into the kernel's BSM audit trail. On stock FreeBSD
the caller must be privileged, and it may write *any* record — the event class
and contents are entirely the caller's to state. That is unacceptable in the
capability plane, where the point is that a component holds narrow authority
and cannot forge the identity of another: a service that could submit an
arbitrary BSM record could forge the audit trail itself.

`auditbrokerd(8)` (`usr.sbin/auditbrokerd/`, client helpers in
`lib/libauditcmp/`) is 5BSD's **submit-only** audit broker. It exposes
`system.Audit` as a socket-free provider, accepts submissions only from a
whitelist of authenticated provider labels, and derives each record's BSM
event class from the *authenticated* label rather than from anything on the
wire. There is deliberately **no query API**: the broker writes the trail,
never reads it back — reading remains the province of the privileged BSM
tooling.

## The class comes from the label, not the wire

An audit trail is worth trusting only if a record attributes an action to the
subsystem that actually performed it. `auditbrokerd` makes the **event class a
function of the [unforgeable channel label](authority-model.md)**: the broker
knows a session is `system.Log` because the label on its channel says so, and
the class of every record that session submits is derived from that fact. The
wire message carries the record's variable content, never its class or claimed
origin.

The whitelist is small and closed — only `system.Log`, `system.Network`, and
`system.Notify` may submit at all. Any other label is refused `EACCES` before
a record is accepted; there is no wildcard and no "unknown submitter" path.

## Service model

`auditbrokerd` is an ordinary socket-free provider (see
[serviced](../system/serviced.md)): it publishes `system.Audit` in
`activation.ipc`, stays stopped until first lookup, and `pdfork(2)`s one
worker per client, which `cap_enter(2)`s. `audit(2)` is CAPENABLED, so record
submission works from inside capability mode — the worker needs no ambient
filesystem or device authority. The worker authenticates the caller's label
once at admission and files every subsequent record under that provider's
class.

## Rate limiting survives reconnection

Each whitelisted provider is rate-limited with a token bucket kept **in the
long-lived parent, keyed by provider label** — not in the per-client worker.
A bucket in the worker would reset on every reconnect, letting a provider
recover its burst by cycling its session; the parent bucket bounds a
provider's real contribution to the trail over time, protecting it from a
compromised or runaway submitter.

## One caller-asserted field

Alongside the label-derived class, a submission carries a client-supplied
**subject/operation** string. The broker validates its character set and
length so it cannot smuggle control bytes, but its *content* is
caller-asserted, not authenticated. Trail consumers should read the two parts
accordingly: the event class and originating provider are trustworthy — they
derive from the unforgeable label — while the operation text is a descriptive
hint from the provider, not an authenticated assertion.
