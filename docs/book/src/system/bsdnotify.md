# BSDNotify

BSDNotify is the system-wide notification service, exposed as `system.Notify`
and consumed through `libnotify(3)`. It gives capability-mode services
bounded exact-topic publish/subscribe, retained state values, and monotonic
timers. One broker routes sessions for the host, but it is not a global
broadcast API: every session is identified by its unforgeable channel label
(see [The Authority Model](../security/authority-model.md)) and gets an
independent, default-deny policy, subscription set, queue, and timer
namespace. Retained state is owner-scoped — only the label that set a value
may clear it, and a label's state is evicted when its last session goes away.

Delivery is honest rather than pretend-reliable. Events carry the
authenticated publisher label (stamped by the broker — it can never be
supplied in a request), and fanout never blocks a publisher: a subscriber
that falls behind loses its newest events and reads an explicit gap marker
with the loss count, and a broker restart surfaces as an explicit reset
rather than a silently discontinuous stream. Payloads are hints — they must
not carry secrets or the only copy of application state.

A session can enumerate its own holdings: **`LIST_SUBSCRIPTIONS`** returns the
topics it is subscribed to and **`LIST_TIMERS`** returns its active timers (id,
interval, and a best-effort time to next expiry). Both are paginated through an
opaque cursor and are always scoped by the router to the requesting session —
there is no cross-session view.

Policy ships inside the provider's bundle: a fail-closed configuration maps
channel labels to exact publish/subscribe topic grants, and undeclared
clients and operations are denied. The router runs in capability mode with no
ambient filesystem, socket, fork, or exec authority, and its audit and DTrace
surfaces record decisions as metadata only, never payload bytes.

Reference: `bsdnotify(8)`, `libnotify(3)`, `notifyctl(8)`.
