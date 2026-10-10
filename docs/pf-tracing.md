# PF tracing

PF exposes static DTrace probes through the `pf` provider. Load `dtraceall`
and inspect the installed kernel with `dtrace -lv -P pf`. These probes supplement
existing state lookup, rule completion, routing, Ethernet and ioctl probes.
They do not change filtering policy or enable packet logging.

## Observation script

The dtrace package installs `/usr/share/dtrace/pf-observe`. Load `dtraceall`
and run as root:

```sh
/usr/share/dtrace/pf-observe
# Or collect a bounded 30-second observation:
dtrace -s /usr/share/dtrace/pf-observe -c 'sleep 30'
```

Ctrl-C or command completion prints call counts, inclusive latency histograms
in nanoseconds for PF, rule evaluation and synchronous Dummynet handoff, plus
rule selections, lookup hits/misses, state changes, translation results and
errors. It aggregates traffic from all VNETs. Calls include bypass paths;
common-path decision counts exclude them. Lookup counts cover the existing
`state:lookup` probe, not every specialized lookup path. Rule pointers distinguish
anchors with equal rule numbers during a capture, but can be reused after reload.

Timing pairs track nested calls by thread and depth and clear their saved values
on return. Calls already in flight when tracing starts are omitted from timing;
incomplete calls at capture end have no sample. Elapsed time includes scheduling
and nested work, so histograms are not exclusive CPU cost. Handoff latency is
not queue residence or end-to-end delivery latency. Tracing itself adds overhead;
compare representative workloads with tracing disabled before drawing throughput
conclusions. DTrace errors and drop messages invalidate the measurements.

## Additional probes

All names below have the prefix `pf:ip:`. `ip` covers both IPv4 and IPv6.
Arguments are listed in order starting at `args[0]`.

| Function:name | Arguments | Event |
| --- | --- | --- |
| `test:entry` / `test:finish` | entry: family, direction, `struct ifnet *`; finish: returned action | Balanced events around every non-panic `pf_test` return, including bypass paths. |
| `rules:entry` / `rules:finish` | entry: `struct pf_pdesc *`; finish: action, reason | Rule evaluation timing, including translation and state creation work within `pf_test_rule`. |
| `rules:selected` | `struct pf_pdesc *`, `struct pf_krule *` | Final rule selected after successful translation processing; pass or block. |
| `translation:result` | `struct pf_pdesc *`, stage, PF reason | Stage 0 is legacy translation lookup; stage 1 is rule translation. PFRES_MAX means no translation; PFRES_MATCH means success. |
| `state:create_error` | `struct pf_pdesc *`, `struct pf_krule *`, PF reason | State creation cleanup after resource/limit/attachment failure. |
| `test:result` | address family, direction, action, reason, `struct ifnet *`, packet still present | Final common return after filtering/routing and IPv6 refragmentation. Does not cover early bypass returns (PF disabled, skipped interface, tagged bypass), or Dummynet reinjection. |
| `state:insert` | `struct pf_kstate *` | State successfully linked into the ID hash, with its lock held. |
| `state:insert_error` | `struct pf_kstate *`, errno | Key attachment or duplicate state ID failure; state keys may be incomplete. |
| `state:remove` | `struct pf_kstate *` | State about to be unlinked, before keys and counters are detached. |
| `state:transition` | `struct pf_kstate *`, peer, old value, new value | A changed protocol-state value, before assignment. BOTH emits separate peer events where values change. May occur during state initialization before insertion. |
| `dummynet:submit` | `struct pf_pdesc *`, nullable `struct pf_kstate *`, rule info, flow flags | Immediately before IP Dummynet handoff. Low 16 bits of rule info identify pipe/queue; `IPFW_IS_PIPE` distinguishes the two. |
| `dummynet:returned` | rule info, packet still present | Synchronous handoff returned. A missing packet means consumed; it does not distinguish queued, freed or dropped. |
| `dummynet:reinject` | address family, direction, `struct ifnet *` | Tagged IP reinjection accepted by PF's normal Dummynet bypass. Route-to reinjection uses a separate path and is not counted here. |
| `dummynet:error` | `struct pf_pdesc *`, errno, diagnostic string | Backend unavailable or packet-tag allocation failed. Both preserve the existing ENOMEM result. |

Pointers are for synchronous inspection only. Copy fields during the probe;
do not retain pointers and dereference them in later events. Insert errors do
not imply a fully initialized state. Protocol state numbers depend on protocol.
The result probe deliberately avoids state and packet pointers after ownership
may have changed. These events do not trace Ethernet Dummynet handoffs or
internal scheduler decisions. Disabled probes use the existing SDT machinery;
no performance benchmark has been run for these additions.

## Examples

Run as root on a machine intended for tracing:

```sh
dtrace -n 'pf:ip:test:result { @[arg0, arg1, arg2, arg3] = count(); }'
dtrace -n 'pf:ip:state:transition { @[arg1, arg2, arg3] = count(); }'
dtrace -n 'pf:ip:dummynet:error { @[arg1, stringof(args[2])] = count(); }'
dtrace -n 'pf:ip:dummynet:submit { @[arg2 & 0xffff] = count(); }'
```

## Validation

`tools/test/pf-consolidation/tracing-smoke.sh --disposable-vm` requires root
in a disposable four-core VM with DTrace/CTF, PF, Dummynet and VNET support.
It creates two private VNET jails linked by an epair, enables PF only in the
receiving jail, and checks all sixteen probe names. With tracing enabled, it
requires real IPv4/IPv6 ping success through a delayed pipe, blocked IPv4/IPv6
ping failures, state insertion/removal/transitions, shaping handoff/return and
reinjection events. It runs the installed observation script alongside the assertions, requires
positive PF/rule/handoff timing sample counts and selected-rule/translation
events, and rejects DTrace faults/drops and retains evidence under
`/tmp/pf-tracing.*`. Cleanup removes its jails and epair.

The runtime test does not force allocation failures or state ID collisions.
Those error probes require separate fault-injection coverage. Compilation and
shell syntax checks alone do not establish that the probes fire correctly;
record an actual `PF_TRACING_PASS` from the VM before claiming runtime success.

## Dummynet internals

The dtrace package also installs `/usr/share/dtrace/dn-observe`:

```sh
dtrace -s /usr/share/dtrace/dn-observe -c 'sleep 30'
```

This summarizes scheduler admissions, queue occupancy, dequeued packet sizes,
queue residence, credit waits, delayed release lateness, output dispatch and
input/drop errors across all VNETs. Use it alongside `pf-observe` to distinguish
PF evaluation and synchronous handoff cost from Dummynet waiting.

| Probe | Arguments (zero based) | Meaning |
| --- | --- | --- |
| `dummynet:sched:enqueue:result` | scheduler instance, internal flowset ID, scheduler result, reported packet depth | Scheduler callback returned; nonzero means rejection. No packet pointer is exposed after the callback may have freed it. |
| `dummynet:sched:dequeue:packet` | scheduler instance, packet, residence ticks, reported remaining packet depth | Admission-to-dequeue residence from existing packet tag timestamp. Excludes configured delay line. |
| `dummynet:sched:credit:wait` | scheduler instance, signed scaled credit, wait ticks | Insufficient bandwidth credit schedules another service event. |
| `dummynet:delay:release:packet` | delay line, packet, lateness ticks | Packet became due. Lateness is current tick minus scheduled due tick, not total delay. Interface restoration or later output may still fail. |
| `dummynet:queue:enqueue:done` | queue, packet depth, byte depth | Basic queue append, after accounting. AQM implementations have separate accounting paths. |
| `dummynet:queue:drop:reason` | queue, packet, diagnostic string | Basic queue/loss-model drops, before freeing the packet. |
| `dummynet:io:input:error` | internal flowset ID, diagnostic string | Missing flowset/scheduler, allocation failure, or scheduler rejection. |
| `dummynet:io:output:packet` | packet, dispatch direction | Output dispatch attempt, including configured drops. Immediate synchronous returns bypass this event. |

Timing here uses Dummynet's logical tick clock. Read `kern.hz` when interpreting
it; do not compare raw tick values directly with PF's nanosecond histograms.
A zero residence time can mean enqueue and dequeue occurred in the same tick.
Internal flowset/scheduler IDs may include Dummynet's pipe offsets. Queue depth
is the scheduler's reported accounting; it is not a census of every delay line.

The core admission/dequeue probes cover registered scheduler callbacks,
including AQM schedulers. These additions do not individually attribute every
CoDel/PIE/FQ internal drop or ECN mark. Input errors and basic queue drops can
refer to the same rejection; do not sum them as independent lost packets.
No cross-event packet pointer table is used for residence timing, so flushing
a queue cannot leave stale packet correlation entries in the observation script.

The VM regression runs both installed scripts, inventories all eight new
Dummynet probes, requires dequeue/release samples, and configures 100% packet
loss temporarily to require a real loss-model drop event. Runtime success still
requires `PF_TRACING_PASS`; syntax/object checks are not a runtime substitute.

The extended traffic fixture also saturates a one-packet, 8-Kbit/s pipe to
require queue-limit drops and credit waits, then applies a one-state PF rule
and requires a state-creation limit failure. The burst is intentionally lossy;
its success criterion is the observed queue/credit events.
