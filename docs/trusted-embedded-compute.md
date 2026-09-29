# Trusted Embedded Compute: what 5BSD must modernize

Status: **strategy and design. Nothing here is built.** This supersedes and
absorbs the separate notes on compressed memory, memory-pressure policy and
scheduling.

## What 5BSD is for

**Trusted Embedded Compute.** Appliances, embedded systems, and battery- or
harvest-powered devices where the operator needs to *prove* what the machine
is doing: solar cameras, smart glasses, rings, wearables that are not phones,
in-vehicle components, industrial and medical appliances.

What that excludes matters as much as what it includes:

- **Not servers.** Throughput per socket, NUMA balance and 64-core scaling are
  not our problems. Where FreeBSD optimises for them at the cost of latency or
  energy, that trade is now wrong for us.
- **Not phones or tablets.** Darwin owns that, with a vertically integrated
  silicon story we will not match.
- **Not a general-purpose desktop.**

Year one built the trust half — the capability plane, where authority is a
held descriptor rather than a uid or a path. The identity is half-complete:
**we can say what a program is allowed to do, and not what it is allowed to
cost.** Everything below is the second half.

## What we forked, and what it was built for

FreeBSD is an excellent server operating system, and its core is conservative
in the way load-bearing things should be. The mismatch is not quality; it is
purpose. Three assumptions run through the parts that need work:

1. **Power is free and unmetered.** There is no energy model, no CPU capacity
   concept, no power cap, no thermal subsystem. Battery and AC are reported
   (`acpi_battery`, `acpi_acad`) and never *reasoned about*.
2. **Cores are interchangeable.** `sched_ule` understands caches, SMT and
   NUMA — distance, not capability. On a P/E part that assumption is false and
   every placement inherits the error.
3. **Memory pressure ends in a kill.** `vm_pageout_oom()` kills the largest
   process, which is very often the most important one, and it is the *only*
   rung: no notification, no throttle, no compression.

## What must not change

Worth stating, because the temptation to modernise for its own sake is real
and most of this inheritance is an asset:

- **Capsicum** — the foundation the entire capability plane stands on.
- **kqueue** — better than epoll. Coalitions already deliver eight event types
  over a kqueue-able descriptor; that integration is done.
- **UMA and the VM core** — well-engineered. The gaps are at the edges
  (pressure participation, compression), not in the middle.
- **ZFS, DTrace, jails, GEOM** — things other systems are still catching up
  to, and the substrate for trusted update, attestation and observability.
- **The network stack.**

Modernising should mean adding what a server never needed, not replacing what
already works.

## The three gaps, in the order they should be done

The order is not preference; it is dependency. The scheduler cannot place work
well without something to drive frequency and idle states. Compression cannot
be tuned without knowing what a CPU cycle costs in joules. Power is the
foundation.

---

## 1. Power and thermal envelope

**The most important, and the one that is closest to a safety gap.**

### What we have

`powerd`, a **userland daemon polling `kern.cp_times` every 250 ms** over
sysctl and writing frequency back. That is a control loop from another era.

There is **no idle governor at all** — nothing choosing *which* C-state to
enter from predicted idle duration. There is **no thermal subsystem**:
`sys/dev/thermal` does not exist. No zones, no trip points, no cooling
devices, no policy. In a sealed enclosure the response to overheating is
whatever the firmware does, with the OS unaware and unable to shed load first.

There is **no power cap**. RAPL appears only as MSR constants in
`specialreg.h`; nothing drives it.

### What Linux does

`schedutil` takes its signal **directly from the scheduler's utilisation
tracking** — the entity that decided to run something decides how fast. CPU
capacity is normalised to 1024 and PELT produces utilisation on the same
scale, so placement is arithmetic. `cpuidle` governors (menu, TEO) predict
idle duration and pick a C-state. `powercap`/RAPL exists but is *not*
connected to scheduling. A thermal framework with zones, trip points and
cooling devices has been there for years.

### What Darwin does

CLPC — a closed-loop performance controller in the kernel that observes
behaviour and **recommends** cores and operating points. Thread groups carry
declared intent (`EFFICIENT`, `APPLICATION`, `CRITICAL`, `BEST_EFFORT`) and
the controller acts on it.

### What neither does

Both treat power as something to *optimise*. Neither treats it as a **budget
that can be declared, granted and enforced** — which is exactly the shape the
capability plane already uses for everything else.

### What we should build

**The power envelope as a first-class, declared resource.** A unit's manifest
states its power budget; switchboard sets it; the kernel enforces it. Same
pattern as authority: declared up front, held, revocable, attributable.

Concretely, in order:

1. **An energy model and CPU capacity.** Prerequisite for everything, and
   nothing today has either. Without it the machine is lying to itself about
   what its cores are.
2. **An in-kernel frequency governor driven by the scheduler's own signal.**
   Retire the 250 ms poll. This is the piece Linux got right and we can copy
   the *shape* of directly.
3. **An idle governor.** On a fanless, battery device, idle-state residency is
   most of the power budget. We currently leave it entirely to firmware.
4. **A thermal subsystem with policy, not just throttling.** Zones and trips
   are table stakes; the interesting part is *shedding the right work* when
   hot, which is the same question as the OOM victim choice and should reuse
   the same declared classes.
5. **Power capping as enforcement**, with a defined consequence for a unit
   that exceeds its envelope.

---

## 2. Scheduling on heterogeneous cores

### What we have

`sched_ule` and `sched_4bsd`, with `sched_shim.c` providing a seam between
implementations. Topology-aware, capability-blind.

### What Linux does

EEVDF replacing CFS — eligibility and virtual deadlines, so latency
requirements are expressed rather than inferred from nice. **EAS** predicts
the energy cost of each placement from a per-domain model and takes the
cheapest that does not cost throughput — but **switches itself off above 80%
utilisation**, because energy prediction is only reliable while there is idle
time to redistribute. Its preconditions (energy model, schedutil, scale-
invariant utilisation, no SMT) are most of the work. **sched_ext** exposes the
whole scheduling interface to BPF with a watchdog that falls back safely.

### What Darwin does

`sched_clutch` is **1:1 with a thread group**, and timesharing decay is
computed **per group per QoS**. A group therefore cannot buy CPU by spawning
threads — the same argument as making a coalition the accounting subject,
applied to scheduling. Root buckets are chosen by earliest-deadline-first with
per-bucket quantums as explicit anti-starvation. Core placement is a
*recommendation* from CLPC that the scheduler honours.

### The idea worth taking

**Who decides which cores is not who picks the next thread.** Keep the
recommendation a value the scheduler reads; keep the controller out of the
fast path. This is the same rule as keeping policy out of the page daemon, and
this session paid to learn it.

And we already have the declaration channel Darwin needed thread groups for:
the manifest, the management class, and the coalition.

### What we should build

1. **Capacity awareness in ULE** — prerequisite, small, and useful alone.
2. **A declared class plus a recommender** that owns cluster choice. Start it
   as a table; let it become closed-loop only if measurement justifies it.
3. **The group as the scheduled entity** — only if per-unit thread counts
   demonstrably crowd each other out. This is a deep change to the run queues.

**Do not port EAS.** Its preconditions are the bulk of the work and its own
rule is that it declines the busy case — which for an appliance is the case.

---

## 3. Memory: compression and a softer rung

### What we have

No compressed memory of any kind. `sys/vm` contains no compression and
`swap_pager.c` writes uncompressed. On a device with a small swap partition or
none, the first and only response to pressure is a kill.

### What Linux does

**zswap**: a compressed RAM cache in front of a swap device, `zsmalloc` pool,
LRU eviction to the device, hysteresis (`accept_threshold_percent`) so a full
pool does not thrash at its boundary, and same-value pages stored as a pattern
with zero length. **zram**: a compressed RAM block device usable *as* swap
with no backing store — which is why Android and ChromeOS use it. **PSI**
reports `some` (someone is stalled) and `full` (everyone is stalled, the
machine has stopped doing useful work) with a threshold-and-poll interface, so
userspace can shed load *before* the kernel OOM killer runs.

`full` is a far better pressure trigger than free-page counts.

### What Darwin does

Compression is a **page state, not an I/O path**. Pages are packed into
segments; a `c_segment`'s store is a union of "buffer in RAM" or "handle on
disk", so the same object is cache and swap representation. A compressed page
is addressed by `(segment, slot)` through an indirection held in the pager,
which means segments can be **relocated and compacted** without touching pager
metadata. Fragmentation is answered by compaction — minor at a quarter unused,
major at an eighth — *not* by a clever allocator. Two codecs (WKdm, LZ4) plus
a hybrid that picks per page.

Jetsam ranks by **band derived from role**, with footprint only as a tiebreak
within a band, plus idle aging and non-fatal high-water marks that make a
process an early candidate rather than killing it.

### The ideas worth taking

- **A compressed page is still resident.** Compression is a state, not a
  destination. That is why iOS works with no swap device.
- **Address through an indirection**, so segments can move. That one decision
  makes compaction possible and is what lets Darwin skip `zsmalloc` entirely.
- **Bands from role, not size.** Size is a poor proxy for what we can afford
  to lose.
- **`full` pressure as the trigger**, and acting before the killer is needed.

### What we should build

1. **A band integer on `struct proc`**, read by the existing
   `vm_pageout_oom()`: lowest band first, largest within a band. Tiny — an
   integer read, no lock, no allocation, no walk.
2. **PSI-style pressure reporting**, so a supervisor can shed load first. A
   kill avoided beats a kill well chosen.
3. **Compression in the swap pager**, built with the indirection from day one
   so the later move to a first-class page state is a change of *who decides*,
   not of format. LZ4 and zstd are already in the tree; nothing needs
   importing.

**Do not put group semantics in the page daemon.** That was tried this year
and every defect came from it: six blocking acquisitions and an `M_WAITOK` in
a context where a wait is a wait on oneself.

---

## Beyond Darwin and Linux

Where the target is battery, solar and trust, there is research neither system
has had reason to adopt. These are **unproven** and listed in descending order
of how well they fit the identity.

### Peak power, not just average energy

Battery chemistry and solar-plus-supercapacitor delivery are limited by
**instantaneous draw**, not by joules over an hour. High-current bursts cost
disproportionate capacity and shorten cell life. Neither Linux nor Darwin
schedules against a *current* ceiling; both optimise energy.

For a solar camera the constraint is literally "what the panel can deliver
right now." Scheduling against a power ceiling — deliberately *not*
racing-to-idle when the envelope is narrow — is a real and under-served
problem. There is an academic literature on battery-aware scheduling to draw
on.

### Intermittent and energy-harvesting computation

A solar device loses power mid-computation, routinely. The research lineage
here (Mementos, Hibernus, Chain, Alpaca, InK, Chinchilla) is about
checkpointing and idempotent re-execution so a computation *survives* power
loss rather than restarting.

Neither Darwin nor Linux has anything in this space, because neither targets
devices that brown out as a normal operating mode. For harvest-powered
products this is arguably the defining capability, and it interacts directly
with our storage story: ZFS transactional semantics and boot environments are
a better substrate for "resume exactly where we were" than most systems have.

### DVFS as a side channel — the trust angle

**Hertzbleed** (2022) showed that frequency scaling leaks data: a
data-dependent workload changes power, which changes frequency, which changes
timing, which is observable remotely. Linux's mitigation was largely "disable
turbo." Darwin has said little publicly.

For a system whose identity is *trusted* embedded compute, "our power
management is a side channel" is not an acceptable answer. A principled
approach — constant-frequency islands for attested workloads, or declaring
which units require DVFS isolation — would be genuinely differentiating and
fits the capability model exactly: it is another thing a manifest could
declare and the kernel could enforce.

### Attested energy accounting

If a device is trusted, can it *prove* how much energy a workload consumed?
For multi-tenant edge, for regulatory claims, for billing solar-harvested
compute — an attested energy ledger is a plausible product feature nobody
offers. It builds on the accounting substrate and the attestation story we
already have.

### Thermal prediction rather than reaction

Both mainstream systems throttle *after* crossing a trip point. Predictive
thermal management — modelling the enclosure and migrating work before the
trip — matters far more in a sealed, fanless case than in a server with fans
and headroom.

---

## Sequence

1. **Energy model and CPU capacity.** Prerequisite for 2, 3 and 5. Small.
2. **In-kernel frequency governor driven by the scheduler signal.** Retires
   `powerd`'s 250 ms poll.
3. **Idle governor.** Largest single energy win on a battery device.
4. **Thermal subsystem with a shedding policy**, reusing the declared classes.
5. **Capacity-aware placement in ULE**, then a class-plus-recommender split.
6. **Band integer + PSI-style pressure reporting.** Independent of 1–5 and
   cheap; could be pulled earlier if a product needs it.
7. **Compression in the swap pager**, with the indirection built in.
8. **Research bets**, chosen against a real product: power-envelope
   scheduling, intermittent computation, DVFS isolation.

Items 1–4 are the power envelope. 5 is the scheduler. 6–7 are memory. That is
the order the user asked for and the order the dependencies require.

## Open questions

1. **Which product drives this?** The failure mode of the past year was
   mechanism outrunning consumers — a hundred-odd tests and no production
   user. Each item above should be justified by a device we intend to ship,
   not by symmetry with Darwin.
2. **Is the target hardware heterogeneous?** RPi5 and Apple silicon are; many
   embedded x86 and single-cluster ARM parts are not. If the fleet is
   homogeneous, capacity awareness is most of the scheduler value and the rest
   is speculative.
3. **How many declared classes?** One vocabulary should serve thermal
   shedding, OOM victim choice and core placement. Four or five names,
   declared in the manifest, is probably the whole thing.
4. **What is the relationship to SCHED_MIC?** That paused design already
   sketched coalition-keyed QoS buckets and a cluster edge matrix, which is
   close to Clutch. Re-read it against this before starting fresh.
5. **Do we own a power model, or read one?** ACPI and device tree can supply
   some of it; the rest is per-board characterisation, which is a product
   process, not a kernel one.

## Sources

- [Energy Aware Scheduling](https://docs.kernel.org/scheduler/sched-energy.html),
  [sched_ext](https://docs.kernel.org/scheduler/sched-ext.html),
  [CFS](https://docs.kernel.org/scheduler/sched-design-CFS.html),
  [PSI](https://docs.kernel.org/accounting/psi.html),
  [zswap](https://docs.kernel.org/admin-guide/mm/zswap.html),
  [zram](https://docs.kernel.org/admin-guide/blockdev/zram.html) — Linux
  kernel documentation
- XNU `osfmk/vm/vm_compressor_xnu.h`, `osfmk/vm/vm_compressor_algorithms_internal.h`,
  `osfmk/kern/sched_clutch.h`, `osfmk/kern/thread_group.h`,
  `bsd/sys/kern_memorystatus.h`, via
  [apple-oss-distributions/xnu](https://github.com/apple-oss-distributions/xnu)
- Hertzbleed and the intermittent-computing literature are named as
  directions, not read for this note.
