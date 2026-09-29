# Scheduling on heterogeneous cores: prior art and a design for 5BSD

Status: **design, nothing built.** This is here to be argued with. It is the
third of three memory/CPU design notes alongside `compressed-memory-design.md`
and `memory-pressure-policy-design.md`.

Prior scheduler work in this tree — SCHED_MIC — is on hold and referenced in
the capability plane work list. This note is meant to inform whether to resume
it and in what shape, not to restart it.

## What we have today

`sched_ule` (the default) and `sched_4bsd`, plus `sched_shim.c` giving a
dispatch layer between `sched_*` implementations. ULE is topology-aware: it
understands SMT, caches and NUMA through `cpu_group`, and balances on those.

What it does **not** have is any notion that two cores might be *differently
capable*. ULE's model is "CPUs are interchangeable; prefer the ones that are
close." On a P/E machine that assumption is simply false, and every placement
decision inherits the error.

## What the others do

### Linux — capacity, energy, and a way out

**The fair scheduler.** CFS orders by virtual runtime and always picks the
smallest; one tunable, `base_slice_ns`, trades latency against batching. It is
being replaced by EEVDF, which adds an eligibility test and virtual deadlines
so latency requirements can be expressed per task rather than inferred from
nice. Group scheduling via cgroups (`cpu.shares`) lets a *group* be the
scheduled entity.

**Capacity awareness.** Every CPU carries a capacity normalised to 1024
against the most capable core on the machine. Per-Entity Load Tracking (PELT)
produces utilisation signals on the same scale, so "will this task fit here"
is arithmetic rather than guesswork.

**Energy Aware Scheduling** (verified from the kernel docs). EAS carries an
**Energy Model**: per performance-domain tables of capacity and power at each
operating point. At wake-up, `find_energy_efficient_cpu()` finds the CPU with
most spare capacity in each domain, predicts total system energy for each
placement, and takes the cheapest that does not cost throughput.

Two details matter more than the mechanism:

- EAS **only runs when the machine is not busy**. Above 80% utilisation on any
  CPU the "over-utilised" flag trips, EAS switches off and ordinary load
  balancing resumes. The reasoning is that energy prediction is only reliable
  while there is idle time to redistribute into.
- It requires a registered Energy Model, the schedutil governor, scale-
  invariant utilisation, an asymmetric topology, and **no SMT**.

That is a lot of preconditions, and they are the honest cost of energy-optimal
placement.

**sched_ext** (verified). A full scheduling interface exposed to BPF, so a
policy can be written and replaced without touching the kernel. Tasks flow
through dispatch queues — per-CPU local, a global fallback, and custom ones.
Crucially, "system integrity is maintained no matter what the BPF scheduler
does": a watchdog detects stalls and falls back to the default scheduler, with
SysRq-S as a manual escape.

The idea worth taking is not BPF. It is that **scheduling policy is worth
making replaceable**, because nobody gets it right for every workload, and an
appliance's workload is known to its builder and not to us.

### Apple — schedule the *group*, and let a controller pick the cores

Read from the XNU source (`osfmk/kern/sched_clutch.h`,
`osfmk/kern/thread_group.h`).

**Clutch schedules thread groups, not threads.** A `sched_clutch` is a **1:1
mapping to a thread group**. Within it, a *clutch bucket* is the threads of
that group at one QoS level in one cluster. The hierarchy is:

| Level | What it is |
|---|---|
| root | the whole hierarchy; tracks highest runnable priority and urgency |
| root bucket | all threads across groups at one QoS level |
| clutch bucket | one thread group's threads at one QoS, in one cluster |

Root buckets are selected by **earliest deadline first**, where the deadline
comes from when the bucket became runnable plus a worst-case latency for that
QoS. Bucket-level quantums give low-priority buckets guaranteed access even
against short-running high-priority threads — an explicit anti-starvation
mechanism rather than an emergent one.

The consequence: **timesharing decay is computed per group per QoS**, not per
thread. A group that has been running a lot decays as a unit, so spawning more
threads does not buy more CPU. That is the same argument as making a coalition
the accounting subject, applied to scheduling.

**Thread groups carry intent as flags.** Mutually exclusive: `EFFICIENT`,
`APPLICATION`, `CRITICAL`, `BEST_EFFORT`. Combinable: `UI_APP`, `MANAGED`,
`GAME_MODE`, `CARPLAY_MODE`. These are declarations about *what kind of work
this is*, not measurements of what it has done.

**Core placement is a recommendation, not a scheduler decision.**
`thread_group_recommendation()` returns a `cluster_type_t`. A separate
performance controller observes behaviour and *recommends* which cluster a
thread group belongs on; the scheduler honours the recommendation. Threads can
also be cluster-bound outright (`SCHED_CLUTCH_THREAD_CLUSTER_BOUND`), and
`CONFIG_SCHED_EDGE` handles migration between clusters with shared-resource
load tracking.

Separating "who decides which cores" from "who picks the next thread" is the
single most transferable idea here.

## The two philosophies

| | Linux | Apple |
|---|---|---|
| Scheduled entity | the task (groups via cgroups) | the **thread group**, always |
| Core choice | computed inline from an energy model | **recommended** by a separate controller |
| Intent | inferred from measured utilisation | **declared** as thread-group flags |
| Extensibility | sched_ext / BPF | fixed, tuned in-house |

Linux measures and computes. Apple declares and delegates. For an appliance —
where the builder knows what the workloads are and the hardware is fixed —
declaring is cheaper and more predictable than measuring.

And we already have the declaration channel: the manifest, the management
class, and the coalition.

## Our design

### The observation that should drive it

XNU's `sched_clutch` is 1:1 with a **thread group**, and thread groups are the
scheduling face of coalitions. We have coalitions already — identity,
membership, inheritance through fork, and a set-once responsible edge. The
substrate the plane needs for group scheduling exists; what is missing is the
scheduling half.

That is worth stating plainly because it is the one place coalitions clearly
earn their keep in the scheduler: **a group that cannot buy more CPU by
spawning more threads** is only expressible if the group is the scheduled
entity.

### Layer 1 — capacity, so the machine stops lying to itself

Give each CPU a capacity number and make ULE's placement aware of it. Without
this, every later decision is built on "cores are interchangeable," which is
false on the hardware we care about. This is a prerequisite, not a feature.

### Layer 2 — a declared class, and a recommender that owns core choice

Take Apple's split. The manifest declares what kind of work a unit is —
`efficient`, `standard`, `interactive`, `critical` is probably enough
resolution — switchboard sets it on the coalition, and a **recommender**
decides which cluster that class currently belongs on. The scheduler asks the
recommender; it does not model energy itself.

The recommender is where policy lives and where it can be wrong without
breaking correctness. Start it as a table (class → cluster) and let it grow
into something closed-loop if measurement justifies it.

### Layer 3 — the group as the scheduled entity, only if Layer 2 is not enough

Clutch's real work is per-group-per-QoS decay. That is a deep change to ULE's
run queues and should only be attempted if Layer 2 demonstrably fails to stop
one unit's thread count from crowding out another's.

## What we should not do

**Do not port EAS.** Its preconditions — energy model, schedutil, scale-
invariant utilisation, no SMT — are most of the work, and its own rule is that
it switches itself off above 80% utilisation. An appliance under load is
exactly the case it declines to handle.

**Do not infer intent from utilisation.** Measuring what a workload did and
guessing what it is for is what the manifest already tells us.

**Do not put a controller in the scheduler's fast path.** The recommendation
must be a value the scheduler *reads*, updated elsewhere. This is the same
rule as the page daemon in `memory-pressure-policy-design.md`, and it is the
lesson the coalition attempt paid for.

## Questions to settle

1. **Is the target hardware actually heterogeneous?** RPi5 and Apple silicon
   are; most x86 appliances are not, beyond Intel's preferred cores. If the
   fleet is homogeneous, Layer 1 is most of the value and Layers 2–3 are
   speculative.
2. **Modify ULE or add a third `sched_*`?** `sched_shim.c` suggests the
   seam exists. A separate implementation is safer to develop and much harder
   to keep current.
3. **How many declared classes?** Four is probably right. Apple's QoS has
   five or six and considerably more machinery behind each.
4. **Does the recommender need to be closed-loop at all?** A static table may
   be sufficient for a fixed appliance workload, and it is testable in a way a
   controller is not.
5. **What is the relationship to SCHED_MIC?** That design already sketched
   coalition-keyed QoS buckets and a cluster edge matrix, which is close to
   Clutch. Resuming it is probably cheaper than starting again — but it should
   be re-read against this note first.
6. **Is replaceable policy worth building for?** sched_ext's real lesson is
   that the builder knows the workload. A narrow hook is not a BPF interface,
   but the direction is worth considering early, because it is hard to add
   later.

## Sources

- [Energy Aware Scheduling — Linux kernel documentation](https://docs.kernel.org/scheduler/sched-energy.html)
- [Extensible Scheduler Class — Linux kernel documentation](https://docs.kernel.org/scheduler/sched-ext.html)
- [CFS Scheduler — Linux kernel documentation](https://docs.kernel.org/scheduler/sched-design-CFS.html)
- XNU `osfmk/kern/sched_clutch.h` and `osfmk/kern/thread_group.h`, via
  [apple-oss-distributions/xnu](https://github.com/apple-oss-distributions/xnu)
