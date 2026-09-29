# Memory pressure policy: prior art and a design for 5BSD

Status: **design, nothing built.** This is here to be argued with. It is the
other half of `compressed-memory-design.md` — that one is about having a
softer rung to fall on; this one is about choosing well when there is none.

## What we have today

`vm_pageout_oom()` in `sys/vm/vm_pageout.c`. When reclaim fails it picks
`bigproc` — **the single largest process by RSS** — and kills it. It is rate
limited by `vm_pageout_oom_seq` (default 12) so a brief shortage does not
trigger it, and on NUMA it takes a vote across domains before firing.

Two problems, and the first is the serious one:

1. **Largest is very often most important.** The database, the compositor,
   the VM host. Size correlates with value at least as well as with waste.
2. **It is the only rung.** There is no notification, no throttle, no softer
   action. The first thing the system does about memory pressure is kill.

## What the others do

### Linux — a score, mostly derived from size

`oom_badness()` scores each task from RSS + swap + page tables, then applies
`oom_score_adj` (−1000 … +1000, where −1000 means never kill). Highest score
dies. An `oom_reaper` thread then reclaims the victim's memory asynchronously,
because waiting for a dying process to release memory is itself a way to wedge.

The interesting part is not the kernel's policy — it is that **modern Linux
tries never to reach it**.

### Linux PSI — act before the kernel has to

Verified against the kernel documentation.

`/proc/pressure/memory` reports two numbers. **`some`**: at least one task is
stalled waiting on memory while others still progress. **`full`**: every
non-idle task is stalled — thrashing, with CPU cycles going to waste.
Averages over 10 s, 60 s and 300 s, plus absolute stalled microseconds so
short latency events are not averaged away.

Userspace registers a threshold — `"some 150000 1000000"` means 150 ms of
stall in any 1 s window — and gets a `poll()` wakeup. `systemd-oomd` and
Android's LMKD use this to shed load *before* the kernel OOM killer runs,
which is the whole point: at kernel-OOM time the system is already wedged and
the only move left is violent.

**`full` is a better trigger than "free memory is low."** Free memory says
nothing about whether anyone is suffering; `full` says the machine has stopped
doing useful work.

### Darwin jetsam — a band, not a score

Read from the XNU source (`bsd/sys/kern_memorystatus.h`).

Processes sit in **priority bands**, from `JETSAM_PRIORITY_IDLE_HEAD` (−2) to
`JETSAM_PRIORITY_INTERNAL` (999), in 211 buckets each holding a queue:

| Band | Meaning |
|---|---|
| 0–15 | idle, with aging |
| 20–30 | background, opportunistic work |
| 80–90 | foreground support |
| 100 | the app the user is looking at |
| 150–190 | system critical — audio, drivers, launchd |
| 999 | so high it is not considered at all |

**Band comes from role, not size.** Size is a tiebreak within a band, not the
criterion. That is the whole difference from Linux, and it is the right way
round: the question is "what can we afford to lose", and size is a poor proxy
for that.

Other pieces worth noting:

- **Idle aging.** Processes drift down through aging bands as they go
  untouched (`AGING_BAND1` = 10, `AGING_BAND2` = 20), so "expendable" is
  earned over time rather than declared once.
- **Per-process limits** with active and inactive values, each independently
  fatal or not. A non-fatal high-water mark does not kill; it makes the
  process an early candidate.
- **Seventeen distinct kill reasons**, including a specific
  `MEMORY_SUSTAINED_PRESSURE` separate from outright exhaustion.
- **Within a band**, selection considers dirty/clean state, footprint,
  coalition membership and LRU order.

## Our design

Three layers, in the order they should be built. Each is useful alone.

### Layer 1 — a band on the process, read by the existing killer

One small integer on `struct proc`. `vm_pageout_oom()` picks the lowest band
first and falls back to largest-RSS within a band, which is exactly its
present behaviour restricted to a subset.

This is deliberately tiny. No new subsystem, no walk, no allocation, no lock —
the page daemon reads an integer. The lesson from the coalition attempt is
that **anything richer than an integer read does not belong in that path**:
that work put six blocking acquisitions and an `M_WAITOK` into the page
daemon, where a wait is a wait on oneself.

Who sets the band is a separate question with an obvious answer: switchboard,
from the manifest, the same way it already derives a management class. A
process with no band set keeps today's behaviour.

### Layer 2 — pressure reporting, so something can act earlier

PSI is the better idea here and it is not Darwin's. Report `some` and `full`
memory stall, expose a threshold-and-poll interface, and let a supervisor shed
load before the killer is needed. `full` in particular is a far better signal
than free-page counts.

This is independent of layer 1 and arguably more valuable: a kill avoided
beats a kill well chosen.

### Layer 3 — idle aging, if the appliance workload wants it

Darwin's aging is what makes bands honest over time. Whether an appliance
needs it depends on whether its workloads are long-lived and static — in which
case a declared band is enough and aging is complexity for nothing.

## What we should not do

**Do not put group semantics in the page daemon.** The argument for killing a
whole unit rather than one process is real — a decapitated remainder helps
nobody. But it was tried and it is where every defect came from: group walks
need locks, locks in the page daemon deadlock against the page daemon.

If group semantics are wanted, the shape that works is to keep the page
daemon's input a plain integer and let *something else* maintain it. A group
identity is an integer; a group *walk* is not.

**Do not derive the band from size.** That is Linux's model and it is the
thing we are trying to improve on.

## Questions to settle

1. **Bands or scores?** I would take bands. Size is a poor proxy for value,
   and an appliance operator knows what is expendable.
2. **How many bands, and who defines them?** Darwin has 211 buckets, which is
   far more resolution than an appliance needs. Five or six named levels
   mapping to management class would probably do.
3. **Is PSI worth porting, or is a simpler "we are thrashing" signal enough?**
   PSI's `some`/`full` distinction is the valuable part; the three averaging
   windows may be more than we need.
4. **Non-fatal high-water marks?** Darwin's "not a limit, a candidacy hint"
   is a genuinely good idea and cheaper than enforcement.
5. **Does the killer need a reason vocabulary?** Darwin has seventeen. An
   operator debugging an appliance needs to know whether something died of
   sustained pressure or of outright exhaustion.

## Sources

- [PSI — Linux kernel documentation](https://docs.kernel.org/accounting/psi.html)
- [Memory management concepts — Linux kernel documentation](https://docs.kernel.org/admin-guide/mm/concepts.html)
- XNU `bsd/sys/kern_memorystatus.h`, via
  [apple-oss-distributions/xnu](https://github.com/apple-oss-distributions/xnu)
