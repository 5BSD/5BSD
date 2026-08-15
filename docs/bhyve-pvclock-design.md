# bhyve KVM-compatible paravirtual clock (pvclock) design

Status: implemented and model-tested (`tests/sys/vmm/vpvclock_model_test.c`);
opt-in and default-off.  Live guest qualification of the KVM clocksource on a
rebuilt host is pending.  Nothing here changes the default guest-visible
hypervisor identity unless an operator opts in.

Normative reference: the de-facto KVM paravirtual-clock ABI — the
`struct pvclock_vcpu_time_info` seqlock page, the mul/shift scaling, the
wall-clock structure, the KVM CPUID leaves, and the KVM MSRs — as described in
`<machine/pvclock.h>` and `<x86/kvm.h>`.  The math and protocol are implemented
from that ABI; no GPL source is copied or mechanically translated.

Primary sources: `sys/amd64/vmm/io/vpvclock.c` / `vpvclock.h`, consumed by
`sys/amd64/vmm/vmm.c` and the Intel/AMD MSR paths.  Guest consumers are the
in-tree FreeBSD `kvm_clock` driver (`sys/dev/kvm_clock`) and Linux `kvm-clock`.

## 1. Purpose

Give the guest an accurate, migration-aware time base by exposing the standard
KVM paravirtual clock.  A TSC-only guest must either trust an invariant TSC or
run a monotonicity backstop; the pvclock lets the host publish the exact
TSC-to-nanosecond scaling and re-publish it after a migration/restore so the
guest clock stays correct across a host change.

## 2. Opt-in default and the KVM-primary-identity tradeoff

The interface is gated by `hw.vmm.pvclock.enabled` (`CTLFLAG_RDTUN`,
default `0`) and `vpvclock_capable()` additionally requires a nonzero
`tsc_freq`.  The default-off choice is deliberate because **enabling it changes
the guest-visible hypervisor identity**:

- **Default (off):** the guest sees exactly what historical bhyve presented —
  the bhyve signature at CPUID leaf `0x40000000`, no KVM leaves, and `#GP` on
  the KVM MSRs.
- **Enabled:** the KVM signature takes the primary hypervisor leaf
  `0x40000000`, bhyve's own signature block moves to the secondary block at
  `0x40000100`, and the guest reports `vm_guest == VM_GUEST_KVM`.  Even then the
  clock stays inert until a guest writes the enable MSR.

The tradeoff: KVM-compatibility requires ceding the primary hypervisor leaf to
the KVM identity, which some guests key behavior on.  Rather than silently
change what every guest detects, the feature is opt-in; operators that want the
KVM clocksource accept the KVM-primary identity by setting the tunable.

## 3. CPUID interface

Two fixed leaves (`vpvclock.h`), which the FreeBSD `kvm_clock` guest driver
hard-codes and which therefore must not move:

- `VPVCLOCK_CPUID_KVM_BASE` = `0x40000000` — the KVM signature leaf; and
- `VPVCLOCK_CPUID_KVM_FEATURES` = `0x40000001` — the feature leaf.

`vpvclock_kvm_features()` advertises `CLOCKSOURCE` (`0x1`), `CLOCKSOURCE2`
(`0x8`), and `MSI_EXT_DEST_ID` (`0x8000`).  It adds
`CLOCKSOURCE_STABLE_BIT` (`0x0100_0000`) **only** when `tsc_is_invariant &&
smp_tsc`, matching the invariant-TSC policy used for CPUID `8000_0007` in
`x86.c`.  When the stable bit is set, the guest may skip its monotonicity
backstop.

## 4. MSRs

Two register pairs (`vpvclock_wrmsr` / `vpvclock_rdmsr`):

| MSR | Address | Feature | Role |
| --- | --- | --- | --- |
| `WALL_CLOCK` | `0x11` | `CLOCKSOURCE` (legacy) | Per-VM wall-clock structure GPA |
| `SYSTEM_TIME` | `0x12` | `CLOCKSOURCE` (legacy) | Per-vCPU time-info page GPA + enable |
| `WALL_CLOCK_NEW` | `0x4b56_4d00` | `CLOCKSOURCE2` | Wall-clock GPA (current drivers) |
| `SYSTEM_TIME_NEW` | `0x4b56_4d01` | `CLOCKSOURCE2` | Time-info page GPA + enable (current drivers) |

The low bit of a `SYSTEM_TIME` write is the enable bit; it is stripped to
recover the page-info GPA.  A fresh `SYSTEM_TIME` registration restarts the
version sequence (`vv->version = 0`).  The legacy `0x11`/`0x12` aliases are
handled for completeness alongside the `NEW` pair.

## 5. Per-vCPU seqlock page

Each vCPU owns a `struct pvclock_vcpu_time_info` in guest RAM.  Updates use the
KVM version seqlock discipline: the `version` field is made **odd** before the
payload is written and **even** once the write completes, so a concurrent guest
reader detects a torn read (odd version, or a version change across the read)
and retries.  The page is written in place so the odd/even transition is
visible in guest RAM.  Guest-object mapping (`vpvclock_map_guest`) honours the
memseg lock so it is safe both during exit emulation (vCPU frozen) and during a
migration-restore ioctl (vCPUs idle); it rejects an object that would span a
page boundary or a GPA not backed by RAM, so a misbehaving guest cannot crash
the host.

## 6. Scaling: mul/shift

`vpvclock_freq_to_scale(freq, &mul, &shift)` derives the `(tsc_to_system_mul,
tsc_shift)` pair for a virtual TSC of `freq` Hz.  The guest computes
nanoseconds from a TSC delta as

```
ns = pvclock_scale_delta(delta, mul, shift)
   = ((shift >= 0 ? delta << shift : delta >> -shift) * mul) >> 32
```

which must approximate `delta * 10^9 / freq`.  The helper solves for a 32-bit
`mul` whose top bit is set (maximal precision) and an `int8_t` shift by keeping
reduced numerator (`10^9`) and denominator (`freq`) copies, halving whichever
term would overflow a 32-bit intermediate and accumulating the net power of two
into `shift`.  This is the standard fixed-point reciprocal every pvclock host
uses; it is deliberately free of kernel dependencies so the model test
exercises exactly the code the host runs.

The guest-visible TSC is `guest_tsc = rdtsc() + vm_get_tsc_offset(vcpu)`.
Because the per-vCPU TSC offset is restored to preserve continuity across
pause/migrate, any value derived from `guest_tsc` is monotonic by construction.

## 7. Wall clock

`WALL_CLOCK`/`WALL_CLOCK_NEW` register a per-VM wall-clock structure whose GPA
is published with the same odd/even seqlock (version `1` odd during the write,
`2` even when complete).  It provides the boot-time epoch the guest adds to the
system-time nanoseconds to get wall-clock time.

## 8. Migration/restore republish

`vpvclock_vcpu_update(vcpu)` republishes the time-info page for a vCPU.  It is
called both during normal exit emulation and after a migration/restore, so a
guest that had the clock enabled before migration sees a freshly published,
correctly scaled page on the destination without re-registering.  Because
`guest_tsc` folds in the restored per-vCPU TSC offset, the destination
republish preserves monotonicity: the scaling (`mul`/`shift`) is recomputed
from the destination virtual TSC frequency and the time-info version is bumped
under the seqlock, so a guest reader transparently picks up the new base.  The
wall clock is likewise re-derived on the destination.

State that must survive save/restore is the per-vCPU registration
(`system_time_enabled`, the raw MSR value, the stripped page GPA, and the last
published version) plus the per-VM wall-clock enable/GPA; the scaling pair and
stable flag are recomputed from the (possibly new) host TSC on restore rather
than serialized.

## 9. Public API

| Symbol | Role |
| --- | --- |
| `vpvclock_init(vm)` / `vpvclock_cleanup(pvc)` | Per-VM allocate (flexible per-vCPU array) and free |
| `vpvclock_capable()` | Enabled tunable and nonzero `tsc_freq` |
| `vpvclock_kvm_features()` | The advertised KVM feature bitmask |
| `vpvclock_wrmsr` / `vpvclock_rdmsr` | Service the four KVM clock MSRs |
| `vpvclock_vcpu_update(vcpu)` | (Re)publish a vCPU time-info page |

## 10. Residuals (not yet qualified)

- Live qualification of the FreeBSD `kvm_clock` and Linux `kvm-clock`
  guest drivers binding to this interface on a rebuilt host;
- correctness of the destination republish across a real migration (§8 of
  `docs/bhyve-migration-design.md`); and
- guest-visible-identity regression testing for guests that key on the primary
  hypervisor leaf, to confirm the default-off boundary is honoured.
