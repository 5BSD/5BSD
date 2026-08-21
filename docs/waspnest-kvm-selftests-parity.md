# WaspNest KVM-selftests parity audit

Date: 2026-08-20

This audit compares the 5BSD/bhyve VMM tests with Linux KVM selftests at
commit `818bebeb63dd6bf5f4e07e145f6cdbace520a34c`.  The upstream inventories
are:

- <https://github.com/torvalds/linux/tree/818bebeb63dd6bf5f4e07e145f6cdbace520a34c/tools/testing/selftests/kvm>
- <https://github.com/torvalds/linux/tree/818bebeb63dd6bf5f4e07e145f6cdbace520a34c/tools/testing/selftests/kvm/x86>

The authoritative machine-readable comparison is
`tests/sys/vmm/kvm-parity-requirements.tsv`.  Its validator checks the pinned
upstream identity, disposition vocabulary, referenced evidence, Kyua
registration, and the concrete multi-VM concurrency test.  Its self-test
proves that duplicate rows, invented completion states, and missing evidence
are rejected.

## What the comparison changes

KVM's strongest pattern is a small userspace harness that directly drives the
kernel virtualization API.  Full operating-system boots and device tests do
not replace that layer.  WaspNest therefore treats these as separate gates:

1. kernel VMM API tests under Kyua;
2. sanitizer-backed state and device models;
3. guest-visible Linux and 5BSD functional tests;
4. checkpoint, migration, mutation, and fault campaigns;
5. concurrency and bounded stress with more than one VM.

The first added parity test creates four VMs, enters four vCPUs concurrently,
checks distinct memory/register/I/O-exit state, destroys one VM, and reruns
the surviving VMs.  It also repeats create/open/destroy with the same name 32
times and requires duplicate creation to fail with `EEXIST`.

The second loop follows the kvm-unit-tests guest-perspective pattern.  A bare
real-mode payload executes CPUID leaf zero inside the vCPU and the test compares
all four resulting registers with the kernel's `VM_GET_CPUID` contract.  The
same case family requires unknown query flags and null output pointers to fail
without mutating caller outputs.  This is intentionally partial CPUID coverage:
leaf allowlists, topology, state-dependent leaves, and vCPU-ID limits remain
open rows.

The third loop adds a runner rather than another one-shot case.  The bounded
stress runner discovers the packaged ATF inventory, runs every parity case in
an isolated directory for a configurable number of iterations, admits several
cases concurrently, checks the ATF result stream rather than process status
alone, and retains the first failure's artifacts.  A rootless fake ATF program
proves discovery, exact case counts, per-case isolation, injected failure, and
configuration rejection.  The real root/VMM runner is part of the WaspNest
host gate with three iterations by default.

## Truthful boundary

`covered` means a directly applicable test exists.  `partial` means relevant
evidence exists but does not cover the complete KVM-derived behavior.  `gap`
is required future work.  `not-applicable` is reserved for Linux KVM public
interfaces that bhyve does not expose, such as KVM's Hyper-V, Xen, SEV, and
guest-memfd ioctls.  An absent bhyve test for a native CPU, memory, interrupt,
or lifecycle behavior is a gap, not an exclusion.

This is a moving comparison.  Each coverage loop must pin the external corpus,
add or refine rows, implement at least one applicable missing behavior, run
the validator's falsification suite, and leave live-only claims pending until
the required host and guest evidence is captured.
