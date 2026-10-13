/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and context restrictions: tools/test/system-tracing/COVERAGE-FIFTH.
 * Elapsed microseconds include preemption/blocking, not CPU execution time.
 * Pointer arguments are identities only. Pairing uses per-thread nesting.
 * Start before the workload; dropped events invalidate pairing.
 * PID filters refer to the executing thread's process: IRQ work usually runs
 * in kernel threads, not in the application that initiated the workload.
 */

ahci:::reset-start
/* @bsdinstruments-predicate */
{
    ahci_reset_depth[tid]++;
    ahci_reset_start[tid, ahci_reset_depth[tid]] = timestamp;
}

ahci:::reset-done
/ahci_reset_start[tid, ahci_reset_depth[tid]] != 0/
{
    @ahci_reset_us[(int)arg1] = quantize((timestamp - ahci_reset_start[tid, ahci_reset_depth[tid]]) / 1000);
    ahci_reset_start[tid, ahci_reset_depth[tid]] = 0;
    ahci_reset_depth[tid]--;
}
