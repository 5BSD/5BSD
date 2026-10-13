/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and context restrictions: tools/test/system-tracing/COVERAGE-FIFTH.
 * Elapsed microseconds include preemption/blocking, not CPU execution time.
 * Pointer arguments are identities only. Pairing uses per-thread nesting.
 * Start before the workload; dropped events invalidate pairing.
 * PID filters refer to the executing thread's process: IRQ work usually runs
 * in kernel threads, not in the application that initiated the workload.
 */

affinity:::set-start
/* @bsdinstruments-predicate */
{
    affinity_set_depth[tid]++;
    affinity_set_start[tid, affinity_set_depth[tid]] = timestamp;
}

affinity:::set-done
/affinity_set_start[tid, affinity_set_depth[tid]] != 0/
{
    @affinity_set_us[(int)arg3] = quantize((timestamp - affinity_set_start[tid, affinity_set_depth[tid]]) / 1000);
    affinity_set_start[tid, affinity_set_depth[tid]] = 0;
    affinity_set_depth[tid]--;
}
