/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and context restrictions: tools/test/system-tracing/COVERAGE-FIFTH.
 * Elapsed microseconds include preemption/blocking, not CPU execution time.
 * Pointer arguments are identities only. Pairing uses per-thread nesting.
 * Start before the workload; dropped events invalidate pairing.
 * PID filters refer to the executing thread's process: IRQ work usually runs
 * in kernel threads, not in the application that initiated the workload.
 */

geom:::access-start
/* @bsdinstruments-predicate */
{
    geom_access_depth[tid]++;
    geom_access_start[tid, geom_access_depth[tid]] = timestamp;
}

geom:::access-done
/geom_access_start[tid, geom_access_depth[tid]] != 0/
{
    @geom_access_us[(int)arg1] = quantize((timestamp - geom_access_start[tid, geom_access_depth[tid]]) / 1000);
    geom_access_start[tid, geom_access_depth[tid]] = 0;
    geom_access_depth[tid]--;
}
