/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and context restrictions: tools/test/system-tracing/COVERAGE-FIFTH.
 * Elapsed microseconds include preemption/blocking, not CPU execution time.
 * Pointer arguments are identities only. Pairing uses per-thread nesting.
 * Start before the workload; dropped events invalidate pairing.
 * PID filters refer to the executing thread's process: IRQ work usually runs
 * in kernel threads, not in the application that initiated the workload.
 */

vtnet:::reinit-start
/* @bsdinstruments-predicate */
{
    vtnet_reinit_depth[tid]++;
    vtnet_reinit_start[tid, vtnet_reinit_depth[tid]] = timestamp;
}

vtnet:::reinit-done
/vtnet_reinit_start[tid, vtnet_reinit_depth[tid]] != 0/
{
    @vtnet_reinit_us[(int)arg1] = quantize((timestamp - vtnet_reinit_start[tid, vtnet_reinit_depth[tid]]) / 1000);
    vtnet_reinit_start[tid, vtnet_reinit_depth[tid]] = 0;
    vtnet_reinit_depth[tid]--;
}
