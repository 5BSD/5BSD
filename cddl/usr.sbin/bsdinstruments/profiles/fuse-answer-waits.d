/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and context restrictions: tools/test/system-tracing/COVERAGE-FIFTH.
 * Elapsed microseconds include preemption/blocking, not CPU execution time.
 * Pointer arguments are identities only. Pairing uses per-thread nesting.
 * Start before the workload; dropped events invalidate pairing.
 * PID filters refer to the executing thread's process: IRQ work usually runs
 * in kernel threads, not in the application that initiated the workload.
 */

fusefs:::answer-wait-start
/* @bsdinstruments-predicate */
{
    fusefs_answer__wait_depth[tid]++;
    fusefs_answer__wait_start[tid, fusefs_answer__wait_depth[tid]] = timestamp;
}

fusefs:::answer-wait-done
/fusefs_answer__wait_start[tid, fusefs_answer__wait_depth[tid]] != 0/
{
    @fusefs_answer__wait_us[(int)arg1] = quantize((timestamp - fusefs_answer__wait_start[tid, fusefs_answer__wait_depth[tid]]) / 1000);
    fusefs_answer__wait_start[tid, fusefs_answer__wait_depth[tid]] = 0;
    fusefs_answer__wait_depth[tid]--;
}
