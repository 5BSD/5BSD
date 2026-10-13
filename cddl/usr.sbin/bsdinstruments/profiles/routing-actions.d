/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and context restrictions: tools/test/system-tracing/COVERAGE-FIFTH.
 * Elapsed microseconds include preemption/blocking, not CPU execution time.
 * Pointer arguments are identities only. Pairing uses per-thread nesting.
 * Start before the workload; dropped events invalidate pairing.
 * PID filters refer to the executing thread's process: IRQ work usually runs
 * in kernel threads, not in the application that initiated the workload.
 */

routing:::action-start
/* @bsdinstruments-predicate */
{
    routing_action_depth[tid]++;
    routing_action_start[tid, routing_action_depth[tid]] = timestamp;
}

routing:::action-done
/routing_action_start[tid, routing_action_depth[tid]] != 0/
{
    @routing_action_us[(int)arg2] = quantize((timestamp - routing_action_start[tid, routing_action_depth[tid]]) / 1000);
    routing_action_start[tid, routing_action_depth[tid]] = 0;
    routing_action_depth[tid]--;
}
