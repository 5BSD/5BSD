/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and context restrictions: tools/test/system-tracing/COVERAGE-FIFTH.
 * Elapsed microseconds include preemption/blocking, not CPU execution time.
 * Pointer arguments are identities only. Pairing uses per-thread nesting.
 * Start before the workload; dropped events invalidate pairing.
 * PID filters refer to the executing thread's process: IRQ work usually runs
 * in kernel threads, not in the application that initiated the workload.
 */

ipsec:::output-start
/* @bsdinstruments-predicate */
{
    ipsec_output_depth[tid]++;
    ipsec_output_start[tid, ipsec_output_depth[tid]] = timestamp;
}

ipsec:::output-done
/ipsec_output_start[tid, ipsec_output_depth[tid]] != 0/
{
    @ipsec_output_us[(int)arg1] = quantize((timestamp - ipsec_output_start[tid, ipsec_output_depth[tid]]) / 1000);
    ipsec_output_start[tid, ipsec_output_depth[tid]] = 0;
    ipsec_output_depth[tid]--;
}
