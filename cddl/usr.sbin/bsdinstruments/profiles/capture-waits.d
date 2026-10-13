/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and context restrictions: tools/test/system-tracing/COVERAGE-FIFTH.
 * Elapsed microseconds include preemption/blocking, not CPU execution time.
 * Pointer arguments are identities only. Pairing uses per-thread nesting.
 * Start before the workload; dropped events invalidate pairing.
 * PID filters refer to the executing thread's process: IRQ work usually runs
 * in kernel threads, not in the application that initiated the workload.
 */

bpf:::read-wait-start
/* @bsdinstruments-predicate */
{
    bpf_read__wait_depth[tid]++;
    bpf_read__wait_start[tid, bpf_read__wait_depth[tid]] = timestamp;
}

bpf:::read-wait-done
/bpf_read__wait_start[tid, bpf_read__wait_depth[tid]] != 0/
{
    @bpf_read__wait_us[(int)arg1] = quantize((timestamp - bpf_read__wait_start[tid, bpf_read__wait_depth[tid]]) / 1000);
    bpf_read__wait_start[tid, bpf_read__wait_depth[tid]] = 0;
    bpf_read__wait_depth[tid]--;
}
