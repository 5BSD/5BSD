/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and context restrictions: tools/test/system-tracing/COVERAGE-FIFTH.
 * Elapsed microseconds include preemption/blocking, not CPU execution time.
 * Pointer arguments are identities only. Pairing uses per-thread nesting.
 * Start before the workload; dropped events invalidate pairing.
 * PID filters refer to the executing thread's process: IRQ work usually runs
 * in kernel threads, not in the application that initiated the workload.
 */

irq:::thread-start
/* @bsdinstruments-predicate */
{
    irq_thread_depth[tid]++;
    irq_thread_start[tid, irq_thread_depth[tid]] = timestamp;
}

irq:::thread-done
/irq_thread_start[tid, irq_thread_depth[tid]] != 0/
{
    @irq_thread_us[(uintptr_t)arg1] = quantize((timestamp - irq_thread_start[tid, irq_thread_depth[tid]]) / 1000);
    irq_thread_start[tid, irq_thread_depth[tid]] = 0;
    irq_thread_depth[tid]--;
}
