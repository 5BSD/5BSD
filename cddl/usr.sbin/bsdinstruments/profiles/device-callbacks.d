/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and context restrictions: tools/test/system-tracing/COVERAGE-FIFTH.
 * Elapsed microseconds include preemption/blocking, not CPU execution time.
 * Pointer arguments are identities only. Pairing uses per-thread nesting.
 * Start before the workload; dropped events invalidate pairing.
 * PID filters refer to the executing thread's process: IRQ work usually runs
 * in kernel threads, not in the application that initiated the workload.
 */

newbus:::attach-start
/* @bsdinstruments-predicate */
{
    newbus_attach_depth[tid]++;
    newbus_attach_start[tid, newbus_attach_depth[tid]] = timestamp;
}

newbus:::attach-done
/newbus_attach_start[tid, newbus_attach_depth[tid]] != 0/
{
    @newbus_attach_us[(int)arg1] = quantize((timestamp - newbus_attach_start[tid, newbus_attach_depth[tid]]) / 1000);
    newbus_attach_start[tid, newbus_attach_depth[tid]] = 0;
    newbus_attach_depth[tid]--;
}

newbus:::detach-start
/* @bsdinstruments-predicate */
{
    newbus_detach_depth[tid]++;
    newbus_detach_start[tid, newbus_detach_depth[tid]] = timestamp;
}

newbus:::detach-done
/newbus_detach_start[tid, newbus_detach_depth[tid]] != 0/
{
    @newbus_detach_us[(int)arg1] = quantize((timestamp - newbus_detach_start[tid, newbus_detach_depth[tid]]) / 1000);
    newbus_detach_start[tid, newbus_detach_depth[tid]] = 0;
    newbus_detach_depth[tid]--;
}
