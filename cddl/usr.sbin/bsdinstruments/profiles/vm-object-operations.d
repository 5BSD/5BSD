/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and context restrictions: tools/test/system-tracing/COVERAGE-FIFTH.
 * Elapsed microseconds include preemption/blocking, not CPU execution time.
 * Pointer arguments are identities only. Pairing uses per-thread nesting.
 * Start before the workload; dropped events invalidate pairing.
 * PID filters refer to the executing thread's process: IRQ work usually runs
 * in kernel threads, not in the application that initiated the workload.
 */

vm:::object-pager-start
/* @bsdinstruments-predicate */
{
    vm_object__pager_depth[tid]++;
    vm_object__pager_start[tid, vm_object__pager_depth[tid]] = timestamp;
}

vm:::object-pager-done
/vm_object__pager_start[tid, vm_object__pager_depth[tid]] != 0/
{
    @vm_object__pager_us[0] = quantize((timestamp - vm_object__pager_start[tid, vm_object__pager_depth[tid]]) / 1000);
    vm_object__pager_start[tid, vm_object__pager_depth[tid]] = 0;
    vm_object__pager_depth[tid]--;
}

vm:::object-collapse
/* @bsdinstruments-predicate */
{
    @vm_object__collapse[0] = count();
}

vm:::object-bypass
/* @bsdinstruments-predicate */
{
    @vm_object__bypass[0] = count();
}
