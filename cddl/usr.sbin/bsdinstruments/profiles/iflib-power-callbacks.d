/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and context restrictions: tools/test/system-tracing/COVERAGE-FIFTH.
 * Elapsed microseconds include preemption/blocking, not CPU execution time.
 * Pointer arguments are identities only. Pairing uses per-thread nesting.
 * Start before the workload; dropped events invalidate pairing.
 * PID filters refer to the executing thread's process: IRQ work usually runs
 * in kernel threads, not in the application that initiated the workload.
 */

iflib:::suspend-start
/* @bsdinstruments-predicate */
{
    iflib_suspend_depth[tid]++;
    iflib_suspend_start[tid, iflib_suspend_depth[tid]] = timestamp;
}

iflib:::suspend-done
/iflib_suspend_start[tid, iflib_suspend_depth[tid]] != 0/
{
    @iflib_suspend_us[(int)arg1] = quantize((timestamp - iflib_suspend_start[tid, iflib_suspend_depth[tid]]) / 1000);
    iflib_suspend_start[tid, iflib_suspend_depth[tid]] = 0;
    iflib_suspend_depth[tid]--;
}

iflib:::resume-start
/* @bsdinstruments-predicate */
{
    iflib_resume_depth[tid]++;
    iflib_resume_start[tid, iflib_resume_depth[tid]] = timestamp;
}

iflib:::resume-done
/iflib_resume_start[tid, iflib_resume_depth[tid]] != 0/
{
    @iflib_resume_us[(int)arg1] = quantize((timestamp - iflib_resume_start[tid, iflib_resume_depth[tid]]) / 1000);
    iflib_resume_start[tid, iflib_resume_depth[tid]] = 0;
    iflib_resume_depth[tid]--;
}
