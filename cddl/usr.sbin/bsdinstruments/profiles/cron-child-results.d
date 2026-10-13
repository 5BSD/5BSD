/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts/context: tools/test/system-tracing/COVERAGE-SIXTH.
 * Elapsed microseconds include blocking and preemption. Pointers are opaque.
 * Start before the workload. Drops or nonlocal exits invalidate pairing.
 * Per-thread depth handles synchronous nesting. PID filters select the
 * executing process, not the application responsible for kernel work.
 * Cron child-wait is reap-wait latency, not complete job execution time.
 */

cron*:::child-wait-start
/* @bsdinstruments-predicate */
{
    cron_child_wait_depth[pid, tid]++;
    cron_child_wait_start[pid, tid, cron_child_wait_depth[pid, tid]] = timestamp;
}

cron*:::child-wait-done
/cron_child_wait_start[pid, tid, cron_child_wait_depth[pid, tid]] != 0/
{
    @cron_child_wait_us[(int)arg3] = quantize((timestamp - cron_child_wait_start[pid, tid, cron_child_wait_depth[pid, tid]]) / 1000);
    @cron_child_status[(int)arg2, (int)arg3] = count();
    cron_child_wait_start[pid, tid, cron_child_wait_depth[pid, tid]] = 0;
    cron_child_wait_depth[pid, tid]--;
}

cron*:::job-launch
/* @bsdinstruments-predicate */
{
    @cron_job_launch[(uint32_t)arg1, (int)arg2] = count();
}

cron*:::job-exec-error
/* @bsdinstruments-predicate */
{
    @cron_job_exec_error[(int)arg0] = count();
}
