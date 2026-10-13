/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts/context: tools/test/system-tracing/COVERAGE-SIXTH.
 * Elapsed microseconds include blocking and preemption. Pointers are opaque.
 * Start before the workload. Drops or nonlocal exits invalidate pairing.
 * Per-thread depth handles synchronous nesting. PID filters select the
 * executing process, not the application responsible for kernel work.
 * Cron child-wait is reap-wait latency, not complete job execution time.
 */

ufsquota:::sync-start
/* @bsdinstruments-predicate */
{
    ufsquota_sync_depth[pid, tid]++;
    ufsquota_sync_start[pid, tid, ufsquota_sync_depth[pid, tid]] = timestamp;
}

ufsquota:::sync-done
/ufsquota_sync_start[pid, tid, ufsquota_sync_depth[pid, tid]] != 0/
{
    @ufsquota_sync_us[(int)arg1] = quantize((timestamp - ufsquota_sync_start[pid, tid, ufsquota_sync_depth[pid, tid]]) / 1000);
    ufsquota_sync_start[pid, tid, ufsquota_sync_depth[pid, tid]] = 0;
    ufsquota_sync_depth[pid, tid]--;
}

ufsquota:::deny
/* @bsdinstruments-predicate */
{
    @ufsquota_deny[(int)arg1, (int)arg2, (int)arg3] = count();
}

ufsquota:::grace-start
/* @bsdinstruments-predicate */
{
    @ufsquota_grace_start[(int)arg1, (int)arg2] = count();
}
