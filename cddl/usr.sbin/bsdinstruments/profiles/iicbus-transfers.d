/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts/context: tools/test/system-tracing/COVERAGE-SIXTH.
 * Elapsed microseconds include blocking and preemption. Pointers are opaque.
 * Start before the workload. Drops or nonlocal exits invalidate pairing.
 * Per-thread depth handles synchronous nesting. PID filters select the
 * executing process, not the application responsible for kernel work.
 * Cron child-wait is reap-wait latency, not complete job execution time.
 */

iicbus:::acquire-start
/* @bsdinstruments-predicate */
{
    iicbus_acquire_depth[pid, tid]++;
    iicbus_acquire_start[pid, tid, iicbus_acquire_depth[pid, tid]] = timestamp;
}

iicbus:::acquire-done
/iicbus_acquire_start[pid, tid, iicbus_acquire_depth[pid, tid]] != 0/
{
    @iicbus_acquire_us[(int)arg2] = quantize((timestamp - iicbus_acquire_start[pid, tid, iicbus_acquire_depth[pid, tid]]) / 1000);
    iicbus_acquire_start[pid, tid, iicbus_acquire_depth[pid, tid]] = 0;
    iicbus_acquire_depth[pid, tid]--;
}

iicbus:::transfer-start
/* @bsdinstruments-predicate */
{
    iicbus_transfer_depth[pid, tid]++;
    iicbus_transfer_start[pid, tid, iicbus_transfer_depth[pid, tid]] = timestamp;
}

iicbus:::transfer-done
/iicbus_transfer_start[pid, tid, iicbus_transfer_depth[pid, tid]] != 0/
{
    @iicbus_transfer_us[(int)arg1] = quantize((timestamp - iicbus_transfer_start[pid, tid, iicbus_transfer_depth[pid, tid]]) / 1000);
    iicbus_transfer_start[pid, tid, iicbus_transfer_depth[pid, tid]] = 0;
    iicbus_transfer_depth[pid, tid]--;
}
