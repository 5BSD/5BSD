/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts/context: tools/test/system-tracing/COVERAGE-SIXTH.
 * Elapsed microseconds include blocking and preemption. Pointers are opaque.
 * Start before the workload. Drops or nonlocal exits invalidate pairing.
 * Per-thread depth handles synchronous nesting. PID filters select the
 * executing process, not the application responsible for kernel work.
 * Cron child-wait is reap-wait latency, not complete job execution time.
 */

moveio*:::rename-start
/* @bsdinstruments-predicate */
{
    moveio_rename_depth[pid, tid]++;
    moveio_rename_start[pid, tid, moveio_rename_depth[pid, tid]] = timestamp;
}

moveio*:::rename-done
/moveio_rename_start[pid, tid, moveio_rename_depth[pid, tid]] != 0/
{
    @moveio_rename_us[(int)arg1] = quantize((timestamp - moveio_rename_start[pid, tid, moveio_rename_depth[pid, tid]]) / 1000);
    moveio_rename_start[pid, tid, moveio_rename_depth[pid, tid]] = 0;
    moveio_rename_depth[pid, tid]--;
}

moveio*:::fallback-start
/* @bsdinstruments-predicate */
{
    moveio_fallback_depth[pid, tid]++;
    moveio_fallback_start[pid, tid, moveio_fallback_depth[pid, tid]] = timestamp;
}

moveio*:::fallback-done
/moveio_fallback_start[pid, tid, moveio_fallback_depth[pid, tid]] != 0/
{
    @moveio_fallback_us[(int)arg0] = quantize((timestamp - moveio_fallback_start[pid, tid, moveio_fallback_depth[pid, tid]]) / 1000);
    moveio_fallback_start[pid, tid, moveio_fallback_depth[pid, tid]] = 0;
    moveio_fallback_depth[pid, tid]--;
}
