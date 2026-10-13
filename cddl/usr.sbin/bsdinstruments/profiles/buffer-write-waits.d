/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts/context: tools/test/system-tracing/COVERAGE-SIXTH.
 * Elapsed microseconds include blocking and preemption. Pointers are opaque.
 * Start before the workload. Drops or nonlocal exits invalidate pairing.
 * Per-thread depth handles synchronous nesting. PID filters select the
 * executing process, not the application responsible for kernel work.
 * Cron child-wait is reap-wait latency, not complete job execution time.
 */

bufcache:::writes-wait-start
/* @bsdinstruments-predicate */
{
    bufcache_writes_wait_depth[pid, tid]++;
    bufcache_writes_wait_start[pid, tid, bufcache_writes_wait_depth[pid, tid]] = timestamp;
}

bufcache:::writes-wait-done
/bufcache_writes_wait_start[pid, tid, bufcache_writes_wait_depth[pid, tid]] != 0/
{
    @bufcache_writes_wait_us[(int)arg1] = quantize((timestamp - bufcache_writes_wait_start[pid, tid, bufcache_writes_wait_depth[pid, tid]]) / 1000);
    bufcache_writes_wait_start[pid, tid, bufcache_writes_wait_depth[pid, tid]] = 0;
    bufcache_writes_wait_depth[pid, tid]--;
}
