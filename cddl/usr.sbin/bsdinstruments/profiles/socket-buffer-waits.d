/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts/context: tools/test/system-tracing/COVERAGE-SIXTH.
 * Elapsed microseconds include blocking and preemption. Pointers are opaque.
 * Start before the workload. Drops or nonlocal exits invalidate pairing.
 * Per-thread depth handles synchronous nesting. PID filters select the
 * executing process, not the application responsible for kernel work.
 * Cron child-wait is reap-wait latency, not complete job execution time.
 */

sockbuf:::wait-start
/* @bsdinstruments-predicate */
{
    sockbuf_wait_depth[pid, tid]++;
    sockbuf_wait_start[pid, tid, sockbuf_wait_depth[pid, tid]] = timestamp;
}

sockbuf:::wait-done
/sockbuf_wait_start[pid, tid, sockbuf_wait_depth[pid, tid]] != 0/
{
    @sockbuf_wait_us[(int)arg2] = quantize((timestamp - sockbuf_wait_start[pid, tid, sockbuf_wait_depth[pid, tid]]) / 1000);
    sockbuf_wait_start[pid, tid, sockbuf_wait_depth[pid, tid]] = 0;
    sockbuf_wait_depth[pid, tid]--;
}
