/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-FOURTH.
 * Durations are elapsed microseconds, including blocking and callbacks.
 * Identities are never dereferenced. Start tracing before the workload.
 * Missing completions (termination, cancellation or nonlocal exits) are not
 * success. Per-thread depth handles synchronous nesting; lost events can
 * invalidate pairing. User providers require MK_DTRACE=yes.
 */

kqueue:::scan-start
/* @bsdinstruments-predicate */
{
    kqueue_scan_depth[pid, tid]++;
    kqueue_scan_start[pid, tid, kqueue_scan_depth[pid, tid]] = timestamp;
}

kqueue:::scan-done
/kqueue_scan_start[pid, tid, kqueue_scan_depth[pid, tid]] != 0/
{
    @kqueue_scan_us[(int)arg2] = quantize((timestamp - kqueue_scan_start[pid, tid, kqueue_scan_depth[pid, tid]]) / 1000);
    kqueue_scan_start[pid, tid, kqueue_scan_depth[pid, tid]] = 0;
    kqueue_scan_depth[pid, tid]--;
}

kqueue:::wait-start
/* @bsdinstruments-predicate */
{
    kqueue_wait_depth[pid, tid]++;
    kqueue_wait_start[pid, tid, kqueue_wait_depth[pid, tid]] = timestamp;
}

kqueue:::wait-done
/kqueue_wait_start[pid, tid, kqueue_wait_depth[pid, tid]] != 0/
{
    @kqueue_wait_us[(int)arg1] = quantize((timestamp - kqueue_wait_start[pid, tid, kqueue_wait_depth[pid, tid]]) / 1000);
    kqueue_wait_start[pid, tid, kqueue_wait_depth[pid, tid]] = 0;
    kqueue_wait_depth[pid, tid]--;
}

kqueue:::copyout-start
/* @bsdinstruments-predicate */
{
    kqueue_copyout_depth[pid, tid]++;
    kqueue_copyout_start[pid, tid, kqueue_copyout_depth[pid, tid]] = timestamp;
}

kqueue:::copyout-done
/kqueue_copyout_start[pid, tid, kqueue_copyout_depth[pid, tid]] != 0/
{
    @kqueue_copyout_us[(int)arg2] = quantize((timestamp - kqueue_copyout_start[pid, tid, kqueue_copyout_depth[pid, tid]]) / 1000);
    kqueue_copyout_start[pid, tid, kqueue_copyout_depth[pid, tid]] = 0;
    kqueue_copyout_depth[pid, tid]--;
}
