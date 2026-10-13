/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-SEVENTH.
 * Pointers are opaque. Elapsed time includes blocking and preemption.
 * Start before the workload; drops or nonlocal exits invalidate pairing.
 * PID filters select executing context, not the initiating workload.
 */

ntsync:::wait-start
/* @bsdinstruments-predicate */
{
    ntsync_wait_depth[pid, tid]++;
    ntsync_wait_start[pid, tid, ntsync_wait_depth[pid, tid]] = timestamp;
}

ntsync:::wait-done
/ntsync_wait_start[pid, tid, ntsync_wait_depth[pid, tid]] != 0/
{
    @ntsync_wait_us[(int)arg1, (int)arg2] = quantize((timestamp - ntsync_wait_start[pid, tid, ntsync_wait_depth[pid, tid]]) / 1000);
    ntsync_wait_start[pid, tid, ntsync_wait_depth[pid, tid]] = 0;
    ntsync_wait_depth[pid, tid]--;
}

inotify:::wait-start
/* @bsdinstruments-predicate */
{
    inotify_wait_depth[pid, tid]++;
    inotify_wait_start[pid, tid, inotify_wait_depth[pid, tid]] = timestamp;
}

inotify:::wait-done
/inotify_wait_start[pid, tid, inotify_wait_depth[pid, tid]] != 0/
{
    @inotify_wait_us[(int)arg1] = quantize((timestamp - inotify_wait_start[pid, tid, inotify_wait_depth[pid, tid]]) / 1000);
    inotify_wait_start[pid, tid, inotify_wait_depth[pid, tid]] = 0;
    inotify_wait_depth[pid, tid]--;
}

ntsync:::create
/* @bsdinstruments-predicate */
{
    @ntsync_create[(int)arg2] = count();
}

inotify:::watch-add
/* @bsdinstruments-predicate */
{
    @watch_add[(int)arg3] = count();
}
