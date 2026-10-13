/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-FOURTH.
 * Durations are elapsed microseconds, including blocking and callbacks.
 * Identities are never dereferenced. Start tracing before the workload.
 * Missing completions (termination, cancellation or nonlocal exits) are not
 * success. Per-thread depth handles synchronous nesting; lost events can
 * invalidate pairing. User providers require MK_DTRACE=yes.
 */

vfs:::syncer-start
/* @bsdinstruments-predicate */
{
    syncer_depth[pid, tid]++;
    syncer_start[pid, tid, syncer_depth[pid, tid]] = timestamp;
}

vfs:::syncer-done
/syncer_start[pid, tid, syncer_depth[pid, tid]] != 0/
{
    @syncer_us[(int)arg1] = quantize((timestamp - syncer_start[pid, tid, syncer_depth[pid, tid]]) / 1000);
    syncer_start[pid, tid, syncer_depth[pid, tid]] = 0;
    syncer_depth[pid, tid]--;
}
