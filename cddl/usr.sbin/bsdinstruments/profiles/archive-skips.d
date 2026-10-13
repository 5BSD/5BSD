/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-FOURTH.
 * Durations are elapsed microseconds, including blocking and callbacks.
 * Identities are never dereferenced. Start tracing before the workload.
 * Missing completions (termination, cancellation or nonlocal exits) are not
 * success. Per-thread depth handles synchronous nesting; lost events can
 * invalidate pairing. User providers require MK_DTRACE=yes.
 */

archiveio*:::skip-start
/* @bsdinstruments-predicate */
{
    archive_skip_depth[pid, tid]++;
    archive_skip_start[pid, tid, archive_skip_depth[pid, tid]] = timestamp;
}

archiveio*:::skip-done
/archive_skip_start[pid, tid, archive_skip_depth[pid, tid]] != 0/
{
    @archive_skip_us[(int)arg1] = quantize((timestamp - archive_skip_start[pid, tid, archive_skip_depth[pid, tid]]) / 1000);
    archive_skip_start[pid, tid, archive_skip_depth[pid, tid]] = 0;
    archive_skip_depth[pid, tid]--;
}
