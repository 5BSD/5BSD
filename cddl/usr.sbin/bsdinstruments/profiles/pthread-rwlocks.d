/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-FOURTH.
 * Durations are elapsed microseconds, including blocking and callbacks.
 * Identities are never dereferenced. Start tracing before the workload.
 * Missing completions (termination, cancellation or nonlocal exits) are not
 * success. Per-thread depth handles synchronous nesting; lost events can
 * invalidate pairing. User providers require MK_DTRACE=yes.
 */

threadwait*:::rwlock-start
/* @bsdinstruments-predicate */
{
    rwlock_depth[pid, tid]++;
    rwlock_start[pid, tid, rwlock_depth[pid, tid]] = timestamp;
}

threadwait*:::rwlock-done
/rwlock_start[pid, tid, rwlock_depth[pid, tid]] != 0/
{
    @rwlock_us[(int)arg2] = quantize((timestamp - rwlock_start[pid, tid, rwlock_depth[pid, tid]]) / 1000);
    rwlock_start[pid, tid, rwlock_depth[pid, tid]] = 0;
    rwlock_depth[pid, tid]--;
}
