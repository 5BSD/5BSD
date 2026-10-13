/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-FOURTH.
 * Durations are elapsed microseconds, including blocking and callbacks.
 * Identities are never dereferenced. Start tracing before the workload.
 * Missing completions (termination, cancellation or nonlocal exits) are not
 * success. Per-thread depth handles synchronous nesting; lost events can
 * invalidate pairing. User providers require MK_DTRACE=yes.
 */

clock:::timer-set-start
/* @bsdinstruments-predicate */
{
    timer_set_depth[pid, tid]++;
    timer_set_start[pid, tid, timer_set_depth[pid, tid]] = timestamp;
}

clock:::timer-set-done
/timer_set_start[pid, tid, timer_set_depth[pid, tid]] != 0/
{
    @timer_set_us[(int)arg1] = quantize((timestamp - timer_set_start[pid, tid, timer_set_depth[pid, tid]]) / 1000);
    timer_set_start[pid, tid, timer_set_depth[pid, tid]] = 0;
    timer_set_depth[pid, tid]--;
}
