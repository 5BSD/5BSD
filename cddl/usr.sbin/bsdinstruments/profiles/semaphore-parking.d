/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-FOURTH.
 * Durations are elapsed microseconds, including blocking and callbacks.
 * Identities are never dereferenced. Start tracing before the workload.
 * Missing completions (termination, cancellation or nonlocal exits) are not
 * success. Per-thread depth handles synchronous nesting; lost events can
 * invalidate pairing. User providers require MK_DTRACE=yes.
 */

semwait*:::park-start
/* @bsdinstruments-predicate */
{
    semaphore_park_depth[pid, tid]++;
    semaphore_park_start[pid, tid, semaphore_park_depth[pid, tid]] = timestamp;
}

semwait*:::park-done
/semaphore_park_start[pid, tid, semaphore_park_depth[pid, tid]] != 0/
{
    @semaphore_park_us[(int)arg2] = quantize((timestamp - semaphore_park_start[pid, tid, semaphore_park_depth[pid, tid]]) / 1000);
    semaphore_park_start[pid, tid, semaphore_park_depth[pid, tid]] = 0;
    semaphore_park_depth[pid, tid]--;
}

semwait*:::wake-start
/* @bsdinstruments-predicate */
{
    semaphore_wake_depth[pid, tid]++;
    semaphore_wake_start[pid, tid, semaphore_wake_depth[pid, tid]] = timestamp;
}

semwait*:::wake-done
/semaphore_wake_start[pid, tid, semaphore_wake_depth[pid, tid]] != 0/
{
    @semaphore_wake_us[(int)arg2] = quantize((timestamp - semaphore_wake_start[pid, tid, semaphore_wake_depth[pid, tid]]) / 1000);
    semaphore_wake_start[pid, tid, semaphore_wake_depth[pid, tid]] = 0;
    semaphore_wake_depth[pid, tid]--;
}
