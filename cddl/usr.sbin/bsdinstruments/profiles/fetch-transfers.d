/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-FOURTH.
 * Durations are elapsed microseconds, including blocking and callbacks.
 * Identities are never dereferenced. Start tracing before the workload.
 * Missing completions (termination, cancellation or nonlocal exits) are not
 * success. Per-thread depth handles synchronous nesting; lost events can
 * invalidate pairing. User providers require MK_DTRACE=yes.
 */

fetchio*:::read-start
/* @bsdinstruments-predicate */
{
    fetch_read_depth[pid, tid]++;
    fetch_read_start[pid, tid, fetch_read_depth[pid, tid]] = timestamp;
}

fetchio*:::read-done
/fetch_read_start[pid, tid, fetch_read_depth[pid, tid]] != 0/
{
    @fetch_read_us[(int)arg2] = quantize((timestamp - fetch_read_start[pid, tid, fetch_read_depth[pid, tid]]) / 1000);
    fetch_read_start[pid, tid, fetch_read_depth[pid, tid]] = 0;
    fetch_read_depth[pid, tid]--;
}

fetchio*:::write-start
/* @bsdinstruments-predicate */
{
    fetch_write_depth[pid, tid]++;
    fetch_write_start[pid, tid, fetch_write_depth[pid, tid]] = timestamp;
}

fetchio*:::write-done
/fetch_write_start[pid, tid, fetch_write_depth[pid, tid]] != 0/
{
    @fetch_write_us[(int)arg2] = quantize((timestamp - fetch_write_start[pid, tid, fetch_write_depth[pid, tid]]) / 1000);
    fetch_write_start[pid, tid, fetch_write_depth[pid, tid]] = 0;
    fetch_write_depth[pid, tid]--;
}
