/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-FOURTH.
 * Durations are elapsed microseconds, including blocking and callbacks.
 * Identities are never dereferenced. Start tracing before the workload.
 * Missing completions (termination, cancellation or nonlocal exits) are not
 * success. Per-thread depth handles synchronous nesting; lost events can
 * invalidate pairing. User providers require MK_DTRACE=yes.
 */

pipe:::read-start
/* @bsdinstruments-predicate */
{
    pipe_read_depth[pid, tid]++;
    pipe_read_start[pid, tid, pipe_read_depth[pid, tid]] = timestamp;
}

pipe:::read-done
/pipe_read_start[pid, tid, pipe_read_depth[pid, tid]] != 0/
{
    @pipe_read_us[(int)arg2] = quantize((timestamp - pipe_read_start[pid, tid, pipe_read_depth[pid, tid]]) / 1000);
    pipe_read_start[pid, tid, pipe_read_depth[pid, tid]] = 0;
    pipe_read_depth[pid, tid]--;
}

pipe:::write-start
/* @bsdinstruments-predicate */
{
    pipe_write_depth[pid, tid]++;
    pipe_write_start[pid, tid, pipe_write_depth[pid, tid]] = timestamp;
}

pipe:::write-done
/pipe_write_start[pid, tid, pipe_write_depth[pid, tid]] != 0/
{
    @pipe_write_us[(int)arg2] = quantize((timestamp - pipe_write_start[pid, tid, pipe_write_depth[pid, tid]]) / 1000);
    pipe_write_start[pid, tid, pipe_write_depth[pid, tid]] = 0;
    pipe_write_depth[pid, tid]--;
}

pipe:::direct-start
/* @bsdinstruments-predicate */
{
    pipe_direct_depth[pid, tid]++;
    pipe_direct_start[pid, tid, pipe_direct_depth[pid, tid]] = timestamp;
}

pipe:::direct-done
/pipe_direct_start[pid, tid, pipe_direct_depth[pid, tid]] != 0/
{
    @pipe_direct_us[(int)arg2] = quantize((timestamp - pipe_direct_start[pid, tid, pipe_direct_depth[pid, tid]]) / 1000);
    pipe_direct_start[pid, tid, pipe_direct_depth[pid, tid]] = 0;
    pipe_direct_depth[pid, tid]--;
}

pipe:::resize-start
/* @bsdinstruments-predicate */
{
    pipe_resize_depth[pid, tid]++;
    pipe_resize_start[pid, tid, pipe_resize_depth[pid, tid]] = timestamp;
}

pipe:::resize-done
/pipe_resize_start[pid, tid, pipe_resize_depth[pid, tid]] != 0/
{
    @pipe_resize_us[(int)arg2] = quantize((timestamp - pipe_resize_start[pid, tid, pipe_resize_depth[pid, tid]]) / 1000);
    pipe_resize_start[pid, tid, pipe_resize_depth[pid, tid]] = 0;
    pipe_resize_depth[pid, tid]--;
}
