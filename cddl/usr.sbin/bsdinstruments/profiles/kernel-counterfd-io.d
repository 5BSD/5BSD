/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-ELEVENTH.
 * Start before workload; event loss invalidates pairing. Latency includes preemption.
 * PID selection uses executing context. No kernel pointer or payload dereferences.
 */

eventfd:::read-copy-start
/* @bsdinstruments-predicate */
{
    eventfd_read_copy_depth[pid, tid]++;
    eventfd_read_copy_time[pid, tid, eventfd_read_copy_depth[pid, tid]] = timestamp;
}

eventfd:::read-copy-done
/eventfd_read_copy_time[pid, tid, eventfd_read_copy_depth[pid, tid]] != 0/
{
    @eventfd_read_copy_us[(int)arg1] = quantize((timestamp - eventfd_read_copy_time[pid, tid, eventfd_read_copy_depth[pid, tid]]) / 1000);
    @eventfd_read_copy_count[(int)arg1] = count();
    eventfd_read_copy_time[pid, tid, eventfd_read_copy_depth[pid, tid]] = 0;
    eventfd_read_copy_depth[pid, tid]--;
}

eventfd:::read-state
/* @bsdinstruments-predicate */
{
    @eventfd_read_state_count[arg1, arg2] = count();
}

timerfd:::read-copy-start
/* @bsdinstruments-predicate */
{
    timerfd_read_copy_depth[pid, tid]++;
    timerfd_read_copy_time[pid, tid, timerfd_read_copy_depth[pid, tid]] = timestamp;
}

timerfd:::read-copy-done
/timerfd_read_copy_time[pid, tid, timerfd_read_copy_depth[pid, tid]] != 0/
{
    @timerfd_read_copy_us[(int)arg1] = quantize((timestamp - timerfd_read_copy_time[pid, tid, timerfd_read_copy_depth[pid, tid]]) / 1000);
    @timerfd_read_copy_count[(int)arg1] = count();
    timerfd_read_copy_time[pid, tid, timerfd_read_copy_depth[pid, tid]] = 0;
    timerfd_read_copy_depth[pid, tid]--;
}

timerfd:::fd-alloc-start
/* @bsdinstruments-predicate */
{
    timerfd_fd_alloc_depth[pid, tid]++;
    timerfd_fd_alloc_time[pid, tid, timerfd_fd_alloc_depth[pid, tid]] = timestamp;
}

timerfd:::fd-alloc-done
/timerfd_fd_alloc_time[pid, tid, timerfd_fd_alloc_depth[pid, tid]] != 0/
{
    @timerfd_fd_alloc_us[(int)arg1] = quantize((timestamp - timerfd_fd_alloc_time[pid, tid, timerfd_fd_alloc_depth[pid, tid]]) / 1000);
    @timerfd_fd_alloc_count[(int)arg1] = count();
    timerfd_fd_alloc_time[pid, tid, timerfd_fd_alloc_depth[pid, tid]] = 0;
    timerfd_fd_alloc_depth[pid, tid]--;
}

timerfd:::read-reset
/* @bsdinstruments-predicate */
{
    @timerfd_read_reset_count[arg1, arg2, arg3] = count();
}
