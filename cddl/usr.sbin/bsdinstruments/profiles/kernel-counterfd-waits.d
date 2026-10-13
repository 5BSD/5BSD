/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-ELEVENTH.
 * Start before workload; event loss invalidates pairing. Latency includes preemption.
 * PID selection uses executing context. No kernel pointer or payload dereferences.
 */

eventfd:::read-wait-start
/* @bsdinstruments-predicate */
{
    eventfd_read_wait_depth[pid, tid]++;
    eventfd_read_wait_time[pid, tid, eventfd_read_wait_depth[pid, tid]] = timestamp;
}

eventfd:::read-wait-done
/eventfd_read_wait_time[pid, tid, eventfd_read_wait_depth[pid, tid]] != 0/
{
    @eventfd_read_wait_us[(int)arg1] = quantize((timestamp - eventfd_read_wait_time[pid, tid, eventfd_read_wait_depth[pid, tid]]) / 1000);
    @eventfd_read_wait_count[(int)arg1] = count();
    eventfd_read_wait_time[pid, tid, eventfd_read_wait_depth[pid, tid]] = 0;
    eventfd_read_wait_depth[pid, tid]--;
}

eventfd:::write-wait-start
/* @bsdinstruments-predicate */
{
    eventfd_write_wait_depth[pid, tid]++;
    eventfd_write_wait_time[pid, tid, eventfd_write_wait_depth[pid, tid]] = timestamp;
}

eventfd:::write-wait-done
/eventfd_write_wait_time[pid, tid, eventfd_write_wait_depth[pid, tid]] != 0/
{
    @eventfd_write_wait_us[(int)arg1] = quantize((timestamp - eventfd_write_wait_time[pid, tid, eventfd_write_wait_depth[pid, tid]]) / 1000);
    @eventfd_write_wait_count[(int)arg1] = count();
    eventfd_write_wait_time[pid, tid, eventfd_write_wait_depth[pid, tid]] = 0;
    eventfd_write_wait_depth[pid, tid]--;
}

timerfd:::read-wait-start
/* @bsdinstruments-predicate */
{
    timerfd_read_wait_depth[pid, tid]++;
    timerfd_read_wait_time[pid, tid, timerfd_read_wait_depth[pid, tid]] = timestamp;
}

timerfd:::read-wait-done
/timerfd_read_wait_time[pid, tid, timerfd_read_wait_depth[pid, tid]] != 0/
{
    @timerfd_read_wait_us[(int)arg1] = quantize((timestamp - timerfd_read_wait_time[pid, tid, timerfd_read_wait_depth[pid, tid]]) / 1000);
    @timerfd_read_wait_count[(int)arg1] = count();
    timerfd_read_wait_time[pid, tid, timerfd_read_wait_depth[pid, tid]] = 0;
    timerfd_read_wait_depth[pid, tid]--;
}
