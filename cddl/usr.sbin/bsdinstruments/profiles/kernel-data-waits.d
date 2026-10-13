/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and exclusions: tools/test/system-tracing/COVERAGE-THIRTEENTH.
 * Start before the workload. Event loss invalidates pairing. Latency includes
 * preemption. PID filtering selects executing context, not a target process.
 * No pointer dereferences or payload reads. VM results are KERN_* codes.
 */

sendfile:::io-wait-start
/* @bsdinstruments-predicate */
{
    sendfile_io_wait_depth[pid, tid]++;
    sendfile_io_wait_time[pid, tid, sendfile_io_wait_depth[pid, tid]] = timestamp;
}

sendfile:::io-wait-done
/sendfile_io_wait_time[pid, tid, sendfile_io_wait_depth[pid, tid]] != 0/
{
    @sendfile_io_wait_us = quantize((timestamp - sendfile_io_wait_time[pid, tid, sendfile_io_wait_depth[pid, tid]]) / 1000);
    @sendfile_io_wait_count = count();
    sendfile_io_wait_time[pid, tid, sendfile_io_wait_depth[pid, tid]] = 0;
    sendfile_io_wait_depth[pid, tid]--;
}

sendfile:::socket-wait-start
/* @bsdinstruments-predicate */
{
    sendfile_socket_wait_depth[pid, tid]++;
    sendfile_socket_wait_time[pid, tid, sendfile_socket_wait_depth[pid, tid]] = timestamp;
}

sendfile:::socket-wait-done
/sendfile_socket_wait_time[pid, tid, sendfile_socket_wait_depth[pid, tid]] != 0/
{
    @sendfile_socket_wait_us[(int)arg1] = quantize((timestamp - sendfile_socket_wait_time[pid, tid, sendfile_socket_wait_depth[pid, tid]]) / 1000);
    @sendfile_socket_wait_count[(int)arg1] = count();
    sendfile_socket_wait_time[pid, tid, sendfile_socket_wait_depth[pid, tid]] = 0;
    sendfile_socket_wait_depth[pid, tid]--;
}

fd:::advlock-start
/* @bsdinstruments-predicate */
{
    fd_advlock_depth[pid, tid]++;
    fd_advlock_time[pid, tid, fd_advlock_depth[pid, tid]] = timestamp;
}

fd:::advlock-done
/fd_advlock_time[pid, tid, fd_advlock_depth[pid, tid]] != 0/
{
    @fd_advlock_us[(int)arg2] = quantize((timestamp - fd_advlock_time[pid, tid, fd_advlock_depth[pid, tid]]) / 1000);
    @fd_advlock_count[(int)arg2] = count();
    fd_advlock_time[pid, tid, fd_advlock_depth[pid, tid]] = 0;
    fd_advlock_depth[pid, tid]--;
}
