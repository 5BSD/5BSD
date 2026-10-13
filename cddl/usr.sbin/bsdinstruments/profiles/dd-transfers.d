/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts/context: tools/test/system-tracing/COVERAGE-SIXTH.
 * Elapsed microseconds include blocking and preemption. Pointers are opaque.
 * Start before the workload. Drops or nonlocal exits invalidate pairing.
 * Per-thread depth handles synchronous nesting. PID filters select the
 * executing process, not the application responsible for kernel work.
 * Cron child-wait is reap-wait latency, not complete job execution time.
 */

ddio*:::read-start
/* @bsdinstruments-predicate */
{
    ddio_read_depth[pid, tid]++;
    ddio_read_start[pid, tid, ddio_read_depth[pid, tid]] = timestamp;
}

ddio*:::read-done
/ddio_read_start[pid, tid, ddio_read_depth[pid, tid]] != 0/
{
    @ddio_read_us[(int)arg2] = quantize((timestamp - ddio_read_start[pid, tid, ddio_read_depth[pid, tid]]) / 1000);
    @ddio_read_bytes[0] = sum((int64_t)arg1 > 0 ? (int64_t)arg1 : 0);
    @ddio_read_results[(int)arg2, (int64_t)arg1 == 0] = count();
    ddio_read_start[pid, tid, ddio_read_depth[pid, tid]] = 0;
    ddio_read_depth[pid, tid]--;
}

ddio*:::write-start
/* @bsdinstruments-predicate */
{
    ddio_write_depth[pid, tid]++;
    ddio_write_start[pid, tid, ddio_write_depth[pid, tid]] = timestamp;
}

ddio*:::write-done
/ddio_write_start[pid, tid, ddio_write_depth[pid, tid]] != 0/
{
    @ddio_write_us[(int)arg2] = quantize((timestamp - ddio_write_start[pid, tid, ddio_write_depth[pid, tid]]) / 1000);
    @ddio_write_bytes[0] = sum((int64_t)arg1 > 0 ? (int64_t)arg1 : 0);
    @ddio_write_results[(int)arg2, (int64_t)arg1 == 0] = count();
    ddio_write_start[pid, tid, ddio_write_depth[pid, tid]] = 0;
    ddio_write_depth[pid, tid]--;
}

ddio*:::sparse
/* @bsdinstruments-predicate */
{
    @ddio_sparse[(int)arg0] = count();
    @ddio_deferred_bytes[(int)arg0] = sum((uint64_t)arg1);
}
