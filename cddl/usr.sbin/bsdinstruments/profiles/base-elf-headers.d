/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-FOURTEENTH.
 * No paths, payloads, credentials or pointer dereferences. Start before the
 * workload; event loss invalidates pairing. Elapsed time includes preemption.
 * processquery's final argument is an unavailable flag, not errno.
 */

elfbrand*:::read-start
/* @bsdinstruments-predicate */
{
    elfbrand_read_depth[pid, tid]++;
    elfbrand_read_time[pid, tid, elfbrand_read_depth[pid, tid]] = timestamp;
}

elfbrand*:::read-done
/elfbrand_read_time[pid, tid, elfbrand_read_depth[pid, tid]] != 0/
{
    @elfbrand_read_us[(int)arg3] = quantize((timestamp - elfbrand_read_time[pid, tid, elfbrand_read_depth[pid, tid]]) / 1000);
    @elfbrand_read_count[(int)arg3] = count();
    if ((int)arg3 == 0)
        @elfbrand_read_bytes = quantize((int64_t)arg2);
    elfbrand_read_time[pid, tid, elfbrand_read_depth[pid, tid]] = 0;
    elfbrand_read_depth[pid, tid]--;
}

elfbrand*:::write-start
/* @bsdinstruments-predicate */
{
    elfbrand_write_depth[pid, tid]++;
    elfbrand_write_time[pid, tid, elfbrand_write_depth[pid, tid]] = timestamp;
}

elfbrand*:::write-done
/elfbrand_write_time[pid, tid, elfbrand_write_depth[pid, tid]] != 0/
{
    @elfbrand_write_us[(int)arg3] = quantize((timestamp - elfbrand_write_time[pid, tid, elfbrand_write_depth[pid, tid]]) / 1000);
    @elfbrand_write_count[(int)arg3] = count();
    if ((int)arg3 == 0)
        @elfbrand_write_bytes = quantize((int64_t)arg2);
    elfbrand_write_time[pid, tid, elfbrand_write_depth[pid, tid]] = 0;
    elfbrand_write_depth[pid, tid]--;
}
