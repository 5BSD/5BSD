/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-SIXTEENTH for argument semantics.
 * No pointer dereferences, payloads, paths, addresses or credentials.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling; PID filters omit unrelated worker threads.
 */

sdt:::hid-report-start
/* @bsdinstruments-predicate */
{
    hid_report_depth[pid, tid]++;
    hid_report_time[pid, tid, hid_report_depth[pid, tid]] = timestamp;
}

sdt:::hid-report-done
/hid_report_time[pid, tid, hid_report_depth[pid, tid]] != 0/
{
    @hid_report_us = quantize((timestamp - hid_report_time[pid, tid, hid_report_depth[pid, tid]]) / 1000);
    @report_status[(int)arg1, (int)arg2] = count();
    hid_report_time[pid, tid, hid_report_depth[pid, tid]] = 0;
    hid_report_depth[pid, tid]--;
}
