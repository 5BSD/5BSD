/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-NINETEENTH for argument meanings.
 * No terminal characters, paths or credential data are collected.
 * Start before the workload; drops invalidate latency pairing.
 */

sdt:::pts-master-wait-start
/* @bsdinstruments-predicate */
{
    pts_depth[pid, tid]++;
    pts_time[pid, tid, pts_depth[pid, tid]] = timestamp;
}

sdt:::pts-master-wait-done
/pts_time[pid, tid, pts_depth[pid, tid]] != 0/
{
    @pts_us = quantize((timestamp - pts_time[pid, tid, pts_depth[pid, tid]]) / 1000);
    @pts_results[(int)arg1, (int)arg2] = count();
    pts_time[pid, tid, pts_depth[pid, tid]] = 0;
    pts_depth[pid, tid]--;
}

sdt:::pts-allocation-limit
/* @bsdinstruments-predicate */
{
    @limits[(int)arg0] = count();
}

sdt:::pts-ptmx-open
/* @bsdinstruments-predicate */
{
    @ptmx_results[(int)arg1] = count();
}
