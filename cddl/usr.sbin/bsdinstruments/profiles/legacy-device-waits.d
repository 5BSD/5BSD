/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-NINETEENTH for argument meanings.
 * No terminal characters, paths or credential data are collected.
 * Start before the workload; drops invalidate latency pairing.
 */

sdt:::snp-read-wait-start
/* @bsdinstruments-predicate */
{
    snp_depth[pid, tid]++;
    snp_time[pid, tid, snp_depth[pid, tid]] = timestamp;
}

sdt:::snp-read-wait-done
/snp_time[pid, tid, snp_depth[pid, tid]] != 0/
{
    @snp_us = quantize((timestamp - snp_time[pid, tid, snp_depth[pid, tid]]) / 1000);
    @snp_results[(int)arg1] = count();
    snp_time[pid, tid, snp_depth[pid, tid]] = 0;
    snp_depth[pid, tid]--;
}
