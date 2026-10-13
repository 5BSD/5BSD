/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-NINETEENTH for argument meanings.
 * No terminal characters, paths or credential data are collected.
 * Start before the workload; drops invalidate latency pairing.
 */

sdt:::uart-parameter-start
/* @bsdinstruments-predicate */
{
    uart_depth[pid, tid]++;
    uart_time[pid, tid, uart_depth[pid, tid]] = timestamp;
}

sdt:::uart-parameter-done
/uart_time[pid, tid, uart_depth[pid, tid]] != 0/
{
    @uart_us = quantize((timestamp - uart_time[pid, tid, uart_depth[pid, tid]]) / 1000);
    @uart_results[(int)arg1] = count();
    uart_time[pid, tid, uart_depth[pid, tid]] = 0;
    uart_depth[pid, tid]--;
}

sdt:::nmdm-rate-configured
/* @bsdinstruments-predicate */
{
    @rate_ticks[(int)arg1] = count();
}
