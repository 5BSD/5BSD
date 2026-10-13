/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-NINETEENTH for argument meanings.
 * No terminal characters, paths or credential data are collected.
 * Start before the workload; drops invalidate latency pairing.
 */

sdt:::tty-sleep-start
/* @bsdinstruments-predicate */
{
    tty_depth[pid, tid]++;
    tty_time[pid, tid, tty_depth[pid, tid]] = timestamp;
}

sdt:::tty-sleep-done
/tty_time[pid, tid, tty_depth[pid, tid]] != 0/
{
    @tty_us = quantize((timestamp - tty_time[pid, tid, tty_depth[pid, tid]]) / 1000);
    @tty_results[(int)arg1, (int)arg2] = count();
    tty_time[pid, tid, tty_depth[pid, tid]] = 0;
    tty_depth[pid, tid]--;
}
