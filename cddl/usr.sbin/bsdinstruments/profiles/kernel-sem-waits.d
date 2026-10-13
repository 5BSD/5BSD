/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-ELEVENTH.
 * Start before workload; event loss invalidates pairing. Latency includes preemption.
 * PID selection uses executing context. No kernel pointer or payload dereferences.
 */

posixsem:::wait-start
/* @bsdinstruments-predicate */
{
    posixsem_wait_depth[pid, tid]++;
    posixsem_wait_time[pid, tid, posixsem_wait_depth[pid, tid]] = timestamp;
}

posixsem:::wait-done
/posixsem_wait_time[pid, tid, posixsem_wait_depth[pid, tid]] != 0/
{
    @posixsem_wait_us[(int)arg1] = quantize((timestamp - posixsem_wait_time[pid, tid, posixsem_wait_depth[pid, tid]]) / 1000);
    @posixsem_wait_count[(int)arg1] = count();
    posixsem_wait_time[pid, tid, posixsem_wait_depth[pid, tid]] = 0;
    posixsem_wait_depth[pid, tid]--;
}

posixsem:::sleep-start
/* @bsdinstruments-predicate */
{
    posixsem_sleep_depth[pid, tid]++;
    posixsem_sleep_time[pid, tid, posixsem_sleep_depth[pid, tid]] = timestamp;
}

posixsem:::sleep-done
/posixsem_sleep_time[pid, tid, posixsem_sleep_depth[pid, tid]] != 0/
{
    @posixsem_sleep_us[(int)arg1] = quantize((timestamp - posixsem_sleep_time[pid, tid, posixsem_sleep_depth[pid, tid]]) / 1000);
    @posixsem_sleep_count[(int)arg1] = count();
    posixsem_sleep_time[pid, tid, posixsem_sleep_depth[pid, tid]] = 0;
    posixsem_sleep_depth[pid, tid]--;
}
