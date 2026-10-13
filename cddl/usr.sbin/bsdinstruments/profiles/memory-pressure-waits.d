/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-SIXTEENTH for argument semantics.
 * No pointer dereferences, payloads, paths, addresses or credentials.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling; PID filters omit unrelated worker threads.
 */

sdt:::memory-wait-start
/* @bsdinstruments-predicate */
{
    memory_depth[pid, tid]++;
    memory_time[pid, tid, memory_depth[pid, tid]] = timestamp;
}

sdt:::memory-wait-done
/memory_time[pid, tid, memory_depth[pid, tid]] != 0/
{
    @memory_us = quantize((timestamp - memory_time[pid, tid, memory_depth[pid, tid]]) / 1000);
    @wait_status[(int)arg0, (int)arg1] = count();
    memory_time[pid, tid, memory_depth[pid, tid]] = 0;
    memory_depth[pid, tid]--;
}

sdt:::memory-fault-wait-start
/* @bsdinstruments-predicate */
{
    faultwait_depth[pid, tid]++;
    faultwait_time[pid, tid, faultwait_depth[pid, tid]] = timestamp;
}

sdt:::memory-fault-wait-done
/faultwait_time[pid, tid, faultwait_depth[pid, tid]] != 0/
{
    @faultwait_us = quantize((timestamp - faultwait_time[pid, tid, faultwait_depth[pid, tid]]) / 1000);
    @fault_wait_status[(int)arg0] = count();
    faultwait_time[pid, tid, faultwait_depth[pid, tid]] = 0;
    faultwait_depth[pid, tid]--;
}

sdt:::memory-domains-wait
/* @bsdinstruments-predicate */
{
    @domain_policy_waits[(int)arg0, (int)arg2, (int)arg3] = count();
}
