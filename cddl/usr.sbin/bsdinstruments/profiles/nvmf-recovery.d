/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-SIXTEENTH for argument semantics.
 * No pointer dereferences, payloads, paths, addresses or credentials.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling; PID filters omit unrelated worker threads.
 */

sdt:::nvmf-disconnect-start
/* @bsdinstruments-predicate */
{
    nvmf_disconnect_depth[pid, tid]++;
    nvmf_disconnect_time[pid, tid, nvmf_disconnect_depth[pid, tid]] = timestamp;
}

sdt:::nvmf-disconnect-done
/nvmf_disconnect_time[pid, tid, nvmf_disconnect_depth[pid, tid]] != 0/
{
    @nvmf_disconnect_us = quantize((timestamp - nvmf_disconnect_time[pid, tid, nvmf_disconnect_depth[pid, tid]]) / 1000);

    nvmf_disconnect_time[pid, tid, nvmf_disconnect_depth[pid, tid]] = 0;
    nvmf_disconnect_depth[pid, tid]--;
}

sdt:::nvmf-reconnect-start
/* @bsdinstruments-predicate */
{
    nvmf_reconnect_depth[pid, tid]++;
    nvmf_reconnect_time[pid, tid, nvmf_reconnect_depth[pid, tid]] = timestamp;
}

sdt:::nvmf-reconnect-done
/nvmf_reconnect_time[pid, tid, nvmf_reconnect_depth[pid, tid]] != 0/
{
    @nvmf_reconnect_us = quantize((timestamp - nvmf_reconnect_time[pid, tid, nvmf_reconnect_depth[pid, tid]]) / 1000);
    @reconnect_status[(int)arg1] = count();
    nvmf_reconnect_time[pid, tid, nvmf_reconnect_depth[pid, tid]] = 0;
    nvmf_reconnect_depth[pid, tid]--;
}

sdt:::nvmf-reconnect-retry
/* @bsdinstruments-predicate */
{
    @reconnect_delay_s = quantize((u_int)arg1);
}

sdt:::nvmf-capsule-pressure
/* @bsdinstruments-predicate */
{
    @capsule_pressure[(int)arg1, (int)arg2] = count();
}
