/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-SIXTEENTH for argument semantics.
 * No pointer dereferences, payloads, paths, addresses or credentials.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling; PID filters omit unrelated worker threads.
 */

sdt:::hyperv-storage-connect-start
/* @bsdinstruments-predicate */
{
    hv_connect_depth[pid, tid]++;
    hv_connect_time[pid, tid, hv_connect_depth[pid, tid]] = timestamp;
}

sdt:::hyperv-storage-connect-done
/hv_connect_time[pid, tid, hv_connect_depth[pid, tid]] != 0/
{
    @hv_connect_us = quantize((timestamp - hv_connect_time[pid, tid, hv_connect_depth[pid, tid]]) / 1000);
    @connect_status[(int)arg1, (uint32_t)arg2, (uint32_t)arg3] = count();
    hv_connect_time[pid, tid, hv_connect_depth[pid, tid]] = 0;
    hv_connect_depth[pid, tid]--;
}

sdt:::hyperv-storage-request-pressure
/* @bsdinstruments-predicate */
{
    @request_pressure[(int)arg1] = count();
}

sdt:::hyperv-net-send-pressure
/* @bsdinstruments-predicate */
{
    @send_pressure[(int)arg1, (int)arg2] = count();
}
