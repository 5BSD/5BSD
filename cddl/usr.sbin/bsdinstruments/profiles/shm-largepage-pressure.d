/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-SEVENTEENTH for argument meanings.
 * Scalar arguments only; no payloads, paths or credential data.
 * Start before the workload. Lost events invalidate latency pairing.
 */

sdt:::shmfd-swap-pressure
/* @bsdinstruments-predicate */
{
    @swap_reservation_bytes = quantize((int64_t)arg1);
}

sdt:::shmfd-largepage-pressure
/* @bsdinstruments-predicate */
{
    @allocation_failures[(int)arg1, (int)arg3] = count();
    @attempts = quantize((int)arg2);
}

sdt:::shmfd-largepage-retry
/* @bsdinstruments-predicate */
{
    @reclaims[(int)arg1] = count();
}

sdt:::shmfd-largepage-wait-start
/* @bsdinstruments-predicate */
{
    depth[pid, tid]++;
    started[pid, tid, depth[pid, tid]] = timestamp;
}

sdt:::shmfd-largepage-wait-done
/started[pid, tid, depth[pid, tid]] != 0/
{
    @wait_us = quantize((timestamp - started[pid, tid, depth[pid, tid]]) / 1000);
    @wait_results[(int)arg1] = count();
    started[pid, tid, depth[pid, tid]] = 0;
    depth[pid, tid]--;
}
