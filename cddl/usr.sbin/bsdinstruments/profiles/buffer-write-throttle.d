/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-EIGHTEENTH for argument semantics.
 * Scalar arguments only, no payloads, addresses or credentials.
 * Start before the workload; dropped events invalidate latency pairing.
 * Elapsed times include scheduling and reacquiring existing locks.
 */

sdt:::bufcache-throttle-start
/* @bsdinstruments-predicate */
{
    depth[pid, tid]++;
    started[pid, tid, depth[pid, tid]] = timestamp;
}

sdt:::bufcache-throttle-done
/started[pid, tid, depth[pid, tid]] != 0/
{
    @wait_us[(int)arg0] = quantize((timestamp - started[pid, tid, depth[pid, tid]]) / 1000);
    @wakes[(int)arg0] = count();
    started[pid, tid, depth[pid, tid]] = 0;
    depth[pid, tid]--;
}
