/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-SIXTEENTH for argument semantics.
 * No pointer dereferences, payloads, paths, addresses or credentials.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling; PID filters omit unrelated worker threads.
 */

sdt:::oom-start
/* @bsdinstruments-predicate */
{
    oom_depth[pid, tid]++;
    oom_time[pid, tid, oom_depth[pid, tid]] = timestamp;
}

sdt:::oom-done
/oom_time[pid, tid, oom_depth[pid, tid]] != 0/
{
    @oom_us = quantize((timestamp - oom_time[pid, tid, oom_depth[pid, tid]]) / 1000);
    @outcomes[(int)arg0, (int)arg1] = count();
    oom_time[pid, tid, oom_depth[pid, tid]] = 0;
    oom_depth[pid, tid]--;
}

sdt:::oom-vote
/* @bsdinstruments-predicate */
{
    @domain_votes[(int)arg0] = count();
    @quorum = quantize((int)arg1);
    @shortage = quantize((int)arg2);
}

sdt:::oom-vote-withdraw
/* @bsdinstruments-predicate */
{
    @withdrawn[(int)arg0, (int)arg1] = count();
}

sdt:::oom-victim
/* @bsdinstruments-predicate */
{
    @victims_by_reason[(int)arg0] = count();
    @estimated_pages = quantize((u_long)arg2);
}
