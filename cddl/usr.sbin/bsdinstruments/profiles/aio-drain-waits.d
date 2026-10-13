/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-EIGHTEENTH for argument semantics.
 * Scalar arguments only, no payloads, addresses or credentials.
 * Start before the workload; dropped events invalidate latency pairing.
 * Elapsed times include scheduling and reacquiring existing locks.
 */

sdt:::aio-rundown-wait-start
/* @bsdinstruments-predicate */
{
    rundown_depth[pid, tid]++;
    rundown_time[pid, tid, rundown_depth[pid, tid]] = timestamp;
    @active_jobs = quantize((int)arg1);
}

sdt:::aio-rundown-wait-done
/rundown_time[pid, tid, rundown_depth[pid, tid]] != 0/
{
    @rundown_us = quantize((timestamp - rundown_time[pid, tid, rundown_depth[pid, tid]]) / 1000);
    @rundown_wakes[(int)arg1] = count();
    rundown_time[pid, tid, rundown_depth[pid, tid]] = 0;
    rundown_depth[pid, tid]--;
}

sdt:::aio-list-wait-start
/* @bsdinstruments-predicate */
{
    list_depth[pid, tid]++;
    list_time[pid, tid, list_depth[pid, tid]] = timestamp;
    @unfinished_jobs = quantize((int)arg1);
}

sdt:::aio-list-wait-done
/list_time[pid, tid, list_depth[pid, tid]] != 0/
{
    @list_us = quantize((timestamp - list_time[pid, tid, list_depth[pid, tid]]) / 1000);
    @list_wakes[(int)arg1] = count();
    list_time[pid, tid, list_depth[pid, tid]] = 0;
    list_depth[pid, tid]--;
}

sdt:::aio-completion-wait-start
/* @bsdinstruments-predicate */
{
    completion_depth[pid, tid]++;
    completion_time[pid, tid, completion_depth[pid, tid]] = timestamp;
    @timeout_ticks[(int)arg1] = count();
}

sdt:::aio-completion-wait-done
/completion_time[pid, tid, completion_depth[pid, tid]] != 0/
{
    @completion_us = quantize((timestamp - completion_time[pid, tid, completion_depth[pid, tid]]) / 1000);
    @completion_wakes[(int)arg1] = count();
    completion_time[pid, tid, completion_depth[pid, tid]] = 0;
    completion_depth[pid, tid]--;
}
