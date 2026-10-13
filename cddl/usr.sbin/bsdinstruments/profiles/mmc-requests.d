/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts/context: tools/test/system-tracing/COVERAGE-SIXTH.
 * Elapsed microseconds include blocking and preemption. Pointers are opaque.
 * Start before the workload. Drops or nonlocal exits invalidate pairing.
 * Per-thread depth handles synchronous nesting. PID filters select the
 * executing process, not the application responsible for kernel work.
 * Cron child-wait is reap-wait latency, not complete job execution time.
 */

mmc:::request-start
/* @bsdinstruments-predicate */
{
    mmc_request_depth[pid, tid]++;
    mmc_request_start[pid, tid, mmc_request_depth[pid, tid]] = timestamp;
}

mmc:::request-done
/mmc_request_start[pid, tid, mmc_request_depth[pid, tid]] != 0/
{
    @mmc_request_us[(int)arg1] = quantize((timestamp - mmc_request_start[pid, tid, mmc_request_depth[pid, tid]]) / 1000);
    mmc_request_start[pid, tid, mmc_request_depth[pid, tid]] = 0;
    mmc_request_depth[pid, tid]--;
}

mmc:::retune-start
/* @bsdinstruments-predicate */
{
    mmc_retune_depth[pid, tid]++;
    mmc_retune_start[pid, tid, mmc_retune_depth[pid, tid]] = timestamp;
}

mmc:::retune-done
/mmc_retune_start[pid, tid, mmc_retune_depth[pid, tid]] != 0/
{
    @mmc_retune_us[(int)arg1] = quantize((timestamp - mmc_retune_start[pid, tid, mmc_retune_depth[pid, tid]]) / 1000);
    mmc_retune_start[pid, tid, mmc_retune_depth[pid, tid]] = 0;
    mmc_retune_depth[pid, tid]--;
}

mmc:::command-retry
/* @bsdinstruments-predicate */
{
    @mmc_command_retry[(uint32_t)arg1, (int)arg2] = count();
}
