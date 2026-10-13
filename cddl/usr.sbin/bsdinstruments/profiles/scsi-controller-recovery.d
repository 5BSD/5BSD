/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-SIXTEENTH for argument semantics.
 * No pointer dereferences, payloads, paths, addresses or credentials.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling; PID filters omit unrelated worker threads.
 */

sdt:::mpr-reset-start
/* @bsdinstruments-predicate */
{
    mpr_reset_depth[pid, tid]++;
    mpr_reset_time[pid, tid, mpr_reset_depth[pid, tid]] = timestamp;
}

sdt:::mpr-reset-done
/mpr_reset_time[pid, tid, mpr_reset_depth[pid, tid]] != 0/
{
    @mpr_reset_us = quantize((timestamp - mpr_reset_time[pid, tid, mpr_reset_depth[pid, tid]]) / 1000);
    @mpr_reset_status[(int)arg1] = count();
    mpr_reset_time[pid, tid, mpr_reset_depth[pid, tid]] = 0;
    mpr_reset_depth[pid, tid]--;
}

sdt:::mpr-command-wait-start
/* @bsdinstruments-predicate */
{
    mpr_command_wait_depth[pid, tid]++;
    mpr_command_wait_time[pid, tid, mpr_command_wait_depth[pid, tid]] = timestamp;
}

sdt:::mpr-command-wait-done
/mpr_command_wait_time[pid, tid, mpr_command_wait_depth[pid, tid]] != 0/
{
    @mpr_command_wait_us = quantize((timestamp - mpr_command_wait_time[pid, tid, mpr_command_wait_depth[pid, tid]]) / 1000);
    @mpr_command_wait_status[(int)arg1] = count();
    mpr_command_wait_time[pid, tid, mpr_command_wait_depth[pid, tid]] = 0;
    mpr_command_wait_depth[pid, tid]--;
}

sdt:::mps-reset-start
/* @bsdinstruments-predicate */
{
    mps_reset_depth[pid, tid]++;
    mps_reset_time[pid, tid, mps_reset_depth[pid, tid]] = timestamp;
}

sdt:::mps-reset-done
/mps_reset_time[pid, tid, mps_reset_depth[pid, tid]] != 0/
{
    @mps_reset_us = quantize((timestamp - mps_reset_time[pid, tid, mps_reset_depth[pid, tid]]) / 1000);
    @mps_reset_status[(int)arg1] = count();
    mps_reset_time[pid, tid, mps_reset_depth[pid, tid]] = 0;
    mps_reset_depth[pid, tid]--;
}

sdt:::mps-command-wait-start
/* @bsdinstruments-predicate */
{
    mps_command_wait_depth[pid, tid]++;
    mps_command_wait_time[pid, tid, mps_command_wait_depth[pid, tid]] = timestamp;
}

sdt:::mps-command-wait-done
/mps_command_wait_time[pid, tid, mps_command_wait_depth[pid, tid]] != 0/
{
    @mps_command_wait_us = quantize((timestamp - mps_command_wait_time[pid, tid, mps_command_wait_depth[pid, tid]]) / 1000);
    @mps_command_wait_status[(int)arg1] = count();
    mps_command_wait_time[pid, tid, mps_command_wait_depth[pid, tid]] = 0;
    mps_command_wait_depth[pid, tid]--;
}
