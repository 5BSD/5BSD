/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-SIXTEENTH for argument semantics.
 * No pointer dereferences, payloads, paths, addresses or credentials.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling; PID filters omit unrelated worker threads.
 */

sdt:::mlx5-recovery-start
/* @bsdinstruments-predicate */
{
    mlx5_recovery_depth[pid, tid]++;
    mlx5_recovery_time[pid, tid, mlx5_recovery_depth[pid, tid]] = timestamp;
}

sdt:::mlx5-recovery-done
/mlx5_recovery_time[pid, tid, mlx5_recovery_depth[pid, tid]] != 0/
{
    @mlx5_recovery_us = quantize((timestamp - mlx5_recovery_time[pid, tid, mlx5_recovery_depth[pid, tid]]) / 1000);
    @recovery_decision[(int)arg1, (int)arg2] = count();
    mlx5_recovery_time[pid, tid, mlx5_recovery_depth[pid, tid]] = 0;
    mlx5_recovery_depth[pid, tid]--;
}
