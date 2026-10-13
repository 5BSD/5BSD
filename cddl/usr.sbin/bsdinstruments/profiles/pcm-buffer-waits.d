/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-SIXTEENTH for argument semantics.
 * No pointer dereferences, payloads, paths, addresses or credentials.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling; PID filters omit unrelated worker threads.
 */

sdt:::pcm-buffer-wait-start
/* @bsdinstruments-predicate */
{
    pcm_buffer_depth[pid, tid]++;
    pcm_buffer_time[pid, tid, pcm_buffer_depth[pid, tid]] = timestamp;
}

sdt:::pcm-buffer-wait-done
/pcm_buffer_time[pid, tid, pcm_buffer_depth[pid, tid]] != 0/
{
    @pcm_buffer_us = quantize((timestamp - pcm_buffer_time[pid, tid, pcm_buffer_depth[pid, tid]]) / 1000);
    @wait_status[(int)arg1, (int)arg2] = count();
    pcm_buffer_time[pid, tid, pcm_buffer_depth[pid, tid]] = 0;
    pcm_buffer_depth[pid, tid]--;
}
