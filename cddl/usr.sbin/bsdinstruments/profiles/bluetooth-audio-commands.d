/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-SEVENTH.
 * Pointers are opaque. Elapsed time includes blocking and preemption.
 * Start before the workload; drops or nonlocal exits invalidate pairing.
 * PID filters select executing context, not the initiating workload.
 */

btaudio*:::command-start
/* @bsdinstruments-predicate */
{
    audio_command_depth[pid, tid]++;
    audio_command_start[pid, tid, audio_command_depth[pid, tid]] = timestamp;
}

btaudio*:::command-done
/audio_command_start[pid, tid, audio_command_depth[pid, tid]] != 0/
{
    @audio_command_us[(uint8_t)arg1, (int)arg3] = quantize((timestamp - audio_command_start[pid, tid, audio_command_depth[pid, tid]]) / 1000);
    audio_command_start[pid, tid, audio_command_depth[pid, tid]] = 0;
    audio_command_depth[pid, tid]--;
}
