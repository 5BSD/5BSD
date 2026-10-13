/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-FOURTH.
 * Durations are elapsed microseconds, including blocking and callbacks.
 * Identities are never dereferenced. Start tracing before the workload.
 * Missing completions (termination, cancellation or nonlocal exits) are not
 * success. Per-thread depth handles synchronous nesting; lost events can
 * invalidate pairing. User providers require MK_DTRACE=yes.
 */

usb:::drain-start
/* @bsdinstruments-predicate */
{
    usb_drain_depth[pid, tid]++;
    usb_drain_start[pid, tid, usb_drain_depth[pid, tid]] = timestamp;
}

usb:::drain-done
/usb_drain_start[pid, tid, usb_drain_depth[pid, tid]] != 0/
{
    @usb_drain_us[0] = quantize((timestamp - usb_drain_start[pid, tid, usb_drain_depth[pid, tid]]) / 1000);
    usb_drain_start[pid, tid, usb_drain_depth[pid, tid]] = 0;
    usb_drain_depth[pid, tid]--;
}

pcm:::drain-start
/* @bsdinstruments-predicate */
{
    pcm_drain_depth[pid, tid]++;
    pcm_drain_start[pid, tid, pcm_drain_depth[pid, tid]] = timestamp;
}

pcm:::drain-done
/pcm_drain_start[pid, tid, pcm_drain_depth[pid, tid]] != 0/
{
    @pcm_drain_us[(int)arg1] = quantize((timestamp - pcm_drain_start[pid, tid, pcm_drain_depth[pid, tid]]) / 1000);
    pcm_drain_start[pid, tid, pcm_drain_depth[pid, tid]] = 0;
    pcm_drain_depth[pid, tid]--;
}
