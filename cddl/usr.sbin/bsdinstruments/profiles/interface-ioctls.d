/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-FOURTH.
 * Durations are elapsed microseconds, including blocking and callbacks.
 * Identities are never dereferenced. Start tracing before the workload.
 * Missing completions (termination, cancellation or nonlocal exits) are not
 * success. Per-thread depth handles synchronous nesting; lost events can
 * invalidate pairing. User providers require MK_DTRACE=yes.
 */

ifnet:::ioctl-start
/* @bsdinstruments-predicate */
{
    if_ioctl_depth[pid, tid]++;
    if_ioctl_start[pid, tid, if_ioctl_depth[pid, tid]] = timestamp;
}

ifnet:::ioctl-done
/if_ioctl_start[pid, tid, if_ioctl_depth[pid, tid]] != 0/
{
    @if_ioctl_us[(int)arg2] = quantize((timestamp - if_ioctl_start[pid, tid, if_ioctl_depth[pid, tid]]) / 1000);
    if_ioctl_start[pid, tid, if_ioctl_depth[pid, tid]] = 0;
    if_ioctl_depth[pid, tid]--;
}
