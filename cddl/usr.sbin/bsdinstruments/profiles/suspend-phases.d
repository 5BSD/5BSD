/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

acpi:::device-start
/* @bsdinstruments-predicate */
{
    device_depth[pid, tid]++;
    device_start[pid, tid, device_depth[pid, tid]] = timestamp;
}

acpi:::device-done
/device_start[pid, tid, device_depth[pid, tid]] != 0/
{
    @device_us[(int)arg2] = quantize((timestamp - device_start[pid, tid, device_depth[pid, tid]]) / 1000);
    device_start[pid, tid, device_depth[pid, tid]] = 0;
    device_depth[pid, tid]--;
}

acpi:::sleep-start
/* @bsdinstruments-predicate */
{
    sleep_depth[pid, tid]++;
    sleep_start[pid, tid, sleep_depth[pid, tid]] = timestamp;
}

acpi:::sleep-done
/sleep_start[pid, tid, sleep_depth[pid, tid]] != 0/
{
    @sleep_us[(int)arg2] = quantize((timestamp - sleep_start[pid, tid, sleep_depth[pid, tid]]) / 1000);
    sleep_start[pid, tid, sleep_depth[pid, tid]] = 0;
    sleep_depth[pid, tid]--;
}

acpi:::prepare-start
/* @bsdinstruments-predicate */
{
    prepare_depth[pid, tid]++;
    prepare_start[pid, tid, prepare_depth[pid, tid]] = timestamp;
}

acpi:::prepare-done
/prepare_start[pid, tid, prepare_depth[pid, tid]] != 0/
{
    @prepare_us[(int)arg2] = quantize((timestamp - prepare_start[pid, tid, prepare_depth[pid, tid]]) / 1000);
    prepare_start[pid, tid, prepare_depth[pid, tid]] = 0;
    prepare_depth[pid, tid]--;
}
