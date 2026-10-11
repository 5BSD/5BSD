/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

sshkeys*:::newkeys-start
/* @bsdinstruments-predicate */
{
    newkeys_depth[pid, tid]++;
    newkeys_start[pid, tid, newkeys_depth[pid, tid]] = timestamp;
}

sshkeys*:::newkeys-done
/newkeys_start[pid, tid, newkeys_depth[pid, tid]] != 0/
{
    @newkeys_us[(int)arg1] = quantize((timestamp - newkeys_start[pid, tid, newkeys_depth[pid, tid]]) / 1000);
    newkeys_start[pid, tid, newkeys_depth[pid, tid]] = 0;
    newkeys_depth[pid, tid]--;
}

sshauth*:::method-start
/* @bsdinstruments-predicate */
{
    method_depth[pid, tid]++;
    method_start[pid, tid, method_depth[pid, tid]] = timestamp;
}

sshauth*:::method-done
/method_start[pid, tid, method_depth[pid, tid]] != 0/
{
    @method_us[(int)arg2] = quantize((timestamp - method_start[pid, tid, method_depth[pid, tid]]) / 1000);
    method_start[pid, tid, method_depth[pid, tid]] = 0;
    method_depth[pid, tid]--;
}

sshauth*:::decision
/* @bsdinstruments-predicate */
{
    @auth_method_decisions[arg2, arg3, arg4] = count();
}

sshkeys*:::channel-new
/* @bsdinstruments-predicate */
{
    @channels[arg2] = count();
}

sshkeys*:::channel-reply
/* @bsdinstruments-predicate */
{
    @channel_replies[arg1, (int)arg2] = count();
}
