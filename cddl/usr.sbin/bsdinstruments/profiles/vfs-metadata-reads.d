/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and exclusions: tools/test/system-tracing/COVERAGE-THIRTEENTH.
 * Start before the workload. Event loss invalidates pairing. Latency includes
 * preemption. PID filtering selects executing context, not a target process.
 * No pointer dereferences or payload reads. VM results are KERN_* codes.
 */

vfs:::extattr-get-start
/* @bsdinstruments-predicate */
{
    vfs_extattr_get_depth[pid, tid]++;
    vfs_extattr_get_time[pid, tid, vfs_extattr_get_depth[pid, tid]] = timestamp;
}

vfs:::extattr-get-done
/vfs_extattr_get_time[pid, tid, vfs_extattr_get_depth[pid, tid]] != 0/
{
    @vfs_extattr_get_us[(int)arg2] = quantize((timestamp - vfs_extattr_get_time[pid, tid, vfs_extattr_get_depth[pid, tid]]) / 1000);
    @vfs_extattr_get_count[(int)arg2] = count();
    vfs_extattr_get_time[pid, tid, vfs_extattr_get_depth[pid, tid]] = 0;
    vfs_extattr_get_depth[pid, tid]--;
}

vfs:::extattr-list-start
/* @bsdinstruments-predicate */
{
    vfs_extattr_list_depth[pid, tid]++;
    vfs_extattr_list_time[pid, tid, vfs_extattr_list_depth[pid, tid]] = timestamp;
}

vfs:::extattr-list-done
/vfs_extattr_list_time[pid, tid, vfs_extattr_list_depth[pid, tid]] != 0/
{
    @vfs_extattr_list_us[(int)arg2] = quantize((timestamp - vfs_extattr_list_time[pid, tid, vfs_extattr_list_depth[pid, tid]]) / 1000);
    @vfs_extattr_list_count[(int)arg2] = count();
    vfs_extattr_list_time[pid, tid, vfs_extattr_list_depth[pid, tid]] = 0;
    vfs_extattr_list_depth[pid, tid]--;
}

vfs:::acl-get-start
/* @bsdinstruments-predicate */
{
    vfs_acl_get_depth[pid, tid]++;
    vfs_acl_get_time[pid, tid, vfs_acl_get_depth[pid, tid]] = timestamp;
}

vfs:::acl-get-done
/vfs_acl_get_time[pid, tid, vfs_acl_get_depth[pid, tid]] != 0/
{
    @vfs_acl_get_us[(int)arg2] = quantize((timestamp - vfs_acl_get_time[pid, tid, vfs_acl_get_depth[pid, tid]]) / 1000);
    @vfs_acl_get_count[(int)arg2] = count();
    vfs_acl_get_time[pid, tid, vfs_acl_get_depth[pid, tid]] = 0;
    vfs_acl_get_depth[pid, tid]--;
}

vfs:::acl-check-start
/* @bsdinstruments-predicate */
{
    vfs_acl_check_depth[pid, tid]++;
    vfs_acl_check_time[pid, tid, vfs_acl_check_depth[pid, tid]] = timestamp;
}

vfs:::acl-check-done
/vfs_acl_check_time[pid, tid, vfs_acl_check_depth[pid, tid]] != 0/
{
    @vfs_acl_check_us[(int)arg2] = quantize((timestamp - vfs_acl_check_time[pid, tid, vfs_acl_check_depth[pid, tid]]) / 1000);
    @vfs_acl_check_count[(int)arg2] = count();
    vfs_acl_check_time[pid, tid, vfs_acl_check_depth[pid, tid]] = 0;
    vfs_acl_check_depth[pid, tid]--;
}
