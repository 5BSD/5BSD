/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-TWELFTH.
 * Start before workload. Event loss invalidates pairing; latency includes preemption.
 * No pointer or payload reads. PF limiter eligibility is not packet admission.
 */

sdt:::zfs-vop-read-start
/* @bsdinstruments-predicate */
{
    zfs_vop_read_depth[pid, tid]++;
    zfs_vop_read_time[pid, tid, zfs_vop_read_depth[pid, tid]] = timestamp;
}

sdt:::zfs-vop-read-done
/zfs_vop_read_time[pid, tid, zfs_vop_read_depth[pid, tid]] != 0/
{
    @zfs_vop_read_us[(int)arg2] = quantize((timestamp - zfs_vop_read_time[pid, tid, zfs_vop_read_depth[pid, tid]]) / 1000);
    @zfs_vop_read_count[(int)arg2] = count();
    zfs_vop_read_time[pid, tid, zfs_vop_read_depth[pid, tid]] = 0;
    zfs_vop_read_depth[pid, tid]--;
}

sdt:::zfs-vop-write-start
/* @bsdinstruments-predicate */
{
    zfs_vop_write_depth[pid, tid]++;
    zfs_vop_write_time[pid, tid, zfs_vop_write_depth[pid, tid]] = timestamp;
}

sdt:::zfs-vop-write-done
/zfs_vop_write_time[pid, tid, zfs_vop_write_depth[pid, tid]] != 0/
{
    @zfs_vop_write_us[(int)arg2] = quantize((timestamp - zfs_vop_write_time[pid, tid, zfs_vop_write_depth[pid, tid]]) / 1000);
    @zfs_vop_write_count[(int)arg2] = count();
    zfs_vop_write_time[pid, tid, zfs_vop_write_depth[pid, tid]] = 0;
    zfs_vop_write_depth[pid, tid]--;
}
