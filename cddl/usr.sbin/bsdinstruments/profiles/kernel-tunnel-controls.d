/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-ELEVENTH.
 * Start before workload; event loss invalidates pairing. Latency includes preemption.
 * PID selection uses executing context. No kernel pointer or payload dereferences.
 */

giftunnel:::control-start
/* @bsdinstruments-predicate */
{
    giftunnel_control_depth[pid, tid]++;
    giftunnel_control_time[pid, tid, giftunnel_control_depth[pid, tid]] = timestamp;
}

giftunnel:::control-done
/giftunnel_control_time[pid, tid, giftunnel_control_depth[pid, tid]] != 0/
{
    @giftunnel_control_us[(int)arg2] = quantize((timestamp - giftunnel_control_time[pid, tid, giftunnel_control_depth[pid, tid]]) / 1000);
    @giftunnel_control_count[(int)arg2] = count();
    giftunnel_control_time[pid, tid, giftunnel_control_depth[pid, tid]] = 0;
    giftunnel_control_depth[pid, tid]--;
}

giftunnel:::access
/* @bsdinstruments-predicate */
{
    @giftunnel_access_count[arg1, arg2] = count();
}

gretunnel:::control-start
/* @bsdinstruments-predicate */
{
    gretunnel_control_depth[pid, tid]++;
    gretunnel_control_time[pid, tid, gretunnel_control_depth[pid, tid]] = timestamp;
}

gretunnel:::control-done
/gretunnel_control_time[pid, tid, gretunnel_control_depth[pid, tid]] != 0/
{
    @gretunnel_control_us[(int)arg2] = quantize((timestamp - gretunnel_control_time[pid, tid, gretunnel_control_depth[pid, tid]]) / 1000);
    @gretunnel_control_count[(int)arg2] = count();
    gretunnel_control_time[pid, tid, gretunnel_control_depth[pid, tid]] = 0;
    gretunnel_control_depth[pid, tid]--;
}

gretunnel:::access
/* @bsdinstruments-predicate */
{
    @gretunnel_access_count[arg1, arg2] = count();
}

vxlanctl:::control-start
/* @bsdinstruments-predicate */
{
    vxlanctl_control_depth[pid, tid]++;
    vxlanctl_control_time[pid, tid, vxlanctl_control_depth[pid, tid]] = timestamp;
}

vxlanctl:::control-done
/vxlanctl_control_time[pid, tid, vxlanctl_control_depth[pid, tid]] != 0/
{
    @vxlanctl_control_us[(int)arg2] = quantize((timestamp - vxlanctl_control_time[pid, tid, vxlanctl_control_depth[pid, tid]]) / 1000);
    @vxlanctl_control_count[(int)arg2] = count();
    vxlanctl_control_time[pid, tid, vxlanctl_control_depth[pid, tid]] = 0;
    vxlanctl_control_depth[pid, tid]--;
}

vxlanctl:::access
/* @bsdinstruments-predicate */
{
    @vxlanctl_access_count[arg1, arg2] = count();
}
