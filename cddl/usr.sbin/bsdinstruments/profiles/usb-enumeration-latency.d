/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-FIFTEENTH.
 * Scalar metadata only; opaque identities must not be dereferenced.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling. Kernel work may run outside caller PID.
 */

sdt:::usb-enumerate-start
/* @bsdinstruments-predicate */
{
    usb_enumerate_depth[pid, tid]++;
    usb_enumerate_time[pid, tid, usb_enumerate_depth[pid, tid]] = timestamp;
}

sdt:::usb-enumerate-done
/usb_enumerate_time[pid, tid, usb_enumerate_depth[pid, tid]] != 0/
{
    @usb_enumerate_us = quantize((timestamp - usb_enumerate_time[pid, tid, usb_enumerate_depth[pid, tid]]) / 1000);
    @enumerated[(int)arg2] = count();
    usb_enumerate_time[pid, tid, usb_enumerate_depth[pid, tid]] = 0;
    usb_enumerate_depth[pid, tid]--;
}

sdt:::usb-tt-drain-start
/* @bsdinstruments-predicate */
{
    usb_tt_drain_depth[pid, tid]++;
    usb_tt_drain_time[pid, tid, usb_tt_drain_depth[pid, tid]] = timestamp;
}

sdt:::usb-tt-drain-done
/usb_tt_drain_time[pid, tid, usb_tt_drain_depth[pid, tid]] != 0/
{
    @usb_tt_drain_us = quantize((timestamp - usb_tt_drain_time[pid, tid, usb_tt_drain_depth[pid, tid]]) / 1000);

    usb_tt_drain_time[pid, tid, usb_tt_drain_depth[pid, tid]] = 0;
    usb_tt_drain_depth[pid, tid]--;
}

sdt:::usb-attach-done
/* @bsdinstruments-predicate */
{ @attach_status[(int)arg1] = count(); }
sdt:::usb-disconnect
/* @bsdinstruments-predicate */
{ @disconnects = count(); }
