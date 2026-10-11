/*
 * USB submission to final callback processing, by device, endpoint and USB status.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

usb:::transfer-start
/* @bsdinstruments-predicate */
{
    transfer_start[arg0] = timestamp;
}

usb:::transfer-done
/transfer_start[arg0] != 0/
{
    @transfer_us[arg1, arg2, arg3] = quantize((timestamp - transfer_start[arg0]) / 1000);
    transfer_start[arg0] = 0;
}

usb:::transfer-done
/* @bsdinstruments-predicate */
{
    @status[arg1, arg2, arg3] = count();
}

usb:::endpoint-stalled
/* @bsdinstruments-predicate */
{
    @stalled[arg1] = count();
}
