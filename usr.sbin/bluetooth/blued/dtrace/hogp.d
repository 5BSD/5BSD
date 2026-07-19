#!/usr/sbin/dtrace -s
/*
 * hogp.d - trace HID-over-GATT (HOGP) flow in blued: report-map parse,
 * report classification, protocol-mode selection, CCCD subscribe, and the
 * input-report -> vhid delivery path.
 *
 * Usage:
 *     dtrace -s hogp.d -p $(pgrep blued)
 *
 * Requires blued built -DWITH_DTRACE.
 */

#pragma D option quiet
#pragma D option strsize=32

dtrace:::BEGIN
{
	rt[1]="Input"; rt[2]="Output"; rt[3]="Feature";
	pm[0]="Boot"; pm[1]="Report";
	printf("%-14s %-20s %s\n", "TIME(us)", "HOGP", "DETAIL");
}

blued$target:::hogp-discover
{
	printf("%-14d %-20s nreports=%d report_map_len=%d\n", timestamp/1000,
	    "discover", arg0, arg1);
}

blued$target:::hogp-map-parse
{
	printf("%-14d %-20s report_map bytes=%d\n", timestamp/1000, "map:parse",
	    arg0);
}

blued$target:::hogp-report-classify
{
	printf("%-14d %-20s report_id=%d type=%s value_handle=0x%04x\n",
	    timestamp/1000, "report:classify", arg0,
	    rt[arg1] != "" ? rt[arg1] : "?", arg2);
	@reports[rt[arg1] != "" ? rt[arg1] : "?"] = count();
}

blued$target:::hogp-protomode
{
	printf("%-14d %-20s mode=%s\n", timestamp/1000, "protocol-mode",
	    pm[arg0] != "" ? pm[arg0] : "?");
}

blued$target:::hogp-boot-setup
{
	printf("%-14d %-20s boot fallback, report_type=%s\n", timestamp/1000,
	    "boot:setup", rt[arg0] != "" ? rt[arg0] : "?");
}

blued$target:::hogp-subscribe
{
	printf("%-14d %-20s report_id=%d cccd_handle=0x%04x (notify on)\n",
	    timestamp/1000, "subscribe", arg0, arg1);
	@subs = count();
}

blued$target:::hid-report
{
	printf("%-14d %-20s report_id=%d len=%d\n", timestamp/1000,
	    "input:notify", arg0, arg1);
	@in = count();
	@bytes = sum(arg1);
}

blued$target:::hogp-vhid-write
{
	printf("%-14d %-20s report_id=%d len=%d status=%d%s\n", timestamp/1000,
	    "vhid:write", arg0, arg1, arg2, arg2 < 0 ? "  <-- FAILED" : "");
	@vhid[arg2 < 0 ? "fail" : "ok"] = count();
}

dtrace:::END
{
	printf("\n==== HOGP summary ====\n");
	printf("reports discovered by type:\n");
	printa("  %-8s %@d\n", @reports);
	printa("\nsubscriptions: %@d\n", @subs);
	printa("input notifications: %@d (%@d bytes)\n", @in, @bytes);
	printf("vhid writes:\n");
	printa("  %-4s %@d\n", @vhid);
}
