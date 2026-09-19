#!/usr/sbin/dtrace -s
/*
 * hci_adv.d - trace the LE advertising and scanning lifecycle in blued.
 *
 * Illuminates: advertising set enable/disable (legacy set 0 and extended
 * sets by handle), advertising-data and parameter programming, scan
 * parameter and scan-enable transitions, scan results, and the RPA/privacy
 * resolving-list programming that underpins private advertising.
 *
 * Usage:
 *     dtrace -s hci_adv.d -p $(pgrep blued)
 *     dtrace -s hci_adv.d -c '/usr/sbin/blued -f -d'
 *
 * Requires blued built -DWITH_DTRACE (MK_DTRACE != no).
 */

#pragma D option quiet
#pragma D option strsize=64

dtrace:::BEGIN
{
	printf("%-12s %-6s %-16s %s\n", "TIME(us)", "KIND", "EVENT", "DETAIL");
	printf("tracing LE advertising/scanning; ^C for summary\n");
}

blued$target:::gap-adv-params
{
	printf("%-12d %-6s %-16s interval_min=%d interval_max=%d\n",
	    timestamp/1000, "adv", "ADV-PARAMS", arg0, arg1);
}
blued$target:::gap-adv-data
{
	printf("%-12d %-6s %-16s len=%d\n", timestamp/1000, "adv",
	    "ADV-DATA", arg0);
}
blued$target:::gap-adv-enable
{
	printf("%-12d %-6s %-16s %s handle=%d\n", timestamp/1000, "adv",
	    "ADV-ENABLE", arg0 ? "ENABLE" : "disable", arg1);
	@adv[arg0 ? "enable" : "disable"] = count();
}

blued$target:::gap-scan-params
{
	printf("%-12d %-6s %-16s interval=%d window=%d\n", timestamp/1000,
	    "scan", "SCAN-PARAMS", arg0, arg1);
}
blued$target:::gap-scan-enable
{
	printf("%-12d %-6s %-16s %s filter_dup=%d\n", timestamp/1000, "scan",
	    "SCAN-ENABLE", arg0 ? "ENABLE" : "disable", arg1);
}
blued$target:::scan-start
{
	printf("%-12d %-6s %-16s adapter=%s\n", timestamp/1000, "scan",
	    "SCAN-START", copyinstr(arg0));
}
blued$target:::scan-result
{
	printf("%-12d %-6s %-16s addr=%s rssi=%d\n", timestamp/1000, "scan",
	    "SCAN-RESULT", copyinstr(arg0), (int)arg1);
	@results = count();
}

blued$target:::privacy-reslist-load
{
	printf("%-12d %-6s %-16s +%d resolving-list entr%s\n", timestamp/1000,
	    "priv", "RESLIST", arg0, arg0 == 1 ? "y" : "ies");
}
blued$target:::privacy-rpa-rotate
{
	printf("%-12d %-6s %-16s new RPA=%s\n", timestamp/1000, "priv",
	    "RPA-ROTATE", copyinstr(arg0));
}
blued$target:::privacy-resolve
{
	printf("%-12d %-6s %-16s addr=%s matched=%d\n", timestamp/1000, "priv",
	    "RPA-RESOLVE", copyinstr(arg0), arg1);
}

dtrace:::END
{
	printf("\n==== advertising/scan summary ====\n");
	printa("adv %-8s %@d\n", @adv);
	printa("scan results: %@d\n", @results);
}
