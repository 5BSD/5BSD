#!/usr/sbin/dtrace -s
/*
 * conn.d - trace GAP connection lifecycle, advertising/scan state, and
 * privacy/RPA rotation in blued.
 *
 * Shows connection alloc/free, state transitions (IDLE/CONNECTING/ACTIVE/
 * RECONNECTING), open/close, advertising and scan enable/disable, and the
 * resolvable-private-address generate/rotate/resolve path.
 *
 * Usage:
 *     dtrace -s conn.d -p $(pgrep blued)
 *
 * Requires blued built -DWITH_DTRACE.
 */

#pragma D option quiet
#pragma D option strsize=32

dtrace:::BEGIN
{
	st[0]="IDLE"; st[1]="CONNECTING"; st[2]="ACTIVE"; st[3]="RECONNECTING";
	rl[0]="central"; rl[1]="peripheral";
	printf("%-14s %-18s %s\n", "TIME(us)", "EVENT", "DETAIL");
}

blued$target:::conn-alloc
{
	printf("%-14d %-18s active_count=%d\n", timestamp/1000, "conn:alloc",
	    arg0);
	@allocs = count();
}

blued$target:::conn-free
{
	printf("%-14d %-18s addr=%s\n", timestamp/1000, "conn:free",
	    copyinstr(arg0));
	@frees = count();
}

blued$target:::conn-state
{
	printf("%-14d %-18s handle=0x%04x %s -> %s\n", timestamp/1000,
	    "conn:state", arg0, st[arg1] != "" ? st[arg1] : "?",
	    st[arg2] != "" ? st[arg2] : "?");
}

blued$target:::conn-open
{
	printf("%-14d %-18s addr=%s role=%s\n", timestamp/1000, "conn:open",
	    copyinstr(arg0), rl[arg1] != "" ? rl[arg1] : "?");
	@opens[rl[arg1] != "" ? rl[arg1] : "?"] = count();
}

blued$target:::conn-close
{
	printf("%-14d %-18s addr=%s reason=0x%02x\n", timestamp/1000,
	    "conn:close", copyinstr(arg0), arg1);
	@closes = count();
}

blued$target:::gap-adv-params
{
	printf("%-14d %-18s interval=%d..%d\n", timestamp/1000, "adv:params",
	    arg0, arg1);
}

blued$target:::gap-adv-enable
{
	printf("%-14d %-18s enable=%d handle=%d\n", timestamp/1000, "adv:enable",
	    arg0, arg1);
	@adv[arg0 ? "on" : "off"] = count();
}

blued$target:::gap-adv-data
{
	printf("%-14d %-18s len=%d\n", timestamp/1000, "adv:data", arg0);
}

blued$target:::gap-scan-params
{
	printf("%-14d %-18s interval=%d window=%d\n", timestamp/1000,
	    "scan:params", arg0, arg1);
}

blued$target:::gap-scan-enable
{
	printf("%-14d %-18s enable=%d filter_dup=%d\n", timestamp/1000,
	    "scan:enable", arg0, arg1);
	@scan[arg0 ? "on" : "off"] = count();
}

blued$target:::scan-start
{
	printf("%-14d %-18s adapter=%s\n", timestamp/1000, "scan:start",
	    copyinstr(arg0));
}

blued$target:::scan-result
{
	printf("%-14d %-18s addr=%s rssi=%d\n", timestamp/1000, "scan:result",
	    copyinstr(arg0), (int)arg1);
	@results = count();
}

blued$target:::privacy-rpa-generate
{
	printf("%-14d %-18s rpa=%s\n", timestamp/1000, "rpa:generate",
	    copyinstr(arg0));
}

blued$target:::privacy-rpa-rotate
{
	printf("%-14d %-18s new rpa=%s\n", timestamp/1000, "rpa:rotate",
	    copyinstr(arg0));
	@rotations = count();
}

blued$target:::privacy-resolve
{
	printf("%-14d %-18s addr=%s matched=%d\n", timestamp/1000, "rpa:resolve",
	    copyinstr(arg0), arg1);
	@resolve[arg1 ? "matched" : "no-match"] = count();
}

blued$target:::privacy-reslist-load
{
	printf("%-14d %-18s entries=%d\n", timestamp/1000, "reslist:load", arg0);
}

dtrace:::END
{
	printf("\n==== conn/GAP summary ====\n");
	printa("conn allocs: %@d  frees: %@d\n", @allocs, @frees);
	printf("opens by role:\n");
	printa("  %-12s %@d\n", @opens);
	printa("closes: %@d\n", @closes);
	printf("adv enable:\n");
	printa("  %-4s %@d\n", @adv);
	printf("scan enable:\n");
	printa("  %-4s %@d\n", @scan);
	printa("scan results: %@d\n", @results);
	printa("RPA rotations: %@d\n", @rotations);
	printf("RPA resolve:\n");
	printa("  %-10s %@d\n", @resolve);
}
