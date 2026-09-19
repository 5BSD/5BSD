#!/usr/sbin/dtrace -s
/*
 * power.d - trace LE Power Control (BT 5.2) in blued: path-loss zone
 * transitions, TX power reports, and the enhanced/remote TX power reads and
 * reporting-enable commands.
 *
 * Usage:
 *     dtrace -s power.d -p $(pgrep blued)
 *
 * Requires blued built -DWITH_DTRACE.
 */

#pragma D option quiet

dtrace:::BEGIN
{
	zone[0]="low"; zone[1]="mid"; zone[2]="high";
	rsn[0]="local"; rsn[1]="remote"; rsn[2]="read-complete";
	phy[1]="1M"; phy[2]="2M"; phy[3]="Coded";
	printf("%-14s %-20s %s\n", "TIME(us)", "POWER", "DETAIL");
}

blued$target:::power-path-loss
{
	printf("%-14d %-20s handle=0x%04x path_loss=%ddB zone=%s\n",
	    timestamp/1000, "path-loss", arg0, arg1,
	    zone[arg2] != "" ? zone[arg2] : "?");
	@zones[zone[arg2] != "" ? zone[arg2] : "?"] = count();
}

blued$target:::power-tx-report
{
	printf("%-14d %-20s handle=0x%04x reason=%s phy=%s tx_power=%ddBm\n",
	    timestamp/1000, "tx-report", arg0,
	    rsn[arg1] != "" ? rsn[arg1] : "?",
	    phy[arg2] != "" ? phy[arg2] : "?", (int)arg3);
	@reports = count();
}

blued$target:::power-tx-read
{
	printf("%-14d %-20s handle=0x%04x phy=%s level=%ddBm status=0x%02x\n",
	    timestamp/1000, "tx-read", arg0,
	    phy[arg1] != "" ? phy[arg1] : "?", (int)arg2, arg3);
}

blued$target:::power-pathloss-enable
{
	printf("%-14d %-20s handle=0x%04x enable=%d\n", timestamp/1000,
	    "pathloss-enable", arg0, arg1);
}

blued$target:::power-report-enable
{
	printf("%-14d %-20s handle=0x%04x local=%d remote=%d\n", timestamp/1000,
	    "report-enable", arg0, arg1, arg2);
}

dtrace:::END
{
	printf("\n==== Power summary ====\n");
	printf("path-loss zone entries:\n");
	printa("  %-6s %@d\n", @zones);
	printa("\ntx power reports: %@d\n", @reports);
}
