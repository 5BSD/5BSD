#!/usr/sbin/dtrace -s
/*
 * hci.d - trace HCI commands and LE events flowing through blued.
 *
 * Commands (send == command-complete/status, they are the same synchronous
 * call site), plus every LE meta subevent blued decodes: connection complete
 * with role, connection update, PHY update, remote features, LTK request,
 * encryption change, auth-payload timeout, and advertising reports.
 *
 * Usage:
 *     dtrace -s hci.d -p $(pgrep blued)
 *
 * Requires blued built -DWITH_DTRACE.
 */

#pragma D option quiet
#pragma D option strsize=32

dtrace:::BEGIN
{
	role[0] = "central"; role[1] = "peripheral";
	phy[1] = "1M"; phy[2] = "2M"; phy[3] = "Coded";
	printf("%-14s %-22s %s\n", "TIME(us)", "HCI-EVENT", "DETAIL");
}

blued$target:::hci-cmd-req
{
	printf("%-14d %-22s opcode=0x%04x status=0x%02x clen=%d\n",
	    timestamp/1000, "cmd:req", arg0, arg1, arg2);
	@cmds[arg0] = count();
	@cmdfail[arg0] = sum(arg1 != 0 ? 1 : 0);
}

blued$target:::hci-cmd-raw
{
	printf("%-14d %-22s opcode=0x%04x plen=%d\n", timestamp/1000,
	    "cmd:raw(async)", arg0, arg1);
}

blued$target:::hci-disconnect-req
{
	printf("%-14d %-22s handle=0x%04x reason=0x%02x\n", timestamp/1000,
	    "disconnect:req", arg0, arg1);
}

blued$target:::hci-le-conn-complete,
blued$target:::hci-le-enh-conn-complete
{
	printf("%-14d %-22s status=0x%02x handle=0x%04x role=%s interval=%d\n",
	    timestamp/1000, "le:conn-complete", arg0, arg1,
	    role[arg2] != "" ? role[arg2] : "?", arg3);
	@conns = count();
}

blued$target:::hci-le-conn-update
{
	printf("%-14d %-22s status=0x%02x handle=0x%04x interval=%d latency=%d\n",
	    timestamp/1000, "le:conn-update", arg0, arg1, arg2, arg3);
}

blued$target:::hci-le-phy-update
{
	printf("%-14d %-22s status=0x%02x handle=0x%04x tx=%s rx=%s\n",
	    timestamp/1000, "le:phy-update", arg0, arg1,
	    phy[arg2] != "" ? phy[arg2] : "?",
	    phy[arg3] != "" ? phy[arg3] : "?");
}

blued$target:::hci-le-remote-features
{
	printf("%-14d %-22s status=0x%02x handle=0x%04x features=0x%016x\n",
	    timestamp/1000, "le:remote-features", arg0, arg1, arg2);
}

blued$target:::hci-le-ltk-request
{
	printf("%-14d %-22s handle=0x%04x ediv=0x%04x rand=0x%016x\n",
	    timestamp/1000, "le:ltk-request", arg0, arg1, arg2);
}

blued$target:::hci-enc-change
{
	printf("%-14d %-22s status=0x%02x handle=0x%04x enabled=%d key_size=%d\n",
	    timestamp/1000, "enc-change", arg0, arg1, arg2, arg3);
}

blued$target:::hci-auth-payload-timeout
{
	printf("%-14d %-22s handle=0x%04x (LE ping lost -> disconnect)\n",
	    timestamp/1000, "auth-payload-timeout", arg0);
}

blued$target:::hci-le-set-phy
{
	printf("%-14d %-22s handle=0x%04x tx_phys=0x%02x rx_phys=0x%02x status=0x%02x\n",
	    timestamp/1000, "le:set-phy", arg0, arg1, arg2, arg3);
}

blued$target:::hci-le-data-length
{
	printf("%-14d %-22s handle=0x%04x tx_octets=%d tx_time=%d status=0x%02x\n",
	    timestamp/1000, "le:data-length", arg0, arg1, arg2, arg3);
}

blued$target:::hci-le-adv-report,
blued$target:::hci-le-ext-adv-report
{
	printf("%-14d %-22s addr=%s type=%d evt=0x%02x rssi=%d\n",
	    timestamp/1000, "le:adv-report", copyinstr(arg0), arg1, arg2,
	    (int)arg3);
	@adv = count();
}

dtrace:::END
{
	printf("\n==== HCI summary ====\n");
	printa("connections: %@d\n", @conns);
	printa("adv reports: %@d\n", @adv);
	printf("\ncommands by opcode (count / failures):\n");
	printa("  0x%-6x %@d\n", @cmds);
	printf("\ncommand failures by opcode:\n");
	printa("  0x%-6x %@d\n", @cmdfail);
}
