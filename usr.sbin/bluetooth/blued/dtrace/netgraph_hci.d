#!/usr/sbin/dtrace -s
/*
 * netgraph_hci.d - trace the kernel HCI layer (ng_hci) via the `bluetooth`
 * SDT provider.
 *
 * This is the kernel companion to hci.d.  It sees what the userland daemon
 * cannot -- notably the HCI Disconnection-Complete reason code and the
 * controller-side connection/encryption events.  Probes marked (wave) are
 * added by the kernel SDT instrumentation wave (see the taxonomy sec.11);
 * the rest are live today.
 *
 * Usage (system-wide, needs privilege):
 *     dtrace -s netgraph_hci.d
 *
 * No target pid: SDT probes are kernel-global.
 */

#pragma D option quiet

dtrace:::BEGIN
{
	role[0]="central"; role[1]="peripheral";
	printf("%-14s %-24s %s\n", "TIME(us)", "HCI(kernel)", "DETAIL");
}

/* ---- live today ---- */

bluetooth:hci:le_connection:complete
{
	printf("%-14d %-24s handle=0x%04x role=%s\n", timestamp/1000,
	    "le-conn-complete", arg0, role[arg1] != "" ? role[arg1] : "?");
	@conns = count();
}

bluetooth:hci:le_connection:disconnect
{
	printf("%-14d %-24s handle=0x%04x\n", timestamp/1000, "le-disconnect",
	    arg0);
}

bluetooth:hci:le_connection:param_change
{
	printf("%-14d %-24s handle=0x%04x interval=%d latency=%d timeout=%d\n",
	    timestamp/1000, "param-change", arg0, arg1, arg2, arg3);
}

bluetooth:hci:encryption:change
{
	printf("%-14d %-24s handle=0x%04x enabled=%d\n", timestamp/1000,
	    "enc-change", arg0, arg1);
	@enc = count();
}

bluetooth:hci:le_data_length:change
{
	printf("%-14d %-24s handle=0x%04x tx_octets=%d rx_octets=%d\n",
	    timestamp/1000, "data-length", arg0, arg1, arg2);
}

bluetooth:hci:le_phy:update
{
	printf("%-14d %-24s handle=0x%04x tx_phy=%d rx_phy=%d\n", timestamp/1000,
	    "phy-update", arg0, arg1, arg2);
}

bluetooth:security:pairing:complete
{
	printf("%-14d %-24s handle=0x%04x key_size=%d\n", timestamp/1000,
	    "pairing-complete", arg0, arg1);
}

bluetooth:security:ltk:request
{
	printf("%-14d %-24s handle=0x%04x ediv=0x%04x rand=0x%016x\n",
	    timestamp/1000, "ltk-request", arg0, arg1, arg2);
}

bluetooth:security:auth_payload:timeout
{
	printf("%-14d %-24s handle=0x%04x\n", timestamp/1000,
	    "auth-payload-timeout", arg0);
}

/* ---- added by the SDT wave ---- */

bluetooth:hci:command:send
{
	printf("%-14d %-24s opcode=0x%04x\n", timestamp/1000, "cmd-send", arg0);
	@cmds[arg0] = count();
}

bluetooth:hci:command:complete,
bluetooth:hci:command:status
{
	printf("%-14d %-24s opcode=0x%04x status=0x%02x\n", timestamp/1000,
	    "cmd-complete", arg0, arg1);
	@cmdfail[arg0] = sum(arg1 != 0 ? 1 : 0);
}

bluetooth:hci:disconnect:complete
{
	printf("%-14d %-24s handle=0x%04x reason=0x%02x  <-- reason blued cannot see\n",
	    timestamp/1000, "disconnect-complete", arg0, arg1);
	@disc[arg1] = count();
}

bluetooth:hci:encryption:refresh
{
	printf("%-14d %-24s handle=0x%04x status=0x%02x\n", timestamp/1000,
	    "enc-key-refresh", arg0, arg1);
}

dtrace:::END
{
	printf("\n==== HCI kernel summary ====\n");
	printa("connections: %@d\n", @conns);
	printa("encryptions: %@d\n", @enc);
	printf("\ncommands by opcode:\n");
	printa("  0x%-6x %@d\n", @cmds);
	printf("\ndisconnect reasons:\n");
	printa("  0x%-4x %@d\n", @disc);
}
