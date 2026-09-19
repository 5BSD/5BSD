#!/usr/sbin/dtrace -s
/*
 * hci_conn.d - trace the HCI command path and LE connection/encryption
 * lifecycle in blued.
 *
 * Illuminates: every HCI command request funnelled through the command
 * chokepoint (opcode + controller status + parameter length), raw commands
 * (LE Start Encryption etc.), connection state transitions, and the
 * encryption-start boundary.  The controller-side LE Connection Complete /
 * Encryption Change events are decoded by the event agent's provider probes;
 * this script focuses on what the command encoders emit.
 *
 * Usage:
 *     dtrace -s hci_conn.d -p $(pgrep blued)
 *     dtrace -s hci_conn.d -c '/usr/sbin/blued -f -d'
 *
 * Requires blued built -DWITH_DTRACE (MK_DTRACE != no).
 */

#pragma D option quiet
#pragma D option strsize=64

dtrace:::BEGIN
{
	printf("%-12s %-6s %-18s %s\n", "TIME(us)", "KIND", "EVENT", "DETAIL");
	printf("tracing HCI command path; ^C for summary\n");
}

/* opcode = OGF<<10 | OCF; print raw hex, count by opcode. */
blued$target:::hci-cmd-req
{
	printf("%-12d %-6s %-18s opcode=0x%04x ogf=0x%02x ocf=0x%03x status=0x%02x clen=%d\n",
	    timestamp/1000, "cmd", "HCI-CMD",
	    arg0, (arg0 >> 10) & 0x3f, arg0 & 0x3ff, arg1, arg2);
	@cmds[arg0] = count();
	@bystatus[arg1] = count();
}

blued$target:::hci-cmd-raw
{
	printf("%-12d %-6s %-18s opcode=0x%04x plen=%d\n", timestamp/1000,
	    "raw", "HCI-CMD-RAW", arg0, arg1);
}

blued$target:::conn-open
{
	printf("%-12d %-6s %-18s addr=%s role=%s\n", timestamp/1000, "state",
	    "CONN-OPEN", copyinstr(arg0), arg1 ? "peripheral" : "central");
}
blued$target:::conn-state
{
	printf("%-12d %-6s %-18s handle=0x%04x %d -> %d\n", timestamp/1000,
	    "state", "CONN-STATE", arg0, arg1, arg2);
}
blued$target:::conn-close
{
	printf("%-12d %-6s %-18s addr=%s reason=0x%02x\n", timestamp/1000,
	    "state", "CONN-CLOSE", copyinstr(arg0), arg1);
}

blued$target:::encrypt-start
{
	printf("%-12d %-6s %-18s addr=%s\n", timestamp/1000, "sec",
	    "ENCRYPT-START", copyinstr(arg0));
}

/* These fire from the event agent's decode of controller events, if present. */
blued$target:::hci-le-conn-complete,
blued$target:::hci-le-enh-conn-complete
{
	printf("%-12d %-6s %-18s status=0x%02x handle=0x%04x role=%d interval=%d\n",
	    timestamp/1000, "evt", "LE-CONN-CMPL", arg0, arg1, arg2, arg3);
}
blued$target:::hci-enc-change
{
	printf("%-12d %-6s %-18s status=0x%02x handle=0x%04x enabled=%d keysz=%d\n",
	    timestamp/1000, "evt", "ENC-CHANGE", arg0, arg1, arg2, arg3);
}

dtrace:::END
{
	printf("\n==== HCI command summary ====\n");
	printf("commands by opcode:\n");
	printa("  0x%04x  %@d\n", @cmds);
	printf("commands by controller status:\n");
	printa("  0x%02x    %@d\n", @bystatus);
}
