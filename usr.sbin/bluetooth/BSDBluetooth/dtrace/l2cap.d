#!/usr/sbin/dtrace -s
/*
 * l2cap.d - trace L2CAP channel and credit lifecycle for blued.
 *
 * NOTE: blued speaks L2CAP through SOCK_SEQPACKET sockets; the signaling,
 * credit accounting, K-frame segmentation/reassembly and RTX timers all live
 * in the kernel (ng_l2cap).  This script therefore joins the userland socket
 * seams (CoC/ECRED connect + reconfigure) with the kernel `bluetooth:l2cap:*`
 * SDT probes so you see the whole channel from both sides.  For the kernel
 * side alone (including the credit/reconfigure/con-fail probes added by the
 * SDT wave) use netgraph_l2cap.d.
 *
 * Usage:
 *     dtrace -s l2cap.d -p $(pgrep blued)   # userland seams + kernel data
 *     dtrace -s l2cap.d                     # kernel probes are system-wide
 *
 * Userland probes require blued built -DWITH_DTRACE.
 */

#pragma D option quiet

dtrace:::BEGIN
{
	printf("%-14s %-20s %s\n", "TIME(us)", "L2CAP", "DETAIL");
}

/* ---- userland (blued) socket seams ---- */

blued$target:::l2cap-coc-connect
{
	printf("%-14d %-20s psm=0x%04x mtu=%d addr_type=%d fd=%d\n",
	    timestamp/1000, "coc:connect", arg0, arg1, arg2, arg3);
	@coc = count();
}

blued$target:::l2cap-ecred-connect
{
	printf("%-14d %-20s psm=0x%04x mtu=%d req=%d opened=%d\n",
	    timestamp/1000, "ecred:connect", arg0, arg1, arg2, arg3);
	@ecred = count();
}

blued$target:::l2cap-ecred-reconfig
{
	printf("%-14d %-20s fd=%d mtu=%d mps=%d\n", timestamp/1000,
	    "ecred:reconfig", arg0, arg1, arg2);
}

blued$target:::l2cap-connparam-update
{
	printf("%-14d %-20s handle=0x%04x interval=%d..%d timeout=%d\n",
	    timestamp/1000, "connparam:update", arg0, arg1, arg2, arg3);
}

/* ---- kernel ng_l2cap (system-wide) ---- */

bluetooth:l2cap:data:send
{
	printf("%-14d %-20s handle=0x%04x cid=0x%04x len=%d\n", timestamp/1000,
	    "K:data-send", arg0, arg1, arg2);
	@ktx = sum(arg2);
}

bluetooth:l2cap:data:recv
{
	printf("%-14d %-20s handle=0x%04x cid=0x%04x len=%d\n", timestamp/1000,
	    "K:data-recv", arg0, arg1, arg2);
	@krx = sum(arg2);
}

bluetooth:l2cap:channel:close
{
	printf("%-14d %-20s scid=0x%04x dcid=0x%04x\n", timestamp/1000,
	    "K:chan-close", arg0, arg1);
}

/* The following fire once the kernel SDT wave lands (see taxonomy sec.11). */
bluetooth:l2cap:channel:open
{
	printf("%-14d %-20s scid=0x%04x dcid=0x%04x psm=0x%04x\n",
	    timestamp/1000, "K:chan-open", arg0, arg1, arg2);
}

bluetooth:l2cap:credit:grant
{
	printf("%-14d %-20s scid=0x%04x credits=%d total=%d\n", timestamp/1000,
	    "K:credit-grant", arg0, arg1, arg2);
	@grant = sum(arg1);
}

bluetooth:l2cap:credit:consume
{
	printf("%-14d %-20s scid=0x%04x remaining=%d\n", timestamp/1000,
	    "K:credit-consume", arg0, arg1);
}

bluetooth:l2cap:cmd:timeout
{
	printf("%-14d %-20s code=0x%02x ident=%d (RTX fired)\n", timestamp/1000,
	    "K:cmd-timeout", arg0, arg1);
}

bluetooth:l2cap:con:fail
{
	printf("%-14d %-20s result=0x%04x\n", timestamp/1000, "K:con-fail",
	    arg0);
}

dtrace:::END
{
	printf("\n==== L2CAP summary ====\n");
	printa("CoC connects   : %@d\n", @coc);
	printa("ECRED connects : %@d\n", @ecred);
	printa("kernel bytes tx: %@d\n", @ktx);
	printa("kernel bytes rx: %@d\n", @krx);
	printa("credits granted: %@d\n", @grant);
}
