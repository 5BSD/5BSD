#!/usr/sbin/dtrace -s
/*
 * netgraph_l2cap.d - trace the kernel L2CAP layer (ng_l2cap) via the
 * `bluetooth` SDT provider.
 *
 * blued's userland side sees only sockets; the real L2CAP signaling, credit
 * accounting, ECRED reconfigure, RTX/command timers and connection-fail flush
 * live here.  This is the kernel companion to l2cap.d.  Probes marked (wave)
 * are added by the kernel SDT instrumentation wave (taxonomy sec.11); the
 * data:send/recv and channel:close probes are live today.
 *
 * Usage (system-wide, needs privilege):
 *     dtrace -s netgraph_l2cap.d
 */

#pragma D option quiet

dtrace:::BEGIN
{
	printf("%-14s %-22s %s\n", "TIME(us)", "L2CAP(kernel)", "DETAIL");
}

/* ---- live today ---- */

bluetooth:l2cap:data:send
{
	printf("%-14d %-22s handle=0x%04x cid=0x%04x len=%d\n", timestamp/1000,
	    "data-send", arg0, arg1, arg2);
	@tx = sum(arg2); @txn = count();
}

bluetooth:l2cap:data:recv
{
	printf("%-14d %-22s handle=0x%04x cid=0x%04x len=%d\n", timestamp/1000,
	    "data-recv", arg0, arg1, arg2);
	@rx = sum(arg2); @rxn = count();
}

bluetooth:l2cap:channel:close
{
	printf("%-14d %-22s scid=0x%04x dcid=0x%04x\n", timestamp/1000,
	    "chan-close", arg0, arg1);
}

/* ---- added by the SDT wave ---- */

bluetooth:l2cap:channel:open
{
	printf("%-14d %-22s scid=0x%04x dcid=0x%04x psm=0x%04x\n", timestamp/1000,
	    "chan-open", arg0, arg1, arg2);
}

bluetooth:l2cap:channel:config
{
	printf("%-14d %-22s scid=0x%04x dcid=0x%04x imtu=%d omtu=%d\n",
	    timestamp/1000, "chan-config", arg0, arg1, arg2, arg3);
}

bluetooth:l2cap:credit:grant
{
	printf("%-14d %-22s scid=0x%04x credits=%d total=%d\n", timestamp/1000,
	    "credit-grant", arg0, arg1, arg2);
	@granted = sum(arg1);
}

bluetooth:l2cap:credit:consume
{
	printf("%-14d %-22s scid=0x%04x remaining=%d\n", timestamp/1000,
	    "credit-consume", arg0, arg1);
	/* flag credit exhaustion (peer flow-control stall) */
	@exhausted = sum(arg1 == 0 ? 1 : 0);
}

bluetooth:l2cap:ecred:req
{
	printf("%-14d %-22s ident=%d psm=0x%04x count=%d mtu=%d mps=%d\n",
	    timestamp/1000, "ecred-req", arg0, arg1, arg2, arg3, arg4);
}

bluetooth:l2cap:ecred:rsp
{
	printf("%-14d %-22s ident=%d result=0x%04x\n", timestamp/1000,
	    "ecred-rsp", arg0, arg1);
}

bluetooth:l2cap:ecred:reconfig
{
	printf("%-14d %-22s ident=%d mtu=%d mps=%d\n", timestamp/1000,
	    "ecred-reconfig", arg0, arg1, arg2);
}

bluetooth:l2cap:cmd:reject
{
	printf("%-14d %-22s ident=%d reason=0x%04x\n", timestamp/1000,
	    "cmd-reject", arg0, arg1);
}

bluetooth:l2cap:cmd:rtx
{
	printf("%-14d %-22s code=0x%02x ident=%d timo=%d (RTX armed)\n",
	    timestamp/1000, "cmd-rtx-arm", arg0, arg1, arg2);
}

bluetooth:l2cap:cmd:timeout
{
	printf("%-14d %-22s code=0x%02x ident=%d (RTX fired)\n", timestamp/1000,
	    "cmd-timeout", arg0, arg1);
	@timeouts = count();
}

bluetooth:l2cap:con:fail
{
	printf("%-14d %-22s result=0x%04x (connection flushed)\n", timestamp/1000,
	    "con-fail", arg0);
	@confail = count();
}

dtrace:::END
{
	printf("\n==== L2CAP kernel summary ====\n");
	printa("data send: %@d bytes in %@d pkts\n", @tx, @txn);
	printa("data recv: %@d bytes in %@d pkts\n", @rx, @rxn);
	printa("credits granted : %@d\n", @granted);
	printa("credit exhaustions: %@d\n", @exhausted);
	printa("cmd timeouts (RTX fired): %@d\n", @timeouts);
	printa("connection failures: %@d\n", @confail);
}
