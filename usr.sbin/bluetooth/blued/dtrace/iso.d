#!/usr/sbin/dtrace -s
/*
 * iso.d - trace LE Isochronous (CIS/BIG) command and event flow.
 *
 * Joins blued's userland ISO command wrappers (CIG params, CIS create/accept/
 * reject, BIG create/terminate, data-path setup) with the kernel
 * `bluetooth:hci:iso_*` and `bluetooth:socket:*:iso` SDT probes so the CIS/BIG
 * lifecycle is visible end to end.
 *
 * Usage:
 *     dtrace -s iso.d -p $(pgrep blued)
 *     dtrace -s iso.d                    # kernel iso probes are system-wide
 *
 * Userland probes require blued built -DWITH_DTRACE.
 */

#pragma D option quiet

dtrace:::BEGIN
{
	printf("%-14s %-22s %s\n", "TIME(us)", "ISO", "DETAIL");
}

/* ---- userland command wrappers ---- */

blued$target:::iso-cig-params
{
	printf("%-14d %-22s cig_id=%d cis_count=%d status=0x%02x\n",
	    timestamp/1000, "cig:params", arg0, arg1, arg2);
}

blued$target:::iso-cis-create
{
	printf("%-14d %-22s cis_count=%d status=0x%02x\n", timestamp/1000,
	    "cis:create", arg0, arg1);
}

blued$target:::iso-cis-accept
{
	printf("%-14d %-22s handle=0x%04x status=0x%02x\n", timestamp/1000,
	    "cis:accept", arg0, arg1);
}

blued$target:::iso-cis-reject
{
	printf("%-14d %-22s handle=0x%04x reason=0x%02x\n", timestamp/1000,
	    "cis:reject", arg0, arg1);
}

blued$target:::iso-cig-remove
{
	printf("%-14d %-22s cig_id=%d status=0x%02x\n", timestamp/1000,
	    "cig:remove", arg0, arg1);
}

blued$target:::iso-big-create
{
	printf("%-14d %-22s big_handle=%d adv_handle=%d status=0x%02x\n",
	    timestamp/1000, "big:create", arg0, arg1, arg2);
}

blued$target:::iso-big-terminate
{
	printf("%-14d %-22s big_handle=%d reason=0x%02x\n", timestamp/1000,
	    "big:terminate", arg0, arg1);
}

blued$target:::iso-datapath-setup
{
	printf("%-14d %-22s handle=0x%04x dir=%d path_id=%d\n", timestamp/1000,
	    "datapath:setup", arg0, arg1, arg2);
}

/* ---- userland event decode ---- */

blued$target:::iso-cis-established
{
	printf("%-14d %-22s handle=0x%04x status=0x%02x iso_interval=%d\n",
	    timestamp/1000, "evt:cis-established", arg0, arg1, arg2);
	@cis = count();
}

blued$target:::iso-cis-request
{
	printf("%-14d %-22s acl=0x%04x cis=0x%04x cig=%d cis_id=%d\n",
	    timestamp/1000, "evt:cis-request", arg0, arg1, arg2, arg3);
}

blued$target:::iso-big-complete
{
	printf("%-14d %-22s big_handle=%d status=0x%02x num_bis=%d\n",
	    timestamp/1000, "evt:big-complete", arg0, arg1, arg2);
	@big = count();
}

blued$target:::iso-big-sync
{
	printf("%-14d %-22s big_handle=%d status=0x%02x num_bis=%d\n",
	    timestamp/1000, "evt:big-sync", arg0, arg1, arg2);
}

/* ---- kernel ng_hci / ng_btsocket_iso (system-wide) ---- */

bluetooth:hci:iso_cis:established
{
	printf("%-14d %-22s handle=0x%04x status=0x%02x\n", timestamp/1000,
	    "K:cis-established", arg0, arg1);
}

bluetooth:hci:iso_cis:request
{
	printf("%-14d %-22s cis=0x%04x acl=0x%04x accepted=%d\n", timestamp/1000,
	    "K:cis-request", arg0, arg1, arg2);
}

bluetooth:hci:iso_big:complete,
bluetooth:hci:iso_big:sync
{
	printf("%-14d %-22s big_handle=%d status=0x%02x num_bis=%d\n",
	    timestamp/1000, "K:big", arg0, arg1, arg2);
}

bluetooth:socket:send:iso,
bluetooth:socket:recv:iso
{
	printf("%-14d %-22s handle=0x%04x len=%d\n", timestamp/1000, "K:iso-data",
	    arg0, arg1);
	@iso_bytes = sum(arg1);
}

dtrace:::END
{
	printf("\n==== ISO summary ====\n");
	printa("CIS established: %@d\n", @cis);
	printa("BIG complete   : %@d\n", @big);
	printa("ISO data bytes : %@d\n", @iso_bytes);
}
