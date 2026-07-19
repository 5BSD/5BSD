#!/usr/sbin/dtrace -s
/*
 * mesh.d - trace a BLE Mesh PDU as it flows through the libmesh layers:
 * network (obfuscate/encrypt/decrypt + NID match + relay), lower/upper
 * transport (SAR seg/reasm + CCM), access/model dispatch, RPL accept/reject,
 * IV update, key refresh, secure beacon auth, friendship and provisioning.
 *
 * Probes come from the `mesh` USDT provider (mesh_provider.d), so target the
 * process that links libmesh:
 *     dtrace -s mesh.d -p $(pgrep blued)
 *     dtrace -s mesh.d -p <pid-of-mesh-app>
 *
 * Requires libmesh built with USDT and its call sites in place.
 */

#pragma D option quiet

dtrace:::BEGIN
{
	prov[0]="Invite"; prov[1]="Capabilities"; prov[2]="Start";
	prov[3]="PublicKey"; prov[4]="InputComplete"; prov[5]="Confirmation";
	prov[6]="Random"; prov[7]="Data"; prov[8]="Complete"; prov[9]="Failed";
	printf("%-14s %-22s %s\n", "TIME(us)", "MESH", "DETAIL");
}

/* ---- Network layer ---- */

mesh$target:::mesh-net-encrypt
{
	printf("%-14d %-22s src=0x%04x dst=0x%04x seq=%d ttl=%d\n",
	    timestamp/1000, "net:encrypt", arg0, arg1, arg2, arg3);
	@tx = count();
}

mesh$target:::mesh-net-decrypt
{
	printf("%-14d %-22s nid=0x%02x src=0x%04x result=%s\n", timestamp/1000,
	    "net:decrypt", arg0, arg1, arg2 == 0 ? "ok" : "FAIL");
	@dec[arg2 == 0 ? "ok" : "fail"] = count();
}

mesh$target:::mesh-net-nid-match
{
	printf("%-14d %-22s local_nid=0x%02x pdu_nid=0x%02x matched=%d\n",
	    timestamp/1000, "net:nid-match", arg0, arg1, arg2);
}

mesh$target:::mesh-net-relay
{
	printf("%-14d %-22s src=0x%04x ttl=%d->%d decision=%s\n", timestamp/1000,
	    "net:relay", arg0, arg1, arg2, arg3 ? "RELAY" : "drop");
	@relay[arg3 ? "relay" : "drop"] = count();
}

/* ---- Transport layer ---- */

mesh$target:::mesh-transport-enc
{
	printf("%-14d %-22s akf=%d szmic=%d len=%d\n", timestamp/1000,
	    "transport:enc", arg0, arg1, arg2);
}

mesh$target:::mesh-transport-dec
{
	printf("%-14d %-22s akf=%d result=%s\n", timestamp/1000, "transport:dec",
	    arg0, arg1 == 0 ? "ok" : "FAIL");
}

mesh$target:::mesh-transport-seg
{
	printf("%-14d %-22s seqzero=%d seg %d/%d\n", timestamp/1000,
	    "transport:seg", arg0, arg1, arg2);
}

mesh$target:::mesh-transport-reasm
{
	printf("%-14d %-22s src=0x%04x seg=%d complete=%d\n", timestamp/1000,
	    "transport:reasm", arg0, arg1, arg2);
}

mesh$target:::mesh-seg-ack
{
	printf("%-14d %-22s seqzero=%d blockack=0x%08x\n", timestamp/1000,
	    "transport:seg-ack", arg0, arg1);
}

/* ---- Access / model ---- */

mesh$target:::mesh-access-dispatch
{
	printf("%-14d %-22s opcode=0x%06x src=0x%04x dst=0x%04x\n",
	    timestamp/1000, "access:dispatch", arg0, arg1, arg2);
	@op[arg0] = count();
}

mesh$target:::mesh-model-recv
{
	printf("%-14d %-22s opcode=0x%06x src=0x%04x\n", timestamp/1000,
	    "model:recv", arg0, arg1);
}

mesh$target:::mesh-cfg-appkey
{
	printf("%-14d %-22s opcode=0x%06x net_idx=%d app_idx=%d\n",
	    timestamp/1000, "cfg:appkey", arg0, arg1, arg2);
}

/* ---- RPL ---- */

mesh$target:::mesh-rpl-check,
mesh$target:::mesh-rpl-net-recv
{
	printf("%-14d %-22s src=0x%04x seq=%d %s\n", timestamp/1000, "rpl:check",
	    arg0, arg1, arg2 ? "ACCEPT" : "REJECT(replay)");
	@rpl[arg2 ? "accept" : "reject"] = count();
}

/* ---- IV update / key refresh ---- */

mesh$target:::mesh-iv-update-begin
{
	printf("%-14d %-22s iv 0x%08x -> 0x%08x (update in progress)\n",
	    timestamp/1000, "iv:update-begin", arg0, arg1);
}

mesh$target:::mesh-iv-update-done
{
	printf("%-14d %-22s iv_index=0x%08x (normal operation)\n",
	    timestamp/1000, "iv:update-done", arg0);
}

mesh$target:::mesh-iv-beacon
{
	printf("%-14d %-22s recv_iv=0x%08x accepted=%d\n", timestamp/1000,
	    "iv:beacon", arg0, arg1);
}

mesh$target:::mesh-keyrefresh-phase
{
	printf("%-14d %-22s phase %d -> %d\n", timestamp/1000,
	    "keyrefresh:phase", arg0, arg1);
}

mesh$target:::mesh-beacon-auth
{
	printf("%-14d %-22s key_refresh=%d auth=%s\n", timestamp/1000,
	    "beacon:auth", arg0, arg1 == 0 ? "ok" : "FAIL");
}

/* ---- Friendship ---- */

mesh$target:::mesh-friend-request
{
	printf("%-14d %-22s lpn=0x%04x criteria=0x%02x\n", timestamp/1000,
	    "friend:request", arg0, arg1);
}

mesh$target:::mesh-friend-offer
{
	printf("%-14d %-22s friend=0x%04x queue_size=%d\n", timestamp/1000,
	    "friend:offer", arg0, arg1);
}

mesh$target:::mesh-friend-poll
{
	printf("%-14d %-22s lpn=0x%04x fsn=%d\n", timestamp/1000, "friend:poll",
	    arg0, arg1);
}

/* ---- Provisioning ---- */

mesh$target:::mesh-prov-step
{
	printf("%-14d %-22s %s (role=%s)\n", timestamp/1000, "prov:step",
	    prov[arg0] != "" ? prov[arg0] : "?",
	    arg1 ? "provisioner" : "device");
	@prov[prov[arg0] != "" ? prov[arg0] : "?"] = count();
}

mesh$target:::mesh-prov-failed
{
	printf("%-14d %-22s error_code=0x%02x\n", timestamp/1000, "prov:failed",
	    arg0);
}

/* ---- Proxy ---- */

mesh$target:::mesh-proxy-pdu
{
	printf("%-14d %-22s type=%d len=%d\n", timestamp/1000, "proxy:pdu", arg0,
	    arg1);
}

dtrace:::END
{
	printf("\n==== Mesh summary ====\n");
	printa("net PDUs encrypted (tx): %@d\n", @tx);
	printf("net decrypt:\n");
	printa("  %-6s %@d\n", @dec);
	printf("relay decisions:\n");
	printa("  %-6s %@d\n", @relay);
	printf("RPL:\n");
	printa("  %-8s %@d\n", @rpl);
	printf("access opcodes (top):\n");
	printa("  0x%-8x %@d\n", @op);
	printf("provisioning steps:\n");
	printa("  %-14s %@d\n", @prov);
}
