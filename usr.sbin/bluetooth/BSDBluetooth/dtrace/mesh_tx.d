#!/usr/sbin/dtrace -s
/*
 * mesh_tx.d - trace a BLE Mesh message end-to-end through libmesh: upper
 * transport encrypt/decrypt, SAR segmentation/reassembly, network-layer
 * encrypt/decrypt (NID match + verdict), relay decision, replay protection,
 * IV-update / beacon acceptance and provisioning steps.
 *
 * This shows the OBSERVABLE protocol facts of a mesh transmit/receive --
 * source/dest, sequence, IV index, akf/szmic, opcodes, verdicts and reason
 * codes -- and NEVER key material.
 *
 * Provider: `mesh` (libmesh built with MESH_DTRACE_PROBES; see the libmesh
 * Makefile).  libmesh is a library, so attach to whatever process links it
 * (e.g. meshd or a mesh unit-test binary).
 *
 * Usage:
 *     dtrace -s mesh_tx.d -p $(pgrep meshd)
 *     dtrace -s mesh_tx.d -c ./mesh_sim_test
 *
 * Requires libmesh built with MESH_DTRACE_PROBES=1 (and MK_DTRACE != no).
 */

#pragma D option quiet

dtrace:::BEGIN
{
	printf("%-12s %-9s %-16s %s\n", "TIME(us)", "LAYER", "EVENT", "DETAIL");
	printf("tracing mesh tx/rx; ^C for summary\n");
}

/* ---- Upper transport (application/device-key CCM) ---- */
mesh$target:::mesh-transport-enc
{
	printf("%-12d %-9s %-16s akf=%d szmic=%d len=%d\n", timestamp/1000,
	    "transport", "UPPER-ENC", arg0, arg1, arg2);
}
mesh$target:::mesh-transport-dec
{
	printf("%-12d %-9s %-16s akf=%d verdict=%s\n", timestamp/1000,
	    "transport", "UPPER-DEC", arg0, arg1 == 0 ? "ok" : "MIC-FAIL");
	@dec[arg1 == 0 ? "ok" : "fail"] = count();
}
mesh$target:::mesh-transport-seg
{
	printf("%-12d %-9s %-16s seqzero=%d segN=%d (%d segments)\n",
	    timestamp/1000, "transport", "SAR-SEGMENT", arg0, arg2, arg2 + 1);
}
mesh$target:::mesh-transport-reasm
{
	printf("%-12d %-9s %-16s src=0x%04x segO=%d complete=%d\n",
	    timestamp/1000, "transport", "SAR-REASM", arg0, arg1, arg2);
}
mesh$target:::mesh-seg-ack
{
	printf("%-12d %-9s %-16s seqzero=%d blockack=0x%08x\n", timestamp/1000,
	    "transport", "SEG-ACK", arg0, arg1);
}

/* ---- Network layer ---- */
mesh$target:::mesh-net-encrypt
{
	printf("%-12d %-9s %-16s src=0x%04x dst=0x%04x seq=%d ttl=%d\n",
	    timestamp/1000, "network", "NET-ENCRYPT", arg0, arg1, arg2, arg3);
}
mesh$target:::mesh-net-decrypt
{
	printf("%-12d %-9s %-16s nid=0x%02x src=0x%04x verdict=%s\n",
	    timestamp/1000, "network", "NET-DECRYPT", arg0, arg1,
	    arg2 == 0 ? "ok" : "FAIL");
	@net[arg2 == 0 ? "ok" : "fail"] = count();
}
mesh$target:::mesh-net-nid-match
{
	printf("%-12d %-9s %-16s local=0x%02x pdu=0x%02x matched=%d\n",
	    timestamp/1000, "network", "NID-MATCH", arg0, arg1, arg2);
}
mesh$target:::mesh-net-relay
{
	printf("%-12d %-9s %-16s ttl=%d -> %d decision=%s\n", timestamp/1000,
	    "network", "RELAY", arg1, arg2, arg3 ? "RELAY" : "drop");
}

/* ---- Replay protection ---- */
mesh$target:::mesh-rpl-check
{
	printf("%-12d %-9s %-16s src=0x%04x seq=%d verdict=%s\n", timestamp/1000,
	    "rpl", "RPL-CHECK", arg0, arg1,
	    arg2 == 1 ? "accept" : (arg2 == 0 ? "REPLAY" : "full/unknown"));
	@rpl[arg2 == 1 ? "accept" : (arg2 == 0 ? "replay" : "reject")] = count();
}
mesh$target:::mesh-rpl-net-recv
{
	printf("%-12d %-9s %-16s src=0x%04x accepted=%d\n", timestamp/1000,
	    "rpl", "RPL-NET-RECV", arg0, arg1);
}

/* ---- IV update / secure network beacon ---- */
mesh$target:::mesh-iv-update-begin
{
	printf("%-12d %-9s %-16s iv %d -> %d (update in progress)\n",
	    timestamp/1000, "iv", "IV-BEGIN", arg0, arg1);
}
mesh$target:::mesh-iv-update-done
{
	printf("%-12d %-9s %-16s iv_index=%d (normal)\n", timestamp/1000,
	    "iv", "IV-DONE", arg0);
}
mesh$target:::mesh-iv-beacon
{
	printf("%-12d %-9s %-16s recv_iv=%d accepted=%d\n", timestamp/1000,
	    "iv", "IV-BEACON", arg0, arg1);
}
mesh$target:::mesh-beacon-auth
{
	printf("%-12d %-9s %-16s key_refresh=%d verdict=%s\n", timestamp/1000,
	    "beacon", "BEACON-AUTH", arg0, arg1 == 0 ? "ok" : "fail");
}

/* ---- Access / model dispatch ---- */
mesh$target:::mesh-access-dispatch
{
	printf("%-12d %-9s %-16s opcode=0x%06x src=0x%04x dst=0x%04x\n",
	    timestamp/1000, "access", "DISPATCH", arg0, arg1, arg2);
}

/* ---- Provisioning ---- */
mesh$target:::mesh-prov-step
{
	printf("%-12d %-9s %-16s type=%d role=%s\n", timestamp/1000, "prov",
	    "PROV-STEP", arg0, arg1 ? "device" : "provisioner");
}
mesh$target:::mesh-prov-failed
{
	printf("%-12d %-9s %-16s error_code=%d\n", timestamp/1000, "prov",
	    "PROV-FAILED", arg0);
}

dtrace:::END
{
	printf("\n==== mesh summary ====\n");
	printf("upper decrypt: ");  printa("%s=%@d ", @dec);  printf("\n");
	printf("net decrypt:   ");  printa("%s=%@d ", @net);  printf("\n");
	printf("rpl verdicts:  ");  printa("%s=%@d ", @rpl);  printf("\n");
}
