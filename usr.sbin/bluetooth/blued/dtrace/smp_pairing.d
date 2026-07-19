#!/usr/sbin/dtrace -s
/*
 * smp_pairing.d - trace a full LE SMP pairing handshake in blued.
 *
 * Shows method selection (IO caps -> association model), every SMP PDU in
 * and out, phase transitions, crypto steps, key distribution, encryption
 * start, and the pairing result (or Pairing-Failed reason / timeout).
 *
 * Usage:
 *     dtrace -s smp_pairing.d -p $(pgrep blued)
 *     dtrace -s smp_pairing.d -c '/usr/sbin/blued -f -d'
 *
 * Requires blued built -DWITH_DTRACE (MK_DTRACE != no).
 */

#pragma D option quiet
#pragma D option strsize=64

dtrace:::BEGIN
{
	smp_op[1]  = "PairingRequest";	smp_op[2]  = "PairingResponse";
	smp_op[3]  = "PairingConfirm";	smp_op[4]  = "PairingRandom";
	smp_op[5]  = "PairingFailed";	smp_op[6]  = "EncryptionInfo(LTK)";
	smp_op[7]  = "CentralIdent(EDIV/Rand)"; smp_op[8] = "IdentityInfo(IRK)";
	smp_op[9]  = "IdentityAddr";	smp_op[10] = "SigningInfo(CSRK)";
	smp_op[11] = "SecurityRequest"; smp_op[12] = "PublicKey";
	smp_op[13] = "DHKeyCheck";	smp_op[14] = "KeypressNotify";

	model[0] = "JustWorks";	 model[1] = "PasskeyEntry";
	model[2] = "NumericComparison"; model[3] = "OOB";

	kt[1] = "LTK"; kt[2] = "EDIV/Rand"; kt[3] = "IRK";
	kt[4] = "IdentityAddr"; kt[5] = "CSRK";

	fail[1]="PasskeyEntryFailed"; fail[2]="OOBNotAvailable";
	fail[3]="AuthRequirements"; fail[4]="ConfirmValueFailed";
	fail[5]="PairingNotSupported"; fail[6]="EncKeySize";
	fail[7]="CmdNotSupported"; fail[8]="Unspecified";
	fail[9]="RepeatedAttempts"; fail[10]="InvalidParameters";
	fail[11]="DHKeyCheckFailed"; fail[12]="NumericCompFailed";
	fail[15]="KeyRejected"; fail[16]="BusY";

	printf("%-14s %-4s %-18s %s\n", "TIME(us)", "DIR", "EVENT", "DETAIL");
	printf("tracing SMP; ^C for summary\n");
}

blued$target:::smp-method-select
{
	this->a = copyinstr(arg0);
	printf("%-14d %-4s %-18s init_io=%d resp_io=%d authreq=0x%02x model=%s [%s]\n",
	    timestamp/1000, "--", "method-select", arg1, arg2, arg3,
	    model[arg4] != "" ? model[arg4] : "?", this->a);
	@pairs = count();
}

blued$target:::smp-pair-start
{
	printf("%-14d %-4s %-18s model=%s addr=%s\n", timestamp/1000, "==",
	    "PAIR-START", model[arg1] != "" ? model[arg1] : "?",
	    copyinstr(arg0));
	self->t0 = timestamp;
}

blued$target:::smp-pdu-tx
{
	printf("%-14d %-4s %-18s %s len=%d\n", timestamp/1000, "TX",
	    smp_op[arg1] != "" ? smp_op[arg1] : "op?", "pdu", arg2);
	@op[smp_op[arg1] != "" ? smp_op[arg1] : "op?", "tx"] = count();
}

blued$target:::smp-pdu-rx
{
	printf("%-14d %-4s %-18s %s len=%d\n", timestamp/1000, "RX",
	    smp_op[arg1] != "" ? smp_op[arg1] : "op?", "pdu", arg2);
	@op[smp_op[arg1] != "" ? smp_op[arg1] : "op?", "rx"] = count();
}

blued$target:::smp-phase
{
	printf("%-14d %-4s %-18s %s\n", timestamp/1000, "..", "phase",
	    copyinstr(arg1));
}

blued$target:::smp-crypto
{
	printf("%-14d %-4s %-18s %s handle=0x%04x\n", timestamp/1000, "fn",
	    "crypto", copyinstr(arg0), arg1);
	@crypto[copyinstr(arg0)] = count();
}

blued$target:::smp-dhkey
{
	printf("%-14d %-4s %-18s P-256 ECDH complete addr=%s\n",
	    timestamp/1000, "fn", "dhkey", copyinstr(arg0));
}

/* key-dist / key-recv carry the SMP key-distribution opcode (6..10). */
blued$target:::smp-key-dist
{
	printf("%-14d %-4s %-18s %s -> peer\n", timestamp/1000, "TX",
	    "key-dist", smp_op[arg1] != "" ? smp_op[arg1] : "key?");
}

blued$target:::smp-key-recv
{
	printf("%-14d %-4s %-18s %s <- peer\n", timestamp/1000, "RX",
	    "key-recv", smp_op[arg1] != "" ? smp_op[arg1] : "key?");
}

blued$target:::encrypt-start
{
	printf("%-14d %-4s %-18s LE encryption started addr=%s\n",
	    timestamp/1000, "==", "ENCRYPT", copyinstr(arg0));
}

blued$target:::smp-pair-done
{
	printf("%-14d %-4s %-18s addr=%s status=%d\n", timestamp/1000, "==",
	    "PAIR-DONE", copyinstr(arg0), arg1);
	printf("            (elapsed %d us)\n",
	    self->t0 ? (timestamp - self->t0)/1000 : 0);
	self->t0 = 0;
	@done[arg1 == 0 ? "success" : "fail"] = count();
}

blued$target:::auth-fail
{
	printf("%-14d %-4s %-18s addr=%s reason=%s(0x%02x)\n", timestamp/1000,
	    "!!", "PAIRING-FAILED-TX", copyinstr(arg0),
	    fail[arg1] != "" ? fail[arg1] : "?", arg1);
	@fails[fail[arg1] != "" ? fail[arg1] : "?"] = count();
}

blued$target:::smp-fail-rx
{
	printf("%-14d %-4s %-18s addr=%s reason=%s(0x%02x)\n", timestamp/1000,
	    "!!", "PAIRING-FAILED-RX", copyinstr(arg0),
	    fail[arg1] != "" ? fail[arg1] : "?", arg1);
}

blued$target:::smp-timeout
{
	printf("%-14d %-4s %-18s addr=%s (30s SMP timeout)\n", timestamp/1000,
	    "!!", "TIMEOUT", copyinstr(arg0));
	@to = count();
}

dtrace:::END
{
	printf("\n==== SMP summary ====\n");
	printa("pairings started : %@d\n", @pairs);
	printf("\nPDUs by opcode/dir:\n");
	printa("  %-24s %-3s %@d\n", @op);
	printf("\ncrypto steps:\n");
	printa("  %-16s %@d\n", @crypto);
	printf("\nresults:\n");
	printa("  %-10s %@d\n", @done);
	printf("\nfailure reasons (tx):\n");
	printa("  %-24s %@d\n", @fails);
	printa("timeouts: %@d\n", @to);
}
