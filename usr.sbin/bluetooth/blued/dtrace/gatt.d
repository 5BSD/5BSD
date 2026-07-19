#!/usr/sbin/dtrace -s
/*
 * gatt.d - trace ATT PDUs, GATT discovery, notifications/indications,
 * CCCD subscriptions and Robust Caching state for blued.
 *
 * Decodes every ATT opcode in and out, error responses (with req opcode +
 * handle + error code), MTU exchange, notify/indicate/confirm, the change-
 * aware/change-unaware robust-caching transitions, and the seven GATT
 * discovery procedures.
 *
 * Usage:
 *     dtrace -s gatt.d -p $(pgrep blued)
 *
 * Requires blued built -DWITH_DTRACE.
 */

#pragma D option quiet
#pragma D option strsize=32

dtrace:::BEGIN
{
	op[0x01]="ErrorRsp";  op[0x02]="MTUReq";  op[0x03]="MTURsp";
	op[0x04]="FindInfoReq"; op[0x05]="FindInfoRsp";
	op[0x06]="FindByTypeValueReq"; op[0x07]="FindByTypeValueRsp";
	op[0x08]="ReadByTypeReq"; op[0x09]="ReadByTypeRsp";
	op[0x0a]="ReadReq"; op[0x0b]="ReadRsp"; op[0x0c]="ReadBlobReq";
	op[0x0d]="ReadBlobRsp"; op[0x0e]="ReadMultiReq"; op[0x0f]="ReadMultiRsp";
	op[0x10]="ReadByGroupTypeReq"; op[0x11]="ReadByGroupTypeRsp";
	op[0x12]="WriteReq"; op[0x13]="WriteRsp"; op[0x16]="PrepareWriteReq";
	op[0x17]="PrepareWriteRsp"; op[0x18]="ExecWriteReq";
	op[0x19]="ExecWriteRsp"; op[0x1b]="HandleNotify"; op[0x1d]="HandleInd";
	op[0x1e]="HandleConfirm"; op[0x20]="ReadMultiVarReq";
	op[0x21]="ReadMultiVarRsp"; op[0x23]="MultiHandleNotify";
	op[0x52]="WriteCmd"; op[0xd2]="SignedWriteCmd";

	err[0x01]="InvalidHandle"; err[0x02]="ReadNotPermitted";
	err[0x03]="WriteNotPermitted"; err[0x04]="InvalidPDU";
	err[0x05]="InsuffAuthen"; err[0x06]="ReqNotSupported";
	err[0x07]="InvalidOffset"; err[0x08]="InsuffAuthor";
	err[0x09]="PrepareQueueFull"; err[0x0a]="AttrNotFound";
	err[0x0b]="AttrNotLong"; err[0x0c]="InsuffEncKeySize";
	err[0x0d]="InvalidAttrLen"; err[0x0e]="UnlikelyError";
	err[0x0f]="InsuffEncryption"; err[0x10]="UnsupportedGroupType";
	err[0x11]="InsuffResources"; err[0x12]="DatabaseOutOfSync";
	err[0x13]="ValueNotAllowed";

	proc[1]="primary"; proc[2]="primary-uuid16"; proc[3]="primary-uuid128";
	proc[4]="secondary"; proc[5]="includes"; proc[6]="characteristics";
	proc[7]="descriptors";

	printf("%-14s %-4s %-22s %s\n", "TIME(us)", "DIR", "ATT", "DETAIL");
}

blued$target:::att-send
{
	printf("%-14d %-4s %-22s len=%d\n", timestamp/1000, "TX",
	    op[arg0] != "" ? op[arg0] : "op?", arg1);
	@ops[op[arg0] != "" ? op[arg0] : "op?", "tx"] = count();
}

blued$target:::att-recv
{
	printf("%-14d %-4s %-22s len=%d\n", timestamp/1000, "RX",
	    op[arg0] != "" ? op[arg0] : "op?", arg1);
	@ops[op[arg0] != "" ? op[arg0] : "op?", "rx"] = count();
}

blued$target:::att-error
{
	printf("%-14d %-4s %-22s req=%s handle=0x%04x code=%s\n", timestamp/1000,
	    "!!", "ErrorRsp(tx)", op[arg0] != "" ? op[arg0] : "op?", arg1,
	    err[arg2] != "" ? err[arg2] : "?");
	@errs[err[arg2] != "" ? err[arg2] : "?"] = count();
}

blued$target:::att-client-error
{
	printf("%-14d %-4s %-22s req=%s handle=0x%04x code=%s\n", timestamp/1000,
	    "!!", "ErrorRsp(rx)", op[arg0] != "" ? op[arg0] : "op?", arg1,
	    err[arg2] != "" ? err[arg2] : "?");
}

blued$target:::att-mtu
{
	printf("%-14d %-4s %-22s %s client=%d server=%d -> mtu=%d\n",
	    timestamp/1000, "==", "MTU-exchange",
	    arg0 == 0 ? "client" : "server", arg1, arg2, arg3);
}

blued$target:::att-notify
{
	printf("%-14d %-4s %-22s handle=0x%04x len=%d\n", timestamp/1000, "TX",
	    "Notify", arg0, arg1);
	@ntf = count();
}

blued$target:::att-indicate
{
	printf("%-14d %-4s %-22s handle=0x%04x len=%d\n", timestamp/1000, "TX",
	    "Indicate", arg0, arg1);
	@ind = count();
}

blued$target:::att-notify-multi
{
	printf("%-14d %-4s %-22s count=%d len=%d\n", timestamp/1000, "TX",
	    "MultiNotify", arg0, arg1);
}

blued$target:::att-confirm
{
	printf("%-14d %-4s %-22s handle=0x%04x\n", timestamp/1000, "RX",
	    "Confirm", arg0);
}

blued$target:::att-robust-transition
{
	printf("%-14d %-4s %-22s change_aware %d->%d trigger=0x%04x\n",
	    timestamp/1000, "..", "robust-cache", arg0, arg1, arg2);
}

blued$target:::att-cache-oos
{
	printf("%-14d %-4s %-22s handle=0x%04x (DatabaseOutOfSync 0x12)\n",
	    timestamp/1000, "!!", "cache:out-of-sync", arg0);
	@oos = count();
}

blued$target:::att-cache-aware
{
	printf("%-14d %-4s %-22s became change-aware trigger=%d\n",
	    timestamp/1000, "..", "cache:aware", arg0);
}

blued$target:::att-cache-invalidate
{
	printf("%-14d %-4s %-22s db changed, %d client(s) -> unaware\n",
	    timestamp/1000, "..", "cache:invalidate", arg0);
}

blued$target:::gatt-disc-step
{
	printf("%-14d %-4s %-22s proc=%s range=0x%04x-0x%04x found=%d\n",
	    timestamp/1000, "..", "discovery",
	    proc[arg0] != "" ? proc[arg0] : "?", arg1, arg2, arg3);
	@disc[proc[arg0] != "" ? proc[arg0] : "?"] = count();
}

blued$target:::gatt-svc-add
{
	printf("%-14d %-4s %-22s handle=0x%04x uuid=0x%04x\n", timestamp/1000,
	    "++", "svc:add", arg0, arg1);
}

blued$target:::gatt-svc-remove
{
	printf("%-14d %-4s %-22s handle=0x%04x\n", timestamp/1000, "--",
	    "svc:remove", arg0);
}

blued$target:::gatt-char-add
{
	printf("%-14d %-4s %-22s handle=0x%04x uuid=0x%04x props=0x%02x\n",
	    timestamp/1000, "++", "char:add", arg0, arg1, arg2);
}

blued$target:::gatt-cccd-write
{
	printf("%-14d %-4s %-22s handle=0x%04x value=0x%04x (%s)\n",
	    timestamp/1000, "..", "cccd:write", arg0, arg1,
	    (arg1 & 1) ? "notify" : ((arg1 & 2) ? "indicate" : "disabled"));
}

blued$target:::gatt-subscribe
{
	printf("%-14d %-4s %-22s addr=%s handle=0x%04x\n", timestamp/1000, "++",
	    "subscribe", copyinstr(arg0), arg1);
}

blued$target:::gatt-unsubscribe
{
	printf("%-14d %-4s %-22s addr=%s handle=0x%04x\n", timestamp/1000, "--",
	    "unsubscribe", copyinstr(arg0), arg1);
}

dtrace:::END
{
	printf("\n==== GATT/ATT summary ====\n");
	printf("ATT ops (opcode/dir):\n");
	printa("  %-22s %-3s %@d\n", @ops);
	printf("\nerrors:\n");
	printa("  %-22s %@d\n", @errs);
	printf("\ndiscovery procedures:\n");
	printa("  %-18s %@d\n", @disc);
	printa("\nnotifications: %@d\n", @ntf);
	printa("indications  : %@d\n", @ind);
	printa("out-of-sync  : %@d\n", @oos);
}
