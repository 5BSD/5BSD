#!/usr/sbin/dtrace -s
/*
 * att_gatt.d - trace ATT/GATT request-response, MTU, notify/indicate and
 * GATT Robust Caching in blued.
 *
 * Illuminates: every ATT PDU in/out (by opcode name), the MTU exchange from
 * both roles, server Error Responses with the spec error code, notifications
 * / indications with handle+length, CCCD subscription writes, the Database
 * Hash recomputation, and change-unaware (out-of-sync) rejections.
 *
 * Usage:
 *     dtrace -s att_gatt.d -p $(pgrep blued)
 *     dtrace -s att_gatt.d -c '/usr/sbin/blued -f -d'
 *
 * Requires blued built -DWITH_DTRACE (MK_DTRACE != no).
 */

#pragma D option quiet
#pragma D option strsize=64

dtrace:::BEGIN
{
	op[0x01]="ErrorRsp";        op[0x02]="MTU-Req";     op[0x03]="MTU-Rsp";
	op[0x04]="FindInfoReq";     op[0x05]="FindInfoRsp";
	op[0x06]="FindByTypeReq";   op[0x07]="FindByTypeRsp";
	op[0x08]="ReadByTypeReq";   op[0x09]="ReadByTypeRsp";
	op[0x0a]="ReadReq";         op[0x0b]="ReadRsp";
	op[0x0c]="ReadBlobReq";     op[0x0d]="ReadBlobRsp";
	op[0x0e]="ReadMultiReq";    op[0x0f]="ReadMultiRsp";
	op[0x10]="ReadByGroupReq";  op[0x11]="ReadByGroupRsp";
	op[0x12]="WriteReq";        op[0x13]="WriteRsp";
	op[0x16]="PrepWriteReq";    op[0x17]="PrepWriteRsp";
	op[0x18]="ExecWriteReq";    op[0x19]="ExecWriteRsp";
	op[0x1b]="HandleNotify";    op[0x1d]="HandleIndicate";
	op[0x1e]="HandleConfirm";   op[0x20]="ReadMultiVarReq";
	op[0x21]="ReadMultiVarRsp"; op[0x23]="MultiNotify";
	op[0x52]="WriteCmd";        op[0x1a]="ReadByGroupRsp";

	err[0x01]="InvalidHandle";      err[0x02]="ReadNotPermitted";
	err[0x03]="WriteNotPermitted";  err[0x04]="InvalidPDU";
	err[0x05]="InsufficientAuthn";  err[0x06]="ReqNotSupported";
	err[0x07]="InvalidOffset";      err[0x08]="InsufficientAuthz";
	err[0x09]="PrepQueueFull";      err[0x0a]="AttrNotFound";
	err[0x0b]="AttrNotLong";        err[0x0c]="InsuffEncKeySize";
	err[0x0d]="InvalidAttrValLen";  err[0x0e]="UnlikelyError";
	err[0x0f]="InsufficientEnc";    err[0x10]="UnsupportedGroupType";
	err[0x11]="InsuffResources";    err[0x12]="DatabaseOutOfSync";
	err[0x13]="ValueNotAllowed";

	role[0]="client"; role[1]="server";
	printf("%-12s %-4s %-16s %s\n", "TIME(us)", "DIR", "EVENT", "DETAIL");
}

blued$target:::att-recv
{
	printf("%-12d %-4s %-16s %s len=%d\n", timestamp/1000, "RX",
	    op[arg0] != "" ? op[arg0] : lltostr(arg0), "att-pdu", arg1);
	@in[op[arg0] != "" ? op[arg0] : lltostr(arg0)] = count();
}

blued$target:::att-send
{
	printf("%-12d %-4s %-16s %s len=%d\n", timestamp/1000, "TX",
	    op[arg0] != "" ? op[arg0] : lltostr(arg0), "att-pdu", arg1);
	@out[op[arg0] != "" ? op[arg0] : lltostr(arg0)] = count();
}

blued$target:::att-mtu
{
	printf("%-12d %-4s %-16s role=%s client=%d server=%d -> eff=%d\n",
	    timestamp/1000, "==", "MTU", role[arg0] != "" ? role[arg0] : "?",
	    arg1, arg2, arg3);
}

blued$target:::att-error
{
	printf("%-12d %-4s %-16s req=%s handle=0x%04x code=%s(0x%02x)\n",
	    timestamp/1000, "!!", "ERROR-RSP",
	    op[arg0] != "" ? op[arg0] : lltostr(arg0), arg1,
	    err[arg2] != "" ? err[arg2] : "?", arg2);
	@errs[err[arg2] != "" ? err[arg2] : lltostr(arg2)] = count();
}

blued$target:::att-notify
{
	printf("%-12d %-4s %-16s handle=0x%04x len=%d\n", timestamp/1000, "TX",
	    "NOTIFY", arg0, arg1);
}
blued$target:::att-indicate
{
	printf("%-12d %-4s %-16s handle=0x%04x len=%d\n", timestamp/1000, "TX",
	    "INDICATE", arg0, arg1);
}
blued$target:::att-notify-multi
{
	printf("%-12d %-4s %-16s count=%d len=%d\n", timestamp/1000, "TX",
	    "MULTI-NOTIFY", arg0, arg1);
}
blued$target:::att-confirm
{
	printf("%-12d %-4s %-16s handle=0x%04x\n", timestamp/1000, "RX",
	    "CONFIRM", arg0);
}

blued$target:::gatt-cccd-write
{
	printf("%-12d %-4s %-16s handle=0x%04x value=0x%04x (%s%s)\n",
	    timestamp/1000, "==", "CCCD", arg0, arg1,
	    (arg1 & 1) ? "notify " : "", (arg1 & 2) ? "indicate" : "");
}

blued$target:::att-cache-hash
{
	printf("%-12d %-4s %-16s db-hash recomputed (len=%d)\n",
	    timestamp/1000, "fn", "DB-HASH", arg0);
}
blued$target:::att-cache-oos
{
	printf("%-12d %-4s %-16s handle=0x%04x rejected: DatabaseOutOfSync\n",
	    timestamp/1000, "!!", "ROBUST-CACHE", arg0);
	@oos = count();
}
blued$target:::att-robust-transition
{
	printf("%-12d %-4s %-16s aware %d -> %d (trigger=0x%04x)\n",
	    timestamp/1000, "..", "CACHE-AWARE", arg0, arg1, arg2);
}

dtrace:::END
{
	printf("\n==== ATT/GATT summary ====\n");
	printf("PDUs received:\n");   printa("  %-20s %@d\n", @in);
	printf("PDUs sent:\n");       printa("  %-20s %@d\n", @out);
	printf("error responses:\n"); printa("  %-20s %@d\n", @errs);
	printa("out-of-sync rejections: %@d\n", @oos);
}
