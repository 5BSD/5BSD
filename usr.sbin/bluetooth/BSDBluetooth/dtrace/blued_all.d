#!/usr/sbin/dtrace -s
/*
 * blued_all.d - firehose: trace every blued USDT probe with a subsystem tag.
 *
 * This is the "show me everything happening" view.  Each line is tagged with
 * the subsystem (the first token of the probe name: hci, l2cap, att, gatt,
 * smp, conn, gap, privacy, hogp, iso, power, bond, ...) and prints the probe
 * name plus its raw arguments.  Integer args render in hex; string args (addr,
 * phase, step) render as pointers here -- use the per-subsystem scripts
 * (smp_pairing.d, gatt.d, hci.d, ...) for decoded, human-readable traces.
 *
 * Usage:
 *     dtrace -s blued_all.d -p $(pgrep blued)
 *     dtrace -s blued_all.d -p $(pgrep blued) | grep '^smp'   # one subsystem
 *
 * Requires blued built -DWITH_DTRACE.
 */

#pragma D option quiet
#pragma D option switchrate=10hz

dtrace:::BEGIN
{
	printf("%-14s %-10s %-28s %s\n", "TIME(us)", "SUBSYS", "PROBE",
	    "ARGS(hex)");
}

blued$target:::
{
	this->sub = strtok(probename, "-");
	printf("%-14d %-10s %-28s %x %x %x %x %x\n", timestamp/1000,
	    this->sub != NULL ? this->sub : probename, probename,
	    arg0, arg1, arg2, arg3, arg4);
	@bysub[this->sub != NULL ? this->sub : probename] = count();
	@byprobe[probename] = count();
}

dtrace:::END
{
	printf("\n==== firings by subsystem ====\n");
	printa("  %-12s %@d\n", @bysub);
	printf("\n==== firings by probe ====\n");
	printa("  %-30s %@d\n", @byprobe);
}
