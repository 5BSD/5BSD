/*
 * dynamic_claims.d — trace the full dynamic claim lifecycle.
 *
 * Shows auto-claim on mint, explicit claim/release operations,
 * refcount changes, and dispatch timing for claim/release opcodes.
 *
 * Usage:
 *   dtrace -s dynamic_claims.d
 *   dtrace -s dynamic_claims.d -p $(pgrep authorityd)
 */

#pragma D option quiet

dtrace:::BEGIN
{
	printf("%-20s %-8s %-40s %s\n",
	    "TIMESTAMP", "EVENT", "RESOURCE", "DETAIL");
	printf("%-20s %-8s %-40s %s\n",
	    "--------------------", "--------",
	    "----------------------------------------",
	    "--------------------");
}

/* --- Dynamic claim acquisition --- */

authorityd*:::dyn-claim-path
{
	printf("%-20Y %-8s %-40s result=%d\n",
	    walltimestamp, "CLAIM", copyinstr(arg0), arg1);
}

authorityd*:::dyn-claim-net
{
	printf("%-20Y %-8s port %d-%d proto=%d          result=%d\n",
	    walltimestamp, "CLAIM", arg0, arg1, arg2, arg3);
}

authorityd*:::dyn-claim-jail
{
	printf("%-20Y %-8s jail %-35s result=%d\n",
	    walltimestamp, "CLAIM", copyinstr(arg0), arg2);
}

authorityd*:::dyn-claim-system
{
	printf("%-20Y %-8s gates=0x%-32x result=%d\n",
	    walltimestamp, "CLAIM", arg0, arg1);
}

/* --- Dynamic claim release --- */

authorityd*:::dyn-release-path
{
	printf("%-20Y %-8s %-40s refcount=%d result=%d\n",
	    walltimestamp, "RELEASE", copyinstr(arg0), arg1, arg2);
}

authorityd*:::dyn-release-net
{
	printf("%-20Y %-8s port %d-%d proto=%d          refcount=%d result=%d\n",
	    walltimestamp, "RELEASE", arg0, arg1, arg2, arg3, arg4);
}

authorityd*:::dyn-release-jail
{
	printf("%-20Y %-8s jail %-35s refcount=%d result=%d\n",
	    walltimestamp, "RELEASE", copyinstr(arg0), arg2, arg3);
}

authorityd*:::dyn-release-system
{
	printf("%-20Y %-8s gates=0x%-4x released=0x%-18x result=%d\n",
	    walltimestamp, "RELEASE", arg0, arg1, arg2);
}

/* --- Dispatch timing for claim/release opcodes (11-18) --- */

authorityd*:::ipc-dispatch-done
/arg0 >= 11 && arg0 <= 18/
{
	printf("%-20Y %-8s op=%-2d status=%-4d               %d us\n",
	    walltimestamp, "DONE", arg0, arg1, arg2 / 1000);
}
