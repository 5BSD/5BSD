/*
 * pf drop reasons - every REASON_SET site in pf, with the PFRES_* code
 * and the source location that recorded it, plus blocked packets per
 * interface.  See dtrace_pf(4) for reason codes.
 */

pf::reason:set
/* @bsdinstruments-predicate */
{
	@reasons[arg0, stringof(arg1), arg2] = count();
}

pf:ip:test:finish
/arg0 == 1/
{
	@blocked[stringof(args[2]->if_xname),
	    arg1 == 1 ? "in" : arg1 == 2 ? "out" : "fwd"] = count();
}

dtrace:::END
{
	printf("\n--- reasons (PFRES code, file, line) ---\n");
	printa("  %-3d %s:%d %@d\n", @reasons);
	printf("\n--- blocked packets (interface, direction) ---\n");
	printa("  %-12s %-4s %@d\n", @blocked);
}
