/*
 * pf fragment reassembly - reassembly calls by direction and the
 * fragment-related drop reasons (PFRES_FRAG 2, PFRES_SHORT 3,
 * PFRES_MEMORY 5) recorded in pf_norm.c (dtrace_pf(4)).
 */

pf:frag:reassemble:entry, pf:frag:reassemble6:entry
/* @bsdinstruments-predicate */
{
	@calls[probefunc, arg1 == 1 ? "in" : "out"] = count();
}

pf::reason:set
/strstr(stringof(arg1), "pf_norm.c") != NULL/
{
	@drops[arg0, arg2] = count();
}

dtrace:::END
{
	printf("\n--- reassembly calls ---\n");
	printa("  %-12s %-4s %@d\n", @calls);
	printf("\n--- pf_norm.c reasons (PFRES code, line) ---\n");
	printa("  %-3d line %-5d %@d\n", @drops);
}
