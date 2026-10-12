/*
 * pf table lookups - lookups and statistics updates per table
 * (dtrace_pf(4)).
 */

pf:table:addr:match
/* @bsdinstruments-predicate */
{
	@lookups[stringof(args[0]->pfrkt_ts.pfrts_t.pfrt_name), arg2 == 2 ? "inet" : "inet6"] =
	    count();
}

pf:table:addr:update
{
	@updates[stringof(args[0]->pfrkt_ts.pfrts_t.pfrt_name)] = count();
}

dtrace:::END
{
	printf("\n--- table lookups (table, family) ---\n");
	printa("  %-32s %-6s %@d\n", @lookups);
	printf("\n--- table statistics updates ---\n");
	printa("  %-32s %@d\n", @updates);
}
