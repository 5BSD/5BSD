/*
 * pf state lifecycle - state creation, insertion, protocol state
 * transitions, removal and purge activity (dtrace_pf(4)).
 */

pf:state:state:create
/* @bsdinstruments-predicate */
{
	@ops["create"] = count();
}
pf:state:state:insert	{ @ops["insert"] = count(); }
pf:state:state:remove	{ @ops["remove"] = count(); }
pf:state:state:free	{ @ops["free"] = count(); }
pf:state:purge:run	{ @purge = count(); }

pf:state:state:transition
{
	@transitions[arg1 == 0 ? "src" : "dst", arg2] = count();
}

dtrace:::END
{
	printf("\n--- state operations ---\n");
	printa("  %-8s %@d\n", @ops);
	printf("\n--- protocol state transitions (peer, new state) ---\n");
	printa("  %-4s %-3d %@d\n", @transitions);
	printa("\n  purge passes %@d\n", @purge);
}
