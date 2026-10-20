/*
 * pf audit - packet verdicts by interface and direction, and pf
 * configuration changes (ioctls and ruleset transactions).
 *
 * Uses the pf SDT provider (dtrace_pf(4)).  Requires pf loaded.
 */

pf:ip:test:finish
/* @bsdinstruments-predicate */
{
	@verdicts[stringof(args[2]->if_xname),
	    arg1 == 1 ? "in" : arg1 == 2 ? "out" : "fwd",
	    arg0 == 0 ? "pass" : arg0 == 1 ? "block" : "other"] = count();
}

pf:ioctl:xact:begin
{
	printf("%Y %s[%d] begin ruleset %s\n", walltimestamp, execname, pid,
	    stringof(arg0));
}

pf:ioctl:xact:commit
{
	printf("%Y %s[%d] commit ruleset %s\n", walltimestamp, execname, pid,
	    stringof(arg1));
}

pf:ioctl:ioctl:return
/arg2 != 0/
{
	@ioctl_errors[execname, arg0, arg2] = count();
}

dtrace:::END
{
	printf("\n--- verdicts (interface, direction, action) ---\n");
	printa("  %-12s %-4s %-6s %@d\n", @verdicts);
	printf("\n--- failed pf ioctls (program, cmd, errno) ---\n");
	printa("  %-16s 0x%x %d %@d\n", @ioctl_errors);
}
