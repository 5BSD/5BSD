/*
 * Shell command line snoop via readline.
 *
 * Traces readline() return in a shell process to capture
 * every command entered. Useful for session auditing.
 * Usage: bsdinstruments watch bashreadline --param pid=<shell-pid>
 */

pid${pid}:libedit.so:readline:return,
pid${pid}:libreadline.so:readline:return,
pid${pid}::readline:return
{
    printf("%s[%d]: %s\n", execname, pid, copyinstr(arg1));
    @cmds[execname] = count();
}

dtrace:::END
{
    printf("\n--- Commands entered by process ---\n");
    printa("%-30s %@d\n", @cmds);
}
