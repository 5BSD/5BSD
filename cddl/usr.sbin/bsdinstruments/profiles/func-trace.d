/*
 * Trace a specific user-space function in a process.
 * Usage: bsdinstruments watch func-trace --param pid=<pid> --param func=<function>
 */

pid${pid}::${func}:entry
{
    printf("%s[%d]: -> ${func}\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

pid${pid}::${func}:return
{
    printf("%s[%d]: <- ${func} = %d\n", execname, pid, arg1);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
