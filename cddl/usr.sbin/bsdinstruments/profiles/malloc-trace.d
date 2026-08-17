/*
 * Trace user-space malloc/free calls for a specific process.
 * Usage: bsdinstruments watch malloc-trace --param pid=<pid>
 */

pid${pid}::malloc:entry
{
    printf("%s[%d]: malloc(%d)\n", execname, pid, arg0);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

pid${pid}::free:entry
{
    printf("%s[%d]: free(0x%p)\n", execname, pid, arg0);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
