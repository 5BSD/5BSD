/*
 * Trace Python function calls via USDT probes.
 * Requires CPython built with --with-dtrace.
 * Usage: bsdinstruments watch python-calls --param pid=<python-pid>
 */

pid${pid}::function__entry:entry
{
    printf("python[%d]: -> %s:%s:%d\n",
        pid, copyinstr(arg0), copyinstr(arg1), arg2);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

pid${pid}::function__return:entry
{
    printf("python[%d]: <- %s:%s:%d\n",
        pid, copyinstr(arg0), copyinstr(arg1), arg2);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
