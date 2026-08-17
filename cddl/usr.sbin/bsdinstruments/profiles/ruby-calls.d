/*
 * Trace Ruby method calls via USDT probes.
 * Requires Ruby built with --enable-dtrace.
 * Usage: bsdinstruments watch ruby-calls --param pid=<ruby-pid>
 */

pid${pid}::method__entry:entry
{
    printf("ruby[%d]: -> %s#%s (%s:%d)\n",
        pid, copyinstr(arg0), copyinstr(arg1),
        copyinstr(arg2), arg3);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

pid${pid}::method__return:entry
{
    printf("ruby[%d]: <- %s#%s (%s:%d)\n",
        pid, copyinstr(arg0), copyinstr(arg1),
        copyinstr(arg2), arg3);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
