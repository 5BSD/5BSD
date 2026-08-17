/*
 * Trace a kernel function via FBT (function boundary tracing).
 * Usage: bsdinstruments watch kfunc-trace --param func=<kernel-function>
 */

fbt::${func}:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: -> ${func}\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::${func}:return
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: <- ${func} = %d\n", execname, pid, arg1);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
