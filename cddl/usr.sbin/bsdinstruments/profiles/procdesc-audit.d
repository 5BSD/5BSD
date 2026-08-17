/*
 * Process descriptor audit — pdfork, pdgetpid, pdkill.
 *
 * Capsicum's process descriptor facility. Complements
 * capsicum-audit for capability-oriented process management.
 * Process descriptors are waited on via standard wait4/waitpid.
 * FreeBSD-specific.
 */

syscall::pdfork:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: pdfork\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::pdgetpid:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: pdgetpid fd=%d\n", execname, pid, arg0);
}

syscall::pdkill:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: pdkill fd=%d sig=%d\n", execname, pid, arg0, arg1);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
