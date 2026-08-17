/*
 * Kernel module audit — kldload, kldunload, kldfirstmod, modfind, kldstat.
 *
 * Traces kernel module lifecycle events. Useful for host
 * forensics and drift detection — shows who loaded or
 * unloaded kernel modules and when. FreeBSD-specific.
 */

syscall::kldload:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: kldload(\"%s\")\n", execname, pid, copyinstr(arg0));
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::kldunload:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: kldunload fileid=%d\n", execname, pid, arg0);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::kldfirstmod:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: kldfirstmod fileid=%d\n", execname, pid, arg0);
}

syscall::modfind:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: modfind(\"%s\")\n", execname, pid, copyinstr(arg0));
}

syscall::kldstat:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: kldstat fileid=%d\n", execname, pid, arg0);
}
