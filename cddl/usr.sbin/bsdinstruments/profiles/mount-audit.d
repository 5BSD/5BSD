/*
 * Mount audit — mount, unmount, chroot activity.
 *
 * Traces filesystem mount/unmount and chroot calls.
 * Important system-level activity stream for host
 * forensics and configuration drift detection.
 */

syscall::nmount:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: nmount\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::unmount:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: unmount(\"%s\")\n", execname, pid, copyinstr(arg0));
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::chroot:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: chroot(\"%s\")\n", execname, pid, copyinstr(arg0));
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
