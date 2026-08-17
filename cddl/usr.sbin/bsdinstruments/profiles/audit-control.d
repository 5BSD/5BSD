/*
 * OpenBSM audit control — auditon, auditctl, setaudit, setauid.
 *
 * Traces the audit subsystem control plane. Shows who is
 * modifying audit policy, rotating audit trails, or changing
 * audit session state. Essential for host security forensics.
 * FreeBSD-specific (OpenBSM).
 */

syscall::auditon:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: auditon cmd=%d\n", execname, pid, arg0);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::auditctl:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: auditctl(\"%s\")\n", execname, pid, copyinstr(arg0));
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::setaudit:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: setaudit\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::setaudit_addr:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: setaudit_addr\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::setauid:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: setauid\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::getaudit:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: getaudit\n", execname, pid);
}

syscall::getaudit_addr:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: getaudit_addr\n", execname, pid);
}

syscall::getauid:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: getauid\n", execname, pid);
}
