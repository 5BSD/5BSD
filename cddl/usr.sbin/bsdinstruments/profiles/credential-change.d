/*
 * Credential change audit — setuid/setgid/setgroups/setlogin.
 *
 * Traces privilege escalation and de-escalation events.
 * Essential for security auditing and forensics on
 * multi-user systems.
 */

syscall::setuid:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: setuid(%d)\n", execname, pid, arg0);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::seteuid:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: seteuid(%d)\n", execname, pid, arg0);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::setgid:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: setgid(%d)\n", execname, pid, arg0);
}

syscall::setegid:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: setegid(%d)\n", execname, pid, arg0);
}

syscall::setgroups:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: setgroups ngroups=%d\n", execname, pid, arg0);
}

syscall::setlogin:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: setlogin(\"%s\")\n", execname, pid, copyinstr(arg0));
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::setresuid:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: setresuid(%d, %d, %d)\n",
        execname, pid, arg0, arg1, arg2);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::setresgid:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: setresgid(%d, %d, %d)\n",
        execname, pid, arg0, arg1, arg2);
}
