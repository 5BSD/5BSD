/*
 * Capsicum capability mode audit.
 *
 * Traces cap_enter, cap_rights_limit, cap_ioctls_limit, and
 * cap_fcntls_limit calls. Shows which processes enter capability
 * mode and how they restrict their file descriptors.
 * FreeBSD-specific.
 */

syscall::cap_enter:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: cap_enter\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::cap_rights_limit:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: cap_rights_limit fd=%d\n", execname, pid, arg0);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::cap_ioctls_limit:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: cap_ioctls_limit fd=%d\n", execname, pid, arg0);
}

syscall::cap_fcntls_limit:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: cap_fcntls_limit fd=%d\n", execname, pid, arg0);
}

syscall::cap_enter:return
/arg1 == 0 /* @bsdinstruments-predicate-and *//
{
    @cap_enters[execname] = count();
}

dtrace:::END
{
    printf("\n--- cap_enter count by process ---\n");
    printa("%-30s %@d\n", @cap_enters);
}
