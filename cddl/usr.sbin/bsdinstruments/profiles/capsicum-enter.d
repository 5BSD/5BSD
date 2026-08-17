/*
 * Capsicum capability mode entry tracking.
 *
 * Traces cap_enter calls and subsequent syscall failures due
 * to capability restrictions (ECAPMODE / ENOTCAPABLE).
 * Helps identify sandboxing gaps. FreeBSD-specific.
 */

syscall::cap_enter:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: cap_enter\n", execname, pid);
    @enters[execname] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall:::return
/errno == 94 /* @bsdinstruments-predicate-and *//
{
    printf("%s[%d]: %s ENOTCAPABLE\n", execname, pid, probefunc);
    @enotcapable[execname, probefunc] = count();
}

syscall:::return
/errno == 93 /* @bsdinstruments-predicate-and *//
{
    printf("%s[%d]: %s ECAPMODE\n", execname, pid, probefunc);
    @ecapmode[execname, probefunc] = count();
}

dtrace:::END
{
    printf("\n--- cap_enter by process ---\n");
    printa("%-30s %@d\n", @enters);
    printf("\n--- ENOTCAPABLE failures ---\n");
    printa("%-20s %-20s %@d\n", @enotcapable);
    printf("\n--- ECAPMODE failures ---\n");
    printa("%-20s %-20s %@d\n", @ecapmode);
}
