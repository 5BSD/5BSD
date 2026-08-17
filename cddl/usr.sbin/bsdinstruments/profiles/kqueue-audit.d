/*
 * kqueue audit — kqueue creation and kevent registration.
 *
 * Traces kqueue(2) and kevent(2) calls to show event-queue
 * usage patterns. Useful for understanding how applications
 * use FreeBSD's event notification mechanism.
 */

syscall::kqueue:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: kqueue\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::kevent:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: kevent fd=%d nchanges=%d nevents=%d\n",
        execname, pid, arg0, arg2, arg4);
    @kevent_calls[execname] = count();
}

dtrace:::END
{
    printf("\n--- kevent call count by process ---\n");
    printa("%-30s %@d\n", @kevent_calls);
}
