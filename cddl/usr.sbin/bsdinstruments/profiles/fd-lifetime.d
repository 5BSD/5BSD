/*
 * File descriptor activity — open/close/dup/socket/pipe counts.
 *
 * Aggregates FD creation and close events by process and source
 * syscall. Compare open vs close counts to identify FD churn
 * or potential leaks.
 */

syscall::open:return,
syscall::openat:return
/arg1 >= 0 /* @bsdinstruments-predicate-and *//
{
    @fd_opens[execname, probefunc] = count();
}

syscall::socket:return
/arg1 >= 0 /* @bsdinstruments-predicate-and *//
{
    @fd_opens[execname, "socket"] = count();
}

syscall::pipe:return,
syscall::pipe2:return
/arg0 == 0 /* @bsdinstruments-predicate-and *//
{
    @fd_opens[execname, probefunc] = count();
}

syscall::dup:return,
syscall::dup2:return
/arg1 >= 0 /* @bsdinstruments-predicate-and *//
{
    @fd_opens[execname, probefunc] = count();
}

syscall::socketpair:return
/arg0 == 0 /* @bsdinstruments-predicate-and *//
{
    @fd_opens[execname, "socketpair"] = count();
}

syscall::close:entry
/* @bsdinstruments-predicate */
{
    @fd_closes[execname] = count();
}

dtrace:::END
{
    printf("\n--- FD opens by process/source ---\n");
    printa("%-20s %-14s %@d\n", @fd_opens);
    printf("\n--- FD closes by process ---\n");
    printa("%-20s %@d\n", @fd_closes);
}
