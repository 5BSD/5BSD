/*
 * Socket errors — network syscall failures by process and errno.
 *
 * Aggregates connect/sendto/recvfrom/sendmsg/recvmsg failures
 * by process, syscall, and errno. Useful for diagnosing
 * connection refused, timeouts, and network unreachable.
 * Note: FreeBSD has no send/recv syscalls — libc wraps them
 * as sendto/recvfrom, which are traced here.
 */

syscall::connect:return,
syscall::sendto:return,
syscall::recvfrom:return,
syscall::sendmsg:return,
syscall::recvmsg:return
/arg1 == -1 /* @bsdinstruments-predicate-and *//
{
    @errors[execname, probefunc, errno] = count();
}

dtrace:::END
{
    printf("\n--- Socket errors by process/syscall/errno ---\n");
    printf("%-20s %-14s %6s %8s\n", "EXECNAME", "SYSCALL", "ERRNO", "COUNT");
    printa("%-20s %-14s %6d %@8d\n", @errors);
}
