/*
 * File descriptor activity — hottest FDs by syscall count.
 *
 * Aggregates read/write/close/ioctl calls by process and FD
 * number. Identifies which file descriptors are busiest.
 */

syscall::read:entry,
syscall::write:entry,
syscall::pread:entry,
syscall::pwrite:entry,
syscall::close:entry,
syscall::ioctl:entry,
syscall::sendto:entry,
syscall::recvfrom:entry,
syscall::sendmsg:entry,
syscall::recvmsg:entry
/* @bsdinstruments-predicate */
{
    @calls[execname, probefunc, arg0] = count();
}

dtrace:::END
{
    printf("\n--- Syscall count by process/syscall/fd ---\n");
    printf("%-20s %-14s %6s %8s\n", "EXECNAME", "SYSCALL", "FD", "COUNT");
    printa("%-20s %-14s %6d %@8d\n", @calls);
}
