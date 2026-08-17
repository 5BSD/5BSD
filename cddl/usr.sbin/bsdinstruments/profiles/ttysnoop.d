/*
 * TTY read/write activity for a specific process.
 *
 * Traces read/write syscalls on file descriptors 0, 1, 2
 * (stdin/stdout/stderr) to show terminal I/O. Useful for
 * session recording and debugging interactive programs.
 * Usage: bsdinstruments watch ttysnoop --param pid=<pid>
 */

pid${pid}::write:entry
/arg0 <= 2/
{
    printf("%s[%d]: tty write fd=%d %d bytes\n",
        execname, pid, arg0, arg2);
    @tty_writes[arg0] = count();
}

pid${pid}::read:entry
/arg0 == 0/
{
    printf("%s[%d]: tty read fd=%d %d bytes\n",
        execname, pid, arg0, arg2);
    @tty_reads = count();
}

dtrace:::END
{
    printf("\n--- TTY writes by fd ---\n");
    printa("fd=%d %@d\n", @tty_writes);
    printf("\n--- TTY reads ---\n");
    printa("%@d\n", @tty_reads);
}
