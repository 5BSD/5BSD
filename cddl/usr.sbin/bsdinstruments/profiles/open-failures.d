/*
 * Open/stat failure hotspots — failed file access by errno and path.
 *
 * Captures the path on entry and aggregates failures on return
 * by process, syscall, and errno. Identifies missing files,
 * permission issues, and search path problems.
 */

syscall::open:entry,
syscall::openat:entry
/* @bsdinstruments-predicate */
{
    self->open_path = probefunc == "open" ? copyinstr(arg0) : copyinstr(arg1);
}

syscall::open:return,
syscall::openat:return
/arg1 == -1 && self->open_path != NULL/
{
    @failures[execname, probefunc, errno, self->open_path] = count();
    self->open_path = 0;
}

syscall::open:return,
syscall::openat:return
/arg1 >= 0/
{
    self->open_path = 0;
}

syscall::stat:entry,
syscall::lstat:entry
/* @bsdinstruments-predicate */
{
    self->stat_path = copyinstr(arg0);
}

syscall::stat:return,
syscall::lstat:return
/arg1 == -1 && self->stat_path != NULL/
{
    @failures[execname, probefunc, errno, self->stat_path] = count();
    self->stat_path = 0;
}

syscall::stat:return,
syscall::lstat:return
/arg1 == 0/
{
    self->stat_path = 0;
}

dtrace:::END
{
    printf("\n--- File access failures ---\n");
    printf("%-16s %-10s %5s %-40s %6s\n",
        "EXECNAME", "SYSCALL", "ERRNO", "PATH", "COUNT");
    printa("%-16s %-10s %5d %-40s %@6d\n", @failures);
}
