/*
 * File Activity — Apple Instruments equivalent.
 *
 * Combines the most useful filesystem syscalls into one stream:
 * open, close, read, write, stat, unlink, rename. Add --with-ustack
 * to see who's calling them.
 */

syscall::open:entry,
syscall::openat:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: open(\"%s\")\n", execname, pid,
           probefunc == "open" ? copyinstr(arg0) : copyinstr(arg1));
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::close:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: close(fd=%d)\n", execname, pid, (int)arg0);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::read:entry,
syscall::pread:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: %s(fd=%d, %d)\n", execname, pid, probefunc, (int)arg0, (size_t)arg2);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::write:entry,
syscall::pwrite:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: %s(fd=%d, %d)\n", execname, pid, probefunc, (int)arg0, (size_t)arg2);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::fstatat:entry
/* @bsdinstruments-predicate */
{
    /* FreeBSD libc stat() is a wrapper around fstatat(AT_FDCWD, …) so
     * the path is in arg1 (the second argument to fstatat). */
    printf("%s[%d]: stat(\"%s\")\n", execname, pid, copyinstr(arg1));
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::unlink:entry,
syscall::unlinkat:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: %s(\"%s\")\n", execname, pid, probefunc,
           probefunc == "unlink" ? copyinstr(arg0) : copyinstr(arg1));
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::rename:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: rename(\"%s\", \"%s\")\n", execname, pid,
           copyinstr(arg0), copyinstr(arg1));
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::renameat:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: renameat(\"%s\", \"%s\")\n", execname, pid,
           copyinstr(arg1), copyinstr(arg3));
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
