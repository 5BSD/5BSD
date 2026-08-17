/*
 * File mutation audit — create/unlink/rename/chmod/chown/mkdir/rmdir.
 *
 * Comprehensive audit trail of filesystem modifications with
 * path context. Useful for security auditing, compliance, and
 * understanding what's changing on disk.
 */

syscall::mkdir:entry,
syscall::mkdirat:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: %s(\"%s\")\n", execname, pid, probefunc,
           probefunc == "mkdir" ? copyinstr(arg0) : copyinstr(arg1));
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::rmdir:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: rmdir(\"%s\")\n", execname, pid, copyinstr(arg0));
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
}

syscall::renameat:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: renameat(\"%s\", \"%s\")\n", execname, pid,
           copyinstr(arg1), copyinstr(arg3));
}

syscall::chmod:entry,
syscall::lchmod:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: %s(\"%s\", 0%o)\n", execname, pid, probefunc,
           copyinstr(arg0), arg1);
}

syscall::fchmodat:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: fchmodat(\"%s\", 0%o)\n", execname, pid,
           copyinstr(arg1), arg2);
}

syscall::chown:entry,
syscall::lchown:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: %s(\"%s\", %d, %d)\n", execname, pid, probefunc,
           copyinstr(arg0), arg1, arg2);
}

syscall::fchownat:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: fchownat(\"%s\", %d, %d)\n", execname, pid,
           copyinstr(arg1), arg2, arg3);
}

syscall::symlink:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: symlink(\"%s\", \"%s\")\n", execname, pid,
           copyinstr(arg0), copyinstr(arg1));
}

syscall::link:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: link(\"%s\", \"%s\")\n", execname, pid,
           copyinstr(arg0), copyinstr(arg1));
}

syscall::truncate:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: truncate(\"%s\", %d)\n", execname, pid,
           copyinstr(arg0), arg1);
}

syscall::chflags:entry,
syscall::lchflags:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: %s(\"%s\", 0x%x)\n", execname, pid, probefunc,
           copyinstr(arg0), arg1);
}

syscall::mkdir:entry, syscall::mkdirat:entry,
syscall::rmdir:entry,
syscall::unlink:entry, syscall::unlinkat:entry,
syscall::rename:entry, syscall::renameat:entry,
syscall::chmod:entry, syscall::lchmod:entry, syscall::fchmodat:entry,
syscall::chown:entry, syscall::lchown:entry, syscall::fchownat:entry,
syscall::chflags:entry, syscall::lchflags:entry,
syscall::symlink:entry, syscall::link:entry,
syscall::truncate:entry
/* @bsdinstruments-predicate */
{
    @mutations[execname, probefunc] = count();
}

dtrace:::END
{
    printf("\n--- File mutations by process/operation ---\n");
    printa("%-20s %-14s %@d\n", @mutations);
}
