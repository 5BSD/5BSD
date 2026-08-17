/* Print every read(2)/write(2)/pread(2)/pwrite(2) entry with fd and length */

syscall::read:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: read(fd=%d, %d)\n", execname, pid, (int)arg0, (size_t)arg2);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::write:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: write(fd=%d, %d)\n", execname, pid, (int)arg0, (size_t)arg2);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::pread:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: pread(fd=%d, %d)\n", execname, pid, (int)arg0, (size_t)arg2);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::pwrite:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: pwrite(fd=%d, %d)\n", execname, pid, (int)arg0, (size_t)arg2);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
