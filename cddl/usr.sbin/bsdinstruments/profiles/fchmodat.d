/* Print every fchmodat(2) call with path and mode */

syscall::fchmodat:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: fchmodat(_, \"%s\", 0%o)\n",
           execname, pid, copyinstr(arg1), (mode_t)arg2);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
