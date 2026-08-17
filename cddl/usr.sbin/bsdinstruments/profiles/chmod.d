/* Print every chmod / fchmod / lchmod / fchmodat call with path and mode */

syscall::chmod:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: chmod(\"%s\", 0%o)\n",
           execname, pid, copyinstr(arg0), (mode_t)arg1);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::lchmod:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: lchmod(\"%s\", 0%o)\n",
           execname, pid, copyinstr(arg0), (mode_t)arg1);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::fchmod:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: fchmod(%d, 0%o)\n",
           execname, pid, (int)arg0, (mode_t)arg1);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::fchmodat:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: fchmodat(_, \"%s\", 0%o)\n",
           execname, pid, copyinstr(arg1), (mode_t)arg2);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
