/* Print every lchmod(2) call with path and mode */

syscall::lchmod:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: lchmod(\"%s\", 0%o)\n",
           execname, pid, copyinstr(arg0), (mode_t)arg1);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
