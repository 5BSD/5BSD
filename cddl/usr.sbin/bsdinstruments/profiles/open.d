/* Print every open(2) and openat(2) call with the path argument */

syscall::open:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: open(\"%s\")\n",
           execname, pid, copyinstr(arg0));
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::openat:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: openat(_, \"%s\")\n",
           execname, pid, copyinstr(arg1));
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
