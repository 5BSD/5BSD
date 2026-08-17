/* Print every sched:::lend-pri event */

sched:::lend-pri
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched lend-pri\n", execname, pid, tid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
