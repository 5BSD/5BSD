/* Print every sched:::change-pri event */

sched:::change-pri
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched change-pri\n", execname, pid, tid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
