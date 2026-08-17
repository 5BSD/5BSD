/* Print every sched:::off-cpu event */

sched:::off-cpu
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched off-cpu\n", execname, pid, tid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
