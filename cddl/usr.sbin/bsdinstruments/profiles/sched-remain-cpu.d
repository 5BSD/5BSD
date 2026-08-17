/* Print every sched:::remain-cpu event */

sched:::remain-cpu
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched remain-cpu\n", execname, pid, tid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
