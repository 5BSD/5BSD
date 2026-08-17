/* Print sched priority change events (change-pri + lend-pri) */

sched:::change-pri,
sched:::lend-pri
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched %s\n", execname, pid, tid, probename);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
