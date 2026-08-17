/* Print every kill(2) syscall with signal number and target pid */

syscall::kill:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: signal %d to pid %d\n",
           execname, pid, (int)arg1, (pid_t)arg0);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
