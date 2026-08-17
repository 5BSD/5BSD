/* Print every proc:::exit event with the exit reason */

proc:::exit
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: exit (reason=%d)\n", execname, pid, (int)arg0);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
