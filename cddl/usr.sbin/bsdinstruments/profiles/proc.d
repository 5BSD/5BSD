/* Print every proc::: provider event */

proc:::create,
proc:::exec,
proc:::exec-success,
proc:::exec-failure,
proc:::exit,
proc:::signal-send,
proc:::signal-clear,
proc:::signal-discard,
proc:::lwp-exit
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: proc %s\n", execname, pid, probename);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
