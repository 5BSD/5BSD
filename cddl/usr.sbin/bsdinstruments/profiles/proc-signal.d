/* Print every proc::: signal-related event */

proc:::signal-send,
proc:::signal-clear,
proc:::signal-discard
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: proc %s\n", execname, pid, probename);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
