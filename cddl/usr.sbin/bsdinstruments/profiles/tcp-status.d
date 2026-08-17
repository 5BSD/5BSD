/* Print every tcp:::state-change (alias of tcp-state-change) */

tcp:::state-change
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp status %d -> %d\n",
           execname, pid, args[5]->tcps_state, args[3]->tcps_state);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
