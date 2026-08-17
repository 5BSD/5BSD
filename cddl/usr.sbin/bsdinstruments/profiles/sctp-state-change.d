/* Print every SCTP association state change */

sctp:::state-change
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: sctp state %d -> %d\n",
        execname, pid,
        args[5]->sctps_state, args[3]->sctps_state);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
