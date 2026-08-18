/* Print every SCTP association state change and its previous state. */

sctp:::state-change
/* @bsdinstruments-predicate */
{
	/* arg5 is old state; arg3 is the association after the transition. */
	printf("%s[%d]: sctp state %d -> %d\n", execname, pid,
	    (int)arg5, ((struct sctp_tcb *)arg3)->asoc.state);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
