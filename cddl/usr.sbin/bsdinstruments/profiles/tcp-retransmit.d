/*
 * TCP retransmit timer events.
 *
 * Traces TCP retransmission timeouts via FBT on tcp_timer_rexmt.
 * High retransmit rates indicate congestion, packet loss, or
 * misconfigured timeouts. Requires the tcp_timer_rexmt kernel
 * function (present in all supported FreeBSD versions).
 */

fbt::tcp_timer_rexmt:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp retransmit timeout\n", execname, pid);
    @rexmt_timeouts[execname] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- Retransmit timeouts by process ---\n");
    printa("%-20s %@d\n", @rexmt_timeouts);
}
