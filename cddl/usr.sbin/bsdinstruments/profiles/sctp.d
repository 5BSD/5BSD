/* Print every SCTP send and receive event with payload length */

sctp:::send
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: sctp send %d bytes\n",
        execname, pid, args[2]->ip_plength);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

sctp:::receive
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: sctp recv %d bytes\n",
        execname, pid, args[2]->ip_plength);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
