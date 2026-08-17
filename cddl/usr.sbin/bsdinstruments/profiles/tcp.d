/* Print every TCP event — send, receive, and state change */

tcp:::send
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp send %d bytes\n", execname, pid, args[2]->ip_plength);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

tcp:::receive
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp recv %d bytes\n", execname, pid, args[2]->ip_plength);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

tcp:::state-change
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp state %d -> %d\n", execname, pid, args[5]->tcps_state, args[3]->tcps_state);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
