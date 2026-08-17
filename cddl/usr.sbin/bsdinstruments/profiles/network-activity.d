/*
 * Network Activity — Apple Instruments equivalent.
 *
 * Combines tcp:::send / tcp:::receive / tcp:::state-change /
 * udp:::send / udp:::receive into one event stream so you can
 * watch the entire network stack at once. Add --with-ustack to
 * see who's making the calls.
 */

tcp:::state-change
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp state %d -> %d\n",
           execname, pid, args[5]->tcps_state, args[3]->tcps_state);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

tcp:::send
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp send len=%d\n", execname, pid, args[2]->ip_plength);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

tcp:::receive
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp recv len=%d\n", execname, pid, args[2]->ip_plength);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

udp:::send
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: udp send len=%d\n", execname, pid, args[2]->ip_plength);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

udp:::receive
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: udp recv len=%d\n", execname, pid, args[2]->ip_plength);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
