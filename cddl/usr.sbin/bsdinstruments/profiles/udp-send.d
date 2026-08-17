/* Print every udp:::send event */

udp:::send
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: udp send len=%d\n", execname, pid, args[2]->ip_plength);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
