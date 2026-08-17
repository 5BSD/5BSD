/* Print every udplite:::receive event (requires kernel UDP-Lite support) */

udplite:::receive
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: udplite recv\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
