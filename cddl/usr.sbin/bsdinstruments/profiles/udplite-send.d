/* Print every udplite:::send event (requires kernel UDP-Lite support) */

udplite:::send
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: udplite send\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
