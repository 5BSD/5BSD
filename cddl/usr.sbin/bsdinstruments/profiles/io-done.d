/* Print every block-I/O done event */

io:::done
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: io done\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
