/* Print every block-I/O start event */

io:::start
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: io start\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
