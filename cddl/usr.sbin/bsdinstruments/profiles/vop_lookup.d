/* Print every vfs:::vop_lookup event */

vfs::vop_lookup:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: vop_lookup\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
