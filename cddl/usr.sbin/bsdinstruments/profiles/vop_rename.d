/* Print every vfs:::vop_rename event */

vfs::vop_rename:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: vop_rename\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
