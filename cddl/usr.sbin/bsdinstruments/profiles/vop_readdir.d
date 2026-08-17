/* Print every vfs:::vop_readdir event */

vfs::vop_readdir:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: vop_readdir\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
