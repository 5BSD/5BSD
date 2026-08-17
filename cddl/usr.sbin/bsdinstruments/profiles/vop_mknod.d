/* Print every vfs:::vop_mknod event */

vfs::vop_mknod:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: vop_mknod\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
