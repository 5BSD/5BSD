/*
 * Trace virtual memory page faults via the kernel vm_fault function.
 */

fbt::vm_fault:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: vm_fault addr=0x%p\n", execname, pid, arg1);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
