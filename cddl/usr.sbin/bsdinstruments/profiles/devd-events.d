/*
 * Device attach/detach events via devd.
 *
 * Traces device_attach and device_detach kernel calls to
 * show hardware hotplug events. Useful for USB device
 * monitoring and hardware audit logging.
 */

fbt::device_attach:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: device attach\n", execname, pid);
    @attaches[execname] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::device_detach:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: device detach\n", execname, pid);
    @detaches[execname] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- Device attaches ---\n");
    printa("%-30s %@d\n", @attaches);
    printf("\n--- Device detaches ---\n");
    printa("%-30s %@d\n", @detaches);
}
