/*
 * Route / netlink audit — routing table and interface changes.
 *
 * Traces route manipulation via the routing socket (PF_ROUTE)
 * and kernel route functions. Shows who is adding, deleting,
 * or changing routes. For interface address changes, see the
 * kernel ifa_* and in_* functions.
 */

fbt::rib_add_route:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: rib_add_route\n", execname, pid);
    @route_ops[execname, "add"] = count();
}

fbt::rib_del_route:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: rib_del_route\n", execname, pid);
    @route_ops[execname, "delete"] = count();
}

fbt::rib_change_route:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: rib_change_route\n", execname, pid);
    @route_ops[execname, "change"] = count();
}

fbt::in_control:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: in_control (IPv4 ioctl)\n", execname, pid);
    @iface_ops[execname, "in_control"] = count();
}

fbt::in6_control:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: in6_control (IPv6 ioctl)\n", execname, pid);
    @iface_ops[execname, "in6_control"] = count();
}

dtrace:::END
{
    printf("\n--- Route operations by process ---\n");
    printa("%-20s %-10s %@d\n", @route_ops);
    printf("\n--- Interface operations by process ---\n");
    printa("%-20s %-14s %@d\n", @iface_ops);
}
