/*
 * OpenEndpointSecurity exec monitoring — binary execution control.
 *
 * Traces OES exec authorization to show which binaries are
 * allowed or blocked. The most critical OES event for endpoint
 * protection. Requires oes.ko loaded.
 */

fbt::oes_mac_vnode_check_exec:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: OES exec check\n", execname, pid);
    @exec_checks[execname] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::oes_mac_vnode_check_exec:return
/arg1 != 0/
{
    printf("%s[%d]: OES exec DENIED err=%d\n", execname, pid, arg1);
    @exec_denied[execname] = count();
}

fbt::oes_mac_vnode_check_exec:return
/arg1 == 0/
{
    @exec_allowed[execname] = count();
}

dtrace:::END
{
    printf("\n--- OES exec checks ---\n");
    printa("%-30s %@d\n", @exec_checks);
    printf("\n--- OES exec allowed ---\n");
    printa("%-30s %@d\n", @exec_allowed);
    printf("\n--- OES exec DENIED ---\n");
    printa("%-30s %@d\n", @exec_denied);
}
