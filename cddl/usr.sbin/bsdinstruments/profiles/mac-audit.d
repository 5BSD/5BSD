/*
 * MAC Framework comprehensive audit — all denial events.
 *
 * Traces every MAC framework check function and reports
 * only denials (non-zero returns). Provides a single-pane
 * view of all MAC policy enforcement. High-overhead — use
 * with --execname or --pid filters.
 */

fbt::mac_vnode_check_*:return
/arg1 != 0 /* @bsdinstruments-predicate-and *//
{
    printf("%s[%d]: MAC DENIED %s err=%d\n",
        execname, pid, probefunc, arg1);
    @denied[execname, probefunc] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::mac_proc_check_*:return
/arg1 != 0 /* @bsdinstruments-predicate-and *//
{
    printf("%s[%d]: MAC DENIED %s err=%d\n",
        execname, pid, probefunc, arg1);
    @denied[execname, probefunc] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::mac_socket_check_*:return
/arg1 != 0 /* @bsdinstruments-predicate-and *//
{
    printf("%s[%d]: MAC DENIED %s err=%d\n",
        execname, pid, probefunc, arg1);
    @denied[execname, probefunc] = count();
}

fbt::mac_system_check_*:return
/arg1 != 0 /* @bsdinstruments-predicate-and *//
{
    printf("%s[%d]: MAC DENIED %s err=%d\n",
        execname, pid, probefunc, arg1);
    @denied[execname, probefunc] = count();
}

fbt::mac_pipe_check_*:return
/arg1 != 0 /* @bsdinstruments-predicate-and *//
{
    printf("%s[%d]: MAC DENIED %s err=%d\n",
        execname, pid, probefunc, arg1);
    @denied[execname, probefunc] = count();
}

fbt::mac_priv_check_impl:return
/arg1 != 0 /* @bsdinstruments-predicate-and *//
{
    printf("%s[%d]: MAC DENIED priv check err=%d\n",
        execname, pid, arg1);
    @denied[execname, "mac_priv_check_impl"] = count();
}

dtrace:::END
{
    printf("\n--- All MAC denials by process/check ---\n");
    printf("%-20s %-36s %8s\n", "EXECNAME", "CHECK", "COUNT");
    printa("%-20s %-36s %@8d\n", @denied);
}
