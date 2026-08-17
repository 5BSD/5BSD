/*
 * MAC Framework process checks — process control decisions.
 *
 * Traces MAC checks on process operations: debug (ptrace),
 * signal delivery, scheduling, and wait. Non-zero returns
 * indicate a MAC policy denied the operation.
 */

fbt::mac_proc_check_debug:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: MAC proc debug check\n", execname, pid);
    @checks[execname, "debug"] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::mac_proc_check_debug:return
/arg1 != 0/
{
    printf("%s[%d]: MAC DENIED proc debug\n", execname, pid);
    @denied[execname, "debug"] = count();
}

fbt::mac_proc_check_signal:entry
/* @bsdinstruments-predicate */
{
    @checks[execname, "signal"] = count();
}

fbt::mac_proc_check_signal:return
/arg1 != 0/
{
    printf("%s[%d]: MAC DENIED proc signal\n", execname, pid);
    @denied[execname, "signal"] = count();
}

fbt::mac_proc_check_sched:entry
/* @bsdinstruments-predicate */
{
    @checks[execname, "sched"] = count();
}

fbt::mac_proc_check_sched:return
/arg1 != 0/
{
    printf("%s[%d]: MAC DENIED proc sched\n", execname, pid);
    @denied[execname, "sched"] = count();
}

fbt::mac_proc_check_wait:entry
/* @bsdinstruments-predicate */
{
    @checks[execname, "wait"] = count();
}

fbt::mac_proc_check_wait:return
/arg1 != 0/
{
    printf("%s[%d]: MAC DENIED proc wait\n", execname, pid);
    @denied[execname, "wait"] = count();
}

dtrace:::END
{
    printf("\n--- MAC process checks ---\n");
    printf("%-20s %-10s %8s\n", "EXECNAME", "OP", "COUNT");
    printa("%-20s %-10s %@8d\n", @checks);
    printf("\n--- MAC process denials ---\n");
    printa("%-20s %-10s %@8d\n", @denied);
}
