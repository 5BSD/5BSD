/*
 * CAP_RT capprotect — process integrity shielding events.
 *
 * Traces the cap_rt_capprotect service which protects processes
 * from ptrace, signals, and visibility. Shows shield activations
 * and blocked access attempts. Requires cap_rt_capprotect.ko.
 */

fbt::cap_rt_capprotect_call:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: capprotect call\n", execname, pid);
    @shield_ops[execname] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::capprotect_check_debug:entry
/* @bsdinstruments-predicate */
{
    @checks[execname, "debug"] = count();
}

fbt::capprotect_check_debug:return
/arg1 != 0/
{
    printf("%s[%d]: capprotect BLOCKED debug\n", execname, pid);
    @blocked[execname, "debug"] = count();
}

fbt::capprotect_check_signal:entry
/* @bsdinstruments-predicate */
{
    @checks[execname, "signal"] = count();
}

fbt::capprotect_check_signal:return
/arg1 != 0/
{
    printf("%s[%d]: capprotect BLOCKED signal\n", execname, pid);
    @blocked[execname, "signal"] = count();
}

fbt::capprotect_check_visible:entry
/* @bsdinstruments-predicate */
{
    @checks[execname, "visible"] = count();
}

fbt::capprotect_check_visible:return
/arg1 != 0/
{
    @blocked[execname, "visible"] = count();
}

dtrace:::END
{
    printf("\n--- capprotect shield operations ---\n");
    printa("%-30s %@d\n", @shield_ops);
    printf("\n--- capprotect checks ---\n");
    printf("%-20s %-10s %8s\n", "EXECNAME", "CHECK", "COUNT");
    printa("%-20s %-10s %@8d\n", @checks);
    printf("\n--- capprotect BLOCKED ---\n");
    printa("%-20s %-10s %@8d\n", @blocked);
}
