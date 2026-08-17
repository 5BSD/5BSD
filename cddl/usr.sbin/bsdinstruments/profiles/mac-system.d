/*
 * MAC Framework system checks — system-level security decisions.
 *
 * Traces MAC checks on system operations: reboot, swapon,
 * swapoff, sysctl, audit, kld load/unload, and kenv access.
 * Shows which processes trigger system-level MAC decisions.
 */

fbt::mac_system_check_reboot:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: MAC system reboot check\n", execname, pid);
    @checks[execname, "reboot"] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::mac_system_check_swapon:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: MAC system swapon check\n", execname, pid);
    @checks[execname, "swapon"] = count();
}

fbt::mac_system_check_sysctl:entry
/* @bsdinstruments-predicate */
{
    @checks[execname, "sysctl"] = count();
}

fbt::mac_system_check_audit:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: MAC system audit check\n", execname, pid);
    @checks[execname, "audit"] = count();
}

fbt::mac_kld_check_load:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: MAC kld load check\n", execname, pid);
    @checks[execname, "kld_load"] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::mac_kld_check_stat:entry
/* @bsdinstruments-predicate */
{
    @checks[execname, "kld_stat"] = count();
}

fbt::mac_kenv_check_set:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: MAC kenv set check\n", execname, pid);
    @checks[execname, "kenv_set"] = count();
}

dtrace:::END
{
    printf("\n--- MAC system checks by process/op ---\n");
    printf("%-20s %-14s %8s\n", "EXECNAME", "OP", "COUNT");
    printa("%-20s %-14s %@8d\n", @checks);
}
