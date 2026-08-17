/*
 * MAC Framework privilege checks — grant/deny decisions.
 *
 * Traces mac_priv_check and mac_priv_grant to show which
 * privilege operations MAC policies allow or deny. Works
 * alongside priv-check.d which traces the base priv_check.
 */

fbt::mac_priv_check_impl:entry
/* @bsdinstruments-predicate */
{
    self->mac_priv = arg1;
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::mac_priv_check_impl:return
/self->mac_priv && arg1 != 0/
{
    printf("%s[%d]: MAC DENIED priv=%d\n",
        execname, pid, self->mac_priv);
    @denied[execname, self->mac_priv] = count();
    self->mac_priv = 0;
}

fbt::mac_priv_check_impl:return
/self->mac_priv && arg1 == 0/
{
    @allowed[execname, self->mac_priv] = count();
    self->mac_priv = 0;
}

fbt::mac_priv_grant_impl:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: MAC priv grant priv=%d\n",
        execname, pid, arg1);
    @grants[execname, arg1] = count();
}

dtrace:::END
{
    printf("\n--- MAC privilege denials ---\n");
    printf("%-20s %8s %8s\n", "EXECNAME", "PRIV", "COUNT");
    printa("%-20s %8d %@8d\n", @denied);
    printf("\n--- MAC privilege allowed ---\n");
    printa("%-20s %8d %@8d\n", @allowed);
    printf("\n--- MAC privilege grants ---\n");
    printa("%-20s %8d %@8d\n", @grants);
}
