/*
 * pf firewall audit — rule evaluation events and actions.
 *
 * Traces pf_test to show which processes trigger firewall
 * evaluation and the resulting action. Aggregates results
 * by process. Requires pf loaded and active.
 */

fbt::pf_test:entry
/* @bsdinstruments-predicate */
{
    self->pf_ts = timestamp;
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::pf_test:return
/self->pf_ts/
{
    this->us = (timestamp - self->pf_ts) / 1000;
    printf("%s[%d]: pf_test result=%d %dus\n",
        execname, pid, arg1, this->us);
    @pf_results[execname, arg1] = count();
    self->pf_ts = 0;
}

dtrace:::END
{
    printf("\n--- pf evaluations by process/result ---\n");
    printf("%-20s %8s %8s\n", "EXECNAME", "RESULT", "COUNT");
    printa("%-20s %8d %@8d\n", @pf_results);
}
