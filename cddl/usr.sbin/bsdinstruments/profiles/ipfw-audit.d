/*
 * ipfw firewall audit — rule evaluation and match events.
 *
 * Traces ipfw_chk to show firewall rule evaluation results
 * by process. Aggregates action counts. Requires ipfw loaded.
 */

fbt::ipfw_chk:entry
/* @bsdinstruments-predicate */
{
    self->ipfw_ts = timestamp;
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::ipfw_chk:return
/self->ipfw_ts/
{
    this->us = (timestamp - self->ipfw_ts) / 1000;
    printf("%s[%d]: ipfw_chk result=%d %dus\n",
        execname, pid, arg1, this->us);
    @ipfw_results[execname, arg1] = count();
    self->ipfw_ts = 0;
}

dtrace:::END
{
    printf("\n--- ipfw evaluations by process/result ---\n");
    printf("%-20s %8s %8s\n", "EXECNAME", "RESULT", "COUNT");
    printa("%-20s %8d %@8d\n", @ipfw_results);
}
