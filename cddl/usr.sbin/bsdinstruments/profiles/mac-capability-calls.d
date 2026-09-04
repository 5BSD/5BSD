/*
 * MAC_CAPABILITY sync call latency — per-service timing histograms.
 *
 * Measures synchronous call duration by service using the framework's
 * own call completion probe, which carries the latency (sbintime).
 */

mac_capability:::call-done
/* @bsdinstruments-predicate */
{
    /* arg5 is the call latency in sbintime units (1/2^32 s). */
    this->us = (arg5 * 1000000) >> 32;
    printf("%s[%d]: call %s %dus%s\n",
        execname, pid, stringof(arg0), this->us,
        arg4 != 0 ? " (error)" : "");
    @latency[stringof(arg0)] = quantize(this->us);
    @by_proc[execname, stringof(arg0)] = count();
}

dtrace:::END
{
    printf("\n--- call latency (us) by service ---\n");
    printa(@latency);
    printf("\n--- calls by process/service ---\n");
    printf("%-20s %-24s %8s\n", "EXECNAME", "SERVICE", "COUNT");
    printa("%-20s %-24s %@8d\n", @by_proc);
}
