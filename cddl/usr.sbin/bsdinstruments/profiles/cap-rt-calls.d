/*
 * CAP_RT sync call latency — per-service timing histograms.
 *
 * Measures synchronous cap_rt call duration by service. Shows
 * how long each service takes to handle requests. Requires
 * cap_rt.ko loaded.
 */

cap_rt:::call
/* @bsdinstruments-predicate */
{
    self->call_ts = timestamp;
    self->call_svc = copyinstr(arg0);
}

cap_rt:::reply
/self->call_ts/
{
    this->us = (timestamp - self->call_ts) / 1000;
    printf("%s[%d]: cap_rt call %s %dus\n",
        execname, pid, self->call_svc, this->us);
    @latency[self->call_svc] = quantize(this->us);
    @by_proc[execname, self->call_svc] = count();
    self->call_ts = 0;
    self->call_svc = 0;
}

dtrace:::END
{
    printf("\n--- cap_rt call latency (us) by service ---\n");
    printa(@latency);
    printf("\n--- cap_rt calls by process/service ---\n");
    printf("%-20s %-20s %8s\n", "EXECNAME", "SERVICE", "COUNT");
    printa("%-20s %-20s %@8d\n", @by_proc);
}
