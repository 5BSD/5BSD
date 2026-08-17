/*
 * CAP_RT async message flow — send, dispatch, reply, receive.
 *
 * Traces the full async message lifecycle through the cap_rt
 * framework. Shows message throughput and handler latency.
 * Requires cap_rt.ko loaded.
 */

cap_rt:::send
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: cap_rt send service=%s len=%d\n",
        execname, pid, copyinstr(arg0), arg2);
    @msg_flow[copyinstr(arg0), "send"] = count();
}

cap_rt:::dispatch
/* @bsdinstruments-predicate */
{
    self->dispatch_ts = timestamp;
    @msg_flow[copyinstr(arg0), "dispatch"] = count();
}

cap_rt:::reply
/self->dispatch_ts/
{
    this->us = (timestamp - self->dispatch_ts) / 1000;
    @handler_latency[copyinstr(arg0)] = quantize(this->us);
    @msg_flow[copyinstr(arg0), "reply"] = count();
    self->dispatch_ts = 0;
}

cap_rt:::recv
/* @bsdinstruments-predicate */
{
    @msg_flow[copyinstr(arg0), "recv"] = count();
}

cap_rt:::notify
/* @bsdinstruments-predicate */
{
    @msg_flow[copyinstr(arg0), "notify"] = count();
}

dtrace:::END
{
    printf("\n--- cap_rt message flow by service/stage ---\n");
    printf("%-20s %-10s %8s\n", "SERVICE", "STAGE", "COUNT");
    printa("%-20s %-10s %@8d\n", @msg_flow);
    printf("\n--- cap_rt handler latency (us) by service ---\n");
    printa(@handler_latency);
}
