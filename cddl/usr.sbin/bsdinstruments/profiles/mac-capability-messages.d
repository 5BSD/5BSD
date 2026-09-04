/*
 * MAC_CAPABILITY async message flow — send, dispatch, reply, receive.
 *
 * Traces the async message lifecycle through the framework. Shows
 * message throughput per stage and handler latency from the
 * dispatch completion probe.
 */

mac_capability:::send
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: send service=%s len=%d\n",
        execname, pid, stringof(arg0), arg2);
    @msg_flow[stringof(arg0), "send"] = count();
}

mac_capability:::dispatch
/* @bsdinstruments-predicate */
{
    @msg_flow[stringof(arg0), "dispatch"] = count();
}

mac_capability:::dispatch-done
/* @bsdinstruments-predicate */
{
    /* arg3 is the handler latency in sbintime units (1/2^32 s). */
    @handler_latency[stringof(arg0)] = quantize((arg3 * 1000000) >> 32);
}

mac_capability:::reply
/* @bsdinstruments-predicate */
{
    @msg_flow[stringof(arg0), "reply"] = count();
}

mac_capability:::recv
/* @bsdinstruments-predicate */
{
    @msg_flow[stringof(arg0), "recv"] = count();
}

mac_capability:::notify
/* @bsdinstruments-predicate */
{
    @msg_flow[stringof(arg0), "notify"] = count();
}

dtrace:::END
{
    printf("\n--- message flow by service/stage ---\n");
    printf("%-24s %-10s %8s\n", "SERVICE", "STAGE", "COUNT");
    printa("%-24s %-10s %@8d\n", @msg_flow);
    printf("\n--- handler latency (us) by service ---\n");
    printa(@handler_latency);
}
