/*
 * TCP window size tracking — send and receive window monitoring.
 *
 * Shows TCP window sizes on send and receive events. Small
 * windows indicate receiver-side backpressure or network
 * congestion. Useful for diagnosing throughput issues.
 */

tcp:::send
/* @bsdinstruments-predicate */
{
    @snd_wnd[execname] = quantize(args[4]->tcp_window);
    @snd_bytes[execname] = sum(args[2]->ip_plength);
}

tcp:::receive
/* @bsdinstruments-predicate */
{
    @rcv_wnd[execname] = quantize(args[4]->tcp_window);
    @rcv_bytes[execname] = sum(args[2]->ip_plength);
}

dtrace:::END
{
    printf("\n--- TCP send window size distribution ---\n");
    printa(@snd_wnd);
    printf("\n--- TCP send bytes by process ---\n");
    printa("%-30s %@d\n", @snd_bytes);
    printf("\n--- TCP receive window size distribution ---\n");
    printa(@rcv_wnd);
    printf("\n--- TCP receive bytes by process ---\n");
    printa("%-30s %@d\n", @rcv_bytes);
}
