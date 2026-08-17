/*
 * Busiest outbound connectors — connect rate and failures.
 *
 * Aggregates connect(2) calls by process, showing both
 * successful and failed connection attempts with latency.
 */

syscall::connect:entry
/* @bsdinstruments-predicate */
{
    self->conn_ts = timestamp;
}

syscall::connect:return
/self->conn_ts && arg1 == 0/
{
    this->elapsed_us = (timestamp - self->conn_ts) / 1000;
    @connect_ok[execname] = count();
    @connect_latency[execname] = quantize(this->elapsed_us);
    self->conn_ts = 0;
}

syscall::connect:return
/self->conn_ts && arg1 == -1/
{
    @connect_fail[execname, errno] = count();
    self->conn_ts = 0;
}

syscall::connect:return
/self->conn_ts/
{
    self->conn_ts = 0;
}

dtrace:::END
{
    printf("\n--- Successful connects by process ---\n");
    printa("%-30s %@d\n", @connect_ok);
    printf("\n--- Connect latency (us) by process ---\n");
    printa(@connect_latency);
    printf("\n--- Failed connects by process/errno ---\n");
    printa("%-20s %6d %@8d\n", @connect_fail);
}
