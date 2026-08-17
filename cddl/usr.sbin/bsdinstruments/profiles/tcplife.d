/*
 * TCP connection lifespan — established to close duration.
 *
 * Tracks how long TCP connections live by timing from
 * connect/accept-established to state-change into CLOSED
 * or TIME_WAIT. Shows connection duration and bytes transferred.
 */

tcp:::connect-established,
tcp:::accept-established
/* @bsdinstruments-predicate */
{
    conn_start[args[1]->cs_cid] = timestamp;
    conn_exec[args[1]->cs_cid] = execname;
    conn_pid[args[1]->cs_cid] = pid;
}

tcp:::send
/conn_start[args[1]->cs_cid]/
{
    conn_bytes_out[args[1]->cs_cid] += args[2]->ip_plength;
}

tcp:::receive
/conn_start[args[1]->cs_cid]/
{
    conn_bytes_in[args[1]->cs_cid] += args[2]->ip_plength;
}

tcp:::state-change
/conn_start[args[1]->cs_cid] &&
 (args[3]->tcps_state == 0 || args[3]->tcps_state == 10)/
{
    this->ms = (timestamp - conn_start[args[1]->cs_cid]) / 1000000;
    printf("%s[%d]: conn %dms tx=%d rx=%d\n",
        conn_exec[args[1]->cs_cid],
        conn_pid[args[1]->cs_cid],
        this->ms,
        conn_bytes_out[args[1]->cs_cid],
        conn_bytes_in[args[1]->cs_cid]);
    @life[conn_exec[args[1]->cs_cid]] = quantize(this->ms);
    conn_start[args[1]->cs_cid] = 0;
    conn_exec[args[1]->cs_cid] = 0;
    conn_pid[args[1]->cs_cid] = 0;
    conn_bytes_out[args[1]->cs_cid] = 0;
    conn_bytes_in[args[1]->cs_cid] = 0;
}

dtrace:::END
{
    printf("\n--- TCP connection lifetime (ms) by process ---\n");
    printa(@life);
}
