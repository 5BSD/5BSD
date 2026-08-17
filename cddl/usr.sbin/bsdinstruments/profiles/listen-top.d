/*
 * Busiest listeners — accept rate and listen backlog by process.
 *
 * Aggregates accept(2) calls and listen(2) backlog settings
 * to identify the busiest server processes and whether their
 * listen backlogs are appropriately sized.
 */

syscall::listen:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: listen fd=%d backlog=%d\n",
        execname, pid, arg0, arg1);
    @listen_calls[execname] = count();
    @backlog[execname] = max(arg1);
}

syscall::accept:entry,
syscall::accept4:entry
/* @bsdinstruments-predicate */
{
    self->accept_ts = timestamp;
}

syscall::accept:return,
syscall::accept4:return
/self->accept_ts && arg1 >= 0/
{
    this->elapsed_us = (timestamp - self->accept_ts) / 1000;
    @accept_rate[execname] = count();
    @accept_latency[execname] = quantize(this->elapsed_us);
    self->accept_ts = 0;
}

syscall::accept:return,
syscall::accept4:return
/self->accept_ts/
{
    self->accept_ts = 0;
}

dtrace:::END
{
    printf("\n--- Listen calls by process ---\n");
    printa("%-30s %@d\n", @listen_calls);
    printf("\n--- Max backlog by process ---\n");
    printa("%-30s %@d\n", @backlog);
    printf("\n--- Accept count by process ---\n");
    printa("%-30s %@d\n", @accept_rate);
    printf("\n--- Accept latency (us) by process ---\n");
    printa(@accept_latency);
}
