/*
 * Userspace mutex contention — _umtx_op syscall tracing.
 *
 * Traces _umtx_op to show userspace synchronization primitive
 * contention (pthread mutexes, condvars, rwlocks). High call
 * rates indicate lock contention in application code.
 */

syscall::_umtx_op:entry
/* @bsdinstruments-predicate */
{
    self->umtx_ts = timestamp;
    self->umtx_op = arg1;
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::_umtx_op:return
/self->umtx_ts/
{
    this->us = (timestamp - self->umtx_ts) / 1000;
    @latency[execname, self->umtx_op] = quantize(this->us);
    @counts[execname, self->umtx_op] = count();
    self->umtx_ts = 0;
    self->umtx_op = 0;
}

dtrace:::END
{
    printf("\n--- _umtx_op latency (us) by process/op ---\n");
    printa(@latency);
    printf("\n--- _umtx_op count by process/op ---\n");
    printf("%-20s %8s %8s\n", "EXECNAME", "OP", "COUNT");
    printa("%-20s %8d %@8d\n", @counts);
}
