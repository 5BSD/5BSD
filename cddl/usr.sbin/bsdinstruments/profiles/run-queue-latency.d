/*
 * Run-queue latency — time spent runnable but not on CPU.
 *
 * Measures how long threads sit in the scheduler run queue
 * after becoming runnable (enqueue) before getting dispatched
 * (on-cpu). High run-queue latency means CPU saturation.
 */

sched:::enqueue
/* @bsdinstruments-predicate */
{
    enqueue_ts[args[0]->td_tid] = timestamp;
}

sched:::on-cpu
/enqueue_ts[tid]/
{
    this->latency_us = (timestamp - enqueue_ts[tid]) / 1000;
    @latency[execname] = quantize(this->latency_us);
    @total_us[execname] = sum(this->latency_us);
    enqueue_ts[tid] = 0;
}

dtrace:::END
{
    printf("\n--- Run-queue latency (us) by process ---\n");
    printa(@latency);
    printf("\n--- Total run-queue wait (us) by process ---\n");
    printa("%-30s %@d\n", @total_us);
}
