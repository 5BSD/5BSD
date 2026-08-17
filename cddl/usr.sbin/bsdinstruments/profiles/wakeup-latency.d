/*
 * Wakeup latency — time from sched:::wakeup to sched:::on-cpu.
 *
 * Measures scheduler dispatch latency: how long a thread waits
 * in the run queue after being woken before it actually gets CPU
 * time. High wakeup latency indicates CPU saturation or priority
 * inversion.
 */

sched:::wakeup
/* @bsdinstruments-predicate */
{
    wakeup_ts[args[0]->td_tid] = timestamp;
}

sched:::on-cpu
/wakeup_ts[tid]/
{
    this->latency_us = (timestamp - wakeup_ts[tid]) / 1000;
    printf("%s[%d/tid %d]: wakeup-latency %dus\n",
        execname, pid, tid, this->latency_us);
    @latency[execname] = quantize(this->latency_us);
    wakeup_ts[tid] = 0;
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- Wakeup latency (us) by process ---\n");
    printa(@latency);
}
