/*
 * Hardware interrupt handler duration.
 *
 * Measures time spent in interrupt handlers via FBT on
 * intr_event_handle. Long interrupt handlers cause latency
 * spikes in all other work. Histogram in microseconds.
 */

fbt::intr_event_handle:entry
/* @bsdinstruments-predicate */
{
    self->intr_ts = timestamp;
}

fbt::intr_event_handle:return
/self->intr_ts/
{
    this->us = (timestamp - self->intr_ts) / 1000;
    @latency = quantize(this->us);
    @by_cpu[cpu] = quantize(this->us);
    self->intr_ts = 0;
}

dtrace:::END
{
    printf("\n--- Interrupt handler duration (us) ---\n");
    printa(@latency);
    printf("\n--- Interrupt handler duration by CPU (us) ---\n");
    printa(@by_cpu);
}
