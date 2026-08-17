/*
 * Event loop blocking — time spent in poll, select, and kevent.
 *
 * Measures how long processes block in event demultiplexing
 * syscalls. Long waits are normal for idle servers. Short
 * busy-waits indicate polling loops. Histograms in us.
 */

syscall::poll:entry
/* @bsdinstruments-predicate */
{
    self->poll_ts = timestamp;
}

syscall::poll:return
/self->poll_ts/
{
    this->us = (timestamp - self->poll_ts) / 1000;
    @poll_lat[execname] = quantize(this->us);
    self->poll_ts = 0;
}

syscall::select:entry
/* @bsdinstruments-predicate */
{
    self->select_ts = timestamp;
}

syscall::select:return
/self->select_ts/
{
    this->us = (timestamp - self->select_ts) / 1000;
    @select_lat[execname] = quantize(this->us);
    self->select_ts = 0;
}

syscall::kevent:entry
/* @bsdinstruments-predicate */
{
    self->kevent_ts = timestamp;
}

syscall::kevent:return
/self->kevent_ts/
{
    this->us = (timestamp - self->kevent_ts) / 1000;
    @kevent_lat[execname] = quantize(this->us);
    self->kevent_ts = 0;
}

dtrace:::END
{
    printf("\n--- poll latency (us) by process ---\n");
    printa(@poll_lat);
    printf("\n--- select latency (us) by process ---\n");
    printa(@select_lat);
    printf("\n--- kevent latency (us) by process ---\n");
    printa(@kevent_lat);
}
