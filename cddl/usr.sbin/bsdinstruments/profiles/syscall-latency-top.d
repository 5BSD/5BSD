/*
 * Top slow syscalls by process and syscall name.
 *
 * Measures every syscall's latency and aggregates by
 * execname + syscall. At exit, prints a table sorted by
 * total time spent — the heaviest syscall paths bubble up.
 */

syscall:::entry
/* @bsdinstruments-predicate */
{
    self->sc_ts = timestamp;
}

syscall:::return
/self->sc_ts/
{
    this->elapsed_us = (timestamp - self->sc_ts) / 1000;
    @total_us[execname, probefunc] = sum(this->elapsed_us);
    @call_count[execname, probefunc] = count();
    @max_us[execname, probefunc] = max(this->elapsed_us);
    self->sc_ts = 0;
}

dtrace:::END
{
    printf("\n--- Total syscall time (us) by process/syscall ---\n");
    printa("%-20s %-20s %@d\n", @total_us);
    printf("\n--- Syscall count by process/syscall ---\n");
    printa("%-20s %-20s %@d\n", @call_count);
    printf("\n--- Max syscall latency (us) ---\n");
    printa("%-20s %-20s %@d\n", @max_us);
}
