/*
 * Block I/O latency — service time histograms by process.
 *
 * Measures the time between io:::start and io:::done for each
 * block I/O request. Aggregates as histograms to show the
 * latency distribution of disk operations.
 */

io:::start
/* @bsdinstruments-predicate */
{
    start_ts[arg0] = timestamp;
    start_exec[arg0] = execname;
}

io:::done
/start_ts[arg0]/
{
    this->elapsed_us = (timestamp - start_ts[arg0]) / 1000;
    @latency[start_exec[arg0]] = quantize(this->elapsed_us);
    @iops[start_exec[arg0]] = count();
    start_ts[arg0] = 0;
    start_exec[arg0] = 0;
}

dtrace:::END
{
    printf("\n--- I/O latency (us) by process ---\n");
    printa(@latency);
    printf("\n--- IOPS by process ---\n");
    printa("%-30s %@d\n", @iops);
}
