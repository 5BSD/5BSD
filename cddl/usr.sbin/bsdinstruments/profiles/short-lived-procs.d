/*
 * Process lifetime — create-to-exit duration by execname.
 *
 * Tracks process creation to exit time and quantizes the
 * lifetime distribution. Short-lived processes cluster in
 * the low-microsecond buckets; long-running daemons in the
 * high-second buckets. Use the histogram to spot churn.
 */

proc:::create
/* @bsdinstruments-predicate */
{
    proc_start[args[0]->p_pid] = timestamp;
}

proc:::exit
/proc_start[pid]/
{
    this->lifetime_us = (timestamp - proc_start[pid]) / 1000;
    printf("%s[%d]: exit after %dus\n", execname, pid, this->lifetime_us);
    @lifetime[execname] = quantize(this->lifetime_us);
    @short_count[execname] = count();
    proc_start[pid] = 0;
}

dtrace:::END
{
    printf("\n--- Process lifetime (us) by execname ---\n");
    printa(@lifetime);
    printf("\n--- Process exit count by execname ---\n");
    printa("%-30s %@d\n", @short_count);
}
