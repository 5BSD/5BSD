/*
 * OpenEndpointSecurity decision cache — hit/miss analysis.
 *
 * Traces OES cache lookups to measure caching effectiveness.
 * High miss rates mean more events are dispatched to clients,
 * increasing latency. Requires oes.ko loaded.
 */

oes:::cache-hit
/* @bsdinstruments-predicate */
{
    @hits[arg0] = count();
    @hit_total = count();
}

oes:::cache-miss
/* @bsdinstruments-predicate */
{
    @misses[arg0] = count();
    @miss_total = count();
}

dtrace:::END
{
    printf("\n--- OES cache hits by event type ---\n");
    printf("%8s %8s\n", "EVENT", "COUNT");
    printa("%8d %@8d\n", @hits);
    printf("\n--- OES cache misses by event type ---\n");
    printa("%8d %@8d\n", @misses);
    printf("\n--- Total hits ---\n");
    printa("%@d\n", @hit_total);
    printf("\n--- Total misses ---\n");
    printa("%@d\n", @miss_total);
}
