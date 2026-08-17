/*
 * Kernel stack sampler for flamegraphs.
 *
 * Samples at 997 Hz (prime to avoid aliasing) and aggregates
 * by kernel stack. Complement to time-profiler which samples
 * user stacks. Pipe to --format collapsed for flamegraph.pl.
 */

profile-997
/* @bsdinstruments-predicate */
{
    @samples[stack()] = count();
}

dtrace:::END
{
    printa(@samples);
}
