/*
 * Mixed CPU profiler — kernel + user stacks in one view.
 *
 * Samples at 997 Hz and aggregates by combined kernel+user
 * stack. Shows the full call path from userspace through the
 * kernel. Use --format collapsed for flamegraph generation.
 */

profile-997
/* @bsdinstruments-predicate */
{
    @samples[stack(), ustack()] = count();
}

dtrace:::END
{
    printa(@samples);
}
