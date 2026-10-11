/*
 * TTY input drops, output flow/watermark changes and carrier notifications.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

tty:::input-drop
/* @bsdinstruments-predicate */
{
    @input_drops[arg0, arg1] = count();
}

tty:::flow
/* @bsdinstruments-predicate */
{
    @flow[arg0, arg1] = count();
}

tty:::watermark
/* @bsdinstruments-predicate */
{
    @watermark[arg0, arg1] = count();
}

tty:::carrier
/* @bsdinstruments-predicate */
{
    @carrier[arg0, arg1] = count();
}
