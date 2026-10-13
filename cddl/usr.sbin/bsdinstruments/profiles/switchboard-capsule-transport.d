/* switchboard capsule transport. Scalar diagnostics; no message or command contents.
 * Argument meanings: tools/test/system-tracing/COVERAGE-TWENTIETH.
 */

switchboard*:::capsule-rpc-start
/* @bsdinstruments-predicate */
{
    @switchboard_capsule_rpc_start = quantize(arg0);
}

switchboard*:::capsule-rpc-done
/* @bsdinstruments-predicate */
{
    @switchboard_capsule_rpc_done[(int)arg0, (int)arg1] = count();
}

switchboard*:::capsule-stale-reply
/* @bsdinstruments-predicate */
{
    @switchboard_capsule_stale_reply[(int)arg0] = count();
}

switchboard*:::capsule-malformed-reply
/* @bsdinstruments-predicate */
{
    @switchboard_capsule_malformed_reply = quantize(arg0);
}
