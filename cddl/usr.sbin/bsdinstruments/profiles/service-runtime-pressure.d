/* service runtime pressure. Scalar diagnostics; no message or command contents.
 * Argument meanings: tools/test/system-tracing/COVERAGE-TWENTIETH.
 */

service_runtime*:::retry-scheduled
/* @bsdinstruments-predicate */
{
    @service_runtime_retry_scheduled = quantize(arg1);
}

service_runtime*:::retry-recovered
/* @bsdinstruments-predicate */
{
    @service_runtime_retry_recovered = quantize(arg1);
}

service_runtime*:::health-change
/* @bsdinstruments-predicate */
{
    @service_runtime_health_change[(int)arg1] = count();
}

service_runtime*:::budget-rejected
/* @bsdinstruments-predicate */
{
    @service_runtime_budget_rejected[(int)arg0] = count();
}

service_runtime*:::budget-expired
/* @bsdinstruments-predicate */
{
    @service_runtime_budget_expired = quantize(arg0);
}

service_runtime*:::lease-limit
/* @bsdinstruments-predicate */
{
    @service_runtime_lease_limit[(int)arg2] = count();
}

libchannel*:::queue-limit
/* @bsdinstruments-predicate */
{
    @libchannel_queue_limit = quantize(arg0);
}

libchannel*:::pending-limit
/* @bsdinstruments-predicate */
{
    @libchannel_pending_limit = quantize(arg0);
}
