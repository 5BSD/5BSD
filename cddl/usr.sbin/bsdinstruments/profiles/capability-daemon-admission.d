/* capability daemon admission. Scalar diagnostics; no message or command contents.
 * Argument meanings: tools/test/system-tracing/COVERAGE-TWENTIETH.
 */

capsule*:::ctl-admission-failure
/* @bsdinstruments-predicate */
{
    @capsule_ctl_admission_failure[(int)arg0] = count();
}

capsule*:::ctl-timeout
/* @bsdinstruments-predicate */
{
    @capsule_ctl_timeout[(int)arg0] = count();
}

bsddevice*:::worker-reject
/* @bsdinstruments-predicate */
{
    @bsddevice_worker_reject[(int)arg0] = count();
}

bsdextension*:::accept-retry
/* @bsdinstruments-predicate */
{
    @bsdextension_accept_retry[(int)arg0] = count();
}

bsdextension*:::worker-reject
/* @bsdinstruments-predicate */
{
    @bsdextension_worker_reject[(int)arg0] = count();
}

bsdmemory*:::dependency-health
/* @bsdinstruments-predicate */
{
    @bsdmemory_dependency_health[(int)arg0] = count();
}

bsdsysctl*:::session-limit
/* @bsdinstruments-predicate */
{
    @bsdsysctl_session_limit[(int)arg0] = count();
}

bsdsysctl*:::session-open-failure
/* @bsdinstruments-predicate */
{
    @bsdsysctl_session_open_failure[(int)arg0] = count();
}

bsdsysctl*:::session-close-reason
/* @bsdinstruments-predicate */
{
    @bsdsysctl_session_close_reason[(int)arg0] = count();
}
