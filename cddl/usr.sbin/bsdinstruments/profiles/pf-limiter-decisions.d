/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-TWELFTH.
 * Start before workload. Event loss invalidates pairing; latency includes preemption.
 * No pointer or payload reads. PF limiter eligibility is not packet admission.
 */

pf:ip:limiter:decision
/* @bsdinstruments-predicate */
{
    @decisions[arg0, arg1, arg2, arg3, arg4, arg5] = count();
}

pf:ip:limiter:pressure
/* @bsdinstruments-predicate */
{
    @pressure[arg0, arg1, arg2, arg5] = quantize(arg3);
    @threshold[arg0, arg1, arg2, arg5] = max(arg4);
}

pf:ip:limiter:eligible
/* @bsdinstruments-predicate */
{
    @eligible[arg0, arg1, arg2] = count();
}
