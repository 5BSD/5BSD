/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-TWELFTH.
 * Start before workload. Event loss invalidates pairing; latency includes preemption.
 * No pointer or payload reads. PF limiter eligibility is not packet admission.
 */

zfs:::access
/* @bsdinstruments-predicate */
{
    @access[(int)arg1, (int)arg3] = count();
}
