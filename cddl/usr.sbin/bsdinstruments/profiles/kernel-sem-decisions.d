/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-ELEVENTH.
 * Start before workload; event loss invalidates pairing. Latency includes preemption.
 * PID selection uses executing context. No kernel pointer or payload dereferences.
 */

posixsem:::access
/* @bsdinstruments-predicate */
{
    @posixsem_access_count[arg1] = count();
}

posixsem:::post
/* @bsdinstruments-predicate */
{
    @posixsem_post_count[arg1, arg2] = count();
}

posixsem:::value
/* @bsdinstruments-predicate */
{
    @posixsem_value_count[arg1, arg2, arg3] = count();
}
