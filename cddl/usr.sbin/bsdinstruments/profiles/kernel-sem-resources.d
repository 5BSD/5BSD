/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-ELEVENTH.
 * Start before workload; event loss invalidates pairing. Latency includes preemption.
 * PID selection uses executing context. No kernel pointer or payload dereferences.
 */

posixsem:::allocate
/* @bsdinstruments-predicate */
{
    @posixsem_allocate_count[arg1] = count();
}

posixsem:::release
/* @bsdinstruments-predicate */
{
    @posixsem_release_count = count();
}

posixsem:::limit
/* @bsdinstruments-predicate */
{
    @posixsem_limit_count[arg0, arg1] = count();
}
