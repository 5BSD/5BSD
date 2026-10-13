/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-SIXTEENTH for argument semantics.
 * No pointer dereferences, payloads, paths, addresses or credentials.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling; PID filters omit unrelated worker threads.
 */

sdt:::geli-bio-pressure
/* @bsdinstruments-predicate */
{
    @clone_failures[(int)arg1] = count();
}

sdt:::geli-crypto-pressure
/* @bsdinstruments-predicate */
{
    @crypto_allocation_bytes[(int)arg1] = quantize((size_t)arg2);
}

sdt:::graid-bio-pressure
/* @bsdinstruments-predicate */
{
    @raid_allocation_failures[(int)arg1] = count();
}

sdt:::graid-disk-state
/* @bsdinstruments-predicate */
{
    @raid_states[probename, (int)arg1, (int)arg2] = count();
}

sdt:::graid-subdisk-state
/* @bsdinstruments-predicate */
{
    @raid_states[probename, (int)arg1, (int)arg2] = count();
}

sdt:::graid-volume-state
/* @bsdinstruments-predicate */
{
    @raid_states[probename, (int)arg1, (int)arg2] = count();
}

sdt:::graid-rebuild-start
/* @bsdinstruments-predicate */
{
    @rebuild_events[probename] = count();
}

sdt:::graid-rebuild-finish
/* @bsdinstruments-predicate */
{
    @rebuild_events[probename] = count();
}

sdt:::graid-rebuild-abort
/* @bsdinstruments-predicate */
{
    @rebuild_events[probename] = count();
}
