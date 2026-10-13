/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-FOURTEENTH.
 * No paths, payloads, credentials or pointer dereferences. Start before the
 * workload; event loss invalidates pairing. Elapsed time includes preemption.
 * processquery's final argument is an unavailable flag, not errno.
 */

catio*:::read-start
/* @bsdinstruments-predicate */
{
    catio_read_depth[pid, tid]++;
    catio_read_time[pid, tid, catio_read_depth[pid, tid]] = timestamp;
}

catio*:::read-done
/catio_read_time[pid, tid, catio_read_depth[pid, tid]] != 0/
{
    @catio_read_us[(int)arg3] = quantize((timestamp - catio_read_time[pid, tid, catio_read_depth[pid, tid]]) / 1000);
    @catio_read_count[(int)arg3] = count();
    if ((int)arg3 == 0)
        @catio_read_bytes = quantize((int64_t)arg2);
    catio_read_time[pid, tid, catio_read_depth[pid, tid]] = 0;
    catio_read_depth[pid, tid]--;
}

catio*:::write-start
/* @bsdinstruments-predicate */
{
    catio_write_depth[pid, tid]++;
    catio_write_time[pid, tid, catio_write_depth[pid, tid]] = timestamp;
}

catio*:::write-done
/catio_write_time[pid, tid, catio_write_depth[pid, tid]] != 0/
{
    @catio_write_us[(int)arg3] = quantize((timestamp - catio_write_time[pid, tid, catio_write_depth[pid, tid]]) / 1000);
    @catio_write_count[(int)arg3] = count();
    if ((int)arg3 == 0)
        @catio_write_bytes = quantize((int64_t)arg2);
    catio_write_time[pid, tid, catio_write_depth[pid, tid]] = 0;
    catio_write_depth[pid, tid]--;
}

teeio*:::read-start
/* @bsdinstruments-predicate */
{
    teeio_read_depth[pid, tid]++;
    teeio_read_time[pid, tid, teeio_read_depth[pid, tid]] = timestamp;
}

teeio*:::read-done
/teeio_read_time[pid, tid, teeio_read_depth[pid, tid]] != 0/
{
    @teeio_read_us[(int)arg3] = quantize((timestamp - teeio_read_time[pid, tid, teeio_read_depth[pid, tid]]) / 1000);
    @teeio_read_count[(int)arg3] = count();
    if ((int)arg3 == 0)
        @teeio_read_bytes = quantize((int64_t)arg2);
    teeio_read_time[pid, tid, teeio_read_depth[pid, tid]] = 0;
    teeio_read_depth[pid, tid]--;
}

teeio*:::write-start
/* @bsdinstruments-predicate */
{
    teeio_write_depth[pid, tid]++;
    teeio_write_time[pid, tid, teeio_write_depth[pid, tid]] = timestamp;
}

teeio*:::write-done
/teeio_write_time[pid, tid, teeio_write_depth[pid, tid]] != 0/
{
    @teeio_write_us[(int)arg3] = quantize((timestamp - teeio_write_time[pid, tid, teeio_write_depth[pid, tid]]) / 1000);
    @teeio_write_count[(int)arg3] = count();
    if ((int)arg3 == 0)
        @teeio_write_bytes = quantize((int64_t)arg2);
    teeio_write_time[pid, tid, teeio_write_depth[pid, tid]] = 0;
    teeio_write_depth[pid, tid]--;
}

splitio*:::read-start
/* @bsdinstruments-predicate */
{
    splitio_read_depth[pid, tid]++;
    splitio_read_time[pid, tid, splitio_read_depth[pid, tid]] = timestamp;
}

splitio*:::read-done
/splitio_read_time[pid, tid, splitio_read_depth[pid, tid]] != 0/
{
    @splitio_read_us[(int)arg3] = quantize((timestamp - splitio_read_time[pid, tid, splitio_read_depth[pid, tid]]) / 1000);
    @splitio_read_count[(int)arg3] = count();
    if ((int)arg3 == 0)
        @splitio_read_bytes = quantize((int64_t)arg2);
    splitio_read_time[pid, tid, splitio_read_depth[pid, tid]] = 0;
    splitio_read_depth[pid, tid]--;
}

splitio*:::write-start
/* @bsdinstruments-predicate */
{
    splitio_write_depth[pid, tid]++;
    splitio_write_time[pid, tid, splitio_write_depth[pid, tid]] = timestamp;
}

splitio*:::write-done
/splitio_write_time[pid, tid, splitio_write_depth[pid, tid]] != 0/
{
    @splitio_write_us[(int)arg3] = quantize((timestamp - splitio_write_time[pid, tid, splitio_write_depth[pid, tid]]) / 1000);
    @splitio_write_count[(int)arg3] = count();
    if ((int)arg3 == 0)
        @splitio_write_bytes = quantize((int64_t)arg2);
    splitio_write_time[pid, tid, splitio_write_depth[pid, tid]] = 0;
    splitio_write_depth[pid, tid]--;
}

wordcountio*:::read-start
/* @bsdinstruments-predicate */
{
    wordcountio_read_depth[pid, tid]++;
    wordcountio_read_time[pid, tid, wordcountio_read_depth[pid, tid]] = timestamp;
}

wordcountio*:::read-done
/wordcountio_read_time[pid, tid, wordcountio_read_depth[pid, tid]] != 0/
{
    @wordcountio_read_us[(int)arg3] = quantize((timestamp - wordcountio_read_time[pid, tid, wordcountio_read_depth[pid, tid]]) / 1000);
    @wordcountio_read_count[(int)arg3] = count();
    if ((int)arg3 == 0)
        @wordcountio_read_bytes = quantize((int64_t)arg2);
    wordcountio_read_time[pid, tid, wordcountio_read_depth[pid, tid]] = 0;
    wordcountio_read_depth[pid, tid]--;
}
