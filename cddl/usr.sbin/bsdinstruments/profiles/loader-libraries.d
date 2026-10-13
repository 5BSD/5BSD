/* SPDX-License-Identifier: BSD-2-Clause
 * Requested library names and load outcomes; requires rtldtrace support.
 * Uses normal DTrace permissions, including protected-process restrictions. */
#pragma D option quiet
#pragma D option strsize=256
rtldtrace*:::load-done
/* @bsdinstruments-predicate */
{
    printf("%u\t%u\t%s\t%s\t%s\n", pid, tid, execname,
        arg0 == 0 ? "<descriptor>" : copyinstr(arg0),
        arg1 == 0 ? "failed" : "loaded");
}
