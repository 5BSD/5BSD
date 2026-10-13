/* SPDX-License-Identifier: BSD-2-Clause
 * Load request counts include already-loaded objects, not unique files. */
#pragma D option quiet
#pragma D option strsize=256
rtldtrace*:::load-done
/* @bsdinstruments-predicate */
{
    @loads[execname, arg0 == 0 ? "<descriptor>" : copyinstr(arg0),
        arg1 == 0 ? "failed" : "loaded"] = count();
}
