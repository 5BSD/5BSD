/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every proc:::signal-discard event */

proc:::signal-discard
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: proc signal-discard\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
