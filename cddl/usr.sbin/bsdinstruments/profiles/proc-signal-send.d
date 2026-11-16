/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every proc:::signal-send event */

proc:::signal-send
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: proc signal-send\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
