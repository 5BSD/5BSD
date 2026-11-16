/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every vfs:::vop_lookup event */

vfs::vop_lookup:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: vop_lookup\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
