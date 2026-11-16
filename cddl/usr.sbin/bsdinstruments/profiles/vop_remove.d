/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every vfs:::vop_remove event */

vfs::vop_remove:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: vop_remove\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
