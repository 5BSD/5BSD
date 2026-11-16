/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every vfs:::vop_create event */

vfs::vop_create:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: vop_create\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
