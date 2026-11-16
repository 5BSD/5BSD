/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every vfs:::vop_mkdir event */

vfs::vop_mkdir:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: vop_mkdir\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
