/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every vfs:::vop_readdir event */

vfs::vop_readdir:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: vop_readdir\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
