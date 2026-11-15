/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every vfs:::vop_mknod event */

vfs::vop_mknod:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: vop_mknod\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
