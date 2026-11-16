/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every vfs:::vop_symlink event */

vfs::vop_symlink:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: vop_symlink\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
