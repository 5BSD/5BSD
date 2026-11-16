/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every syscall return that delivered a non-zero errno */

syscall:::return
/errno != 0 /* @bsdinstruments-predicate-and */ /
{
    printf("%s[%d]: %s -> errno %d\n", execname, pid, probefunc, errno);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
