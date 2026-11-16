/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every tcp:::send event */

tcp:::send
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp send len=%d\n", execname, pid, args[2]->ip_plength);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
