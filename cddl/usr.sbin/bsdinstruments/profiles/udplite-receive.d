/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every udplite:::receive event (requires kernel UDP-Lite support) */

udplite:::receive
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: udplite recv\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
