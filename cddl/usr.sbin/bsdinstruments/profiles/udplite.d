/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Print every UDP-Lite send and receive event (requires kernel UDP-Lite support) */

udplite:::send
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: udplite send\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

udplite:::receive
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: udplite recv\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
