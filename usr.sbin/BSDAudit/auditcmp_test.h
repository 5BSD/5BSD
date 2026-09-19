/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _AUDITCMP_TEST_H_
#define _AUDITCMP_TEST_H_

struct auditcmp_backend;
struct auditcmp_rate;
struct label_rate;
struct timespec;

int auditcmp_test_serve(int, const char *, int,
    const struct auditcmp_backend *);

/*
 * Parent per-label admission-bucket accounting hooks (see auditcmp.c).  The
 * table is opaque; _table() allocates one and the caller frees it.
 */
struct label_rate *auditcmp_test_accept_table(void);
struct auditcmp_rate *auditcmp_test_accept_lookup(struct label_rate *,
    const char *, const struct timespec *);

#endif
