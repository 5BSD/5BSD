/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _AUDITCMP_TEST_H_
#define _AUDITCMP_TEST_H_

struct auditcmp_backend;

int auditcmp_test_serve(int, const char *, int,
    const struct auditcmp_backend *);

#endif
