/* SPDX-License-Identifier: BSD-2-Clause */
struct first { int value; };
struct first first_data = {17};
int support_value(void);
int first_value(void) { return support_value(); }
