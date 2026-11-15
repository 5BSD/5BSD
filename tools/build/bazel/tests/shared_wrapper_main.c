/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
/* Consumer for a native static-in-shared linkage qualification fixture. */
extern int bsd_test_entry(void);

int
main(void)
{
	return (bsd_test_entry());
}
