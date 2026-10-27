/* SPDX-License-Identifier: BSD-2-Clause */
/* Consumer for a native static-in-shared linkage qualification fixture. */
extern int bsd_test_entry(void);

int
main(void)
{
	return (bsd_test_entry());
}
