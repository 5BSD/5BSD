/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
/* Retain exactly one original archive data member without a whole-archive link. */
extern int BZ2_rNums[512];

int
main(void)
{
	return (BZ2_rNums[0] == 619 ? 0 : 1);
}
