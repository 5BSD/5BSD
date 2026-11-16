/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
#include <libsecureboot.h>
int
main(void)
{
	/* Exercise actual PEM decoding and trust-anchor construction, plus cache. */
	if (ve_trust_init() != 1 || ve_trust_init() != 1)
		return 1;
	return 0;
}
