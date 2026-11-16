/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
#include <stdio.h>

int program_registration_count;

int
main(void)
{
	if (program_registration_count != 1) {
		fprintf(stderr, "constructor registrations: %d (expected 1)\n",
		    program_registration_count);
		return (1);
	}
	return (0);
}
