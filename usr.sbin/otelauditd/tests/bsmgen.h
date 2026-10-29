/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Deterministic BSM records for the otelauditd tests.
 */

#ifndef _BSMGEN_H_
#define	_BSMGEN_H_

#include <sys/types.h>

#include <stdio.h>

enum bsmgen_header { BSMGEN_H32, BSMGEN_H32_EX, BSMGEN_H64, BSMGEN_H64_EX };

/*
 * Build a record of header kind h for event with the given body tokens
 * (each consumed and freed), header time sec.ms, and a trailer.
 * Returns a malloc'd buffer and its length.
 */
u_char	*bsmgen_record(enum bsmgen_header h, u_short event, time_t sec,
	    int ms, void **tokens, int ntokens, size_t *lenp);

/* The standard test trail: see bsmgen.c.  Returns the record count. */
int	bsmgen_trail(FILE *, int with_file_tokens, int corrupt);

#endif /* !_BSMGEN_H_ */
