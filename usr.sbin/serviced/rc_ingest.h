/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * rc(8) ingest: parse rc.d scripts' rcorder headers into unit metadata so
 * serviced can run existing rc services (SVC_KIND_RC) in its own
 * dependency graph.  The parser is pure string logic with no I/O so it is
 * unit-testable in isolation (see tests/rc_ingest_test.c).
 */

#ifndef SERVICED_RC_INGEST_H
#define SERVICED_RC_INGEST_H

#include <stdbool.h>

#include "serviced_manifest.h"	/* SERVICED_LABEL_MAX, SERVICED_MAX_PROVIDES */

#define	RC_MAX_DEPS	16

/*
 * The orderable metadata extracted from an rc.d script's leading comment
 * block: PROVIDE (this service's names), REQUIRE (must start after),
 * BEFORE (must start before), and the KEYWORD flags serviced cares about.
 */
struct rc_unit_meta {
	char		provides[SERVICED_MAX_PROVIDES][SERVICED_LABEL_MAX];
	unsigned	nprovides;
	char		req[RC_MAX_DEPS][SERVICED_LABEL_MAX];	/* REQUIRE */
	unsigned	nreq;
	char		before[RC_MAX_DEPS][SERVICED_LABEL_MAX]; /* BEFORE */
	unsigned	nbefore;
	bool		kw_nostart;	/* KEYWORD: nostart  — never auto-start */
	bool		kw_firstboot;	/* KEYWORD: firstboot */
	bool		kw_shutdown;	/* KEYWORD: shutdown — run at shutdown */
};

/*
 * Parse an rc.d script's rcorder header (its leading comment block) into
 * meta.  Recognizes PROVIDE/REQUIRE/BEFORE/KEYWORD.  Parsing stops at the
 * first non-blank line that is not a comment, so tags appearing later in
 * the script body are ignored (matching rcorder(8)).  A script with no
 * PROVIDE yields nprovides == 0, which the caller treats as "not an
 * orderable service."  text must be NUL-terminated.  Always returns 0.
 */
int	rc_parse_header(const char *text, struct rc_unit_meta *meta);

#endif /* SERVICED_RC_INGEST_H */
