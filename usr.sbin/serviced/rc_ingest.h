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

/* One ingested rc.d service: the script basename plus its parsed header. */
struct rc_unit {
	char			name[SERVICED_LABEL_MAX];   /* rc.d service name */
	struct rc_unit_meta	meta;
};

/*
 * Scan rc.d directory dir, parse each executable regular file's header,
 * and append every orderable service (nprovides > 0 and not KEYWORD
 * nostart) to units, up to max.  Returns the count appended, or -1 if the
 * directory cannot be opened.  Only the leading part of each script is
 * read — enough for the rcorder header.
 */
int	rc_ingest_scan(const char *dir, struct rc_unit *units, unsigned max);

#endif /* SERVICED_RC_INGEST_H */
