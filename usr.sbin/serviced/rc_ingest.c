/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * rc(8) header parser — see rc_ingest.h.  Pure string logic, no I/O.
 */

#include <string.h>

#include "rc_ingest.h"

static void
add_name(char list[][SERVICED_LABEL_MAX], unsigned *n, unsigned max,
    const char *tok)
{

	if (*n >= max)
		return;
	strlcpy(list[*n], tok, SERVICED_LABEL_MAX);
	(*n)++;
}

/* Whitespace-split s, appending each token to list (bounded by max). */
static void
tokenize(const char *s, char list[][SERVICED_LABEL_MAX], unsigned *n,
    unsigned max)
{
	const char *start;
	char tok[SERVICED_LABEL_MAX];
	size_t tl;

	for (;;) {
		while (*s == ' ' || *s == '\t')
			s++;
		if (*s == '\0')
			return;
		start = s;
		while (*s != '\0' && *s != ' ' && *s != '\t')
			s++;
		tl = (size_t)(s - start);
		if (tl >= sizeof(tok))
			tl = sizeof(tok) - 1;
		memcpy(tok, start, tl);
		tok[tl] = '\0';
		add_name(list, n, max, tok);
	}
}

/* If s begins with "<tag>:", return the text after the colon, else NULL. */
static const char *
match_tag(const char *s, const char *tag)
{
	size_t n = strlen(tag);

	if (strncmp(s, tag, n) == 0 && s[n] == ':')
		return (s + n + 1);
	return (NULL);
}

static void
parse_keywords(const char *s, struct rc_unit_meta *meta)
{
	char kws[RC_MAX_DEPS][SERVICED_LABEL_MAX];
	unsigned n = 0, i;

	tokenize(s, kws, &n, RC_MAX_DEPS);
	for (i = 0; i < n; i++) {
		if (strcmp(kws[i], "nostart") == 0)
			meta->kw_nostart = true;
		else if (strcmp(kws[i], "firstboot") == 0)
			meta->kw_firstboot = true;
		else if (strcmp(kws[i], "shutdown") == 0)
			meta->kw_shutdown = true;
	}
}

int
rc_parse_header(const char *text, struct rc_unit_meta *meta)
{
	const char *p = text;
	char line[512];

	memset(meta, 0, sizeof(*meta));
	while (*p != '\0') {
		const char *eol, *s, *rest;
		size_t len;

		eol = strchr(p, '\n');
		len = (eol != NULL) ? (size_t)(eol - p) : strlen(p);
		if (len >= sizeof(line))
			len = sizeof(line) - 1;
		memcpy(line, p, len);
		line[len] = '\0';
		p = (eol != NULL) ? eol + 1 : p + strlen(p);

		s = line;
		while (*s == ' ' || *s == '\t')
			s++;
		if (*s == '\0')
			continue;	/* blank line: allowed within header */
		if (*s != '#')
			break;		/* first code line: header block ends */
		s++;			/* consume '#' */
		while (*s == ' ' || *s == '\t')
			s++;

		if ((rest = match_tag(s, "PROVIDE")) != NULL)
			tokenize(rest, meta->provides, &meta->nprovides,
			    SERVICED_MAX_PROVIDES);
		else if ((rest = match_tag(s, "REQUIRE")) != NULL)
			tokenize(rest, meta->req, &meta->nreq, RC_MAX_DEPS);
		else if ((rest = match_tag(s, "BEFORE")) != NULL)
			tokenize(rest, meta->before, &meta->nbefore,
			    RC_MAX_DEPS);
		else if ((rest = match_tag(s, "KEYWORD")) != NULL)
			parse_keywords(rest, meta);
	}
	return (0);
}
