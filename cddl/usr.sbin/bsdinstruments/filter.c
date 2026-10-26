/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * CLI filter flags -> D predicate rendering.  Filters AND together;
 * --where is the escape hatch for predicates the typed flags don't
 * cover.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bsdinstruments.h"

struct clauses {
	char	*data;
	size_t	 len, cap;
};

/* Append one clause, joined with " && "; exits rather than drop it. */
static void
append_clause(struct clauses *c, const char *clause)
{
	size_t clen;
	char *np;

	clen = strlen(clause);
	if (c->len + clen + 5 > c->cap) {
		while (c->cap < c->len + clen + 5)
			c->cap *= 2;
		np = realloc(c->data, c->cap);
		if (np == NULL)
			err(1, "filter");	/* never silently drop a filter */
		c->data = np;
	}
	if (c->len > 0) {
		memcpy(c->data + c->len, " && ", 4);
		c->len += 4;
	}
	memcpy(c->data + c->len, clause, clen + 1);
	c->len += clen;
}

/*
 * Build the joined clause list (no surrounding slashes).  Returns a
 * malloc'd string, or NULL if no filters are set.
 */
static char *
clause_list(const struct filter_opts *fo)
{
	struct clauses c;
	char clause[1024];
	const char *p;

	c.cap = 1024;
	c.len = 0;
	c.data = malloc(c.cap);
	if (c.data == NULL)
		err(1, "filter");	/* never silently drop a filter */
	c.data[0] = '\0';

	if (fo->have_pid) {
		snprintf(clause, sizeof(clause), "pid == %d", (int)fo->pid);
		append_clause(&c, clause);
	}
	if (fo->execname != NULL) {
		/*
		 * Escape embedded double quotes so the D string
		 * literal stays intact.
		 */
		char escaped[512];
		size_t o = 0;

		for (p = fo->execname; *p != '\0' &&
		    o + 3 < sizeof(escaped); p++) {
			if (*p == '"')
				escaped[o++] = '\\';
			escaped[o++] = *p;
		}
		escaped[o] = '\0';
		snprintf(clause, sizeof(clause), "execname == \"%s\"",
		    escaped);
		append_clause(&c, clause);
	}
	if (fo->have_uid) {
		snprintf(clause, sizeof(clause), "uid == %u",
		    (unsigned)fo->uid);
		append_clause(&c, clause);
	}
	if (fo->have_gid) {
		snprintf(clause, sizeof(clause), "gid == %u",
		    (unsigned)fo->gid);
		append_clause(&c, clause);
	}
	if (fo->have_jail) {
		snprintf(clause, sizeof(clause),
		    "curproc->p_ucred->cr_prison->pr_id == %d", fo->jail);
		append_clause(&c, clause);
	}
	if (fo->where != NULL) {
		/* Parenthesize to keep the && composition unambiguous. */
		snprintf(clause, sizeof(clause), "(%s)", fo->where);
		append_clause(&c, clause);
	}

	if (c.len == 0) {
		free(c.data);
		return (NULL);
	}
	return (c.data);
}

char *
filter_predicate(const struct filter_opts *fo)
{
	char *clauses, *out;
	size_t len;

	clauses = clause_list(fo);
	if (clauses == NULL)
		return (strdup(""));
	len = strlen(clauses) + 3;
	out = malloc(len);
	if (out != NULL)
		snprintf(out, len, "/%s/", clauses);
	free(clauses);
	return (out);
}

char *
filter_predicate_and(const struct filter_opts *fo)
{
	char *clauses, *out;
	size_t len;

	clauses = clause_list(fo);
	if (clauses == NULL)
		return (strdup(""));
	len = strlen(clauses) + 5;
	out = malloc(len);
	if (out != NULL)
		snprintf(out, len, " && %s", clauses);
	free(clauses);
	return (out);
}
