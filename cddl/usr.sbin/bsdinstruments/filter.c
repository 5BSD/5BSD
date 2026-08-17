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

/*
 * Build the joined clause list (no surrounding slashes).  Returns a
 * malloc'd string, or NULL if no filters are set.
 */
static char *
clause_list(const struct filter_opts *fo)
{
	char clause[1024];
	char *out;
	const char *p;
	size_t cap, len;
	int any;

	cap = 1024;
	out = malloc(cap);
	if (out == NULL)
		err(1, "filter");	/* never silently drop a filter */
	out[0] = '\0';
	len = 0;
	any = 0;

#define	APPEND_CLAUSE()	do {						\
	size_t clen = strlen(clause);					\
	if (len + clen + 5 > cap) {					\
		char *np;						\
		while (cap < len + clen + 5)				\
			cap *= 2;					\
		np = realloc(out, cap);					\
		if (np == NULL)						\
			err(1, "filter");	/* see above */		\
		out = np;						\
	}								\
	if (any) {							\
		memcpy(out + len, " && ", 4);				\
		len += 4;						\
	}								\
	memcpy(out + len, clause, clen + 1);				\
	len += clen;							\
	any = 1;							\
} while (0)

	if (fo->have_pid) {
		snprintf(clause, sizeof(clause), "pid == %d", (int)fo->pid);
		APPEND_CLAUSE();
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
		APPEND_CLAUSE();
	}
	if (fo->have_uid) {
		snprintf(clause, sizeof(clause), "uid == %u",
		    (unsigned)fo->uid);
		APPEND_CLAUSE();
	}
	if (fo->have_gid) {
		snprintf(clause, sizeof(clause), "gid == %u",
		    (unsigned)fo->gid);
		APPEND_CLAUSE();
	}
	if (fo->have_jail) {
		snprintf(clause, sizeof(clause),
		    "curproc->p_ucred->cr_prison->pr_id == %d", fo->jail);
		APPEND_CLAUSE();
	}
	if (fo->where != NULL) {
		/* Parenthesize to keep the && composition unambiguous. */
		snprintf(clause, sizeof(clause), "(%s)", fo->where);
		APPEND_CLAUSE();
	}
#undef APPEND_CLAUSE

	if (!any) {
		free(out);
		return (NULL);
	}
	return (out);
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
