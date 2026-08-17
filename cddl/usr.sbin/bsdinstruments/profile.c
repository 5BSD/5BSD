/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Profile loading and rendering.  A profile is a .d file with a name
 * (the filename minus .d), a one-line description (first block
 * comment), and raw D source.  The source may contain:
 *
 *   /@ @bsdinstruments-predicate @/	 CLI filter predicate slot
 *   /@ @bsdinstruments-predicate-and @/ AND'd into an existing predicate
 *   /@ @bsdinstruments-stack @/	 becomes stack(); with --with-stack
 *   /@ @bsdinstruments-ustack @/	 becomes ustack(); with --with-ustack
 *   ${name}				 --param name=value substitution
 *
 * Profiles load from three directories with shadowing (user overrides
 * local overrides base); -f paths bypass the catalog.
 */

#include <sys/stat.h>

#include <ctype.h>
#include <dirent.h>
#include <limits.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bsdinstruments.h"

#define	PROFILE_DIR_BASE	"/usr/share/bsdinstruments/profiles"
#define	PROFILE_DIR_SYSTEM	"/usr/local/share/bsdinstruments/profiles"

const char *
profile_origin_name(enum profile_origin origin)
{

	switch (origin) {
	case ORIGIN_BASE:	return ("base");
	case ORIGIN_SYSTEM:	return ("local");
	case ORIGIN_USER:	return ("user");
	case ORIGIN_EXPLICIT:	return ("explicit");
	}
	return ("unknown");
}

/*
 * Parse the first block comment and return its first non-empty line
 * (leading '*' decoration stripped) as a malloc'd description.
 */
static char *
parse_description(const char *source)
{
	const char *open, *close, *p, *line, *end;
	char *descr;
	size_t len;

	open = strstr(source, "/*");
	if (open == NULL)
		return (strdup(""));
	close = strstr(open + 2, "*/");
	if (close == NULL)
		return (strdup(""));

	for (line = open + 2; line < close; line = end + 1) {
		end = memchr(line, '\n', (size_t)(close - line));
		if (end == NULL)
			end = close;
		p = line;
		while (p < end && isspace((unsigned char)*p))
			p++;
		if (p < end && *p == '*')
			p++;
		while (p < end && isspace((unsigned char)*p))
			p++;
		/* Trim trailing whitespace. */
		while (end > p && isspace((unsigned char)end[-1]))
			end--;
		if (p < end) {
			len = (size_t)(end - p);
			descr = malloc(len + 1);
			if (descr == NULL)
				return (strdup(""));
			memcpy(descr, p, len);
			descr[len] = '\0';
			return (descr);
		}
		if (end == close)
			break;
	}
	return (strdup(""));
}

static char *
read_file(const char *path)
{
	FILE *fp;
	char *buf;
	long size;

	fp = fopen(path, "r");
	if (fp == NULL)
		return (NULL);
	if (fseek(fp, 0, SEEK_END) != 0 || (size = ftell(fp)) < 0 ||
	    fseek(fp, 0, SEEK_SET) != 0) {
		fclose(fp);
		return (NULL);
	}
	buf = malloc((size_t)size + 1);
	if (buf == NULL) {
		fclose(fp);
		return (NULL);
	}
	if (fread(buf, 1, (size_t)size, fp) != (size_t)size) {
		free(buf);
		fclose(fp);
		return (NULL);
	}
	buf[size] = '\0';
	fclose(fp);
	return (buf);
}

void
profile_free(struct profile *p)
{

	if (p == NULL)
		return;
	free(p->name);
	free(p->descr);
	free(p->source);
	free(p);
}

static struct profile *
profile_new(const char *name, char *source, enum profile_origin origin)
{
	struct profile *p;

	p = calloc(1, sizeof(*p));
	if (p == NULL) {
		free(source);
		return (NULL);
	}
	p->name = strdup(name);
	p->descr = parse_description(source);
	p->source = source;
	p->origin = origin;
	if (p->name == NULL || p->descr == NULL) {
		profile_free(p);
		return (NULL);
	}
	return (p);
}

/*
 * Insert into the list, applying shadowing: same-name profiles from
 * a higher-precedence origin replace earlier ones with a warning.
 */
static void
profile_list_insert(struct profile_list *list, struct profile *p)
{
	struct profile **pp;

	for (pp = &list->head; *pp != NULL; pp = &(*pp)->next) {
		if (strcmp((*pp)->name, p->name) != 0)
			continue;
		if ((*pp)->origin < p->origin)
			fprintf(stderr, "bsdinstruments: profile '%s' from "
			    "%s shadows %s version\n", p->name,
			    profile_origin_name(p->origin),
			    profile_origin_name((*pp)->origin));
		p->next = (*pp)->next;
		profile_free(*pp);
		*pp = p;
		return;
	}
	*pp = p;
	list->count++;
}

static void
profile_load_dir(struct profile_list *list, const char *dir,
    enum profile_origin origin)
{
	DIR *dp;
	struct dirent *de;
	struct profile *p;
	char path[PATH_MAX], name[NAME_MAX];
	char *source;
	size_t len;

	dp = opendir(dir);
	if (dp == NULL)
		return;
	while ((de = readdir(dp)) != NULL) {
		len = strlen(de->d_name);
		if (len < 3 || strcmp(de->d_name + len - 2, ".d") != 0)
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
		source = read_file(path);
		if (source == NULL) {
			fprintf(stderr, "bsdinstruments: failed to read "
			    "%s: %s\n", path, strerror(errno));
			continue;
		}
		strlcpy(name, de->d_name, sizeof(name));
		name[len - 2] = '\0';
		p = profile_new(name, source, origin);
		if (p != NULL)
			profile_list_insert(list, p);
	}
	closedir(dp);
}

void
profile_list_load(struct profile_list *list)
{
	const char *home;
	char userdir[PATH_MAX];

	list->head = NULL;
	list->count = 0;
	profile_load_dir(list, PROFILE_DIR_BASE, ORIGIN_BASE);
	profile_load_dir(list, PROFILE_DIR_SYSTEM, ORIGIN_SYSTEM);
	home = getenv("HOME");
	if (home != NULL) {
		snprintf(userdir, sizeof(userdir), "%s/.bsdinstruments/profiles",
		    home);
		profile_load_dir(list, userdir, ORIGIN_USER);
	}
}

void
profile_list_free(struct profile_list *list)
{
	struct profile *p, *next;

	for (p = list->head; p != NULL; p = next) {
		next = p->next;
		profile_free(p);
	}
	list->head = NULL;
	list->count = 0;
}

struct profile *
profile_lookup(const struct profile_list *list, const char *name)
{
	struct profile *p;

	for (p = list->head; p != NULL; p = p->next)
		if (strcmp(p->name, name) == 0)
			return (p);
	return (NULL);
}

struct profile *
profile_load_file(const char *path)
{
	struct profile *p;
	const char *base, *dot;
	char name[NAME_MAX];
	char *source;
	size_t len;

	source = read_file(path);
	if (source == NULL) {
		fprintf(stderr, "bsdinstruments: failed to read profile at "
		    "%s: %s\n", path, strerror(errno));
		return (NULL);
	}
	base = strrchr(path, '/');
	base = base != NULL ? base + 1 : path;
	dot = strrchr(base, '.');
	len = dot != NULL && dot > base ? (size_t)(dot - base) : strlen(base);
	if (len >= sizeof(name))
		len = sizeof(name) - 1;
	memcpy(name, base, len);
	name[len] = '\0';
	p = profile_new(name, source, ORIGIN_EXPLICIT);
	return (p);
}

struct profile *
profile_resolve(const char *name, const char *file)
{
	struct profile_list list;
	struct profile *p, **pp;

	if (file != NULL)
		return (profile_load_file(file));
	if (name == NULL) {
		fprintf(stderr, "bsdinstruments: provide a profile name or "
		    "-f /path/to/script.d\n");
		return (NULL);
	}
	profile_list_load(&list);
	p = profile_lookup(&list, name);
	if (p == NULL) {
		fprintf(stderr, "bsdinstruments: unknown profile '%s'. "
		    "Try `bsdinstruments list`.\n", name);
		profile_list_free(&list);
		return (NULL);
	}
	/* Detach the match, free the rest. */
	for (pp = &list.head; *pp != NULL; pp = &(*pp)->next) {
		if (*pp == p) {
			*pp = p->next;
			p->next = NULL;
			break;
		}
	}
	profile_list_free(&list);
	return (p);
}

/*
 * Replace every occurrence of "needle" with "repl" in a malloc'd
 * string, returning a new malloc'd string.
 */
static char *
replace_all(const char *s, const char *needle, const char *repl)
{
	struct {
		char *data;
		size_t len, cap;
	} b = { NULL, 0, 0 };
	const char *p, *hit;
	size_t nlen, rlen, chunk, need;
	char *np;

	nlen = strlen(needle);
	rlen = strlen(repl);
	p = s;
	for (;;) {
		hit = strstr(p, needle);
		chunk = hit != NULL ? (size_t)(hit - p) : strlen(p);
		need = chunk + (hit != NULL ? rlen : 0);
		if (b.len + need + 1 > b.cap) {
			b.cap = b.cap == 0 ? 1024 : b.cap;
			while (b.cap < b.len + need + 1)
				b.cap *= 2;
			np = realloc(b.data, b.cap);
			if (np == NULL) {
				free(b.data);
				return (NULL);
			}
			b.data = np;
		}
		memcpy(b.data + b.len, p, chunk);
		b.len += chunk;
		if (hit == NULL)
			break;
		memcpy(b.data + b.len, repl, rlen);
		b.len += rlen;
		p = hit + nlen;
	}
	b.data[b.len] = '\0';
	return (b.data);
}

/*
 * Match a ${ident} placeholder at "start" (which points at "${").
 * Returns the '}' position and copies the identifier out, or NULL
 * if this is not a well-formed placeholder.
 */
static const char *
placeholder_at(const char *start, char *name, size_t namesize)
{
	const char *p, *end;
	size_t len;

	p = start + 2;
	if (!isalpha((unsigned char)*p) && *p != '_')
		return (NULL);
	for (end = p + 1; isalnum((unsigned char)*end) || *end == '_'; end++)
		;
	if (*end != '}')
		return (NULL);
	len = (size_t)(end - p);
	if (len >= namesize)
		len = namesize - 1;
	memcpy(name, p, len);
	name[len] = '\0';
	return (end);
}

/*
 * Substitute ${name} parameter placeholders.  Returns a malloc'd
 * string, or NULL if a placeholder has no supplied value.
 */
static char *
substitute_params(const char *source, const struct param *params,
    size_t nparams, const char *profile_name)
{
	const char *scan, *end;
	char *result, name[128];
	size_t i;
	int found;

	/* Pass 1: every placeholder must have a supplied value. */
	for (scan = strstr(source, "${"); scan != NULL;
	    scan = strstr(scan + 1, "${")) {
		end = placeholder_at(scan, name, sizeof(name));
		if (end == NULL)
			continue;
		found = 0;
		for (i = 0; i < nparams; i++)
			if (strcmp(params[i].name, name) == 0) {
				found = 1;
				break;
			}
		if (!found) {
			fprintf(stderr, "bsdinstruments: profile '%s' "
			    "requires --param %s=<value>\n", profile_name,
			    name);
			return (NULL);
		}
		scan = end;
	}

	/*
	 * Pass 2: single left-to-right scan.  Substituted values are
	 * emitted verbatim and never rescanned, so a value containing
	 * "${other}" cannot be re-substituted by a later parameter
	 * (order-independent, matching the original Swift splice).
	 */
	{
		struct {
			char *data;
			size_t len, cap;
		} b = { NULL, 0, 0 };
		const char *p2;
		size_t need;
		char *np;

#define	SUB_APPEND(src, n) do {						\
	need = (n);							\
	if (b.len + need + 1 > b.cap) {					\
		b.cap = b.cap == 0 ? 1024 : b.cap;			\
		while (b.cap < b.len + need + 1)			\
			b.cap *= 2;					\
		np = realloc(b.data, b.cap);				\
		if (np == NULL) {					\
			free(b.data);					\
			return (NULL);					\
		}							\
		b.data = np;						\
	}								\
	memcpy(b.data + b.len, (src), need);				\
	b.len += need;							\
} while (0)

		for (p2 = source; *p2 != '\0';) {
			const char *hit, *hend;
			const char *value;

			hit = strstr(p2, "${");
			if (hit == NULL) {
				SUB_APPEND(p2, strlen(p2));
				break;
			}
			hend = placeholder_at(hit, name, sizeof(name));
			if (hend == NULL) {
				/* Not a placeholder; copy past "${". */
				SUB_APPEND(p2, (size_t)(hit + 2 - p2));
				p2 = hit + 2;
				continue;
			}
			SUB_APPEND(p2, (size_t)(hit - p2));
			value = NULL;
			for (i = 0; i < nparams; i++)
				if (strcmp(params[i].name, name) == 0)
					value = params[i].value;
			/* Pass 1 guaranteed a value exists. */
			if (value != NULL)
				SUB_APPEND(value, strlen(value));
			p2 = hend + 1;
		}
#undef SUB_APPEND
		if (b.data == NULL)
			return (strdup(""));
		b.data[b.len] = '\0';
		result = b.data;
	}
	return (result);
}

char *
profile_render(const struct profile *p, const struct render_opts *ro)
{
	const char *ustack_action;
	char *rendered, *next;
	char tick[64];
	size_t len;

	/* 1. Parameter substitution. */
	rendered = substitute_params(p->source, ro->params, ro->nparams,
	    p->name);
	if (rendered == NULL)
		return (NULL);

	/*
	 * 2. Filter-predicate injection, both flavors.  Profiles
	 * without either marker silently ignore filter flags.
	 */
	next = replace_all(rendered, "/* @bsdinstruments-predicate-and */",
	    ro->predicate_and != NULL ? ro->predicate_and : "");
	free(rendered);
	if (next == NULL)
		return (NULL);
	rendered = next;
	next = replace_all(rendered, "/* @bsdinstruments-predicate */",
	    ro->predicate != NULL ? ro->predicate : "");
	free(rendered);
	if (next == NULL)
		return (NULL);
	rendered = next;

	/* 3. Stack capture injection. */
	next = replace_all(rendered, "/* @bsdinstruments-stack */",
	    ro->with_stack ? "stack();" : "");
	free(rendered);
	if (next == NULL)
		return (NULL);
	rendered = next;
	/*
	 * When both stack types are captured, a marker printf between
	 * them lets the structured backend tell kernel frames from
	 * user frames.
	 */
	if (ro->with_ustack)
		ustack_action = ro->with_stack ?
		    "printf(\"__BSDINSTRUMENTS_USTACK__\\n\"); ustack();" :
		    "ustack();";
	else
		ustack_action = "";
	next = replace_all(rendered, "/* @bsdinstruments-ustack */",
	    ustack_action);
	free(rendered);
	if (next == NULL)
		return (NULL);
	rendered = next;

	/* 4. CLI-supplied duration: append a tick exit clause. */
	if (ro->duration > 0) {
		snprintf(tick, sizeof(tick),
		    "\n\ntick-%jdns { exit(0); }\n",
		    (intmax_t)(ro->duration * 1e9));
		len = strlen(rendered) + strlen(tick) + 1;
		next = malloc(len);
		if (next == NULL) {
			free(rendered);
			return (NULL);
		}
		snprintf(next, len, "%s%s", rendered, tick);
		free(rendered);
		rendered = next;
	}

	return (rendered);
}
