/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Unit tests for the profile loader/renderer (profile.c) and the
 * filter predicates (filter.c): the corner cases and failure paths
 * the command-line tests cannot reach, including allocation failure
 * (malloc, calloc, realloc, strdup and strndup are wrapped by the
 * linker; see failalloc_arm()).
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bsdinstruments.h"

/* ---------------------------------------------------------------- */
/* Allocation-failure injection					*/

void	*__real_malloc(size_t);
void	*__real_calloc(size_t, size_t);
void	*__real_realloc(void *, size_t);
char	*__real_strdup(const char *);
char	*__real_strndup(const char *, size_t);
void	*__wrap_malloc(size_t);
void	*__wrap_calloc(size_t, size_t);
void	*__wrap_realloc(void *, size_t);
char	*__wrap_strdup(const char *);
char	*__wrap_strndup(const char *, size_t);

static int fail_at;	/* fail the fail_at'th allocation; 0: never */
static int fail_count;

static void
failalloc_arm(int nth)
{

	fail_at = nth;
	fail_count = 0;
}

static int
failalloc_now(void)
{

	return (fail_at != 0 && ++fail_count == fail_at);
}

void *
__wrap_malloc(size_t n)
{

	if (failalloc_now()) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_malloc(n));
}

void *
__wrap_calloc(size_t n, size_t s)
{

	if (failalloc_now()) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_calloc(n, s));
}

void *
__wrap_realloc(void *p, size_t n)
{

	if (failalloc_now()) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_realloc(p, n));
}

char *
__wrap_strdup(const char *s)
{

	if (failalloc_now()) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_strdup(s));
}

char *
__wrap_strndup(const char *s, size_t n)
{

	if (failalloc_now()) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_strndup(s, n));
}

/* ---------------------------------------------------------------- */
/* Helpers								*/

static void
put_file(const char *path, const char *text)
{
	FILE *fp;

	fp = fopen(path, "w");
	ATF_REQUIRE(fp != NULL);
	fputs(text, fp);
	ATF_REQUIRE_EQ(0, fclose(fp));
}

static struct profile *
mkprofile(const char *name, const char *source)
{
	struct profile *p;

	p = calloc(1, sizeof(*p));
	ATF_REQUIRE(p != NULL);
	p->name = strdup(name);
	p->descr = strdup("");
	p->source = strdup(source);
	p->origin = ORIGIN_EXPLICIT;
	return (p);
}

static char *
render(const char *source, const struct render_opts *ro)
{
	struct profile *p;
	char *out;

	p = mkprofile("t", source);
	out = profile_render(p, ro);
	profile_free(p);
	return (out);
}

static const char *
userdir(void)
{
	static char dir[PATH_MAX];
	char cwd[PATH_MAX];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	setenv("HOME", cwd, 1);
	snprintf(dir, sizeof(dir), "%s/.bsdinstruments/profiles", cwd);
	ATF_REQUIRE_EQ(0, mkdir(".bsdinstruments", 0755));
	ATF_REQUIRE_EQ(0, mkdir(dir, 0755));
	return (dir);
}

/* ---------------------------------------------------------------- */
/* Loading								*/

ATF_TC_WITHOUT_HEAD(origin_names);
ATF_TC_BODY(origin_names, tc)
{

	ATF_REQUIRE_STREQ("base", profile_origin_name(ORIGIN_BASE));
	ATF_REQUIRE_STREQ("local", profile_origin_name(ORIGIN_SYSTEM));
	ATF_REQUIRE_STREQ("user", profile_origin_name(ORIGIN_USER));
	ATF_REQUIRE_STREQ("explicit", profile_origin_name(ORIGIN_EXPLICIT));
	ATF_REQUIRE_STREQ("unknown",
	    profile_origin_name((enum profile_origin)99));
}

ATF_TC_WITHOUT_HEAD(descriptions);
ATF_TC_BODY(descriptions, tc)
{
	static const struct {
		const char *source, *descr;
	} cases[] = {
		{ "no comment at all", "" },
		{ "/* never closed", "" },
		{ "/**/", "" },
		{ "/*   */", "" },
		{ "/*\n*/", "" },
		{ "/*\n *\n *   \n */", "" },
		{ "/*\n * \tFirst line.  \n * second\n */", "First line." },
		{ "/* inline */", "inline" },
	};
	struct profile *p;
	size_t i;

	for (i = 0; i < nitems(cases); i++) {
		put_file("x.d", cases[i].source);
		p = profile_load_file("x.d");
		ATF_REQUIRE(p != NULL);
		ATF_REQUIRE_STREQ_MSG(cases[i].descr, p->descr, "case %zu", i);
		profile_free(p);
	}
}

ATF_TC(load_dir_entries);
ATF_TC_HEAD(load_dir_entries, tc)
{

	atf_tc_set_md_var(tc, "require.user", "unprivileged");
}
ATF_TC_BODY(load_dir_entries, tc)
{
	struct profile_list list;
	struct profile *p;
	char path[PATH_MAX];
	const char *dir;

	dir = userdir();
	/* Skipped: too short, wrong suffix. */
	snprintf(path, sizeof(path), "%s/.d", dir);
	put_file(path, "/* skipped */");
	snprintf(path, sizeof(path), "%s/notes.txt", dir);
	put_file(path, "/* skipped */");
	/* Unreadable, and a directory: reported and skipped. */
	snprintf(path, sizeof(path), "%s/locked.d", dir);
	put_file(path, "/* locked */");
	ATF_REQUIRE_EQ(0, chmod(path, 0));
	snprintf(path, sizeof(path), "%s/subdir.d", dir);
	ATF_REQUIRE_EQ(0, mkdir(path, 0755));
	snprintf(path, sizeof(path), "%s/a-one.d", dir);
	put_file(path, "/* One. */");
	snprintf(path, sizeof(path), "%s/z-two.d", dir);
	put_file(path, "/* Two. */");
	profile_list_load(&list);
	ATF_REQUIRE(profile_lookup(&list, "a-one") != NULL);
	ATF_REQUIRE(profile_lookup(&list, "z-two") != NULL);
	/* Root reads a mode 0 file anyway. */
	if (geteuid() != 0)
		ATF_REQUIRE(profile_lookup(&list, "locked") == NULL);
	ATF_REQUIRE(profile_lookup(&list, "subdir") == NULL);
	ATF_REQUIRE(profile_lookup(&list, "notes") == NULL);
	ATF_REQUIRE(profile_lookup(&list, "") == NULL);
	profile_list_free(&list);
	ATF_REQUIRE(list.head == NULL);
	/* Resolution detaches the match from anywhere in the list. */
	p = profile_resolve("z-two", NULL);
	ATF_REQUIRE(p != NULL && p->next == NULL);
	ATF_REQUIRE_STREQ("Two.", p->descr);
	profile_free(p);
	p = profile_resolve("a-one", NULL);
	ATF_REQUIRE(p != NULL);
	profile_free(p);
	ATF_REQUIRE(profile_resolve("missing", NULL) == NULL);
	p = profile_resolve(NULL, path);	/* -f wins */
	ATF_REQUIRE_STREQ("z-two", p->name);
	ATF_REQUIRE_EQ(ORIGIN_EXPLICIT, p->origin);
	profile_free(p);
	ATF_REQUIRE(profile_resolve(NULL, NULL) == NULL);
	profile_free(NULL);
	/* Without HOME only the system tiers load. */
	unsetenv("HOME");
	profile_list_load(&list);
	ATF_REQUIRE(profile_lookup(&list, "a-one") == NULL);
	profile_list_free(&list);
}

ATF_TC_WITHOUT_HEAD(load_file_names);
ATF_TC_BODY(load_file_names, tc)
{
	char longname[NAME_MAX + 1];
	struct profile *p;

	put_file("plain", "/* x */");
	p = profile_load_file("plain");
	ATF_REQUIRE_STREQ("plain", p->name);
	ATF_REQUIRE_EQ(ORIGIN_EXPLICIT, p->origin);
	profile_free(p);
	ATF_REQUIRE_EQ(0, mkdir("d", 0755));
	put_file("d/.hidden", "/* x */");
	p = profile_load_file("d/.hidden");
	ATF_REQUIRE_STREQ(".hidden", p->name);
	profile_free(p);
	/* A name as long as the file system allows is truncated. */
	memset(longname, 'n', NAME_MAX);
	longname[NAME_MAX] = '\0';
	put_file(longname, "/* x */");
	p = profile_load_file(longname);
	ATF_REQUIRE_EQ(NAME_MAX - 1, strlen(p->name));
	profile_free(p);
	ATF_REQUIRE(profile_load_file("does-not-exist.d") == NULL);
	ATF_REQUIRE(profile_load_file("d") == NULL);	/* a directory */
}

ATF_TC_WITHOUT_HEAD(load_alloc_failure);
ATF_TC_BODY(load_alloc_failure, tc)
{
	struct profile_list list;
	struct profile *p;
	char path[PATH_MAX];
	const char *dir;
	int i, ok;

	dir = userdir();
	snprintf(path, sizeof(path), "%s/one.d", dir);
	put_file(path, "/*\n * One.\n */\n");
	ok = 0;
	for (i = 1; i <= 20; i++) {
		failalloc_arm(i);
		p = profile_load_file(path);
		failalloc_arm(0);
		if (p != NULL) {
			ok++;
			profile_free(p);
		}
	}
	ATF_REQUIRE(ok > 0);
	/* Without a comment the description is an empty copy. */
	put_file("bare.d", "syscall:::entry {}\n");
	for (i = 1; i <= 6; i++) {
		failalloc_arm(i);
		profile_free(profile_load_file("bare.d"));
		failalloc_arm(0);
	}
	/* The base tier may hold many profiles; sweep the first ones. */
	for (i = 1; i <= 40; i++) {
		failalloc_arm(i);
		profile_list_load(&list);
		failalloc_arm(0);
		profile_list_free(&list);
		failalloc_arm(i);
		p = profile_resolve("one", NULL);
		failalloc_arm(0);
		profile_free(p);
	}
	/* HOME naming a file: there is no user tier. */
	setenv("HOME", path, 1);
	profile_list_load(&list);
	profile_list_free(&list);
}

/* ---------------------------------------------------------------- */
/* Rendering							*/

ATF_TC_WITHOUT_HEAD(params);
ATF_TC_BODY(params, tc)
{
	struct param params[4] = {
		{ "other", "O" }, { "what", "${other}" }, { "_u", "U" },
		{ "a_b9", "AB" }
	};
	struct render_opts ro;
	char longsrc[400], *out;
	int n;

	memset(&ro, 0, sizeof(ro));
	ro.params = params;
	ro.nparams = 4;
	out = render("${_u}${a_b9}", &ro);
	ATF_REQUIRE_STREQ("UAB", out);
	free(out);
	/* Values are not rescanned; non-placeholders are copied. */
	out = render("a ${what} $${ ${1x} ${a-b} ${} ${other}", &ro);
	ATF_REQUIRE_STREQ("a ${other} $${ ${1x} ${a-b} ${} O", out);
	free(out);
	out = render("", &ro);
	ATF_REQUIRE_STREQ("", out);
	free(out);
	out = render("${what}", &ro);
	ATF_REQUIRE_STREQ("${other}", out);
	free(out);
	/* A missing value; an over-long name (truncated, so missing). */
	ATF_REQUIRE(render("x ${missing} y", &ro) == NULL);
	n = snprintf(longsrc, sizeof(longsrc), "${");
	memset(longsrc + n, 'k', 200);
	snprintf(longsrc + n + 200, sizeof(longsrc) - (size_t)n - 200, "}");
	ATF_REQUIRE(render(longsrc, &ro) == NULL);
	ro.nparams = 0;
	out = render("${", &ro);
	ATF_REQUIRE_STREQ("${", out);
	free(out);
}

ATF_TC_WITHOUT_HEAD(render_markers);
ATF_TC_BODY(render_markers, tc)
{
	struct render_opts ro;
	char *big, *out;
	size_t i;

	memset(&ro, 0, sizeof(ro));
	ro.predicate = "/pid == 1/";
	ro.predicate_and = " && pid == 1";
	ro.with_ustack = 1;
	out = render("a\n/* @bsdinstruments-predicate */\n"
	    "/x /* @bsdinstruments-predicate-and */ /\n"
	    "/* @bsdinstruments-stack */ /* @bsdinstruments-ustack */\n"
	    "/* @bsdinstruments-context */", &ro);
	ATF_REQUIRE(strstr(out, "/pid == 1/") != NULL);
	ATF_REQUIRE(strstr(out, "/x  && pid == 1 /") != NULL);
	ATF_REQUIRE(strstr(out, " ustack();") != NULL);
	ATF_REQUIRE(strstr(out, "USTACK") == NULL);
	ATF_REQUIRE(strstr(out, "stack();") == strstr(out, "ustack();") + 1);
	ATF_REQUIRE(strstr(out, "otel.ctx") == NULL);
	free(out);
	/* NULL predicates render as nothing. */
	ro.predicate = ro.predicate_and = NULL;
	ro.with_ustack = 0;
	ro.with_stack = 1;
	ro.structured = 1;
	ro.duration = 0.5;
	out = render("/* @bsdinstruments-predicate */"
	    "/* @bsdinstruments-stack */", &ro);
	ATF_REQUIRE(strncmp(out, "printf(\"\\037otel.ctx", 18) == 0);
	ATF_REQUIRE(strstr(out, " stack();") != NULL);
	ATF_REQUIRE(strstr(out, "tick-500000000ns") != NULL);
	free(out);
	/* Output longer than the first buffer. */
	big = malloc(8192);
	for (i = 0; i + 40 < 8192; i += 34)
		memcpy(big + i, "/* @bsdinstruments-predicate */ ;\n", 34);
	big[i] = '\0';
	ro.predicate = "/a really rather long predicate here/";
	ro.structured = 0;
	ro.duration = 0;
	out = render(big, &ro);
	ATF_REQUIRE(out != NULL && strlen(out) > 8192);
	free(out);
	free(big);
}

ATF_TC_WITHOUT_HEAD(span_markers);
ATF_TC_BODY(span_markers, tc)
{
	static const char *const bad[] = {
		/* unterminated marker, string, or comment inside */
		"/* @bsdinstruments-span(name=\"x\", start=1",
		"/* @bsdinstruments-span(name=\"x, start=1) */",
		"/* @bsdinstruments-span(name=x */ start=1) */",
		"/* @bsdinstruments-span(name=x, start=1) junk */",
		/* argument errors */
		"/* @bsdinstruments-span(=1, start=1) */",
		"/* @bsdinstruments-span(name, start=1) */",
		"/* @bsdinstruments-span(name=x, start=  ) */",
		"/* @bsdinstruments-span(name=x, start=1, kind=sideways) */",
		"/* @bsdinstruments-span(name=x, start=1, int.=1) */",
		"/* @bsdinstruments-span(name=x, start=1, str.=a) */",
		"/* @bsdinstruments-span(name=x, start=1, bogus=1) */",
		"/* @bsdinstruments-span(name=x) */",
		"/* @bsdinstruments-span(start=1) */",
	};
	struct render_opts ro;
	char many[512], *out;
	size_t i, n;

	memset(&ro, 0, sizeof(ro));
	ro.structured = 1;
	for (i = 0; i < nitems(bad); i++)
		ATF_REQUIRE_MSG(render(bad[i], &ro) == NULL, "case %zu", i);
	/* A backslash ending an unterminated literal. */
	ATF_REQUIRE(render("/* @bsdinstruments-span(name=\"x\\", &ro) == NULL);
	/* Over a buffer's worth of attributes; '*' that ends nothing. */
	n = (size_t)snprintf(many, sizeof(many),
	    "/* @bsdinstruments-span(name=x, start=a*b");
	for (i = 0; i < 25; i++)
		n += (size_t)snprintf(many + n, sizeof(many) - n,
		    ", int.k_%zu=1", i);
	snprintf(many + n, sizeof(many) - n, ")\t*/");
	out = render(many, &ro);
	ATF_REQUIRE(out != NULL && strlen(out) > 1024);
	ATF_REQUIRE(strstr(out, "(int64_t)(a*b)") != NULL);
	ATF_REQUIRE(strstr(out, "\\037a.i.k_24=%d") != NULL);
	free(out);
	/* Too many arguments. */
	n = (size_t)snprintf(many, sizeof(many),
	    "/* @bsdinstruments-span(name=x, start=1");
	for (i = 0; i < 40; i++)
		n += (size_t)snprintf(many + n, sizeof(many) - n, ", error=1");
	snprintf(many + n, sizeof(many) - n, ") */");
	ATF_REQUIRE(render(many, &ro) == NULL);
	/* Literals with escapes and nesting; attribution elsewhere. */
	out = render("{ /* @bsdinstruments-span(name=\"a\\\"b,)\", "
	    "start=f(x[1], ')'), end=t, kind=client, str.k=s[\",\"], "
	    "int.n= 2 ,  pid=p, error=e ) */ }", &ro);
	ATF_REQUIRE(out != NULL);
	ATF_REQUIRE(strstr(out, "\\037kind=client") != NULL);
	ATF_REQUIRE(strstr(out, "\\037a.s.k=%s") != NULL);
	ATF_REQUIRE(strstr(out, "(int64_t)(2)") != NULL);
	ATF_REQUIRE(strstr(out, "(int64_t)(p)") != NULL);
	ATF_REQUIRE(strstr(out, "\\037ppid=") == NULL);
	free(out);
	out = render("/* @bsdinstruments-span(name=n, start=s, execname=e) */",
	    &ro);
	ATF_REQUIRE(strstr(out, "\\037ppid=") == NULL);
	free(out);
	out = render("/* @bsdinstruments-span(name=n, start=s, thread=t) */",
	    &ro);
	ATF_REQUIRE(strstr(out, "\\037ppid=") == NULL);
	ATF_REQUIRE(strstr(out, "(int64_t)(timestamp)") != NULL);
	free(out);
	/* Text output: marker lines vanish, inline markers leave text. */
	ro.structured = 0;
	out = render("a\n\t /* @bsdinstruments-span(name=n, start=s) */\nb\n"
	    "c; /* @bsdinstruments-span(name=n, start=s) */\n"
	    "  /* @bsdinstruments-span(name=n, start=s) */ d\n"
	    "/* @bsdinstruments-span(name=n, start=s) */"
	    "/* @bsdinstruments-span(name=n, start=s) */", &ro);
	ATF_REQUIRE_STREQ("a\nb\nc; \n d\n", out);
	free(out);
}

ATF_TC_WITHOUT_HEAD(render_alloc_failure);
ATF_TC_BODY(render_alloc_failure, tc)
{
	struct param params[1] = { { "what", "open" } };
	struct render_opts ro;
	struct profile *p;
	char *out;
	int i, ok = 0;

	p = mkprofile("t", "/*\n * T.\n */\nsyscall::${what}:entry\n"
	    "/* @bsdinstruments-predicate */\n{\n"
	    "/x /* @bsdinstruments-predicate-and */ /\n"
	    "/* @bsdinstruments-context */\n"
	    "/* @bsdinstruments-stack */\n/* @bsdinstruments-ustack */\n"
	    "/* @bsdinstruments-span(name=\"s\", start=1, int.a=1, str.b=\"\","
	    " kind=server) */\n}\n");
	memset(&ro, 0, sizeof(ro));
	ro.params = params;
	ro.nparams = 1;
	ro.predicate = "/pid == 1/";
	ro.predicate_and = " && pid == 1";
	ro.with_stack = ro.with_ustack = 1;
	ro.structured = 1;
	ro.duration = 1;
	for (i = 1; i <= 40; i++) {
		failalloc_arm(i);
		out = profile_render(p, &ro);
		failalloc_arm(0);
		if (out != NULL)
			ok++;
		free(out);
	}
	ATF_REQUIRE(ok > 0);
	profile_free(p);
}

/* ---------------------------------------------------------------- */
/* Filters								*/

ATF_TC_WITHOUT_HEAD(filters);
ATF_TC_BODY(filters, tc)
{
	struct filter_opts fo;
	char longexec[1100], longwhere[1500], *s;

	memset(&fo, 0, sizeof(fo));
	s = filter_predicate(&fo);
	ATF_REQUIRE_STREQ("", s);
	free(s);
	s = filter_predicate_and(&fo);
	ATF_REQUIRE_STREQ("", s);
	free(s);
	fo.have_pid = 1;
	fo.pid = 7;
	fo.execname = "a\"b";
	fo.have_uid = 1;
	fo.uid = 8;
	fo.have_gid = 1;
	fo.gid = 9;
	fo.have_jail = 1;
	fo.jail = 3;
	fo.where = "x > 1 || y";
	s = filter_predicate(&fo);
	ATF_REQUIRE_STREQ("/pid == 7 && execname == \"a\\\"b\" && uid == 8 && "
	    "gid == 9 && curproc->p_ucred->cr_prison->pr_id == 3 && "
	    "(x > 1 || y)/", s);
	free(s);
	s = filter_predicate_and(&fo);
	ATF_REQUIRE(strncmp(s, " && pid == 7 && ", 16) == 0);
	free(s);
	/* Each flag alone. */
	memset(&fo, 0, sizeof(fo));
	fo.have_gid = 1;
	s = filter_predicate(&fo);
	ATF_REQUIRE_STREQ("/gid == 0/", s);
	free(s);
	memset(&fo, 0, sizeof(fo));
	fo.have_jail = 1;
	s = filter_predicate_and(&fo);
	ATF_REQUIRE_STREQ(" && curproc->p_ucred->cr_prison->pr_id == 0", s);
	free(s);
	memset(&fo, 0, sizeof(fo));
	fo.have_uid = 1;
	s = filter_predicate(&fo);
	ATF_REQUIRE_STREQ("/uid == 0/", s);
	free(s);
	/* An over-long execname is cut; quotes never split. */
	memset(longexec, '"', sizeof(longexec) - 1);
	longexec[sizeof(longexec) - 1] = '\0';
	memset(&fo, 0, sizeof(fo));
	fo.execname = longexec;
	s = filter_predicate(&fo);
	ATF_REQUIRE(strlen(s) < 600);
	ATF_REQUIRE(strstr(s, "\\\"\"") != NULL);
	free(s);
	/* Clauses longer than the first buffer grow it. */
	memset(longwhere, 'w', sizeof(longwhere) - 1);
	longwhere[sizeof(longwhere) - 1] = '\0';
	memset(&fo, 0, sizeof(fo));
	fo.have_pid = 1;
	fo.where = longwhere;	/* each clause is cut at 1023 */
	fo.execname = "x";
	fo.have_uid = 1;
	s = filter_predicate(&fo);
	ATF_REQUIRE(strlen(s) > 1024);
	free(s);
	/* An allocation failure in the final wrapping returns NULL. */
	memset(&fo, 0, sizeof(fo));
	fo.have_pid = 1;
	failalloc_arm(2);
	ATF_REQUIRE(filter_predicate(&fo) == NULL);
	failalloc_arm(2);
	ATF_REQUIRE(filter_predicate_and(&fo) == NULL);
	failalloc_arm(0);
}

/* A filter is never silently dropped: allocation failure exits. */
ATF_TC_WITHOUT_HEAD(filter_alloc_exit);
ATF_TC_BODY(filter_alloc_exit, tc)
{
	struct filter_opts fo;

	memset(&fo, 0, sizeof(fo));
	fo.have_pid = 1;
	atf_tc_expect_exit(1, "malloc failure exits");
	failalloc_arm(1);
	(void)filter_predicate(&fo);
}

ATF_TC_WITHOUT_HEAD(filter_grow_exit);
ATF_TC_BODY(filter_grow_exit, tc)
{
	char longwhere[1500];
	struct filter_opts fo;

	memset(longwhere, 'w', sizeof(longwhere) - 1);
	longwhere[sizeof(longwhere) - 1] = '\0';
	memset(&fo, 0, sizeof(fo));
	fo.have_pid = 1;
	fo.where = longwhere;
	atf_tc_expect_exit(1, "realloc failure exits");
	failalloc_arm(2);
	(void)filter_predicate(&fo);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, origin_names);
	ATF_TP_ADD_TC(tp, descriptions);
	ATF_TP_ADD_TC(tp, load_dir_entries);
	ATF_TP_ADD_TC(tp, load_file_names);
	ATF_TP_ADD_TC(tp, load_alloc_failure);
	ATF_TP_ADD_TC(tp, params);
	ATF_TP_ADD_TC(tp, render_markers);
	ATF_TP_ADD_TC(tp, span_markers);
	ATF_TP_ADD_TC(tp, render_alloc_failure);
	ATF_TP_ADD_TC(tp, filters);
	ATF_TP_ADD_TC(tp, filter_alloc_exit);
	ATF_TP_ADD_TC(tp, filter_grow_exit);
	return (atf_no_error());
}
