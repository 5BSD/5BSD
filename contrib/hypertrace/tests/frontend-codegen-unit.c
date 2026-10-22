/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Direct checks of libdtrace's identifier hash (dt_ident.c), register set
 * (dt_regset.c) and compile-ident list (dtrace_compile_idents_set) against
 * their documented contracts:
 *
 *  - dt_idhash_create(name, tmpl, min, max): a hash whose template entries
 *    are inserted lazily by the first lookup, insert, xinsert or iteration;
 *    dt_idhash_nextid() hands out min..max-1 and then fails; iteration visits
 *    identifiers in (id, name) order and stops at the first non-zero
 *    callback result, which it returns; dt_idhash_update() recomputes the
 *    next id from the variables/aggregations present.
 *  - dt_regset: a register bitmap; alloc returns the lowest free register,
 *    free releases it, reset frees everything, assert_free reports leaks
 *    (aborting only when DTRACE_DEBUG_REGSET is set, which it is not here).
 *  - dt_idkind_name(): a distinct description for each identifier kind and
 *    "<?>" for unknown kinds.
 *  - dtrace_compile_idents_set(): rejects NULL, appends one list entry per
 *    DT_PROG_IDENTLEN-byte identifier.
 *
 * Output: "PASS name" / "FAIL name: detail" lines.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <dt_impl.h>
#include <dt_ident.h>
#include <dt_regset.h>
#include <dt_resolver.h>

static int failures;

static void
check(const char *name, int ok, const char *detail)
{
	if (ok) {
		printf("PASS %s\n", name);
	} else {
		printf("FAIL %s: %s\n", name, detail);
		failures++;
	}
}

static const dtrace_attribute_t attr = { DTRACE_STABILITY_STABLE,
    DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON };

/* Template: three scalars with ids 7, 3 and 5 (iteration sorts by id). */
static const dt_ident_t tmpl[] = {
	{ "tz", DT_IDENT_SCALAR, 0, 7, { DTRACE_STABILITY_STABLE,
	    DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON }, 0 },
	{ "ta", DT_IDENT_SCALAR, 0, 3, { DTRACE_STABILITY_STABLE,
	    DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON }, 0 },
	{ "tm", DT_IDENT_ARRAY, 0, 5, { DTRACE_STABILITY_STABLE,
	    DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON }, 0 },
	{ NULL }
};

static int order[8], norder;

static int
collect(dt_idhash_t *dhp, dt_ident_t *idp, void *arg)
{
	int stop = arg != NULL ? *(int *)arg : -1;

	(void) dhp;
	order[norder++] = (int)idp->di_id;
	return (norder == stop ? 42 : 0);
}

static void
idhash_cases(void)
{
	dt_idhash_t *dhp;
	dt_ident_t *idp;
	uint_t id;
	int stop, rv;
	char buf[128];

	/* Lookup first populates the template. */
	dhp = dt_idhash_create("t-lookup", tmpl, 10, 12);
	idp = dt_idhash_lookup(dhp, "tm");
	check("idhash-lookup-populates", idp != NULL && idp->di_id == 5 &&
	    dt_idhash_size(dhp) == 3 && dt_idhash_lookup(dhp, "nope") == NULL &&
	    strcmp(dt_idhash_name(dhp), "t-lookup") == 0, "lookup");
	/* nextid hands out [min, max) and then fails. */
	{
		uint_t a = 0, b = 0;
		int r1 = dt_idhash_nextid(dhp, &a);
		int r2 = dt_idhash_nextid(dhp, &b);
		int r3 = dt_idhash_nextid(dhp, &id);

		check("idhash-nextid-exhausts", r1 == 0 && a == 10 &&
		    r2 == 0 && b == 11 && r3 == -1, "nextid");
	}
	/* update(): next id is max(min, highest scalar/array/agg id + 1). */
	dt_idhash_update(dhp);
	check("idhash-update-min", dhp->dh_nextid == 10, "update below min");
	(void) dt_idhash_insert(dhp, "big", DT_IDENT_AGG, 0, 40, attr, 0,
	    &dt_idops_thaw, NULL, 0);
	(void) dt_idhash_insert(dhp, "fn", DT_IDENT_FUNC, 0, 90, attr, 0,
	    &dt_idops_thaw, NULL, 0);
	dt_idhash_update(dhp);
	check("idhash-update-max", dhp->dh_nextid == 41, "update ignores func");
	dt_idhash_destroy(dhp);

	/* Insert first populates, then adds. */
	dhp = dt_idhash_create("t-insert", tmpl, 0, 100);
	idp = dt_idhash_insert(dhp, "new", DT_IDENT_SCALAR, 0, 9, attr, 0,
	    &dt_idops_thaw, NULL, 0);
	check("idhash-insert-populates", idp != NULL &&
	    dt_idhash_size(dhp) == 4 && dt_idhash_lookup(dhp, "ta") != NULL,
	    "insert");
	/* Delete removes exactly one identifier. */
	dt_idhash_delete(dhp, idp);
	check("idhash-delete", dt_idhash_size(dhp) == 3 &&
	    dt_idhash_lookup(dhp, "new") == NULL, "delete");
	dt_idhash_destroy(dhp);

	/* Orphan xinsert first populates and clears the orphan flag. */
	dhp = dt_idhash_create("t-xinsert", tmpl, 0, 100);
	idp = dt_ident_create("orph", DT_IDENT_SCALAR, DT_IDFLG_ORPHAN, 11,
	    attr, 0, &dt_idops_thaw, NULL, 0);
	dt_idhash_xinsert(dhp, idp);
	check("idhash-xinsert-populates", dt_idhash_size(dhp) == 4 &&
	    !(idp->di_flags & DT_IDFLG_ORPHAN) &&
	    dt_idhash_lookup(dhp, "orph") == idp, "xinsert");
	dt_idhash_destroy(dhp);

	/* Iteration first populates; order is by id; non-zero stops. */
	dhp = dt_idhash_create("t-iter", tmpl, 0, 100);
	norder = 0;
	rv = dt_idhash_iter(dhp, collect, NULL);
	snprintf(buf, sizeof (buf), "rv %d n %d order %d %d %d", rv, norder,
	    order[0], order[1], order[2]);
	check("idhash-iter-populates-sorted", rv == 0 && norder == 3 &&
	    order[0] == 3 && order[1] == 5 && order[2] == 7, buf);
	norder = 0;
	stop = 2;
	rv = dt_idhash_iter(dhp, collect, &stop);
	check("idhash-iter-stops", rv == 42 && norder == 2, "early stop");
	/* Equal ids order by name. */
	(void) dt_idhash_insert(dhp, "tb", DT_IDENT_SCALAR, 0, 3, attr, 0,
	    &dt_idops_thaw, NULL, 0);
	norder = 0;
	(void) dt_idhash_iter(dhp, collect, NULL);
	check("idhash-iter-tie", norder == 4 && order[0] == 3 &&
	    order[1] == 3 && order[2] == 5, "tie order");
	dt_idhash_destroy(dhp);

	/* An empty template-less hash. */
	dhp = dt_idhash_create("t-empty", NULL, 0, 0);
	check("idhash-empty", dt_idhash_size(dhp) == 0 &&
	    dt_idhash_nextid(dhp, &id) == -1 &&
	    dt_idhash_iter(dhp, collect, NULL) == 0, "empty");
	dt_idhash_destroy(dhp);
}

static void
idkind_cases(void)
{
	const char *names[DT_IDENT_PROBE + 1];
	int i, j, ok = 1;

	for (i = 0; i <= DT_IDENT_PROBE; i++) {
		names[i] = dt_idkind_name(i);
		if (names[i] == NULL || strcmp(names[i], "<?>") == 0)
			ok = 0;
		for (j = 0; j < i; j++)
			if (strcmp(names[i], names[j]) == 0)
				ok = 0;
	}
	check("idkind-distinct", ok, "kind names");
	check("idkind-unknown", strcmp(dt_idkind_name(DT_IDENT_PROBE + 1),
	    "<?>") == 0 && strcmp(dt_idkind_name(1000), "<?>") == 0,
	    "unknown kind");
}

static void
regset_cases(void)
{
	dt_regset_t *drp = dt_regset_create(130);
	int i, ok = 1, r;
	char buf[96];

	/* Allocation is lowest-free-first across bitmap words. */
	for (i = 0; i < 130; i++) {
		if ((r = dt_regset_alloc(drp)) != i) {
			ok = 0;
			snprintf(buf, sizeof (buf), "alloc %d got %d", i, r);
		}
	}
	check("regset-alloc-order", ok, buf);
	dt_regset_free(drp, 64);
	dt_regset_free(drp, 3);
	r = dt_regset_alloc(drp);
	check("regset-lowest-free", r == 3 && dt_regset_alloc(drp) == 64,
	    "reuse");
	/* Leaks are reported without aborting (DTRACE_DEBUG_REGSET unset). */
	dt_regset_assert_free(drp);
	check("regset-assert-leak", 1, "");
	dt_regset_reset(drp);
	dt_regset_assert_free(drp);
	check("regset-reset", dt_regset_alloc(drp) == 0, "reset");
	dt_regset_destroy(drp);

	drp = dt_regset_create(1);
	check("regset-single", dt_regset_alloc(drp) == 0, "single");
	dt_regset_free(drp, 0);
	check("regset-single-reuse", dt_regset_alloc(drp) == 0, "reuse");
	dt_regset_destroy(drp);
}

static void
idents_cases(void)
{
	dtrace_hdl_t *dtp;
	int err, n = 0;
	char idents[2 * DT_PROG_IDENTLEN];
	dt_identlist_t *ip;

	dtp = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV | DTRACE_O_NOSYS,
	    &err);
	assert(dtp != NULL);
	memset(idents, 0xa5, sizeof (idents));
	idents[DT_PROG_IDENTLEN] = 0x5a;
	check("idents-null", dtrace_compile_idents_set(dtp, NULL, 1) == -1,
	    "NULL");
	check("idents-set", dtrace_compile_idents_set(dtp, idents, 2) == 0,
	    "set");
	for (ip = dt_list_next(&dtp->dt_compile_idents); ip != NULL;
	    ip = dt_list_next(ip)) {
		if (memcmp(ip->dtil_ident, idents + n * DT_PROG_IDENTLEN,
		    DT_PROG_IDENTLEN) != 0)
			n = 100;
		n++;
	}
	check("idents-list", n == 2, "list contents");
	dtrace_close(dtp);
}

/*
 * Run with frontend-codegen-resolver-shim.so preloaded (gethostname() and
 * kern.osrelease fail with EIO).  Matching a probe target then needs the
 * local identity: a compilation reports an error and dt_resolve() outside a
 * compilation returns DT_RESOLVE_ERROR with errno EIO; the process is not
 * terminated (previously errx()).
 */
static void
resolver_cases(void)
{
	static const uint32_t flags[] = { 1, 2 };
	static const char *const what[] = { "hostname", "OS release" };
	dtrace_hdl_t *dtp;
	dtrace_prog_t *pgp;
	int err, i;
	char detail[256];

	for (i = 0; i < 2; i++) {
		dtp = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV |
		    DTRACE_O_NOSYS, &err);
		assert(dtp != NULL);
		(void) dtrace_setopt(dtp, "nolibs", NULL);
		dtrace_resolver_setflags(flags[i]);
		pgp = dtrace_program_strcompile(dtp,
		    "sometarget:fbt::foo:entry { x = args[0]; trace(x); }",
		    DTRACE_PROBESPEC_NAME, DTRACE_C_ZDEFS, 0, NULL);
		snprintf(detail, sizeof (detail), "pgp %p: %s", (void *)pgp,
		    pgp == NULL ? dtrace_errmsg(dtp, dtrace_errno(dtp)) : "");
		check(i == 0 ? "resolver-compile-hostname" :
		    "resolver-compile-osrelease", pgp == NULL &&
		    strstr(dtrace_errmsg(dtp, dtrace_errno(dtp)),
		    what[i]) != NULL, detail);
		dtrace_close(dtp);

		errno = 0;
		err = dt_resolve("sometarget", flags[i]);
		snprintf(detail, sizeof (detail), "rv %d errno %d", err,
		    errno);
		check(i == 0 ? "resolver-direct-hostname" :
		    "resolver-direct-osrelease",
		    err == DT_RESOLVE_ERROR && errno == EIO, detail);
	}
	dtrace_resolver_setflags(0);
}

/*
 * dt_resolve() matching against the real local identity.  Oracles are read
 * here independently: gethostname() and the kern.osrelease sysctl, with the
 * documented "FreeBSD-<release>" form for the version flag; patterns are
 * fnmatch(3) globs; an empty target matches every machine; flags 0 means
 * the default set by dtrace_resolver_setflags().
 */
static void
resolver_match_cases(void)
{
	char host[MAXHOSTNAMELEN + 1], rel[256], pat[300];
	size_t len = sizeof (rel);

	memset(host, 0, sizeof (host));
	assert(gethostname(host, sizeof (host) - 1) == 0 && host[0] != '\0');
	assert(sysctlbyname("kern.osrelease", rel, &len, NULL, 0) == 0);

	check("resolve-host-exact", dt_resolve(host, 1) == 0, host);
	snprintf(pat, sizeof (pat), "%c*", host[0]);
	check("resolve-host-glob", dt_resolve(pat, 1) == 0, pat);
	snprintf(pat, sizeof (pat), "FreeBSD-%s", rel);
	check("resolve-version-exact", dt_resolve(pat, 2) == 0, pat);
	check("resolve-version-glob", dt_resolve("FreeBSD-*", 2) == 0, rel);
	/* Hostname tried first, then version: both fail to match. */
	check("resolve-nomatch-both", dt_resolve("no-such-target-97", 3) == -1,
	    "no match");
	/* The version is still tried when the hostname does not match. */
	snprintf(pat, sizeof (pat), "FreeBSD-%s", rel);
	check("resolve-version-after-host", dt_resolve(pat, 3) == 0, pat);
	check("resolve-empty", dt_resolve("", 3) == 0 && dt_resolve("", 0) == 0,
	    "empty target");
	dtrace_resolver_setflags(0);
	check("resolve-no-flags", dt_resolve(host, 0) == -1, "flags 0");
	dtrace_resolver_setflags(1);
	check("resolve-default-flags", dt_resolve(host, 0) == 0, "default");
	dtrace_resolver_setflags(0);
}

static const char *abort_name;

static void
on_abort_free(int sig)
{
	(void) sig;
	printf("PASS %s\n", abort_name);
	fflush(stdout);
	exit(0);
}

static void
on_abort(int sig)
{
	(void) sig;
	printf("PASS regset-debug-abort\n");
	fflush(stdout);
	exit(0);
}

int
main(int argc, char **argv)
{
	if (argc > 2 && strcmp(argv[1], "compile") == 0) {
		/*
		 * Compile one clause of N statements and close the handle;
		 * run under frontend-codegen-alloc-shim.so, whose exit report
		 * shows what stayed allocated.
		 */
		int n = atoi(argv[2]), err, i;
		char *p = malloc(64 * n + 64);
		dtrace_hdl_t *dtp;

		strcpy(p, "BEGIN {");
		for (i = 0; i < n; i++)
			strcat(p, " trace((char)arg0 + 1);");
		strcat(p, " }");
		dtp = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV |
		    DTRACE_O_NOSYS, &err);
		assert(dtp != NULL);
		(void) dtrace_setopt(dtp, "nolibs", NULL);
		if (dtrace_program_strcompile(dtp, p, DTRACE_PROBESPEC_NAME, 0,
		    0, NULL) == NULL)
			return (2);
		dtrace_close(dtp);
		free(p);
		return (0);
	}
	if (argc > 1 && (strcmp(argv[1], "regset-free-range") == 0 ||
	    strcmp(argv[1], "regset-free-negative") == 0 ||
	    strcmp(argv[1], "regset-free-twice") == 0)) {
		/*
		 * dt_regset_free()'s contract: the register is in range and
		 * allocated.  A violation fails its assertion (SIGABRT, which
		 * the handler reports as a pass and turns into exit()).
		 */
		dt_regset_t *drp = dt_regset_create(4);
		struct sigaction sa;
		int r;

		memset(&sa, 0, sizeof (sa));
		sa.sa_handler = on_abort_free;
		(void) sigaction(SIGABRT, &sa, NULL);
		abort_name = argv[1];
		r = dt_regset_alloc(drp);
		if (strcmp(argv[1], "regset-free-range") == 0) {
			dt_regset_free(drp, 4);
		} else if (strcmp(argv[1], "regset-free-negative") == 0) {
			dt_regset_free(drp, -1);
		} else {
			dt_regset_free(drp, r);
			dt_regset_free(drp, r);
		}
		printf("FAIL %s: no assertion\n", argv[1]);
		return (1);
	}
	if (argc > 1 && strcmp(argv[1], "regset-abort") == 0) {
		/*
		 * With DTRACE_DEBUG_REGSET set, a leaked register aborts in
		 * dt_regset_assert_free().  The SIGABRT handler reports the
		 * abort and exits normally (so coverage is written).
		 */
		dt_regset_t *drp = dt_regset_create(4);
		struct sigaction sa;

		memset(&sa, 0, sizeof (sa));
		sa.sa_handler = on_abort;
		(void) sigaction(SIGABRT, &sa, NULL);
		(void) dt_regset_alloc(drp);
		dt_regset_assert_free(drp);
		printf("FAIL regset-debug-abort: no abort\n");
		return (1);
	}
	if (argc > 1 && strcmp(argv[1], "resolver") == 0) {
		resolver_cases();
		printf("failures %d\n", failures);
		return (failures != 0);
	}
	idhash_cases();
	resolver_match_cases();
	idkind_cases();
	regset_cases();
	idents_cases();
	printf("failures %d\n", failures);
	return (failures != 0);
}
