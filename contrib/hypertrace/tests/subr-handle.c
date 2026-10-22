/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * libdtrace utility, error, handler and description-map coverage
 * (dt_subr.c, dt_error.c, dt_handle.c, dt_map.c, dt_sugar.c).
 *
 * The dtrace(4) model of consume-ingestion.c is reused unchanged by
 * inclusion; a wrapping vector adds scripted kernel answers that the model
 * does not produce on its own (status drop counters, a hole in the probe
 * ID space, a foreign ECB uarg, a malformed ERROR description, an
 * unparseable format string).  Every expected value is written from the
 * documented interface or the kernel/daemon contract, not captured from
 * the library:
 *
 *  - probe descriptions follow dtrace(1) "provider:module:function:name"
 *    parsing with $N / $$N / $macro substitution;
 *  - attribute and version strings follow the stability/class names and
 *    the 8.12.12-bit version encoding in dt_impl.h / dtrace.h;
 *  - drop and error messages follow the dtrace(1) text emitted by its
 *    default handlers;
 *  - D "if/else" sugar is checked structurally (clauses, predicates and
 *    probes of the generated statements) against the documented rewrite;
 *  - dt_set_progerr() is run in child processes; the guest path is served
 *    by a socket peer that decodes the frame with dtraced's wire decoder.
 *
 * No daemon, tracing device, kernel module or VM is used.
 */

#include <dt_impl.h>
#include <dt_program.h>
#include <dtraced.h>
#include <dtraced_io.h>
#include <dtraced_wire.h>
#include <dtraced_derived.h>
#include <sys/hypertrace_wire.h>

#define	main consume_ingestion_main
#include "consume-ingestion.c"
#undef main

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include <signal.h>

static int nchecks, nfail;
static const char *cur;

#define	OK(cond, ...) do {						\
	nchecks++;							\
	if (!(cond)) {							\
		nfail++;						\
		printf("FAIL %s:%d: ", cur, __LINE__);			\
		printf(__VA_ARGS__);					\
		printf("\n");						\
	}								\
} while (0)

static int
streq(const char *a, const char *b)
{
	return (a != NULL && b != NULL && strcmp(a, b) == 0);
}

/* ------------------------------------------------------------------ */
/* Wrapping vector: scripted kernel answers layered over the model.    */

static struct {
	dtrace_status_t st;		/* added to every STATUS answer */
	uint32_t uarg_epid;		/* EPROBE: report this EPID ... */
	uint64_t uarg;			/* ... with this ECB uarg */
	uint32_t probe_epid;		/* EPROBE: report this EPID ... */
	dtrace_id_t probe_id;		/* ... as firing this probe */
	dtrace_id_t hole;		/* PROBES: this ID is absent */
	const char *fmt;		/* FORMAT: answer this string */
	int aggrecs;			/* AGGDESC: keep only the last N
					   records (N = aggrecs - 1) */
	int poison;			/* ... and name a crafted statement */
} W;

/*
 * A crafted compiler statement whose aggregation variable ID equals
 * DTRACEAGG_COUNT.  dtagd_rec[-1] of an aggregation description overlays
 * the header (dtagd_varid first), so code that indexes the last record of
 * a description without records would see a COUNT action there.
 */
static dt_ident_t poison_ident = { .di_name = "c", .di_id = DTRACEAGG_COUNT };
static dtrace_stmtdesc_t poison_stmt = { .dtsd_aggdata = &poison_ident };
_Static_assert(offsetof(dtrace_aggdesc_t, dtagd_rec) -
    sizeof (dtrace_recdesc_t) == offsetof(dtrace_aggdesc_t, dtagd_varid),
    "dtagd_rec[-1].dtrd_action overlays dtagd_varid");

static int
wrap_ioctl(void *varg, u_long cmd, void *arg)
{
	int rc;

	cmd = CMD(cmd);
	if (cmd == CMD(DTRACEIOC_FORMAT) && W.fmt != NULL) {
		dtrace_fmtdesc_t *f = arg;
		int len = strlen(W.fmt) + 1;

		if (len > f->dtfd_length)
			f->dtfd_length = len;
		else
			memcpy(f->dtfd_string, W.fmt, len);
		return (0);
	}
	if (cmd == CMD(DTRACEIOC_PROBES) && W.hole != 0 &&
	    ((dtrace_probedesc_t *)arg)->dtpd_id == W.hole) {
		/* The kernel answers with the next probe above a hole. */
		((dtrace_probedesc_t *)arg)->dtpd_id = W.hole + 1;
	}
	rc = model_ioctl(varg, cmd, arg);
	if (rc != 0)
		return (rc);
	if (cmd == CMD(DTRACEIOC_STATUS)) {
		dtrace_status_t *st = arg;

		st->dtst_dyndrops += W.st.dtst_dyndrops;
		st->dtst_dyndrops_rinsing += W.st.dtst_dyndrops_rinsing;
		st->dtst_dyndrops_dirty += W.st.dtst_dyndrops_dirty;
		st->dtst_specdrops += W.st.dtst_specdrops;
		st->dtst_specdrops_busy += W.st.dtst_specdrops_busy;
		st->dtst_specdrops_unavail += W.st.dtst_specdrops_unavail;
		st->dtst_stkstroverflows += W.st.dtst_stkstroverflows;
		st->dtst_dblerrors += W.st.dtst_dblerrors;
		st->dtst_killed |= W.st.dtst_killed;
	} else if (cmd == CMD(DTRACEIOC_EPROBE)) {
		dtrace_eprobedesc_t *d = *(dtrace_eprobedesc_t **)arg;

		if (W.uarg_epid != 0 && d->dtepd_epid == W.uarg_epid)
			d->dtepd_uarg = W.uarg;
		if (W.probe_epid != 0 && d->dtepd_epid == W.probe_epid)
			d->dtepd_probeid = W.probe_id;
	} else if (cmd == CMD(DTRACEIOC_AGGDESC) && W.aggrecs != 0) {
		dtrace_aggdesc_t *d = *(dtrace_aggdesc_t **)arg;
		struct mset *ms = &M.set[M.agg[d->dtagd_id - 1].set];
		struct mact *ma = &ms->act[M.agg[d->dtagd_id - 1].act];

		/*
		 * A malformed description: no records (aggrecs 1), or only
		 * the aggregating action's record (aggrecs 2), without the
		 * variable-ID and key records the kernel always reports.
		 */
		d->dtagd_nrecs = W.aggrecs - 1;
		if (W.poison)
			d->dtagd_rec[0].dtrd_uarg = (uintptr_t)&poison_stmt;
		if (W.aggrecs == 2) {
			d->dtagd_rec[0] = ma->rec;
			d->dtagd_rec[0].dtrd_offset -= ma->base;
		}
	}
	return (0);
}

static const dtrace_vector_t wvector = {
	.dtv_ioctl = wrap_ioctl,
	.dtv_lookup_by_addr = model_lookup,
	.dtv_status = model_status,
	.dtv_sysconf = model_sysconf,
};

static void
wreset(void)
{
	reset_model();
	memset(&W, 0, sizeof (W));
}

/* Handler registration selectors for wopen(). */
#define	H_ERR		0x1
#define	H_DROP		0x2
#define	H_ALL		(H_ERR | H_DROP)

static int err_abort, drop_abort;
static unsigned drop_seen;
static dtrace_dropdata_t last_drop;

static int
err_cb2(const dtrace_errdata_t *d, void *arg)
{
	(void) arg;
	event("error: %s", d->dteda_msg);
	return (err_abort ? DTRACE_HANDLE_ABORT : DTRACE_HANDLE_OK);
}

static int
drop_cb2(const dtrace_dropdata_t *d, void *arg)
{
	(void) arg;
	drop_seen++;
	last_drop = *d;
	event("drop cpu=%d kind=%d n=%" PRIu64 " total=%" PRIu64 ": %s",
	    d->dtdda_cpu, d->dtdda_kind, d->dtdda_drops, d->dtdda_total,
	    d->dtdda_msg);
	return (drop_abort ? DTRACE_HANDLE_ABORT : DTRACE_HANDLE_OK);
}

static int
wopen(struct session *s, const char *const *opts, const char *prog,
    int handlers)
{
	dtrace_prog_t *p;
	dtrace_proginfo_t info;
	int err, i;

	memset(s, 0, sizeof (*s));
	err_abort = drop_abort = 0;
	drop_seen = 0;
	s->dtp = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS | DTRACE_O_LP64,
	    &err, &wvector, &M);
	if (s->dtp == NULL) {
		OK(0, "dtrace_vopen: %s", dtrace_errmsg(NULL, err));
		return (-1);
	}
	s->out = open_memstream(&s->text, &s->len);
	assert(s->out != NULL);
	(void) dtrace_setopt(s->dtp, "bufsize", "64k");
	(void) dtrace_setopt(s->dtp, "aggsize", "64k");
	for (i = 0; opts != NULL && opts[i] != NULL; i += 2) {
		if (dtrace_setopt(s->dtp, opts[i], opts[i + 1]) != 0) {
			OK(0, "setopt %s: %s", opts[i], dtrace_errmsg(s->dtp,
			    dtrace_errno(s->dtp)));
			return (-1);
		}
	}
	if ((handlers & H_ERR) && dtrace_handle_err(s->dtp, err_cb2, NULL))
		return (-1);
	if ((handlers & H_DROP) && dtrace_handle_drop(s->dtp, drop_cb2, NULL))
		return (-1);
	if ((p = dtrace_program_strcompile(s->dtp, prog,
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL)) == NULL ||
	    dtrace_program_exec(s->dtp, p, &info) != 0 ||
	    dtrace_go(s->dtp) != 0) {
		OK(0, "session for %s: %s", prog, dtrace_errmsg(s->dtp,
		    dtrace_errno(s->dtp)));
		return (-1);
	}
	return (0);
}

static const char *
evtext(void)
{
	fflush(eventfp);
	return (events);
}

static const char *
outtext(struct session *s)
{
	fflush(s->out);
	return (s->text);
}

static const char *
emsg(dtrace_hdl_t *dtp)
{
	return (dtrace_errmsg(dtp, dtrace_errno(dtp)));
}

/* A plain handle without a device or a vector. */
static dtrace_hdl_t *
nodev(void)
{
	int err;
	dtrace_hdl_t *dtp = dtrace_open(DTRACE_VERSION,
	    DTRACE_O_NODEV | DTRACE_O_NOSYS, &err);

	assert(dtp != NULL);
	return (dtp);
}

/* A vector handle without any program. */
static dtrace_hdl_t *
vhandle(void)
{
	int err;
	dtrace_hdl_t *dtp = dtrace_vopen(DTRACE_VERSION,
	    DTRACE_O_NOSYS | DTRACE_O_LP64, &err, &wvector, &M);

	assert(dtp != NULL);
	return (dtp);
}

/* ------------------------------------------------------------------ */
/* dt_error.c                                                          */

static void
case_errors(void)
{
	dtrace_hdl_t *dtp;
	const char *file;
	int line, e, gaps = 0, unknown = 0;
	char *dup;

	cur = "errmsg-table";
	wreset();
	dtp = vhandle();
	/* A sample of the documented libdtrace messages. */
	OK(streq(dtrace_errmsg(NULL, EDT_VERSION),
	    "Client requested version newer than library"),
	    "EDT_VERSION: %s", dtrace_errmsg(NULL, EDT_VERSION));
	OK(streq(dtrace_errmsg(dtp, EDT_NOMEM), "Memory allocation failure"),
	    "EDT_NOMEM");
	OK(streq(dtrace_errmsg(dtp, EDT_ACTLAST),
	    "Last action of a statement is empty"), "EDT_ACTLAST");
	OK(streq(dtrace_errmsg(dtp, EDT_BADERROR),
	    "Invalid library ERROR action"), "EDT_BADERROR: %s",
	    dtrace_errmsg(dtp, EDT_BADERROR));
	/* Every code in the libdtrace range has its own message. */
	for (e = EDT_BASE; e <= EDT_ACTLAST; e++) {
		if (streq(dtrace_errmsg(dtp, e), "Unknown error"))
			gaps++;
	}
	OK(gaps == 0, "%d EDT codes without a message", gaps);
	/* Past the table: no libdtrace message, falls back to strerror(). */
	OK(streq(dtrace_errmsg(dtp, EDT_ACTLAST + 1),
	    strerror(EDT_ACTLAST + 1)), "past the table");
	OK(streq(dtrace_errmsg(dtp, ENOENT), strerror(ENOENT)), "errno text");
	/* Without a handle there is no compiler or libctf detail. */
	OK(streq(dtrace_errmsg(NULL, EDT_COMPILER),
	    "Error in D program compilation"), "EDT_COMPILER, no handle");
	OK(streq(dtrace_errmsg(NULL, EDT_CTF), "Unexpected libctf error"),
	    "EDT_CTF, no handle: %s", dtrace_errmsg(NULL, EDT_CTF));
	/* EDT_COMPILER without a message uses the table text. */
	dtp->dt_errmsg[0] = '\0';
	OK(streq(dtrace_errmsg(dtp, EDT_COMPILER),
	    "Error in D program compilation"), "EDT_COMPILER without text");
	/* EDT_CTF reports the libctf error that caused it. */
	dtp->dt_ctferr = 1000 /* ECTF_FMT */;
	OK(streq(dtrace_errmsg(dtp, EDT_CTF), ctf_errmsg(1000 /* ECTF_FMT */)),
	    "EDT_CTF: %s", dtrace_errmsg(dtp, EDT_CTF));
	dtp->dt_ctferr = 0;
	OK(!streq(dtrace_errmsg(dtp, EDT_CTF), ctf_errmsg(1000 /* ECTF_FMT */)),
	    "EDT_CTF without a libctf error");
	(void) unknown;

	cur = "error-location";
	/* An option failure records where the library set the error. */
	OK(dtrace_setopt(dtp, "nosuchoption", "1") == -1 &&
	    dtrace_errno(dtp) == EDT_BADOPTNAME, "bad option");
	dt_get_errloc(dtp, &file, &line);
	dup = strdup(file != NULL ? file : "");
	OK(file != NULL && streq(basename(dup), "dt_options.c") && line > 0,
	    "errloc %s:%d", file ? file : "(null)", line);
	free(dup);

	cur = "fault-strings";
	{
		static const struct { int code; const char *str; } f[] = {
			{ DTRACEFLT_BADADDR, "invalid address" },
			{ DTRACEFLT_BADALIGN, "invalid alignment" },
			{ DTRACEFLT_ILLOP, "illegal operation" },
			{ DTRACEFLT_DIVZERO, "divide-by-zero" },
			{ DTRACEFLT_NOSCRATCH, "out of scratch space" },
			{ DTRACEFLT_KPRIV, "invalid kernel access" },
			{ DTRACEFLT_UPRIV, "invalid user access" },
			{ DTRACEFLT_TUPOFLOW, "tuple stack overflow" },
			{ DTRACEFLT_BADSTACK, "bad stack" },
			{ DTRACEFLT_LIBRARY, "library-level fault" },
		};
		size_t i;

		for (i = 0; i < sizeof (f) / sizeof (f[0]); i++)
			OK(streq(dtrace_faultstr(dtp, f[i].code), f[i].str),
			    "fault %d", f[i].code);
		OK(streq(dtrace_faultstr(dtp, 0), "unknown fault") &&
		    streq(dtrace_faultstr(dtp, 9999), "unknown fault"),
		    "unknown fault");
	}

	cur = "progerr-null";
	/* No program: nothing to record. */
	OK(dt_set_progerr(dtp, NULL, "ignored %d", 1) == 0, "returns 0");
	dtrace_close(dtp);
}

/* ------------------------------------------------------------------ */
/* Probe descriptions.                                                 */

static void
case_descriptions(void)
{
	dtrace_hdl_t *dtp;
	dtrace_probedesc_t pd;
	char *const argv[] = { "prog", "open", "7" };
	char buf[256], name[300], want[32];
	int rc;

	cur = "xstr2desc";
	wreset();
	dtp = vhandle();
	OK(dtrace_xstr2desc(dtp, DTRACE_PROBESPEC_NAME + 1, "a", 0, NULL,
	    &pd) == -1 && dtrace_errno(dtp) == EINVAL, "spec above range");
	OK(dtrace_xstr2desc(dtp, DTRACE_PROBESPEC_NONE - 1, "a", 0, NULL,
	    &pd) == -1 && dtrace_errno(dtp) == EINVAL, "spec below range");
	OK(dtrace_str2desc(dtp, DTRACE_PROBESPEC_NAME, "p:m:f:n", &pd) == 0 &&
	    streq(pd.dtpd_provider, "p") && streq(pd.dtpd_mod, "m") &&
	    streq(pd.dtpd_func, "f") && streq(pd.dtpd_name, "n") &&
	    pd.dtpd_id == DTRACE_IDNONE, "four fields");
	OK(dtrace_str2desc(dtp, DTRACE_PROBESPEC_FUNC, "m:f", &pd) == 0 &&
	    streq(pd.dtpd_mod, "m") && streq(pd.dtpd_func, "f") &&
	    pd.dtpd_name[0] == '\0', "fields fill from the given spec");
	/* HyperTrace descriptions may carry a fifth, leading target field. */
	OK(dtrace_str2desc(dtp, DTRACE_PROBESPEC_NAME, "t:p:m:f:n", &pd) ==
	    0 && streq(pd.dtpd_target, "t") && streq(pd.dtpd_provider, "p") &&
	    streq(pd.dtpd_name, "n"), "target field");
	rc = dtrace_str2desc(dtp, DTRACE_PROBESPEC_NAME, "a:b:c:d:e:f", &pd);
	OK(rc == -1 && dtrace_errno(dtp) == EDT_BADSPEC, "six fields: %d %s",
	    rc, emsg(dtp));
	/* $N substitutes argv[N]; $$N is the same; text may surround it. */
	OK(dtrace_xstr2desc(dtp, DTRACE_PROBESPEC_NAME, "syscall::$1:entry",
	    3, argv, &pd) == 0 && streq(pd.dtpd_func, "open"), "$1: %s",
	    pd.dtpd_func);
	OK(dtrace_xstr2desc(dtp, DTRACE_PROBESPEC_NAME, "syscall::$$1:entry",
	    3, argv, &pd) == 0 && streq(pd.dtpd_func, "open"), "$$1");
	OK(dtrace_xstr2desc(dtp, DTRACE_PROBESPEC_NAME, "p:m:pre$2x:n",
	    3, argv, &pd) == 0 && streq(pd.dtpd_func, "pre7x"), "pre$2x: %s",
	    pd.dtpd_func);
	OK(dtrace_xstr2desc(dtp, DTRACE_PROBESPEC_NAME, "p:m:$3:n", 3, argv,
	    &pd) == -1 && dtrace_errno(dtp) == EDT_BADSPCV, "$3 of 3");
	OK(dtrace_xstr2desc(dtp, DTRACE_PROBESPEC_NAME,
	    "p:m:$99999999999999999999:n", 3, argv, &pd) == -1 &&
	    dtrace_errno(dtp) == EDT_BADSPCV, "$N overflow");
	/* $pid is a macro whose value is this process's ID. */
	snprintf(want, sizeof (want), "%d", (int)getpid());
	OK(dtrace_xstr2desc(dtp, DTRACE_PROBESPEC_NAME, "pid$pid:::entry",
	    0, NULL, &pd) == 0 && strncmp(pd.dtpd_provider, "pid", 3) == 0 &&
	    streq(pd.dtpd_provider + 3, want), "$pid: %s", pd.dtpd_provider);
	OK(dtrace_xstr2desc(dtp, DTRACE_PROBESPEC_NAME, "p:m:$nosuchmacro:n",
	    0, NULL, &pd) == -1 && dtrace_errno(dtp) == EDT_BADSPCV,
	    "unknown macro");
	OK(dtrace_xstr2desc(dtp, DTRACE_PROBESPEC_NAME, "p:m:f$:n",
	    0, NULL, &pd) == -1 && dtrace_errno(dtp) == EDT_BADSPCV,
	    "bare $");
	memset(name, 'n', sizeof (name) - 1);
	name[sizeof (name) - 1] = '\0';
	OK(dtrace_str2desc(dtp, DTRACE_PROBESPEC_NAME, name, &pd) == -1 &&
	    dtrace_errno(dtp) == ENAMETOOLONG, "name too long");

	cur = "compile-macro-reference";
	{
		/* $1 used only in a probe description still counts as used. */
		char *const cargv[] = { "prog", "entry" };
		dtrace_prog_t *p = dtrace_program_strcompile(dtp,
		    "test:kernel:alpha:$1 { trace(1); }",
		    DTRACE_PROBESPEC_NAME, 0, 2, cargv);

		OK(p != NULL, "compile: %s", emsg(dtp));
		p = dtrace_program_strcompile(dtp,
		    "test:kernel:alpha:entry { trace(1); }",
		    DTRACE_PROBESPEC_NAME, 0, 2, cargv);
		OK(p == NULL && strstr(emsg(dtp), "extraneous argument") !=
		    NULL, "unused $1 refused: %s", emsg(dtp));
	}

	cur = "id2desc";
	OK(dtrace_id2desc(dtp, 4, &pd) == 0 && pd.dtpd_id == 4 &&
	    streq(pd.dtpd_func, "alpha") && streq(pd.dtpd_name, "entry"),
	    "probe 4");
	OK(dtrace_id2desc(dtp, 99, &pd) == -1 &&
	    dtrace_errno(dtp) == EDT_BADID, "no probe 99");
	W.hole = 3;
	OK(dtrace_id2desc(dtp, 3, &pd) == -1 &&
	    dtrace_errno(dtp) == EDT_BADID, "hole answers the next probe");
	W.hole = 0;

	cur = "desc2str";
	memset(&pd, 0, sizeof (pd));
	strlcpy(pd.dtpd_provider, "p", sizeof (pd.dtpd_provider));
	strlcpy(pd.dtpd_mod, "m", sizeof (pd.dtpd_mod));
	strlcpy(pd.dtpd_func, "f", sizeof (pd.dtpd_func));
	strlcpy(pd.dtpd_name, "n", sizeof (pd.dtpd_name));
	OK(streq(dtrace_desc2str(&pd, buf, sizeof (buf)), "p:m:f:n"),
	    "by name");
	pd.dtpd_id = 42;
	OK(streq(dtrace_desc2str(&pd, buf, sizeof (buf)), "42"), "by id");
	rc = 0;
	(void) rc;
	dtrace_close(dtp);
}

/* ------------------------------------------------------------------ */
/* Attributes and versions.                                            */

static dtrace_attribute_t
attr(int n, int d, int c)
{
	dtrace_attribute_t a;

	a.dtat_name = n;
	a.dtat_data = d;
	a.dtat_class = c;
	return (a);
}

static void
case_attributes(void)
{
	static const char *const stab[] = { "Internal", "Private",
	    "Obsolete", "External", "Unstable", "Evolving", "Stable",
	    "Standard" };
	static const char *const cls[] = { "Unknown", "CPU", "Platform",
	    "Group", "ISA", "Common" };
	dtrace_attribute_t a, b, m;
	char buf[64];
	int i;

	cur = "attribute-names";
	for (i = 0; i <= DTRACE_STABILITY_MAX; i++)
		OK(streq(dtrace_stability_name(i), stab[i]), "stability %d", i);
	for (i = 0; i <= DTRACE_CLASS_MAX; i++)
		OK(streq(dtrace_class_name(i), cls[i]), "class %d", i);
	OK(dtrace_stability_name(DTRACE_STABILITY_MAX + 1) == NULL &&
	    dtrace_class_name(DTRACE_CLASS_MAX + 1) == NULL, "out of range");

	cur = "attr2str";
	OK(streq(dtrace_attr2str(attr(5, 6, 5), buf, sizeof (buf)),
	    "Evolving/Stable/Common"), "valid");
	OK(dtrace_attr2str(attr(99, 6, 5), buf, sizeof (buf)) == NULL &&
	    dtrace_attr2str(attr(5, 99, 5), buf, sizeof (buf)) == NULL &&
	    dtrace_attr2str(attr(5, 6, 99), buf, sizeof (buf)) == NULL,
	    "invalid fields");

	cur = "str2attr";
	OK(dtrace_str2attr(NULL, &a) == -1 && dtrace_str2attr("x", NULL) ==
	    -1, "NULL arguments");
	/* Unspecified fields keep the maximum attribute. */
	OK(dtrace_str2attr("", &a) == 0 &&
	    a.dtat_name == DTRACE_STABILITY_MAX &&
	    a.dtat_data == DTRACE_STABILITY_MAX &&
	    a.dtat_class == DTRACE_CLASS_MAX, "empty");
	OK(dtrace_str2attr("evolving", &a) == 0 &&
	    a.dtat_name == DTRACE_STABILITY_EVOLVING &&
	    a.dtat_data == DTRACE_STABILITY_MAX, "name only, any case");
	OK(dtrace_str2attr("Evolving/", &a) == 0 &&
	    a.dtat_name == DTRACE_STABILITY_EVOLVING &&
	    a.dtat_data == DTRACE_STABILITY_MAX, "trailing slash");
	OK(dtrace_str2attr("Private/STABLE", &a) == 0 &&
	    a.dtat_name == DTRACE_STABILITY_PRIVATE &&
	    a.dtat_data == DTRACE_STABILITY_STABLE &&
	    a.dtat_class == DTRACE_CLASS_MAX, "name/data");
	OK(dtrace_str2attr("Private/Stable/", &a) == 0 &&
	    a.dtat_class == DTRACE_CLASS_MAX, "name/data/");
	OK(dtrace_str2attr("Unstable/Obsolete/isa", &a) == 0 &&
	    a.dtat_name == DTRACE_STABILITY_UNSTABLE &&
	    a.dtat_data == DTRACE_STABILITY_OBSOLETE &&
	    a.dtat_class == DTRACE_CLASS_ISA, "all three");
	OK(dtrace_str2attr("bogus", &a) == -1, "bad name");
	OK(dtrace_str2attr("Stable/bogus", &a) == -1, "bad data");
	OK(dtrace_str2attr("Stable/Stable/bogus", &a) == -1, "bad class");
	OK(dtrace_str2attr("Stable/Stable/CPU/extra", &a) == -1,
	    "fourth field");

	cur = "attr-min-max-cmp";
	a = attr(2, 6, 1);
	b = attr(5, 3, 4);
	m = dt_attr_min(a, b);
	OK(m.dtat_name == 2 && m.dtat_data == 3 && m.dtat_class == 1, "min");
	m = dt_attr_max(a, b);
	OK(m.dtat_name == 5 && m.dtat_data == 6 && m.dtat_class == 4, "max");
	m = dt_attr_min(b, a);
	OK(m.dtat_name == 2 && m.dtat_data == 3 && m.dtat_class == 1,
	    "min, swapped");
	m = dt_attr_max(b, a);
	OK(m.dtat_name == 5 && m.dtat_data == 6 && m.dtat_class == 4,
	    "max, swapped");
	/* <0 if any field is less, 0 if equal, >0 if all >=. */
	OK(dt_attr_cmp(a, b) < 0 && dt_attr_cmp(b, a) < 0, "mixed is less");
	OK(dt_attr_cmp(a, a) == 0, "equal");
	OK(dt_attr_cmp(attr(5, 6, 4), a) > 0, "dominates");

	cur = "attr-str";
	OK(streq(dt_attr_str(attr(0, 7, 0), buf, sizeof (buf)), "[i/S/u]") &&
	    streq(dt_attr_str(attr(5, 6, 5), buf, sizeof (buf)), "[e/s/c]") &&
	    streq(dt_attr_str(attr(3, 4, 4), buf, sizeof (buf)), "[x/u/I]"),
	    "letters");
	/* Regression: index 8 (stability) and 6 (class) are past the tables. */
	OK(streq(dt_attr_str(attr(8, 1, 1), buf, sizeof (buf)), "[8/1/1]"),
	    "stability 8: %s", buf);
	OK(streq(dt_attr_str(attr(9, 1, 1), buf, sizeof (buf)), "[9/1/1]") &&
	    streq(dt_attr_str(attr(1, 9, 1), buf, sizeof (buf)), "[1/9/1]") &&
	    streq(dt_attr_str(attr(1, 1, 6), buf, sizeof (buf)), "[1/1/6]"),
	    "numeric when out of range: %s", buf);
}

static void
case_versions(void)
{
	dt_version_t v;
	char buf[32];

	cur = "version-num2str";
	OK(streq(dt_version_num2str(DT_VERSION_NUMBER(1, 2, 0), buf,
	    sizeof (buf)), "1.2"), "micro 0");
	OK(streq(dt_version_num2str(DT_VERSION_NUMBER(1, 13, 3), buf,
	    sizeof (buf)), "1.13.3"), "micro 3");

	cur = "version-str2num";
	OK(dt_version_str2num("1.2.3", &v) == 0 &&
	    v == DT_VERSION_NUMBER(1, 2, 3), "1.2.3");
	OK(dt_version_str2num("1.2", NULL) == 0, "NULL result");
	OK(dt_version_str2num("1.2.3.4", &v) == -1, "four parts");
	OK(dt_version_str2num("1.x", &v) == -1, "letter");
	snprintf(buf, sizeof (buf), "%u", DT_VERSION_MAJMAX + 1);
	OK(dt_version_str2num(buf, &v) == -1, "major too big");
	snprintf(buf, sizeof (buf), "1.%u", DT_VERSION_MINMAX + 1);
	OK(dt_version_str2num(buf, &v) == -1, "minor too big");
	snprintf(buf, sizeof (buf), "1.1.%u", DT_VERSION_MICMAX + 1);
	OK(dt_version_str2num(buf, &v) == -1, "micro too big");
	/* Regression: long digit strings must not overflow int (UBSan). */
	OK(dt_version_str2num("99999999999999999999", &v) == -1,
	    "overflowing major");
	OK(dt_version_str2num("1.99999999999999999999", &v) == -1,
	    "overflowing minor");
	/* 4294967297 = 2^32 + 1: a wrapping parser would accept "1.0". */
	OK(dt_version_str2num("4294967297.0", &v) == -1, "2^32+1 accepted "
	    "as %u.%u.%u", DT_VERSION_MAJOR(v), DT_VERSION_MINOR(v),
	    DT_VERSION_MICRO(v));

	cur = "version-defined";
	OK(dt_version_defined(DT_VERSION_NUMBER(1, 0, 0)) == 1, "1.0 defined");
	OK(dt_version_defined(DT_VERSION_NUMBER(1, 0, 7)) == 0, "1.0.7 not");
}

/* ------------------------------------------------------------------ */
/* Miscellaneous helpers.                                              */

static void
case_misc(void)
{
	dtrace_hdl_t *dtp;
	char *arg, *mine;
	ulong_t bits[3];
	int maxid = -1, fds[2], i;
	size_t len = sizeof (maxid);
	char tmp[] = "a/b/c", plain[] = "plain";

	cur = "cpp-args";
	wreset();
	dtp = vhandle();
	/* Pop returns what was added last; argv[0] is never popped. */
	mine = dt_cpp_add_arg(dtp, "-DSUBR_HANDLE=1");
	OK(mine != NULL && streq(mine, "-DSUBR_HANDLE=1"), "add");
	arg = dt_cpp_pop_arg(dtp);
	OK(arg == mine, "pop returns the added argument");
	free(arg);
	for (i = 0; i < 64 && (arg = dt_cpp_pop_arg(dtp)) != NULL; i++)
		free(arg);
	OK(dtp->dt_cpp_argc == 1 && dt_cpp_pop_arg(dtp) == NULL,
	    "argv[0] stays");
	/* Growing past the allocated vector doubles it. */
	for (i = 0; i < 40; i++) {
		char a[16];

		snprintf(a, sizeof (a), "-D%d", i);
		OK(dt_cpp_add_arg(dtp, a) != NULL, "add %d", i);
	}
	OK(dtp->dt_cpp_argc == 41 && dtp->dt_cpp_args >= 41 &&
	    streq(dtp->dt_cpp_argv[40], "-D39"), "grown vector");

	cur = "popc";
	OK(dt_popc(0) == 0 && dt_popc(~0UL) == 64 && dt_popc(0x8001) == 2,
	    "popc");
	bits[0] = ~0UL;
	bits[1] = 0x5;
	bits[2] = 0xff;
	OK(dt_popcb(bits, 0) == 0, "n=0");
	OK(dt_popcb(bits, 3) == 3, "below 3");
	OK(dt_popcb(bits, 64) == 64, "one word");
	OK(dt_popcb(bits, 64 + 3) == 66, "into the second word");
	OK(dt_popcb(bits, 128 + 4) == 66 + 4, "into the third word");

	cur = "gmatch-basename";
	OK(dt_gmatch("anything", NULL) && dt_gmatch("anything", "") &&
	    dt_gmatch("vm_fault", "vm_*") && !dt_gmatch("zio", "vm_*"),
	    "gmatch");
	OK(streq(dt_basename(tmp), "c") && streq(dt_basename(plain), "plain"),
	    "basename");
	OK(dt_mutex_held(NULL) == 1, "mutex_held is a stub on FreeBSD");

	cur = "cpu-and-sysconf";
	(void) sysctlbyname("kern.smp.maxid", &maxid, &len, NULL, 0);
	OK(dt_cpu_maxid(dtp) == maxid, "maxid");
	dtrace_close(dtp);
	dtp = nodev();
	/* Without a vector: CPUs 0..kern.smp.maxid are online. */
	OK(dt_status(dtp, 0) == 1 && dt_status(dtp, maxid) == 1 &&
	    dt_status(dtp, maxid + 1) == -1, "status without a vector");
	OK(dt_sysconf(dtp, _SC_PAGESIZE) == sysconf(_SC_PAGESIZE),
	    "sysconf without a vector");
	{
		dtrace_status_t st;

		OK(dt_ioctl(dtp, DTRACEIOC_STATUS, &st) == -1 &&
		    errno == EBADF, "no device: EBADF");
		/* A descriptor that is not dtrace(4) refuses the request. */
		dtp->dt_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
		OK(dt_ioctl(dtp, DTRACEIOC_STATUS, &st) == -1 &&
		    errno == ENOTTY, "non-dtrace descriptor: errno %d",
		    errno);
		close(dtp->dt_fd);
		dtp->dt_fd = -1;
	}

	cur = "dt-write";
	assert(pipe(fds) == 0);
	OK(dt_write(dtp, fds[1], "hello", 5) == 5, "complete write");
	{
		char got[8] = { 0 };

		OK(read(fds[0], got, sizeof (got)) == 5 && streq(got, "hello"),
		    "read back");
	}
	OK(dt_write(dtp, fds[1], "", 0) == 0, "empty write");
	close(fds[0]);
	signal(SIGPIPE, SIG_IGN);
	OK(dt_write(dtp, fds[1], "x", 1) == -1 &&
	    dtrace_errno(dtp) == EPIPE, "broken pipe: %d", dtrace_errno(dtp));
	close(fds[1]);

	cur = "hypertrace-errstr";
	{
		static const struct { int e; const char *s; } t[] = {
			{ E_HYPERTRACE_NONE, "No error" },
			{ E_HYPERTRACE_SYS, "System error" },
			{ E_HYPERTRACE_ELFCREATE, "ELF Creation failed" },
			{ E_HYPERTRACE_ELFPARSE, "ELF Parsing failed" },
			{ E_HYPERTRACE_LIBDTRACE, "Internal libdtrace error" },
			{ E_HYPERTRACE_CHECKSUM, "Checksum error" },
			{ E_HYPERTRACE_AGAIN, "Call the subroutine again" },
			{ E_HYPERTRACE_PROPAGATED, "Propagated error" },
			{ E_HYPERTRACE_IDENT_NOTFOUND, "Identifier not found" },
			{ E_HYPERTRACE_LINKING, "Linking error" },
		};
		size_t k;

		for (k = 0; k < sizeof (t) / sizeof (t[0]); k++)
			OK(streq(dtrace_hypertrace_errstr(t[k].e), t[k].s),
			    "%d", t[k].e);
		OK(streq(dtrace_hypertrace_errstr(-12345), "Unknown error"),
		    "unknown");
	}

	cur = "guest-and-flags";
	OK(dtrace_is_guest(dtp) == 0, "host by default");
	dtrace_set_guest(dtp);
	OK(dtrace_is_guest(dtp) == 1, "guest after set");
	dtrace_set_failmsg_needed(dtp);
	OK(dtp->dt_failmsg_needed == 1, "failmsg flag");
	OK(dtrace_hypertrace_enabled(dtp) == 0, "hypertrace off");
	setenv("_HYPERTRACE_LOG_ELF", "1", 1);
	dtrace_enable_hypertrace(dtp);
	unsetenv("_HYPERTRACE_LOG_ELF");
	OK(dtrace_hypertrace_enabled(dtp) == 1, "hypertrace on");
	dtrace_close(dtp);

	cur = "options-update";
	/* Reloading kernel options reads them back through DOFGET. */
	wreset();
	dtp = vhandle();
	M.opt[DTRACEOPT_STRSIZE] = 333;
	OK(dtrace_hypertrace_options_update(dtp) == 0 &&
	    dtp->dt_options[DTRACEOPT_STRSIZE] == 333, "strsize %jd",
	    (intmax_t)dtp->dt_options[DTRACEOPT_STRSIZE]);
	dtrace_close(dtp);
}

/* A DIFO copy has equal contents in separate storage. */
static void
case_difo_dup(void)
{
	dtrace_hdl_t *dtp;
	dtrace_difo_t src, *d;
	dif_instr_t ins[3] = { 1, 2, 3 };
	uint64_t ints[2] = { 10, 20 };
	char strs[] = "a\0bc";
	char syms[] = "sym";
	dtrace_difv_t vars[1];
	dof_relodesc_t krel[1], urel[2];
	struct dt_node *xl[2];
	int fail = -1;

	cur = "difo-dup";
	wreset();
	dtp = vhandle();
	memset(&src, 0, sizeof (src));
	memset(vars, 0x5a, sizeof (vars));
	memset(krel, 0x11, sizeof (krel));
	memset(urel, 0x22, sizeof (urel));
	xl[0] = (void *)0x1;
	xl[1] = (void *)0x2;
	OK(dt_difo_dup(dtp, NULL, &fail) == NULL && fail == 0, "NULL");
	/* No instructions: nothing to copy and not an allocation failure. */
	fail = -1;
	OK(dt_difo_dup(dtp, &src, &fail) == NULL && fail == 0, "empty");
	src.dtdo_buf = ins;
	src.dtdo_len = 3;
	src.dtdo_rtype.dtdt_size = 8;
	d = dt_difo_dup(dtp, &src, &fail);
	OK(d != NULL && fail == 0 && d->dtdo_buf != ins &&
	    memcmp(d->dtdo_buf, ins, sizeof (ins)) == 0 &&
	    d->dtdo_inttab == NULL && d->dtdo_strtab == NULL &&
	    d->dtdo_rtype.dtdt_size == 8, "instructions only");
	dt_difo_free(dtp, d);
	src.dtdo_inttab = ints;
	src.dtdo_intlen = 2;
	src.dtdo_strtab = strs;
	src.dtdo_strlen = sizeof (strs);
	src.dtdo_symtab = syms;
	src.dtdo_symlen = sizeof (syms);
	src.dtdo_vartab = vars;
	src.dtdo_varlen = 1;
	src.dtdo_kreltab = krel;
	src.dtdo_krelen = 1;
	src.dtdo_ureltab = urel;
	src.dtdo_urelen = 2;
	src.dtdo_xlmtab = xl;
	src.dtdo_xlmlen = 2;
	d = dt_difo_dup(dtp, &src, &fail);
	OK(d != NULL && fail == 0, "all tables");
	if (d != NULL) {
		OK(d->dtdo_inttab != ints && memcmp(d->dtdo_inttab, ints,
		    sizeof (ints)) == 0, "inttab");
		OK(d->dtdo_strtab != strs && memcmp(d->dtdo_strtab, strs,
		    sizeof (strs)) == 0, "strtab");
		OK(d->dtdo_symtab != syms && memcmp(d->dtdo_symtab, syms,
		    sizeof (syms)) == 0, "symtab");
		OK(memcmp(d->dtdo_vartab, vars, sizeof (vars)) == 0, "vartab");
		OK(memcmp(d->dtdo_kreltab, krel, sizeof (krel)) == 0 &&
		    memcmp(d->dtdo_ureltab, urel, sizeof (urel)) == 0,
		    "relocations");
		OK(memcmp(d->dtdo_xlmtab, xl, sizeof (xl)) == 0, "xlmtab");
		OK(d->dtdo_len == 3 && d->dtdo_intlen == 2 &&
		    d->dtdo_urelen == 2, "lengths");
	}
	dt_difo_free(dtp, d);
	dt_difo_free(dtp, NULL);
	dtrace_close(dtp);
}

/* ------------------------------------------------------------------ */
/* Address formatting.                                                 */

static void
case_addr2str(void)
{
	dtrace_hdl_t *dtp;
	char buf[128], small[6];
	int n;

	cur = "addr2str";
	wreset();
	dtp = vhandle();
	n = dtrace_addr2str(dtp, 0xffffffff80001010ULL, buf, sizeof (buf));
	OK(streq(buf, "kernel`vm_fault+0x10") && n == (int)strlen(buf),
	    "offset: %s", buf);
	(void) dtrace_addr2str(dtp, 0xffffffff80002000ULL, buf, sizeof (buf));
	OK(streq(buf, "kernel`sched_tick"), "exact: %s", buf);
	(void) dtrace_addr2str(dtp, 0xffffffff80050000ULL, buf, sizeof (buf));
	OK(streq(buf, "kernel`0xffffffff80050000"), "module only: %s", buf);
	(void) dtrace_addr2str(dtp, 0x1234, buf, sizeof (buf));
	OK(streq(buf, "0x1234"), "unknown: %s", buf);
	/* snprintf-like: size 0 only measures, short buffers terminate. */
	OK(dtrace_addr2str(dtp, 0x1234, NULL, 0) == 6, "measure");
	OK(dtrace_addr2str(dtp, 0xffffffff80001010ULL, small,
	    sizeof (small)) == 20 && streq(small, "kerne"), "truncated: %s",
	    small);
	/* No process to grab: user addresses print raw. */
	(void) dtrace_uaddr2str(dtp, 0, 0x4000, buf, sizeof (buf));
	OK(streq(buf, "0x4000"), "uaddr pid 0: %s", buf);
	dtrace_close(dtp);
}

/* ------------------------------------------------------------------ */
/* Handler registration.                                               */

static int
nop_err(const dtrace_errdata_t *d, void *a)
{
	(void) d; (void) a;
	return (DTRACE_HANDLE_OK);
}

static int
nop_drop(const dtrace_dropdata_t *d, void *a)
{
	(void) d; (void) a;
	return (DTRACE_HANDLE_OK);
}

static void
nop_proc(struct ps_prochandle *P, const char *m, void *a)
{
	(void) P; (void) m; (void) a;
}

static int
nop_buf(const dtrace_bufdata_t *d, void *a)
{
	(void) d; (void) a;
	return (DTRACE_HANDLE_OK);
}

static void
case_registration(void)
{
	dtrace_hdl_t *dtp;

	cur = "handler-registration";
	wreset();
	dtp = vhandle();
	OK(dtrace_handle_err(dtp, nop_err, NULL) == 0, "err");
	OK(dtrace_handle_err(dtp, nop_err, NULL) == -1 &&
	    dtrace_errno(dtp) == EALREADY, "second err handler");
	OK(dtrace_handle_drop(dtp, nop_drop, NULL) == 0 &&
	    dtrace_handle_drop(dtp, nop_drop, NULL) == -1 &&
	    dtrace_errno(dtp) == EALREADY, "drop");
	OK(dtrace_handle_proc(dtp, nop_proc, NULL) == 0 &&
	    dtrace_handle_proc(dtp, nop_proc, NULL) == -1 &&
	    dtrace_errno(dtp) == EALREADY, "proc");
	OK(dtrace_handle_buffered(dtp, NULL, NULL) == -1 &&
	    dtrace_errno(dtp) == EINVAL, "NULL buffered handler");
	OK(dtrace_handle_buffered(dtp, nop_buf, NULL) == 0 &&
	    dtrace_handle_buffered(dtp, nop_buf, NULL) == -1 &&
	    dtrace_errno(dtp) == EALREADY, "buffered");
	OK(dtrace_handle_setopt(dtp, NULL, NULL) == -1 &&
	    dtrace_errno(dtp) == EINVAL, "NULL setopt handler");
	dtrace_close(dtp);
}

/* ------------------------------------------------------------------ */
/* ERROR records and library errors.                                   */

struct walked {
	int n;
	int64_t key, val;
};

/* Aggregation records: variable ID, key, value (the last record). */
static int
walk_anon(const dtrace_aggdata_t *a, void *arg)
{
	struct walked *w = arg;
	const dtrace_aggdesc_t *d = a->dtada_desc;

	/*
	 * Anonymous aggregations have no compiler statement: no name, and the
	 * variable ID is taken from the first (compiler-generated) record.
	 */
	if (d->dtagd_name != NULL || d->dtagd_varid != *(const int32_t *)
	    (a->dtada_data + d->dtagd_rec[0].dtrd_offset))
		return (DTRACE_AGGWALK_NEXT);
	w->n++;
	w->key = *(const int64_t *)(a->dtada_data + d->dtagd_rec[1].dtrd_offset);
	w->val = *(const int64_t *)(a->dtada_data +
	    d->dtagd_rec[d->dtagd_nrecs - 1].dtrd_offset);
	return (DTRACE_AGGWALK_NEXT);
}

static void
case_error_records(void)
{
	struct session s;
	int rc;

	/* Fault details: address for BADALIGN/BADSTACK, none for others. */
	cur = "error-fault-details";
	wreset();
	if (wopen(&s, NULL, TRACE_PROG, H_ALL) == 0) {
		fire(0, "dtrace:::ERROR", 0, VALS(N(1), N(2), N(-1),
		    N(DTRACEFLT_BADALIGN), N(0x31)));
		fire(0, "dtrace:::ERROR", 0, VALS(N(1), N(0), N(4),
		    N(DTRACEFLT_BADSTACK), N(0x40)));
		fire(0, "dtrace:::ERROR", 0, VALS(N(1), N(3), N(16),
		    N(DTRACEFLT_ILLOP), N(0x99)));
		rc = consume(&s);
		OK(rc == 0, "consume: %s", emsg(s.dtp));
		OK(streq(evtext(),
		    "error: error on enabled probe ID 1 (ID 4: "
		    "test:kernel:alpha:entry): invalid alignment (0x31) in "
		    "action #2\n"
		    "error: error on enabled probe ID 1 (ID 4: "
		    "test:kernel:alpha:entry): bad stack (0x40) in predicate "
		    "at DIF offset 4\n"
		    "error: error on enabled probe ID 1 (ID 4: "
		    "test:kernel:alpha:entry): illegal operation in action #3 "
		    "at DIF offset 16\n"), "events:\n%s", evtext());
	}
	close_session(&s);

	/* A handler that aborts stops consumption. */
	cur = "error-handler-abort";
	wreset();
	if (wopen(&s, NULL, TRACE_PROG, H_ALL) == 0) {
		err_abort = 1;
		fire(0, "dtrace:::ERROR", 0, VALS(N(1), N(1), N(0),
		    N(DTRACEFLT_DIVZERO), N(0)));
		rc = consume(&s);
		OK(rc == -1 && dtrace_errno(s.dtp) == EDT_ERRABORT,
		    "rc %d: %s", rc, emsg(s.dtp));
	}
	close_session(&s);

	/* The faulting EPID must describe an enabled probe. */
	cur = "error-unknown-epid";
	wreset();
	if (wopen(&s, NULL, TRACE_PROG, H_ALL) == 0) {
		fire(0, "dtrace:::ERROR", 0, VALS(N(77), N(1), N(0),
		    N(DTRACEFLT_DIVZERO), N(0)));
		rc = consume(&s);
		OK(rc == -1 && dtrace_errno(s.dtp) == EDT_BADERROR,
		    "rc %d: %s", rc, emsg(s.dtp));
	}
	close_session(&s);

	/* The ERROR enabling must describe dtrace:::ERROR. */
	cur = "error-wrong-probe";
	wreset();
	if (wopen(&s, NULL, TRACE_PROG, H_ALL) == 0) {
		/*
		 * EPIDs 1 and 2 are the program's (alpha and beta entry);
		 * EPID 3 is the library's ERROR ECB.  Report it on probe 4.
		 */
		W.probe_epid = 3;
		W.probe_id = 4;
		fire(0, "dtrace:::ERROR", 0, VALS(N(1), N(1), N(0),
		    N(DTRACEFLT_DIVZERO), N(0)));
		rc = consume(&s);
		OK(rc == -1 && dtrace_errno(s.dtp) == EDT_BADERROR,
		    "rc %d: %s", rc, emsg(s.dtp));
	}
	close_session(&s);

	/* The ERROR description must have exactly five records. */
	cur = "error-wrong-nrecs";
	wreset();
	if (wopen(&s, NULL, TRACE_PROG, H_ALL) == 0) {
		W.uarg_epid = 1;
		W.uarg = DT_ECB_ERROR;
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		rc = consume(&s);
		OK(rc == -1 && dtrace_errno(s.dtp) == EDT_BADERROR,
		    "rc %d: %s", rc, emsg(s.dtp));
	}
	close_session(&s);

	/* ... and describe dtrace:::ERROR, not another dtrace probe. */
	cur = "error-wrong-name";
	wreset();
	if (wopen(&s, NULL, TRACE_PROG, H_ALL) == 0) {
		W.probe_epid = 3;
		W.probe_id = 1;		/* dtrace:::BEGIN */
		fire(0, "dtrace:::ERROR", 0, VALS(N(1), N(1), N(0),
		    N(DTRACEFLT_DIVZERO), N(0)));
		rc = consume(&s);
		OK(rc == -1 && dtrace_errno(s.dtp) == EDT_BADERROR,
		    "rc %d: %s", rc, emsg(s.dtp));
	}
	close_session(&s);

	/*
	 * Grabbing anonymous state (dtrace -a): the anonymous enabling
	 * already has an ERROR ECB, so registering the handler compiles
	 * nothing, and aggregation uargs are not compiler statements.  The
	 * anonymous enabling is modelled by enabling its clauses here; the
	 * kernel then reports the ERROR ECB with the library's ERROR uarg.
	 */
	cur = "grabanon";
	{
		static const char *const anon[] = { "grabanon", NULL, NULL };
		struct walked w = { 0 };

		wreset();
		if (wopen(&s, anon, "dtrace:::ERROR { trace(arg1); "
		    "trace(arg2); trace(arg3); trace(arg4); trace(arg5); } "
		    "test:kernel:alpha:entry { @c[arg0] = count(); }",
		    H_ALL) == 0) {
			OK(s.dtp->dt_errprog == NULL, "no ERROR program");
			W.uarg_epid = 1;
			W.uarg = DT_ECB_ERROR;
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), N(6),
			    AGG(0, 1)));
			fire(0, "dtrace:::ERROR", 0, VALS(N(2), N(1), N(0),
			    N(DTRACEFLT_KPRIV), N(0)));
			rc = consume(&s);
			OK(rc == 0 && streq(evtext(), "error: error on enabled "
			    "probe ID 2 (ID 4: test:kernel:alpha:entry): "
			    "invalid kernel access in action #1 at DIF offset "
			    "0\n"), "rc %d: %s", rc, evtext());
			rc = dtrace_aggregate_snap(s.dtp);
			OK(rc == 0, "snap: %s", emsg(s.dtp));
			rc = dtrace_aggregate_walk(s.dtp, walk_anon, &w);
			OK(rc == 0 && w.n == 1 && w.key == 6 && w.val == 1,
			    "rc %d n %d key %jd val %jd: %s", rc, w.n,
			    (intmax_t)w.key, (intmax_t)w.val, emsg(s.dtp));
		}
		close_session(&s);
	}

	/* An anonymous ERROR ECB without a registered handler aborts. */
	cur = "error-no-handler";
	wreset();
	if (wopen(&s, NULL, "dtrace:::ERROR { trace(arg1); trace(arg2); "
	    "trace(arg3); trace(arg4); trace(arg5); } " TRACE_PROG,
	    H_DROP) == 0) {
		W.uarg_epid = 1;
		W.uarg = DT_ECB_ERROR;
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(3)));
		fire(0, "dtrace:::ERROR", 0, VALS(N(2), N(1), N(0),
		    N(DTRACEFLT_KPRIV), N(0)));
		rc = consume(&s);
		OK(rc == -1 && dtrace_errno(s.dtp) == EDT_ERRABORT,
		    "rc %d: %s", rc, emsg(s.dtp));
	}
	close_session(&s);

	/* An ECB with an uarg the library did not assign is data. */
	cur = "foreign-ecb-uarg";
	wreset();
	if (wopen(&s, NULL, TRACE_PROG, H_ALL) == 0) {
		W.uarg_epid = 1;
		W.uarg = 7;
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(9)));
		rc = consume(&s);
		xbegin();
		X(" %16lld", 9LL);
		OK(rc == 0 && streq(outtext(&s), xend()), "output %s",
		    outtext(&s));
	}
	close_session(&s);

	/* Library-level errors without a handler, and with an aborting one. */
	cur = "liberr-no-handler";
	wreset();
	if (wopen(&s, NULL, "test:::return { setopt(\"nosuchoption\"); }",
	    H_DROP) == 0) {
		fire(0, "test:kernel:alpha:return", 0, VALS(S("nosuchoption"),
		    N(0)));
		rc = consume(&s);
		OK(rc == -1 && dtrace_errno(s.dtp) == EDT_ERRABORT,
		    "rc %d: %s", rc, emsg(s.dtp));
	}
	close_session(&s);
	cur = "liberr-abort";
	wreset();
	if (wopen(&s, NULL, "test:::return { setopt(\"nosuchoption\"); }",
	    H_ALL) == 0) {
		err_abort = 1;
		fire(0, "test:kernel:alpha:return", 0, VALS(S("nosuchoption"),
		    N(0)));
		rc = consume(&s);
		OK(rc == -1 && dtrace_errno(s.dtp) == EDT_ERRABORT &&
		    strstr(evtext(), "couldn't set option \"nosuchoption\"")
		    != NULL, "rc %d: %s / %s", rc, emsg(s.dtp), evtext());
	}
	close_session(&s);
}

/* ------------------------------------------------------------------ */
/* setopt() records and the setopt handler.                            */

static int setopt_abort;
static dtrace_setoptdata_t last_setopt;
static char last_setopt_name[32];

static int
setopt_cb(const dtrace_setoptdata_t *d, void *arg)
{
	(void) arg;
	last_setopt = *d;
	strlcpy(last_setopt_name, d->dtsda_option, sizeof (last_setopt_name));
	return (setopt_abort ? DTRACE_HANDLE_ABORT : DTRACE_HANDLE_OK);
}

static void
case_setopt_handler(void)
{
	struct session s;
	int rc;

	cur = "setopt-handler";
	wreset();
	setopt_abort = 0;
	if (wopen(&s, NULL, "test:::entry { setopt(\"quiet\"); "
	    "trace(arg0); }", H_ALL) == 0) {
		OK(dtrace_handle_setopt(s.dtp, setopt_cb, NULL) == 0, "set");
		fire(0, "test:kernel:alpha:entry", 0, VALS(S("quiet"), N(0),
		    N(5)));
		rc = consume(&s);
		/* quiet goes from unset to set. */
		OK(rc == 0 && streq(last_setopt_name, "quiet") &&
		    last_setopt.dtsda_oldval == DTRACEOPT_UNSET &&
		    last_setopt.dtsda_newval != DTRACEOPT_UNSET &&
		    last_setopt.dtsda_probe != NULL, "rc %d option %s",
		    rc, last_setopt_name);
		OK(streq(outtext(&s), "5"), "quiet output: %s", outtext(&s));
	}
	close_session(&s);

	cur = "setopt-handler-abort";
	wreset();
	setopt_abort = 1;
	if (wopen(&s, NULL, "test:::entry { setopt(\"quiet\"); "
	    "trace(arg0); }", H_ALL) == 0) {
		(void) dtrace_handle_setopt(s.dtp, setopt_cb, NULL);
		fire(0, "test:kernel:alpha:entry", 0, VALS(S("quiet"), N(0),
		    N(5)));
		rc = consume(&s);
		OK(rc == -1 && dtrace_errno(s.dtp) == EDT_DIRABORT,
		    "rc %d: %s", rc, emsg(s.dtp));
	}
	close_session(&s);
	setopt_abort = 0;
}

/* ------------------------------------------------------------------ */
/* Drops.                                                              */

static void
case_cpu_drops(void)
{
	static const char *const tags[] = { "droptags", NULL,
	    "bufsize", "64", NULL };
	static const char *const small[] = { "bufsize", "64", NULL };
	static const char *const aggsmall[] = { "aggsize", "32", NULL };
	struct session s;
	int rc, i;

	/* Tagged principal drop message. */
	cur = "cpudrop-tags";
	wreset();
	if (wopen(&s, tags, TRACE_PROG, H_ALL) == 0) {
		for (i = 1; i <= 3; i++)
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(i)));
		rc = consume(&s);
		OK(rc == 0 && strstr(evtext(), "drop cpu=0 kind=0 n=1 total=0: "
		    "[DTRACEDROP_PRINCIPAL] 1 drop on CPU 0\n") != NULL,
		    "events:\n%s", evtext());
	}
	close_session(&s);

	/* Aggregation drops are counted by the aggregation snapshot. */
	cur = "cpudrop-aggregation";
	wreset();
	if (wopen(&s, aggsmall, "test:::entry { @c[arg0] = count(); }",
	    H_ALL) == 0) {
		/*
		 * One entry is the aggregation ID, the variable record and
		 * the key (dtrace_ecb_aggregation_create layout: 4 + 4 pad +
		 * 8 + 8) and the count: 32 bytes, so a 32-byte buffer keeps
		 * the first key and drops the other two.
		 */
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), N(1),
		    AGG(0, 1)));
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), N(2),
		    AGG(0, 1)));
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), N(3),
		    AGG(0, 1)));
		rc = dtrace_aggregate_snap(s.dtp);
		OK(rc == 0 && strstr(evtext(), "kind=1 n=2 total=0: "
		    "2 aggregation drops on CPU 0\n") != NULL,
		    "rc %d events:\n%s", rc, evtext());
	}
	close_session(&s);

	/* Without a drop handler, a drop aborts consumption. */
	cur = "cpudrop-no-handler";
	wreset();
	if (wopen(&s, small, TRACE_PROG, H_ERR) == 0) {
		for (i = 1; i <= 3; i++)
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(i)));
		rc = consume(&s);
		OK(rc == -1 && dtrace_errno(s.dtp) == EDT_DROPABORT,
		    "rc %d: %s", rc, emsg(s.dtp));
	}
	close_session(&s);

	cur = "cpudrop-abort";
	wreset();
	if (wopen(&s, small, TRACE_PROG, H_ALL) == 0) {
		drop_abort = 1;
		for (i = 1; i <= 3; i++)
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(i)));
		rc = consume(&s);
		OK(rc == -1 && dtrace_errno(s.dtp) == EDT_DROPABORT,
		    "rc %d: %s", rc, emsg(s.dtp));
	}
	close_session(&s);
}

static void
case_status_drops(void)
{
	static const char *const tags[] = { "droptags", NULL, NULL };
	struct session s;
	int rc;

	cur = "status-drops";
	wreset();
	if (wopen(&s, NULL, TRACE_PROG, H_ALL) == 0) {
		W.st.dtst_dyndrops = 1;
		rc = dtrace_status(s.dtp);
		OK(rc == DTRACE_STATUS_OKAY, "status %d: %s", rc, emsg(s.dtp));
		OK(streq(evtext(), "drop cpu=-1 kind=2 n=1 total=1: "
		    "1 dynamic variable drop\n"), "first:\n%s", evtext());
		OK(last_drop.dtdda_cpu == DTRACE_CPUALL, "all CPUs");
		/* Final status at stop: deltas from the previous answer. */
		W.st.dtst_dyndrops = 3;
		W.st.dtst_dyndrops_rinsing = 2;
		W.st.dtst_dyndrops_dirty = 1;
		W.st.dtst_specdrops = 5;
		W.st.dtst_specdrops_busy = 1;
		W.st.dtst_specdrops_unavail = 2;
		W.st.dtst_stkstroverflows = 1;
		W.st.dtst_dblerrors = 4;
		rc = dtrace_stop(s.dtp);
		OK(rc == 0, "stop: %s", emsg(s.dtp));
		OK(streq(evtext(),
		    "drop cpu=-1 kind=2 n=1 total=1: 1 dynamic variable drop\n"
		    "drop cpu=-1 kind=2 n=2 total=3: 2 dynamic variable drops\n"
		    "drop cpu=-1 kind=3 n=2 total=2: 2 dynamic variable drops "
		    "with non-empty rinsing list\n"
		    "drop cpu=-1 kind=4 n=1 total=1: 1 dynamic variable drop "
		    "with non-empty dirty list\n"
		    "drop cpu=-1 kind=5 n=5 total=5: 5 speculative drops\n"
		    "drop cpu=-1 kind=6 n=1 total=1: 1 failed speculation "
		    "(available buffer(s) still busy)\n"
		    "drop cpu=-1 kind=7 n=2 total=2: 2 failed speculations "
		    "(no speculative buffer available)\n"
		    "drop cpu=-1 kind=8 n=1 total=1: 1 jstack()/ustack() "
		    "string table overflow\n"
		    "drop cpu=-1 kind=9 n=4 total=4: 4 errors in ERROR probe "
		    "enabling\n"), "all:\n%s", evtext());
	}
	close_session(&s);

	cur = "status-drop-tags";
	wreset();
	if (wopen(&s, tags, TRACE_PROG, H_ALL) == 0) {
		W.st.dtst_specdrops_busy = 2;
		(void) dtrace_status(s.dtp);
		OK(streq(evtext(), "drop cpu=-1 kind=6 n=2 total=2: "
		    "[DTRACEDROP_SPECBUSY] 2 failed speculations (available "
		    "buffer(s) still busy)\n"), "tagged:\n%s", evtext());
	}
	close_session(&s);

	cur = "status-killed";
	wreset();
	if (wopen(&s, NULL, TRACE_PROG, H_ALL) == 0) {
		W.st.dtst_killed = 1;
		rc = dtrace_status(s.dtp);
		OK(rc == -1 && dtrace_errno(s.dtp) == EDT_BRICKED, "rc %d: %s",
		    rc, emsg(s.dtp));
		/* Only the transition to killed is reported. */
		rc = dtrace_stop(s.dtp);
		OK(rc == 0, "still killed at stop: rc %d: %s", rc,
		    emsg(s.dtp));
	}
	close_session(&s);

	cur = "status-no-drop-handler";
	wreset();
	if (wopen(&s, NULL, TRACE_PROG, H_ERR) == 0) {
		W.st.dtst_dblerrors = 1;
		rc = dtrace_status(s.dtp);
		OK(rc == -1 && dtrace_errno(s.dtp) == EDT_DROPABORT,
		    "rc %d: %s", rc, emsg(s.dtp));
	}
	close_session(&s);

	cur = "status-drop-abort";
	wreset();
	if (wopen(&s, NULL, TRACE_PROG, H_ALL) == 0) {
		drop_abort = 1;
		W.st.dtst_specdrops = 1;
		rc = dtrace_status(s.dtp);
		OK(rc == -1 && dtrace_errno(s.dtp) == EDT_DROPABORT,
		    "rc %d: %s", rc, emsg(s.dtp));
	}
	close_session(&s);
}

static int run_child(void (*)(void *), void *, const char *, int *);

/*
 * Structured output of drops.  The JSON document is checked by
 * subr-handle.py: one principal drop and one dynamic-variable drop object.
 */
static void
oformat_drops(const char *file, int handlers, int abort_drop)
{
	static const char *const small[] = { "bufsize", "64", "quiet", NULL,
	    NULL };
	struct session s;
	FILE *json;
	int i, rc;

	wreset();
	json = fopen(file, "w");
	assert(json != NULL);
	xo_set_style(NULL, XO_STYLE_JSON);
	dtrace_set_outfp(json);
	if (wopen(&s, small, TRACE_PROG, handlers) == 0) {
		drop_abort = abort_drop;
		OK(dtrace_oformat_configure(s.dtp) == 0 &&
		    dtrace_oformat(s.dtp), "configure");
		dtrace_oformat_setup(s.dtp);
		for (i = 1; i <= 3; i++)
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(i)));
		rc = consume(&s);
		W.st.dtst_dyndrops = 2;
		rc |= dtrace_status(s.dtp);
		if (handlers & H_DROP && !abort_drop)
			OK(rc == 0 || rc == DTRACE_STATUS_OKAY, "rc %d: %s",
			    rc, emsg(s.dtp));
		else
			OK(rc != 0 && dtrace_errno(s.dtp) == EDT_DROPABORT,
			    "rc %d: %s", rc, emsg(s.dtp));
		dtrace_oformat_teardown(s.dtp);
	}
	close_session(&s);
	xo_set_style(NULL, XO_STYLE_TEXT);
	dtrace_set_outfp(stdout);
	fclose(json);
}

/* libxo's default handle is process state: one document per process. */
struct oformat_arg {
	const char *file;
	int handlers, abort_drop;
};

static void
child_oformat(void *argp)
{
	struct oformat_arg *a = argp;

	oformat_drops(a->file, a->handlers, a->abort_drop);
	printf("%s: %d checks, %d failures\n", a->file, nchecks, nfail);
	exit(nfail != 0);
}

static void
case_oformat_drops(void)
{
	static struct oformat_arg runs[] = {
		{ "drops.json", H_ALL, 0 },
		/* Aborting without a handler must still close the object. */
		{ "drops-nohandler.json", H_ERR, 0 },
		{ "drops-abort.json", H_ALL, 1 },
	};
	size_t i;
	int status;

	for (i = 0; i < sizeof (runs) / sizeof (runs[0]); i++) {
		cur = runs[i].file;
		run_child(child_oformat, &runs[i], "oformat.err", &status);
		OK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "child status %#x", status);
	}
}

/* ------------------------------------------------------------------ */
/* Buffered output.                                                    */

static char *bufd;
static size_t bufdlen;
static FILE *bufdfp;
static unsigned bufd_calls, bufd_abort_at;

static int
buf_cb(const dtrace_bufdata_t *d, void *arg)
{
	(void) arg;
	bufd_calls++;
	fputs(d->dtbda_buffered, bufdfp);
	if (bufd_abort_at != 0 && bufd_calls == bufd_abort_at)
		return (DTRACE_HANDLE_ABORT);
	return (DTRACE_HANDLE_OK);
}

static void
case_buffered(void)
{
	struct session s;
	char longs[300];
	int rc;

	/* Without a buffered handler, NULL output is refused. */
	cur = "buffered-required";
	wreset();
	if (wopen(&s, NULL, TRACE_PROG, H_ALL) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(3)));
		rc = dtrace_consume(s.dtp, NULL, probe_cb, rec_cb, NULL);
		OK(rc == -1 && dtrace_errno(s.dtp) == EDT_NOBUFFERED,
		    "rc %d: %s", rc, emsg(s.dtp));
	}
	close_session(&s);

	/* Buffered text equals what a stream would have received. */
	cur = "buffered-output";
	wreset();
	memset(longs, 'z', sizeof (longs) - 1);
	longs[sizeof (longs) - 1] = '\0';
	bufdfp = open_memstream(&bufd, &bufdlen);
	bufd_calls = bufd_abort_at = 0;
	if (wopen(&s, NULL, "test:::entry { trace(arg0); } "
	    "test:::return { printf(\"%s|%s|\", stringof(arg0), "
	    "stringof(arg1)); }", H_ALL) == 0) {
		OK(dtrace_handle_buffered(s.dtp, buf_cb, NULL) == 0, "handler");
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(3)));
		fire(0, "test:kernel:alpha:return", 0, VALS(S(""), B(longs,
		    sizeof (longs))));
		rc = dtrace_consume(s.dtp, NULL, probe_cb, rec_cb, NULL);
		fflush(bufdfp);
		xbegin();
		X(" %16lld", 3LL);
		/* A string record holds at most strsize (256) bytes. */
		X("|%.256s|", longs);
		OK(rc == 0 && streq(bufd, xend()) && bufd_calls >= 2,
		    "rc %d calls %u text %s", rc, bufd_calls, bufd);
	}
	close_session(&s);
	fclose(bufdfp);
	free(bufd);

	cur = "buffered-abort";
	wreset();
	bufdfp = open_memstream(&bufd, &bufdlen);
	bufd_calls = 0;
	bufd_abort_at = 1;
	if (wopen(&s, NULL, TRACE_PROG, H_ALL) == 0) {
		(void) dtrace_handle_buffered(s.dtp, buf_cb, NULL);
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(3)));
		rc = dtrace_consume(s.dtp, NULL, probe_cb, rec_cb, NULL);
		OK(rc == -1 && dtrace_errno(s.dtp) == EDT_DIRABORT,
		    "rc %d: %s", rc, emsg(s.dtp));
	}
	close_session(&s);
	fclose(bufdfp);
	free(bufd);
	bufd_abort_at = 0;
}

static void *
idle_thread(void *arg)
{
	return (arg);
}

/*
 * Formats whose expansion exceeds INT_MAX fail with EOVERFLOW (printf(3));
 * the second conversion is refused before any padding is produced.
 */
static void
case_printf_overflow(void)
{
	dtrace_hdl_t *dtp;
	char buf[16] = "";
	FILE *fp;
	int rc;

	cur = "printf-overflow";
	wreset();
	dtp = vhandle();
	fp = fopen("/dev/null", "w");
	assert(fp != NULL);
	rc = dt_printf(dtp, fp, "%d%*d", 1, INT_MAX, 1);
	OK(rc == -1 && dtrace_errno(dtp) == EOVERFLOW && !ferror(fp),
	    "stream: rc %d errno %d", rc, dtrace_errno(dtp));
	/* Once the process is threaded, stdio takes the locked paths. */
	{
		pthread_t t;

		pthread_create(&t, NULL, idle_thread, NULL);
		pthread_join(t, NULL);
	}
	rc = dt_printf(dtp, fp, "%d%*d", 1, INT_MAX, 1);
	OK(rc == -1 && dtrace_errno(dtp) == EOVERFLOW && !ferror(fp),
	    "threaded stream: rc %d errno %d", rc, dtrace_errno(dtp));
	/* dtrace_sprintf() mode writes into the handle's buffer. */
	dtp->dt_sprintf_buf = buf;
	dtp->dt_sprintf_buflen = sizeof (buf);
	rc = dt_printf(dtp, NULL, "%s-%d", "ab", 5);
	OK(rc == 4 && streq(buf, "ab-5"), "sprintf: %d %s", rc, buf);
	rc = dt_printf(dtp, NULL, "%d%*d", 1, INT_MAX, 1);
	OK(rc == -1 && dtrace_errno(dtp) == EOVERFLOW, "sprintf overflow");
	dtp->dt_sprintf_buf = NULL;
	dtp->dt_sprintf_buflen = 0;
	/* Buffered mode. */
	OK(dtrace_handle_buffered(dtp, nop_buf, NULL) == 0, "handler");
	rc = dt_printf(dtp, NULL, "%d%*d", 1, INT_MAX, 1);
	OK(rc == -1 && dtrace_errno(dtp) == EOVERFLOW, "buffered overflow");
	rc = dt_printf(dtp, NULL, "%s", "");
	OK(rc == 0 && dtp->dt_buffered_offs == 0, "empty buffered text");
	/* Output after a discard is refused. */
	OK(dtrace_output_discard(dtp, fp) == 0, "discard");
	rc = dt_printf(dtp, fp, "x");
	OK(rc == -1 && dtrace_errno(dtp) == ESHUTDOWN, "after discard");
	fclose(fp);
	dtrace_close(dtp);
}

/* ------------------------------------------------------------------ */
/* Description maps (dt_map.c).                                        */

/* Only the aggregation's last record (its value). */
static int
walk_last(const dtrace_aggdata_t *a, void *arg)
{
	struct walked *w = arg;
	const dtrace_aggdesc_t *d = a->dtada_desc;

	w->n++;
	w->key = d->dtagd_nrecs;
	w->val = *(const int64_t *)(a->dtada_data +
	    d->dtagd_rec[d->dtagd_nrecs - 1].dtrd_offset);
	return (DTRACE_AGGWALK_NEXT);
}

/* Records: variable ID, key, value (the aggregation's last record). */
static int
walk_one(const dtrace_aggdata_t *a, void *arg)
{
	struct walked *w = arg;
	const dtrace_aggdesc_t *d = a->dtada_desc;

	w->n++;
	w->key = *(const int64_t *)(a->dtada_data + d->dtagd_rec[1].dtrd_offset);
	w->val = *(const int64_t *)(a->dtada_data +
	    d->dtagd_rec[d->dtagd_nrecs - 1].dtrd_offset);
	return (DTRACE_AGGWALK_NEXT);
}

static void
case_maps(void)
{
	struct session s;
	int rc;

	/* A clause without actions has an ECB without records. */
	cur = "eprobe-no-records";
	wreset();
	if (wopen(&s, NULL, "test:kernel:alpha:entry { }", H_ALL) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, NULL, 0);
		rc = consume(&s);
		OK(rc == 0 && streq(evtext(), "probe cpu=0 "
		    "test:kernel:alpha:entry\nend-of-probe\n"), "rc %d: %s",
		    rc, evtext());
	}
	close_session(&s);

	/* system() formats are loaded like printf()'s (here: "true"). */
	cur = "system-format";
	{
		static const char *const destr[] = { "destructive", NULL,
		    "quiet", NULL, NULL };

		wreset();
		if (wopen(&s, destr, "test:kernel:alpha:entry "
		    "{ system(\"true\"); }", H_ALL) == 0) {
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(0)));
			rc = consume(&s);
			OK(rc == 0 && dt_format_lookup(s.dtp, 1) != NULL,
			    "rc %d: %s", rc, emsg(s.dtp));
		}
		close_session(&s);
	}

	/* Formats load on first use, in any order. */
	cur = "format-order";
	wreset();
	if (wopen(&s, NULL, "test:::entry { printf(\"a%d\", arg0); } "
	    "test:::return { printf(\"b%d\", arg0); }", H_ALL) == 0) {
		fire(0, "test:kernel:alpha:return", 0, VALS(N(1)));
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(2)));
		rc = consume(&s);
		OK(rc == 0 && streq(outtext(&s), "b1a2"), "rc %d: %s", rc,
		    outtext(&s));
	}
	close_session(&s);

	/* The second FORMAT request (copying the string) fails. */
	cur = "format-copy-failure";
	wreset();
	if (wopen(&s, NULL, "test:::entry { printf(\"%d\", arg0); }",
	    H_ALL) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(2)));
		inject(DTRACEIOC_FORMAT, 1, EIO);
		rc = consume(&s);
		OK(rc == -1 && dtrace_errno(s.dtp) == EIO, "rc %d: %s", rc,
		    emsg(s.dtp));
	}
	close_session(&s);

	/* An unparseable format string from the kernel. */
	cur = "format-unparseable";
	wreset();
	if (wopen(&s, NULL, "test:::entry { printf(\"%d\", arg0); }",
	    H_ALL) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(2)));
		W.fmt = "%Q";
		rc = consume(&s);
		OK(rc == -1 && streq(outtext(&s), ""), "rc %d: %s", rc,
		    emsg(s.dtp));
	}
	close_session(&s);

	/* print()'s type string is string data fetched through FORMAT. */
	cur = "strdata-failure";
	wreset();
	if (wopen(&s, NULL, "test:::entry { print((int)arg0); }",
	    H_ALL) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(2)));
		inject(DTRACEIOC_FORMAT, 0, ENOMEM);
		rc = consume(&s);
		OK(rc == -1 && dtrace_errno(s.dtp) == ENOMEM, "rc %d: %s", rc,
		    emsg(s.dtp));
	}
	close_session(&s);

	/* Aggregation descriptions with several records are re-queried. */
	cur = "aggdesc-requery-failure";
	wreset();
	if (wopen(&s, NULL, "test:::entry { @c[arg0] = count(); }",
	    H_ALL) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), N(1),
		    AGG(0, 1)));
		inject(DTRACEIOC_AGGDESC, 1, EIO);
		rc = dtrace_aggregate_snap(s.dtp);
		OK(rc == -1 && dtrace_errno(s.dtp) == EIO, "rc %d: %s", rc,
		    emsg(s.dtp));
	}
	close_session(&s);

	/*
	 * Malformed aggregation descriptions from the kernel (no records, or
	 * only the value record) must be refused or handled without reading
	 * outside the description; ASan checks the reads.
	 */
	for (int bad = 1; bad <= 2; bad++) {
		struct walked w = { 0 };

		cur = bad == 1 ? "aggdesc-no-records" : "aggdesc-value-only";
		wreset();
		if (wopen(&s, NULL, "test:kernel:alpha:entry { @c = count(); }",
		    H_ALL) == 0) {
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(1),
			    AGG(0, 1)));
			W.aggrecs = bad;
			/*
			 * Regression: the description without records is
			 * refused by dt_aggid_add() and never cached, whatever
			 * its header holds (poisoned so that reading
			 * dtagd_rec[-1] would find a COUNT action).
			 */
			W.poison = bad == 1;
			rc = dtrace_aggregate_snap(s.dtp);
			if (rc == 0)
				rc = dtrace_aggregate_walk(s.dtp, walk_last, &w);
			if (bad == 1)
				/* No aggregating record: refused. */
				OK(rc == -1 && dtrace_errno(s.dtp) == EDT_BADAGG &&
				    (s.dtp->dt_aggdesc == NULL ||
				    s.dtp->dt_maxagg <= 1 ||
				    s.dtp->dt_aggdesc[1] == NULL),
				    "rc %d: %s, cached %d", rc, emsg(s.dtp),
				    s.dtp->dt_aggdesc != NULL &&
				    s.dtp->dt_maxagg > 1 &&
				    s.dtp->dt_aggdesc[1] != NULL);
			else
				/*
				 * The value record alone reads as a keyless
				 * count fired once.  (Printing it aborts on
				 * an assertion in dt_consume.c: reported.)
				 */
				OK(rc == 0 && w.n == 1 && w.key == 1 &&
				    w.val == 1, "rc %d: %s n %d value %jd", rc,
				    emsg(s.dtp), w.n, (intmax_t)w.val);
		}
		close_session(&s);
	}

	/* An aggregation whose ECB lies beyond the EPIDs seen so far. */
	cur = "aggdesc-later-epid";
	wreset();
	if (wopen(&s, NULL, "test:kernel:alpha:entry { trace(arg0); } "
	    "test:kernel:beta:entry { @c[arg0] = count(); }", H_ALL) == 0) {
		struct walked w = { 0 };

		fire(0, "test:kernel:alpha:entry", 0, VALS(N(8)));
		fire(0, "test:kernel:beta:entry", 0, VALS(N(1), N(5),
		    AGG(0, 1)));
		rc = consume(&s);
		rc |= dtrace_aggregate_snap(s.dtp);
		rc |= dtrace_aggregate_walk(s.dtp, walk_one, &w);
		OK(rc == 0 && w.n == 1 && w.key == 5 && w.val == 1,
		    "rc %d n %d", rc, w.n);
	}
	close_session(&s);

	/* An aggregation's EPID is described even before any trace data. */
	cur = "aggdesc-before-epid";
	wreset();
	if (wopen(&s, NULL, "test:::entry { @c[arg0] = count(); }",
	    H_ALL) == 0) {
		struct walked w = { 0 };

		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), N(4),
		    AGG(0, 1)));
		inject(DTRACEIOC_EPROBE, 0, EIO);
		rc = dtrace_aggregate_snap(s.dtp);
		OK(rc == -1 && dtrace_errno(s.dtp) == EIO, "EPROBE failure: "
		    "rc %d: %s", rc, emsg(s.dtp));
		M.fail_cmd = 0;
		/* The failed snapshot consumed (switched) the kernel buffer. */
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), N(4),
		    AGG(0, 1)));
		rc = dtrace_aggregate_snap(s.dtp);
		rc |= dtrace_aggregate_walk(s.dtp, walk_one, &w);
		OK(rc == 0 && w.n == 1 && w.key == 4 && w.val == 1,
		    "rc %d entries %d key %jd count %jd", rc, w.n,
		    (intmax_t)w.key, (intmax_t)w.val);
	}
	close_session(&s);
}

/* ------------------------------------------------------------------ */
/* D sugar: the clauses, predicates and probes of the rewrite.         */

struct clause_shape {
	const dtrace_ecbdesc_t *last;
	char text[1024];
};

static int
shape_cb(dtrace_hdl_t *dtp, dtrace_prog_t *p, dtrace_stmtdesc_t *sdp,
    void *arg)
{
	struct clause_shape *cs = arg;
	const dtrace_ecbdesc_t *e = sdp->dtsd_ecbdesc;
	char one[160];

	(void) dtp; (void) p;
	if (e == cs->last)
		return (0);
	cs->last = e;
	snprintf(one, sizeof (one), "%s:%s %s;", e->dted_probe.dtpd_provider,
	    e->dted_probe.dtpd_name,
	    e->dted_pred.dtpdd_difo != NULL ? "pred" : "nopred");
	strlcat(cs->text, one, sizeof (cs->text));
	return (0);
}

static const char *
shape(dtrace_hdl_t *dtp, const char *src, struct clause_shape *cs)
{
	dtrace_prog_t *p;

	memset(cs, 0, sizeof (*cs));
	p = dtrace_program_strcompile(dtp, src, DTRACE_PROBESPEC_NAME, 0, 0,
	    NULL);
	if (p == NULL) {
		snprintf(cs->text, sizeof (cs->text), "compile: %s",
		    emsg(dtp));
		return (cs->text);
	}
	(void) dtrace_stmt_iter(dtp, p, shape_cb, cs);
	return (cs->text);
}

static void
case_sugar(void)
{
	dtrace_hdl_t *dtp;
	struct clause_shape cs;

	cur = "sugar-if-else";
	wreset();
	dtp = vhandle();
	/*
	 * First sugared clause of the handle: the ERROR clause setting
	 * self->%error, the clause clearing it, the block before the "if"
	 * (unpredicated: no condition exists yet), the condition, the "if"
	 * block, the inverted condition, the "else" block, and the block
	 * after the "if" (predicated on !self->%error).
	 */
	OK(streq(shape(dtp, "test:kernel:alpha:entry { trace(1); "
	    "if (arg0 > 0) { trace(2); } else { trace(4); } trace(3); }",
	    &cs),
	    "dtrace:ERROR nopred;test:entry nopred;test:entry nopred;"
	    "test:entry pred;test:entry pred;test:entry pred;"
	    "test:entry pred;test:entry pred;"), "%s", cs.text);
	/*
	 * Later clauses add no second ERROR clause.  A clause predicate
	 * becomes condition 1; an "if" first in the body opens no block.
	 */
	OK(streq(shape(dtp, "test:kernel:alpha:return /arg0 == 1/ "
	    "{ if (arg1) { trace(5); } }", &cs),
	    "test:return nopred;test:return pred;test:return pred;"
	    "test:return pred;"), "%s", cs.text);
	/* Nested if: conditions chain; the outer block follows. */
	OK(streq(shape(dtp, "test:kernel:beta:entry { if (arg0) { "
	    "if (arg1) { trace(1); } trace(2); } }", &cs),
	    "test:entry nopred;test:entry pred;test:entry pred;"
	    "test:entry pred;test:entry pred;"), "%s", cs.text);
	/* No sugar: the clause is unchanged, predicate intact. */
	OK(streq(shape(dtp, "test:kernel:beta:return /arg0/ { trace(1); }",
	    &cs), "test:return pred;"), "%s", cs.text);
	/* Consecutive statements share one block. */
	OK(streq(shape(dtp, "test:kernel:beta:entry { trace(1); trace(2); "
	    "if (arg0) { trace(3); trace(4); } }", &cs),
	    "test:entry nopred;test:entry nopred;test:entry pred;"
	    "test:entry pred;"), "%s", cs.text);
	/* An empty "if" body generates no block. */
	OK(streq(shape(dtp, "test:kernel:beta:return { if (arg0) { } }",
	    &cs), "test:return nopred;test:return pred;"), "%s", cs.text);
	dtrace_close(dtp);
}

/* ------------------------------------------------------------------ */
/* Children: debug output, process symbols, program errors.            */

/*
 * Children are forked while this process is single-threaded: a peer thread
 * is started only after the fork, so no lock can be inherited held.
 */
static pid_t
start_child(void (*fn)(void *), void *arg, const char *errfile)
{
	pid_t pid;

	fflush(stdout);
	fflush(stderr);
	pid = fork();
	assert(pid >= 0);
	if (pid == 0) {
		int fd = open(errfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);

		assert(fd >= 0);
		dup2(fd, STDERR_FILENO);
		close(fd);
		fn(arg);
		exit(0);
	}
	return (pid);
}

static int
run_child(void (*fn)(void *), void *arg, const char *errfile, int *status)
{
	pid_t pid = start_child(fn, arg, errfile);

	assert(waitpid(pid, status, 0) == pid);
	return (0);
}

static char *
slurp(const char *path)
{
	FILE *f = fopen(path, "r");
	char *buf = NULL;
	size_t len = 0;
	FILE *m = open_memstream(&buf, &len);
	int c;

	if (f != NULL) {
		while ((c = fgetc(f)) != EOF)
			fputc(c, m);
		fclose(f);
	}
	fclose(m);
	return (buf);
}

static void
child_debug(void *arg)
{
	dtrace_hdl_t *dtp;
	int err;

	(void) arg;
	/* The documented "debug" option enables library tracing. */
	dtp = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV | DTRACE_O_NOSYS,
	    &err);
	if (dtp != NULL) {
		(void) dtrace_setopt(dtp, "debug", NULL);
		(void) dtrace_program_strcompile(dtp, "BEGIN { trace(1); }",
		    DTRACE_PROBESPEC_NAME, 0, 0, NULL);
		dtrace_close(dtp);
	}
	exit(dtp == NULL ? 2 : 0);
}

static void
case_debug(void)
{
	int status;
	char *text;

	cur = "debug-output";
	run_child(child_debug, NULL, "debug.err", &status);
	text = slurp("debug.err");
	OK(WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
	    strncmp(text, "libdtrace DEBUG: ", 17) == 0, "status %d: %.80s",
	    status, text);
	free(text);
}

/* Exported (-rdynamic) so that dladdr(3) is an independent oracle. */
int subr_handle_uaddr_target(int);

__attribute__((noinline)) int
subr_handle_uaddr_target(int x)
{
	return (x * 3 + 1);
}

/* A grabbed child process resolves addresses to object`symbol+off. */
static void
case_uaddr(void)
{
	dtrace_hdl_t *dtp;
	char buf[1024], want[1024], self[PATH_MAX];
	Dl_info info;
	pid_t pid;
	int fds[2], status;
	char c;
	uint64_t fn = (uint64_t)(uintptr_t)subr_handle_uaddr_target;

	cur = "uaddr2str-process";
	assert(pipe(fds) == 0);
	pid = fork();
	assert(pid >= 0);
	if (pid == 0) {
		close(fds[1]);
		/* Wait for the parent to finish, then exit normally. */
		(void) read(fds[0], &c, 1);
		exit(0);
	}
	close(fds[0]);
	wreset();
	dtp = vhandle();
	assert(dladdr((void *)(uintptr_t)fn, &info) != 0 && info.dli_sname != NULL);
	strlcpy(self, info.dli_fname, sizeof (self));
	snprintf(want, sizeof (want), "%s`%s+0x%jx", basename(self),
	    info.dli_sname, (uintmax_t)(fn + 4 - (uint64_t)(uintptr_t)
	    info.dli_saddr));
	(void) dtrace_uaddr2str(dtp, pid, fn + 4, buf, sizeof (buf));
	OK(streq(buf, want), "got %s want %s", buf, want);
	snprintf(want, sizeof (want), "%s`%s", basename(self),
	    info.dli_sname);
	(void) dtrace_uaddr2str(dtp, pid, (uint64_t)(uintptr_t)
	    info.dli_saddr, buf, sizeof (buf));
	OK(streq(buf, want), "exact: got %s want %s", buf, want);
	/* Inside the object but before any symbol (its ELF header). */
	{
		uint64_t hdr = (uint64_t)(uintptr_t)info.dli_fbase + 0x40;

		snprintf(want, sizeof (want), "%s`0x%jx", basename(self),
		    (uintmax_t)hdr);
		(void) dtrace_uaddr2str(dtp, pid, hdr, buf, sizeof (buf));
		OK(streq(buf, want), "object only: got %s want %s", buf,
		    want);
	}
	/* An unmapped address prints raw. */
	(void) dtrace_uaddr2str(dtp, pid, 0x10, buf, sizeof (buf));
	OK(streq(buf, "0x10"), "unmapped: %s", buf);
	dtrace_close(dtp);
	(void) write(fds[1], "x", 1);
	close(fds[1]);
	waitpid(pid, &status, 0);
}

/* ---- dt_set_progerr() in children ---------------------------------- */

static char sockdir[PATH_MAX];
static char redirect_path[sizeof (((struct sockaddr_un *)0)->sun_path)];
/*
 * Failures apply to the program-error file only (not, e.g., the profile
 * runtime's files).  fail_lseek: 1 = every rewind (libelf's too), 2 = only
 * after fsync().
 */
static int fail_mkstemp, fail_fsync, fail_lseek, synced, progerr_fd = -1;

int
connect(int s, const struct sockaddr *name, socklen_t namelen)
{
	static int (*real)(int, const struct sockaddr *, socklen_t);
	struct sockaddr_un alt;

	if (real == NULL)
		real = (int (*)(int, const struct sockaddr *, socklen_t))
		    dlsym(RTLD_NEXT, "connect");
	if (name->sa_family == AF_UNIX && redirect_path[0] != '\0' &&
	    strcmp(((const struct sockaddr_un *)name)->sun_path,
	    DTRACED_SOCKPATH) == 0) {
		memset(&alt, 0, sizeof (alt));
		alt.sun_family = AF_UNIX;
		strlcpy(alt.sun_path, redirect_path, sizeof (alt.sun_path));
		alt.sun_len = SUN_LEN(&alt);
		return (real(s, (struct sockaddr *)&alt, alt.sun_len));
	}
	return (real(s, name, namelen));
}

/*
 * The program-error file is created under $TMPDIR (the test directory);
 * remember its descriptor so faults apply to it alone.
 */
int
mkstemp(char *template)
{
	static int (*real)(char *);

	if (real == NULL)
		real = (int (*)(char *))dlsym(RTLD_NEXT, "mkstemp");
	if (strstr(template, "/ddtrace-set-prog-err.") != NULL) {
		if (fail_mkstemp) {
			errno = EMFILE;
			return (-1);
		}
		return (progerr_fd = real(template));
	}
	return (real(template));
}

int
fsync(int fd)
{
	static int (*real)(int);

	if (real == NULL)
		real = (int (*)(int))dlsym(RTLD_NEXT, "fsync");
	if (fd != progerr_fd)
		return (real(fd));
	synced = 1;
	if (fail_fsync) {
		errno = EIO;
		return (-1);
	}
	return (real(fd));
}

off_t
lseek(int fd, off_t off, int whence)
{
	static off_t (*real)(int, off_t, int);

	if (real == NULL)
		real = (off_t (*)(int, off_t, int))dlsym(RTLD_NEXT, "lseek");
	if (fd == progerr_fd && off == 0 && whence == SEEK_SET &&
	    (fail_lseek == 1 || (fail_lseek == 2 && synced))) {
		errno = EIO;
		return (-1);
	}
	return (real(fd, off, whence));
}

static void
birth_set(int on)
{
	void (*set)(int, int) = (void (*)(int, int))dlsym(RTLD_DEFAULT,
	    "dtc_birth_set");

	assert(set != NULL);
	set(on, 0);
}

struct peer {
	int lfd;
	int nack;
	int got;
	dtraced_hdr_t hdr;
	unsigned char head[4];
	size_t payload_len;
};

static void *
serve_progerr(void *arg)
{
	struct peer *p = arg;
	dtd_initmsg_t hello = { 0 }, client;
	unsigned char wire[DTRACED_MSGHDRSIZE], *payload, ack;
	size_t done, len;
	int64_t dl = dtraced_io_deadline_after(10000);
	int fd = accept(p->lfd, NULL, NULL);

	if (fd < 0)
		return (NULL);
	hello.kind = DTRACED_KIND_DTRACED;
	hello.protocol_version = DTRACED_PROTOCOL_VERSION;
	if (dtraced_wire_write_init(fd, &hello, dl, &done) != 0 ||
	    dtraced_wire_read_init(fd, &client, dl, &done) != 0 ||
	    dtraced_io_read_size(fd, &len, dl, &done) != 0 ||
	    len < DTRACED_MSGHDRSIZE ||
	    dtraced_io_transfer(fd, wire, sizeof (wire), false, dl,
	    &done) != 0 || dtraced_wire_decode_header(&p->hdr, wire) != 0) {
		close(fd);
		return (NULL);
	}
	p->payload_len = len - DTRACED_MSGHDRSIZE;
	payload = malloc(p->payload_len);
	if (payload != NULL && dtraced_io_transfer(fd, payload,
	    p->payload_len, false, dl, &done) == 0) {
		memcpy(p->head, payload, 4);
		p->got = 1;
		ack = p->nack ? 0 : 1;
		(void) write(fd, &ack, 1);
	}
	free(payload);
	close(fd);
	return (NULL);
}

static int
listen_at(const char *path)
{
	struct sockaddr_un a = { .sun_family = AF_UNIX };
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

	unlink(path);
	strlcpy(a.sun_path, path, sizeof (a.sun_path));
	a.sun_len = SUN_LEN(&a);
	assert(fd >= 0 && bind(fd, (struct sockaddr *)&a, a.sun_len) == 0 &&
	    listen(fd, 4) == 0);
	return (fd);
}

struct progerr_arg {
	int guest;
	const char *fmt;
	int long_msg;
	int overflow;
	int long_tmpdir;
	int want_rc;
	const char *want_err;	/* dp_err, exactly or as a prefix */
	int prefix;
	int want_errno;		/* 0: not checked; -1: ENOENT/ECONNREFUSED */
};

/*
 * dt_set_progerr() contract (dt_error.c): the program is marked
 * (dp_haserror), the formatted message kept in dp_err (or "failed to format
 * program error") and printed on stderr; it returns.  A guest also forwards
 * the program to dtraced through a temporary file under $TMPDIR; on failure
 * it appends "; <reason>" to dp_err, prints the reason, returns -1 with
 * errno set, and always removes the temporary file.
 */
static void
child_progerr(void *argp)
{
	struct progerr_arg *a = argp;
	dtrace_hdl_t *dtp;
	dtrace_prog_t *p;
	char *big = NULL, *tmp;
	int rc, err;

	nchecks = nfail = 0;	/* this child's own verdict */
	wreset();
	dtp = vhandle();
	p = dtrace_program_strcompile(dtp, "BEGIN { trace(1); }",
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL);
	assert(p != NULL);
	if (a->guest)
		dtrace_set_guest(dtp);
	if (a->long_tmpdir) {
		tmp = malloc(MAXPATHLEN + 1);
		memset(tmp, 'd', MAXPATHLEN);
		tmp[0] = '/';
		tmp[MAXPATHLEN] = '\0';
		setenv("TMPDIR", tmp, 1);
	}
	errno = 0;
	if (a->long_msg) {
		big = malloc(DT_PROG_ERRLEN + 10);
		memset(big, 'e', DT_PROG_ERRLEN + 9);
		big[DT_PROG_ERRLEN + 9] = '\0';
		rc = dt_set_progerr(dtp, p, "%s", big);
	} else if (a->overflow) {
		rc = dt_set_progerr(dtp, p, "%d%*d", 1, INT_MAX, 1);
	} else {
		rc = dt_set_progerr(dtp, p, a->fmt, 7);
	}
	err = errno;
	OK(rc == a->want_rc, "rc %d errno %d", rc, err);
	OK(p->dp_haserror == 1, "program not marked");
	if (a->long_msg)
		OK(strlen(p->dp_err) == DT_PROG_ERRLEN - 1 &&
		    strspn(p->dp_err, "e") == DT_PROG_ERRLEN - 1,
		    "truncated message of %zu bytes", strlen(p->dp_err));
	else if (a->prefix)
		OK(strncmp(p->dp_err, a->want_err, strlen(a->want_err)) == 0,
		    "dp_err \"%s\", want prefix \"%s\"", p->dp_err,
		    a->want_err);
	else
		OK(streq(p->dp_err, a->want_err), "dp_err \"%s\", want \"%s\"",
		    p->dp_err, a->want_err);
	if (a->want_errno == -1)
		OK(err == ENOENT || err == ECONNREFUSED, "errno %d", err);
	else if (a->want_errno != 0)
		OK(err == a->want_errno, "errno %d, want %d", err,
		    a->want_errno);
	free(big);
	dtrace_close(dtp);
	exit(nfail != 0);
}

static void
progerr_run(const char *name, struct progerr_arg *a, int serve, int nack,
    const char *want_stderr, int want_frame)
{
	struct peer pr = { .lfd = -1, .nack = nack };
	pthread_t t;
	char errfile[PATH_MAX], *text;
	int status;
	pid_t pid;
	static const unsigned char elfmag[4] = { 0x7f, 'E', 'L', 'F' };

	cur = name;
	if (serve)
		pr.lfd = listen_at(redirect_path);
	snprintf(errfile, sizeof (errfile), "%s.err", name);
	pid = start_child(child_progerr, a, errfile);
	if (serve)
		pthread_create(&t, NULL, serve_progerr, &pr);
	assert(waitpid(pid, &status, 0) == pid);
	if (serve) {
		/* Unblock accept() if the child never connected. */
		if (!pr.got) {
			int fd = socket(AF_UNIX, SOCK_STREAM, 0);
			struct sockaddr_un sa = { .sun_family = AF_UNIX };

			strlcpy(sa.sun_path, redirect_path,
			    sizeof (sa.sun_path));
			sa.sun_len = SUN_LEN(&sa);
			redirect_path[0] = '\0';
			(void) connect(fd, (struct sockaddr *)&sa, sa.sun_len);
			close(fd);
			snprintf(redirect_path, sizeof (redirect_path),
			    "%s/d.sock", sockdir);
		}
		pthread_join(t, NULL);
		close(pr.lfd);
	}
	text = slurp(errfile);
	/* The child's own checks of rc, dp_haserror, dp_err and errno. */
	OK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child status %#x:\n%.600s", status, text);
	OK(strstr(text, want_stderr) != NULL, "stderr lacks \"%s\":\n%.300s",
	    want_stderr, text);
	if (want_frame)
		OK(pr.got && pr.hdr.msg_type == DTRACED_MSG_ELF &&
		    streq(pr.hdr.elf.location, "outbound") &&
		    pr.hdr.elf.ident_present == 0 &&
		    pr.payload_len == pr.hdr.elf.len &&
		    memcmp(pr.head, elfmag, 4) == 0,
		    "frame: got %d type %ju loc %s len %zu", pr.got,
		    (uintmax_t)pr.hdr.msg_type, pr.hdr.elf.location,
		    pr.payload_len);
	free(text);
}

static void
case_progerr(void)
{
	char trunc[128], nack[160], mk[160], fs[160], ls[160];
	struct progerr_arg host = { 0, "host failure %d", 0, 0, 0, 0,
	    "host failure 7", 0, 0 };
	struct progerr_arg longm = { 0, NULL, 1, 0, 0, 0, NULL, 0, 0 };
	struct progerr_arg ovf = { 0, NULL, 0, 1, 0, 0,
	    "failed to format program error", 0, 0 };
	struct progerr_arg guest = { 1, "guest failure %d", 0, 0, 0, 0,
	    "guest failure 7", 0, 0 };
	struct progerr_arg gnack = { 1, "guest failure %d", 0, 0, 0, -1,
	    nack, 0, EPROTO };
	struct progerr_arg gmk = { 1, "guest failure %d", 0, 0, 0, -1,
	    mk, 0, EMFILE };
	struct progerr_arg gfs = { 1, "guest failure %d", 0, 0, 0, -1,
	    fs, 0, EIO };
	struct progerr_arg gelf = { 1, "guest failure %d", 0, 0, 0, -1,
	    "guest failure 7; dt_elf_create() failed: ELF Creation failed: ",
	    1, EIO };
	struct progerr_arg gls = { 1, "guest failure %d", 0, 0, 0, -1,
	    ls, 0, EIO };
	struct progerr_arg gnod = { 1, "guest failure %d", 0, 0, 0, -1,
	    "guest failure 7; failed to open dtraced: ", 1, -1 };
	struct progerr_arg glong = { 1, "guest failure %d", 0, 0, 1, -1,
	    "guest failure 7; temporary file name too long", 0, ENAMETOOLONG };
	DIR *d;
	struct dirent *de;
	int left = 0;

	signal(SIGPIPE, SIG_IGN);
	assert(getcwd(sockdir, sizeof (sockdir)) != NULL);
	snprintf(redirect_path, sizeof (redirect_path), "%s/d.sock", sockdir);
	setenv("TMPDIR", sockdir, 1);
	snprintf(trunc, sizeof (trunc),
	    "program error message truncated to %ju bytes",
	    (uintmax_t)DT_PROG_ERRLEN - 1);
	snprintf(nack, sizeof (nack), "guest failure 7; "
	    "dtrace_send_elf() failed: %s", strerror(EPROTO));
	snprintf(mk, sizeof (mk), "guest failure 7; mkstemp() failed: %s",
	    strerror(EMFILE));
	snprintf(fs, sizeof (fs), "guest failure 7; fsync() failed: %s",
	    strerror(EIO));
	snprintf(ls, sizeof (ls), "guest failure 7; lseek() failed: %s",
	    strerror(EIO));

	/* Host: record, report and return. */
	progerr_run("progerr-host", &host, 0, 0, "host failure 7", 0);
	progerr_run("progerr-truncated", &longm, 0, 0, trunc, 0);
	/*
	 * Only dp_err carries the fallback text; stderr gets the failed
	 * format's (empty) output and a newline.
	 */
	progerr_run("progerr-unformattable", &ovf, 0, 0, "\n", 0);

	/* Guest: the program is also forwarded to dtraced. */
	birth_set(1);
	progerr_run("progerr-guest", &guest, 1, 0, "guest failure 7", 1);
	progerr_run("progerr-guest-nack", &gnack, 1, 1,
	    "dtrace_send_elf() failed", 1);
	fail_mkstemp = 1;
	progerr_run("progerr-guest-mkstemp", &gmk, 1, 0,
	    "mkstemp() failed", 0);
	fail_mkstemp = 0;
	fail_fsync = 1;
	progerr_run("progerr-guest-fsync", &gfs, 1, 0, "fsync() failed", 0);
	fail_fsync = 0;
	/* libelf rewinds while writing: the ELF image cannot be created. */
	fail_lseek = 1;
	progerr_run("progerr-guest-elfcreate", &gelf, 1, 0,
	    "dt_elf_create() failed: ELF Creation failed", 0);
	fail_lseek = 2;
	progerr_run("progerr-guest-lseek", &gls, 1, 0, "lseek() failed", 0);
	fail_lseek = 0;
	progerr_run("progerr-guest-tmpdir", &glong, 0, 0,
	    "temporary file name too long", 0);
	unlink(redirect_path);
	progerr_run("progerr-guest-nodaemon", &gnod, 0, 0,
	    "failed to open dtraced", 0);
	birth_set(0);

	/* Every forward, delivered or failed, removed its temporary file. */
	cur = "progerr-cleanup";
	d = opendir(".");
	while (d != NULL && (de = readdir(d)) != NULL)
		if (strncmp(de->d_name, "ddtrace-set-prog-err.", 21) == 0)
			left++;
	if (d != NULL)
		closedir(d);
	OK(left == 0, "%d temporary files left", left);
}

/* ------------------------------------------------------------------ */
/* freopen(): output follows the most recent file until restored.      */

static void
case_freopen(void)
{
	static const char *const opts[] = { "destructive", NULL, "quiet",
	    NULL, NULL };
	struct session s;
	char *text;
	int rc;

	cur = "freopen";
	wreset();
	unlink("fo.txt");
	if (wopen(&s, opts, "test:kernel:alpha:entry { freopen(\"fo.txt\"); } "
	    "test:kernel:beta:entry { printf(\"%d;\", arg0); } "
	    "test:kernel:alpha:return { freopen(\"\"); }", H_ALL) == 0) {
		fire(0, "test:kernel:beta:entry", 0, VALS(N(1)));
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(0)));
		fire(0, "test:kernel:beta:entry", 0, VALS(N(2)));
		fire(0, "test:kernel:alpha:return", 0, VALS(N(0)));
		fire(0, "test:kernel:beta:entry", 0, VALS(N(3)));
		rc = consume(&s);
		OK(rc == 0, "consume: %s", emsg(s.dtp));
		/* Restoring closed the file, so its content is complete. */
		text = slurp("fo.txt");
		OK(streq(text, "2;"), "file: %s", text);
		OK(streq(outtext(&s), "1;3;"), "stream: %s", outtext(&s));
		free(text);
		/* A redirection active at discard time is purged too. */
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(0)));
		fire(0, "test:kernel:beta:entry", 0, VALS(N(4)));
		rc = consume(&s);
		OK(rc == 0 && s.dtp->dt_freopen_fp != NULL, "redirected again");
		/* The redirection itself as the caller's stream: one purge. */
		OK(dtrace_output_discard(s.dtp, s.dtp->dt_freopen_fp) == 0,
		    "discard: %s", emsg(s.dtp));
	}
	close_session(&s);
	text = slurp("fo.txt");
	/* "4;" was buffered in the redirection and purged unwritten. */
	OK(streq(text, "2;"), "after discard: %s", text);
	free(text);
}

/* ------------------------------------------------------------------ */
/* Program identities.                                                 */

static void
case_identity(void)
{
	dtrace_hdl_t *a, *b;
	dtrace_prog_t *pa, *pb, *pc, fake;
	uint8_t da[32], db[32], dc[32], id[16], want[16], zero[32] = { 0 };
	uint8_t d[32];
	SHA256_CTX ctx;
	const char *src = "test:kernel:alpha:entry { trace(arg0); "
	    "printf(\"%d\", arg1); @c[arg2] = count(); }";

	cur = "compiled-digest";
	wreset();
	a = vhandle();
	b = vhandle();
	pa = dtrace_program_strcompile(a, src, DTRACE_PROBESPEC_NAME, 0, 0,
	    NULL);
	pb = dtrace_program_strcompile(b, src, DTRACE_PROBESPEC_NAME, 0, 0,
	    NULL);
	pc = dtrace_program_strcompile(a, "test:kernel:alpha:entry "
	    "{ trace(arg1); }", DTRACE_PROBESPEC_NAME, 0, 0, NULL);
	assert(pa != NULL && pb != NULL && pc != NULL);
	/* Identity of the compiled program, not of the process-local uarg. */
	OK(dtrace_program_compiled_digest(a, pa, da) == 0 &&
	    dtrace_program_compiled_digest(b, pb, db) == 0 &&
	    memcmp(da, db, 32) == 0 && memcmp(da, zero, 32) != 0,
	    "same source, two handles");
	OK(dtrace_program_compiled_digest(a, pc, dc) == 0 &&
	    memcmp(da, dc, 32) != 0, "different program");
	OK(dtrace_program_compiled_digest(NULL, pa, dc) == -1 &&
	    errno == EINVAL, "NULL handle");
	OK(dtrace_program_compiled_digest(a, NULL, dc) == -1 &&
	    errno == EINVAL, "NULL program");
	OK(dtrace_program_compiled_digest(a, pa, NULL) == -1 &&
	    errno == EINVAL, "NULL result");

	cur = "source-id";
	OK(dtrace_program_source_id(NULL, id) == -1 && errno == EINVAL &&
	    dtrace_program_source_id(pa, NULL) == -1 && errno == EINVAL,
	    "NULL arguments");
	memset(&fake, 0, sizeof (fake));
	OK(dtrace_program_source_id(&fake, id) == -1 && errno == EINVAL,
	    "no identity");
	/* dp_srcident wins over dp_ident when present. */
	memset(fake.dp_ident, 'i', sizeof (fake.dp_ident));
	memset(fake.dp_srcident, 's', sizeof (fake.dp_srcident));
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, fake.dp_srcident, DT_PROG_IDENTLEN);
	SHA256_Final(d, &ctx);
	memcpy(want, d, 16);
	OK(dtrace_program_source_id(&fake, id) == 0 &&
	    memcmp(id, want, 16) == 0, "source identity");
	dtrace_close(a);
	dtrace_close(b);
}

/* ------------------------------------------------------------------ */
/* Derived program delivery (protocol 36 installed-event slot).        */

struct dpeer {
	int fd;
	int ok;
	dtraced_hdr_t hdr;
	unsigned char *payload;
	size_t len;
};

static void *
dpeer_run(void *arg)
{
	struct dpeer *p = arg;
	unsigned char wire[DTRACED_MSGHDRSIZE], ack = 1;
	size_t len, done;
	int64_t dl = dtraced_io_deadline_after(5000);

	if (dtraced_io_read_size(p->fd, &len, dl, &done) != 0 ||
	    len < DTRACED_MSGHDRSIZE || dtraced_io_transfer(p->fd, wire,
	    sizeof (wire), false, dl, &done) != 0 ||
	    dtraced_wire_decode_header(&p->hdr, wire) != 0)
		return (NULL);
	p->len = len - DTRACED_MSGHDRSIZE;
	p->payload = malloc(p->len);
	if (dtraced_io_transfer(p->fd, p->payload, p->len, false, dl,
	    &done) != 0)
		return (NULL);
	p->ok = 1;
	(void) write(p->fd, &ack, 1);
	return (NULL);
}

static void
case_derived(void)
{
	dtrace_hdl_t *dtp;
	dtrace_prog_t *p;
	dtraced_derived_parent_t parent;
	struct dpeer pr = { 0 };
	pthread_t t;
	uint8_t pre[8 + 16 + 8 + 2 + 8 + 16 + 16 + 32], digest[32];
	char msg[512];
	int fds[2], fd, rc;
	unsigned i;
	SHA256_CTX ctx;

	cur = "send-elf-derived";
	wreset();
	dtp = vhandle();
	p = dtrace_program_strcompile(dtp, "BEGIN { trace(1); }",
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL);
	assert(p != NULL);
	fd = open("derived.elf", O_RDWR | O_CREAT | O_TRUNC, 0600);
	assert(fd >= 0 && dtrace_elf_create(dtp, p, ELFDATA2LSB, fd,
	    "derived.elf", msg) == 0);
	p->dp_vmid = 3;
	p->dp_vmepoch = 0x77;
	memset(&parent, 0, sizeof (parent));
	assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) == 0);
	/* An incomplete parent is refused before anything is sent. */
	OK(dtrace_send_elf_derived(p, fd, fds[0], &parent) == -1 &&
	    errno == EINVAL, "invalid parent");
	OK(dtrace_send_elf_derived(NULL, fd, fds[0], &parent) == -1 &&
	    errno == EINVAL, "no program");
	memset(parent.consumer_session, 0xc5, 16);
	parent.delivery_id = 41;
	parent.vmid = 3;
	parent.epoch = 0x77;
	memset(parent.program_id, 0xa1, 16);
	memset(parent.source_id, 0xb2, 16);
	pr.fd = fds[1];
	pthread_create(&t, NULL, dpeer_run, &pr);
	rc = dtrace_send_elf_derived(p, fd, fds[0], &parent);
	pthread_join(t, NULL);
	OK(rc == 0 && pr.ok, "sent: rc %d errno %d", rc, errno);
	OK(pr.hdr.installed.delivery_id == 41 && pr.hdr.installed.vmid == 3 &&
	    pr.hdr.installed.epoch == 0x77 &&
	    memcmp(pr.hdr.installed.program_id, parent.program_id, 16) == 0 &&
	    memcmp(pr.hdr.installed.source_id, parent.source_id, 16) == 0 &&
	    memcmp(pr.hdr.installed.name, parent.consumer_session, 16) == 0 &&
	    streq(pr.hdr.elf.location, "outbound") &&
	    pr.hdr.elf.ident_present == 0, "installed-event slot");
	/*
	 * Program id: SHA-256("HDERIV1\0" session delivery(le64) vmid(le16)
	 * epoch(le64) parent program id, parent source id, SHA-256(payload)),
	 * first 16 bytes; the payload includes the VM envelope.
	 */
	memset(pre, 0, sizeof (pre));
	memcpy(pre, "HDERIV1", 8);
	memcpy(pre + 8, parent.consumer_session, 16);
	for (i = 0; i < 8; i++) {
		pre[24 + i] = (uint8_t)(parent.delivery_id >> (8 * i));
		pre[34 + i] = (uint8_t)(parent.epoch >> (8 * i));
	}
	pre[32] = parent.vmid & 0xff;
	pre[33] = parent.vmid >> 8;
	memcpy(pre + 42, parent.program_id, 16);
	memcpy(pre + 58, parent.source_id, 16);
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, pr.payload, pr.len);
	SHA256_Final(pre + 74, &ctx);
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, pre, sizeof (pre));
	SHA256_Final(digest, &ctx);
	OK(pr.ok && memcmp(pr.hdr.elf.program_id, digest, 16) == 0 &&
	    pr.len == HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + (size_t)lseek(fd, 0,
	    SEEK_END), "derived program id over the enveloped payload");
	free(pr.payload);

	cur = "message-without-payload";
	{
		dtraced_hdr_t h;
		struct dpeer q = { 0 };
		int m[2];

		memset(&h, 0, sizeof (h));
		h.msg_type = DTRACED_MSG_ELF;
		strlcpy(h.elf.location, "inbound", sizeof (h.elf.location));
		assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0,
		    m) == 0);
		q.fd = m[1];
		pthread_create(&t, NULL, dpeer_run, &q);
		rc = dtrace_send_message(m[0], &h, NULL, 0);
		pthread_join(t, NULL);
		OK(rc == 0 && q.ok && q.len == 0 &&
		    streq(q.hdr.elf.location, "inbound"), "header only: rc %d",
		    rc);
		free(q.payload);
		close(m[0]);
		close(m[1]);
	}

	cur = "send-elf-refusals";
	{
		/* Larger than a frame (64 MiB) can carry: sparse file. */
		int big = open("big.elf", O_RDWR | O_CREAT | O_TRUNC, 0600);

		assert(big >= 0 && ftruncate(big, 65 << 20) == 0);
		OK(dtrace_send_elf(p, big, fds[0], "inbound", 0) == -1 &&
		    errno == EMSGSIZE, "oversized file");
		close(big);
		unlink("big.elf");
	}
	/* A descriptor that cannot be examined. */
	OK(dtrace_send_elf(p, 1000, fds[0], "inbound", 0) == -1 &&
	    errno == EBADF, "fstat failure: %d", errno);
	OK(dtrace_send_elf(p, fd, -1, "inbound", 0) == -1 &&
	    errno == EINVAL, "bad destination");
	/* A program without identities has no source id. */
	memset(p->dp_ident, 0, sizeof (p->dp_ident));
	memset(p->dp_srcident, 0, sizeof (p->dp_srcident));
	OK(dtrace_send_elf(p, fd, fds[0], "inbound", 0) == -1 &&
	    errno == EINVAL, "no identity");
	close(fds[0]);
	close(fds[1]);
	close(fd);
	dtrace_close(dtp);
}

/* ------------------------------------------------------------------ */
/* Output style selection.                                             */

static void
case_oformat_style(void)
{
	dtrace_hdl_t *dtp;

	cur = "oformat-text";
	wreset();
	dtp = vhandle();
	xo_set_style(NULL, XO_STYLE_TEXT);
	OK(dtrace_oformat_configure(dtp) == 0 && dtrace_oformat(dtp) == 0,
	    "text style is unstructured");
	dtrace_close(dtp);
}

/*
 * Discarding output drops structured text that was never flushed: the
 * file holds only what was written before the discard.
 */
static void
child_xo_discard(void *arg)
{
	struct session s;
	FILE *json = fopen("discard.json", "w");

	(void) arg;
	wreset();
	setvbuf(json, NULL, _IOFBF, 1 << 16);
	xo_set_style(NULL, XO_STYLE_JSON);
	dtrace_set_outfp(json);
	if (wopen(&s, NULL, TRACE_PROG, H_ALL) == 0) {
		(void) dtrace_oformat_configure(s.dtp);
		dtrace_oformat_setup(s.dtp);
		use_oformat = 1;
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(5)));
		(void) consume(&s);
		/*
		 * Consumption flushed the probe; the list is still open and
		 * the consumer has formatted, unflushed output pending.
		 */
		xo_open_instance("probes");
		xo_emit("{:pending/%d}", 77);
		OK(dtrace_output_discard(s.dtp, json) == 0, "discard");
	}
	close_session(&s);
	fclose(json);
	exit(nfail != 0);
}

static void
case_xo_discard(void)
{
	int status;
	char *text;

	cur = "oformat-discard";
	run_child(child_xo_discard, NULL, "discard.err", &status);
	text = slurp("discard.json");
	OK(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child %#x",
	    status);
	/*
	 * The flushed probe is in the file, but the formatter's closing of
	 * the open "probes" list and "dtrace" container was discarded.
	 */
	OK(text != NULL && strstr(text, "\"value\":5") != NULL &&
	    strstr(text, "pending") == NULL && strstr(text, "]}}") == NULL,
	    "file: %s", text);
	free(text);
}
/* ------------------------------------------------------------------ */

int
main(int argc, char **argv)
{
	static const struct {
		const char *name;
		void (*fn)(void);
	} cases[] = {
		{ "errors", case_errors },
		{ "descriptions", case_descriptions },
		{ "attributes", case_attributes },
		{ "versions", case_versions },
		{ "misc", case_misc },
		{ "difo-dup", case_difo_dup },
		{ "addr2str", case_addr2str },
		{ "registration", case_registration },
		{ "error-records", case_error_records },
		{ "setopt-handler", case_setopt_handler },
		{ "cpu-drops", case_cpu_drops },
		{ "status-drops", case_status_drops },
		{ "oformat-drops", case_oformat_drops },
		{ "buffered", case_buffered },
		{ "printf-overflow", case_printf_overflow },
		{ "maps", case_maps },
		{ "sugar", case_sugar },
		{ "debug", case_debug },
		{ "uaddr", case_uaddr },
		{ "progerr", case_progerr },
		{ "freopen", case_freopen },
		{ "identity", case_identity },
		{ "derived", case_derived },
		{ "oformat-style", case_oformat_style },
		{ "oformat-discard", case_xo_discard },
	};
	size_t i;
	int ran = 0;

	signal(SIGPIPE, SIG_IGN);
	setvbuf(stdout, NULL, _IOLBF, 0);
	for (i = 0; i < sizeof (cases) / sizeof (cases[0]); i++) {
		if (argc > 1 && strcmp(argv[1], cases[i].name) != 0)
			continue;
		cases[i].fn();
		ran++;
	}
	reset_model();
	printf("%s: %d checks, %d failures\n", argc > 1 ? argv[1] : "all",
	    nchecks, nfail);
	return (ran == 0 || nfail != 0 || failures != 0);
}
