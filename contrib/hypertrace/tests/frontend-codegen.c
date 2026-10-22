/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Offline D compiler driver for the frontend-codegen suites.
 *
 * libdtrace is opened with dtrace_vopen() and a small modeled dtrace(4)
 * vector: DTRACEIOC_CONF, provider/probe discovery and typed probe argument
 * descriptions (DTRACEIOC_PROBEARG).  No device, kernel or daemon is used and
 * nothing is enabled.  Each case from the input file is compiled and every
 * statement is dumped as one JSON line: probe descriptions, action kinds and
 * arguments, and each DIF object (instructions, integer/string/variable
 * tables, return type, relocations and translator member DIFOs).  The Python
 * side checks the DIF by executing it in an independent interpreter.
 *
 * Input: a sequence of records "@@case NAME CFLAGS SPEC OPTS\n<program>"
 * where CFLAGS is hex DTRACE_C_* bits, SPEC is a dtrace_probespec_t and OPTS
 * is a comma-separated list of option[=value] (or "-").  Special OPTS tokens:
 * "file" compiles via dtrace_program_fcompile() from a temporary file,
 * "type" compiles with dtrace_type_strcompile(), "argv=a|b" passes macro
 * arguments, "conf_tupregs=N" lowers the modeled tuple register count.
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <signal.h>
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dt_impl.h>
#include <dt_xlator.h>
#include <dt_module.h>
#include <dt_printf.h>
#include <dt_hypertrace.h>

#define	CMD(x)	((u_long)(x) & 0xffffffffUL)

struct marg {
	const char *native, *xlate;
	int mapping;
};

struct mprobe {
	const char *prov, *mod, *func, *name;
	struct marg args[6];
	int nargs;
};

/* Probe IDs are index + 1. */
static const struct mprobe probes[] = {
	{ "dtrace", "", "", "BEGIN", { { 0 } }, 0 },
	{ "dtrace", "", "", "END", { { 0 } }, 0 },
	{ "dtrace", "", "", "ERROR", { { 0 } }, 0 },
	{ "test", "kernel", "alpha", "entry", { { 0 } }, 0 },
	{ "test", "kernel", "alpha", "return", { { 0 } }, 0 },
	{ "test", "kernel", "beta", "entry", { { 0 } }, 0 },
	/*
	 * Typed arguments; args 4 and 5 are translated views of native
	 * argument 4 (a struct xin pointer, declared by the program).
	 */
	{ "typed", "kernel", "fn", "t", {
	    { "int", NULL, 0 }, { "char *", NULL, 1 }, { "uint8_t", NULL, 2 },
	    { "short", NULL, 3 }, { "struct xin *", "struct xout", 4 },
	    { "struct xin *", "struct xout *", 4 } }, 6 },
	/* An argument whose native type does not resolve. */
	{ "typed", "kernel", "fn", "bad", {
	    { "no_such_type_t", NULL, 0 } }, 1 },
	/* Translated type with no translator, and a type-only mapping. */
	{ "typed", "kernel", "fn", "nox", {
	    { "int", "struct nosuch_xlate", 0 }, { "int", "long", 1 } }, 2 },
	/* Native type unresolvable, translated type resolvable. */
	{ "typed", "kernel", "fn", "badn", {
	    { "no_such_type_t", "int", 0 } }, 1 },
	/* DTRACEIOC_PROBEARG fails for this probe (modeled EIO). */
	{ "typed", "kernel", "fn", "argfail", { { 0 } }, -1 },
	/* A translated pointer type with no translator (dynamic extern). */
	{ "typed", "kernel", "fn", "noxp", {
	    { "int", "struct nosuch_xlate *", 0 } }, 1 },
	/* Two probes with identical names in an unstable provider. */
	{ "unstable", "kernel", "f1", "u", { { "int", NULL, 0 } }, 1 },
	{ "unstable", "kernel", "f2", "u", { { "int", NULL, 0 } }, 1 },
	{ "profile", "", "", "tick-1sec", { { 0 } }, 0 },
	/* A kernel provider whose name ends in a digit (not a pid provider). */
	{ "ip6", "kernel", "f", "n", { { 0 } }, 0 },
};
#define	NPROBES	((int)(sizeof (probes) / sizeof (probes[0])))

static int conf_tupregs = DIF_DTR_NREGS;

static int
glob(const char *pat, const char *s)
{
	return (pat[0] == '\0' || fnmatch(pat, s, 0) == 0);
}

static int
model_ioctl(void *varg, u_long cmd, void *arg)
{
	int error = 0, i;

	(void) varg;
	cmd = CMD(cmd);
	if (cmd == CMD(DTRACEIOC_CONF)) {
		dtrace_conf_t *c = arg;

		memset(c, 0, sizeof (*c));
		c->dtc_difversion = DIF_VERSION;
		c->dtc_difintregs = DIF_DIR_NREGS;
		c->dtc_diftupregs = conf_tupregs;
		c->dtc_ctfmodel = CTF_MODEL_NATIVE;
	} else if (cmd == CMD(DTRACEIOC_PROVIDER)) {
		dtrace_providerdesc_t *pvd = arg;
		dtrace_attribute_t at = { DTRACE_STABILITY_EVOLVING,
		    DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON };
		dtrace_attribute_t un = { DTRACE_STABILITY_PRIVATE,
		    DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN };

		error = ESRCH;
		for (i = 0; i < NPROBES; i++) {
			if (strcmp(pvd->dtvd_name, probes[i].prov) != 0)
				continue;
			memset(&pvd->dtvd_priv, 0, sizeof (pvd->dtvd_priv));
			pvd->dtvd_attr.dtpa_provider = at;
			pvd->dtvd_attr.dtpa_mod = at;
			pvd->dtvd_attr.dtpa_func = at;
			pvd->dtvd_attr.dtpa_name = at;
			pvd->dtvd_attr.dtpa_args =
			    strcmp(probes[i].prov, "unstable") == 0 ? un : at;
			error = 0;
			break;
		}
	} else if (cmd == CMD(DTRACEIOC_PROBEMATCH) ||
	    cmd == CMD(DTRACEIOC_PROBES)) {
		dtrace_probedesc_t *d = arg;
		int match = cmd == CMD(DTRACEIOC_PROBEMATCH);
		dtrace_id_t id = d->dtpd_id == DTRACE_IDNONE ? 1 : d->dtpd_id;

		error = ESRCH;
		for (i = id - 1; d->dtpd_vmid == 0 && i < NPROBES; i++) {
			if (match && (!glob(d->dtpd_provider, probes[i].prov) ||
			    !glob(d->dtpd_mod, probes[i].mod) ||
			    !glob(d->dtpd_func, probes[i].func) ||
			    !glob(d->dtpd_name, probes[i].name)))
				continue;
			d->dtpd_id = i + 1;
			strlcpy(d->dtpd_provider, probes[i].prov,
			    sizeof (d->dtpd_provider));
			strlcpy(d->dtpd_mod, probes[i].mod,
			    sizeof (d->dtpd_mod));
			strlcpy(d->dtpd_func, probes[i].func,
			    sizeof (d->dtpd_func));
			strlcpy(d->dtpd_name, probes[i].name,
			    sizeof (d->dtpd_name));
			error = 0;
			break;
		}
	} else if (cmd == CMD(DTRACEIOC_PROBEARG)) {
		dtrace_argdesc_t *a = arg;
		const struct mprobe *p;

		if (a->dtargd_id == DTRACE_IDNONE ||
		    a->dtargd_ndx == DTRACE_ARGNONE ||
		    a->dtargd_id > (dtrace_id_t)NPROBES) {
			error = EINVAL;
		} else {
			p = &probes[a->dtargd_id - 1];
			if (p->nargs < 0) {
				error = EIO;
			} else if ((int)a->dtargd_ndx >= p->nargs) {
				a->dtargd_ndx = DTRACE_ARGNONE;
			} else {
				const struct marg *m = &p->args[a->dtargd_ndx];

				strlcpy(a->dtargd_native, m->native,
				    sizeof (a->dtargd_native));
				if (m->xlate != NULL)
					strlcpy(a->dtargd_xlate, m->xlate,
					    sizeof (a->dtargd_xlate));
				a->dtargd_mapping = m->mapping;
			}
		}
	} else {
		error = ENOTTY;
	}
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

static int
model_lookup(void *varg, GElf_Addr addr, GElf_Sym *sym, dtrace_syminfo_t *si)
{
	(void) varg; (void) addr; (void) sym; (void) si;
	return (-1);
}

static int
model_status(void *varg, processorid_t cpu)
{
	(void) varg;
	return (cpu == 0 ? 1 : -1);
}

static long
model_sysconf(void *varg, int name)
{
	(void) varg;
	if (name == _SC_NPROCESSORS_CONF || name == _SC_NPROCESSORS_ONLN)
		return (1);
	return (sysconf(name));
}

static const dtrace_vector_t vector = {
	.dtv_ioctl = model_ioctl,
	.dtv_lookup_by_addr = model_lookup,
	.dtv_status = model_status,
	.dtv_sysconf = model_sysconf,
};

/*
 * Symbol modules: three dt_module_t's backed by one ELF shared object (path
 * in FRONTEND_FAKEMOD) so that `symbol references resolve offline: "fakek"
 * is the primary kernel module, "fakel" a loadable kernel module and
 * "fakeu" a user module.  The library loads their symbol tables lazily.
 */
static void
add_fakemods(dtrace_hdl_t *dtp)
{
	static const struct {
		const char *name;
		uint_t flags;
	} mods[] = {
		{ "fakek", DT_DM_KERNEL | DT_DM_PRIMARY },
		{ "fakel", DT_DM_KERNEL },
		{ "fakeu", 0 },
	};
	const char *path = getenv("FRONTEND_FAKEMOD");
	size_t i;

	assert(path != NULL);
	for (i = 0; i < sizeof (mods) / sizeof (mods[0]); i++) {
		dt_module_t *dmp = dt_module_create(dtp, mods[i].name);
		int fd = open(path, O_RDONLY);

		assert(dmp != NULL && fd != -1);
		dmp->dm_elf = elf_begin(fd, ELF_C_READ, NULL);
		assert(dmp->dm_elf != NULL);
		dmp->dm_flags |= mods[i].flags;
	}
}

/* ------------------------------------------------------------------ */

static FILE *out;

/*
 * Allocation fault injection (frontend-codegen-oom): when the injector shim
 * is preloaded, compile_phase() arms it with oom_n around each compilation.
 */
static void (*oom_arm)(long);
static void (*oom_target)(const char *);
static int (*oom_hit)(void);
static long oom_n;
static int oom_was_hit;

static void
jstr(const char *s, size_t n)
{
	size_t i;

	fputc('"', out);
	for (i = 0; i < n; i++) {
		unsigned char c = s[i];
		if (c == '"' || c == '\\')
			fprintf(out, "\\%c", c);
		else if (c < 0x20 || c >= 0x7f)
			fprintf(out, "\\u%04x", c);
		else
			fputc(c, out);
	}
	fputc('"', out);
}

static void
jcstr(const char *s)
{
	if (s == NULL)
		fputs("null", out);
	else
		jstr(s, strlen(s));
}

static void dump_difo(const dtrace_difo_t *dp, int depth);

static void
dump_type(const dtrace_diftype_t *t)
{
	fprintf(out, "[%u,%u,%u,%u]", t->dtdt_kind, t->dtdt_ckind,
	    t->dtdt_flags, t->dtdt_size);
}

static void
dump_difo(const dtrace_difo_t *dp, int depth)
{
	uint_t i;

	if (dp == NULL) {
		fputs("null", out);
		return;
	}
	fputs("{\"buf\":[", out);
	for (i = 0; i < dp->dtdo_len; i++)
		fprintf(out, "%s%u", i ? "," : "", dp->dtdo_buf[i]);
	fputs("],\"int\":[", out);
	for (i = 0; i < dp->dtdo_intlen; i++)
		fprintf(out, "%s\"%ju\"", i ? "," : "",
		    (uintmax_t)dp->dtdo_inttab[i]);
	fputs("],\"str\":", out);
	jstr(dp->dtdo_strtab != NULL ? dp->dtdo_strtab : "", dp->dtdo_strlen);
	fputs(",\"sym\":", out);
	jstr(dp->dtdo_symtab != NULL ? dp->dtdo_symtab : "",
	    (size_t)dp->dtdo_symlen);
	fputs(",\"var\":[", out);
	for (i = 0; i < dp->dtdo_varlen; i++) {
		const dtrace_difv_t *v = &dp->dtdo_vartab[i];
		fprintf(out, "%s[%u,%u,%u,%u,%u,", i ? "," : "", v->dtdv_name,
		    v->dtdv_id, v->dtdv_kind, v->dtdv_scope, v->dtdv_flags);
		dump_type(&v->dtdv_type);
		fputc(']', out);
	}
	fputs("],\"rtype\":", out);
	dump_type(&dp->dtdo_rtype);
	fprintf(out, ",\"destructive\":%u,\"krel\":[", dp->dtdo_destructive);
	for (i = 0; i < dp->dtdo_krelen; i++)
		fprintf(out, "%s[%u,%u,%ju,%ju]", i ? "," : "",
		    dp->dtdo_kreltab[i].dofr_name, dp->dtdo_kreltab[i].dofr_type,
		    (uintmax_t)dp->dtdo_kreltab[i].dofr_offset,
		    (uintmax_t)dp->dtdo_kreltab[i].dofr_data);
	fputs("],\"urel\":[", out);
	for (i = 0; i < dp->dtdo_urelen; i++)
		fprintf(out, "%s[%u,%u,%ju,%ju]", i ? "," : "",
		    dp->dtdo_ureltab[i].dofr_name, dp->dtdo_ureltab[i].dofr_type,
		    (uintmax_t)dp->dtdo_ureltab[i].dofr_offset,
		    (uintmax_t)dp->dtdo_ureltab[i].dofr_data);
	fputs("],\"xl\":[", out);
	for (i = 0; i < dp->dtdo_xlmlen; i++) {
		dt_node_t *dnp = dp->dtdo_xlmtab[i];
		dt_xlator_t *dxp;

		if (i)
			fputc(',', out);
		if (dnp == NULL || depth > 4) {
			fputs("null", out);
			continue;
		}
		dxp = dnp->dn_membexpr->dn_xlator;
		fprintf(out, "{\"member\":");
		jcstr(dnp->dn_membname);
		fprintf(out, ",\"id\":%u,\"difo\":", dnp->dn_membid);
		dump_difo(dxp->dx_membdif != NULL ?
		    dxp->dx_membdif[dnp->dn_membid] : NULL, depth + 1);
		fputc('}', out);
	}
	fputs("]}", out);
}

static void
dump_pdesc(const dtrace_probedesc_t *p)
{
	fputc('[', out);
	jcstr(p->dtpd_provider);
	fputc(',', out);
	jcstr(p->dtpd_mod);
	fputc(',', out);
	jcstr(p->dtpd_func);
	fputc(',', out);
	jcstr(p->dtpd_name);
	fprintf(out, ",%u]", p->dtpd_id);
}

static int
stmt_cb(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, dtrace_stmtdesc_t *sdp,
    void *arg)
{
	const dtrace_actdesc_t *ap;
	int *first = arg;

	(void) dtp; (void) pgp;
	fputs(*first ? "{" : ",{", out);
	*first = 0;
	fputs("\"probe\":", out);
	dump_pdesc(&sdp->dtsd_ecbdesc->dted_probe);
	fputs(",\"pred\":", out);
	dump_difo(sdp->dtsd_ecbdesc->dted_pred.dtpdd_difo, 0);
	fputs(",\"strdata\":", out);
	jcstr(sdp->dtsd_strdata);
	/* Final per-conversion formats chosen by printf validation. */
	fputs(",\"fmts\":[", out);
	if (sdp->dtsd_fmtdata != NULL) {
		const dt_pfargv_t *pfv = sdp->dtsd_fmtdata;
		const dt_pfargd_t *pfd;
		int n = 0;

		for (pfd = pfv->pfv_argv; pfd != NULL; pfd = pfd->pfd_next) {
			if (pfd->pfd_conv == NULL)
				continue;
			fputs(n++ ? "," : "", out);
			jcstr(pfd->pfd_fmt);
		}
	}
	fputs("]", out);
	fputs(",\"actions\":[", out);
	for (ap = sdp->dtsd_action; ap != NULL; ap = ap->dtad_next) {
		fprintf(out, "%s{\"kind\":%u,\"ntuple\":%u,\"arg\":\"%ju\","
		    "\"uarg\":\"%ju\",\"return\":%d,\"difo\":",
		    ap == sdp->dtsd_action ? "" : ",", ap->dtad_kind,
		    ap->dtad_ntuple, (uintmax_t)ap->dtad_arg,
		    (uintmax_t)(oom_arm != NULL ? 0 : ap->dtad_uarg),
		    ap->dtad_return);
		dump_difo(ap->dtad_difo, 0);
		fputc('}', out);
		if (ap == sdp->dtsd_action_last)
			break;
	}
	fputs("]}", out);
	return (0);
}

static char *
read_all(const char *path, size_t *lenp)
{
	FILE *fp = fopen(path, "r");
	char *buf;
	long n;

	if (fp == NULL)
		return (NULL);
	fseek(fp, 0, SEEK_END);
	n = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	buf = malloc(n + 1);
	if (fread(buf, 1, n, fp) != (size_t)n)
		abort();
	buf[n] = '\0';
	fclose(fp);
	*lenp = n;
	return (buf);
}

/*
 * Apply comma-separated options.  Tokens handled by the driver itself are
 * recorded in the flags; everything else goes to dtrace_setopt().
 */
struct copts {
	int use_file, use_type, use_typefile, libs, argc;
	int use_pipe, nproc0, alarm, link;
	char *argv[16];
};

static void
apply_opts(dtrace_hdl_t *dtp, char *opts, struct copts *co)
{
	char *tok, *save, *argstr = NULL;

	for (tok = strtok_r(opts, ",", &save); tok != NULL;
	    tok = strtok_r(NULL, ",", &save)) {
		char *eq;

		if (strcmp(tok, "-") == 0 || strncmp(tok, "conf_", 5) == 0 ||
		    strcmp(tok, "libs") == 0 || strcmp(tok, "fakemods") == 0 ||
		    strncmp(tok, "oomfunc=", 8) == 0)
			continue;
		if (strcmp(tok, "file") == 0) {
			co->use_file = 1;
			continue;
		}
		if (strcmp(tok, "type") == 0) {
			co->use_type = 1;
			continue;
		}
		if (strcmp(tok, "typefile") == 0) {
			co->use_typefile = 1;
			continue;
		}
		if (strcmp(tok, "link") == 0) {		/* run hypertrace_link() */
			co->link = 1;
			continue;
		}
		if (strcmp(tok, "pipe") == 0) {		/* fcompile from a pipe */
			co->use_pipe = 1;
			continue;
		}
		if (strcmp(tok, "nproc0") == 0) {	/* fork() fails (EAGAIN) */
			co->nproc0 = 1;
			continue;
		}
		if (strcmp(tok, "alarm") == 0) {	/* signals interrupt waits */
			co->alarm = 1;
			continue;
		}
		if (strncmp(tok, "argv=", 5) == 0) {
			argstr = tok + 5;
			continue;
		}
		eq = strchr(tok, '=');
		if (eq != NULL)
			*eq++ = '\0';
		if (dtrace_setopt(dtp, tok, eq) != 0) {
			fprintf(out, ",\"setopt_error\":");
			jcstr(dtrace_errmsg(dtp, dtrace_errno(dtp)));
		}
	}
	if (argstr != NULL) {
		co->argc = 0;
		for (tok = strtok_r(argstr, "|", &save); tok != NULL &&
		    co->argc < 16; tok = strtok_r(NULL, "|", &save))
			co->argv[co->argc++] = tok;
	}
}

static struct rlimit saved_nproc;
static volatile sig_atomic_t alarms;

static void
on_alarm(int sig)
{
	(void) sig;
	alarms++;
}

static void
compile_phase(dtrace_hdl_t *dtp, const char *name, int phase, unsigned cflags,
    int spec, struct copts *co, const char *program, const char *tmpdir)
{
	dtrace_prog_t *pgp = NULL;
	dtrace_typeinfo_t dtt;
	int rc = 0, first = 1, typed = co->use_type || co->use_typefile;
	char path[1024];
	FILE *fp = NULL;

	if (co->use_pipe) {
		int pfd[2];

		assert(pipe(pfd) == 0);
		assert(write(pfd[1], program, strlen(program)) ==
		    (ssize_t)strlen(program));
		close(pfd[1]);
		fp = fdopen(pfd[0], "r");
		assert(fp != NULL);
		co->use_file = 1;
	} else if (co->use_file || co->use_typefile) {
		snprintf(path, sizeof (path), "%s/%s.%d.d", tmpdir, name, phase);
		fp = fopen(path, "w+");
		assert(fp != NULL);
		fputs(program, fp);
		rewind(fp);
	}
	if (co->nproc0) {
		struct rlimit rl = { 0, RLIM_INFINITY };

		(void) getrlimit(RLIMIT_NPROC, &rl);
		saved_nproc = rl;
		rl.rlim_cur = 0;
		(void) setrlimit(RLIMIT_NPROC, &rl);
	}
	if (co->alarm) {
		struct sigaction sa;
		struct itimerval it = { { 0, 200 }, { 0, 200 } };

		memset(&sa, 0, sizeof (sa));
		sa.sa_handler = on_alarm;	/* no SA_RESTART */
		(void) sigaction(SIGALRM, &sa, NULL);
		(void) setitimer(ITIMER_REAL, &it, NULL);
	}
	if (oom_arm != NULL)
		oom_arm(oom_n);
	if (co->use_type) {
		rc = dtrace_type_strcompile(dtp, program, &dtt);
	} else if (co->use_typefile) {
		rc = dtrace_type_fcompile(dtp, fp, &dtt);
	} else if (co->use_file) {
		pgp = dtrace_program_fcompile(dtp, fp, cflags, co->argc,
		    co->argv);
	} else {
		pgp = dtrace_program_strcompile(dtp, program, spec, cflags,
		    co->argc, co->argv);
	}
	if (oom_arm != NULL) {
		oom_was_hit |= oom_hit();
		oom_arm(0);
	}
	if (co->alarm) {
		struct itimerval off = { { 0, 0 }, { 0, 0 } };

		(void) setitimer(ITIMER_REAL, &off, NULL);
		fprintf(out, ",\"alarms\":%d", alarms > 0);
	}
	if (co->nproc0)
		(void) setrlimit(RLIMIT_NPROC, &saved_nproc);
	if (fp != NULL)
		fclose(fp);
	if (typed && rc == 0) {
		char n[DT_TYPE_NAMELEN];

		fprintf(out, ",\"type\":");
		jcstr(ctf_type_name(dtt.dtt_ctfp, dtt.dtt_type, n, sizeof (n)));
		fprintf(out, ",\"size\":%zd", ctf_type_size(dtt.dtt_ctfp,
		    dtt.dtt_type));
	}
	if ((!typed && pgp == NULL) || (typed && rc != 0)) {
		fprintf(out, ",\"error\":");
		jcstr(dtrace_errmsg(dtp, dtrace_errno(dtp)));
		fprintf(out, ",\"errno\":%d", dtrace_errno(dtp));
	} else if (pgp != NULL) {
		dtrace_proginfo_t info;

		if (co->link) {
			hypertrace_errmsg_t msg;
			int lrc;

			/* The compiler's statements, then the linked ones. */
			fputs(",\"stmts0\":[", out);
			(void) dtrace_stmt_iter(dtp, pgp, stmt_cb, &first);
			fputs("]", out);
			first = 1;
			msg[0] = '\0';
			lrc = hypertrace_link(dtp, pgp, msg);
			fprintf(out, ",\"link\":%d,\"linkmsg\":", lrc);
			jcstr(msg);
		}
		fputs(",\"stmts\":[", out);
		(void) dtrace_stmt_iter(dtp, pgp, stmt_cb, &first);
		fputs("]", out);
		dtrace_program_info(dtp, pgp, &info);
		fprintf(out, ",\"info\":[%u,%u,%u,%u]",
		    info.dpi_descattr.dtat_name, info.dpi_stmtattr.dtat_name,
		    info.dpi_aggregates, info.dpi_recgens);
	}
}

/*
 * A case may consist of several phases on one handle, separated by lines
 * "@@then OPTS": the options are applied between compilations.  Earlier
 * phases are reported as "phaseN" objects; the last phase's fields are at
 * the top level.
 */
static void
run_case(const char *name, unsigned cflags, int spec, char *opts,
    char *program, const char *tmpdir)
{
	dtrace_hdl_t *dtp;
	struct copts co;
	char *tok, *save, *o1 = strdup(opts), *o2 = strdup(opts), *next;
	int err, libs = 0, fakemods = 0, phase = 0;

	memset(&co, 0, sizeof (co));
	conf_tupregs = DIF_DTR_NREGS;
	for (tok = strtok_r(o1, ",", &save); tok != NULL;
	    tok = strtok_r(NULL, ",", &save)) {
		if (strncmp(tok, "conf_tupregs=", 13) == 0)
			conf_tupregs = atoi(tok + 13);
		if (strcmp(tok, "libs") == 0)
			libs = 1;
		if (strcmp(tok, "fakemods") == 0)
			fakemods = 1;
	}

	dtp = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS | DTRACE_O_LP64,
	    &err, &vector, NULL);
	fprintf(out, "{\"case\":");
	jcstr(name);
	if (dtp == NULL) {
		fprintf(out, ",\"open_error\":");
		jcstr(dtrace_errmsg(NULL, err));
		fputs("}\n", out);
		free(o1);
		free(o2);
		return;
	}
	if (!libs)
		(void) dtrace_setopt(dtp, "nolibs", NULL);
	if (fakemods)
		add_fakemods(dtp);
	apply_opts(dtp, o2, &co);
	for (;;) {
		next = strstr(program, "\n@@then ");
		if (next != NULL)
			*next = '\0';
		if (next != NULL)
			fprintf(out, ",\"phase%d\":{\"case\":0", phase);
		compile_phase(dtp, name, phase, cflags, spec, &co, program,
		    tmpdir);
		if (next == NULL)
			break;
		fputc('}', out);
		program = next + strlen("\n@@then ");
		{
			char *nl = strchr(program, '\n');

			assert(nl != NULL);
			*nl = '\0';
			apply_opts(dtp, program, &co);
			program = nl + 1;
		}
		phase++;
	}
	fputs("}\n", out);
	fflush(out);
	dtrace_close(dtp);
	free(o1);
	free(o2);
}

/*
 * Run one case with the n-th allocation failing (n = 0: none) and return
 * its JSON result line; *hitp says whether the failure was injected.
 */
static char *
oom_run(const char *name, unsigned cflags, int spec, const char *opts,
    const char *prog, const char *tmpdir, long n, int *hitp)
{
	FILE *save = out;
	char *buf = NULL, *o = strdup(opts), *pg = strdup(prog);
	size_t len = 0;

	out = open_memstream(&buf, &len);
	oom_n = n;
	oom_was_hit = 0;
	run_case(name, cflags, spec, o, pg, tmpdir);
	fclose(out);
	out = save;
	free(o);
	free(pg);
	*hitp = oom_was_hit;
	return (buf);
}

/*
 * Sweep every allocation of one compilation: the n-th request fails for
 * n = 1, 2, ... until a compilation makes fewer than n requests.  Each run
 * must either fail with an error or succeed with output identical to the
 * fault-free compilation.
 */
static void
oom_sweep(const char *name, unsigned cflags, int spec, const char *opts,
    const char *prog, const char *tmpdir)
{
	char *base, *got, path[1024], others[4096] = "", diffs[512] = "";
	long n, nomem = 0, other = 0, same = 0, differ = 0, firstdiff = 0;
	int hit, fd;

	snprintf(path, sizeof (path), "%s/oom-progress", tmpdir);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	base = oom_run(name, cflags, spec, opts, prog, tmpdir, 0, &hit);
	if (getenv("FCG_OOM_ONLY") != NULL) {
		/* Debugging aid: show one injected run next to the baseline. */
		got = oom_run(name, cflags, spec, opts, prog, tmpdir,
		    atol(getenv("FCG_OOM_ONLY")), &hit);
		fprintf(out, "BASE %sGOT(hit=%d) %s", base, hit, got);
		return;
	}
	for (n = 1; ; n++) {
		char nb[32];
		int l = snprintf(nb, sizeof (nb), "%ld\n", n);

		(void) pwrite(fd, nb, l, 0);
		got = oom_run(name, cflags, spec, opts, prog, tmpdir, n, &hit);
		if (!hit) {
			if (strcmp(got, base) != 0 && firstdiff == 0)
				firstdiff = -n;
			free(got);
			break;
		}
		if (strstr(got, "\"stmts\"") != NULL ||
		    strstr(got, "\"type\"") != NULL ||
		    (strstr(got, "\"errno\":0") != NULL &&
		    strstr(base, "\"errno\":0") != NULL)) {
			if (strcmp(got, base) == 0) {
				same++;
			} else {
				differ++;
				if (firstdiff == 0)
					firstdiff = n;
				{
					FILE *dfp;
					char dp[1100];

					snprintf(dp, sizeof (dp), "%s/%s.%ld.diff",
					    tmpdir, name, n);
					if ((dfp = fopen(dp, "w")) != NULL) {
						fprintf(dfp, "%s%s", base, got);
						fclose(dfp);
					}
				}
				if (strlen(diffs) < sizeof (diffs) - 24)
					snprintf(diffs + strlen(diffs),
					    sizeof (diffs) - strlen(diffs),
					    "%s%ld", diffs[0] ? "," : "", n);
			}
		} else if (strstr(got, "Memory allocation failure") != NULL ||
		    strstr(got, "Cannot allocate memory") != NULL) {
			nomem++;
		} else {
			char *e = strstr(got, "\"error\":");

			other++;
			if (e != NULL && strlen(others) < sizeof (others) - 200) {
				char *end = strchr(e + 9, '"');

				end = end != NULL ? strchr(end + 1, '"') : NULL;
				strncat(others, e + 8, end != NULL ?
				    (size_t)(end - e - 7) : 60);
				strcat(others, ";");
			}
		}
		free(got);
	}
	close(fd);
	fprintf(out, "{\"case\":");
	jcstr(name);
	fprintf(out, ",\"requests\":%ld,\"nomem\":%ld,\"other\":%ld,"
	    "\"same\":%ld,\"differ\":%ld,\"firstdiff\":%ld,\"others\":",
	    n - 1, nomem, other, same, differ, firstdiff);
	jcstr(others);
	fprintf(out, ",\"diffs\":[%s]", diffs);
	fprintf(out, ",\"baseline_ok\":%d}\n",
	    strstr(base, "\"stmts\"") != NULL || strstr(base, "\"type\"") != NULL);
	fflush(out);
	free(base);
}

int
main(int argc, char **argv)
{
	size_t len;
	char *buf, *p, *next;

	if (argc != 4) {
		fprintf(stderr, "usage: %s cases out.jsonl tmpdir\n", argv[0]);
		return (2);
	}
	oom_arm = (void (*)(long))dlsym(RTLD_DEFAULT, "fcg_oom_arm");
	oom_hit = (int (*)(void))dlsym(RTLD_DEFAULT, "fcg_oom_hit");
	oom_target = (void (*)(const char *))dlsym(RTLD_DEFAULT,
	    "fcg_oom_target");
	if (oom_arm == NULL || oom_hit == NULL)
		oom_arm = NULL;
	if ((buf = read_all(argv[1], &len)) == NULL ||
	    (out = fopen(argv[2], "w")) == NULL) {
		perror("open");
		return (2);
	}
	for (p = strstr(buf, "@@case "); p != NULL; p = next) {
		char name[256], opts[2048], *nl, *prog;
		unsigned cflags;
		int spec;

		nl = strchr(p, '\n');
		assert(nl != NULL);
		*nl = '\0';
		if (sscanf(p, "@@case %255s %x %d %2047s", name, &cflags, &spec,
		    opts) != 4)
			abort();
		prog = nl + 1;
		next = strstr(prog, "\n@@case ");
		if (next != NULL) {
			*next = '\0';
			next++;
		}
		if (oom_arm != NULL) {
			pid_t pid;
			int status;

			{
				char *t = strstr(opts, "oomfunc=");
				char fn[128] = "";

				if (t != NULL)
					(void) sscanf(t + 8, "%127[^,]", fn);
				if (oom_target != NULL)
					oom_target(fn);
			}
			fflush(out);
			if (getenv("FCG_NOFORK") != NULL) {
				/* Debugging aid: run the sweep in-process. */
				oom_sweep(name, cflags, spec, opts, prog,
				    argv[3]);
				continue;
			}
			if ((pid = fork()) == 0) {
				oom_sweep(name, cflags, spec, opts, prog,
				    argv[3]);
				exit(0);
			}
			(void) waitpid(pid, &status, 0);
			if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
				char path[1024], nb[32] = "";
				FILE *fp;

				snprintf(path, sizeof (path), "%s/oom-progress",
				    argv[3]);
				if ((fp = fopen(path, "r")) != NULL) {
					if (fgets(nb, sizeof (nb), fp) == NULL)
						nb[0] = '\0';
					fclose(fp);
				}
				fprintf(out, "{\"case\":");
				jcstr(name);
				fprintf(out, ",\"crash\":%d,\"at\":%ld}\n",
				    WIFSIGNALED(status) ? WTERMSIG(status) : -1,
				    atol(nb));
				fflush(out);
			}
			continue;
		}
		run_case(name, cflags, spec, opts, prog, argv[3]);
	}
	fclose(out);
	return (0);
}
