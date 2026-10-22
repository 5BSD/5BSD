/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Providers and probes (dt_provider.c) through a dtrace_vopen() vector that
 * models the dtrace(4) provider/probe ioctls:
 *   DTRACEIOC_PROVIDER   describe a named provider, ESRCH if unknown;
 *   DTRACEIOC_PROBEMATCH first probe with id >= dtpd_id matching the glob
 *                        description (empty field = any), ESRCH when none;
 *   DTRACEIOC_PROBES     same over all probes;
 *   DTRACEIOC_PROBEARG   argument dtargd_ndx of probe dtargd_id, or
 *                        dtargd_ndx = DTRACE_ARGNONE past the last one
 * (sys/cddl/dev/dtrace/dtrace_ioctl.c).  The kinst device is answered by
 * frontend-runtime-shim.so.  Expected results follow the documented rules
 * in dt_provider.c and the Dynamic Tracing Guide "Stability" chapter: a
 * description matching several probes reports argument information only if
 * the provider's Arguments data stability is at least Evolving and no
 * Evolving-or-better name component is empty or a glob.
 */
#include <sys/types.h>
#include <sys/ioctl.h>

#include <dlfcn.h>
#include <fnmatch.h>
#include <string.h>
#include <unistd.h>

#include <dt_impl.h>
#include <dt_provider.h>
#include <dt_parser.h>
#include <kinst.h>
#include <libctf.h>

#include "frontend-faults.h"
#include "frontend-runtime-shim.h"

#define	CMD(x)	((u_long)(x) & 0xffffffffUL)
#define	E	DTRACE_STABILITY_EVOLVING
#define	P	DTRACE_STABILITY_PRIVATE
#define	U	DTRACE_STABILITY_UNSTABLE

struct marg { int mapping; const char *native, *xlate; };
struct mprobe {
	const char *prov, *mod, *func, *name;
	int argerr;
	struct marg args[4];
};
/* Probe ids are index + 1. */
static const struct mprobe probes[] = {
	{ "dtrace", "", "", "BEGIN", 0, { { -1 } } },
	{ "dtrace", "", "", "END", 0, { { -1 } } },
	{ "dtrace", "", "", "ERROR", 0, { { -1 } } },
	{ "kp", "kmod", "alpha", "entry", 0,
	    { { 0, "int", "" }, { 1, "char *", "string" }, { -1 } } },
	{ "kp", "kmod", "alpha", "return", 0, { { -1 } } },
	{ "kp", "kmod", "beta", "entry", 0,
	    { { 1, "nosuch_97_t", "" }, { 0, "int", "nosuch_98_t" },
	    { 2, "long", "int" }, { -1 } } },
	{ "unst", "m", "f", "a", 0, { { 0, "int", "" }, { -1 } } },
	{ "unst", "m", "f", "b", 0, { { 0, "int", "" }, { -1 } } },
	{ "evm", "m1", "f", "a", 0, { { -1 } } },
	{ "evm", "m1", "g", "a", 0, { { -1 } } },
	{ "evf", "m", "f1", "b", 0, { { -1 } } },
	{ "evn", "m", "g", "a1", 0, { { -1 } } },
	{ "ghost", "m", "f", "x", 0, { { -1 } } },
	{ "same", "m", "f", "x", 0, { { 0, "int", "int" }, { -1 } } },
	{ "user", "m", "f", "x", 0, { { 0, "userland int *", "" }, { -1 } } },
	{ "many", "m", "f", "x", 2, { { -1 } } },
	{ "evm", "m2", "f", "a", 0, { { -1 } } },
	{ "evf", "m", "f1", "a", 0, { { -1 } } },
	{ "evf", "m", "f2", "a", 0, { { -1 } } },
	{ "evn", "m", "f", "a1", 0, { { -1 } } },
	{ "evn", "m", "f", "a2", 0, { { -1 } } },
	{ "pv", "m", "f", "a1", 0, { { 0, "int", "" }, { -1 } } },
	{ "pv", "m", "f", "a2", 0, { { 0, "int", "" }, { -1 } } },
	{ "argerr", "m", "f", "n", 1, { { -1 } } },
	{ "kinst", "", "vm_fault", "12", 0, { { -1 } } },
	{ "pid999999", "a.out", "main", "entry", 0, { { -1 } } },
};
#define	NPROBES	((int)(sizeof (probes) / sizeof (probes[0])))

static void
attrs(const char *prov, dtrace_pattr_t *pa)
{
	dtrace_attribute_t ev = { E, E, DTRACE_CLASS_COMMON };
	dtrace_attribute_t pr = { P, P, DTRACE_CLASS_UNKNOWN };

	pa->dtpa_provider = ev;
	pa->dtpa_mod = pr;
	pa->dtpa_func = pr;
	pa->dtpa_name = pr;
	pa->dtpa_args = ev;
	if (strcmp(prov, "unst") == 0)
		pa->dtpa_args.dtat_data = U;
	else if (strcmp(prov, "evm") == 0)
		pa->dtpa_mod = ev;
	else if (strcmp(prov, "evf") == 0)
		pa->dtpa_func = ev;
	else if (strcmp(prov, "evn") == 0 || strcmp(prov, "kp") == 0)
		pa->dtpa_name = ev;
}

static int
known_provider(const char *name)
{
	int i;

	if (strcmp(name, "ghost") == 0)
		return (0);	/* matched by PROBEMATCH, unknown to PROVIDER */
	for (i = 0; i < NPROBES; i++)
		if (strcmp(probes[i].prov, name) == 0)
			return (1);
	return (0);
}

static int
fmatch(const char *pat, const char *s)
{
	return (pat[0] == '\0' || fnmatch(pat, s, 0) == 0);
}

static int probes_calls;

static int
model_ioctl(void *arg, u_long cmd, void *data)
{
	int i;

	(void) arg;
	if (cmd == CMD(DTRACEIOC_CONF)) {
		dtrace_conf_t *c = data;

		memset(c, 0, sizeof (*c));
		c->dtc_difversion = DIF_VERSION;
		c->dtc_difintregs = DIF_DIR_NREGS;
		c->dtc_diftupregs = DIF_DTR_NREGS;
		c->dtc_ctfmodel = CTF_MODEL_NATIVE;
		return (0);
	}
	if (cmd == CMD(DTRACEIOC_PROVIDER)) {
		dtrace_providerdesc_t *pv = data;

		if (strcmp(pv->dtvd_name, "ioerr") == 0)
			return (errno = EIO, -1);
		if (!known_provider(pv->dtvd_name))
			return (errno = ESRCH, -1);
		attrs(pv->dtvd_name, &pv->dtvd_attr);
		return (0);
	}
	if (cmd == CMD(DTRACEIOC_PROBEMATCH) || cmd == CMD(DTRACEIOC_PROBES)) {
		dtrace_probedesc_t *pd = data;
		int all = cmd == CMD(DTRACEIOC_PROBES);

		probes_calls++;
		if (!all && strcmp(pd->dtpd_provider, "badglob") == 0)
			return (errno = EINVAL, -1);
		if (!all && (strcmp(pd->dtpd_provider, "eio") == 0 ||
		    strcmp(pd->dtpd_name, "eioname") == 0))
			return (errno = EIO, -1);
		if (!all && strcmp(pd->dtpd_name, "ebadfname") == 0)
			return (errno = EBADF, -1);
		for (i = pd->dtpd_id > 0 ? pd->dtpd_id - 1 : 0; i < NPROBES;
		    i++) {
			if (!all && (!fmatch(pd->dtpd_provider, probes[i].prov) ||
			    !fmatch(pd->dtpd_mod, probes[i].mod) ||
			    !fmatch(pd->dtpd_func, probes[i].func) ||
			    !fmatch(pd->dtpd_name, probes[i].name)))
				continue;
			pd->dtpd_id = i + 1;
			(void) strlcpy(pd->dtpd_provider, probes[i].prov,
			    sizeof (pd->dtpd_provider));
			(void) strlcpy(pd->dtpd_mod, probes[i].mod,
			    sizeof (pd->dtpd_mod));
			(void) strlcpy(pd->dtpd_func, probes[i].func,
			    sizeof (pd->dtpd_func));
			(void) strlcpy(pd->dtpd_name, probes[i].name,
			    sizeof (pd->dtpd_name));
			return (0);
		}
		return (errno = ESRCH, -1);
	}
	if (cmd == CMD(DTRACEIOC_PROBEARG)) {
		dtrace_argdesc_t *ad = data;
		const struct mprobe *mp;
		int k;

		if (ad->dtargd_id < 1 || ad->dtargd_id > NPROBES)
			return (errno = EINVAL, -1);
		mp = &probes[ad->dtargd_id - 1];
		if (mp->argerr == 1)
			return (errno = EIO, -1);
		if (mp->argerr == 2) {	/* never reports DTRACE_ARGNONE */
			ad->dtargd_mapping = ad->dtargd_ndx;
			(void) strlcpy(ad->dtargd_native, "int",
			    sizeof (ad->dtargd_native));
			ad->dtargd_xlate[0] = '\0';
			return (0);
		}
		for (k = 0; k <= ad->dtargd_ndx && mp->args[k].mapping != -1; k++)
			continue;
		if (k <= ad->dtargd_ndx) {
			ad->dtargd_ndx = DTRACE_ARGNONE;
			return (0);
		}
		ad->dtargd_mapping = mp->args[ad->dtargd_ndx].mapping;
		(void) strlcpy(ad->dtargd_native, mp->args[ad->dtargd_ndx].native,
		    sizeof (ad->dtargd_native));
		(void) strlcpy(ad->dtargd_xlate, mp->args[ad->dtargd_ndx].xlate,
		    sizeof (ad->dtargd_xlate));
		return (0);
	}
	return (errno = ENOTTY, -1);
}

static int
model_lookup(void *a, GElf_Addr addr, GElf_Sym *s, dtrace_syminfo_t *i)
{
	(void) a; (void) addr; (void) s; (void) i;
	return (-1);
}

static int
model_status(void *a, processorid_t cpu)
{
	(void) a;
	return (cpu == 0 ? 1 : -1);
}

static long
model_sysconf(void *a, int name)
{
	(void) a;
	return (sysconf(name));
}

static const dtrace_vector_t vector = {
	.dtv_ioctl = model_ioctl,
	.dtv_lookup_by_addr = model_lookup,
	.dtv_status = model_status,
	.dtv_sysconf = model_sysconf,
};

/* ---- kinst device via the shim ---------------------------------------- */

static struct {
	void (*reset)(void);
	void (*dev)(const char *, int);
	int (*opens)(const char *);
	void (*ioctl)(frontend_shim_ioctl_f *, void *);
} S;
static dtrace_kinst_probedesc_t last_kinst;
static int kinst_calls, kinst_fail;

static int
kinst_ioctl(void *arg, int fd, unsigned long req, void *data)
{
	(void) arg; (void) fd;
	if (req == KINSTIOC_MAKEPROBE) {
		kinst_calls++;
		memcpy(&last_kinst, data, sizeof (last_kinst));
		return (kinst_fail ? (errno = EINVAL, -1) : 0);
	}
	return (errno = ENOTTY, -1);
}

static void
bind_shim(void)
{
	int (*active)(void) = (int (*)(void))dlsym(RTLD_DEFAULT,
	    "frontend_shim_active");

	if (active == NULL || active() != 1) {
		printf("FAIL frontend-runtime-shim.so is not preloaded\n");
		exit(2);
	}
#define	B(f) S.f = dlsym(RTLD_DEFAULT, "frontend_shim_" #f)
	B(reset); B(dev); B(opens); B(ioctl);
#undef B
}

/* ---- helpers --------------------------------------------------------- */

static dtrace_hdl_t *
vopen(void)
{
	int err;
	dtrace_hdl_t *dtp = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS, &err,
	    &vector, NULL);

	if (dtp == NULL) {
		printf("FAIL vopen: %s\n", dtrace_errmsg(NULL, err));
		exit(2);
	}
	(void) dtrace_setopt(dtp, "nolibs", NULL);
	return (dtp);
}

static int
info(dtrace_hdl_t *dtp, const char *spec, dtrace_id_t id,
    dtrace_probeinfo_t *pi)
{
	dtrace_probedesc_t pd;

	if (dtrace_str2desc(dtp, DTRACE_PROBESPEC_NAME, spec, &pd) != 0)
		return (-2);
	pd.dtpd_id = id;
	memset(pi, 0, sizeof (*pi));
	return (dtrace_probe_info(dtp, &pd, pi) == 0 ? 0 : dtrace_errno(dtp));
}

static int
argtype_is(const dtrace_probeinfo_t *pi, int i, const char *name)
{
	char buf[128];

	if (i >= pi->dtp_argc)
		return (0);
	if (name == NULL)
		return (pi->dtp_argv[i].dtt_type == CTF_ERR);
	if (pi->dtp_argv[i].dtt_type == CTF_ERR)
		return (0);
	return (ctf_type_name(pi->dtp_argv[i].dtt_ctfp,
	    pi->dtp_argv[i].dtt_type, buf, sizeof (buf)) != NULL &&
	    strcmp(buf, name) == 0);
}

/* ---- tests ------------------------------------------------------------ */

static void
test_info(void)
{
	dtrace_hdl_t *dtp = vopen();
	dtrace_probeinfo_t pi;
	dt_provider_t *pvp;
	int e;

	e = info(dtp, "kp:kmod:alpha:entry", DTRACE_IDNONE, &pi);
	check(e == 0 && pi.dtp_argc == 2 && argtype_is(&pi, 0, "int") &&
	    argtype_is(&pi, 1, "string"),
	    "alpha entry: int, string (translated from char *) e=%d argc=%d",
	    e, pi.dtp_argc);
	/* Attributes: minimum of provider (Evolving) and the named fields;
	 * mod and func are Private. */
	check(e == 0 && pi.dtp_attr.dtat_name == P, "attribute minimum");
	pvp = dt_provider_lookup(dtp, "kp");
	check(pvp != NULL && (pvp->pv_flags & DT_PROVIDER_IMPL),
	    "kernel provider cached as implemented");
	e = info(dtp, "kp:kmod:alpha:entry", DTRACE_IDNONE, &pi);
	check(e == 0 && pi.dtp_argc == 2, "cached probe");
	e = info(dtp, "kp:kmod:alpha:return", DTRACE_IDNONE, &pi);
	check(e == 0 && pi.dtp_argc == 0, "probe without arguments");
	/* Explicit id: discovered directly.  arg0 maps to native 1 (an
	 * unknown type), arg1's translated type is unknown, arg2 int. */
	e = info(dtp, "kp:kmod:beta:entry", 6, &pi);
	check(e == 0 && pi.dtp_argc == 3 && argtype_is(&pi, 0, NULL) &&
	    argtype_is(&pi, 1, NULL) && argtype_is(&pi, 2, "int"),
	    "beta entry argument resolution e=%d argc=%d", e, pi.dtp_argc);
	/* Several matches. */
	check(info(dtp, "unst:m:f:", DTRACE_IDNONE, &pi) == EDT_UNSTABLE,
	    "unstable argument data with several matches");
	check(info(dtp, "evm:::a", DTRACE_IDNONE, &pi) == EDT_UNSTABLE,
	    "evolving module name globbed");
	check(info(dtp, "evf:m::a", DTRACE_IDNONE, &pi) == EDT_UNSTABLE,
	    "evolving function name globbed");
	check(info(dtp, "evn:m:f:a*", DTRACE_IDNONE, &pi) == EDT_UNSTABLE,
	    "evolving probe name globbed");
	e = info(dtp, "pv:m:f:", DTRACE_IDNONE, &pi);
	check(e == 0 && pi.dtp_argc == 1 && argtype_is(&pi, 0, "int"),
	    "private names may be globbed (e=%d)", e);
	e = info(dtp, "p*:m:f:a1", DTRACE_IDNONE, &pi);
	check(e == 0 && pi.dtp_attr.dtat_name == DTRACE_STABILITY_UNSTABLE,
	    "globbed provider reports Unstable attributes (e=%d)", e);
	/* Errors. */
	check(info(dtp, "nosuchprov:::x", DTRACE_IDNONE, &pi) == EDT_NOPROBE,
	    "unknown provider");
	check(info(dtp, "ioerr:::x", DTRACE_IDNONE, &pi) == EDT_NOPROBE,
	    "provider ioctl failure falls back to matching");
	check(dt_provider_lookup(dtp, "ioerr") == NULL &&
	    dtrace_errno(dtp) == EIO, "provider ioctl errno");
	check(dt_provider_lookup(dtp, "nosuchprov") == NULL &&
	    dtrace_errno(dtp) == EDT_NOPROV, "ESRCH -> EDT_NOPROV");
	check(dt_provider_lookup(dtp, "k*") == NULL &&
	    dtrace_errno(dtp) == EDT_NOPROV, "glob provider name");
	check(dt_provider_lookup(dtp, "") == NULL &&
	    dtrace_errno(dtp) == EDT_NOPROV, "empty provider name");
	check(info(dtp, "argerr:m:f:n", DTRACE_IDNONE, &pi) == EIO,
	    "PROBEARG failure");
	check(info(dtp, "badglob:::", DTRACE_IDNONE, &pi) == EDT_BADPGLOB,
	    "EINVAL -> EDT_BADPGLOB");
	check(info(dtp, "eio:::", DTRACE_IDNONE, &pi) == EIO, "match errno");
	check(info(dtp, "ghost:m:f:x", DTRACE_IDNONE, &pi) == EDT_NOPROV,
	    "matched probe of an unknown provider");
	e = info(dtp, "same:m:f:x", DTRACE_IDNONE, &pi);
	check(e == 0 && argtype_is(&pi, 0, "int"),
	    "translated type equal to native");
	e = info(dtp, "user:m:f:x", DTRACE_IDNONE, &pi);
	check(e == 0 && pi.dtp_argc == 1 &&
	    (pi.dtp_argv[0].dtt_flags & DTT_FL_USER),
	    "userland native type keeps the user flag (e=%d)", e);
	e = info(dtp, "many:m:f:x", DTRACE_IDNONE, &pi);
	check(e == 0 && pi.dtp_argc == 32,
	    "argument discovery stops at the argument maximum (%d)",
	    pi.dtp_argc);
	/* Several matches but nothing Evolving is globbed. */
	check(info(dtp, "evm:m1::a", DTRACE_IDNONE, &pi) == 0,
	    "evolving module named exactly");
	check(info(dtp, "evf:m:f1:", DTRACE_IDNONE, &pi) == 0,
	    "evolving function named exactly");
	check(info(dtp, "evn:m::a1", DTRACE_IDNONE, &pi) == 0,
	    "evolving name named exactly");
	check(info(dtp, "kp:km*:alpha:entry", DTRACE_IDNONE, &pi) == 0,
	    "module glob with a single match");
	pvp = dt_provider_lookup(dtp, "kp");
	check(dt_probe_lookup(pvp, "kmod:alpha:return") != NULL,
	    "probe lookup discovers through PROBEMATCH");
	check(dt_probe_lookup(pvp, "ebadfname") == NULL &&
	    dtrace_errno(dtp) == EDT_NOPROBE, "probe lookup EBADF");
	check(info(dtp, "kp:kmod:al*:entry", DTRACE_IDNONE, &pi) == 0,
	    "function glob with a single match");
	check(dt_probe_lookup(pvp, "kmod:alpha:nosuch") == NULL &&
	    dtrace_errno(dtp) == EDT_NOPROBE, "probe lookup ESRCH");
	check(dt_probe_lookup(pvp, "eioname") == NULL &&
	    dtrace_errno(dtp) == EIO, "probe lookup errno");
	check(dt_probe_lookup(pvp, "x$1") == NULL &&
	    dtrace_errno(dtp) == EDT_BADSPCV, "probe lookup bad description");
	/* A pid provider probe without kernel argument data asks the pid
	 * provider support for types; process 999999 does not exist. */
	e = info(dtp, "pid999999:a.out:main:entry", DTRACE_IDNONE, &pi);
	check(e == 0 && pi.dtp_argc == 0, "pid probe without types (e=%d)", e);
	dtrace_close(dtp);
}

static int
count_cb(dtrace_hdl_t *dtp, const dtrace_probedesc_t *pd, void *arg)
{
	int *n = arg;

	(void) dtp;
	if (pd->dtpd_id >= 1 && pd->dtpd_id <= NPROBES &&
	    strcmp(pd->dtpd_name, probes[pd->dtpd_id - 1].name) == 0)
		n[0]++;
	else
		n[1]++;
	return (0);
}

static int
stop_cb(dtrace_hdl_t *dtp, const dtrace_probedesc_t *pd, void *arg)
{
	(void) dtp; (void) pd;
	return (++*(int *)arg == 2 ? 77 : 0);
}

static void
test_iter(void)
{
	dtrace_hdl_t *dtp = vopen();
	dt_provider_t *pvp;

	/* An uncached probe is discovered through PROBEMATCH. */
	pvp = dt_provider_lookup(dtp, "kp");
	check(pvp != NULL && dt_probe_lookup(pvp, "kmod:beta:entry") != NULL,
	    "uncached probe lookup");
	dtrace_probedesc_t pd;
	int n[2] = { 0, 0 }, stop = 0;

	check(dtrace_probe_iter(dtp, NULL, count_cb, n) == 0 &&
	    n[0] == NPROBES, "all kernel probes listed once (%d, other %d)",
	    n[0], n[1]);
	check(dtrace_probe_iter(dtp, NULL, stop_cb, &stop) == 77 && stop == 2,
	    "callback return stops the iteration");
	(void) dtrace_str2desc(dtp, DTRACE_PROBESPEC_NAME, "kp:::entry", &pd);
	n[0] = n[1] = 0;
	check(dtrace_probe_iter(dtp, &pd, count_cb, n) == 0 && n[0] == 2,
	    "kp:::entry matches two probes (%d)", n[0]);
	(void) dtrace_str2desc(dtp, DTRACE_PROBESPEC_NAME, "kp:::nomatch", &pd);
	check(dtrace_probe_iter(dtp, &pd, count_cb, n) == -1 &&
	    dtrace_errno(dtp) == EDT_NOPROBE, "no match -> EDT_NOPROBE");
	dtrace_close(dtp);
}

/* Providers declared in D: static probes, argument mappings, translators. */
static void
test_declared(void)
{
	static const char prog[] =
	    "struct xin { int a; }; struct xout { int b; };\n"
	    "translator struct xout < struct xin *p > { b = p->a; };\n"
	    "provider dp {\n"
	    "	probe one(int, char *);\n"
	    "	probe two(int a, char *b) : (char *b, int a);\n"
	    "	probe three(struct xin *p) : (struct xout *p);\n"
	    "	probe four(struct xin *p) : (struct xout *p);\n"
	    "	probe five(int, int b) : (int b);\n"
	    "};\n"
	    "BEGIN { trace(1); }\n";
	dtrace_hdl_t *dtp = vopen();
	dtrace_probedesc_t pd;
	dtrace_probeinfo_t pi;
	dt_provider_t *pvp;
	dt_probe_t *prp;
	int n[2] = { 0, 0 }, e;

	check(dtrace_program_strcompile(dtp, prog, DTRACE_PROBESPEC_NAME, 0, 0,
	    NULL) != NULL, "provider declaration compiles: %s",
	    dtrace_errmsg(dtp, dtrace_errno(dtp)));
	pvp = dt_provider_lookup(dtp, "dp");
	check(pvp != NULL && !(pvp->pv_flags & DT_PROVIDER_IMPL),
	    "declared provider");
	if (pvp == NULL) {
		dtrace_close(dtp);
		return;
	}
	check(!(pvp->pv_flags & DT_PROVIDER_INTF),
	    "translated probes clear the interface-only flag");
	prp = dt_probe_lookup(pvp, "two");
	check(prp != NULL && prp->pr_xargc == 2 && prp->pr_mapping[0] == 1 &&
	    prp->pr_mapping[1] == 0, "two(int a, char *b) : (char *b, int a) "
	    "maps xarg0 -> arg1, xarg1 -> arg0");
	prp = dt_probe_lookup(pvp, "one");
	check(prp != NULL && prp->pr_xargc == 2 && prp->pr_mapping[0] == 0 &&
	    prp->pr_mapping[1] == 1, "one(int, char *) is the identity mapping");
	check(pvp->pv_xrefs != NULL && pvp->pv_xrmax > 0,
	    "translator reference recorded");
	(void) dtrace_str2desc(dtp, DTRACE_PROBESPEC_NAME, "dp:::t*", &pd);
	check(dtrace_probe_iter(dtp, &pd, count_cb, n) == 0 && n[1] == 2,
	    "declared probes iterate by name glob (%d)", n[1]);
	e = info(dtp, "dp:::three", DTRACE_IDNONE, &pi);
	check(e == 0 && pi.dtp_argc == 1, "declared probe info (e=%d)", e);
	/* A glob matching one declared probe is resolved by name; one that
	 * matches two (two, three) is subject to the stability rule, and a
	 * declared provider's Arguments data stability is Private. */
	e = info(dtp, "dp:::thr*", DTRACE_IDNONE, &pi);
	check(e == 0 && pi.dtp_argc == 1, "glob matching one declared probe "
	    "(e=%d)", e);
	check(pvp->pv_desc.dtvd_attr.dtpa_args.dtat_data <
	    DTRACE_STABILITY_EVOLVING &&
	    info(dtp, "dp:::t*", DTRACE_IDNONE, &pi) == EDT_UNSTABLE,
	    "glob matching two declared probes is unstable");
	(void) dtrace_str2desc(dtp, DTRACE_PROBESPEC_NAME, "zz*:::", &pd);
	n[0] = n[1] = 0;
	check(dtrace_probe_iter(dtp, &pd, count_cb, n) == -1 &&
	    dtrace_errno(dtp) == EDT_NOPROBE && n[1] == 0,
	    "provider pattern matching no declared provider");
	/* Output prototype arguments must name input arguments, and a
	 * probe may be declared once. */
	check(dtrace_program_strcompile(dtp,
	    "provider pq { probe six(int a) : (int z); }; BEGIN { }",
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL) == NULL &&
	    strstr(dtrace_errmsg(dtp, dtrace_errno(dtp)), "not declared") != NULL,
	    "unknown output argument name");
	check(dtrace_program_strcompile(dtp,
	    "provider pr { probe x(); probe x(); }; BEGIN { }",
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL) == NULL &&
	    strstr(dtrace_errmsg(dtp, dtrace_errno(dtp)), "redeclared") != NULL,
	    "probe redeclared");
	{
		int stop = 0;

		(void) dtrace_str2desc(dtp, DTRACE_PROBESPEC_NAME, "dp:::", &pd);
		check(dtrace_probe_iter(dtp, &pd, stop_cb, &stop) == 77,
		    "callback stops iteration of declared probes");
	}
	dtrace_close(dtp);
}

/* Dynamic translation of a kernel probe argument creates a type tag. */
static void
test_probe_tag(void)
{
	dtrace_hdl_t *dtp = vopen();
	dtrace_typeinfo_t t;
	int i;

	(void) dtrace_setopt(dtp, "late", "dynamic");
	for (i = 0; i < 2; i++)
		(void) dtrace_program_strcompile(dtp,
		    "kp:kmod:beta:entry { trace(args[2]); }",
		    DTRACE_PROBESPEC_NAME, 0, 0, NULL);
	check(dtrace_lookup_by_type(dtp, DTRACE_OBJ_DDEFS,
	    "__dtrace_kp___entry_arg2", &t) == 0,
	    "dynamic translator tag typedef defined");
	dtrace_close(dtp);
}

static void
test_kinst(void)
{
	dtrace_hdl_t *dtp;
	dtrace_probeinfo_t pi;
	int e;

	S.reset();
	S.ioctl(kinst_ioctl, NULL);
	S.dev("/dev/dtrace/kinst", 0);
	dtp = vopen();
	kinst_calls = 0;
	e = info(dtp, "kinst::vm_fault:12", DTRACE_IDNONE, &pi);
	check(e == 0 && kinst_calls == 1 &&
	    strcmp(last_kinst.kpd_func, "vm_fault") == 0 &&
	    last_kinst.kpd_off == 12, "kinst probe at offset 12 (e=%d)", e);
	e = info(dtp, "kinst::vm_fault:", DTRACE_IDNONE, &pi);
	check(kinst_calls == 2 && last_kinst.kpd_off == -1 &&
	    S.opens("/dev/dtrace/kinst") == 1,
	    "kinst glob name requests every offset; device opened once");
	kinst_fail = 1;
	check(info(dtp, "kinst::vm_fault:12", DTRACE_IDNONE, &pi) == EINVAL,
	    "kinst ioctl failure");
	kinst_fail = 0;
	dtrace_close(dtp);

	S.reset();
	S.dev("/dev/dtrace/kinst", EACCES);
	dtp = vopen();
	check(info(dtp, "kinst::vm_fault:12", DTRACE_IDNONE, &pi) == EACCES,
	    "kinst device open failure");
	dtrace_close(dtp);
	S.reset();
}

/* USDT probe sites recorded by dt_probe_define (dtrace -G). */
static void
test_define(void)
{
	static const char prog[] = "provider up { probe p(int); };\n"
	    "BEGIN { trace(1); }\n";
	dtrace_hdl_t *dtp = vopen();
	dt_provider_t *pvp;
	dt_probe_t *prp;
	dt_probe_instance_t *pip;
	uint_t i;
	int ok = 1;

	(void) dtrace_program_strcompile(dtp, prog, DTRACE_PROBESPEC_NAME, 0, 0,
	    NULL);
	pvp = dt_provider_lookup(dtp, "up");
	prp = pvp ? dt_probe_lookup(pvp, "p") : NULL;
	check(prp != NULL, "USDT provider declared");
	if (prp == NULL) {
		dtrace_close(dtp);
		return;
	}
	for (i = 0; i < 9; i++)
		ok &= dt_probe_define(pvp, prp, "fn", "obj", 0x10 * i, i % 3 == 0) == 0;
	ok &= dt_probe_define(pvp, prp, "fn2", "obj", 0x99, 0) == 0;
	ok &= dt_probe_define(pvp, prp, "fn", "obj2", 0x77, 0) == 0;
	check(ok, "probe sites defined");
	for (pip = prp->pr_inst; pip != NULL; pip = pip->pi_next) {
		if (strcmp(pip->pi_fname, "fn") == 0 &&
		    strcmp(pip->pi_rname, "obj") == 0) {
			check(pip->pi_noffs == 6 && pip->pi_nenoffs == 3 &&
			    pip->pi_offs[0] == 0x10 && pip->pi_offs[5] == 0x80 &&
			    pip->pi_enoffs[0] == 0 && pip->pi_enoffs[2] == 0x60,
			    "fn/obj sites in order (%u, %u)", pip->pi_noffs,
			    pip->pi_nenoffs);
		} else
			check(pip->pi_noffs == 1 && pip->pi_nenoffs == 0,
			    "%s/%s single site", pip->pi_fname, pip->pi_rname);
	}
	dtrace_close(dtp);
}

#ifdef WITH_FAULTS
static void
fault_sweep(void)
{
	long n;
	int done, e;

	for (n = 1, done = 0; !done && n < 5000; n++) {	/* discovery */
		dtrace_hdl_t *dtp = vopen();
		dtrace_probeinfo_t pi;

		arm(n);
		e = info(dtp, "kp:kmod:beta:entry", DTRACE_IDNONE, &pi);
		arm(0);
		if (!fault_hit) {
			check(e == 0, "discovery unfaulted");
			done = 1;
		} else
			check(e != 0 || pi.dtp_argc == 3,
			    "discovery fault %ld (e=%d)", n, e);
		dtrace_close(dtp);
	}
	for (n = 1, done = 0; !done && n < 50000; n++) {	/* compiles */
		dtrace_hdl_t *dtp = vopen();
		int r1, r2;

		(void) dtrace_setopt(dtp, "late", "dynamic");
		arm(n);
		r1 = dtrace_program_strcompile(dtp,
		    "struct xin { int a; }; struct xout { int b; };\n"
		    "translator struct xout < struct xin *p > { b = p->a; };\n"
		    "provider fp { probe t(struct xin *p) : (struct xout *p); };\n"
		    "BEGIN { }", DTRACE_PROBESPEC_NAME, 0, 0, NULL) == NULL;
		r2 = dtrace_program_strcompile(dtp,
		    "kp:kmod:beta:entry { trace(args[2]); }",
		    DTRACE_PROBESPEC_NAME, 0, 0, NULL) == NULL;
		arm(0);
		if (!fault_hit) {
			check(r1 == 0 && r2 == 1, "compiles unfaulted");
			done = 1;
		}
		dtrace_close(dtp);
	}
	for (n = 1, done = 0; !done && n < 100; n++) {	/* probe sites */
		dtrace_hdl_t *dtp = vopen();
		dt_provider_t *pvp;
		dt_probe_t *prp;

		(void) dtrace_program_strcompile(dtp,
		    "provider up { probe p(int); }; BEGIN { trace(1); }",
		    DTRACE_PROBESPEC_NAME, 0, 0, NULL);
		pvp = dt_provider_lookup(dtp, "up");
		prp = pvp ? dt_probe_lookup(pvp, "p") : NULL;
		if (prp == NULL) {
			check(0, "USDT provider for fault sweep");
			dtrace_close(dtp);
			break;
		}
		(void) dt_probe_define(pvp, prp, "fn", "obj", 1, 0);
		arm(n);
		e = dt_probe_define(pvp, prp, "fn", "obj", 2, 0);
		if (e == 0)
			e = dt_probe_define(pvp, prp, "g", "obj", 3, 1);
		arm(0);
		if (!fault_hit) {
			check(e == 0, "define unfaulted");
			done = 1;
		} else
			check(e == -1 && dtrace_errno(dtp) == EDT_NOMEM,
			    "define fault %ld", n);
		dtrace_close(dtp);
	}
}
#endif

int
main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	bind_shim();
	test_info();
	test_iter();
	test_declared();
	test_probe_tag();
	test_kinst();
	test_define();
#ifdef WITH_FAULTS
	fault_sweep();
#endif
	exit(summary());
}
