/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Option handling in dt_options.c, checked against the documented option
 * semantics (dtrace(1) -x options, the Dynamic Tracing Guide "Options and
 * Tunables" chapter) and the option tables' declared meaning:
 *  - size options take an optional k/m/g/t binary suffix;
 *  - rate options take ns/us/ms/s/m/h/d suffixes or hz (period = 1e9/n);
 *  - boolean run-time options accept yes/no style words, "" (unset) or a
 *    non-negative integer;
 *  - compile-time options set the handle state named by the option, and
 *    options that cannot work from a #pragma report EDT_BADOPTCTX there.
 * Kernel options are loaded through a dtrace_vopen() vector whose
 * DTRACEIOC_DOFGET follows sys/cddl/dev/dtrace/dtrace_ioctl.c (copy out
 * MIN(requested, available) bytes of the state's DOF).
 */
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <dt_impl.h>
#include <dt_string.h>
#include <libctf.h>

#include "frontend-faults.h"

#define	CMD(x)	((u_long)(x) & 0xffffffffUL)

/* abort() is reached only from dt_coredump(); finish the child normally. */
static volatile int abort_calls;
void
abort(void)
{
	abort_calls++;
	exit(abort_calls == 1 ? 42 : 43);
}

/*
 * atexit() can be made to fail once (ENOMEM), as libc's does when it cannot
 * allocate a new handler block; otherwise registration is passed to libc.
 */
extern int __cxa_atexit(void (*)(void *), void *, void *);
static volatile int atexit_fail;

int
atexit(void (*fn)(void))
{
	if (atexit_fail) {
		atexit_fail = 0;
		errno = ENOMEM;
		return (-1);
	}
	return (__cxa_atexit((void (*)(void *))(void *)fn, NULL, NULL));
}

/* ---- vector model -------------------------------------------------- */

enum { DOF_GOOD, DOF_NOOPT, DOF_ZEROSEC, DOF_SHORT, DOF_FAIL1, DOF_FAIL2,
    DOF_BADENT, DOF_OOB, DOF_SECOOB, DOF_SECSIZE, DOF_SECOFF, DOF_OPTOFF,
    DOF_PARTIAL };
static int dof_mode, dof_calls;

static int
model_ioctl(void *arg, u_long cmd, void *data)
{
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
	if (cmd == CMD(DTRACEIOC_DOFGET)) {
		dof_hdr_t **pdof = data, *dof;
		size_t len = sizeof (dof_hdr_t) + 2 * sizeof (dof_sec_t) +
		    4 * sizeof (dof_optdesc_t);
		dof_sec_t *sec;
		dof_optdesc_t *o;

		dof_calls++;
		if ((dof_mode == DOF_FAIL1 && dof_calls == 1) ||
		    (dof_mode == DOF_FAIL2 && dof_calls == 2))
			return (errno = EIO, -1);
		dof = __builtin_alloca(len);
		memset(dof, 0, len);
		memcpy(dof->dofh_ident, "\177DOF", 4);
		dof->dofh_hdrsize = sizeof (dof_hdr_t);
		dof->dofh_secsize = sizeof (dof_sec_t);
		dof->dofh_secnum = 2;
		dof->dofh_secoff = sizeof (dof_hdr_t);
		dof->dofh_loadsz = dof->dofh_filesz = len;
		sec = (dof_sec_t *)(dof + 1);
		/* Section 0: a string table holding bytes that look like an
		 * option record setting option 1 (bufsize) to 777. */
		sec[0].dofs_type = DOF_SECT_STRTAB;
		sec[0].dofs_entsize = sizeof (dof_optdesc_t);
		sec[0].dofs_offset = sizeof (dof_hdr_t) + 2 * sizeof (dof_sec_t);
		sec[0].dofs_size = sizeof (dof_optdesc_t);
		o = (dof_optdesc_t *)((char *)dof + sec[0].dofs_offset);
		o[0].dofo_option = DTRACEOPT_BUFSIZE;
		o[0].dofo_strtab = DOF_SECIDX_NONE;
		o[0].dofo_value = 777;
		/* Section 1: the option descriptions. */
		sec[1].dofs_type = DOF_SECT_OPTDESC;
		sec[1].dofs_entsize = sizeof (dof_optdesc_t);
		sec[1].dofs_offset = sec[0].dofs_offset + sizeof (dof_optdesc_t);
		sec[1].dofs_size = 3 * sizeof (dof_optdesc_t);
		o[1].dofo_option = DTRACEOPT_NSPEC;	/* loaded */
		o[1].dofo_strtab = DOF_SECIDX_NONE;
		o[1].dofo_value = 9;
		o[2].dofo_option = DTRACEOPT_SPECSIZE;	/* string valued: skip */
		o[2].dofo_strtab = 0;
		o[2].dofo_value = 123;
		o[3].dofo_option = DTRACEOPT_MAX + 5;	/* unknown: skip */
		o[3].dofo_strtab = DOF_SECIDX_NONE;
		o[3].dofo_value = 5;
		switch (dof_mode) {
		case DOF_NOOPT:
			sec[1].dofs_type = DOF_SECT_COMMENTS;
			break;
		case DOF_ZEROSEC:
			dof->dofh_secnum = 0;
			break;
		case DOF_SHORT:
			dof->dofh_loadsz = sizeof (dof_hdr_t) - 1;
			break;
		case DOF_BADENT:
			sec[1].dofs_entsize = 0;
			break;
		case DOF_OOB:
			sec[1].dofs_size = 1 << 20;
			break;
		case DOF_SECOOB:
			dof->dofh_secnum = 1000;
			break;
		case DOF_SECSIZE:
			dof->dofh_secsize = 0;
			break;
		case DOF_SECOFF:
			dof->dofh_secoff = 1 << 30;
			break;
		case DOF_OPTOFF:
			sec[1].dofs_offset = 1ULL << 40;
			break;
		case DOF_PARTIAL:	/* a trailing partial record is ignored */
			sec[1].dofs_size = 3 * sizeof (dof_optdesc_t) - 4;
			break;
		}
		memcpy(*pdof, dof, MIN((*pdof)->dofh_loadsz, len));
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

/* ---- helpers -------------------------------------------------------- */

static dtrace_hdl_t *
hopen(void)
{
	int err;
	dtrace_hdl_t *dtp = dtrace_open(DTRACE_VERSION,
	    DTRACE_O_NODEV | DTRACE_O_NOSYS, &err);

	if (dtp == NULL) {
		printf("FAIL dtrace_open: %s\n", dtrace_errmsg(NULL, err));
		exit(2);
	}
	(void) dtrace_setopt(dtp, "nolibs", NULL);
	return (dtp);
}

static int
setopt_err(dtrace_hdl_t *dtp, const char *opt, const char *val)
{
	return (dtrace_setopt(dtp, opt, val) == 0 ? 0 : dtrace_errno(dtp));
}

static dtrace_optval_t
getopt_val(dtrace_hdl_t *dtp, const char *opt)
{
	dtrace_optval_t v = -12345;

	if (dtrace_getopt(dtp, opt, &v) != 0)
		return (-12345);
	return (v);
}

/* ---- run-time value parsing ----------------------------------------- */

static void
test_values(void)
{
	static const struct { const char *opt, *val; dtrace_optval_t want; } ok[] = {
		{ "bufsize", "10", 10 }, { "bufsize", "4k", 4096 },
		{ "bufsize", "4K", 4096 }, { "bufsize", "2m", 2 << 20 },
		{ "bufsize", "2M", 2 << 20 }, { "bufsize", "1g", 1LL << 30 },
		{ "bufsize", "1G", 1LL << 30 }, { "bufsize", "3t", 3LL << 40 },
		{ "bufsize", "3T", 3LL << 40 }, { "bufsize", "0x10k", 16384 },
		{ "bufsize", NULL, 0 }, { "aggsize", "8k", 8192 },
		{ "dynvarsize", "1m", 1 << 20 }, { "specsize", "512", 512 },
		{ "jstackstrsize", "1k", 1024 },
		{ "switchrate", "10hz", 100000000 }, { "switchrate", "0hz", 0 },
		{ "switchrate", "5ms", 5000000 }, { "switchrate", "5msec", 5000000 },
		{ "switchrate", "7ns", 7 }, { "switchrate", "7nsec", 7 },
		{ "switchrate", "3us", 3000 }, { "switchrate", "3usec", 3000 },
		{ "switchrate", "2s", 2000000000 }, { "switchrate", "2sec", 2000000000 },
		{ "switchrate", "1m", 60000000000LL }, { "switchrate", "1min", 60000000000LL },
		{ "switchrate", "1h", 3600000000000LL }, { "switchrate", "1HOUR", 3600000000000LL },
		{ "switchrate", "1d", 86400000000000LL }, { "switchrate", "1day", 86400000000000LL },
		{ "switchrate", "42", 42 }, { "switchrate", NULL, 0 },
		{ "cleanrate", "100hz", 10000000 }, { "statusrate", "1s", 1000000000 },
		{ "aggrate", "2hz", 500000000 },
		{ "quiet", NULL, 0 }, { "quiet", "yes", 1 }, { "quiet", "no", DTRACEOPT_UNSET },
		{ "quiet", "ENABLE", 1 }, { "quiet", "disable", DTRACEOPT_UNSET },
		{ "quiet", "enabled", 1 }, { "quiet", "Disabled", DTRACEOPT_UNSET },
		{ "quiet", "true", 1 }, { "quiet", "false", DTRACEOPT_UNSET },
		{ "quiet", "on", 1 }, { "quiet", "off", DTRACEOPT_UNSET },
		{ "quiet", "set", 1 }, { "quiet", "unset", DTRACEOPT_UNSET },
		{ "quiet", "", DTRACEOPT_UNSET }, { "quiet", "17", 17 },
		{ "quiet", "0x20", 32 }, { "nspec", "4", 4 }, { "cpu", "0", 0 },
		{ "bufpolicy", "ring", DTRACEOPT_BUFPOLICY_RING },
		{ "bufpolicy", "fill", DTRACEOPT_BUFPOLICY_FILL },
		{ "bufpolicy", "switch", DTRACEOPT_BUFPOLICY_SWITCH },
		{ "bufresize", "auto", DTRACEOPT_BUFRESIZE_AUTO },
		{ "bufresize", "manual", DTRACEOPT_BUFRESIZE_MANUAL },
		{ "strsize", "128", 128 }, { "strsize", "1k", 1024 },
	};
	static const struct { const char *opt, *val; int err; } bad[] = {
		{ "bufsize", "", EDT_BADOPTVAL }, { "bufsize", "k", EDT_BADOPTVAL },
		{ "bufsize", "4kk", EDT_BADOPTVAL }, { "bufsize", "1x", EDT_BADOPTVAL },
		{ "bufsize", "-1", EDT_BADOPTVAL }, { "bufsize", "-1k", EDT_BADOPTVAL },
		{ "bufsize", "9223372036854775807k", EDT_BADOPTVAL },
		{ "bufsize", "99999999999999999999", EDT_BADOPTVAL },
		{ "switchrate", "abc", EDT_BADOPTVAL }, { "switchrate", "-5", EDT_BADOPTVAL },
		{ "switchrate", "5zz", EDT_BADOPTVAL },
		{ "switchrate", "99999999999999999999", EDT_BADOPTVAL },
		{ "switchrate", "9223372036854775807d", EDT_BADOPTVAL },
		{ "quiet", "maybe", EDT_BADOPTVAL }, { "quiet", "-1", EDT_BADOPTVAL },
		{ "quiet", "12x", EDT_BADOPTVAL },
		{ "quiet", "99999999999999999999", EDT_BADOPTVAL },
		{ "bufpolicy", NULL, EDT_BADOPTVAL }, { "bufpolicy", "wrap", EDT_BADOPTVAL },
		{ "bufresize", NULL, EDT_BADOPTVAL }, { "bufresize", "never", EDT_BADOPTVAL },
		{ "strsize", "bad", EDT_BADOPTVAL }, { "strsize", "8g", EOVERFLOW },
		{ "oformat", NULL, EDT_BADOPTVAL },
		{ "oformat", "no-such-xo-flag-97", EDT_BADOPTVAL },
		{ "no-such-option-97", "1", EDT_BADOPTNAME },
		{ "no-such-option-97", NULL, EDT_BADOPTNAME },
	};
	dtrace_hdl_t *dtp = hopen();
	dtrace_typeinfo_t dtt;
	dtrace_optval_t v;
	size_t i;
	int e;

	for (i = 0; i < sizeof (ok) / sizeof (ok[0]); i++) {
		e = setopt_err(dtp, ok[i].opt, ok[i].val);
		v = getopt_val(dtp, ok[i].opt);
		check(e == 0 && v == ok[i].want, "%s=%s: err %d value %jd want %jd",
		    ok[i].opt, ok[i].val ? ok[i].val : "(null)", e, (intmax_t)v,
		    (intmax_t)ok[i].want);
	}
	for (i = 0; i < sizeof (bad) / sizeof (bad[0]); i++) {
		dtrace_optval_t before = getopt_val(dtp, bad[i].opt);

		e = setopt_err(dtp, bad[i].opt, bad[i].val);
		check(e == bad[i].err && getopt_val(dtp, bad[i].opt) == before,
		    "%s=%s rejected with %d (got %d), value unchanged", bad[i].opt,
		    bad[i].val ? bad[i].val : "(null)", bad[i].err, e);
	}
	/* strsize redefines the D string type to char[strsize]. */
	check(setopt_err(dtp, "strsize", "300") == 0 &&
	    dtrace_type_strcompile(dtp, "string", &dtt) == 0 &&
	    ctf_type_size(dtt.dtt_ctfp, dtt.dtt_type) == 300,
	    "strsize resizes the string type");
	/* Compile-time options and unknown names cannot be read back. */
	check(dtrace_getopt(dtp, "cpp", &v) == -1 &&
	    dtrace_errno(dtp) == EDT_BADOPTNAME, "getopt of compile option");
	check(dtrace_getopt(dtp, NULL, &v) == -1 && dtrace_errno(dtp) == EINVAL,
	    "getopt NULL");
	check(dtrace_setopt(dtp, NULL, "1") == -1 && dtrace_errno(dtp) == EINVAL,
	    "setopt NULL");
	dtrace_close(dtp);
	/* oformat changes libxo's process-global state: use a child. */
	{
		pid_t pid;
		int status;

		if ((pid = fork()) == 0) {
			dtp = hopen();
			exit(setopt_err(dtp, "oformat", "json") == 0 ? 0 : 5);
		}
		check(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
		    WEXITSTATUS(status) == 0, "oformat json");
	}
}

/* ---- compile-time options ------------------------------------------- */

static int
cpp_has(dtrace_hdl_t *dtp, const char *arg)
{
	int i;

	for (i = 0; i < dtp->dt_cpp_argc; i++)
		if (strcmp(dtp->dt_cpp_argv[i], arg) == 0)
			return (1);
	return (0);
}

static int
env_has(dtrace_hdl_t *dtp, const char *var)
{
	char **p;

	for (p = dtp->dt_proc_env; *p != NULL; p++)
		if (strcmp(*p, var) == 0)
			return (1);
	return (0);
}

static int
env_count(dtrace_hdl_t *dtp)
{
	char **p;
	int n = 0;

	for (p = dtp->dt_proc_env; *p != NULL; p++)
		n++;
	return (n);
}

static void
test_compile_options(const char *dir)
{
	static const struct { const char *opt; uint_t flag; } cflags[] = {
		{ "argref", DTRACE_C_ARGREF }, { "cpp", DTRACE_C_CPP },
		{ "defaultargs", DTRACE_C_DEFARG }, { "empty", DTRACE_C_EMPTY },
		{ "errtags", DTRACE_C_ETAGS }, { "knodefs", DTRACE_C_KNODEF },
		{ "nolibs", DTRACE_C_NOLIBS }, { "pspec", DTRACE_C_PSPEC },
		{ "unodefs", DTRACE_C_UNODEF }, { "verbose", DTRACE_C_DIFV },
		{ "zdefs", DTRACE_C_ZDEFS },
	};
	static const struct { const char *opt, *val; int err; } bad[] = {
		{ "aggpercpu", "1", EDT_BADOPTVAL }, { "amin", NULL, EDT_BADOPTVAL },
		{ "amin", "Bogus/Bogus/Bogus", EDT_BADOPTVAL },
		{ "core", "1", EDT_BADOPTVAL }, { "cpphdrs", "1", EDT_BADOPTVAL },
		{ "cpppath", NULL, EDT_BADOPTVAL }, { "ctypes", NULL, EDT_BADOPTVAL },
		{ "dtypes", NULL, EDT_BADOPTVAL }, { "debug", "1", EDT_BADOPTVAL },
		{ "define", NULL, EDT_BADOPTVAL }, { "incdir", NULL, EDT_BADOPTVAL },
		{ "undef", NULL, EDT_BADOPTVAL }, { "encoding", NULL, EDT_BADOPTVAL },
		{ "encoding", "ebcdic", EDT_BADOPTVAL },
		{ "evaltime", NULL, EDT_BADOPTVAL }, { "evaltime", "never", EDT_BADOPTVAL },
		{ "iregs", NULL, EDT_BADOPTVAL }, { "iregs", "0", EDT_BADOPTVAL },
		{ "tregs", NULL, EDT_BADOPTVAL }, { "tregs", "-3", EDT_BADOPTVAL },
		{ "tree", NULL, EDT_BADOPTVAL }, { "tree", "0", EDT_BADOPTVAL },
		{ "pgmax", NULL, EDT_BADOPTVAL }, { "pgmax", "-1", EDT_BADOPTVAL },
		{ "late", NULL, EDT_BADOPTVAL }, { "late", "sometimes", EDT_BADOPTVAL },
		{ "ldpath", NULL, EDT_BADOPTVAL }, { "objcopypath", NULL, EDT_BADOPTVAL },
		{ "libdir", NULL, EDT_BADOPTVAL }, { "syslibdir", NULL, EDT_BADOPTVAL },
		{ "linkmode", NULL, EDT_BADOPTVAL }, { "linkmode", "lazy", EDT_BADOPTVAL },
		{ "linktype", NULL, EDT_BADOPTVAL }, { "linktype", "coff", EDT_BADOPTVAL },
		{ "stdc", NULL, EDT_BADOPTVAL }, { "stdc", "k", EDT_BADOPTVAL },
		{ "strip", "1", EDT_BADOPTVAL }, { "kdefs", "1", EDT_BADOPTVAL },
		{ "udefs", "1", EDT_BADOPTVAL }, { "zdefs", "1", EDT_BADOPTVAL },
		{ "version", NULL, EDT_BADOPTVAL }, { "version", "x.y", EDT_VERSINVAL },
		{ "version", "99.99", EDT_VERSUNDEF },
		{ "setenv", NULL, EDT_BADOPTVAL }, { "unsetenv", NULL, EDT_BADOPTVAL },
		{ "unsetenv", "A=B", EDT_BADOPTVAL },
	};
	char path[PATH_MAX];
	dtrace_hdl_t *dtp = hopen();
	size_t i;
	int n;

	for (i = 0; i < sizeof (cflags) / sizeof (cflags[0]); i++) {
		dtp->dt_cflags &= ~cflags[i].flag;
		check(setopt_err(dtp, cflags[i].opt, NULL) == 0 &&
		    (dtp->dt_cflags & cflags[i].flag), "cflag %s", cflags[i].opt);
		check(setopt_err(dtp, cflags[i].opt, "x") == EDT_BADOPTVAL,
		    "cflag %s rejects a value", cflags[i].opt);
	}
	check(setopt_err(dtp, "kdefs", NULL) == 0 &&
	    !(dtp->dt_cflags & DTRACE_C_KNODEF), "kdefs clears knodefs");
	check(setopt_err(dtp, "udefs", NULL) == 0 &&
	    !(dtp->dt_cflags & DTRACE_C_UNODEF), "udefs clears unodefs");
	check(setopt_err(dtp, "strip", NULL) == 0 &&
	    (dtp->dt_dflags & DTRACE_D_STRIP), "strip");
	check(setopt_err(dtp, "aggpercpu", NULL) == 0 &&
	    (dtp->dt_aggregate.dtat_flags & DTRACE_A_PERCPU), "aggpercpu");
	check(setopt_err(dtp, "amin", "Stable/Stable/Common") == 0 &&
	    (dtp->dt_cflags & DTRACE_C_EATTR) &&
	    dtp->dt_amin.dtat_name == DTRACE_STABILITY_STABLE &&
	    dtp->dt_amin.dtat_class == DTRACE_CLASS_COMMON, "amin");
	n = dtp->dt_cpp_argc;
	check(setopt_err(dtp, "cpphdrs", NULL) == 0 && cpp_has(dtp, "-H") &&
	    dtp->dt_cpp_argc == n + 1, "cpphdrs adds -H");
	check(setopt_err(dtp, "define", "FOO=1") == 0 && cpp_has(dtp, "-DFOO=1"),
	    "define");
	check(setopt_err(dtp, "incdir", "/inc") == 0 && cpp_has(dtp, "-I/inc"),
	    "incdir");
	check(setopt_err(dtp, "undef", "BAR") == 0 && cpp_has(dtp, "-UBAR"),
	    "undef");
	check(setopt_err(dtp, "cpppath", "/opt/bin/mycpp") == 0 &&
	    strcmp(dtp->dt_cpp_path, "/opt/bin/mycpp") == 0 &&
	    strcmp(dtp->dt_cpp_argv[0], "mycpp") == 0, "cpppath");
	check(setopt_err(dtp, "ldpath", "/opt/bin/ld") == 0 &&
	    strcmp(dtp->dt_ld_path, "/opt/bin/ld") == 0, "ldpath");
	check(setopt_err(dtp, "objcopypath", "/opt/bin/oc") == 0 &&
	    strcmp(dtp->dt_objcopy_path, "/opt/bin/oc") == 0, "objcopypath");
	check(setopt_err(dtp, "encoding", "ascii") == 0 &&
	    dtp->dt_encoding == DT_ENCODING_ASCII, "encoding ascii");
	check(setopt_err(dtp, "encoding", "utf8") == 0 &&
	    dtp->dt_encoding == DT_ENCODING_UTF8, "encoding utf8");
	check(setopt_err(dtp, "evaltime", "exec") == 0 &&
	    dtp->dt_prcmode == DT_PROC_STOP_CREATE, "evaltime exec");
	check(setopt_err(dtp, "evaltime", "preinit") == 0 &&
	    dtp->dt_prcmode == DT_PROC_STOP_PREINIT, "evaltime preinit");
	check(setopt_err(dtp, "evaltime", "postinit") == 0 &&
	    dtp->dt_prcmode == DT_PROC_STOP_POSTINIT, "evaltime postinit");
	check(setopt_err(dtp, "evaltime", "main") == 0 &&
	    dtp->dt_prcmode == DT_PROC_STOP_MAIN, "evaltime main");
	check(setopt_err(dtp, "iregs", "12") == 0 &&
	    dtp->dt_conf.dtc_difintregs == 12, "iregs");
	check(setopt_err(dtp, "tregs", "6") == 0 &&
	    dtp->dt_conf.dtc_diftupregs == 6, "tregs");
	check(setopt_err(dtp, "tree", "4") == 0 && dtp->dt_treedump == 4, "tree");
	dtp->dt_treedump = 0;
	check(setopt_err(dtp, "pgmax", "3") == 0 &&
	    dtp->dt_procs->dph_lrulim == 3, "pgmax");
	check(setopt_err(dtp, "late", "dynamic") == 0 &&
	    dtp->dt_xlatemode == DT_XL_DYNAMIC, "late dynamic");
	check(setopt_err(dtp, "late", "static") == 0 &&
	    dtp->dt_xlatemode == DT_XL_STATIC, "late static");
	check(setopt_err(dtp, "lazyload", NULL) == 0 && dtp->dt_lazyload,
	    "lazyload");
	check(setopt_err(dtp, "droptags", NULL) == 0 && dtp->dt_droptags,
	    "droptags");
	check(setopt_err(dtp, "linkmode", "kernel") == 0 &&
	    dtp->dt_linkmode == DT_LINK_KERNEL, "linkmode kernel");
	check(setopt_err(dtp, "linkmode", "primary") == 0 &&
	    dtp->dt_linkmode == DT_LINK_PRIMARY, "linkmode primary");
	check(setopt_err(dtp, "linkmode", "dynamic") == 0 &&
	    dtp->dt_linkmode == DT_LINK_DYNAMIC, "linkmode dynamic");
	check(setopt_err(dtp, "linkmode", "static") == 0 &&
	    dtp->dt_linkmode == DT_LINK_STATIC, "linkmode static");
	check(setopt_err(dtp, "linktype", "ELF") == 0 &&
	    dtp->dt_linktype == DT_LTYP_ELF, "linktype elf");
	check(setopt_err(dtp, "linktype", "dof") == 0 &&
	    dtp->dt_linktype == DT_LTYP_DOF, "linktype dof");
	check(setopt_err(dtp, "stdc", "a") == 0 &&
	    dtp->dt_stdcmode == DT_STDC_XA, "stdc a");
	check(setopt_err(dtp, "stdc", "c") == 0 &&
	    dtp->dt_stdcmode == DT_STDC_XC, "stdc c");
	check(setopt_err(dtp, "stdc", "s") == 0 &&
	    dtp->dt_stdcmode == DT_STDC_XS, "stdc s");
	check(setopt_err(dtp, "stdc", "t") == 0 &&
	    dtp->dt_stdcmode == DT_STDC_XT, "stdc t");
	check(setopt_err(dtp, "libdir", "/extra/lib") == 0 &&
	    strcmp(((dt_dirpath_t *)dt_list_prev(&dtp->dt_lib_path))->dir_path,
	    "/extra/lib") == 0, "libdir appends");
	check(setopt_err(dtp, "syslibdir", "/sys/lib") == 0 &&
	    strcmp(((dt_dirpath_t *)dt_list_next(&dtp->dt_lib_path))->dir_path,
	    "/sys/lib") == 0, "syslibdir replaces the first entry");
	check(setopt_err(dtp, "version", "1.0") == 0, "version 1.0");
	/* setenv/unsetenv maintain the child environment list. */
	n = env_count(dtp);
	check(setopt_err(dtp, "setenv", "FOO=1") == 0 && env_has(dtp, "FOO=1") &&
	    env_count(dtp) == n + 1, "setenv adds");
	check(setopt_err(dtp, "setenv", "FOO=2") == 0 && env_has(dtp, "FOO=2") &&
	    !env_has(dtp, "FOO=1") && env_count(dtp) == n + 1, "setenv replaces");
	check(setopt_err(dtp, "setenv", "NOVALUE") == 0 &&
	    env_has(dtp, "NOVALUE") && env_count(dtp) == n + 2,
	    "setenv bare name");
	check(setopt_err(dtp, "setenv", "NOVALUE") == 0 &&
	    env_count(dtp) == n + 2, "setenv bare name again replaces");
	check(setopt_err(dtp, "unsetenv", "FOO") == 0 && !env_has(dtp, "FOO=2") &&
	    env_count(dtp) == n + 1, "unsetenv removes");
	/* Variables are matched by whole name, not by prefix (regression). */
	check(setopt_err(dtp, "setenv", "FOO=1") == 0 &&
	    setopt_err(dtp, "setenv", "FOOBAR=2") == 0 && env_has(dtp, "FOO=1") &&
	    env_has(dtp, "FOOBAR=2"), "setenv FOOBAR keeps FOO");
	check(setopt_err(dtp, "unsetenv", "FO") == 0 && env_has(dtp, "FOO=1") &&
	    env_has(dtp, "FOOBAR=2"), "unsetenv FO keeps FOO and FOOBAR");
	check(setopt_err(dtp, "unsetenv", "FOOBAR") == 0 && env_has(dtp, "FOO=1") &&
	    !env_has(dtp, "FOOBAR=2"), "unsetenv FOOBAR keeps FOO");
	check(setopt_err(dtp, "unsetenv", "FOO") == 0 && !env_has(dtp, "FOO=1") &&
	    env_count(dtp) == n + 1, "unsetenv FOO");
	for (i = 0; i < sizeof (bad) / sizeof (bad[0]); i++)
		check(setopt_err(dtp, bad[i].opt, bad[i].val) == bad[i].err,
		    "compile option %s=%s -> %d (got %d)", bad[i].opt,
		    bad[i].val ? bad[i].val : "(null)", bad[i].err,
		    setopt_err(dtp, bad[i].opt, bad[i].val));
	/* ctypes/dtypes: the C and D containers are written after compiles
	 * and must be valid CTF holding int (C) and string (D). */
	(void) snprintf(path, sizeof (path), "%s/c.ctf", dir);
	check(setopt_err(dtp, "ctypes", path) == 0, "ctypes");
	check(setopt_err(dtp, "ctypes", path) == 0, "ctypes reopen");
	(void) snprintf(path, sizeof (path), "%s/d.ctf", dir);
	check(setopt_err(dtp, "dtypes", path) == 0, "dtypes");
	check(setopt_err(dtp, "dtypes", path) == 0, "dtypes reopen");
	check(setopt_err(dtp, "ctypes", "/nonexistent-dir-97/x") == ENOENT,
	    "ctypes into missing directory");
	check(setopt_err(dtp, "dtypes", "/nonexistent-dir-97/x") == ENOENT,
	    "dtypes into missing directory");
	/* NODEV handles permit zero-match descriptions (dt_vopen sets
	 * DTRACE_C_ZDEFS) since no provider can be queried. */
	dtp->dt_cflags &= ~(DTRACE_C_CPP | DTRACE_C_DIFV | DTRACE_C_PSPEC |
	    DTRACE_C_ARGREF | DTRACE_C_DEFARG | DTRACE_C_EATTR);
	check(dtrace_program_strcompile(dtp, "BEGIN { trace(1); }",
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL) != NULL,
	    "compile with ctypes: %s (cflags %#x)",
	    dtrace_errmsg(dtp, dtrace_errno(dtp)), dtp->dt_cflags);
	dtrace_close(dtp);
	{
		int err, fd;
		ctf_file_t *fp;
		static const char *const want[2][2] = {
			{ "c.ctf", "int" }, { "d.ctf", "string" } };

		for (i = 0; i < 2; i++) {
			(void) snprintf(path, sizeof (path), "%s/%s", dir,
			    want[i][0]);
			fd = open(path, O_RDONLY);
			fp = fd >= 0 ? ctf_fdopen(fd, &err) : NULL;
			check(fp != NULL && ctf_lookup_by_name(fp, want[i][1]) !=
			    CTF_ERR, "%s is CTF holding %s", want[i][0],
			    want[i][1]);
			if (fp != NULL)
				ctf_close(fp);
			if (fd >= 0)
				close(fd);
		}
	}
}

/* Options set from #pragma D option run with a compiler context. */
static void
test_pragma_context(void)
{
	static const struct { const char *pragma; int err; } ctx[] = {
		{ "cpphdrs", EDT_BADOPTCTX }, { "cpppath=/bin/cpp", EDT_BADOPTCTX },
		{ "define=X", EDT_BADOPTCTX }, { "ldpath=/bin/ld", EDT_BADOPTCTX },
		{ "objcopypath=/bin/oc", EDT_BADOPTCTX },
		{ "setenv=A=1", EDT_BADOPTCTX }, { "stdc=a", EDT_BADOPTCTX },
	};
	char prog[256];
	const char *msg;
	dtrace_hdl_t *dtp;
	size_t i;

	for (i = 0; i < sizeof (ctx) / sizeof (ctx[0]); i++) {
		dtp = hopen();
		(void) snprintf(prog, sizeof (prog),
		    "#pragma D option %s\nBEGIN { trace(1); }", ctx[i].pragma);
		msg = dtrace_program_strcompile(dtp, prog, DTRACE_PROBESPEC_NAME,
		    0, 0, NULL) == NULL ? dtrace_errmsg(dtp, dtrace_errno(dtp)) :
		    "(compiled)";
		check(strstr(msg, dtrace_errmsg(NULL, ctx[i].err)) != NULL,
		    "pragma %s: %s", ctx[i].pragma, msg);
		dtrace_close(dtp);
	}
	/* Compile flags and attribute floors apply to the current program. */
	dtp = hopen();
	check(dtrace_program_strcompile(dtp,
	    "#pragma D option amin=Private/Private/Unknown\n"
	    "#pragma D option argref\n#pragma D option kdefs\n"
	    "BEGIN { trace(1); }", DTRACE_PROBESPEC_NAME, 0, 0, NULL) != NULL &&
	    !(dtp->dt_cflags & DTRACE_C_ARGREF) &&
	    !(dtp->dt_cflags & DTRACE_C_EATTR),
	    "pragma cflags/amin affect only the compile: %s (cflags %#x)",
	    dtrace_errmsg(dtp, dtrace_errno(dtp)), dtp->dt_cflags);
	/* A raised attribute floor rejects a program below it. */
	check(dtrace_program_strcompile(dtp,
	    "#pragma D option amin=Stable/Stable/Common\n"
	    "BEGIN { trace(curthread); }", DTRACE_PROBESPEC_NAME, 0, 0,
	    NULL) == NULL, "pragma amin rejects lower attributes");
	dtrace_close(dtp);
}

/* debug and core change process-global state: run them in children. */
static void
test_children(void)
{
	pid_t pid;
	int status, pfd[2];
	char buf[512];
	ssize_t n;

	check(pipe(pfd) == 0, "pipe");
	if ((pid = fork()) == 0) {
		dtrace_hdl_t *dtp;

		(void) dup2(pfd[1], STDERR_FILENO);
		dtp = hopen();
		if (dtrace_setopt(dtp, "debug", NULL) != 0)
			exit(3);
		(void) dtrace_program_strcompile(dtp, "BEGIN { trace(1); }",
		    DTRACE_PROBESPEC_NAME, 0, 0, NULL);
		exit(_dtrace_debug == 1 ? 0 : 4);
	}
	close(pfd[1]);
	n = read(pfd[0], buf, sizeof (buf) - 1);
	close(pfd[0]);
	check(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
	    WEXITSTATUS(status) == 0, "debug option child");
	buf[n > 0 ? n : 0] = '\0';
	check(strstr(buf, "libdtrace DEBUG") != NULL,
	    "debug output goes to stderr");

	/* core: an atexit handler that writes a notice and aborts. */
	check(pipe(pfd) == 0, "pipe");
	if ((pid = fork()) == 0) {
		dtrace_hdl_t *dtp;

		(void) dup2(pfd[1], STDERR_FILENO);
		dtp = hopen();
		if (dtrace_setopt(dtp, "core", NULL) != 0 ||
		    dtrace_setopt(dtp, "core", NULL) != 0)
			exit(3);
		dtrace_close(dtp);
		exit(0);
	}
	close(pfd[1]);
	n = read(pfd[0], buf, sizeof (buf) - 1);
	close(pfd[0]);
	buf[n > 0 ? n : 0] = '\0';
	check(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
	    WEXITSTATUS(status) == 42, "core option aborts once at exit (%d)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
	check(strstr(buf, "forcing coredump") != NULL, "core notice: %s", buf);

	/* A failed registration is reported, and a retry registers the
	 * handler (regression: the retry used to report success without
	 * registering anything). */
	if ((pid = fork()) == 0) {
		dtrace_hdl_t *dtp = hopen();

		atexit_fail = 1;
		if (dtrace_setopt(dtp, "core", NULL) != -1 ||
		    dtrace_errno(dtp) != ENOMEM)
			exit(3);
		if (dtrace_setopt(dtp, "core", NULL) != 0)
			exit(4);
		dtrace_close(dtp);
		exit(0);
	}
	check(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
	    WEXITSTATUS(status) == 42, "core retry after atexit failure (%d)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
}

/* HyperTrace mode mirrors options into the ELF option tables. */
static void
test_hypertrace(void)
{
	dtrace_hdl_t *dtp = hopen();

	dtrace_enable_hypertrace(dtp);
	check(dtrace_hypertrace_enabled(dtp) != 0, "hypertrace enabled");
	check(setopt_err(dtp, "quiet", "yes") == 0 &&
	    setopt_err(dtp, "quiet", NULL) == 0 &&
	    setopt_err(dtp, "quiet", "yes") == 0, "hypertrace drt option twice");
	check(setopt_err(dtp, "bufsize", "4k") == 0 &&
	    setopt_err(dtp, "bufsize", NULL) == 0 &&
	    setopt_err(dtp, "bufsize", "8k") == 0 &&
	    getopt_val(dtp, "bufsize") == 8192, "hypertrace rt option twice");
	check(setopt_err(dtp, "zdefs", NULL) == 0 &&
	    setopt_err(dtp, "define", "Z=1") == 0 &&
	    setopt_err(dtp, "define", "Z=2") == 0, "hypertrace ct option twice");
	dtp->dt_active = 1;
	check(setopt_err(dtp, "quiet", "yes") == EDT_ACTIVE,
	    "hypertrace: no options while active");
	dtp->dt_active = 0;
	dtp->dt_hypertrace = 0;
	dtrace_close(dtp);

	dtp = hopen();
	dtp->dt_active = 1;
	check(setopt_err(dtp, "bufsize", "4k") == EDT_ACTIVE,
	    "run-time option refused while active");
	check(setopt_err(dtp, "quiet", "yes") == 0 &&
	    getopt_val(dtp, "quiet") == 1, "dynamic option allowed while active");
	dtp->dt_active = 0;
	dtrace_close(dtp);
}

static void
test_dofget(void)
{
	static const struct { int mode; int ok; int err; } cases[] = {
		{ DOF_GOOD, 1, 0 }, { DOF_FAIL1, 0, EIO }, { DOF_FAIL2, 0, EIO },
		{ DOF_SHORT, 0, EINVAL }, { DOF_NOOPT, 0, EINVAL },
		{ DOF_ZEROSEC, 0, EINVAL }, { DOF_BADENT, 0, EINVAL },
		{ DOF_OOB, 0, EINVAL }, { DOF_SECOOB, 0, EINVAL },
		{ DOF_SECSIZE, 0, EINVAL }, { DOF_SECOFF, 0, EINVAL },
		{ DOF_OPTOFF, 0, EINVAL }, { DOF_PARTIAL, 1, 0 },
	};
	dtrace_hdl_t *dtp;
	size_t i;
	int err, rv;

	for (i = 0; i < sizeof (cases) / sizeof (cases[0]); i++) {
		dtp = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS, &err,
		    &vector, NULL);
		check(dtp != NULL, "vopen");
		if (dtp == NULL)
			return;
		dof_mode = cases[i].mode;
		dof_calls = 0;
		(void) dtrace_setopt(dtp, "bufsize", "4k");
		rv = dtrace_hypertrace_options_update(dtp);
		if (cases[i].ok)
			check(rv == 0 && getopt_val(dtp, "nspec") == 9 &&
			    getopt_val(dtp, "specsize") == DTRACEOPT_UNSET &&
			    getopt_val(dtp, "bufsize") == DTRACEOPT_UNSET,
			    "dof options loaded (only OPTDESC integer records)");
		else
			check(rv == -1 && dtrace_errno(dtp) == cases[i].err &&
			    getopt_val(dtp, "bufsize") != 777,
			    "dof mode %d rejected with %d (got %d)", cases[i].mode,
			    cases[i].err, rv ? dtrace_errno(dtp) : 0);
		dtrace_close(dtp);
	}
}

#ifdef WITH_FAULTS
static void
fault_sweep(void)
{
	static const struct { const char *opt, *val; } ops[] = {
		{ "cpphdrs", NULL }, { "cpppath", "/x/cpp" }, { "define", "A=1" },
		{ "ldpath", "/x/ld" }, { "objcopypath", "/x/oc" },
		{ "libdir", "/x/lib" }, { "syslibdir", "/x/sys" },
		{ "setenv", "A=1" }, { "strsize", "200" },
	};
	size_t i;
	long n;
	int done, e;

	for (i = 0; i < sizeof (ops) / sizeof (ops[0]); i++) {
		for (n = 1, done = 0; !done && n < 200; n++) {
			dtrace_hdl_t *dtp = hopen();

			arm(n);
			e = setopt_err(dtp, ops[i].opt, ops[i].val);
			arm(0);
			if (!fault_hit) {
				check(e == 0, "%s unfaulted", ops[i].opt);
				done = 1;
			} else if (e == 0) {
				/* Some library allocations are optional (for
				 * example libctf's lookup caches); success must
				 * then mean the option took effect. */
				dtrace_typeinfo_t t;

				check(strcmp(ops[i].opt, "strsize") == 0 &&
				    dtrace_type_strcompile(dtp, "string", &t) == 0 &&
				    ctf_type_size(t.dtt_ctfp, t.dtt_type) == 200,
				    "%s fault %ld: success without effect",
				    ops[i].opt, n);
			} else
				check(dtrace_errno(dtp) == EDT_NOMEM ||
				    dtrace_errno(dtp) == EDT_CTF,
				    "%s fault %ld reported as %d", ops[i].opt, n,
				    dtrace_errno(dtp));
			/* The handle stays usable after a failed option. */
			check(setopt_err(dtp, "quiet", "yes") == 0,
			    "%s usable after fault", ops[i].opt);
			dtrace_close(dtp);
		}
	}
	for (n = 1, done = 0; !done && n < 20; n++) {	/* dof buffer */
		dtrace_hdl_t *dtp;
		int err;

		dtp = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS, &err,
		    &vector, NULL);
		dof_mode = DOF_GOOD;
		dof_calls = 0;
		arm(n);
		e = dtrace_hypertrace_options_update(dtp);
		arm(0);
		if (!fault_hit) {
			check(e == 0, "dof load unfaulted");
			done = 1;
		} else
			check(e == -1 && dtrace_errno(dtp) == EDT_NOMEM,
			    "dof load fault %ld", n);
		dtrace_close(dtp);
	}
}
#endif

int
main(int argc, char **argv)
{
	const char *dir = argc > 1 ? argv[1] : ".";

	test_values();
	test_compile_options(dir);
	test_pragma_context();
	test_children();
	test_hypertrace();
	test_dofget();
#ifdef WITH_FAULTS
	fault_sweep();
#endif
	exit(summary());
}
