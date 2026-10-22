/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * pid provider probe placement through the actual libdtrace and libproc.
 *
 * The harness creates the target stopped at exec (dtrace_proc_create), gives
 * the handle a placeholder fasttrap descriptor, and compiles pid probe
 * descriptions with DTRACE_C_ZDEFS.  libdtrace reads the target's text,
 * decides where entry, return and offset probes go, and issues
 * FASTTRAPIOC_MAKEPROBE, which pid-placement-shim.so records instead of a
 * kernel.  Each request is printed as one JSON line; pid-placement.py
 * compares the offsets with LLVM's disassembly of the same functions.
 *
 * The dtrace(4) vector answers only CONF (and reports no probes), so no
 * tracing device is involved; the target never runs past exec.
 */

#include <dt_impl.h>
#include <libproc.h>

#include <sys/dtrace.h>
#include <sys/fasttrap.h>

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

/* ENABLE requests asking for re-evaluation, and malformed NULL ones. */
static int rematch_ok, rematch_null;
/* When set, pid providers exist and every pid probe has id PID_PROBE_ID. */
static int known_pid;
#define	PID_PROBE_ID	4242

static int
vec_ioctl(void *arg, u_long cmd, void *data)
{
	(void)arg;
	cmd &= 0xffffffffUL;
	if (cmd == (DTRACEIOC_ENABLE & 0xffffffffUL) && data == NULL) {
		/* The real ioctl layer fails the copyin of a NULL argument. */
		rematch_null++;
		errno = EFAULT;
		return (-1);
	}
	if (known_pid && cmd == (DTRACEIOC_PROVIDER & 0xffffffffUL) &&
	    strncmp(((dtrace_providerdesc_t *)data)->dtvd_name, "pid", 3) == 0) {
		dtrace_providerdesc_t *pv = data;

		memset(&pv->dtvd_attr, 0, sizeof (pv->dtvd_attr));
		pv->dtvd_priv.dtpp_flags = DTRACE_PRIV_PROC;
		return (0);
	}
	if (known_pid && cmd == (DTRACEIOC_PROBEMATCH & 0xffffffffUL) &&
	    strncmp(((dtrace_probedesc_t *)data)->dtpd_provider, "pid", 3) ==
	    0 && ((dtrace_probedesc_t *)data)->dtpd_id == DTRACE_IDNONE) {
		((dtrace_probedesc_t *)data)->dtpd_id = PID_PROBE_ID;
		return (0);
	}
	if (known_pid && cmd == (DTRACEIOC_PROBEARG & 0xffffffffUL)) {
		/* The kernel knows no argument types for pid probes. */
		((dtrace_argdesc_t *)data)->dtargd_ndx = DTRACE_ARGNONE;
		return (0);
	}
	if (cmd == (DTRACEIOC_CONF & 0xffffffffUL)) {
		dtrace_conf_t *c = data;

		memset(c, 0, sizeof (*c));
		c->dtc_difversion = DIF_VERSION;
		c->dtc_difintregs = DIF_DIR_NREGS;
		c->dtc_diftupregs = DIF_DTR_NREGS;
		c->dtc_ctfmodel = CTF_MODEL_NATIVE;
		return (0);
	}
	if (cmd == (DTRACEIOC_ENABLE & 0xffffffffUL) &&
	    ((dtrace_enable_io_t *)data)->dof == NULL) {
		rematch_ok++;
		return (0);	/* re-evaluate retained enablings */
	}
	errno = (cmd == (DTRACEIOC_PROBEMATCH & 0xffffffffUL) ||
	    cmd == (DTRACEIOC_PROVIDER & 0xffffffffUL)) ? ESRCH : ENOTTY;
	return (-1);
}

static int
vec_lookup(void *arg, GElf_Addr a, GElf_Sym *s, dtrace_syminfo_t *i)
{
	(void)arg; (void)a; (void)s; (void)i;
	return (-1);
}

static int
vec_status(void *arg, processorid_t cpu)
{
	(void)arg;
	return (cpu == 0 ? 1 : -1);
}

static long
vec_sysconf(void *arg, int name)
{
	(void)arg;
	return (sysconf(name));
}

static const dtrace_vector_t vector = {
	.dtv_ioctl = vec_ioctl, .dtv_lookup_by_addr = vec_lookup,
	.dtv_status = vec_status, .dtv_sysconf = vec_sysconf,
};

/* ---------------------------------------------------------------- */
/* Process lifecycle through libdtrace's control thread.            */

static int lc_calls, lc_pid = -1, lc_state = -1, lc_status = -1;
static const char *lc_msg = "unset";

static void
lc_handler(struct ps_prochandle *P, const char *msg, void *arg)
{
	(void)arg;
	lc_calls++;
	lc_pid = proc_getpid(P);
	lc_state = proc_state(P);
	lc_status = proc_getwstat(P);
	lc_msg = msg;
}

static int lc_failures;

static void
lc_check(int ok, const char *what)
{
	printf("%s %s\n", ok ? "PASS" : "FAIL", what);
	lc_failures += !ok;
}

static int
lifecycle(dtrace_hdl_t *dtp, const char *target)
{
	struct ps_prochandle *P;
	char *targv[2] = { (char *)target, NULL };
	int i, pid, child;

	/* A created target that runs to completion is reported once. */
	if (dtrace_handle_proc(dtp, lc_handler, NULL) != 0)
		return (2);
	(void) dtrace_setopt(dtp, "statusrate", "50ms");
	P = dtrace_proc_create(dtp, target, targv, NULL, NULL);
	if (P == NULL)
		return (2);
	pid = proc_getpid(P);
	dtrace_proc_continue(dtp, P);
	/*
	 * With no recent status poll the sleep deadline has already passed;
	 * dtrace_sleep() must still deliver the queued exit notification.
	 */
	for (i = 0; i < 200 && lc_calls == 0; i++) {
		dtrace_sleep(dtp);
		if (lc_calls == 0)
			usleep(20000);
	}
	lc_check(lc_calls == 1 && lc_pid == pid, "exit notification for "
	    "the created target");
	lc_check(lc_state == PS_UNDEAD && lc_msg == NULL,
	    "reported as undead without an error message");
	lc_check(WIFEXITED(lc_status) && WEXITSTATUS(lc_status) == 0,
	    "exit status 0 (target computes no match)");
	dtrace_proc_release(dtp, P);

	/* A grabbed running process is detached, not killed, on release. */
	child = fork();
	if (child == 0) {
		execl("/bin/sleep", "sleep", "30", (char *)NULL);
		_exit(127);
	}
	usleep(200000);
	P = dtrace_proc_grab(dtp, child, 0);
	lc_check(P != NULL && proc_getpid(P) == child, "grab running process");
	if (P != NULL) {
		lc_check(proc_state(P) == PS_STOP, "grabbed process is stopped");
		dtrace_proc_release(dtp, P);
	}
	usleep(100000);
	lc_check(kill(child, 0) == 0 && waitpid(child, NULL, WNOHANG) == 0,
	    "released process still running");
	kill(child, SIGKILL);
	waitpid(child, NULL, 0);

	/* A process that does not exist cannot be grabbed. */
	lc_check(dtrace_proc_grab(dtp, child, 0) == NULL &&
	    dtrace_errno(dtp) != 0, "grab of an exited pid fails");
	return (lc_failures != 0);
}

static const char *const types[] = { "none", "entry", "return", "offsets",
	"post-offsets", "is-enabled" };

/* Capture shim entry points (pid-placement-shim.so). */
static void (*cap_set)(int);
static int (*cap_count)(void);
static const fasttrap_probe_spec_t *(*cap_get)(int);
static void (*cap_reset)(void);
static void (*cap_fail)(int);
static void (*cap_helper)(int);
static int (*cap_helper_opens)(void);
static int (*cap_helper_count)(void);
static const dof_helper_t *(*cap_helper_get)(int);
static void (*cap_getinstr)(int);
static int (*cap_getinstr_count)(void);
static uint64_t (*cap_getinstr_pc)(int);

static void
print_requests(void)
{
	int j, n = cap_count();
	uint64_t k;

	printf("\"requests\": [");
	for (j = 0; j < n; j++) {
		const fasttrap_probe_spec_t *f = cap_get(j);

		printf("%s{\"func\": \"%s\", \"type\": \"%s\", \"pid\": %d, "
		    "\"size\": %ju, \"offs\": [", j ? ", " : "", f->ftps_func,
		    (unsigned)f->ftps_type < 6 ? types[f->ftps_type] : "?",
		    (int)f->ftps_pid, (uintmax_t)f->ftps_size);
		for (k = 0; k < f->ftps_noffs; k++)
			printf("%s%ju", k ? ", " : "",
			    (uintmax_t)f->ftps_offs[k]);
		printf("]}");
	}
	printf("]");
}

static void
print_helpers(void)
{
	int j, n = cap_helper_count();

	printf("\"helper_opens\": %d, \"helpers\": [", cap_helper_opens());
	for (j = 0; j < n; j++) {
		const dof_helper_t *h = cap_helper_get(j);

		printf("%s{\"mod\": \"%s\", \"addr\": %ju, \"dof\": %ju, "
		    "\"pid\": %d}", j ? ", " : "", h->dofhp_mod,
		    (uintmax_t)h->dofhp_addr, (uintmax_t)h->dofhp_dof,
		    (int)h->dofhp_pid);
	}
	printf("]");
}

/* Compile one description; print the outcome as one JSON line. */
static dtrace_prog_t *
compile_spec(dtrace_hdl_t *dtp, const char *label, const char *text)
{
	dtrace_prog_t *prog;
	int before_ok = rematch_ok, before_null = rematch_null;
	const char *msg;

	prog = dtrace_program_strcompile(dtp, text, DTRACE_PROBESPEC_NAME,
	    DTRACE_C_ZDEFS, 0, NULL);
	msg = prog != NULL ? "" : dtrace_errmsg(dtp, dtrace_errno(dtp));
	printf("{\"spec\": \"%s\", \"compiled\": %d, \"error\": \"", label,
	    prog != NULL);
	for (; *msg != '\0'; msg++)
		printf(*msg == '"' || *msg == '\\' ? "\\%c" : "%c", *msg);
	printf("\", \"rematch\": %d, \"rematch_null\": %d, ",
	    rematch_ok - before_ok, rematch_null - before_null);
	print_requests();
	printf(", ");
	print_helpers();
	printf(", \"getinstr\": [");
	for (int j = 0; j < cap_getinstr_count(); j++)
		printf("%s%ju", j ? ", " : "", (uintmax_t)cap_getinstr_pc(j));
	printf("]}\n");
	fflush(stdout);
	return (prog);
}

/*
 * Expand a spec: "PID" in a spec beginning with '=' is the target pid and
 * the rest is used verbatim; otherwise the spec is appended to "pid<PID>".
 * A leading "!N" makes the shim refuse MAKEPROBE requests of type N, and a
 * leading '@' makes it answer FASTTRAPIOC_GETINSTR (with a nop).
 */
static const char *
expand_spec(const char *in, int pid, char *out, size_t len)
{
	char pidbuf[16];
	const char *at;

	cap_fail(-1);
	cap_getinstr(0);
	if (in[0] == '@') {
		cap_getinstr(1);
		in++;
	}
	if (in[0] == '!' && in[1] >= '0' && in[1] <= '9') {
		cap_fail(in[1] - '0');
		in += 2;
	}
	if (in[0] != '=') {
		snprintf(out, len, "pid%d%s {}", pid, in);
		return (out);
	}
	in++;
	snprintf(pidbuf, sizeof (pidbuf), "%d", pid);
	if ((at = strstr(in, "PID")) == NULL)
		snprintf(out, len, "%s {}", in);
	else
		snprintf(out, len, "%.*s%s%s {}", (int)(at - in), in, pidbuf,
		    at + 3);
	return (out);
}

static int
wait_exit(dtrace_hdl_t *dtp)
{
	int i;

	for (i = 0; i < 500 && lc_calls == 0; i++) {
		dtrace_sleep(dtp);
		if (lc_calls == 0)
			usleep(20000);
	}
	return (lc_calls);
}

/*
 * USDT registration for a target linked with dtrace -G: each helper mode
 * runs against a fresh process because USDT discovery happens once per
 * process.
 */
static int
usdt(dtrace_hdl_t *dtp, const char *target, const char *provider)
{
	char *targv[2] = { (char *)target, NULL }, spec[256], label[64];
	struct ps_prochandle *P;
	int mode;

	for (mode = 0; mode < 3; mode++) {
		cap_reset();
		cap_helper(mode);
		P = dtrace_proc_create(dtp, target, targv, NULL, NULL);
		if (P == NULL)
			return (2);
		snprintf(spec, sizeof (spec), "%s%d:::go {}", provider,
		    proc_getpid(P));
		snprintf(label, sizeof (label), "usdt-helper-mode-%d", mode);
		printf("{\"usdt_pid\": %d}\n", proc_getpid(P));
		compile_spec(dtp, label, spec);
		/* A second enabling does not register the DOF again. */
		if (mode == 1) {
			cap_reset();
			compile_spec(dtp, "usdt-again", spec);
		}
		dtrace_proc_release(dtp, P);
	}
	return (0);
}

/*
 * A library loaded after the program was compiled: libdtrace must create
 * the pid and USDT probes when the run-time linker reports it.
 */
static int
count_fds(void)
{
	int fd, n = 0;

	for (fd = 0; fd < 1024; fd++)
		n += fcntl(fd, F_GETFD) != -1;
	return (n);
}

static int
late_load(dtrace_hdl_t *dtp, const char *target, const char *library,
    const char *basefile, const char *other, const char *nolib,
    const char *mode)
{
	char *targv[6] = { (char *)target, (char *)library, (char *)basefile,
	    (char *)nolib, (char *)mode, NULL };
	char *otherv[2] = { (char *)other, NULL };
	struct ps_prochandle *P, *Q;
	char spec[256];
	int before, fds;

	if (dtrace_handle_proc(dtp, lc_handler, NULL) != 0)
		return (2);
	(void) dtrace_setopt(dtp, "statusrate", "50ms");
	cap_helper(1);
	fds = count_fds();
	Q = dtrace_proc_create(dtp, other, otherv, NULL, NULL);
	P = dtrace_proc_create(dtp, target, targv, NULL, NULL);
	if (P == NULL || Q == NULL)
		return (2);
	printf("{\"late_pid\": %d, \"other_pid\": %d}\n", proc_getpid(P),
	    proc_getpid(Q));
	snprintf(spec, sizeof (spec), "pid%d:libhtlate.so:ht_late:entry {}",
	    proc_getpid(P));
	compile_spec(dtp, "late-pid-before-load", spec);
	snprintf(spec, sizeof (spec), "htlate%d:::fire {}", proc_getpid(P));
	compile_spec(dtp, "late-usdt-before-load", spec);
	snprintf(spec, sizeof (spec), "pid%d:a.out:ht_leaf:entry {}",
	    proc_getpid(Q));
	compile_spec(dtp, "other-process", spec);
	cap_reset();
	before = rematch_ok;
	dtrace_proc_continue(dtp, P);
	wait_exit(dtp);
	printf("{\"spec\": \"after-load\", \"exited\": %d, \"status\": %d, "
	    "\"rematch\": %d, \"rematch_null\": %d, ", lc_calls,
	    lc_calls ? lc_status : -1, rematch_ok - before, rematch_null);
	print_requests();
	printf(", ");
	print_helpers();
	printf("}\n");
	fflush(stdout);
	dtrace_proc_release(dtp, P);
	dtrace_proc_release(dtp, Q);
	/* Repeated object-list updates must not leak descriptors. */
	printf("{\"fds_before\": %d, \"fds_after\": %d}\n", fds, count_fds());
	return (0);
}

/* Print the argument types libdtrace reports for one pid probe. */
static void
print_types(dtrace_hdl_t *dtp, const char *label, int pid, const char *mod,
    const char *func, const char *name)
{
	dtrace_probedesc_t pd;
	dtrace_probeinfo_t pi;
	char tname[256];
	int i;

	memset(&pd, 0, sizeof (pd));
	snprintf(pd.dtpd_provider, sizeof (pd.dtpd_provider), "pid%d", pid);
	snprintf(pd.dtpd_mod, sizeof (pd.dtpd_mod), "%s", mod);
	snprintf(pd.dtpd_func, sizeof (pd.dtpd_func), "%s", func);
	snprintf(pd.dtpd_name, sizeof (pd.dtpd_name), "%s", name);
	pd.dtpd_id = PID_PROBE_ID;
	if (dtrace_probe_info(dtp, &pd, &pi) != 0) {
		printf("{\"types\": \"%s\", \"error\": \"%s\"}\n", label,
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		return;
	}
	printf("{\"types\": \"%s\", \"argv\": [", label);
	for (i = 0; i < pi.dtp_argc; i++) {
		if (pi.dtp_argv[i].dtt_ctfp == NULL ||
		    ctf_type_name(pi.dtp_argv[i].dtt_ctfp,
		    pi.dtp_argv[i].dtt_type, tname, sizeof (tname)) == NULL)
			snprintf(tname, sizeof (tname), "?");
		printf("%s\"%s\"", i ? ", " : "", tname);
	}
	printf("]}\n");
	fflush(stdout);
}

/* Argument types of pid probes come from the target's own CTF. */
static int
arg_types(dtrace_hdl_t *dtp, const char *target, const char *func)
{
	char *targv[2] = { (char *)target, NULL }, spec[512], lm[128];
	static const char *const names[] = { "entry", "return" };
	struct ps_prochandle *P;
	const char *base;
	int n;

	known_pid = 1;
	P = dtrace_proc_create(dtp, target, targv, NULL, NULL);
	if (P == NULL)
		return (2);
	base = strrchr(target, '/') != NULL ? strrchr(target, '/') + 1 :
	    target;
	for (n = 0; n < 2; n++) {
		snprintf(spec, sizeof (spec), "pid%d:%s:%s:%s {}",
		    proc_getpid(P), base, func, names[n]);
		compile_spec(dtp, names[n], spec);
		print_types(dtp, names[n], proc_getpid(P), base, func, names[n]);
	}
	/*
	 * Descriptions libdtrace may be asked about directly: an offset probe
	 * (no typed arguments), link-map qualified module names (valid and
	 * malformed), an unknown function, and one without CTF data.
	 */
	snprintf(lm, sizeof (lm), "LM0`%s", base);
	print_types(dtp, "offset", proc_getpid(P), base, func, "0");
	print_types(dtp, "lm0", proc_getpid(P), lm, func, "entry");
	print_types(dtp, "lm-short", proc_getpid(P), "L`", func, "entry");
	snprintf(lm, sizeof (lm), "XX0`%s", base);
	print_types(dtp, "lm-prefix", proc_getpid(P), lm, func, "entry");
	snprintf(lm, sizeof (lm), "LMzz`%s", base);
	print_types(dtp, "lm-number", proc_getpid(P), lm, func, "entry");
	print_types(dtp, "nosuch", proc_getpid(P), base, "ht_nosuch", "entry");
	print_types(dtp, "no-ctf-func", proc_getpid(P), base, "_start",
	    "entry");
	/* Arguments are usable in D with their CTF types. */
	snprintf(spec, sizeof (spec), "pid%d:%s:%s:entry { trace(args[0] + 1); "
	    "trace(stringof(args[1])); } pid%d:%s:%s:return "
	    "{ trace(args[1]); }", proc_getpid(P), base, func, proc_getpid(P),
	    base, func);
	printf("{\"typed_clause\": %d, \"error\": \"%s\"}\n",
	    dtrace_program_strcompile(dtp, spec, DTRACE_PROBESPEC_NAME,
	    DTRACE_C_ZDEFS, 0, NULL) != NULL, dtrace_errmsg(dtp,
	    dtrace_errno(dtp)));
	dtrace_proc_release(dtp, P);
	return (0);
}

int
main(int argc, char **argv)
{
	dtrace_hdl_t *dtp;
	struct ps_prochandle *P;
	char spec[512];
	int err, i, pid, rc = 0;

	if (argc < 3) {
		fprintf(stderr, "usage: pid-placement target spec...\n");
		return (2);
	}
	cap_set = (void (*)(int))dlsym(RTLD_DEFAULT, "pidcap_set");
	cap_count = (int (*)(void))dlsym(RTLD_DEFAULT, "pidcap_count");
	cap_get = (const fasttrap_probe_spec_t *(*)(int))dlsym(RTLD_DEFAULT,
	    "pidcap_get");
	cap_reset = (void (*)(void))dlsym(RTLD_DEFAULT, "pidcap_reset");
	cap_fail = (void (*)(int))dlsym(RTLD_DEFAULT, "pidcap_fail");
	cap_helper = (void (*)(int))dlsym(RTLD_DEFAULT, "pidcap_helper");
	cap_helper_opens = (int (*)(void))dlsym(RTLD_DEFAULT,
	    "pidcap_helper_opens");
	cap_helper_count = (int (*)(void))dlsym(RTLD_DEFAULT,
	    "pidcap_helper_count");
	cap_helper_get = (const dof_helper_t *(*)(int))dlsym(RTLD_DEFAULT,
	    "pidcap_helper_get");
	cap_getinstr = (void (*)(int))dlsym(RTLD_DEFAULT, "pidcap_getinstr");
	cap_getinstr_count = (int (*)(void))dlsym(RTLD_DEFAULT,
	    "pidcap_getinstr_count");
	cap_getinstr_pc = (uint64_t (*)(int))dlsym(RTLD_DEFAULT,
	    "pidcap_getinstr_pc");
	if (cap_set == NULL || cap_count == NULL || cap_get == NULL ||
	    cap_reset == NULL || cap_fail == NULL || cap_helper == NULL ||
	    cap_helper_opens == NULL || cap_helper_count == NULL ||
	    cap_helper_get == NULL || cap_getinstr == NULL ||
	    cap_getinstr_count == NULL || cap_getinstr_pc == NULL) {
		fprintf(stderr, "capture shim not preloaded\n");
		return (2);
	}

	dtp = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS | DTRACE_O_LP64,
	    &err, &vector, NULL);
	if (dtp == NULL) {
		fprintf(stderr, "vopen: %s\n", dtrace_errmsg(NULL, err));
		return (2);
	}
	if (strcmp(argv[1], "--lifecycle") == 0) {
		rc = lifecycle(dtp, argv[2]);
		dtrace_close(dtp);
		return (rc);
	}
	if (strcmp(argv[1], "--no-fasttrap") == 0) {
		/* dtrace_open() records why the fasttrap device is missing. */
		static const int errs[] = { ENOENT, EACCES };

		for (i = 0; i < 2; i++) {
			dtp->dt_ftfd = -1;
			dtp->dt_fterr = errs[i];
			snprintf(spec, sizeof (spec), "pid%d:a.out:main:entry {}",
			    (int)getpid());
			compile_spec(dtp, errs[i] == ENOENT ? "fterr-ENOENT" :
			    "fterr-EACCES", spec);
		}
		dtrace_close(dtp);
		return (0);
	}
	/* The pid provider needs a fasttrap descriptor; this one is inert. */
	dtp->dt_ftfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	cap_set(dtp->dt_ftfd);
	if (strcmp(argv[1], "--usdt") == 0 && argc == 4)
		rc = usdt(dtp, argv[2], argv[3]);
	else if (strcmp(argv[1], "--late") == 0 && argc == 8)
		rc = late_load(dtp, argv[2], argv[3], argv[4], argv[5], argv[6],
		    argv[7]);
	else if (strcmp(argv[1], "--types") == 0 && argc == 4)
		rc = arg_types(dtp, argv[2], argv[3]);
	else {
		char *targv[2] = { argv[1], NULL };

		P = dtrace_proc_create(dtp, argv[1], targv, NULL, NULL);
		if (P == NULL) {
			fprintf(stderr, "proc_create: %s\n",
			    dtrace_errmsg(dtp, dtrace_errno(dtp)));
			return (2);
		}
		pid = proc_getpid(P);
		printf("{\"target_pid\": %d}\n", pid);
		for (i = 2; i < argc; i++) {
			cap_reset();
			compile_spec(dtp, argv[i], expand_spec(argv[i], pid,
			    spec, sizeof (spec)));
		}
		cap_fail(-1);
		dtrace_proc_release(dtp, P);
		kill(pid, SIGKILL);
	}
	dtrace_close(dtp);
	return (rc);
}
