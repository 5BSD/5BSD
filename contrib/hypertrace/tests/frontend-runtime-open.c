/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * dtrace_open()/dtrace_vopen()/dtrace_fdopen()/dtrace_close() in dt_open.c.
 *
 * Oracles: the documented argument contract in dtrace.h and dt_open.c
 * (version and flag checks, DTRACE_O_* model selection, the errno mapping
 * ENOENT->EDT_NOENT, EBUSY->EDT_BUSY, EACCES->EDT_ACCESS, autoloading of
 * dtraceall and the Linux systrace modules), the ILP32 data model sizes
 * (long and pointers are 4 bytes), and the kern.bootfile naming rule.
 * Device access is answered by frontend-runtime-shim.so: /dev/dtrace/ paths
 * resolve to stand-in descriptors or scripted errors and kldload() never
 * reaches the kernel.  With -DWITH_FAULTS every allocation of dtrace_open()
 * is failed in turn; each must yield NULL with a library error, or a usable
 * handle.
 */
#include <sys/types.h>
#include <sys/ioctl.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <dt_impl.h>
#include <libctf.h>

#include "frontend-faults.h"

extern const char *_dtrace_libdir32;	/* dt_open.c */
#include "frontend-runtime-shim.h"

#define	CMD(x)	((u_long)(x) & 0xffffffffUL)

static struct {
	void (*reset)(void);
	void (*dev)(const char *, int);
	int (*opens)(const char *);
	void (*modfind)(int, int, int);
	int (*kldloads)(char [][64], int);
	void (*providers)(const char *, int);
	void (*bootfile)(const char *);
	void (*ioctl)(frontend_shim_ioctl_f *, void *);
	void (*getrlimit_fail)(int);
} S;

static int conf_mode;	/* 0 ok, 1 fail, 2 old DIF version, 3 ILP32 */
static int conf_calls;

static int
dev_ioctl(void *arg, int fd, unsigned long req, void *data)
{
	(void) arg; (void) fd;
	if (CMD(req) == CMD(DTRACEIOC_CONF)) {
		dtrace_conf_t *c = data;

		conf_calls++;
		if (conf_mode == 1)
			return (errno = ENXIO, -1);
		memset(c, 0, sizeof (*c));
		c->dtc_difversion = conf_mode == 2 ? DIF_VERSION - 1 :
		    DIF_VERSION;
		c->dtc_difintregs = DIF_DIR_NREGS;
		c->dtc_diftupregs = DIF_DTR_NREGS;
		c->dtc_ctfmodel = conf_mode == 3 ? CTF_MODEL_ILP32 :
		    CTF_MODEL_LP64;
		return (0);
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
	B(reset); B(dev); B(opens); B(modfind); B(kldloads); B(providers);
	B(bootfile); B(ioctl); B(getrlimit_fail);
#undef B
}

static size_t
type_size(dtrace_hdl_t *dtp, const char *name)
{
	dtrace_typeinfo_t t;

	if (dtrace_type_strcompile(dtp, name, &t) != 0)
		return ((size_t)-1);
	return ((size_t)ctf_type_size(t.dtt_ctfp, t.dtt_type));
}

static int
compiles(dtrace_hdl_t *dtp)
{
	return (dtrace_program_strcompile(dtp, "BEGIN { trace(1); }",
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL) != NULL);
}

static void
test_arguments(void)
{
	static const struct { int version, flags, err; } cases[] = {
		{ 0, DTRACE_O_NODEV, EINVAL }, { -1, DTRACE_O_NODEV, EINVAL },
		{ DTRACE_VERSION + 1, DTRACE_O_NODEV, EDT_VERSION },
		{ DTRACE_VERSION - 1, DTRACE_O_NODEV, EDT_OVERSION },
		{ DTRACE_VERSION, 0x10 | DTRACE_O_NODEV, EINVAL },
		{ DTRACE_VERSION, DTRACE_O_LP64 | DTRACE_O_ILP32 |
		    DTRACE_O_NODEV, EINVAL },
	};
	dtrace_hdl_t *dtp;
	size_t i;
	int err, fd, x = 0;

	for (i = 0; i < sizeof (cases) / sizeof (cases[0]); i++) {
		err = 0;
		dtp = dtrace_open(cases[i].version, cases[i].flags, &err);
		check(dtp == NULL && err == cases[i].err,
		    "open(%d, %#x) -> %d (got %d)", cases[i].version,
		    cases[i].flags, cases[i].err, err);
		/* errp is optional. */
		check(dtrace_open(cases[i].version, cases[i].flags, NULL) ==
		    NULL, "open(%d, %#x) without errp", cases[i].version,
		    cases[i].flags);
	}
	check(dtrace_vopen(DTRACE_VERSION, DTRACE_O_NODEV, &err, NULL, &x) ==
	    NULL && err == EINVAL, "vopen: argument without vector");
	check(dtrace_fdopen(-1, DTRACE_VERSION, 0, &err) == NULL &&
	    err == EINVAL, "fdopen(-1)");
	check(dtrace_fdopen(-1, DTRACE_VERSION, 0, NULL) == NULL,
	    "fdopen(-1) without errp");
	fd = open("/dev/null", O_RDWR);
	check(dtrace_fdopen(fd, DTRACE_VERSION, DTRACE_O_NODEV, &err) == NULL &&
	    err == EINVAL, "fdopen with NODEV");
	close(fd);
	check(dtrace_fdopen(fd, DTRACE_VERSION, 0, &err) == NULL &&
	    err == EBADF, "fdopen of a closed descriptor (%d)", err);
}

/*
 * A handle that never opened the devices (NODEV, or a vector) must report
 * why the pid provider is unavailable (regression: "No error: 0").
 */
static void
test_pid_unavailable(void)
{
	char prog[128], want[128];
	const char *msg;
	dtrace_hdl_t *dtp;
	int err;

	(void) snprintf(prog, sizeof (prog), "pid%d:a.out:main:entry {}",
	    (int)getpid());
	(void) snprintf(want, sizeof (want), "pid provider is not available: %s",
	    strerror(ENODEV));
	dtp = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV | DTRACE_O_NOSYS, &err);
	check(dtp != NULL, "NODEV open");
	if (dtp == NULL)
		return;
	msg = dtrace_program_strcompile(dtp, prog, DTRACE_PROBESPEC_NAME, 0, 0,
	    NULL) == NULL ? dtrace_errmsg(dtp, dtrace_errno(dtp)) : "(compiled)";
	check(dtp->dt_fterr == ENODEV && strstr(msg, want) != NULL &&
	    strstr(msg, "No error") == NULL,
	    "pid probe on NODEV handle: %s", msg);
	dtrace_close(dtp);
}

static void
test_ilp32(void)
{
	int err;
	dtrace_hdl_t *dtp = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV |
	    DTRACE_O_NOSYS | DTRACE_O_ILP32, &err);
	dt_dirpath_t *dp;
	int i, m32 = 0;

	check(dtp != NULL, "ILP32 open: %s", dtrace_errmsg(NULL, err));
	if (dtp == NULL)
		return;
	check(dtp->dt_conf.dtc_ctfmodel == CTF_MODEL_ILP32, "ILP32 model");
	check(type_size(dtp, "long") == 4 && type_size(dtp, "int *") == 4 &&
	    type_size(dtp, "uintptr_t") == 4 && type_size(dtp, "long long") ==
	    8, "ILP32 sizes long=%zu ptr=%zu", type_size(dtp, "long"),
	    type_size(dtp, "int *"));
	for (i = 0; i < dtp->dt_cpp_argc; i++)
		m32 |= strcmp(dtp->dt_cpp_argv[i], "-m32") == 0;
	check(m32, "ILP32 passes -m32 to cpp");
	dp = dt_list_next(&dtp->dt_lib_path);
	check(dp != NULL && strcmp(dp->dir_path, _dtrace_libdir32) == 0,
	    "ILP32 library directory %s", dp ? dp->dir_path : "(none)");
	check(compiles(dtp), "ILP32 handle compiles");
	dtrace_close(dtp);

	dtp = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV | DTRACE_O_NOSYS |
	    DTRACE_O_LP64, &err);
	check(dtp != NULL && type_size(dtp, "long") == 8 &&
	    type_size(dtp, "int *") == 8, "LP64 sizes");
	if (dtp != NULL)
		dtrace_close(dtp);
}

static dtrace_hdl_t *
dev_open(int *err)
{
	return (dtrace_open(DTRACE_VERSION, DTRACE_O_NOSYS, err));
}

static void
test_device(void)
{
	char loads[8][64];
	const char *mods[8];
	dtrace_hdl_t *dtp;
	char big[600];
	int err, n, i, fd;

	/* No driver: autoload dtraceall and the Linux systrace modules. */
	S.reset();
	S.modfind(-1, 5, 6);
	dtp = dev_open(&err);
	n = S.kldloads(loads, 8);
	check(dtp == NULL && err == EDT_NOENT, "no device -> EDT_NOENT (%d)",
	    err);
	check(n == 3 && strcmp(loads[0], "dtraceall") == 0 &&
	    strcmp(loads[1], "systrace_linux") == 0 &&
	    strcmp(loads[2], "systrace_linux32") == 0,
	    "autoload dtraceall + systrace_linux{,32} (%d loads)", n);
	check(S.opens("/dev/dtrace/dtrace") == 0 &&
	    S.opens(NULL) >= 3, "device opened twice, fasttrap once");

	S.reset();
	S.modfind(-1, -1, -1);
	dtp = dev_open(&err);
	n = S.kldloads(loads, 8);
	check(dtp == NULL && err == EDT_NOENT && n == 1,
	    "no Linux ABI: only dtraceall is loaded (%d)", n);

	S.reset();
	S.modfind(3, -1, -1);	/* dtraceall present but no device */
	dtp = dev_open(&err);
	check(dtp == NULL && err == EDT_NOENT && S.kldloads(loads, 8) == 0,
	    "dtraceall already loaded: no kldload");

	S.reset();
	S.dev("/dev/dtrace/dtrace", EBUSY);
	check(dev_open(&err) == NULL && err == EDT_BUSY, "EBUSY -> EDT_BUSY");
	S.reset();
	S.dev("/dev/dtrace/dtrace", EACCES);
	check(dev_open(&err) == NULL && err == EDT_ACCESS,
	    "EACCES -> EDT_ACCESS");
	S.reset();
	S.dev("/dev/dtrace/dtrace", EPERM);
	check(dev_open(&err) == NULL && err == EPERM && S.kldloads(loads, 8) ==
	    0, "EPERM passed through without autoload");

	/* A working device: providers are opened and released, CONF read. */
	S.reset();
	S.ioctl(dev_ioctl, NULL);
	S.dev("/dev/dtrace/dtrace", 0);
	S.dev("/dev/dtrace/fasttrap", ENOENT);
	S.dev("/dev/dtrace/fbt", 0);
	S.dev("/dev/dtrace/profile", 0);
	S.providers("fbt missing profile", 1);
	conf_mode = 0;
	conf_calls = 0;
	S.getrlimit_fail(1);
	dtp = dev_open(&err);
	S.getrlimit_fail(0);
	check(dtp != NULL, "device open: %s", dtrace_errmsg(NULL, err));
	if (dtp != NULL) {
		check(conf_calls == 1 && dtrace_ctlfd(dtp) >= 0,
		    "CONF read from the device");
		check(dtp->dt_fterr == ENOENT, "fasttrap error recorded");
		n = dtrace_provider_modules(dtp, mods, 1);
		check(n == 2, "two provider modules (%d)", n);
		n = dtrace_provider_modules(dtp, mods, 8);
		check(n == 2 && ((strcmp(mods[0], "profile") == 0 &&
		    strcmp(mods[1], "fbt") == 0) ||
		    (strcmp(mods[0], "fbt") == 0 &&
		    strcmp(mods[1], "profile") == 0)), "provider names");
		check(S.opens("/dev/dtrace/fbt") == 1 &&
		    S.opens("/dev/dtrace/missing") == 0, "provider opens");
		dtrace_close(dtp);
	}

	/* More than 16 providers grows the descriptor list. */
	S.reset();
	S.ioctl(dev_ioctl, NULL);
	S.dev("/dev/dtrace/dtrace", 0);
	S.dev("/dev/dtrace/fasttrap", 0);
	big[0] = '\0';
	for (i = 0; i < 20; i++) {
		static char names[20][24];

		(void) snprintf(names[i], sizeof (names[i]),
		    "/dev/dtrace/p%d", i);
		S.dev(names[i], 0);
		(void) strlcat(big, names[i] + 12, sizeof (big));
		(void) strlcat(big, i < 19 ? " " : "", sizeof (big));
	}
	S.providers(big, 0);
	dtp = dev_open(&err);
	check(dtp != NULL && dtrace_provider_modules(dtp, mods, 0) == 20 &&
	    dtp->dt_fterr == 0, "20 providers");
	if (dtp != NULL)
		dtrace_close(dtp);

	/* Provider sysctl absent or empty; CONF failures. */
	S.reset();
	S.ioctl(dev_ioctl, NULL);
	S.dev("/dev/dtrace/dtrace", 0);
	S.providers("", 0);
	dtp = dev_open(&err);
	check(dtp != NULL && dtrace_provider_modules(dtp, mods, 8) == 0,
	    "empty provider list");
	if (dtp != NULL)
		dtrace_close(dtp);
	/* A provider list that cannot be read is treated as empty. */
	S.providers("fbt", 2);
	dtp = dev_open(&err);
	check(dtp != NULL && dtrace_provider_modules(dtp, mods, 8) == 0,
	    "unreadable provider list");
	if (dtp != NULL)
		dtrace_close(dtp);
	S.providers(NULL, 0);
	conf_mode = 1;
	check(dev_open(&err) == NULL && err == ENXIO, "CONF failure errno");
	conf_mode = 2;
	check(dev_open(&err) == NULL && err == EDT_DIFVERS, "old DIF version");
	conf_mode = 3;
	dtp = dev_open(&err);
	check(dtp != NULL && type_size(dtp, "long") == 4,
	    "kernel reports ILP32 model");
	if (dtp != NULL)
		dtrace_close(dtp);
	conf_mode = 0;

	/* A supplied descriptor stands for the device. */
	S.reset();
	S.ioctl(dev_ioctl, NULL);
	fd = open("/dev/null", O_RDWR);
	dtp = dtrace_fdopen(fd, DTRACE_VERSION, DTRACE_O_NOSYS, &err);
	check(dtp != NULL && dtrace_ctlfd(dtp) != fd &&
	    dtp->dt_fterr == EACCES && S.opens(NULL) == 0,
	    "fdopen duplicates the descriptor and opens no device");
	if (dtp != NULL)
		dtrace_close(dtp);
	check(fcntl(fd, F_GETFD) != -1, "caller keeps its descriptor");
	close(fd);
	S.reset();
}

/* Close releases a freopen() destination and honours a discarded output. */
static void
test_close(void)
{
	int err, fd;
	dtrace_hdl_t *dtp = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV |
	    DTRACE_O_NOSYS, &err);

	check(dtp != NULL, "open for close tests");
	if (dtp == NULL)
		return;
	/* As the freopen() action leaves it: a stream the handle owns. */
	dtp->dt_freopen_fp = fopen("/dev/null", "w");
	fd = dtp->dt_freopen_fp != NULL ? fileno(dtp->dt_freopen_fp) : -1;
	check(fd >= 0 && dtrace_output_discard(dtp, NULL) == 0,
	    "output discarded");
	dtrace_close(dtp);
	check(fd >= 0 && fcntl(fd, F_GETFD) == -1 && errno == EBADF,
	    "close released the freopen stream");
}

static void
test_bootfile(void)
{
	static const struct { const char *sysctl, *want; } cases[] = {
		{ "/boot/kernel.alt/kernel.alt", "kernel.alt`struct thread *" },
		{ "mykernel", "mykernel`struct thread *" },
		{ NULL, "kernel`struct thread *" },
	};
	dtrace_hdl_t *dtp;
	size_t i;
	int err;

	for (i = 0; i < sizeof (cases) / sizeof (cases[0]); i++) {
		S.reset();
		S.bootfile(cases[i].sysctl);
		dtp = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV |
		    DTRACE_O_NOSYS, &err);
		check(dtp != NULL && strcmp(curthread_str, cases[i].want) == 0,
		    "bootfile %s -> %s (got %s)", cases[i].sysctl ?
		    cases[i].sysctl : "(fails)", cases[i].want, curthread_str);
		if (dtp != NULL)
			dtrace_close(dtp);
	}
	S.reset();
}

#ifdef WITH_FAULTS
static void
fault_sweep(int flags, const char *what)
{
	long n;
	int done, err, ok = 0, failed = 0;

	/* FAULT_START/FAULT_TRACE are debugging aids; the suite sets neither. */
	n = getenv("FAULT_START") ? atol(getenv("FAULT_START")) : 1;
	if (getenv("FAULT_ONLY") && strcmp(getenv("FAULT_ONLY"), what) != 0)
		return;
	for (done = 0; !done && n < 200000; n++) {
		dtrace_hdl_t *dtp;

		if (getenv("FAULT_TRACE"))
			fprintf(stderr, "fault %s %ld\n", what, n);

		if (n % 1000 == 0)
			printf("progress %s %ld\n", what, n);
		err = 0;
		arm(n);
		dtp = dtrace_open(DTRACE_VERSION, flags, &err);
		arm(0);
		if (!fault_hit) {
			check(dtp != NULL, "%s unfaulted open", what);
			done = 1;
		} else if (dtp == NULL) {
			failed++;
			check(err == EDT_NOMEM || err == EDT_CTF ||
			    err == EDT_HARDWIRE || err == ENOMEM,
			    "%s fault %ld: error %d (%s)", what, n, err,
			    dtrace_errmsg(NULL, err));
		} else {
			ok++;
			check(compiles(dtp), "%s fault %ld: handle usable: %s",
			    what, n, dtrace_errmsg(dtp, dtrace_errno(dtp)));
		}
		if (dtp != NULL)
			dtrace_close(dtp);
	}
	printf("fault sweep %s: %ld allocations, %d failed opens, %d "
	    "tolerated, %d skipped (dt_proc_init)\n", what, n - 1, failed, ok,
	    fault_skipped);
}

static void
fault_device(void)
{
	long n;
	int done, err;

	if (getenv("FAULT_ONLY") != NULL)
		return;
	for (n = 1, done = 0; !done && n < 400; n++) {
		dtrace_hdl_t *dtp;
		char big[200];
		int i;

		S.reset();
		S.ioctl(dev_ioctl, NULL);
		S.dev("/dev/dtrace/dtrace", 0);
		S.dev("/dev/dtrace/fasttrap", 0);
		big[0] = '\0';
		for (i = 0; i < 18; i++) {
			static char names[18][24];

			(void) snprintf(names[i], sizeof (names[i]),
			    "/dev/dtrace/q%d", i);
			S.dev(names[i], 0);
			(void) strlcat(big, names[i] + 12, sizeof (big));
			(void) strlcat(big, " ", sizeof (big));
		}
		S.providers(big, 1);
		err = 0;
		arm(n);
		dtp = dev_open(&err);
		arm(0);
		check(dtp != NULL || err == EDT_NOMEM || err == EDT_CTF ||
		    err == EDT_HARDWIRE || err == ENOMEM,
		    "device fault %ld: error %d", n, err);
		if (dtp != NULL)
			dtrace_close(dtp);
		/* Provider discovery and handle allocation come first. */
		if (n > 80)
			done = 1;
	}
	S.reset();
}
#endif

int
main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	bind_shim();
	test_arguments();
	test_pid_unavailable();
	test_ilp32();
	test_device();
	test_bootfile();
	test_close();
#ifdef WITH_FAULTS
	/*
	 * No allocation is skipped: dt_proc_init() failures used to crash
	 * dt_proc_fini() (NULL environment) and free out of bounds; they are
	 * now swept like every other allocation.
	 */
	{
		static const char *const skip[] = { NULL };

		fault_skip_fns = skip;
	}
	fault_device();
	fault_sweep(DTRACE_O_NODEV | DTRACE_O_NOSYS, "native");
	fault_sweep(DTRACE_O_NODEV | DTRACE_O_NOSYS | DTRACE_O_ILP32, "ilp32");
#endif
	exit(summary());
}
