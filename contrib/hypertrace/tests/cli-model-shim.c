/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Preload boundary for executable-level tests of the actual dtrace(1).
 *
 * The real dtrace binary runs unmodified.  This object is LD_PRELOADed and
 * is the only test boundary:
 *
 *  - dtrace_open() either forwards to the real library with
 *    DTRACE_O_NODEV|DTRACE_O_NOSYS forced (compile, link and header modes),
 *    or opens the real library through dtrace_vopen() with the audited
 *    dtrace(4) model from consume-ingestion.c (a snapshot of that file is
 *    compiled into this object; its hash is recorded by the driver).
 *    Scripted probe firings are applied at GO, STOP and the Nth STATUS or
 *    BUFSNAP; D clauses are never executed.
 *  - connect() to the dtraced socket is redirected to a private fake daemon
 *    named by CLI_DTRACED_SOCK, or refused.  The real daemon socket is never
 *    reached.
 *  - Every /dev/dtrace* path, /dev/ksyms, /boot and kldload(2) is refused.
 *    /dev/dtrace/hypertrace alone is modeled (an fd for /dev/null whose
 *    HYPERTRACE_IOC_EPOCH_GATE_QUERY answer comes from CLI_GATE).
 *  - pdself(PD_DAEMON|PD_CLOEXEC) and PDIOC_GET_BIRTH_IDENTITY are modeled
 *    (the running host kernel predates the source tree's process-descriptor
 *    birth identity), answering this process's pid and a fixed start time.
 *  - posix_spawnp("nextboot") runs /usr/bin/true or /usr/bin/false instead,
 *    after recording the requested argv.
 *  - CLI_FAULTS ("func:nth:errno,...") fails the nth call of a libc
 *    function made directly from the dtrace executable after main() has
 *    started.  Each fired fault is logged, so cases can require it fired.
 *  - syslog() is captured in the log instead of reaching syslogd.
 *  - CLI_CLOCK="jump:N:MS" adds MS to CLOCK_MONOTONIC for executable calls
 *    from the Nth one on, so a pending deadline expires deterministically.
 *  - CLI_API_FAULTS ("function:nth:value,...") makes the nth call of a few
 *    libdtrace entry points, made from the executable, fail without calling
 *    the library: the return value and errno are documented per function
 *    in api_fault().  Used only where no model or daemon behavior can make
 *    the library fail.
 *  - abort() is logged and converted to exit(134) so that the profile
 *    runtime's exit handler records coverage of abort paths; cases assert
 *    the logged abort, never a signal.
 *
 * Every boundary action is appended to CLI_SHIM_LOG.
 */

#define	main cli_model_unused_main
#include "consume-ingestion.c"
#undef main

#include <sys/ioctl.h>
#include <sys/procctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdatomic.h>
#include <time.h>

#include <sys/hypertrace.h>
#include <sys/procdesc.h>

#define	DTRACED_SOCK	"/var/ddtrace/sub.sock"

static int log_fd = -1;
static pthread_mutex_t shim_mtx = PTHREAD_MUTEX_INITIALIZER;
static uintptr_t exe_lo, exe_hi;
static atomic_int armed;
static int gate_fd = -1;
static int birth_fd = -1;
static unsigned gate_queries;

static void
shim_log(const char *fmt, ...)
{
	char line[1024];
	va_list ap;
	int n;

	if (log_fd < 0)
		return;
	va_start(ap, fmt);
	n = vsnprintf(line, sizeof (line) - 1, fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if (n > (int)sizeof (line) - 2)
		n = sizeof (line) - 2;
	line[n++] = '\n';
	(void) write(log_fd, line, n);
}

/* ------------------------------------------------------------------ */
/* Fault injection.                                                    */

#define	MAXFAULT	16
static struct fault {
	char name[64];
	int nth, error, calls, fired;
} faults[MAXFAULT];
static int nfaults;

static int
from_exe(const void *ret)
{
	return ((uintptr_t)ret >= exe_lo && (uintptr_t)ret < exe_hi);
}

/* Returns the errno to inject, or 0. */
static int
fault(const char *name, const void *ret)
{
	int i, e = 0;

	if (!atomic_load(&armed) || !from_exe(ret))
		return (0);
	pthread_mutex_lock(&shim_mtx);
	for (i = 0; i < nfaults; i++) {
		if (strcmp(faults[i].name, name) != 0)
			continue;
		if (++faults[i].calls == faults[i].nth) {
			faults[i].fired++;
			e = faults[i].error;
			shim_log("FAULT %s #%d errno %d", name, faults[i].nth,
			    e);
		}
	}
	pthread_mutex_unlock(&shim_mtx);
	return (e);
}

#define	REAL(type, name, args)						\
	static type (*real_##name) args;				\
	if (real_##name == NULL)					\
		real_##name = (type (*) args)dlsym(RTLD_NEXT, #name);	\
	if (real_##name == NULL)					\
		_exit(97)

static int
exe_range(struct dl_phdr_info *info, size_t size, void *arg)
{
	int i;

	(void) size;
	(void) arg;
	/* The first object is the executable. */
	for (i = 0; i < info->dlpi_phnum; i++) {
		const ElfW(Phdr) *ph = &info->dlpi_phdr[i];

		if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_X))
			continue;
		exe_lo = info->dlpi_addr + ph->p_vaddr;
		exe_hi = exe_lo + ph->p_memsz;
	}
	return (1);
}

/* ------------------------------------------------------------------ */
/* Scripted model events.                                              */

#define	MAXEV		64
#define	MAXVAL		32
static struct ev {
	char when[16];		/* go, stop, status:N, snap:N, aggsnap:N */
	int cpu, nth;
	char desc[128];
	char raw;		/* raw bytes instead of a firing */
	int nv;
	struct val v[MAXVAL];
	unsigned char *bytes[MAXVAL];
} evs[MAXEV];
static int nevs;
static unsigned nstatus, nsnap, naggsnap;
/* Options changed by the modeled kernel after GO (as dtrace_state_go()
 * lowers buffer sizes and clamps rates): setopt=NAME:VALUE. */
static struct { int opt; int64_t value; } postgo[8];
static u_long delay_cmd;	/* the first such command sleeps delay_ms */
static int delay_ms;
static int npostgo;
static int model_open;

static size_t
pct_decode(const char *in, unsigned char *out, size_t cap)
{
	size_t n = 0;

	while (*in != '\0' && n + 1 < cap) {
		if (in[0] == '%' && in[1] != '\0' && in[2] != '\0') {
			char hex[3] = { in[1], in[2], 0 };
			out[n++] = (unsigned char)strtoul(hex, NULL, 16);
			in += 3;
		} else
			out[n++] = (unsigned char)*in++;
	}
	out[n] = '\0';
	return (n);
}

static void
parse_events(const char *spec)
{
	char *copy = strdup(spec), *evtext, *save1 = NULL;

	for (evtext = strtok_r(copy, ";", &save1); evtext != NULL;
	    evtext = strtok_r(NULL, ";", &save1)) {
		struct ev *e = &evs[nevs];
		char *tok, *save2 = NULL;
		int field = 0;

		if (nevs == MAXEV)
			_exit(98);
		memset(e, 0, sizeof (*e));
		for (tok = strtok_r(evtext, " ", &save2); tok != NULL;
		    tok = strtok_r(NULL, " ", &save2)) {
			if (field == 0)
				strlcpy(e->when, tok, sizeof (e->when));
			else if (field == 1)
				e->cpu = atoi(tok);
			else if (field == 2) {
				char *hash = strchr(tok, '#');

				if (strcmp(tok, "raw") == 0)
					e->raw = 1;
				if (hash != NULL) {
					*hash = '\0';
					e->nth = atoi(hash + 1);
				}
				strlcpy(e->desc, tok, sizeof (e->desc));
			} else {
				struct val *v = &e->v[e->nv];

				if (e->nv == MAXVAL)
					_exit(98);
				memset(v, 0, sizeof (*v));
				v->incr = 1;
				if (strncmp(tok, "n:", 2) == 0)
					v->num = strtoll(tok + 2, NULL, 0);
				else if (strncmp(tok, "s:", 2) == 0) {
					unsigned char *b = calloc(1, 512);

					v->len = pct_decode(tok + 2, b, 512) + 1;
					v->bytes = b;
					e->bytes[e->nv] = b;
				} else if (strncmp(tok, "x:", 2) == 0) {
					unsigned char *b = calloc(1, 512);
					size_t i, l = strlen(tok + 2) / 2;

					for (i = 0; i < l && i < 512; i++) {
						char hex[3] = { tok[2 + 2 * i],
						    tok[3 + 2 * i], 0 };
						b[i] = strtoul(hex, NULL, 16);
					}
					v->len = l;
					v->bytes = b;
					e->bytes[e->nv] = b;
				} else if (strncmp(tok, "a:", 2) == 0) {
					char *colon = strchr(tok + 2, ':');

					v->num = strtoll(tok + 2, NULL, 0);
					v->incr = colon ? strtoll(colon + 1,
					    NULL, 0) : 1;
				} else if (strcmp(tok, "skip") == 0)
					v->incr = 0;
				else
					_exit(98);
				e->nv++;
			}
			field++;
		}
		nevs++;
	}
	free(copy);
}

static void
run_events(const char *when)
{
	int i;

	for (i = 0; i < nevs; i++) {
		struct ev *e = &evs[i];

		if (strcmp(e->when, when) != 0)
			continue;
		if (e->raw) {
			/* Raw principal-buffer bytes, for malformed buffers. */
			raw(e->cpu, e->v[0].bytes, e->v[0].len);
			shim_log("RAW %s cpu %d %zu bytes", when, e->cpu,
			    e->v[0].len);
			continue;
		}
		shim_log("FIRE %s cpu %d %s#%d (%d values) = %d", when,
		    e->cpu, e->desc, e->nth, e->nv,
		    fire(e->cpu, e->desc, e->nth, e->v, e->nv));
	}
}

static int
shim_ioctl(void *varg, u_long cmd, void *arg)
{
	char when[32];
	u_long c = CMD(cmd);
	int rc, saved;

	if (delay_ms > 0 && c == delay_cmd) {
		int ms = delay_ms;

		delay_ms = 0;
		shim_log("DELAY %#lx %d ms", c, ms);
		usleep(ms * 1000);
	}
	pthread_mutex_lock(&shim_mtx);
	if (c == CMD(DTRACEIOC_VPROBE_CREATE)) {
		dtrace_vprobe_io_t *v = arg;

		shim_log("VPROBE_CREATE vmid %u epoch %ju n %d", v->vmid,
		    (uintmax_t)v->epoch, v->neprobes);
		rc = 0;
		if (c == M.fail_cmd && M.fail_after-- == 0) {
			errno = M.fail_errno;
			rc = -1;
		}
	} else if (c == CMD(DTRACEIOC_PROBEARG) &&
	    ((dtrace_argdesc_t *)arg)->dtargd_id == 4) {
		/* test:kernel:alpha:entry declares typed arguments: a native
		 * type, a userland type and an unresolvable type. */
		static const char *const types[] = { "int", "int [",
		    "userland char *" };
		dtrace_argdesc_t *a = arg;

		if (a->dtargd_ndx < (int)nitems(types)) {
			strlcpy(a->dtargd_native, types[a->dtargd_ndx],
			    sizeof (a->dtargd_native));
			a->dtargd_xlate[0] = '\0';
			a->dtargd_mapping = a->dtargd_ndx;
		} else
			a->dtargd_ndx = DTRACE_ARGNONE;
		rc = 0;
	} else if (c == CMD(DTRACEIOC_AUGMENT) || (c == CMD(DTRACEIOC_ENABLE) &&
	    ((dtrace_enable_io_t *)arg)->vmid != 0)) {
		dtrace_enable_io_t *p = arg;

		/* The model has no hypertrace_check_epoch(); a guest or
		 * augmenting enable is recorded and applied as a host one. */
		shim_log("%s vmid %u epoch %ju", c == CMD(DTRACEIOC_AUGMENT) ?
		    "AUGMENT" : "ENABLE-GUEST", p->vmid, (uintmax_t)p->epoch);
		saved = M.activity;
		if (c == CMD(DTRACEIOC_AUGMENT) && c == M.fail_cmd &&
		    M.fail_after-- == 0) {
			errno = M.fail_errno;
			rc = -1;
		} else {
			uint16_t vmid = p->vmid;
			int first = M.necb, i;

			p->vmid = 0;
			M.activity = ACT_INACTIVE;
			rc = model_ioctl(varg, DTRACEIOC_ENABLE, arg);
			M.activity = saved;
			p->vmid = vmid;
			/* Their enabled probe descriptions name the guest. */
			for (i = first; rc == 0 && i < M.necb; i++)
				M.ecb[i].vmid = vmid;
		}
	} else {
		rc = model_ioctl(varg, cmd, arg);
		if (c == CMD(DTRACEIOC_ENABLE) && rc == 0)
			shim_log("ENABLE matched %d",
			    ((dtrace_enable_io_t *)arg)->n_matched);
	}
	if (rc != 0)
		shim_log("IOCTL %#lx failed errno %d", c, errno);
	if (rc == 0) {
		when[0] = '\0';
		if (c == CMD(DTRACEIOC_GO)) {
			int i;

			for (i = 0; i < npostgo; i++) {
				M.opt[postgo[i].opt] = postgo[i].value;
				shim_log("POSTGO option %d = %jd", postgo[i].opt,
				    (intmax_t)postgo[i].value);
			}
			shim_log("GO");
			strlcpy(when, "go", sizeof (when));
		}
		else if (c == CMD(DTRACEIOC_STOP))
			strlcpy(when, "stop", sizeof (when));
		else if (c == CMD(DTRACEIOC_STATUS))
			snprintf(when, sizeof (when), "status:%u", ++nstatus);
		else if (c == CMD(DTRACEIOC_BUFSNAP)) {
			dtrace_bufdesc_t *b = *(dtrace_bufdesc_t **)arg;

			snprintf(when, sizeof (when), "snap:%u", ++nsnap);
			/* A marker per completed pass over the modeled CPUs. */
			if (b->dtbd_cpu == (uint32_t)M.ncpu - 1)
				shim_log("ROUND %u", nsnap / M.ncpu);
		}
		else if (c == CMD(DTRACEIOC_AGGSNAP))
			snprintf(when, sizeof (when), "aggsnap:%u",
			    ++naggsnap);
		if (when[0] != '\0')
			run_events(when);
	}
	if (M.unexpected != 0) {
		shim_log("UNEXPECTED ioctl %#lx", M.last_unexpected);
		M.unexpected = 0;
	}
	pthread_mutex_unlock(&shim_mtx);
	return (rc);
}

static const dtrace_vector_t shim_vector = {
	.dtv_ioctl = shim_ioctl,
	.dtv_lookup_by_addr = model_lookup,
	.dtv_status = model_status,
	.dtv_sysconf = model_sysconf,
};

static u_long
command_named(const char *name)
{
	static const struct {
		const char *name;
		u_long cmd;
	} cmds[] = {
		{ "GO", DTRACEIOC_GO }, { "STOP", DTRACEIOC_STOP },
		{ "STATUS", DTRACEIOC_STATUS }, { "ENABLE", DTRACEIOC_ENABLE },
		{ "BUFSNAP", DTRACEIOC_BUFSNAP },
		{ "AGGSNAP", DTRACEIOC_AGGSNAP },
		{ "DOFGET", DTRACEIOC_DOFGET },
		{ "HANDLE_ID", DTRACEIOC_HANDLE_ID },
		{ "PROBEMATCH", DTRACEIOC_PROBEMATCH },
		{ "PROBES", DTRACEIOC_PROBES },
		{ "VPROBE_CREATE", DTRACEIOC_VPROBE_CREATE },
		{ "AUGMENT", DTRACEIOC_AUGMENT },
		{ "EPROBE", DTRACEIOC_EPROBE },
		{ "DRAINABLE", DTRACEIOC_DRAINABLE },
	};
	size_t i;

	for (i = 0; i < nitems(cmds); i++)
		if (strcmp(cmds[i].name, name) == 0)
			return (CMD(cmds[i].cmd));
	_exit(98);
}

static void
configure_model(void)
{
	const char *knobs = getenv("CLI_MODEL"), *script = getenv("CLI_SCRIPT");
	char *copy, *tok, *save = NULL;

	reset_model();
	if (knobs != NULL) {
		copy = strdup(knobs);
		for (tok = strtok_r(copy, ",", &save); tok != NULL;
		    tok = strtok_r(NULL, ",", &save)) {
			char *v = strchr(tok, '=');

			if (v == NULL)
				_exit(98);
			*v++ = '\0';
			if (strcmp(tok, "fail") == 0) {
				/* fail=CMD:after:errno */
				char *a = strchr(v, ':'), *b;

				*a++ = '\0';
				b = strchr(a, ':');
				*b++ = '\0';
				M.fail_cmd = command_named(v);
				M.fail_after = atoi(a);
				M.fail_errno = atoi(b);
			} else if (strcmp(tok, "begancpu") == 0)
				M.begancpu = atoi(v);
			else if (strcmp(tok, "endcpu") == 0)
				M.endcpu = atoi(v);
			else if (strcmp(tok, "delay") == 0) {
				char *a = strchr(v, ':');

				*a++ = '\0';
				delay_cmd = command_named(v);
				delay_ms = atoi(a);
			} else if (strcmp(tok, "status_errors") == 0)
				M.status_errors = atoi(v);
			else if (strcmp(tok, "hid_mode") == 0)
				M.hid_mode = atoi(v);
			else if (strcmp(tok, "speculates") == 0)
				M.speculates = atoi(v);
			else if (strcmp(tok, "setopt") == 0) {
				static const struct {
					const char *name;
					int opt;
				} names[] = {
					{ "bufsize", DTRACEOPT_BUFSIZE },
					{ "aggsize", DTRACEOPT_AGGSIZE },
					{ "specsize", DTRACEOPT_SPECSIZE },
					{ "dynvarsize", DTRACEOPT_DYNVARSIZE },
					{ "cleanrate", DTRACEOPT_CLEANRATE },
					{ "statusrate", DTRACEOPT_STATUSRATE },
				};
				char *colon = strchr(v, ':');
				size_t i;

				if (colon == NULL || npostgo == 8)
					_exit(98);
				*colon++ = '\0';
				for (i = 0; i < nitems(names); i++)
					if (strcmp(names[i].name, v) == 0)
						break;
				if (i == nitems(names))
					_exit(98);
				postgo[npostgo].opt = names[i].opt;
				postgo[npostgo++].value = strtoll(colon, NULL, 0);
			}
			else
				_exit(98);
		}
		free(copy);
	}
	if (script != NULL)
		parse_events(script);
	model_open = 1;
}

/* ------------------------------------------------------------------ */
/* Interposed library entry points.                                    */

dtrace_hdl_t *
dtrace_open(int version, int flags, int *errp)
{
	const char *mode = getenv("CLI_OPEN");
	static int failures;
	REAL(dtrace_hdl_t *, dtrace_open, (int, int, int *));

	if (mode != NULL && strncmp(mode, "fail:", 5) == 0) {
		/* fail:N:err fails the first N opens. */
		int n = atoi(mode + 5), err = atoi(strchr(mode + 5, ':') + 1);

		if (failures++ < n) {
			shim_log("OPEN-FAIL flags %#x err %d", flags, err);
			*errp = err;
			return (NULL);
		}
		mode = "nodev";
	}
	if (mode != NULL && strcmp(mode, "model") == 0 &&
	    !(flags & DTRACE_O_NODEV)) {
		pthread_mutex_lock(&shim_mtx);
		configure_model();
		pthread_mutex_unlock(&shim_mtx);
		shim_log("VOPEN flags %#x ncpu %d", flags, M.ncpu);
		return (dtrace_vopen(version, flags | DTRACE_O_NOSYS, errp,
		    &shim_vector, &M));
	}
	shim_log("NODEV-OPEN flags %#x", flags);
	return (real_dtrace_open(version, flags | DTRACE_O_NODEV |
	    DTRACE_O_NOSYS, errp));
}

int
xo_parse_args(int argc, char **argv)
{
	REAL(int, xo_parse_args, (int, char **));

	/* main() has started: arm executable-call fault injection. */
	atomic_store(&armed, 1);
	return (real_xo_parse_args(argc, argv));
}

static int
refused_path(const char *path)
{
	if (path == NULL)
		return (0);
	return (strncmp(path, "/dev/dtrace", 11) == 0 ||
	    strcmp(path, "/dev/ksyms") == 0 || strncmp(path, "/boot", 5) == 0 ||
	    strcmp(path, "/dev/hypertrace") == 0);
}

int
open(const char *path, int flags, ...)
{
	va_list ap;
	int mode = 0, e;
	REAL(int, open, (const char *, int, ...));

	if (flags & O_CREAT) {
		va_start(ap, flags);
		mode = va_arg(ap, int);
		va_end(ap);
	}
	if (path != NULL && strcmp(path, "/dev/dtrace/hypertrace") == 0) {
		const char *gate = getenv("CLI_GATE");

		if (gate == NULL || strcmp(gate, "absent") == 0) {
			shim_log("GATE-OPEN refused");
			errno = ENOENT;
			return (-1);
		}
		e = real_open("/dev/null", O_RDONLY | O_CLOEXEC);
		pthread_mutex_lock(&shim_mtx);
		gate_fd = e;
		pthread_mutex_unlock(&shim_mtx);
		shim_log("GATE-OPEN fd %d", e);
		return (e);
	}
	if (refused_path(path)) {
		Dl_info info;
		void *ret = __builtin_return_address(0);

		if (dladdr(ret, &info) == 0)
			info.dli_fname = info.dli_sname = NULL;
		shim_log("REFUSED open %s from %s:%s", path,
		    info.dli_fname ? info.dli_fname : "?",
		    info.dli_sname ? info.dli_sname : "?");
		errno = EACCES;
		return (-1);
	}
	if ((e = fault("open", __builtin_return_address(0))) != 0) {
		errno = e;
		return (-1);
	}
	return (real_open(path, flags, mode));
}

int
ioctl(int fd, unsigned long request, ...)
{
	va_list ap;
	void *arg;
	REAL(int, ioctl, (int, unsigned long, ...));

	va_start(ap, request);
	arg = va_arg(ap, void *);
	va_end(ap);
	if (fd >= 0 && fd == birth_fd && request == PDIOC_GET_BIRTH_IDENTITY) {
		struct pd_birth_identity *b = arg;

		memset(b, 0, sizeof (*b));
		b->pid = getpid();
		b->start_sec = 1792540800;
		b->start_usec = 123;
		shim_log("BIRTH-IDENTITY pid %d", (int)b->pid);
		return (0);
	}
	if (fd >= 0 && fd == gate_fd &&
	    request == HYPERTRACE_IOC_EPOCH_GATE_QUERY) {
		/* CLI_GATE: held:TOKENHEX[:N] (held for N queries, then
		 * released), suspended0:TOKENHEX, ioerr */
		struct hypertrace_epoch_gate *g = arg;
		const char *gate = getenv("CLI_GATE");
		unsigned limit = 0, i;
		const char *colon;

		pthread_mutex_lock(&shim_mtx);
		gate_queries++;
		shim_log("GATE-QUERY #%u vmid %u epoch %ju", gate_queries,
		    g->vmid, (uintmax_t)g->epoch);
		if (strcmp(gate, "ioerr") == 0) {
			pthread_mutex_unlock(&shim_mtx);
			errno = EIO;
			return (-1);
		}
		colon = strchr(gate, ':');
		for (i = 0; colon != NULL && i < 16 && colon[1 + 2 * i] &&
		    colon[2 + 2 * i]; i++) {
			char hex[3] = { colon[1 + 2 * i], colon[2 + 2 * i], 0 };
			g->token[i] = strtoul(hex, NULL, 16);
		}
		if (colon != NULL && (colon = strchr(colon + 1, ':')) != NULL)
			limit = atoi(colon + 1);
		g->suspended = strncmp(gate, "held", 4) == 0 &&
		    (limit == 0 || gate_queries <= limit);
		pthread_mutex_unlock(&shim_mtx);
		return (0);
	}
	return (real_ioctl(fd, request, arg));
}

int
close(int fd)
{
	int e;
	REAL(int, close, (int));

	if ((e = fault("close", __builtin_return_address(0))) != 0) {
		(void) real_close(fd);
		errno = e;
		return (-1);
	}

	pthread_mutex_lock(&shim_mtx);
	if (fd == gate_fd)
		gate_fd = -1;
	if (fd == birth_fd)
		birth_fd = -1;
	pthread_mutex_unlock(&shim_mtx);
	return (real_close(fd));
}

int
connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	REAL(int, connect, (int, const struct sockaddr *, socklen_t));

	if (addr != NULL && addr->sa_family == AF_UNIX) {
		const struct sockaddr_un *un = (const void *)addr;

		if (strcmp(un->sun_path, DTRACED_SOCK) == 0) {
			const char *fake = getenv("CLI_DTRACED_SOCK");
			struct sockaddr_un to = { .sun_family = AF_UNIX };

			if (fake == NULL) {
				shim_log("CONNECT refused %s", un->sun_path);
				errno = ECONNREFUSED;
				return (-1);
			}
			strlcpy(to.sun_path, fake, sizeof (to.sun_path));
			to.sun_len = SUN_LEN(&to);
			shim_log("CONNECT redirect %s", fake);
			return (real_connect(fd, (void *)&to, to.sun_len));
		}
	}
	return (real_connect(fd, addr, len));
}

int
pdself(int *fdp, int flags)
{
	REAL(int, open, (const char *, int, ...));

	if (flags != (PD_DAEMON | PD_CLOEXEC)) {
		errno = EINVAL;
		return (-1);
	}
	*fdp = real_open("/dev/null", O_RDONLY | O_CLOEXEC);
	pthread_mutex_lock(&shim_mtx);
	birth_fd = *fdp;
	pthread_mutex_unlock(&shim_mtx);
	return (*fdp < 0 ? -1 : 0);
}

/* The modeled kernel has no loaded modules: kernel CTF is never read. */
int
kldnext(int fileid)
{
	(void) fileid;
	return (0);
}

int
kldload(const char *file)
{
	shim_log("REFUSED kldload %s", file);
	errno = EPERM;
	return (-1);
}

int
posix_spawnp(pid_t *pid, const char *file,
    const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *attr,
    char *const argv[], char *const envp[])
{
	REAL(int, posix_spawnp, (pid_t *, const char *,
	    const posix_spawn_file_actions_t *, const posix_spawnattr_t *,
	    char *const[], char *const[]));

	if (file != NULL && strcmp(file, "nextboot") == 0) {
		const char *mode = getenv("CLI_NEXTBOOT");
		char line[512] = "";
		char *const t[] = { "true", NULL }, *const f[] = { "false", NULL };
		int i;

		for (i = 0; argv[i] != NULL; i++) {
			strlcat(line, argv[i], sizeof (line));
			strlcat(line, " ", sizeof (line));
		}
		shim_log("NEXTBOOT %s", line);
		if (mode != NULL && strcmp(mode, "spawnfail") == 0)
			return (ENOENT);
		return (real_posix_spawnp(pid, mode != NULL &&
		    strcmp(mode, "fail") == 0 ? "/usr/bin/false" :
		    "/usr/bin/true", fa, attr, mode != NULL &&
		    strcmp(mode, "fail") == 0 ? f : t, envp));
	}
	return (real_posix_spawnp(pid, file, fa, attr, argv, envp));
}

void
abort(void)
{
	shim_log("ABORT");
	exit(134);
}

/* Allocation faults (callers in the executable only). */
extern void *__malloc(size_t);
extern void *__calloc(size_t, size_t);
extern void *__realloc(void *, size_t);

void *
malloc(size_t size)
{
	int e = fault("malloc", __builtin_return_address(0));

	if (e != 0) {
		errno = e;
		return (NULL);
	}
	return (__malloc(size));
}

void *
calloc(size_t n, size_t size)
{
	int e = fault("calloc", __builtin_return_address(0));

	if (e != 0) {
		errno = e;
		return (NULL);
	}
	return (__calloc(n, size));
}

void *
realloc(void *p, size_t size)
{
	int e = fault("realloc", __builtin_return_address(0));

	if (e != 0) {
		errno = e;
		return (NULL);
	}
	return (__realloc(p, size));
}

#define	FAULT_INT(name, proto, args, failval)				\
int									\
name proto								\
{									\
	int e;								\
	REAL(int, name, proto);						\
	if ((e = fault(#name, __builtin_return_address(0))) != 0) {	\
		errno = e;						\
		return (failval);					\
	}								\
	return (real_##name args);					\
}

FAULT_INT(mkstemp, (char *t), (t), -1)
FAULT_INT(fsync, (int fd), (fd), -1)
FAULT_INT(flock, (int fd, int op), (fd, op), -1)
FAULT_INT(fstat, (int fd, struct stat *sb), (fd, sb), -1)
FAULT_INT(unlink, (const char *p), (p), -1)
static int clock_jump_after, clock_calls;
static int64_t clock_jump_ms;
static char clock_file[256];	/* jump once this file exists */
static int clock_file_seen;

int
clock_gettime(clockid_t c, struct timespec *t)
{
	int e, rc, n;
	REAL(int, clock_gettime, (clockid_t, struct timespec *));

	if ((e = fault("clock_gettime", __builtin_return_address(0))) != 0) {
		errno = e;
		return (-1);
	}
	rc = real_clock_gettime(c, t);
	if (rc == 0 && clock_file[0] != '\0' && c == CLOCK_MONOTONIC) {
		struct stat sb;

		if (!clock_file_seen && stat(clock_file, &sb) == 0) {
			clock_file_seen = 1;
			shim_log("CLOCK-JUMP by %jd ms", (intmax_t)clock_jump_ms);
		}
		if (clock_file_seen) {
			t->tv_sec += clock_jump_ms / 1000;
		}
	}
	if (rc == 0 && clock_jump_after > 0 && c == CLOCK_MONOTONIC &&
	    atomic_load(&armed) && from_exe(__builtin_return_address(0))) {
		pthread_mutex_lock(&shim_mtx);
		n = ++clock_calls;
		pthread_mutex_unlock(&shim_mtx);
		if (n >= clock_jump_after) {
			if (n == clock_jump_after)
				shim_log("CLOCK-JUMP at call %d by %jd ms", n,
				    (intmax_t)clock_jump_ms);
			t->tv_sec += clock_jump_ms / 1000;
			t->tv_nsec += (clock_jump_ms % 1000) * 1000000;
			if (t->tv_nsec >= 1000000000) {
				t->tv_sec++;
				t->tv_nsec -= 1000000000;
			}
		}
	}
	return (rc);
}

void
syslog(int priority, const char *fmt, ...)
{
	char line[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(line, sizeof (line), fmt, ap);
	va_end(ap);
	line[strcspn(line, "\n")] = '\0';
	shim_log("SYSLOG %d %s", priority, line);
}

/* API faults: each returns the documented failure without the library. */
static struct fault api_faults[MAXFAULT];
static int napi;

static int
api_fault(const char *name, const void *ret)
{
	int i, hit = 0;

	if (!from_exe(ret))
		return (0);
	pthread_mutex_lock(&shim_mtx);
	for (i = 0; i < napi; i++) {
		if (strcmp(api_faults[i].name, name) != 0)
			continue;
		if (++api_faults[i].calls == api_faults[i].nth) {
			api_faults[i].fired++;
			hit = 1;
			errno = api_faults[i].error;
			shim_log("API-FAULT %s #%d value %d", name,
			    api_faults[i].nth, api_faults[i].error);
		}
	}
	pthread_mutex_unlock(&shim_mtx);
	return (hit);
}

#define	API_FAULT(type, name, proto, args, failval)			\
type									\
name proto								\
{									\
	REAL(type, name, proto);					\
	if (api_fault(#name, __builtin_return_address(0)))		\
		return (failval);					\
	return (real_##name args);					\
}

/* NULL with errno = value (the OpenTelemetry probe clock program). */
API_FAULT(dtrace_prog_t *, dtrace_program_strcompile, (dtrace_hdl_t *h,
    const char *s, dtrace_probespec_t c, uint_t f, int ac, char *const av[]),
    (h, s, c, f, ac, av), NULL)

/* -1 with errno = value. */
API_FAULT(int, dtrace_program_exec, (dtrace_hdl_t *h, dtrace_prog_t *p,
    dtrace_proginfo_t *i), (h, p, i), -1)
API_FAULT(int, dtrace_aggregate_snap, (dtrace_hdl_t *h), (h), -1)
API_FAULT(int, dtrace_program_compiled_digest, (dtrace_hdl_t *h,
    dtrace_prog_t *p, uint8_t id[32]), (h, p, id), -1)
API_FAULT(int, dtrace_getopt, (dtrace_hdl_t *h, const char *o,
    dtrace_optval_t *v), (h, o, v), -1)
API_FAULT(int, dtrace_hypertrace_options_update, (dtrace_hdl_t *h), (h), -1)
API_FAULT(int, dtrace_program_append, (dtrace_hdl_t *h, dtrace_prog_t *d,
    dtrace_prog_t *s), (h, d, s), -1)
API_FAULT(int, dtrace_compile_idents_set, (dtrace_hdl_t *h, char *i,
    size_t n), (h, i, n), -1)
API_FAULT(int, dtrace_program_header, (dtrace_hdl_t *h, FILE *f,
    const char *n), (h, f, n), -1)
API_FAULT(int, dtrace_handle_err, (dtrace_hdl_t *h, dtrace_handle_err_f *f,
    void *a), (h, f, a), -1)
API_FAULT(int, dtrace_handle_drop, (dtrace_hdl_t *h, dtrace_handle_drop_f *f,
    void *a), (h, f, a), -1)
API_FAULT(int, dtrace_handle_proc, (dtrace_hdl_t *h, dtrace_handle_proc_f *f,
    void *a), (h, f, a), -1)
API_FAULT(int, dtrace_handle_setopt, (dtrace_hdl_t *h,
    dtrace_handle_setopt_f *f, void *a), (h, f, a), -1)
API_FAULT(int, dtrace_handle_buffered, (dtrace_hdl_t *h,
    dtrace_handle_buffered_f *f, void *a), (h, f, a), -1)
API_FAULT(int, dtrace_setopt, (dtrace_hdl_t *h, const char *o, const char *v),
    (h, o, v), -1)
API_FAULT(int, dtrace_aggregate_print, (dtrace_hdl_t *h, FILE *f,
    dtrace_aggregate_walk_f *w), (h, f, w), -1)
/* NULL with *err = value. */
dtrace_prog_t *
dtrace_elf_parse(dtrace_hdl_t *h, int fd, const char *path, int rslv,
    int *err, char *errmsg, dtrace_prog_t *ref)
{
	REAL(dtrace_prog_t *, dtrace_elf_parse, (dtrace_hdl_t *, int,
	    const char *, int, int *, char *, dtrace_prog_t *));
	if (api_fault("dtrace_elf_parse", __builtin_return_address(0))) {
		*err = errno;
		errmsg[0] = '\0';
		return (NULL);
	}
	return (real_dtrace_elf_parse(h, fd, path, rslv, err, errmsg, ref));
}
/* Copies a chosen identifier (CLI_SRCIDENT_FILE: an ELF whose program
 * identifier is read at offset CLI_SRCIDENT_OFFSET). */
char *
dtrace_get_srcident(char *buf)
{
	REAL(char *, dtrace_get_srcident, (char *));
	const char *path = getenv("CLI_SRCIDENT_FILE");
	const char *off = getenv("CLI_SRCIDENT_OFFSET");

	if (path != NULL && off != NULL &&
	    api_fault("dtrace_get_srcident", __builtin_return_address(0))) {
		FILE *fp = fopen(path, "r");

		if (fp != NULL) {
			(void) fseek(fp, strtol(off, NULL, 0), SEEK_SET);
			(void) fread(buf, 1, 128, fp);
			fclose(fp);
		}
		return (buf);
	}
	return (real_dtrace_get_srcident(buf));
}
/* Nonzero: verification failure. */
API_FAULT(int, dt_prog_verify, (void *c, dtrace_prog_t *a, dtrace_prog_t *b),
    (c, a, b), 1)
/* NULL. */
API_FAULT(void *, dtrace_dof_create, (dtrace_hdl_t *h, dtrace_prog_t *p,
    uint_t f), (h, p, f), NULL)
API_FAULT(dtrace_prog_t *, dtrace_vprog_from, (dtrace_hdl_t *h,
    dtrace_prog_t *p, int k), (h, p, k), NULL)
/* The hypertrace error number = value (errmsg left empty). */
int
dtrace_elf_create(dtrace_hdl_t *h, dtrace_prog_t *p, int e, int fd,
    const char *path, char *errmsg)
{
	REAL(int, dtrace_elf_create, (dtrace_hdl_t *, dtrace_prog_t *, int,
	    int, const char *, char *));
	if (api_fault("dtrace_elf_create", __builtin_return_address(0))) {
		errmsg[0] = '\0';
		return (errno);
	}
	return (real_dtrace_elf_create(h, p, e, fd, path, errmsg));
}

int
hypertrace_link(dtrace_hdl_t *h, dtrace_prog_t *p, char *errmsg)
{
	REAL(int, hypertrace_link, (dtrace_hdl_t *, dtrace_prog_t *, char *));
	if (api_fault("hypertrace_link", __builtin_return_address(0))) {
		strlcpy(errmsg, "injected", 16);
		return (errno);
	}
	return (real_hypertrace_link(h, p, errmsg));
}
FAULT_INT(procctl, (idtype_t i, id_t id, int cmd, void *d), (i, id, cmd, d),
    -1)
FAULT_INT(shutdown, (int fd, int how), (fd, how), -1)
FAULT_INT(vfprintf, (FILE *fp, const char *f, va_list ap), (fp, f, ap), -1)

/* Functions returning an error number rather than setting errno. */
#define	FAULT_ERR(name, proto, args)					\
int									\
name proto								\
{									\
	int e;								\
	REAL(int, name, proto);						\
	if ((e = fault(#name, __builtin_return_address(0))) != 0)	\
		return (e);						\
	return (real_##name args);					\
}

FAULT_ERR(pthread_create, (pthread_t *t, const pthread_attr_t *a,
    void *(*f)(void *), void *arg), (t, a, f, arg))
FAULT_ERR(pthread_join, (pthread_t t, void **r), (t, r))
FAULT_ERR(pthread_mutex_init, (pthread_mutex_t *m,
    const pthread_mutexattr_t *a), (m, a))
FAULT_ERR(pthread_cond_init, (pthread_cond_t *c,
    const pthread_condattr_t *a), (c, a))
FAULT_ERR(pthread_sigmask, (int how, const sigset_t *s, sigset_t *o),
    (how, s, o))
FAULT_ERR(sigwait, (const sigset_t *s, int *sig), (s, sig))

off_t
lseek(int fd, off_t off, int whence)
{
	int e;
	REAL(off_t, lseek, (int, off_t, int));

	if ((e = fault("lseek", __builtin_return_address(0))) != 0) {
		errno = e;
		return (e == 1 ? 1 : -1);	/* errno 1: short (nonzero) */
	}
	return (real_lseek(fd, off, whence));
}

ssize_t
pread(int fd, void *b, size_t n, off_t off)
{
	int e;
	REAL(ssize_t, pread, (int, void *, size_t, off_t));

	if ((e = fault("pread", __builtin_return_address(0))) != 0) {
		errno = e;
		return (e == 1 ? 1 : -1);	/* errno 1: short read */
	}
	return (real_pread(fd, b, n, off));
}

ssize_t
write(int fd, const void *b, size_t n)
{
	int e;
	REAL(ssize_t, write, (int, const void *, size_t));

	if ((e = fault("write", __builtin_return_address(0))) != 0) {
		errno = e == 1 ? EINTR : e;	/* errno 1: one EINTR */
		return (-1);
	}
	return (real_write(fd, b, n));
}

ssize_t
read(int fd, void *b, size_t n)
{
	int e;
	REAL(ssize_t, read, (int, void *, size_t));

	if ((e = fault("read", __builtin_return_address(0))) != 0) {
		errno = e;
		return (-1);
	}
	return (real_read(fd, b, n));
}

ssize_t
send(int fd, const void *b, size_t n, int flags)
{
	int e;
	REAL(ssize_t, send, (int, const void *, size_t, int));

	if ((e = fault("send", __builtin_return_address(0))) != 0) {
		errno = e;
		return (-1);
	}
	return (real_send(fd, b, n, flags));
}

ssize_t
recv(int fd, void *b, size_t n, int flags)
{
	int e;
	REAL(ssize_t, recv, (int, void *, size_t, int));

	if ((e = fault("recv", __builtin_return_address(0))) != 0) {
		errno = e;
		return (-1);
	}
	/* recv_large counts only reads of more than 1 KiB (ELF frames, not
	 * headers), so the target does not depend on EAGAIN retries. */
	if (n > 1024 &&
	    (e = fault("recv_large", __builtin_return_address(0))) != 0) {
		errno = e;
		return (-1);
	}
	return (real_recv(fd, b, n, flags));
}

FILE *
fopen(const char *path, const char *mode)
{
	int e;
	REAL(FILE *, fopen, (const char *, const char *));

	if (refused_path(path)) {
		shim_log("REFUSED fopen %s", path);
		errno = EACCES;
		return (NULL);
	}
	if ((e = fault("fopen", __builtin_return_address(0))) != 0) {
		errno = e;
		return (NULL);
	}
	return (real_fopen(path, mode));
}

int
fclose(FILE *fp)
{
	int e;
	REAL(int, fclose, (FILE *));

	if ((e = fault("fclose", __builtin_return_address(0))) != 0) {
		(void) real_fclose(fp);
		errno = e;
		return (EOF);
	}
	return (real_fclose(fp));
}

int
fflush(FILE *fp)
{
	int e;
	REAL(int, fflush, (FILE *));

	if ((e = fault("fflush", __builtin_return_address(0))) != 0) {
		errno = e;
		return (EOF);
	}
	return (real_fflush(fp));
}

pid_t
waitpid(pid_t pid, int *status, int options)
{
	int e;
	REAL(pid_t, waitpid, (pid_t, int *, int));

	if ((e = fault("waitpid", __builtin_return_address(0))) != 0) {
		pid_t r = real_waitpid(pid, status, options);

		(void) r;
		errno = e;
		return (-1);
	}
	return (real_waitpid(pid, status, options));
}

__attribute__((constructor)) static void
shim_init(void)
{
	const char *path = getenv("CLI_SHIM_LOG"), *spec;
	REAL(int, open, (const char *, int, ...));

	if (path != NULL)
		log_fd = real_open(path, O_WRONLY | O_APPEND | O_CREAT |
		    O_CLOEXEC, 0644);
	/* Only the measured dtrace process runs behind this boundary; its
	 * children (-c victims, system() actions) start without it. */
	unsetenv("LD_PRELOAD");
	dl_iterate_phdr(exe_range, NULL);
	if ((spec = getenv("CLI_CLOCK")) != NULL &&
	    sscanf(spec, "jump:%d:%jd", &clock_jump_after,
	    (intmax_t *)&clock_jump_ms) != 2 &&
	    sscanf(spec, "file:%255[^:]:%jd", clock_file,
	    (intmax_t *)&clock_jump_ms) != 2)
		_exit(98);
	if (getenv("CLI_ARM_EARLY") != NULL)
		atomic_store(&armed, 1);
	if ((spec = getenv("CLI_API_FAULTS")) != NULL) {
		char *copy = strdup(spec), *tok, *save = NULL;

		for (tok = strtok_r(copy, ",", &save); tok != NULL;
		    tok = strtok_r(NULL, ",", &save)) {
			struct fault *f = &api_faults[napi++];

			if (napi > MAXFAULT || sscanf(tok, "%63[^:]:%d:%d",
			    f->name, &f->nth, &f->error) != 3)
				_exit(98);
		}
		free(copy);
	}
	spec = getenv("CLI_FAULTS");
	if (spec != NULL) {
		char *copy = strdup(spec), *tok, *save = NULL;

		for (tok = strtok_r(copy, ",", &save); tok != NULL;
		    tok = strtok_r(NULL, ",", &save)) {
			struct fault *f = &faults[nfaults++];
			char *a = strchr(tok, ':'), *b;

			if (nfaults > MAXFAULT || a == NULL ||
			    (b = strchr(a + 1, ':')) == NULL)
				_exit(98);
			*a++ = '\0';
			*b++ = '\0';
			strlcpy(f->name, tok, sizeof (f->name));
			f->nth = atoi(a);
			f->error = atoi(b);
		}
		free(copy);
	}
	shim_log("SHIM pid %d exe %#jx-%#jx", getpid(), (uintmax_t)exe_lo,
	    (uintmax_t)exe_hi);
}
