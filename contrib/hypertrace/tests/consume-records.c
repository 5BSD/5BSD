/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Consumer record handling beyond consume-ingestion.c: output-failure
 * propagation, malformed record descriptions, histogram rendering edge
 * cases, structured output, temporal drops, buffer snapshots and the
 * work loop.
 *
 * The dtrace(4) model (DOF parsing, the kernel record layout rules and
 * BUFSNAP/AGGSNAP buffers) is reused verbatim from consume-ingestion.c,
 * which is included below with its main() renamed.  As there, D clauses are
 * not executed: every case scripts firings with explicit record values and
 * every expected output is derived from documented formats or the kernel
 * rules, not captured from the library.
 *
 * Built twice by consume-records.py: once with ASan/UBSan for the record
 * cases, and once without ASan (FAULT_MALLOC) so that malloc() can be
 * interposed for the allocation-failure sweep.
 */

#define	main consume_ingestion_main
#include "consume-ingestion.c"
#undef main

#include <sys/stat.h>
#include <fcntl.h>

#include "consume-records.h"


/* ------------------------------------------------------------------ */
/* Allocation failure (non-ASan build only).                           */

#ifdef FAULT_MALLOC
#include <dlfcn.h>
#include <stdarg.h>

/*
 * Only allocations made directly by libdtrace (dt_alloc(), dt_zalloc() and
 * the library's own malloc()/realloc() calls) are counted and failed;
 * libc, libxo and the harness allocate normally (malloc_lib can select
 * another library's direct calls instead).
 */
void *__malloc(size_t);
static long malloc_countdown;	/* 0: off; n: the nth library call fails */
static long malloc_calls;	/* library calls seen */
static int in_malloc;
static const char *malloc_lib = "libdtrace.so";	/* whose calls count */

static int
from_libdtrace(void *ra)
{
	Dl_info info;

	return (dladdr(ra, &info) != 0 && info.dli_fname != NULL &&
	    strstr(info.dli_fname, malloc_lib) != NULL);
}

void *
malloc(size_t n)
{
	if (!in_malloc) {
		in_malloc = 1;
		if (from_libdtrace(__builtin_return_address(0))) {
			malloc_calls++;
			if (malloc_countdown > 0 && --malloc_countdown == 0) {
				in_malloc = 0;
				errno = ENOMEM;
				return (NULL);
			}
		}
		in_malloc = 0;
	}
	return (__malloc(n));
}

/* The compiler folds dt_zalloc()'s malloc()+bzero() into calloc(); a fault
 * sweep that skipped calloc would silently miss every zeroed allocation. */
void *__calloc(size_t, size_t);

void *
calloc(size_t n, size_t size)
{
	if (!in_malloc) {
		in_malloc = 1;
		if (from_libdtrace(__builtin_return_address(0))) {
			malloc_calls++;
			if (malloc_countdown > 0 && --malloc_countdown == 0) {
				in_malloc = 0;
				errno = ENOMEM;
				return (NULL);
			}
		}
		in_malloc = 0;
	}
	return (__calloc(n, size));
}

/* libxo allocates through realloc(NULL, n); count those calls too. */
void *__realloc(void *, size_t);

void *
realloc(void *p, size_t n)
{
	if (!in_malloc) {
		in_malloc = 1;
		if (from_libdtrace(__builtin_return_address(0))) {
			malloc_calls++;
			if (malloc_countdown > 0 && --malloc_countdown == 0) {
				in_malloc = 0;
				errno = ENOMEM;
				return (NULL);
			}
		}
		in_malloc = 0;
	}
	return (__realloc(p, n));
}

static void
fail_next_malloc(long n)
{
	malloc_countdown = n;
}

/* dtrace(4) on a descriptor: the model answers ioctls on its file. */
int __sys_ioctl(int, unsigned long, ...);
static dev_t model_dev;
static ino_t model_ino;
static int model_fd_live;
static int r_ioctl(void *, u_long, void *);

int
ioctl(int fd, unsigned long req, ...)
{
	struct stat st;
	va_list ap;
	void *arg;

	va_start(ap, req);
	arg = va_arg(ap, void *);
	va_end(ap);
	if (model_fd_live && fstat(fd, &st) == 0 && st.st_dev == model_dev &&
	    st.st_ino == model_ino)
		return (r_ioctl(&M, req, arg));
	return (__sys_ioctl(fd, req, arg));
}

/* kern.smp.maxid can be made to fail (the library reads it directly). */
int __sysctlbyname(const char *, size_t, void *, size_t *, const void *,
    size_t);
static int fail_maxid;

int
sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen)
{
	if (fail_maxid && strcmp(name, "kern.smp.maxid") == 0) {
		errno = EPERM;
		return (-1);
	}
	return (__sysctlbyname(name, strlen(name), oldp, oldlenp, newp,
	    newlen));
}
#endif

/* ------------------------------------------------------------------ */
/* An output stream that fails every write from the Kth one on.        */

struct wfail {
	FILE *fp;
	char *text;
	size_t len, cap;
	int calls, fail_at;
};

static int
wf_write(void *cookie, const char *b, int n)
{
	struct wfail *w = cookie;

	w->calls++;
	if (w->fail_at != 0 && w->calls >= w->fail_at) {
		errno = EIO;
		return (-1);
	}
	if (w->len + n + 1 > w->cap) {
		w->cap = (w->len + n + 1) * 2;
		w->text = realloc(w->text, w->cap);
		assert(w->text != NULL);
	}
	memcpy(w->text + w->len, b, n);
	w->len += n;
	w->text[w->len] = '\0';
	return (n);
}

static FILE *
wf_open(struct wfail *w, int fail_at)
{
	memset(w, 0, sizeof (*w));
	w->fail_at = fail_at;
	w->text = strdup("");
	w->cap = 1;
	w->fp = funopen(w, NULL, wf_write, NULL, NULL);
	assert(w->fp != NULL);
	/* Unbuffered: each library dt_printf() reaches wf_write at once. */
	setvbuf(w->fp, NULL, _IONBF, 0);
	return (w->fp);
}

static void
wf_close(struct wfail *w)
{
	if (w->fp != NULL)
		fclose(w->fp);
	free(w->text);
	memset(w, 0, sizeof (*w));
}

/* ------------------------------------------------------------------ */
/* A vector around the model for kernel answers it does not produce.   */

static int r_killed;		/* STATUS reports the state as killed */
static int r_enoent_cpu = -1;	/* BUFSNAP of this CPU fails with ENOENT */
static int r_eio_cpu = -1;	/* BUFSNAP of this CPU fails with EIO */
static int r_value_only;	/* AGGDESC reports only the value record */
static struct {			/* PROBES answers with renamed probes */
	dtrace_id_t id;
	const char *prov, *name;
} r_rename[4];

static int
r_ioctl(void *varg, u_long cmd, void *arg)
{
	int rc, i, room;

	if (CMD(cmd) == CMD(DTRACEIOC_BUFSNAP) && r_enoent_cpu >= 0 &&
	    (*(dtrace_bufdesc_t **)arg)->dtbd_cpu == (uint32_t)r_enoent_cpu) {
		M.bufsnaps++;
		errno = ENOENT;
		return (-1);
	}
	if (CMD(cmd) == CMD(DTRACEIOC_BUFSNAP) && r_eio_cpu >= 0 &&
	    (*(dtrace_bufdesc_t **)arg)->dtbd_cpu == (uint32_t)r_eio_cpu) {
		errno = EIO;
		return (-1);
	}
	room = CMD(cmd) == CMD(DTRACEIOC_AGGDESC) ?
	    (*(dtrace_aggdesc_t **)arg)->dtagd_nrecs : 0;
	rc = model_ioctl(varg, cmd, arg);
	if (rc == 0 && CMD(cmd) == CMD(DTRACEIOC_AGGDESC) && r_value_only) {
		dtrace_aggdesc_t *d = *(dtrace_aggdesc_t **)arg;

		/*
		 * Malformed: the aggregation-ID key record is missing; only
		 * the value record (filled when the caller had room) is
		 * reported.
		 */
		if (room >= d->dtagd_nrecs) {
			d->dtagd_rec[0] = d->dtagd_rec[d->dtagd_nrecs - 1];
			d->dtagd_nrecs = 1;
		}
	}
	if (rc == 0 && CMD(cmd) == CMD(DTRACEIOC_STATUS) && r_killed)
		((dtrace_status_t *)arg)->dtst_killed = 1;
	if (rc == 0 && CMD(cmd) == CMD(DTRACEIOC_PROBES)) {
		dtrace_probedesc_t *d = arg;

		for (i = 0; i < 4 && r_rename[i].id != 0; i++) {
			if (d->dtpd_id != r_rename[i].id)
				continue;
			strlcpy(d->dtpd_provider, r_rename[i].prov,
			    sizeof (d->dtpd_provider));
			strlcpy(d->dtpd_name, r_rename[i].name,
			    sizeof (d->dtpd_name));
		}
	}
	return (rc);
}

static const dtrace_vector_t rvector = {
	.dtv_ioctl = r_ioctl,
	.dtv_lookup_by_addr = model_lookup,
	.dtv_status = model_status,
	.dtv_sysconf = model_sysconf,
};

/* ------------------------------------------------------------------ */
/* Sessions with controllable handlers.                                 */

static int err_mode, drop_mode, buf_mode, setopt_mode;
static int buf_calls;
static const char *abort_on;	/* r_probe aborts at this probe name */
static char *bufout;		/* concatenated buffered output */
static size_t bufoutlen;

static int
r_err(const dtrace_errdata_t *d, void *arg)
{
	(void) arg;
	event("error: %s", d->dteda_msg);
	return (err_mode ? DTRACE_HANDLE_ABORT : DTRACE_HANDLE_OK);
}

static int
r_drop(const dtrace_dropdata_t *d, void *arg)
{
	(void) arg;
	event("drop cpu=%d kind=%d n=%" PRIu64 ": %s", d->dtdda_cpu,
	    d->dtdda_kind, d->dtdda_drops, d->dtdda_msg);
	return (drop_mode ? DTRACE_HANDLE_ABORT : DTRACE_HANDLE_OK);
}

/* Buffered output: each flushed chunk is logged with its flags. */
static int
r_buffered(const dtrace_bufdata_t *b, void *arg)
{
	(void) arg;
	buf_calls++;
	if (getenv("BUF_TRACE") != NULL)
		fprintf(stderr, "delivery %d flags %#x \"%s\"\n", buf_calls,
		    b->dtbda_flags, b->dtbda_buffered);
	{
		size_t n = strlen(b->dtbda_buffered);

		bufout = realloc(bufout, bufoutlen + n + 1);
		assert(bufout != NULL);
		memcpy(bufout + bufoutlen, b->dtbda_buffered, n + 1);
		bufoutlen += n;
	}
	if (buf_mode != 0 && buf_calls >= buf_mode)
		return (DTRACE_HANDLE_ABORT);
	return (DTRACE_HANDLE_OK);
}

static int
r_setopt(const dtrace_setoptdata_t *d, void *arg)
{
	(void) arg;
	event("setopt %s %lld -> %lld\n", d->dtsda_option,
	    (long long)d->dtsda_oldval, (long long)d->dtsda_newval);
	return (setopt_mode ? DTRACE_HANDLE_ABORT : DTRACE_HANDLE_OK);
}

#define	RO_BUFFERED	0x1
#define	RO_SETOPT	0x2
#define	RO_NOGO		0x4

static void
r_reset(void)
{
	reset_model();
	err_mode = drop_mode = buf_mode = setopt_mode = 0;
	buf_calls = 0;
	r_killed = 0;
	r_value_only = 0;
	r_enoent_cpu = r_eio_cpu = -1;
	abort_on = NULL;
	free(bufout);
	bufout = NULL;
	bufoutlen = 0;
	memset(r_rename, 0, sizeof (r_rename));
}

static int
r_open(struct session *s, const char *name, const char *const *opts,
    const char *program, int flags)
{
	dtrace_prog_t *prog;
	dtrace_proginfo_t info;
	int err, i;

	memset(s, 0, sizeof (*s));
	s->dtp = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS | DTRACE_O_LP64,
	    &err, &rvector, &M);
	if (s->dtp == NULL) {
		fail(name, "dtrace_vopen", "", dtrace_errmsg(NULL, err));
		return (-1);
	}
	s->out = open_memstream(&s->text, &s->len);
	assert(s->out != NULL);
	(void) dtrace_setopt(s->dtp, "bufsize", "64k");
	(void) dtrace_setopt(s->dtp, "aggsize", "64k");
	for (i = 0; opts != NULL && opts[i] != NULL; i += 2) {
		if (dtrace_setopt(s->dtp, opts[i], opts[i + 1]) != 0) {
			fail(name, opts[i], "", dtrace_errmsg(s->dtp,
			    dtrace_errno(s->dtp)));
			return (-1);
		}
	}
	if (program == NULL)
		return (0);
	if (dtrace_handle_drop(s->dtp, r_drop, NULL) != 0 ||
	    dtrace_handle_err(s->dtp, r_err, NULL) != 0 ||
	    ((flags & RO_BUFFERED) &&
	    dtrace_handle_buffered(s->dtp, r_buffered, NULL) != 0) ||
	    ((flags & RO_SETOPT) &&
	    dtrace_handle_setopt(s->dtp, r_setopt, NULL) != 0)) {
		fail(name, "handlers", "", dtrace_errmsg(s->dtp,
		    dtrace_errno(s->dtp)));
		return (-1);
	}
	if ((prog = dtrace_program_strcompile(s->dtp, program,
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL)) == NULL) {
		fail(name, "compile", program, dtrace_errmsg(s->dtp,
		    dtrace_errno(s->dtp)));
		return (-1);
	}
	if (dtrace_program_exec(s->dtp, prog, &info) != 0) {
		fail(name, "exec", "", dtrace_errmsg(s->dtp,
		    dtrace_errno(s->dtp)));
		return (-1);
	}
	if (!(flags & RO_NOGO) && dtrace_go(s->dtp) != 0) {
		fail(name, "go", "", dtrace_errmsg(s->dtp,
		    dtrace_errno(s->dtp)));
		return (-1);
	}
	return (0);
}

static int
r_probe(const dtrace_probedata_t *data, void *arg)
{
	dtrace_probedesc_t *pd = data->dtpda_pdesc;

	if (abort_on != NULL && (strcmp(pd->dtpd_name, abort_on) == 0 ||
	    strcmp(pd->dtpd_func, abort_on) == 0)) {
		event("abort at %s:%s\n", pd->dtpd_func, pd->dtpd_name);
		return (DTRACE_CONSUME_ABORT);
	}
	return (probe_cb(data, arg));
}

static int
consume_fp(struct session *s, FILE *fp)
{
	return (dtrace_consume(s->dtp, fp, r_probe, rec_cb, NULL));
}

/* Every case below consumes through r_probe (abort_on support). */
#define	consume(s)	consume_fp((s), (s)->out)

static void
pass(const char *name)
{
	passes++;
	printf("PASS %s\n", name);
}

/* Compare text, reporting as a named failure; returns 0 when equal. */
static int
same(const char *name, const char *what, const char *want, const char *got)
{
	if (strcmp(want, got) == 0)
		return (0);
	fail(name, what, want, got);
	return (-1);
}

static int
want_err(const char *name, struct session *s, int rc, int want)
{
	char buf[160];

	if (rc == -1 && dtrace_errno(s->dtp) == want)
		return (0);
	snprintf(buf, sizeof (buf), "rc %d errno %d (%s)\n", rc,
	    dtrace_errno(s->dtp), dtrace_errmsg(s->dtp, dtrace_errno(s->dtp)));
	fail(name, "error", dtrace_errmsg(s->dtp, want), buf);
	return (-1);
}

/* The model's action set for the nth ECB of a probe. */
static struct mset *
ecb_set(const char *desc)
{
	return (&M.set[M.ecb[find_ecb(desc, 0)].set]);
}

/* ------------------------------------------------------------------ */
/* Output failure propagation.                                          */

/*
 * A scenario fires probes, then produces output on fp.  Every write the
 * library performs is a dt_printf() into the unbuffered stream, so failing
 * the Kth write and all later ones models a full device at each point of
 * the output.  For every K the library must return -1 with EIO (the errno
 * of the failed write), and what was written must be a prefix of the
 * complete output.
 */
typedef void fire_f(struct session *);
typedef int print_f(struct session *, FILE *);

/* Principal buffers are restored before each output pass. */
static struct mbuf saved[NCPU_MODEL];

static void
save_bufs(void)
{
	int i;

	for (i = 0; i < M.ncpu; i++) {
		saved[i] = M.buf[i];
		saved[i].data = NULL;
		if (M.buf[i].data != NULL) {
			saved[i].data = malloc(M.buf[i].size);
			assert(saved[i].data != NULL);
			memcpy(saved[i].data, M.buf[i].data, M.buf[i].size);
		}
	}
}

static void
restore_bufs(void)
{
	int i;

	for (i = 0; i < M.ncpu; i++) {
		char *data = M.buf[i].data;

		if (data != NULL)
			memcpy(data, saved[i].data, saved[i].size);
		M.buf[i] = saved[i];
		M.buf[i].data = data;
	}
}

static void
free_saved(void)
{
	int i;

	for (i = 0; i < M.ncpu; i++) {
		free(saved[i].data);
		saved[i].data = NULL;
	}
}

static int
sweep(const char *name, const char *const *opts, const char *prog,
    fire_f *fire_fn, print_f *print_fn, int expect_writes_min)
{
	struct session s;
	struct wfail w;
	char *full = NULL;
	int total = 0, k, rc, bad = 0, pass_no;

	r_reset();
	if (r_open(&s, name, opts, prog, 0) != 0) {
		close_session(&s);
		return (-1);
	}
	fire_fn(&s);
	save_bufs();
	/*
	 * Two unfaulted passes: the first lets printa() mark what it prints
	 * (as any earlier pass would), the second is the reference.
	 */
	for (pass_no = 0; pass_no < 2; pass_no++) {
		restore_bufs();
		wf_open(&w, 0);
		rc = print_fn(&s, w.fp);
		total = w.calls;
		if (pass_no == 1 && full != NULL && strcmp(full, w.text) != 0)
			rc = -2;
		free(full);
		full = strdup(w.text);
		wf_close(&w);
		if (rc != 0)
			break;
	}
	if (rc != 0 || total < expect_writes_min) {
		char buf[64];

		snprintf(buf, sizeof (buf), "rc %d, %d writes\n", rc, total);
		fail(name, "unfaulted run", "rc 0, stable output", buf);
		bad = 1;
	}
	if (getenv("SWEEP_TRACE") != NULL)
		fprintf(stderr, "%s: %d writes\n", name, total);
	if (getenv("SWEEP_DUMP") != NULL)
		fprintf(stderr, "==== %s\n%s\n====\n", name, full);
	for (k = 1; k <= total && !bad; k++) {
		restore_bufs();
		wf_open(&w, k);
		rc = print_fn(&s, w.fp);
		if (rc != -1 || dtrace_errno(s.dtp) != EIO ||
		    strncmp(full, w.text, w.len) != 0) {
			char buf[256];

			snprintf(buf, sizeof (buf), "write %d of %d: rc %d, "
			    "errno %d (%s), prefix %s\n", k, total, rc,
			    dtrace_errno(s.dtp), dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)), strncmp(full, w.text,
			    w.len) == 0 ? "ok" : "differs");
			fail(name, "write failure", "rc -1, EIO, prefix", buf);
			bad = 1;
		}
		wf_close(&w);
	}
	free(full);
	free_saved();
	close_session(&s);
	if (!bad)
		pass(name);
	return (bad ? -1 : 0);
}

static const uint64_t K_PCS[3] = { 0xffffffff80001010ULL,
    0xffffffff80002000ULL, 0xffffffff90000400ULL };

/* Data records of every size class and every symbolic kind. */
#define	SWEEP_DATA_PROG \
	"typedef char b5_t[5]; typedef char b20_t[20]; " \
	"test:kernel:alpha:entry { trace((char)arg0); trace((short)arg0); " \
	"trace((int)arg0); trace(arg0); trace(probefunc); " \
	"trace(*(b5_t *)arg1); trace(*(b20_t *)arg1); " \
	"stack(3); ustack(3, 16); sym(arg0); mod(arg0); usym(arg0); " \
	"umod(arg0); uaddr(arg0); tracemem(arg0, 20); " \
	"printm(4, (uintptr_t *)arg0); immstack(2); } " \
	"struct pf { int a; char b[4]; long c; " \
	"unsigned int lo:3; unsigned int hi:5; void *p; }; " \
	"test:kernel:beta:entry { ustack(2); sym(arg0); " \
	"print(*(struct pf *)arg1); printf(\"%d %s\\n\", arg0, probefunc); }"
/* The same without print(), which cannot use buffered output (below). */
#define	SWEEP_DATA_PROG_NOPRINT \
	"typedef char b5_t[5]; typedef char b20_t[20]; " \
	"test:kernel:alpha:entry { trace((char)arg0); trace((short)arg0); " \
	"trace((int)arg0); trace(arg0); trace(probefunc); " \
	"trace(*(b5_t *)arg1); trace(*(b20_t *)arg1); " \
	"stack(3); ustack(3, 16); sym(arg0); mod(arg0); usym(arg0); " \
	"umod(arg0); uaddr(arg0); tracemem(arg0, 20); " \
	"printm(4, (uintptr_t *)arg0); immstack(2); } " \
	"test:kernel:beta:entry { ustack(2); sym(arg0); " \
	"printf(\"%d %s\\n\", arg0, probefunc); }"
static int data_noprint;

static void
fire_data(struct session *s)
{
	static const char bin5[5] = { 'a', 'b', 'c', 'd', 'e' };
	static const char bin20[20] = { 1, 2, 3, 'x', 0, 'y' };
	uint64_t ust[1 + 3 + 2];
	uint64_t ua[2] = { 0, 0x401234 };
	unsigned char pm[8 + 16] = { 4, 0, 0, 0, 0, 0, 0, 0, 'P', 'R', 'N',
	    'T' };
	static char mem[20] = "0123456789abcdefghi";
	char imm[2 * 64];
	uint64_t off = 0x10;

	(void) s;
	memset(ust, 0, sizeof (ust));
	ust[1] = 0x400100;
	ust[2] = 0x400200;
	memcpy(&ust[4], "@note\0frame2\0", 13);
	memset(imm, 0, sizeof (imm));
	strcpy(imm, "vm_fault");
	memcpy(imm + 16, &off, sizeof (off));
	strcpy(imm + 64, "sched_tick");
	memcpy(imm + 80, &off, sizeof (off));
	fire(0, "test:kernel:alpha:entry", 0, VALS(N(-3), N(-3), N(-3),
	    N(-3), S("alpha"), B(bin5, 5), B(bin20, 20),
	    B(K_PCS, sizeof (K_PCS)), B(ust, sizeof (ust)),
	    N(0xffffffff80001010ULL), N(0xffffffff90000010ULL), B(ua, 16),
	    B(ua, 16), B(ua, 16), B(mem, 20), B(pm, sizeof (pm)),
	    B(imm, sizeof (imm))));
	{
		/* A guest user stack, an unknown kernel address, print(). */
		static const struct print_fixture pv = { 9, { 'o', 'k', 0, 0 },
		    -1, 0, 0, { 0 }, NULL };
		uint64_t gust[3] = { HYPERTRACE_USTACK_ENCODE(7, 42),
		    0x500100, 0 };

		if (data_noprint)
			fire(1, "test:kernel:beta:entry", 0, VALS(B(gust, 24),
			    N(0x1234), N(12), S("beta")));
		else
			fire(1, "test:kernel:beta:entry", 0, VALS(B(gust, 24),
			    N(0x1234), B(&pv, sizeof (pv)), N(12), S("beta")));
	}
}

static int
print_consume(struct session *s, FILE *fp)
{
	return (consume_fp(s, fp));
}

#define	SWEEP_AGG_PROG \
	"typedef char b20_t[20]; " \
	"test:kernel:alpha:entry { @q[probefunc] = quantize(arg0); " \
	"@l[probefunc] = lquantize(arg0, -4, 4, 2); " \
	"@ll[probefunc] = llquantize(arg0, 10, 0, 2, 10); " \
	"@a[probefunc] = avg(arg0); @sd[probefunc] = stddev(arg0); " \
	"@s[probefunc] = sum(arg0); @c[probefunc] = count(); } " \
	"test:kernel:beta:entry { " \
	"@st[stack(2)] = count(); @u[usym(arg1)] = count(); " \
	"@sz[(char)arg0, (short)arg0, (int)arg0] = sum(arg0); " \
	"@by[*(b20_t *)arg2] = count(); } " \
	"test:kernel:alpha:return { printa(@q); printa(\"%s %@d %@d\\n\", " \
	"@s, @c); printa(@s, @c); }"

static void
fire_aggs(struct session *s)
{
	static const int64_t v[] = { -5, 0, 3, 3, 120 };
	uint64_t ua[2] = { 0, 0x401234 };
	static const char bin20[20] = { 1, 2, 3 };
	size_t i;

	for (i = 0; i < sizeof (v) / sizeof (v[0]); i++) {
		struct val fn = S("alpha");

		fire(i % 2, "test:kernel:alpha:entry", 0, VALS(
		    N(1), fn, AGG(v[i], 1), N(2), fn, AGG(v[i], 1),
		    N(3), fn, AGG(v[i], 1), N(4), fn, AGG(v[i], 1),
		    N(5), fn, AGG(v[i], 1),
		    N(6), fn, AGG(v[i], 1), N(7), fn, AGG(0, 1)));
		fire(i % 2, "test:kernel:beta:entry", 0, VALS(
		    N(8), B(K_PCS, 16), AGG(0, 1),
		    N(9), B(ua, 16), AGG(0, 1),
		    N(10), N(v[i]), N(v[i]), N(v[i]), AGG(v[i], 1),
		    N(11), B(bin20, 20), AGG(0, 1)));
	}
	fire(0, "test:kernel:alpha:return", 0, VALS(N(1), N(6), N(7),
	    N(6), N(7)));
	if (dtrace_aggregate_snap(s->dtp) != 0)
		fail("fire-aggs", "snap", "", "");
}

static int
print_consume_aggs(struct session *s, FILE *fp)
{
	int rc;

	if ((rc = consume_fp(s, fp)) != 0)
		return (rc);
	return (dtrace_aggregate_print(s->dtp, fp, NULL));
}

static int
print_aggs(struct session *s, FILE *fp)
{
	return (dtrace_aggregate_print(s->dtp, fp, NULL));
}

#define	SWEEP_HIST_PROG \
	"test:kernel:alpha:entry { @q = quantize(arg0, arg1); " \
	"@qn = quantize(arg0, arg1); @l = lquantize(arg0, -8, 8, 4); " \
	"@ln = lquantize(arg0, -8, 8, 4, arg1); " \
	"@ll = llquantize(arg0, 2, 0, 4, 2, arg1); }"

static void
fire_hist_neg(struct session *s)
{
	/* 40 lands in llquantize's overflow bucket (>= 2^5). */
	static const int64_t v[] = { -5, -1, -1, 2, 7, 40 };
	size_t i;

	for (i = 0; i < sizeof (v) / sizeof (v[0]); i++)
		fire(0, "test:kernel:alpha:entry", 0, VALS(
		    N(1), N(0), AGG(v[i], v[i] < 0 ? -1 : 1),
		    N(2), N(0), AGG(v[i], v[i] > 0 ? -1 : 1),
		    N(3), AGG(v[i], 1),
		    N(4), N(0), AGG(v[i], v[i] < 0 ? -1 : 1),
		    N(5), N(0), AGG(v[i], v[i] > 0 ? -2 : 1)));
	if (dtrace_aggregate_snap(s->dtp) != 0)
		fail("fire-hist", "snap", "", "");
}

#define	SWEEP_PACKED_PROG \
	"test:kernel:alpha:entry { @q[probefunc] = quantize(arg0); " \
	"@l[probefunc] = lquantize(arg0, -4, 4, 1); " \
	"@c[probefunc] = count(); }"

static void
fire_packed(struct session *s)
{
	static const int64_t v[] = { -3, 1, 2, 3, 3, 9 };
	size_t i;

	for (i = 0; i < sizeof (v) / sizeof (v[0]); i++)
		fire(0, "test:kernel:alpha:entry", 0, VALS(
		    N(1), S("alpha"), AGG(v[i], 1),
		    N(2), S("alpha"), AGG(v[i], 1),
		    N(3), S("alpha"), AGG(0, 1)));
	if (dtrace_aggregate_snap(s->dtp) != 0)
		fail("fire-packed", "snap", "", "");
}

static void
case_write_failures(void)
{
	static const char *const quiet[] = { "quiet", NULL, NULL };
	static const char *const raw[] = { "rawbytes", NULL, NULL };
	static const char *const hist[] = { "aggzoom", NULL, NULL };
	static const char *const agghist[] = { "agghist", NULL, "encoding",
	    "utf8", NULL };
	static const char *const packa[] = { "aggpack", NULL, "encoding",
	    "ascii", NULL };
	static const char *const utf8[] = { "encoding", "utf8", NULL };

	sweep("write-failure-records", NULL, SWEEP_DATA_PROG, fire_data,
	    print_consume, 40);
	sweep("write-failure-records-quiet", quiet, SWEEP_DATA_PROG,
	    fire_data, print_consume, 40);
	sweep("write-failure-records-rawbytes", raw, SWEEP_DATA_PROG,
	    fire_data, print_consume, 40);
	sweep("write-failure-aggregations", NULL, SWEEP_AGG_PROG, fire_aggs,
	    print_consume_aggs, 40);
	sweep("write-failure-signed-histograms", NULL, SWEEP_HIST_PROG,
	    fire_hist_neg, print_aggs, 20);
	sweep("write-failure-signed-histograms-zoom", hist, SWEEP_HIST_PROG,
	    fire_hist_neg, print_aggs, 20);
	sweep("write-failure-signed-histograms-utf8", utf8, SWEEP_HIST_PROG,
	    fire_hist_neg, print_aggs, 20);
	sweep("write-failure-agghist", agghist, SWEEP_PACKED_PROG,
	    fire_packed, print_aggs, 10);
	sweep("write-failure-aggpack", packa, SWEEP_PACKED_PROG, fire_packed,
	    print_aggs, 10);
}


/* ------------------------------------------------------------------ */
/* Private structures (consume-records-internal.c).                     */

static void
case_buf(void)
{
	const char *name = "dt-buf-growth";
	struct session s;
	char msg[256];

	r_reset();
	if (r_open(&s, name, NULL, NULL, 0) == 0) {
		if (cr_buf_cases(s.dtp, msg, sizeof (msg)) != 0)
			fail(name, "dt_buf", "", msg);
		else
			pass(name);
	}
	close_session(&s);
}

static void
case_sleep(void)
{
	const char *name = "sleep-notifications";
	struct session s;
	char msg[256];

	r_reset();
	if (r_open(&s, name, NULL, NULL, 0) == 0) {
		if (cr_sleep_cases(s.dtp, msg, sizeof (msg)) != 0)
			fail(name, "dtrace_sleep", "", msg);
		else
			pass(name);
	}
	close_session(&s);
}

/* ------------------------------------------------------------------ */
/* Status, work loop, go and stop.                                      */

/*
 * dtrace_status(): INACTIVE before go; the first call queries STATUS, a
 * second call within statusrate reports NONE without a query; a filled
 * fill-policy buffer stops tracing (FILLED), a filled switching buffer is
 * OKAY; STOPPED once stopped; a killed state fails with EDT_BRICKED.
 */
static void
case_status(void)
{
	const char *name;
	struct session s;
	static const char *const slow[] = { "statusrate", "10s", NULL };
	static const char *const fill[] = { "bufpolicy", "fill",
	    "statusrate", "1ns", NULL };
	static const char *const sw[] = { "statusrate", "1ns", NULL };
	int rc;

	name = "status-inactive-none-stopped";
	r_reset();
	if (r_open(&s, name, slow, TRACE_PROG, RO_NOGO) == 0) {
		int r0 = dtrace_status(s.dtp), r1, r2, r3;
		unsigned before;

		(void) dtrace_go(s.dtp);
		r1 = dtrace_status(s.dtp);
		before = M.unexpected;
		r2 = dtrace_status(s.dtp);
		(void) dtrace_stop(s.dtp);
		r3 = dtrace_status(s.dtp);
		if (r0 != DTRACE_STATUS_INACTIVE || r1 != DTRACE_STATUS_OKAY ||
		    r2 != DTRACE_STATUS_NONE || r3 != DTRACE_STATUS_STOPPED ||
		    before != M.unexpected)
			fail(name, "statuses", "INACTIVE OKAY NONE STOPPED", "");
		else
			pass(name);
	}
	close_session(&s);

	name = "status-filled";
	r_reset();
	if (r_open(&s, name, fill, TRACE_PROG, 0) == 0) {
		M.buf[1].flags |= BUF_FULL;
		rc = dtrace_status(s.dtp);
		if (rc != DTRACE_STATUS_FILLED || M.activity != ACT_STOPPED)
			fail(name, "status", "FILLED and stopped", "");
		else
			pass(name);
	}
	close_session(&s);

	name = "status-filled-stop-fails";
	r_reset();
	if (r_open(&s, name, fill, TRACE_PROG, 0) == 0) {
		M.buf[0].flags |= BUF_FULL;
		M.fail_cmd = CMD(DTRACEIOC_STOP);
		M.fail_errno = EIO;
		rc = dtrace_status(s.dtp);
		M.fail_cmd = 0;
		if (want_err(name, &s, rc, EIO) == 0)
			pass(name);
	}
	close_session(&s);

	name = "status-filled-switch";
	r_reset();
	if (r_open(&s, name, sw, TRACE_PROG, 0) == 0) {
		M.buf[0].flags |= BUF_FULL;
		rc = dtrace_status(s.dtp);
		if (rc != DTRACE_STATUS_OKAY || M.activity != ACT_ACTIVE)
			fail(name, "status", "OKAY, still active", "");
		else
			pass(name);
	}
	close_session(&s);

	name = "status-killed";
	r_reset();
	if (r_open(&s, name, sw, TRACE_PROG, 0) == 0) {
		r_killed = 1;
		if (want_err(name, &s, dtrace_status(s.dtp), EDT_BRICKED) == 0)
			pass(name);
	}
	close_session(&s);

	/* dtrace_stop() is idempotent; its final status check can fail. */
	name = "stop-twice-and-killed";
	r_reset();
	if (r_open(&s, name, sw, TRACE_PROG, 0) == 0) {
		r_killed = 1;
		rc = dtrace_stop(s.dtp);
		if (want_err(name, &s, rc, EDT_BRICKED) == 0) {
			if (dtrace_stop(s.dtp) != 0)
				fail(name, "second stop", "0", "");
			else
				pass(name);
		}
	}
	close_session(&s);
}

static dtrace_workstatus_t
work(struct session *s)
{
	return (dtrace_work(s->dtp, s->out, probe_cb, rec_cb, NULL));
}

/*
 * dtrace_work(): with a switching buffer and nothing wrong, each call
 * consumes and returns OKAY; with a ring buffer it returns OKAY without
 * consuming; status, snapshot and consumption failures return ERROR, as
 * does an inactive handle.
 */
static void
case_work(void)
{
	const char *name;
	struct session s;
	static const char *const sw[] = { "statusrate", "1ns",
	    "switchrate", "1ns", NULL };
	static const char *const ring[] = { "statusrate", "1ns",
	    "bufpolicy", "ring", NULL };
	dtrace_workstatus_t st;

	name = "work-okay-consumes";
	r_reset();
	if (r_open(&s, name, sw, TRACE_PROG, 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(6)));
		st = work(&s);
		xbegin();
		X(" %16lld", 6LL);
		if (st != DTRACE_WORKSTATUS_OKAY)
			fail(name, "status", "OKAY", "");
		else
			check(name, &s, xend(),
			    "probe cpu=0 test:kernel:alpha:entry\n"
			    "end-of-probe\n");
	}
	close_session(&s);

	name = "work-ring-defers";
	r_reset();
	if (r_open(&s, name, ring, TRACE_PROG, 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(6)));
		st = work(&s);
		if (st != DTRACE_WORKSTATUS_OKAY || M.bufsnaps != 0)
			fail(name, "status", "OKAY, no snapshot", "");
		else
			check(name, &s, "", "");
	}
	close_session(&s);

	name = "work-inactive";
	r_reset();
	if (r_open(&s, name, sw, TRACE_PROG, RO_NOGO) == 0) {
		st = work(&s);
		if (st != DTRACE_WORKSTATUS_ERROR ||
		    dtrace_errno(s.dtp) != EINVAL)
			fail(name, "status", "ERROR, EINVAL", "");
		else
			pass(name);
	}
	close_session(&s);

	name = "work-status-error";
	r_reset();
	if (r_open(&s, name, sw, TRACE_PROG, 0) == 0) {
		M.fail_cmd = CMD(DTRACEIOC_STATUS);
		M.fail_errno = EIO;
		st = work(&s);
		M.fail_cmd = 0;
		if (st != DTRACE_WORKSTATUS_ERROR || dtrace_errno(s.dtp) != EIO)
			fail(name, "status", "ERROR, EIO", "");
		else
			pass(name);
	}
	close_session(&s);

	name = "work-snapshot-error";
	r_reset();
	if (r_open(&s, name, sw, "test:::entry { @c = count(); }", 0) == 0) {
		M.fail_cmd = CMD(DTRACEIOC_AGGSNAP);
		M.fail_errno = EIO;
		st = work(&s);
		M.fail_cmd = 0;
		if (st != DTRACE_WORKSTATUS_ERROR || dtrace_errno(s.dtp) != EIO)
			fail(name, "status", "ERROR, EIO", "");
		else
			pass(name);
	}
	close_session(&s);

	name = "work-consume-error";
	r_reset();
	probe_mode = 2;
	if (r_open(&s, name, sw, TRACE_PROG, 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(6)));
		st = work(&s);
		if (st != DTRACE_WORKSTATUS_ERROR ||
		    dtrace_errno(s.dtp) != EDT_DIRABORT)
			fail(name, "status", "ERROR, EDT_DIRABORT", "");
		else
			pass(name);
	}
	close_session(&s);
}

/*
 * dtrace_go(): a second go is EINVAL.  A vector without ENABLE support
 * (ENOTTY) still starts, whether the error enabling or the program's DOF
 * was refused.
 */
static void
case_go(void)
{
	const char *name;
	struct session s;
	int i;

	name = "go-twice";
	r_reset();
	if (r_open(&s, name, NULL, TRACE_PROG, 0) == 0) {
		if (want_err(name, &s, dtrace_go(s.dtp), EINVAL) == 0)
			pass(name);
	}
	close_session(&s);

	for (i = 0; i < 2; i++) {
		name = i == 0 ? "go-enable-enotty-errprog" :
		    "go-enable-enotty-program";
		r_reset();
		if (r_open(&s, name, NULL, TRACE_PROG, RO_NOGO) == 0) {
			M.fail_cmd = CMD(DTRACEIOC_ENABLE);
			M.fail_errno = ENOTTY;
			M.fail_after = i;
			if (dtrace_go(s.dtp) != 0 || M.activity != ACT_ACTIVE)
				fail(name, "go", "started", dtrace_errmsg(s.dtp,
				    dtrace_errno(s.dtp)));
			else
				pass(name);
			M.fail_cmd = 0;
		}
		close_session(&s);
	}
}

/* A drain with structured output configured is refused. */
static void
case_quiesced_oformat(void)
{
	const char *name;
	struct session s;
	dtrace_consumer_t con = { .dc_consume_probe = probe_cb,
	    .dc_consume_rec = rec_cb };
	int rc;

	name = "quiesced-oformat";
	r_reset();
	if (r_open(&s, name, NULL, TRACE_PROG, 0) == 0) {
		FILE *json = fopen("/dev/null", "w");

		dtrace_set_outfp(json);
		xo_set_style(NULL, XO_STYLE_JSON);
		if (dtrace_oformat_configure(s.dtp) != 0)
			fail(name, "configure", "", "");
		rc = dtrace_consume_quiesced(s.dtp, s.out, &con, NULL);
		if (want_err(name, &s, rc, EOPNOTSUPP) == 0)
			pass(name);
		dtrace_oformat_teardown(s.dtp);
		close_session(&s);
		xo_set_style(NULL, XO_STYLE_TEXT);
		dtrace_set_outfp(stdout);
		fclose(json);
	} else
		close_session(&s);

}

/*
 * dtrace_consume_quiesced() beyond consume-ingestion: structured output is
 * refused, an inactive handle is EINVAL, aggregation data that arrives
 * without a compiled aggregation (externally enabled DOF) is refused after
 * the snapshot, a DRAINABLE failure after the snapshot is reported, an
 * aborting consumer fails the drain, and a NULL stream skips the flush.
 */
static void
case_quiesced(void)
{
	const char *name;
	struct session s, ext;
	static const char *const sw[] = { "bufpolicy", "switch", NULL };
	dtrace_consumer_t con = { .dc_consume_probe = probe_cb,
	    .dc_consume_rec = rec_cb };
	int rc;

	name = "quiesced-not-started";
	r_reset();
	if (r_open(&s, name, sw, TRACE_PROG, RO_NOGO) == 0) {
		rc = dtrace_consume_quiesced(s.dtp, s.out, &con, NULL);
		if (want_err(name, &s, rc, EINVAL) == 0)
			pass(name);
	}
	close_session(&s);

	/*
	 * Another handle enables an aggregation into the same state; this
	 * handle compiled none, so only the snapshot reveals it.
	 */
	name = "quiesced-external-aggregation";
	r_reset();
	if (r_open(&s, name, NULL, TRACE_PROG, RO_NOGO) == 0 &&
	    r_open(&ext, name, NULL, "test:kernel:beta:entry { @c = count(); }",
	    RO_NOGO) == 0) {
		/* ext's ENABLE; then this handle's go enables its ECBs. */
		if (dtrace_go(ext.dtp) != 0)
			fail(name, "ext go", "", "");
		M.activity = ACT_INACTIVE;
		if (dtrace_go(s.dtp) != 0)
			fail(name, "go", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		/* Both handles' ECBs were enabled at exec; ext's is second. */
		fire(0, "test:kernel:beta:entry", 1, VALS(N(1), AGG(0, 1)));
		rc = dtrace_consume_quiesced(s.dtp, s.out, &con, NULL);
		if (want_err(name, &s, rc, EOPNOTSUPP) == 0)
			pass(name);
		close_session(&ext);
	}
	close_session(&s);

	name = "quiesced-second-drainable";
	r_reset();
	if (r_open(&s, name, NULL, TRACE_PROG, 0) == 0) {
		M.fail_cmd = CMD(DTRACEIOC_DRAINABLE);
		M.fail_errno = EBUSY;
		M.fail_after = 1;
		rc = dtrace_consume_quiesced(s.dtp, s.out, &con, NULL);
		M.fail_cmd = 0;
		if (want_err(name, &s, rc, EBUSY) == 0 && M.bufsnaps == 0)
			pass(name);
		else if (M.bufsnaps != 0)
			fail(name, "bufsnaps", "0", "");
	}
	close_session(&s);

	name = "quiesced-consumer-abort";
	r_reset();
	probe_mode = 2;
	if (r_open(&s, name, NULL, TRACE_PROG, 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		rc = dtrace_consume_quiesced(s.dtp, s.out, &con, NULL);
		if (want_err(name, &s, rc, EDT_DIRABORT) == 0)
			pass(name);
	}
	close_session(&s);

	name = "quiesced-null-stream";
	r_reset();
	if (r_open(&s, name, NULL, TRACE_PROG, 0) == 0) {
		/* NULL callbacks never print, so no stream is needed. */
		dtrace_consumer_t quiet = { 0 };

		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		rc = dtrace_consume_quiesced(s.dtp, NULL, &quiet, NULL);
		if (rc != 0 || M.buf[0].offset != 0)
			fail(name, "drain", "0, drained", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		else
			pass(name);
	}
	close_session(&s);
}

/* ------------------------------------------------------------------ */
/* Flow indentation heuristics.                                         */

/*
 * Entry probes indent unless the previous record was a different ECB of
 * the same probe; a return unindents unless the next record (skipping
 * alignment filler) is a different ECB of the same probe, and the last
 * record of a buffer unindents.  Flow values: 0 entry, 1 return, 2 none.
 */
static void
case_flow_heuristics(void)
{
	const char *name = "flowindent-same-probe-and-filler";
	static const char *const opts[] = { "flowindent", NULL, NULL };
	struct session s;

	r_reset();
	log_flow = 1;
	if (r_open(&s, name, opts,
	    "test:kernel:alpha:entry { trace(arg0); } "
	    "test:kernel:alpha:entry { trace(arg0); } "
	    "test:kernel:beta:return { trace((int)arg0); trace((int)arg1); } "
	    "test:kernel:beta:return { trace((int)arg0); trace((int)arg1); } "
	    "test:kernel:beta:entry { trace(arg0); } "
	    "test:kernel:alpha:return { trace(arg0); }", 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		fire(0, "test:kernel:alpha:entry", 1, VALS(N(2)));
		fire(0, "test:kernel:beta:return", 0, VALS(N(3), N(4)));
		fire(0, "test:kernel:beta:return", 1, VALS(N(5), N(6)));
		fire(0, "test:kernel:beta:return", 0, VALS(N(7), N(8)));
		/*
		 * Three 20-byte records from offset 48 end at 108; the next
		 * record needs 8-byte alignment, so 108 holds filler.
		 */
		fire(0, "test:kernel:beta:entry", 0, VALS(N(9)));
		fire(0, "test:kernel:alpha:return", 0, VALS(N(10)));
		if (*(uint32_t *)(M.buf[0].data + 108) != DTRACE_EPIDNONE)
			fail(name, "model filler", "EPIDNONE at 108", "");
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X(" %16lld %16lld %8d %8d %8d %8d %8d %8d %16lld %16lld", 1LL,
		    2LL, 3, 4, 5, 6, 7, 8, 9LL, 10LL);
		check(name, &s, xend(),
		    "probe cpu=0 test:kernel:alpha:entry\n"
		    "flow 0 indent 0 prefix \" -> \"\nend-of-probe\n"
		    "probe cpu=0 test:kernel:alpha:entry\n"
		    "flow 2 indent 2 prefix \"| \"\nend-of-probe\n"
		    "probe cpu=0 test:kernel:beta:return\n"
		    "flow 2 indent 2 prefix \"| \"\nend-of-probe\n"
		    "probe cpu=0 test:kernel:beta:return\n"
		    "flow 2 indent 2 prefix \"| \"\nend-of-probe\n"
		    "probe cpu=0 test:kernel:beta:return\n"
		    "flow 1 indent 0 prefix \" <- \"\nend-of-probe\n"
		    "probe cpu=0 test:kernel:beta:entry\n"
		    "flow 0 indent 0 prefix \" -> \"\nend-of-probe\n"
		    "probe cpu=0 test:kernel:alpha:return\n"
		    "flow 1 indent 0 prefix \" <- \"\nend-of-probe\n");
	}
	close_session(&s);

	/*
	 * Names ending in "-entry"/"-return" participate; "carpentry" does
	 * not; the syscall provider uses the double arrows.
	 */
	name = "flowindent-names";
	r_reset();
	log_flow = 1;
	if (r_open(&s, name, opts,
	    "test:kernel:beta:entry { trace(arg0); } "
	    "test:kernel:beta:return { trace(arg0); } "
	    "test:kernel:alpha:return { trace(arg0); }", 0) == 0) {
		r_rename[0].id = 6;
		r_rename[0].prov = "syscall";
		r_rename[0].name = "method-entry";
		r_rename[1].id = 7;
		r_rename[1].prov = "test";
		r_rename[1].name = "carpentry";
		r_rename[2].id = 5;
		r_rename[2].prov = "syscall";
		r_rename[2].name = "fn-return";
		fire(0, "test:kernel:beta:entry", 0, VALS(N(1)));
		fire(0, "test:kernel:beta:return", 0, VALS(N(2)));
		fire(0, "test:kernel:alpha:return", 0, VALS(N(3)));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X(" %16lld %16lld %16lld", 1LL, 2LL, 3LL);
		check(name, &s, xend(),
		    "probe cpu=0 syscall:kernel:beta:method-entry\n"
		    "flow 0 indent 0 prefix \" => \"\nend-of-probe\n"
		    "probe cpu=0 test:kernel:beta:carpentry\n"
		    "flow 2 indent 2 prefix \"| \"\nend-of-probe\n"
		    "probe cpu=0 syscall:kernel:alpha:fn-return\n"
		    "flow 1 indent 0 prefix \" <= \"\nend-of-probe\n");
	}
	close_session(&s);

	/* A return followed by an EPID the kernel never issued. */
	name = "flowindent-bad-next-epid";
	r_reset();
	if (r_open(&s, name, opts, "test:kernel:alpha:return { trace(arg0); }",
	    0) == 0) {
		dtrace_rechdr_t h = { 77, 0, 1 };
		uint64_t pad = 0;

		fire(0, "test:kernel:alpha:return", 0, VALS(N(1)));
		raw(0, &h, sizeof (h));
		raw(0, &pad, 4);
		if (want_err(name, &s, consume(&s), EINVAL) == 0)
			pass(name);
	}
	close_session(&s);
}

/* ------------------------------------------------------------------ */
/* Library actions with malformed record descriptions.                 */

/* The ith record (action) of the nth ECB of a probe. */
static dtrace_recdesc_t *
recn(const char *desc, int nth, int i)
{
	struct mset *set = &M.set[M.ecb[find_ecb(desc, nth)].set];

	assert(i < set->nact);
	return (&set->act[i].rec);
}

/* Drop the trailing records of an ECB from what EPROBE reports. */
static void
truncate_ecb(const char *desc, int nth, int nact)
{
	struct mset *set = &M.set[M.ecb[find_ecb(desc, nth)].set];

	set->nact = nact;
}

#define	NORM_PROG \
	"test:::entry { @s[probefunc] = sum(arg0); } " \
	"test:kernel:alpha:return { normalize(@s, 2); printa(@s); }"
#define	TRUNC_PROG \
	"test:::entry { @s[probefunc] = sum(arg0); } " \
	"test:kernel:alpha:return { trunc(@s, -1); printa(@s); }"
/* 64-bit arguments (D's integer constants are 32-bit ints). */
#define	NORM_PROG64 \
	"test:::entry { @s[probefunc] = sum(arg0); } " \
	"test:kernel:alpha:return { normalize(@s, arg1); printa(@s); }"
#define	TRUNC_PROG64 \
	"test:::entry { @s[probefunc] = sum(arg0); } " \
	"test:kernel:alpha:return { trunc(@s, arg1); printa(@s); }"

enum { T_NONE, T_SIZE0, T_SIZE1, T_ACTION, T_ARG, T_LAST, T_SIZE4,
    T_SIZE2, T_SIZE1B };

/*
 * normalize() and trunc() each record the aggregation ID (8 bytes) and the
 * argument, both as library actions.  The argument may be 1, 2, 4 or 8
 * bytes (trunc's is signed); anything else, a wrong action or argument
 * kind on the second record, or a missing second record is rejected.
 * @s holds alpha=12 and beta=30 (sums); normalize by 2 prints 6 and 15,
 * trunc(@s, -1) keeps only the smallest (alpha).
 */
static void
case_libact_records(void)
{
	static const struct {
		const char *name, *prog;
		int tamper, err;
		const char *out;
	} cases[] = {
		/* err: 1 EDT_BADNORMAL, 2 EDT_BADTRUNC */
		{ "normalize-u64", NORM_PROG64, T_NONE, 0, "6 15" },
		{ "trunc-s64-negative", TRUNC_PROG64, T_NONE, 0, "12" },
		{ "normalize-u32", NORM_PROG, T_SIZE4, 0, "6 15" },
		{ "normalize-u16", NORM_PROG, T_SIZE2, 0, "6 15" },
		{ "normalize-u8", NORM_PROG, T_SIZE1B, 0, "6 15" },
		{ "normalize-bad-id-size", NORM_PROG, T_SIZE0, 1, NULL },
		{ "normalize-bad-value-size", NORM_PROG, T_SIZE1, 1, NULL },
		{ "normalize-bad-action", NORM_PROG, T_ACTION, 1, NULL },
		{ "normalize-bad-arg", NORM_PROG, T_ARG, 1, NULL },
		{ "normalize-missing-value", NORM_PROG, T_LAST, 1, NULL },
		{ "trunc-s64", TRUNC_PROG, T_NONE, 0, "12" },
		{ "trunc-s32", TRUNC_PROG, T_SIZE4, 0, "12" },
		{ "trunc-s16", TRUNC_PROG, T_SIZE2, 0, "12" },
		{ "trunc-s8", TRUNC_PROG, T_SIZE1B, 0, "12" },
		{ "trunc-bad-id-size", TRUNC_PROG, T_SIZE0, 2, NULL },
		{ "trunc-bad-value-size", TRUNC_PROG, T_SIZE1, 2, NULL },
		{ "trunc-bad-action", TRUNC_PROG, T_ACTION, 2, NULL },
		{ "trunc-bad-arg", TRUNC_PROG, T_ARG, 2, NULL },
		{ "trunc-missing-value", TRUNC_PROG, T_LAST, 2, NULL },
	};
	static const char *const opts[] = { "quiet", NULL, NULL };
	size_t i;

	for (i = 0; i < sizeof (cases) / sizeof (cases[0]); i++) {
		const char *name = cases[i].name;
		struct session s;
		const char *ret = "test:kernel:alpha:return";
		int rc;

		r_reset();
		if (r_open(&s, name, opts, cases[i].prog, 0) != 0) {
			close_session(&s);
			continue;
		}
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), S("alpha"),
		    AGG(12, 1)));
		fire(1, "test:kernel:beta:entry", 0, VALS(N(1), S("beta"),
		    AGG(30, 1)));
		switch (cases[i].tamper) {
		case T_SIZE0:
			/* dtrace_aggvarid_t is 8 bytes. */
			recn(ret, 0, 0)->dtrd_size = 4;
			break;
		case T_SIZE1:
			recn(ret, 0, 1)->dtrd_size = 3;
			break;
		case T_SIZE4:
			recn(ret, 0, 1)->dtrd_size = 4;
			break;
		case T_SIZE2:
			recn(ret, 0, 1)->dtrd_size = 2;
			break;
		case T_SIZE1B:
			recn(ret, 0, 1)->dtrd_size = 1;
			break;
		case T_ACTION:
			recn(ret, 0, 1)->dtrd_action = DTRACEACT_DIFEXPR;
			break;
		case T_ARG:
			recn(ret, 0, 1)->dtrd_arg = DT_ACT_CLEAR;
			break;
		case T_LAST:
			truncate_ecb(ret, 0, 1);
			break;
		}
		if (cases[i].tamper == T_LAST)
			fire(0, ret, 0, VALS(N(1)));
		else
			fire(0, ret, 0, VALS(N(1), N(strcmp(cases[i].prog,
			    TRUNC_PROG) == 0 || strcmp(cases[i].prog,
			    TRUNC_PROG64) == 0 ? -1 : 2), N(1)));
		if (dtrace_aggregate_snap(s.dtp) != 0)
			fail(name, "snap", "", "");
		rc = consume(&s);
		if (cases[i].err != 0) {
			if (want_err(name, &s, rc, cases[i].err == 1 ?
			    EDT_BADNORMAL : EDT_BADTRUNC) == 0)
				pass(name);
		} else {
			char want[256];
			long long a, b;

			if (rc != 0) {
				fail(name, "consume", "", dtrace_errmsg(s.dtp,
				    dtrace_errno(s.dtp)));
			} else {
				xbegin();
				if (sscanf(cases[i].out, "%lld %lld", &a,
				    &b) == 2)
					X("\n  %-50s %16lld\n  %-50s %16lld\n",
					    "alpha", a, "beta", b);
				else
					X("\n  %-50s %16lld\n", "alpha", a);
				snprintf(want, sizeof (want), "%s", xend());
				check(name, &s, want, NULL);
			}
		}
		close_session(&s);
	}
}

/*
 * setopt() records the option and its value as two library actions; a
 * value record of at most 8 bytes means "set" and is passed as "1".  A
 * missing or mismatched value record is EDT_BADSETOPT; a setopt handler
 * that aborts, or an error handler that aborts on a refused option, fails
 * the consume.  Unknown library actions are ignored.
 */
static void
case_setopt_records(void)
{
	const char *name;
	struct session s;
	const char *ent = "test:kernel:alpha:entry";
	int t;

	for (t = 0; t < 3; t++) {
		name = t == 0 ? "setopt-missing-value" : t == 1 ?
		    "setopt-value-action" : "setopt-value-arg";
		r_reset();
		if (r_open(&s, name, NULL,
		    "test:kernel:alpha:entry { setopt(\"quiet\"); }", 0) != 0) {
			close_session(&s);
			continue;
		}
		if (t == 0) {
			truncate_ecb(ent, 0, 1);
			fire(0, ent, 0, VALS(S("quiet")));
		} else {
			if (t == 1)
				recn(ent, 0, 1)->dtrd_action =
				    DTRACEACT_DIFEXPR;
			else
				recn(ent, 0, 1)->dtrd_arg = DT_ACT_TRUNC;
			fire(0, ent, 0, VALS(S("quiet"), N(0)));
		}
		if (want_err(name, &s, consume(&s), EDT_BADSETOPT) == 0)
			pass(name);
		close_session(&s);
	}

	name = "setopt-handler-abort";
	r_reset();
	setopt_mode = 1;
	if (r_open(&s, name, NULL,
	    "test:kernel:alpha:entry { setopt(\"quiet\"); trace(arg0); }",
	    RO_SETOPT) == 0) {
		fire(0, ent, 0, VALS(S("quiet"), N(0), N(5)));
		if (want_err(name, &s, consume(&s), EDT_DIRABORT) == 0)
			check(name, &s, "", "probe cpu=0 test:kernel:alpha:entry\n"
			    "setopt quiet -2 -> 1\n");
	}
	close_session(&s);

	name = "setopt-error-abort";
	r_reset();
	err_mode = 1;
	if (r_open(&s, name, NULL,
	    "test:kernel:alpha:entry { setopt(\"nosuchoption\", \"1\"); }",
	    0) == 0) {
		fire(0, ent, 0, VALS(S("nosuchoption"), S("1")));
		if (want_err(name, &s, consume(&s), EDT_ERRABORT) == 0)
			pass(name);
	}
	close_session(&s);

	/* An unknown library action (here: clear's ID record) is skipped. */
	name = "libact-unknown-ignored";
	r_reset();
	{
		static const char *const quiet[] = { "quiet", NULL, NULL };

		if (r_open(&s, name, quiet,
		    "test:kernel:alpha:entry { @s[probefunc] = sum(arg0); } "
		    "test:kernel:alpha:return { clear(@s); printa(@s); }",
		    0) == 0) {
			fire(0, ent, 0, VALS(N(1), S("alpha"), AGG(12, 1)));
			recn("test:kernel:alpha:return", 0, 0)->dtrd_arg = 9999;
			fire(0, "test:kernel:alpha:return", 0, VALS(N(1),
			    N(1)));
			if (dtrace_aggregate_snap(s.dtp) != 0 ||
			    consume(&s) != 0)
				fail(name, "consume", "", "");
			xbegin();
			X("\n  %-50s %16lld\n", "alpha", 12LL);
			check(name, &s, xend(), NULL);
		}
		close_session(&s);
	}
}

/*
 * ftruncate() empties the output file and rewinds it, so only output after
 * it remains; without a stream it is a no-op.
 */
static void
case_ftruncate(void)
{
	const char *name = "ftruncate-output";
	static const char *const opts[] = { "destructive", NULL, NULL };
	struct session s;
	FILE *fp;
	char buf[128];
	size_t n;

	r_reset();
	if (r_open(&s, name, opts, "test:kernel:alpha:entry { trace(arg0); } "
	    "test:kernel:alpha:return { ftruncate(); trace(arg0); }", 0) == 0) {
		fp = fopen("ftruncate.out", "w+");
		assert(fp != NULL);
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(5)));
		fire(0, "test:kernel:alpha:return", 0, VALS(N(0), N(6)));
		if (consume_fp(&s, fp) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		fflush(fp);
		rewind(fp);
		n = fread(buf, 1, sizeof (buf) - 1, fp);
		buf[n] = '\0';
		fclose(fp);
		xbegin();
		X(" %16lld", 6LL);
		if (same(name, "file", xend(), buf) == 0)
			pass(name);
	}
	close_session(&s);

	name = "ftruncate-no-stream";
	r_reset();
	if (r_open(&s, name, opts,
	    "test:kernel:alpha:return { ftruncate(); }", 0) == 0) {
		fire(0, "test:kernel:alpha:return", 0, VALS(N(0)));
		if (dtrace_consume(s.dtp, NULL, probe_cb, rec_cb, NULL) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		else
			check(name, &s, "", "probe cpu=0 "
			    "test:kernel:alpha:return\nend-of-probe\n");
	}
	close_session(&s);
}

/*
 * tracemem(addr, max, size) records the dynamic size before the bytes; the
 * dump shows min(size, max) bytes, or all of them for size 0.
 */
static void
case_tracemem_dynsize(void)
{
	static const struct { const char *name; int64_t size; int shown; }
	    cases[] = {
		{ "tracemem-dynsize-3", 3, 3 },
		{ "tracemem-dynsize-clamped", 100, 8 },
		{ "tracemem-dynsize-zero", 0, 8 },
	};
	static const char mem[8] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H' };
	size_t c;
	int i;

	for (c = 0; c < sizeof (cases) / sizeof (cases[0]); c++) {
		struct session s;

		r_reset();
		if (r_open(&s, cases[c].name, NULL,
		    "test:kernel:alpha:entry { tracemem(arg0, 8, arg1); }",
		    0) != 0) {
			close_session(&s);
			continue;
		}
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(cases[c].size),
		    B(mem, 8)));
		if (consume(&s) != 0)
			fail(cases[c].name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X("\n%11s", "");
		for (i = 0; i < 16; i++)
			X("  %c", "0123456789abcdef"[i]);
		X("  0123456789abcdef\n%5s%5x:", "", 0);
		for (i = 0; i < cases[c].shown; i++)
			X(" %02x", mem[i]);
		for (; i < 16; i++)
			X("   ");
		X("  %.*s\n", cases[c].shown, mem);
		check(cases[c].name, &s, xend(), NULL);
		close_session(&s);
	}
}

/*
 * Records of a printf() whose format the kernel cannot name (format 0) are
 * consumed as plain data: each prints as trace() would.  Every argument of
 * a printf() is its own PRINTF record carrying the format.
 */
static void
case_printf_noformat(void)
{
	const char *name = "printf-unknown-format";
	struct session s;

	r_reset();
	if (r_open(&s, name, NULL,
	    "test:kernel:alpha:entry { printf(\"%d %d\\n\", arg0, arg1); }",
	    0) == 0) {
		recn("test:kernel:alpha:entry", 0, 0)->dtrd_format = 0;
		recn("test:kernel:alpha:entry", 0, 1)->dtrd_format = 0;
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(4), N(9)));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X(" %16lld %16lld", 4LL, 9LL);
		check(name, &s, xend(), NULL);
	}
	close_session(&s);
}

/*
 * freopen() redirects later output to a file and freopen("") restores the
 * caller's stream; system() runs a command.
 */
static void
case_freopen_system(void)
{
	const char *name = "freopen-and-system";
	static const char *const opts[] = { "destructive", NULL, "quiet", NULL,
	    NULL };
	struct session s;
	FILE *fp;
	char buf[64];
	size_t n;

	(void) unlink("freopen.out");
	(void) unlink("system.out");
	r_reset();
	if (r_open(&s, name, opts, "test:kernel:alpha:entry { "
	    "freopen(\"freopen.out\"); printf(\"%d\\n\", arg0); "
	    "freopen(\"\"); printf(\"%d\\n\", arg1); "
	    "system(\"echo ran > system.out\"); }", 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(0), N(11), N(0),
		    N(22), N(0)));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		fp = fopen("freopen.out", "r");
		n = fp != NULL ? fread(buf, 1, sizeof (buf) - 1, fp) : 0;
		buf[n] = '\0';
		if (fp != NULL)
			fclose(fp);
		if (same(name, "redirected", "11\n", buf) == 0) {
			fp = fopen("system.out", "r");
			n = fp != NULL ? fread(buf, 1, sizeof (buf) - 1, fp) :
			    0;
			buf[n] = '\0';
			if (fp != NULL)
				fclose(fp);
			if (same(name, "system", "ran\n", buf) == 0)
				check(name, &s, "22\n", NULL);
		}
	}
	close_session(&s);
}

/*
 * Kernel stack records carry frames of rec size / depth bytes: 4-byte
 * frames are read as 32-bit PCs, other sizes and a zero depth are
 * EDT_BADSTACKPC.  stackindent sets the frame indent.
 */
static void
case_stack_frames(void)
{
	const char *name;
	struct session s;
	static const char *const indent[] = { "stackindent", "3", NULL };
	uint32_t pcs32[6] = { 0x1010, 0x2000, 0 };
	int t;

	name = "stack-32bit-frames";
	r_reset();
	if (r_open(&s, name, indent, "test:kernel:alpha:entry { stack(3); }",
	    0) == 0) {
		recn("test:kernel:alpha:entry", 0, 0)->dtrd_size = 12;
		fire(0, "test:kernel:alpha:entry", 0, VALS(B(pcs32, 24)));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		check(name, &s, "\n   0x1010\n   0x2000\n", NULL);
	}
	close_session(&s);

	for (t = 0; t < 2; t++) {
		name = t == 0 ? "stack-bad-frame-size" : "stack-zero-depth";
		r_reset();
		if (r_open(&s, name, NULL,
		    "test:kernel:alpha:entry { stack(3); }", 0) == 0) {
			dtrace_recdesc_t *r = recn("test:kernel:alpha:entry",
			    0, 0);

			if (t == 0)
				r->dtrd_size = 6;
			else
				r->dtrd_arg = 0;
			fire(0, "test:kernel:alpha:entry", 0, VALS(B(pcs32,
			    24)));
			if (want_err(name, &s, consume(&s), EDT_BADSTACKPC) ==
			    0)
				pass(name);
		}
		close_session(&s);
	}
}

/* ------------------------------------------------------------------ */
/* Cases that may crash the library run in a child process.             */

#include <sys/wait.h>

static void
run_forked(const char *name, void (*fn)(void))
{
	pid_t pid;
	int status;

	fflush(stdout);
	if ((pid = fork()) == 0) {
		failures = passes = 0;
		fn();
		fflush(stdout);
		/* exit(), not _exit(): the child's coverage profile counts. */
		exit(failures != 0 ? 1 : 0);
	}
	assert(pid > 0);
	(void) waitpid(pid, &status, 0);
	if (WIFSIGNALED(status)) {
		char buf[64];

		snprintf(buf, sizeof (buf), "signal %d\n", WTERMSIG(status));
		fail(name, "child", "normal exit", buf);
	} else if (WEXITSTATUS(status) != 0) {
		failures++;	/* the child printed its FAIL lines */
	} else {
		passes++;	/* the child printed its PASS lines */
	}
}

/* ------------------------------------------------------------------ */
/* Histogram rendering.                                                 */

int dt_print_quantize(dtrace_hdl_t *, FILE *, const void *, size_t,
    uint64_t);
int dt_print_quantize_packed(dtrace_hdl_t *, FILE *, const void *, size_t,
    const dtrace_aggdata_t *);
int dt_print_lquantize(dtrace_hdl_t *, FILE *, const void *, size_t,
    uint64_t);
int dt_print_lquantize_packed(dtrace_hdl_t *, FILE *, const void *, size_t,
    const dtrace_aggdata_t *);
int dt_print_llquantize(dtrace_hdl_t *, FILE *, const void *, size_t,
    uint64_t);
int dt_format_quantize(dtrace_hdl_t *, const void *, size_t, uint64_t);
int dt_format_lquantize(dtrace_hdl_t *, const void *, size_t, uint64_t);
int dt_format_llquantize(dtrace_hdl_t *, const void *, size_t, uint64_t);
uint64_t dt_stddev(uint64_t *, uint64_t);

#define	QBUCKETS	DTRACE_QUANTIZE_NBUCKETS

/*
 * Every histogram printer validates the record size against the encoded
 * parameters (EDT_DMISMATCH): quantize needs exactly 127 buckets; lquantize
 * needs its parameter word plus levels + 2 buckets; llquantize needs
 * factor >= 2, low < high, 0 < nsteps, factor <= nsteps, nsteps a multiple
 * of factor, a power of factor that nsteps divides, an order range whose
 * magnitudes fit in 64 bits, and exactly the bucket count that geometry
 * implies.
 */
static void
case_hist_mismatch(void)
{
	const char *name = "histogram-size-mismatch";
	struct session s;
	static int64_t data[QBUCKETS + 8];
	dtrace_aggdata_t ad;
	struct { const char *what; int rc; } r[64];
	int n = 0, i, bad = 0;
	uint64_t ok_ll;

	memset(&ad, 0, sizeof (ad));
	r_reset();
	if (r_open(&s, name, NULL, NULL, 0) != 0) {
		close_session(&s);
		return;
	}
	/* A refused option resets the handle's errno between calls. */
#define	TRY(desc, call) do {						\
	(void) dtrace_setopt(s.dtp, "nosuchoption", NULL);		\
	r[n].what = (desc);						\
	r[n].rc = (call) == -1 && dtrace_errno(s.dtp) == EDT_DMISMATCH;	\
	n++;								\
} while (0)
	TRY("quantize short", dt_print_quantize(s.dtp, s.out, data,
	    8 * (QBUCKETS - 1), 1));
	TRY("quantize packed short", dt_print_quantize_packed(s.dtp, s.out,
	    data, 8 * (QBUCKETS - 1), &ad));
	TRY("format quantize short", dt_format_quantize(s.dtp, data,
	    8 * (QBUCKETS - 1), 1));
	/* lquantize(x, 0, 4, 1): 4 levels, 6 buckets after the word. */
	data[0] = DTRACE_LQUANTIZE_STEPSHIFT ? (int64_t)
	    (((uint64_t)1 << DTRACE_LQUANTIZE_STEPSHIFT) |
	    ((uint64_t)4 << DTRACE_LQUANTIZE_LEVELSHIFT)) : 0;
	TRY("lquantize no word", dt_print_lquantize(s.dtp, s.out, data, 4,
	    1));
	TRY("lquantize levels", dt_print_lquantize(s.dtp, s.out, data,
	    8 * 6, 1));
	TRY("lquantize packed no word", dt_print_lquantize_packed(s.dtp,
	    s.out, data, 4, &ad));
	TRY("lquantize packed levels", dt_print_lquantize_packed(s.dtp,
	    s.out, data, 8 * 6, &ad));
	TRY("format lquantize no word", dt_format_lquantize(s.dtp, data, 4,
	    1));
	TRY("format lquantize levels", dt_format_lquantize(s.dtp, data,
	    8 * 6, 1));
	/*
	 * llquantize(x, 10, 0, 2, 10): orders 0..2 have 9 + 9 + 9 buckets
	 * of width 1, 10, 100, plus the underflow and overflow buckets: 29.
	 */
#define	LLQ(f, l, h, n)	((uint64_t)(f) << DTRACE_LLQUANTIZE_FACTORSHIFT | \
	(uint64_t)(l) << DTRACE_LLQUANTIZE_LOWSHIFT | \
	(uint64_t)(h) << DTRACE_LLQUANTIZE_HIGHSHIFT | \
	(uint64_t)(n) << DTRACE_LLQUANTIZE_NSTEPSHIFT)
	ok_ll = LLQ(10, 0, 2, 10);
	data[0] = ok_ll;
	TRY("llquantize no word", dt_print_llquantize(s.dtp, s.out, data, 4,
	    1));
	TRY("llquantize odd size", dt_print_llquantize(s.dtp, s.out, data,
	    8 * 30 + 4, 1));
	TRY("llquantize huge size", dt_print_llquantize(s.dtp, s.out, data,
	    (size_t)INT32_MAX + 16, 1));
	TRY("llquantize bucket count", dt_print_llquantize(s.dtp, s.out,
	    data, 8 * 29, 1));
	data[0] = LLQ(1, 0, 2, 10);
	TRY("llquantize factor < 2", dt_print_llquantize(s.dtp, s.out, data,
	    8 * 30, 1));
	data[0] = LLQ(10, 2, 2, 10);
	TRY("llquantize low >= high", dt_print_llquantize(s.dtp, s.out,
	    data, 8 * 30, 1));
	data[0] = LLQ(10, 0, 2, 0);
	TRY("llquantize nsteps 0", dt_print_llquantize(s.dtp, s.out, data,
	    8 * 30, 1));
	data[0] = LLQ(10, 0, 2, 5);
	TRY("llquantize factor > nsteps", dt_print_llquantize(s.dtp, s.out,
	    data, 8 * 30, 1));
	data[0] = LLQ(4, 0, 2, 6);
	TRY("llquantize nsteps % factor", dt_print_llquantize(s.dtp, s.out,
	    data, 8 * 30, 1));
	data[0] = LLQ(2, 0, 2, 6);
	TRY("llquantize power % nsteps", dt_print_llquantize(s.dtp, s.out,
	    data, 8 * 30, 1));
	data[0] = LLQ(10, 0, 30, 10);
	TRY("llquantize magnitude overflow", dt_print_llquantize(s.dtp,
	    s.out, data, 8 * 300, 1));
	data[0] = ok_ll;
	TRY("format llquantize bucket count", dt_format_llquantize(s.dtp,
	    data, 8 * 29, 1));
#undef TRY
	for (i = 0; i < n; i++) {
		if (!r[i].rc) {
			fail(name, r[i].what, "-1 EDT_DMISMATCH", "accepted\n");
			bad = 1;
		}
	}
	fflush(s.out);
	if (!bad && same(name, "no output", "", s.text) == 0)
		pass(name);
	close_session(&s);
}

/*
 * Histograms without data (clear(), or increments that cancel) print the
 * buckets around zero: quantize -1, 0, 1; lquantize the underflow bucket
 * and the first two levels; llquantize the underflow bucket and the
 * first bucket.
 */
static void
case_hist_empty(void)
{
	const char *name = "histogram-empty";
	static const char *const quiet[] = { "quiet", NULL, NULL };
	struct session s;
	const char *bar = "|                                         0        \n";
	const char *hdr = "\n           value  ------------- Distribution "
	    "------------- count    \n";

	r_reset();
	if (r_open(&s, name, quiet, "test:kernel:alpha:entry { "
	    "@q = quantize(arg0); @l = lquantize(arg0, 10, 20, 5); "
	    "@ll = llquantize(arg0, 10, 1, 2, 10); }", 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), AGG(7, 1),
		    N(2), AGG(12, 1), N(3), AGG(50, 1)));
		if (dtrace_aggregate_snap(s.dtp) != 0)
			fail(name, "snap", "", "");
		dtrace_aggregate_clear(s.dtp);
		if (dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
			fail(name, "print", "", "");
		xbegin();
		X("%s%16d %s%16d %s%16d %s\n", hdr, -1, bar, 0, bar, 1, bar);
		X("%s%16s %s%16d %s%16d %s\n", hdr, "< 10", bar, 10, bar, 15,
		    bar);
		X("%s%16s %s%16d %s\n", hdr, "< 10", bar, 10, bar);
		check(name, &s, xend(), NULL);
	}
	close_session(&s);
}

/* Append n copies of the UTF-8 encoding of code point cp. */
static void
xutf8(unsigned cp, int n)
{
	while (n-- > 0)
		X("%c%c%c", 0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f),
		    0x80 | (cp & 0x3f));
}

/*
 * With encoding=utf8 a positive-only histogram draws 40 columns of U+2588
 * full blocks scaled by count / total, then one partial block for the
 * remaining eighths: U+258F is one eighth ... U+2589 seven eighths.
 * Counts 1 and 2 (total 3): 40/3 = 13 full + 2/8 (U+258E); 80/3 = 26
 * full + 5/8 (U+258B).
 */
static void
case_hist_utf8(void)
{
	const char *name = "histogram-utf8-partial-blocks";
	static const char *const opts[] = { "encoding", "utf8", NULL };
	struct session s;
	int i;

	r_reset();
	if (r_open(&s, name, opts, "test:kernel:alpha:entry { "
	    "@q = quantize(arg0); }", 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), AGG(1, 1)));
		for (i = 0; i < 2; i++)
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(1),
			    AGG(2, 1)));
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
			fail(name, "print", "", "");
		xbegin();
		X("\n%16s %41s %-9s\n", "value",
		    "------------- Distribution -------------", "count");
		X("%16d |%40s %-9d\n", 0, "", 0);
		X("%16d |", 1);
		xutf8(0x2588, 13);
		xutf8(0x258e, 1);
		X("%26s %-9d\n", "", 1);
		X("%16d |", 2);
		xutf8(0x2588, 26);
		xutf8(0x258b, 1);
		X("%13s %-9d\n", "", 2);
		X("%16d |%40s %-9d\n", 4, "", 0);
		X("\n");
		check(name, &s, xend(), NULL);
	}
	close_session(&s);
}

/*
 * dt_stddev() against exact 128-bit arithmetic: for n values with sum S
 * and sum of squares Q, normalized by k, the result is
 * isqrt(floor(Q / k^2 / n) - trunc(S / k / n)^2).
 */
static unsigned __int128
isqrt128(unsigned __int128 v)
{
	unsigned __int128 lo = 0, hi = (unsigned __int128)1 << 64, mid;

	while (lo < hi) {
		mid = lo + (hi - lo + 1) / 2;
		if (mid * mid <= v)
			lo = mid;
		else
			hi = mid - 1;
	}
	return (lo);
}

static void
case_stddev_property(void)
{
	const char *name = "stddev-128bit-property";
	uint64_t state = 0x5b5d20261021ULL;
	int t, bad = 0;

	/*
	 * The second half uses values near 2^62..2^63 (at most three, so
	 * that the sum of squares fits in 128 bits and the sum in 64), so
	 * the square root's partial results exceed 64 bits.
	 */
	for (t = 0; t < 8000 && !bad; t++) {
		uint64_t d[4], k;
		int64_t sum = 0;
		unsigned __int128 q = 0, ref, avgsq;
		int64_t avg;
		int n, i, shift;

#define	RND()	(state = state * 6364136223846793005ULL + \
		    1442695040888963407ULL, state >> 11)
		if (t < 4000) {
			n = 1 + RND() % 40;
			shift = RND() % 46;
		} else {
			n = 1 + RND() % 3;
			shift = 61;
		}
		/* Extremes: +-(2^63 - 1) pairs give a root near 2^63. */
		if (t >= 4000 && t < 4007)
			n = 2;
		for (i = 0; i < n; i++) {
			int64_t v;

			if (t >= 4000 && t < 4007) {
				/*
				 * (first, second) pairs near the extremes.  The
				 * last wraps the 64-bit sum to 0, as the
				 * kernel's sum does: the variance is then 2^126
				 * and the root 2^63.
				 */
				static const int64_t ex[7][2] = {
					{ INT64_MAX, -INT64_MAX },
					{ INT64_MAX, -3 },
					{ INT64_MIN, 0 },
					{ INT64_MIN, INT64_MAX },
					{ INT64_MIN, 1 },
					{ -INT64_MAX, 3 },
					{ INT64_MIN, INT64_MIN },
				};

				v = ex[t - 4000][i];
				sum = (int64_t)((uint64_t)sum + (uint64_t)v);
				q += (unsigned __int128)((__int128)v * v);
				continue;
			} else if (t < 4000)
				v = (int64_t)(RND() % ((1ULL << shift) + 1));
			else {
				uint64_t lo = RND() % (1ULL << 61);
				uint64_t top = RND() & 1 ? (1ULL << 62) : 0;

				v = (int64_t)((1ULL << 61) + lo + top);
			}
			if (RND() & 1)
				v = -v;
			/* Keep the sum within int64_t, as the kernel's is. */
			if ((v > 0 && sum > INT64_MAX - v) ||
			    (v < 0 && sum < INT64_MIN - v))
				v = -v;
			sum += v;
			q += (unsigned __int128)((__int128)v * v);
		}
		k = 1 + (t % 3 == 0 ? RND() % 1000 : 0);
		d[0] = n;
		d[1] = (uint64_t)sum;
		d[2] = (uint64_t)q;
		d[3] = (uint64_t)(q >> 64);
		avgsq = q / k / k / (unsigned)n;
		avg = sum / (int64_t)k / n;
		if (avg < 0)
			avg = -avg;
		ref = isqrt128(avgsq - (unsigned __int128)avg * avg);
		if (dt_stddev(d, k) != (uint64_t)ref) {
			char buf[160];

			snprintf(buf, sizeof (buf), "n %d sum %lld k %llu: "
			    "got %llu want %llu\n", n, (long long)sum,
			    (unsigned long long)k,
			    (unsigned long long)dt_stddev(d, k),
			    (unsigned long long)ref);
			fail(name, "stddev", "", buf);
			bad = 1;
		}
#undef RND
	}
	if (!bad) {
		uint64_t zero[4] = { 0, 0, 0, 0 };

		if (dt_stddev(zero, 1) != 0)
			fail(name, "empty", "0", "");
		else
			pass(name);
	}
}

/*
 * aggpack header widths: quantize buckets one beyond the data on each side
 * (not beyond the table), labelled by the decimal width of their values
 * (at least 4).  With data in the lowest and highest buckets the labels
 * are -4611686018427387904 (20 characters) and 4611686018427387904 (19).
 */
static void
case_aggpack_extremes(void)
{
	const char *name = "aggpack-extreme-buckets";
	static const char *const opts[] = { "aggpack", NULL, "encoding",
	    "ascii", NULL };
	struct session s;
	char *line;

	r_reset();
	if (r_open(&s, name, opts, "test:kernel:alpha:entry { "
	    "@q = quantize(arg0); }", 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1),
		    AGG(INT64_MIN, 1)));
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1),
		    AGG(INT64_MAX, 1)));
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
			fail(name, "print", "", "");
		fflush(s.out);
		xbegin();
		/* Header: no key, min label 20 wide, 127 dashes, max label. */
		X("\n %20s .", "min");
		{
			int i;

			for (i = 0; i < (int)QBUCKETS; i++)
				X("-");
		}
		X(". %-19s | count\n", "max");
		/*
		 * Data: each glyph is "__xxxxXX"[round(7 * count / total)];
		 * both extremes hold half the total (index 4, 'x') and the
		 * empty buckets between print blank.
		 */
		X(" %20lld :x%125sx: %-19lld | 2\n",
		    (long long)DTRACE_QUANTIZE_BUCKETVAL(0), "",
		    (long long)DTRACE_QUANTIZE_BUCKETVAL(QBUCKETS - 1));
		line = s.text;
		check(name, &s, xend(), NULL);
		(void) line;
	}
	close_session(&s);
}

/*
 * agghist draws one bar per key scaled by its share of the variable's
 * total.  For avg() and stddev() the drawn value is the average and the
 * standard deviation: alpha {2, 4} has avg 3 and stddev 1, beta {9} has
 * avg 9 and stddev 0.  avg totals 12 (bars 10 and 30 columns); stddev
 * totals 1 (alpha 40 columns, beta none).
 */
static void
agghist_avg_body(void)
{
	const char *name = "agghist-avg-stddev";
	static const char *const opts[] = { "agghist", NULL, "encoding",
	    "ascii", NULL };
	struct session s;
	static const struct { const char *f; int64_t v; } f[] = {
		{ "alpha", 2 }, { "alpha", 4 }, { "beta", 9 } };
	size_t i;

	r_reset();
	if (r_open(&s, name, opts, "test:kernel:alpha:entry { "
	    "@a[stringof(arg1)] = avg(arg0); @d[stringof(arg1)] = "
	    "stddev(arg0); }", 0) == 0) {
		for (i = 0; i < 3; i++) {
			struct val k = S("");

			k.bytes = f[i].f;
			k.len = strlen(f[i].f) + 1;
			fire(0, "test:kernel:alpha:entry", 0, (const struct
			    val[]){ N(1), k, AGG(f[i].v, 1), N(2), k,
			    AGG(f[i].v, 1) }, 6);
		}
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
			fail(name, "print", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X("\n%17s %41s %-9s\n", "key",
		    "------------- Distribution -------------", "count");
		X(" %16s |%.10s%30s %-9d\n", "alpha",
		    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@", "", 3);
		X(" %16s |%.30s%10s %-9d\n", "beta",
		    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@", "", 9);
		X("\n%17s %41s %-9s\n", "key",
		    "------------- Distribution -------------", "count");
		X(" %16s |%40s %-9d\n", "beta", "", 0);
		X(" %16s |%.40s %-9d\n", "alpha",
		    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@", 1);
		check(name, &s, xend(), NULL);
	}
	close_session(&s);
}

static void
case_agghist_avg(void)
{
	run_forked("agghist-avg-stddev", agghist_avg_body);
}

/*
 * Aggregation keys of every symbolic kind print through the same record
 * printers as trace data: sym, mod, umod, ustack and immstack keys.
 */
static void
case_agg_symbolic_keys(void)
{
	const char *name = "aggregation-symbolic-keys";
	static const char *const opts[] = { "quiet", NULL, NULL };
	struct session s;
	uint64_t ust[1 + 2 + 1] = { 0, 0x400100, 0, 0 };
	uint64_t um[2] = { 0, 0x402000 };
	char imm[2 * 64];
	uint64_t off = 0x8;

	memset(imm, 0, sizeof (imm));
	strcpy(imm, "vm_fault");
	memcpy(imm + 16, &off, sizeof (off));
	r_reset();
	if (r_open(&s, name, opts, "test:kernel:alpha:entry { "
	    "@s[sym(arg0)] = count(); @m[mod(arg0)] = count(); "
	    "@u[umod(arg0)] = count(); @k[ustack(2)] = count(); "
	    "@i[immstack(2)] = count(); }", 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(
		    N(1), N(0xffffffff80001000ULL), AGG(0, 1),
		    N(2), N(0xffffffff90000010ULL), AGG(0, 1),
		    N(3), B(um, 16), AGG(0, 1),
		    N(4), B(ust, sizeof (ust)), AGG(0, 1),
		    N(5), B(imm, sizeof (imm)), AGG(0, 1)));
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
			fail(name, "print", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X("  %-50s %16d\n", "kernel`vm_fault", 1);
		X("  %-50s %16d\n", "zfs", 1);
		X("  %-50s %16d\n", "0x402000", 1);
		X("\n%14s0x400100\n %16d\n", "", 1);
		X("\n%14svm_fault+0x8\n %16d\n", "", 1);
		check(name, &s, xend(), NULL);
	}
	close_session(&s);
}

/*
 * Byte records: printable bytes then NULs print as a string (quiet: as is;
 * otherwise after two spaces); a NUL followed by more data is binary and
 * dumps; the dump and string forms are chosen per record.
 */
static void
case_bytes(void)
{
	static const char *const quiet[] = { "quiet", NULL, NULL };
	static const char str5[5] = { 'a', 'b', 'c', 0, 0 };
	static const char mixed[5] = { 'a', 'b', 0, 'c', 'd' };
	struct session s;
	const char *name;
	int i, q;

	for (q = 0; q < 2; q++) {
		name = q ? "bytes-string-quiet" : "bytes-string-and-binary";
		r_reset();
		if (r_open(&s, name, q ? quiet : NULL, "typedef char b5_t[5]; "
		    "test:kernel:alpha:entry { trace(*(b5_t *)arg0); "
		    "trace(*(b5_t *)arg1); }", 0) != 0) {
			close_session(&s);
			continue;
		}
		fire(0, "test:kernel:alpha:entry", 0, VALS(B(str5, 5),
		    B(mixed, 5)));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		/* Non-quiet strings use a width of -33. */
		if (q)
			X("abc");
		else
			X(" %s%*s", " ", -33, "abc");
		X("\n%11s", "");
		for (i = 0; i < 16; i++)
			X("  %c", "0123456789abcdef"[i]);
		X("  0123456789abcdef\n%5s%5x: 61 62 00 63 64", "", 0);
		for (i = 5; i < 16; i++)
			X("   ");
		X("  ab.cd\n");
		check(name, &s, xend(), NULL);
		close_session(&s);
	}
}

/* immstack() frames honour stackindent. */
static void
case_immstack_indent(void)
{
	const char *name = "immstack-stackindent";
	static const char *const opts[] = { "stackindent", "2", NULL };
	struct session s;
	char rec[2 * 64];
	uint64_t off = 0x20;

	memset(rec, 0, sizeof (rec));
	strcpy(rec, "zio_wait");
	memcpy(rec + 16, &off, sizeof (off));
	r_reset();
	if (r_open(&s, name, opts, "test:kernel:alpha:entry { immstack(2); }",
	    0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(B(rec,
		    sizeof (rec))));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		check(name, &s, "\n  zio_wait+0x20\n", NULL);
	}
	close_session(&s);
}

int dt_print_immstack(dtrace_hdl_t *, FILE *, const char *, caddr_t, int,
    int);

/*
 * dt_print_immstack() is exported for printf-style callers: a caller's
 * format replaces "%s" for each frame name; the offset follows as
 * "+0x%llx".  Entries are size / immstackframes bytes apart.
 */
static void
case_immstack_format(void)
{
	const char *name = "immstack-caller-format";
	struct session s;
	char rec[20 * 64];
	uint64_t off = 0x10;

	memset(rec, 0, sizeof (rec));
	strcpy(rec, "vm_fault");
	memcpy(rec + 16, &off, sizeof (off));
	r_reset();
	if (r_open(&s, name, NULL, TRACE_PROG, 0) == 0) {
		if (dt_print_immstack(s.dtp, s.out, "<%s>", rec, 20,
		    sizeof (rec)) != 0)
			fail(name, "print", "0", "");
		check(name, &s, "\n              <vm_fault>+0x10\n", NULL);
	}
	close_session(&s);
}

/*
 * An AGGDESC without the aggregation-ID key record (only the value) is
 * malformed kernel input: printing and structured formatting refuse it
 * with EDT_BADAGG instead of asserting.  Run in a child so that an
 * abort is reported as a failure.
 */
static void
value_only_body(int oformat)
{
	const char *name = oformat ? "aggdesc-value-only-oformat" :
	    "aggdesc-value-only";
	struct session s;
	FILE *json = NULL;
	int rc;

	r_reset();
	if (r_open(&s, name, NULL, "test:kernel:alpha:entry { @c = count(); }",
	    0) == 0) {
		r_value_only = 1;
		if (oformat) {
			json = fopen("/dev/null", "w");
			dtrace_set_outfp(json);
			xo_set_style(NULL, XO_STYLE_JSON);
			(void) dtrace_oformat_configure(s.dtp);
		}
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), AGG(0, 1)));
		if (dtrace_aggregate_snap(s.dtp) != 0)
			fail(name, "snap", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		rc = dtrace_aggregate_print(s.dtp, oformat ? NULL : s.out,
		    NULL);
		if (want_err(name, &s, rc, EDT_BADAGG) == 0)
			pass(name);
	}
	close_session(&s);
	if (json != NULL)
		fclose(json);
}

static void
value_only_print(void)
{
	value_only_body(0);
}

static void
value_only_format(void)
{
	value_only_body(1);
}

static void
case_aggdesc_value_only(void)
{
	run_forked("aggdesc-value-only", value_only_print);
	run_forked("aggdesc-value-only-oformat", value_only_format);
}

/* ustack() frames honour stackindent; annotations print bracketed. */
static void
case_ustack_indent(void)
{
	const char *name = "ustack-stackindent-annotation";
	static const char *const opts[] = { "stackindent", "1", NULL };
	struct session s;
	uint64_t ust[1 + 2 + 2];

	memset(ust, 0, sizeof (ust));
	ust[1] = 0x400100;
	ust[2] = 0x400200;
	memcpy(&ust[3], "x\0@later", 9);
	r_reset();
	if (r_open(&s, name, opts, "test:kernel:alpha:entry { ustack(2, 16); }",
	    0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(B(ust,
		    sizeof (ust))));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		check(name, &s, "\n 0x400100\n 0x400200\n   [ later ]\n", NULL);
	}
	close_session(&s);
}

/* ------------------------------------------------------------------ */
/* Buffer retrieval order and failures.                                 */

/*
 * dtrace_consume() honours switchrate (a second call within it takes no
 * snapshot), refuses an inactive handle, skips CPUs whose snapshot reports
 * ENOENT (unconfigured), and fails on any other snapshot error.
 */
static void
case_consume_paths(void)
{
	const char *name;
	struct session s;
	static const char *const slow[] = { "switchrate", "10s", NULL };
	unsigned before;

	name = "consume-switchrate";
	r_reset();
	if (r_open(&s, name, slow, TRACE_PROG, 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		if (consume(&s) != 0)
			fail(name, "first", "", "");
		before = M.bufsnaps;
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(2)));
		if (consume(&s) != 0 || M.bufsnaps != before)
			fail(name, "second", "0, no snapshot", "");
		else {
			xbegin();
			X(" %16lld", 1LL);
			check(name, &s, xend(), NULL);
		}
	}
	close_session(&s);

	name = "consume-inactive";
	r_reset();
	if (r_open(&s, name, NULL, TRACE_PROG, RO_NOGO) == 0) {
		if (want_err(name, &s, consume(&s), EINVAL) == 0)
			pass(name);
	}
	close_session(&s);

	/* After the first pass the BEGIN CPU is no longer special. */
	name = "consume-snapshot-error";
	r_reset();
	if (r_open(&s, name, NULL, TRACE_PROG, 0) == 0) {
		if (consume(&s) != 0)
			fail(name, "first", "", "");
		r_eio_cpu = 1;
		if (want_err(name, &s, consume(&s), EIO) == 0)
			pass(name);
	}
	close_session(&s);

	name = "consume-unconfigured-cpus";
	r_reset();
	if (r_open(&s, name, NULL, TRACE_PROG, 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		fire(1, "test:kernel:alpha:entry", 0, VALS(N(2)));
		/* The BEGIN CPU (0) is unconfigured: nothing from it. */
		r_enoent_cpu = 0;
		if (consume(&s) != 0)
			fail(name, "first", "", "");
		/* Now CPU 1 is unconfigured and CPU 0's record is read. */
		r_enoent_cpu = 1;
		fire(1, "test:kernel:beta:entry", 0, VALS(N(3)));
		if (consume(&s) != 0)
			fail(name, "second", "", "");
		xbegin();
		X(" %16lld %16lld", 2LL, 1LL);
		check(name, &s, xend(), NULL);
		if (M.buf[0].offset != 0 || M.buf[1].offset == 0)
			fail(name, "buffers", "cpu 0 drained, cpu 1 kept", "");
	}
	close_session(&s);

	/*
	 * Once stopped, the END CPU is read last; if it is unconfigured the
	 * pass ends after the other CPUs, and a snapshot error fails it.
	 */
	name = "consume-end-cpu-unconfigured";
	r_reset();
	if (r_open(&s, name, NULL, TRACE_PROG, 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		if (consume(&s) != 0 || dtrace_stop(s.dtp) != 0)
			fail(name, "first", "", "");
		r_enoent_cpu = M.endcpu;
		if (consume(&s) != 0)
			fail(name, "stopped", "", "");
		else {
			xbegin();
			X(" %16lld", 1LL);
			check(name, &s, xend(), NULL);
		}
	}
	close_session(&s);

	name = "consume-end-cpu-error";
	r_reset();
	if (r_open(&s, name, NULL, TRACE_PROG, 0) == 0) {
		if (consume(&s) != 0 || dtrace_stop(s.dtp) != 0)
			fail(name, "first", "", "");
		r_eio_cpu = M.endcpu;
		if (want_err(name, &s, consume(&s), EIO) == 0)
			pass(name);
	}
	close_session(&s);

	/* A drop handler that aborts fails the consume after the records. */
	name = "consume-drop-abort";
	r_reset();
	drop_mode = 1;
	{
		static const char *const small[] = { "bufsize", "64", NULL };

		if (r_open(&s, name, small, TRACE_PROG, 0) == 0) {
			int i;

			for (i = 1; i <= 3; i++)
				fire(0, "test:kernel:alpha:entry", 0,
				    VALS(N(i)));
			if (want_err(name, &s, consume(&s), EDT_DROPABORT) ==
			    0)
				check(name, &s, NULL,
				    "probe cpu=0 test:kernel:alpha:entry\n"
				    "end-of-probe\n"
				    "probe cpu=0 test:kernel:alpha:entry\n"
				    "end-of-probe\n"
				    "drop cpu=0 kind=0 n=1: 1 drop on CPU 0\n");
		}
		close_session(&s);
	}

	/* An error handler that aborts fails the consume at the ERROR. */
	name = "consume-error-abort";
	r_reset();
	err_mode = 1;
	if (r_open(&s, name, NULL, TRACE_PROG, 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		fire(0, "dtrace:::ERROR", 0, VALS(N(1), N(1), N(8),
		    N(DTRACEFLT_BADADDR), N(0x10)));
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(2)));
		if (want_err(name, &s, consume(&s), EDT_ERRABORT) == 0)
			check(name, &s, NULL,
			    "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n"
			    "error: error on enabled probe ID 1 (ID 4: "
			    "test:kernel:alpha:entry): invalid address (0x10) "
			    "in action #1 at DIF offset 8\n");
	}
	close_session(&s);
}

/*
 * Stopped with BEGIN and END on one CPU, consumption is BEGIN, the other
 * CPUs, then the rest of the BEGIN CPU; each stage's failure ends the
 * consume, and an unconfigured other CPU is skipped.
 */
static void
case_begin_paths(void)
{
	static const struct {
		const char *name, *abort_at;
		int enoent, eio, err;
		const char *events;
	} cases[] = {
		{ "begin-pass-abort", "BEGIN", -1, -1, 1,
		    "abort at :BEGIN\n" },
		{ "begin-other-cpu-error", NULL, -1, 1, 2,
		    "probe cpu=0 dtrace:::BEGIN\nend-of-probe\n" },
		{ "begin-other-cpu-unconfigured", NULL, 1, -1, 0,
		    "probe cpu=0 dtrace:::BEGIN\nend-of-probe\n"
		    "probe cpu=0 dtrace:::END\nend-of-probe\n" },
		{ "begin-other-cpu-abort", "alpha", -1, -1, 1,
		    "probe cpu=0 dtrace:::BEGIN\nend-of-probe\n"
		    "abort at alpha:entry\n" },
		{ "begin-rest-abort", "END", -1, -1, 1,
		    "probe cpu=0 dtrace:::BEGIN\nend-of-probe\n"
		    "probe cpu=1 test:kernel:alpha:entry\nend-of-probe\n"
		    "abort at :END\n" },
	};
	size_t i;

	for (i = 0; i < sizeof (cases) / sizeof (cases[0]); i++) {
		struct session s;
		int rc;

		r_reset();
		M.endcpu = 0;
		if (r_open(&s, cases[i].name, NULL,
		    "BEGIN { trace(1); } test:::entry { trace(arg0); } "
		    "END { trace(3); }", 0) != 0) {
			close_session(&s);
			continue;
		}
		fire(0, "dtrace:::BEGIN", 0, VALS(N(1)));
		fire(1, "test:kernel:alpha:entry", 0, VALS(N(20)));
		fire(0, "dtrace:::END", 0, VALS(N(3)));
		if (dtrace_stop(s.dtp) != 0)
			fail(cases[i].name, "stop", "", "");
		abort_on = cases[i].abort_at;
		r_enoent_cpu = cases[i].enoent;
		r_eio_cpu = cases[i].eio;
		rc = consume(&s);
		if (cases[i].err == 0 ? rc != 0 : want_err(cases[i].name, &s,
		    rc, cases[i].err == 1 ? EDT_DIRABORT : EIO) != 0) {
			if (cases[i].err == 0)
				fail(cases[i].name, "consume", "0",
				    dtrace_errmsg(s.dtp, dtrace_errno(s.dtp)));
		} else
			check(cases[i].name, &s, NULL, cases[i].events);
		close_session(&s);
	}
}

/*
 * Temporal ordering interleaves CPUs by record time; drops are reported
 * per CPU after the records (a drop handler may abort); snapshot and
 * consumer failures end the pass; a CPU buffer holding only alignment
 * filler contributes nothing.
 */
static void
case_temporal_paths(void)
{
	const char *name;
	struct session s;
	static const char *const temporal[] = { "temporal", NULL, NULL };
	static const char *const small[] = { "temporal", NULL, "bufsize",
	    "64", NULL };
	int i, mode;

	for (mode = 0; mode < 2; mode++) {
		name = mode == 0 ? "temporal-drops" : "temporal-drop-abort";
		r_reset();
		drop_mode = mode;
		if (r_open(&s, name, small, TRACE_PROG, 0) != 0) {
			close_session(&s);
			continue;
		}
		for (i = 1; i <= 3; i++)
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(i)));
		fire(1, "test:kernel:beta:entry", 0, VALS(N(4)));
		if (mode == 0 ? consume(&s) != 0 : want_err(name, &s,
		    consume(&s), EDT_DROPABORT) != 0) {
			if (mode == 0)
				fail(name, "consume", "", dtrace_errmsg(s.dtp,
				    dtrace_errno(s.dtp)));
		} else {
			xbegin();
			X(" %16lld %16lld %16lld", 1LL, 2LL, 4LL);
			check(name, &s, xend(),
			    "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n"
			    "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n"
			    "probe cpu=1 test:kernel:beta:entry\nend-of-probe\n"
			    "drop cpu=0 kind=0 n=1: 1 drop on CPU 0\n");
		}
		close_session(&s);
	}

	name = "temporal-snapshot-error";
	r_reset();
	if (r_open(&s, name, temporal, TRACE_PROG, 0) == 0) {
		r_eio_cpu = 1;
		if (want_err(name, &s, consume(&s), EIO) == 0)
			pass(name);
	}
	close_session(&s);

	name = "temporal-consumer-abort";
	r_reset();
	if (r_open(&s, name, temporal, TRACE_PROG, 0) == 0) {
		fire(1, "test:kernel:alpha:entry", 0, VALS(N(1)));
		abort_on = "alpha";
		if (want_err(name, &s, consume(&s), EDT_DIRABORT) == 0)
			pass(name);
	}
	close_session(&s);

	/*
	 * CPU 1 holds only filler; after stopping, every remaining record is
	 * consumed in time order in one pass, then a later pass finds the
	 * retained (empty) buffers.
	 */
	name = "temporal-filler-and-stop";
	r_reset();
	if (r_open(&s, name, temporal, TRACE_PROG, 0) == 0) {
		uint32_t filler[2] = { DTRACE_EPIDNONE, DTRACE_EPIDNONE };

		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		fire(2, "test:kernel:alpha:entry", 0, VALS(N(2)));
		fire(0, "test:kernel:beta:entry", 0, VALS(N(3)));
		raw(1, filler, sizeof (filler));
		if (dtrace_stop(s.dtp) != 0 || consume(&s) != 0 ||
		    consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X(" %16lld %16lld %16lld", 1LL, 2LL, 3LL);
		check(name, &s, xend(),
		    "probe cpu=0 test:kernel:alpha:entry\nend-of-probe\n"
		    "probe cpu=2 test:kernel:alpha:entry\nend-of-probe\n"
		    "probe cpu=0 test:kernel:beta:entry\nend-of-probe\n");
	}
	close_session(&s);
}

/* ------------------------------------------------------------------ */
/* Buffered output.                                                     */

/*
 * With a buffered-output handler and no stream, every piece of output is
 * delivered to the handler; concatenated it equals what the same handle
 * state writes to a stream.  A handler that aborts at its Nth delivery
 * fails the operation with EDT_DIRABORT for every N.  Without a handler a
 * NULL stream is EDT_NOBUFFERED.
 */
static int
bsweep(const char *name, const char *const *opts, const char *prog,
    fire_f *fire_fn, print_f *print_fn, int expect_min)
{
	struct session s;
	char *stream = NULL;
	FILE *fp;
	size_t len;
	int total, k, rc, bad = 0;

	r_reset();
	if (r_open(&s, name, opts, prog, RO_BUFFERED) != 0) {
		close_session(&s);
		return (-1);
	}
	fire_fn(&s);
	save_bufs();
	/* Reference: the same state written to a stream (twice, see sweep). */
	for (k = 0; k < 2; k++) {
		restore_bufs();
		free(stream);
		stream = NULL;
		fp = open_memstream(&stream, &len);
		rc = print_fn(&s, fp);
		fclose(fp);
	}
	restore_bufs();
	free(bufout);
	bufout = strdup("");
	bufoutlen = 0;
	buf_calls = 0;
	rc |= print_fn(&s, NULL);
	total = buf_calls;
	if (rc != 0 || total < expect_min || strcmp(stream, bufout) != 0) {
		fail(name, "buffered equals stream", stream, bufout);
		bad = 1;
	}
	for (k = 1; k <= total && !bad; k++) {
		restore_bufs();
		buf_calls = 0;
		buf_mode = k;
		rc = print_fn(&s, NULL);
		if (rc != -1 || dtrace_errno(s.dtp) != EDT_DIRABORT ||
		    buf_calls != k) {
			char buf[160];

			snprintf(buf, sizeof (buf), "abort at %d of %d: rc %d "
			    "errno %d, %d deliveries\n", k, total, rc,
			    dtrace_errno(s.dtp), buf_calls);
			fail(name, "handler abort", "rc -1 EDT_DIRABORT", buf);
			bad = 1;
		}
	}
	buf_mode = 0;
	free(stream);
	free_saved();
	close_session(&s);
	if (!bad)
		pass(name);
	return (bad ? -1 : 0);
}

/* SWEEP_AGG_PROG without the formatted printa() (see below). */
#define	SWEEP_AGG_PROG_PLAIN \
	"typedef char b20_t[20]; " \
	"test:kernel:alpha:entry { @q[probefunc] = quantize(arg0); " \
	"@l[probefunc] = lquantize(arg0, -4, 4, 2); " \
	"@ll[probefunc] = llquantize(arg0, 10, 0, 2, 10); " \
	"@a[probefunc] = avg(arg0); @sd[probefunc] = stddev(arg0); " \
	"@s[probefunc] = sum(arg0); @c[probefunc] = count(); } " \
	"test:kernel:beta:entry { " \
	"@st[stack(2)] = count(); @u[usym(arg1)] = count(); " \
	"@sz[(char)arg0, (short)arg0, (int)arg0] = sum(arg0); " \
	"@by[*(b20_t *)arg2] = count(); } " \
	"test:kernel:alpha:return { printa(@q); printa(@s, @c); }"

static void
fire_aggs_plain(struct session *s)
{
	static const int64_t v[] = { -5, 0, 3, 3, 120 };
	uint64_t ua[2] = { 0, 0x401234 };
	static const char bin20[20] = { 1, 2, 3 };
	size_t i;

	for (i = 0; i < sizeof (v) / sizeof (v[0]); i++) {
		struct val fn = S("alpha");

		fire(i % 2, "test:kernel:alpha:entry", 0, VALS(
		    N(1), fn, AGG(v[i], 1), N(2), fn, AGG(v[i], 1),
		    N(3), fn, AGG(v[i], 1), N(4), fn, AGG(v[i], 1),
		    N(5), fn, AGG(v[i], 1),
		    N(6), fn, AGG(v[i], 1), N(7), fn, AGG(0, 1)));
		fire(i % 2, "test:kernel:beta:entry", 0, VALS(
		    N(8), B(K_PCS, 16), AGG(0, 1),
		    N(9), B(ua, 16), AGG(0, 1),
		    N(10), N(v[i]), N(v[i]), N(v[i]), AGG(v[i], 1),
		    N(11), B(bin20, 20), AGG(0, 1)));
	}
	fire(0, "test:kernel:alpha:return", 0, VALS(N(1), N(6), N(7)));
	if (dtrace_aggregate_snap(s->dtp) != 0)
		fail("fire-aggs", "snap", "", "");
}

/*
 * A formatted printa() of several aggregations whose buffered handler
 * aborts fails with EDT_DIRABORT at that delivery.  (This found that the
 * joined walk ignored DTRACE_AGGWALK_ABORT from dt_fprintas(); fixed in
 * the printf/aggregate code.)
 */
static void
buffered_printa_format_abort(void)
{
	const char *name = "buffered-printa-format-joined-abort";
	static const char *const quiet[] = { "quiet", NULL, NULL };
	struct session s;
	int rc;

	r_reset();
	if (r_open(&s, name, quiet, "test:::entry { @s[probefunc] = sum(arg0); "
	    "@c[probefunc] = count(); } test:kernel:alpha:return { "
	    "printa(\"%s %@d %@d\\n\", @s, @c); trace(arg0); }",
	    RO_BUFFERED) != 0) {
		close_session(&s);
		return;
	}
	fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), S("alpha"),
	    AGG(5, 1), N(2), S("alpha"), AGG(0, 1)));
	fire(0, "test:kernel:beta:entry", 0, VALS(N(1), S("beta"), AGG(7, 1),
	    N(2), S("beta"), AGG(0, 1)));
	if (dtrace_aggregate_snap(s.dtp) != 0)
		fail(name, "snap", "", "");
	fire(0, "test:kernel:alpha:return", 0, VALS(N(1), N(2), N(9)));
	buf_mode = 1;
	buf_calls = 0;
	rc = dtrace_consume(s.dtp, NULL, probe_cb, rec_cb, NULL);
	buf_mode = 0;
	if (rc == -1 && dtrace_errno(s.dtp) == EDT_DIRABORT && buf_calls == 1)
		pass(name);
	else {
		char buf[128];

		snprintf(buf, sizeof (buf), "rc %d errno %d, %d deliveries\n",
		    rc, dtrace_errno(s.dtp), buf_calls);
		fail(name, "abort", "rc -1 EDT_DIRABORT, 1 delivery", buf);
	}
	close_session(&s);
}

/*
 * print() with buffered output (a buffered handler and no stream)
 * delivers its text to the handler like every other record.  (This found
 * that dtrace_print() wrote to the NULL stream; fixed in dt_print.c.)
 * Run in a child so that a regression is reported, not fatal.
 */
static void
buffered_print_body(void)
{
	const char *name = "buffered-print-typed";
	struct session s;
	static const struct print_fixture pv = { 9, { 'o', 'k', 0, 0 }, 0,
	    0, 0, { 0 }, NULL };
	int rc;

	r_reset();
	if (r_open(&s, name, NULL, "struct pf { int a; char b[4]; long c; "
	    "unsigned int lo:3; unsigned int hi:5; void *p; }; "
	    "test:kernel:alpha:entry { print(*(struct pf *)arg0); }",
	    RO_BUFFERED) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(B(&pv,
		    sizeof (pv))));
		rc = dtrace_consume(s.dtp, NULL, probe_cb, rec_cb, NULL);
		if (rc == 0 && bufout != NULL &&
			    strstr(bufout, "int a = 0x9") != NULL)
			pass(name);
		else
			fail(name, "print", "struct text delivered", bufout);
	}
	close_session(&s);
}

static void
buffered_print_typed(void)
{
	pid_t pid;
	int status;

	fflush(stdout);
	if ((pid = fork()) == 0) {
		failures = 0;
		buffered_print_body();
		fflush(stdout);
		exit(failures != 0);
	}
	(void) waitpid(pid, &status, 0);
	if (WIFSIGNALED(status)) {
		char buf[64];

		snprintf(buf, sizeof (buf), "signal %d\n", WTERMSIG(status));
		fail("buffered-print-typed", "child", "exit", buf);
	} else if (WEXITSTATUS(status) != 0)
		failures++;
	else
		passes++;
}

static void
case_buffered(void)
{
	static const char *const quiet[] = { "quiet", NULL, NULL };
	struct session s;
	const char *name = "buffered-without-handler";

	bsweep("buffered-records", NULL, SWEEP_DATA_PROG, fire_data,
	    print_consume, 10);
	bsweep("buffered-records-quiet", quiet, SWEEP_DATA_PROG, fire_data,
	    print_consume, 10);
	buffered_print_typed();
	bsweep("buffered-aggregations", NULL, SWEEP_AGG_PROG_PLAIN,
	    fire_aggs_plain, print_consume_aggs, 10);
	buffered_printa_format_abort();

	r_reset();
	if (r_open(&s, name, NULL, TRACE_PROG, 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		if (want_err(name, &s, dtrace_consume(s.dtp, NULL, probe_cb,
		    rec_cb, NULL), EDT_NOBUFFERED) == 0)
			pass(name);
	}
	close_session(&s);
}

/* ------------------------------------------------------------------ */
/* Packed glyph selection (one choice per process).                     */

/*
 * aggpack glyphs: explicit encoding wins; otherwise TERM=sun, sun-color
 * and dumb select ASCII and anything else (or no TERM) UTF-8.  For
 * lquantize(x, 0, 2, 1) with bucket counts [<0]=0, [0]=2, [1]=-1, [>=2]=0
 * (total magnitude 3) the line is "     < 0 :", blank, the level for 2/3
 * (ASCII "__xxxxXX"[round(14/3)] = 'x', UTF-8 U+2581 + round(14/3) =
 * U+2586), the negative glyph "vvvvVV"[round(5/3)] = 'v', blank, then
 * ": >= 2     | 1".
 */
static void
case_packed_term(const char *encoding)
{
	const char *name = "aggpack-glyph-selection";
	const char *term = getenv("TERM");
	const char *opts[] = { "aggpack", NULL, "encoding", encoding, NULL };
	struct session s;
	int utf8;
	char *last;

	if (encoding == NULL)
		opts[2] = NULL;
	utf8 = encoding != NULL ? strcmp(encoding, "utf8") == 0 :
	    !(term != NULL && (strcmp(term, "sun") == 0 ||
	    strcmp(term, "sun-color") == 0 || strcmp(term, "dumb") == 0));
	r_reset();
	if (r_open(&s, name, opts, "test:kernel:alpha:entry { "
	    "@l = lquantize(arg0, 0, 2, 1, arg1); }", 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), N(0),
		    AGG(0, 2)));
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), N(0),
		    AGG(1, -1)));
		if (dtrace_aggregate_snap(s.dtp) != 0 ||
		    dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
			fail(name, "print", "", "");
		fflush(s.out);
		/* The data line is the last line. */
		s.text[strlen(s.text) - 1] = '\0';
		last = strrchr(s.text, '\n');
		xbegin();
		X("     < 0 : ");
		if (utf8)
			xutf8(0x2586, 1);
		else
			X("x");
		X("v : >= 2     | 1");
		if (last == NULL || same(name, utf8 ? "utf8 line" :
		    "ascii line", xend(), last + 1) == 0)
			pass(name);
	}
	close_session(&s);
}

/* ------------------------------------------------------------------ */
/* Structured output (checked as parsed JSON by consume-records.py).    */

static FILE *json_fp;

static void
json_begin(struct session *s, const char *file)
{
	json_fp = fopen(file, "w");
	assert(json_fp != NULL);
	xo_set_style(NULL, XO_STYLE_JSON);
	dtrace_set_outfp(json_fp);
	use_oformat = 1;
	if (dtrace_oformat_configure(s->dtp) != 0)
		fail(file, "configure", "", "");
	dtrace_oformat_setup(s->dtp);
}

/* Closing the handle finishes the document (xo_finish). */
static void
json_end(struct session *s)
{
	dtrace_oformat_teardown(s->dtp);
	close_session(s);
	xo_set_style(NULL, XO_STYLE_TEXT);
	dtrace_set_outfp(stdout);
	fclose(json_fp);
	json_fp = NULL;
	use_oformat = 0;
}

/*
 * Every record kind in structured output; the expected document is in
 * consume-records.py.  The beta ECB is a guest probe (stack argument
 * tagged with VM 9) firing with a guest user stack and address.
 */
static void
case_oformat_records(void)
{
	const char *name = "oformat-records";
	static const char *const opts[] = { "quiet", NULL, NULL };
	struct session s;
	static const uint64_t pcs[4] = { 0xffffffff80001010ULL,
	    0xffffffff80001000ULL, 0xffffffff90000400ULL, 0x1234 };
	static const uint64_t gpcs[2] = { 0xffffffff81000010ULL,
	    0xffffffff81000020ULL };
	static const char b5[5] = { 'a', 'b', 0, 'c', 'd' };
	static const char b20[20] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T' };
	static const char mem[20] = "0123456789abcdefghi";
	static const struct print_fixture pv = { 7, { 'x', 'y', 0, 0 }, 0,
	    0, 0, { 0 }, NULL };
	unsigned char pm[8 + 8] = { 4, 0, 0, 0, 0, 0, 0, 0, 'P', 'R', 'N',
	    'T' };
	uint64_t ust[1 + 3 + 2], gust[1 + 2];
	uint64_t ua[2] = { 0, 0x401234 }, um[2] = { 0, 0x402000 };
	uint64_t gua[2] = { HYPERTRACE_UADDR_ENCODE(7, 42), 0x401234 };
	struct mset *set;
	int i;

	memset(ust, 0, sizeof (ust));
	ust[1] = 0x400100;
	ust[2] = 0x400200;
	ust[3] = 0x400300;
	memcpy(&ust[4], "@ann\0\0@b\0", 9);
	gust[0] = HYPERTRACE_USTACK_ENCODE(7, 42);
	gust[1] = 0x500100;
	gust[2] = 0;
	r_reset();
	if (r_open(&s, name, opts, "typedef char b5_t[5]; "
	    "typedef char b20_t[20]; "
	    "struct pf { int a; char b[4]; long c; "
	    "unsigned int lo:3; unsigned int hi:5; void *p; }; "
	    "test:kernel:alpha:entry { stack(4); ustack(3, 16); sym(arg0); "
	    "mod(arg0); usym(arg0); umod(arg0); uaddr(arg0); "
	    "printm(4, (uintptr_t *)arg0); tracemem(arg0, 20); "
	    "trace((char)arg0); trace((short)arg0); trace((int)arg0); "
	    "trace(arg0); trace(*(b5_t *)arg1); trace(*(b20_t *)arg1); "
	    "trace(probefunc); printf(\"%d\\n\", arg0); "
	    "printf(\"100%%\\n\"); print(*(struct pf *)arg0); } "
	    "test:kernel:beta:entry { stack(2); ustack(2); uaddr(arg0); }",
	    0) != 0) {
		close_session(&s);
		return;
	}
	set = ecb_set("test:kernel:beta:entry");
	for (i = 0; i < set->nact; i++)
		if (set->act[i].kind == DTRACEACT_STACK)
			set->act[i].rec.dtrd_arg = HYPERTRACE_STACK_ENCODE(9, 2);
	json_begin(&s, "oformat-records.json");
	fire(0, "test:kernel:alpha:entry", 0, VALS(B(pcs, sizeof (pcs)),
	    B(ust, sizeof (ust)), N(0xffffffff90000400ULL), N(0x1234),
	    B(ua, 16), B(um, 16), B(gua, 16), B(pm, sizeof (pm)),
	    B(mem, 20), N(-3), N(-3), N(-3), N(-3), B(b5, 5), B(b20, 20),
	    S("alpha"), N(-3), N(0), B(&pv, sizeof (pv))));
	fire(1, "test:kernel:beta:entry", 0, VALS(B(gpcs, sizeof (gpcs)),
	    B(gust, sizeof (gust)), B(gua, 16)));
	if (consume(&s) != 0)
		fail(name, "consume", "", dtrace_errmsg(s.dtp,
		    dtrace_errno(s.dtp)));
	json_end(&s);
	/* consume-records.py reports PASS/FAIL from the document. */
	printf("WROTE %s\n", name);
}

/*
 * Aggregation tuples in structured output: integer keys of 1, 2 and 4
 * bytes, user stack/symbol/module/address keys, a binary key, min/max/sum
 * value names, llquantize with underflow and overflow buckets, lquantize
 * with both edges, and a joined printa().
 */
static void
case_oformat_tuples(void)
{
	const char *name = "oformat-aggregation-tuples";
	static const char *const opts[] = { "quiet", NULL, NULL };
	struct session s;
	static const char b5[5] = { 'a', 'b', 0, 'c', 'd' };
	uint64_t ust[1 + 2] = { 0, 0x400100, 0 };
	uint64_t ua[2] = { 0, 0x401234 };
	uint64_t gua[2] = { HYPERTRACE_UADDR_ENCODE(7, 42), 0x401234 };
	int i;

	r_reset();
	if (r_open(&s, name, opts, "typedef char b5_t[5]; "
	    "test:kernel:alpha:entry { "
	    "@k[(char)arg0, (short)arg0, (int)arg0] = min(arg0); "
	    "@x[(char)arg0] = max(arg0); @s[ustack(2)] = sum(arg0); "
	    "@u[usym(arg1)] = count(); @m[umod(arg1)] = count(); } "
	    "test:kernel:alpha:return { @a[uaddr(arg1)] = count(); "
	    "@b[*(b5_t *)arg2] = count(); "
	    "@ll = llquantize(arg0, 10, 0, 1, 10); "
	    "@l = lquantize(arg0, 0, 10, 5); } "
	    "test:kernel:beta:entry { @c[probefunc] = count(); "
	    "@t[probefunc] = sum(arg0); } "
	    "test:kernel:beta:return { printa(@c, @t); }", 0) != 0) {
		close_session(&s);
		return;
	}
	json_begin(&s, "oformat-aggregations.json");
	for (i = 0; i < 2; i++) {
		int64_t v = i == 0 ? -3 : 150;

		fire(i, "test:kernel:alpha:entry", 0, VALS(
		    N(1), N(v), N(v), N(v), AGG(v, 1),
		    N(2), N(v), AGG(v, 1),
		    N(3), B(ust, sizeof (ust)), AGG(v, 1),
		    N(4), B(ua, 16), AGG(0, 1),
		    N(5), B(ua, 16), AGG(0, 1)));
		fire(i, "test:kernel:alpha:return", 0, VALS(
		    N(6), B(gua, 16), AGG(0, 1),
		    N(7), B(b5, 5), AGG(0, 1),
		    N(8), AGG(v, 1), N(9), AGG(v, 1)));
	}
	fire(0, "test:kernel:beta:entry", 0, VALS(N(10), S("beta"), AGG(0, 1),
	    N(11), S("beta"), AGG(5, 1)));
	if (dtrace_aggregate_snap(s.dtp) != 0)
		fail(name, "snap", "", "");
	fire(0, "test:kernel:beta:return", 0, VALS(N(10), N(11)));
	if (consume(&s) != 0 ||
	    dtrace_aggregate_print(s.dtp, NULL, NULL) != 0)
		fail(name, "print", "", dtrace_errmsg(s.dtp,
		    dtrace_errno(s.dtp)));
	json_end(&s);
	printf("WROTE %s\n", name);
}

/*
 * Principal-buffer drops in structured output are reported as a probe
 * entry dtrace:INTERNAL:INTERNAL:DROP with id -1, in both the per-CPU and
 * the temporal consumer.
 */
static void
oformat_drops(int t)
{
	static const char *const opts[2][5] = {
		{ "quiet", NULL, "bufsize", "64", NULL },
		{ "quiet", NULL, "bufsize", "64", "temporal" },
	};
	int i;

	{
		const char *name = t ? "oformat-drops-temporal" :
		    "oformat-drops";
		const char *o[7];
		struct session s;

		memcpy(o, opts[t], sizeof (opts[t]));
		o[5] = NULL;
		o[6] = NULL;
		r_reset();
		if (r_open(&s, name, o, TRACE_PROG, 0) != 0) {
			close_session(&s);
			return;
		}
		json_begin(&s, t ? "oformat-drops-temporal.json" :
		    "oformat-drops.json");
		for (i = 1; i <= 3; i++)
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(i)));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		json_end(&s);
		printf("WROTE %s\n", name);
	}
}

static void
case_oformat_drops(void)
{
	oformat_drops(0);
}

static void
case_oformat_drops_temporal(void)
{
	oformat_drops(1);
}

/*
 * Structured-output failures: a stack record with an impossible frame
 * size, and printa() of an aggregation keyed by such a stack (alone and
 * joined), all fail with EDT_BADSTACKPC.
 */
static void
case_oformat_errors(void)
{
	static const struct { const char *name, *prog, *probe; int nact; }
	    cases[] = {
		{ "oformat-bad-stack-record",
		    "test:kernel:alpha:entry { stack(2); }", NULL, 1 },
		{ "oformat-printa-bad-stack-key",
		    "test:kernel:alpha:entry { @a[stack(2)] = count(); } "
		    "test:kernel:alpha:return { printa(@a); }",
		    "test:kernel:alpha:return", 1 },
		{ "oformat-printa-stack-key-no-frames",
		    "test:kernel:alpha:entry { @a[stack(2)] = count(); } "
		    "test:kernel:alpha:return { printa(@a); }",
		    "test:kernel:alpha:return", -1 },
		{ "oformat-printa-mixed-record-run",
		    "test:kernel:alpha:entry { @a[stack(2)] = count(); "
		    "@b[stack(2)] = sum(arg0); } "
		    "test:kernel:alpha:return { printa(@a, @b); }",
		    "test:kernel:alpha:return", -2 },
		{ "oformat-printa-lquantize-mismatch",
		    "test:kernel:alpha:entry { @a[stack(2)] = "
		    "lquantize(arg0, 0, 10, 5); } "
		    "test:kernel:alpha:return { printa(@a); }",
		    "test:kernel:alpha:return", -3 },
		{ "oformat-printa-joined-bad-stack-key",
		    "test:kernel:alpha:entry { @a[stack(2)] = count(); "
		    "@b[stack(2)] = sum(arg0); } "
		    "test:kernel:alpha:return { printa(@a, @b); }",
		    "test:kernel:alpha:return", 2 },
	};
	static const char *const opts[] = { "quiet", NULL, NULL };
	static const uint64_t pcs[2] = { 0xffffffff80001010ULL, 0 };
	size_t c;

	for (c = 0; c < sizeof (cases) / sizeof (cases[0]); c++) {
		struct session s;
		struct mset *set;
		int i;

		r_reset();
		if (r_open(&s, cases[c].name, opts, cases[c].prog, 0) != 0) {
			close_session(&s);
			continue;
		}
		set = ecb_set("test:kernel:alpha:entry");
		for (i = 0; i < set->nact; i++) {
			if (set->act[i].kind != DTRACEACT_STACK)
				continue;
			if (cases[c].nact == -1)
				set->act[i].rec.dtrd_arg = 0;
			else if (cases[c].nact > 0)
				set->act[i].rec.dtrd_size = 6;
		}
		/* lquantize(x, 0, 10, 5) parameter word claiming 1 level. */
		if (cases[c].nact == -3)
			set->act[2].initial = (int64_t)(((uint64_t)5 <<
			    DTRACE_LQUANTIZE_STEPSHIFT) |
			    ((uint64_t)1 << DTRACE_LQUANTIZE_LEVELSHIFT));
		if (cases[c].nact == -2)
			recn(cases[c].probe, 0, 1)->dtrd_action =
			    DTRACEACT_DIFEXPR;
		json_begin(&s, "/dev/null");
		if (cases[c].probe == NULL)
			fire(0, "test:kernel:alpha:entry", 0, VALS(B(pcs, 16)));
		else if (cases[c].nact == 1 || cases[c].nact == -1 ||
		    cases[c].nact == -3)
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(1),
			    B(pcs, 16), AGG(3, 1)));
		else
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(1),
			    B(pcs, 16), AGG(0, 1), N(2), B(pcs, 16),
			    AGG(1, 1)));
		if (cases[c].probe != NULL) {
			if (dtrace_aggregate_snap(s.dtp) != 0)
				fail(cases[c].name, "snap", "", "");
			if (cases[c].nact != 2 && cases[c].nact != -2)
				fire(0, cases[c].probe, 0, VALS(N(1)));
			else
				fire(0, cases[c].probe, 0, VALS(N(1), N(2)));
		}
		if (want_err(cases[c].name, &s, consume(&s),
		    cases[c].nact == -2 ? EDT_BADAGG : cases[c].nact == -3 ?
		    EDT_DMISMATCH : EDT_BADSTACKPC) == 0)
			pass(cases[c].name);
		json_end(&s);
	}
}

#ifdef FAULT_MALLOC
/* ------------------------------------------------------------------ */
/* Allocation failures (FAULT_MALLOC build).                            */

/*
 * For every library allocation made while producing output, failing that
 * allocation must either leave the output unchanged (the allocation was
 * optional, e.g. shrinking a snapshot) or fail the operation with
 * EDT_NOMEM -- never crash or emit different output while succeeding.
 */
static FILE *msweep_json;	/* structured output stream, if any */
static const char *msweep_xfail;	/* known failure: why */

/*
 * One output pass with the nth library allocation failing (0: none);
 * returns the text written (to fp, or to the structured stream).
 */
static char *
mpass(struct session *s, print_f *print_fn, long n, int *rc, long *calls)
{
	char *text = NULL;
	size_t len;
	FILE *fp;
	long start = 0;

	fp = open_memstream(&text, &len);
	if (msweep_json != NULL) {
		fflush(msweep_json);
		start = ftell(msweep_json);
	}
	malloc_calls = 0;
	malloc_countdown = n;
	*rc = print_fn(s, fp);
	malloc_countdown = 0;
	*calls = malloc_calls;
	fclose(fp);
	if (msweep_json != NULL) {
		long end;

		xo_flush();
		fflush(msweep_json);
		end = ftell(msweep_json);
		free(text);
		text = calloc(1, end - start + 1);
		fseek(msweep_json, start, SEEK_SET);
		fread(text, 1, end - start, msweep_json);
		fseek(msweep_json, end, SEEK_SET);
	}
	return (text);
}

static int
msweep_open(struct session *s, const char *name, const char *const *opts,
    const char *prog, fire_f *fire_fn)
{
	r_reset();
	if (r_open(s, name, opts, prog, 0) != 0) {
		close_session(s);
		return (-1);
	}
	if (msweep_json != NULL) {
		dtrace_set_outfp(msweep_json);
		xo_set_style(NULL, XO_STYLE_JSON);
		(void) dtrace_oformat_configure(s->dtp);
		dtrace_oformat_setup(s->dtp);
	}
	fire_fn(s);
	return (0);
}

/*
 * For every library allocation made while producing output, failing that
 * allocation must either leave the output unchanged (the allocation was
 * optional, e.g. shrinking a snapshot) or fail the operation with
 * EDT_NOMEM -- never crash or emit different output while succeeding.
 * fresh: a new handle per pass (temporal consumption keeps the time
 * reached, so records cannot be replayed into one handle).
 */
static int
msweep(const char *name, const char *const *opts, const char *prog,
    fire_f *fire_fn, print_f *print_fn, int expect_min, int fresh)
{
	struct session s;
	char *ref = NULL, *text;
	long total = 0, k, calls;
	int rc = 0, bad = 0, failed_n = 0, i;

	if (msweep_open(&s, name, opts, prog, fire_fn) != 0)
		return (-1);
	if (!fresh)
		save_bufs();
	for (i = 0; i < (fresh ? 1 : 2); i++) {
		if (!fresh)
			restore_bufs();
		free(ref);
		ref = mpass(&s, print_fn, 0, &rc, &total);
	}
	if (rc != 0 || total < expect_min) {
		char buf[64];

		snprintf(buf, sizeof (buf), "rc %d, %ld allocations\n", rc,
		    total);
		fail(name, "unfaulted run", "", buf);
		bad = 1;
	}
	if (getenv("SWEEP_TRACE") != NULL)
		fprintf(stderr, "%s: %ld allocations\n", name, total);
	for (k = 1; k <= total && !bad; k++) {
		if (fresh) {
			close_session(&s);
			if (msweep_open(&s, name, opts, prog, fire_fn) != 0)
				return (-1);
		} else
			restore_bufs();
		text = mpass(&s, print_fn, k, &rc, &calls);
		if (rc == 0 ? strcmp(text, ref) != 0 : (rc != -1 ||
		    dtrace_errno(s.dtp) != EDT_NOMEM)) {
			char buf[8192];

			snprintf(buf, sizeof (buf), "allocation %ld of %ld: "
			    "rc %d errno %d (%s)\n%s", k, total, rc,
			    dtrace_errno(s.dtp), dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)), text);
			if (msweep_xfail != NULL)
				printf("XFAIL %s: allocation %ld of %ld: %s\n",
				    name, k, total, msweep_xfail);
			else
				fail(name, "allocation failure", ref, buf);
			bad = 2;
		}
		failed_n += rc != 0;
		free(text);
	}
	free(ref);
	if (!fresh)
		free_saved();
	if (msweep_json != NULL)
		dtrace_oformat_teardown(s.dtp);
	close_session(&s);
	if (!bad && failed_n == 0 && total > 0) {
		fail(name, "coverage", "some allocation failure reported", "");
		bad = 1;
	}
	if (!bad && msweep_xfail != NULL)
		printf("XPASS %s\n", name);
	else if (!bad)
		pass(name);
	return (bad ? -1 : 0);
}

static int
print_consume_stop(struct session *s, FILE *fp)
{
	return (consume_fp(s, fp));
}

static void
fire_temporal(struct session *s)
{
	int i;

	for (i = 0; i < 3; i++)
		fire(i % 2, "test:kernel:alpha:entry", 0, VALS(N(i)));
	if (dtrace_stop(s->dtp) != 0)
		fail("fire-temporal", "stop", "", "");
}

static void
case_malloc_failures(void)
{
	static const char *const temporal[] = { "temporal", NULL, NULL };
	static const char *const ring[] = { "bufpolicy", "ring",
	    "bufsize", "64", NULL };
	struct session s;
	const char *name;
	char msg[256];
	int rc;

	msweep("malloc-failure-records", NULL, SWEEP_DATA_PROG, fire_data,
	    print_consume, 3, 0);
	msweep("malloc-failure-aggregations", NULL, SWEEP_AGG_PROG,
	    fire_aggs, print_consume_aggs, 3, 0);
	msweep("malloc-failure-temporal", temporal, TRACE_PROG,
	    fire_temporal, print_consume_stop, 3, 1);

	/* A wrapped ring buffer is reordered into a new allocation. */
	name = "malloc-failure-ring";
	r_reset();
	if (r_open(&s, name, ring, TRACE_PROG, 0) == 0) {
		int i;

		for (i = 1; i <= 5; i++)
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(i)));
		if (dtrace_stop(s.dtp) != 0)
			fail(name, "stop", "", "");
		/*
		 * Allocations per snapshot: descriptor, data, then the
		 * reordered copy; CPU 0 (the BEGIN CPU) is read first.
		 */
		fail_next_malloc(3);
		rc = consume(&s);
		fail_next_malloc(0);
		if (want_err(name, &s, rc, EDT_NOMEM) == 0)
			pass(name);
	}
	close_session(&s);

	name = "dt-buf-allocation-failures";
	r_reset();
	if (r_open(&s, name, NULL, NULL, 0) == 0) {
		if (cr_buf_fault_cases(s.dtp, fail_next_malloc, msg,
		    sizeof (msg)) != 0)
			fail(name, "dt_buf", "", msg);
		else
			pass(name);
	}
	close_session(&s);

	/*
	 * dtrace_go(): every library allocation it makes (the error
	 * enabling's DOF, the option DOF, the matched-probe list, the
	 * aggregation buffers) fails cleanly with EDT_NOMEM.
	 */
	name = "go-allocation-sweep";
	{
		long n = 0, k;
		int bad = 0;

		r_reset();
		if (r_open(&s, name, NULL, TRACE_PROG, RO_NOGO) == 0) {
			malloc_calls = 0;
			if (dtrace_go(s.dtp) != 0)
				fail(name, "unfaulted go", "", "");
			n = malloc_calls;
		}
		close_session(&s);
		for (k = 1; k <= n && !bad; k++) {
			r_reset();
			if (r_open(&s, name, NULL, TRACE_PROG, RO_NOGO) != 0) {
				close_session(&s);
				bad = 1;
				break;
			}
			fail_next_malloc(k);
			rc = dtrace_go(s.dtp);
			fail_next_malloc(0);
			if (rc != 0 && dtrace_errno(s.dtp) != EDT_NOMEM) {
				char buf[128];

				snprintf(buf, sizeof (buf), "allocation %ld of "
				    "%ld: errno %d\n", k, n,
				    dtrace_errno(s.dtp));
				fail(name, "go", "EDT_NOMEM", buf);
				bad = 1;
			}
			close_session(&s);
		}
		if (!bad && n > 0)
			pass(name);
		else if (n == 0)
			fail(name, "allocations", "> 0", "0\n");
	}
}

/* The same in structured output (a process of its own; see cases[]). */
static void
case_malloc_failures_oformat(void)
{
	static const char *const quiet[] = { "quiet", NULL, NULL };

	msweep_json = fopen("malloc-oformat.json", "w+");
	assert(msweep_json != NULL);
	data_noprint = 1;
	msweep("malloc-failure-records-oformat", quiet, SWEEP_DATA_PROG_NOPRINT,
	    fire_data, print_consume, 3, 0);
	data_noprint = 0;
	/*
	 * Structured print() of a char array member must fail with
	 * EDT_NOMEM or emit the value (formerly a known dt_print.c failure,
	 * fixed by returning EDT_NOMEM; see printf-faults "print-value").
	 */
	msweep("malloc-failure-print-oformat", quiet, SWEEP_DATA_PROG,
	    fire_data, print_consume, 3, 0);
	msweep("malloc-failure-aggregations-oformat", quiet, SWEEP_AGG_PROG,
	    fire_aggs, print_consume_aggs, 3, 0);
	xo_set_style(NULL, XO_STYLE_TEXT);
	dtrace_set_outfp(stdout);
	fclose(msweep_json);
	msweep_json = NULL;
}

/*
 * print() creates a libxo handle for its text; if that allocation fails
 * the record fails with EDT_NOMEM.
 */
static void
case_print_xo_allocation(void)
{
	const char *name = "print-xo-allocation";
	struct session s;
	static const struct print_fixture pv = { 1, { 'a', 0, 0, 0 }, 2, 0,
	    0, { 0 }, NULL };

	r_reset();
	if (r_open(&s, name, NULL, "struct pf { int a; char b[4]; long c; "
	    "unsigned int lo:3; unsigned int hi:5; void *p; }; "
	    "test:kernel:alpha:entry { print(*(struct pf *)arg0); }", 0) == 0) {
		int rc;

		fire(0, "test:kernel:alpha:entry", 0, VALS(B(&pv,
		    sizeof (pv))));
		malloc_lib = "libxo.so";
		fail_next_malloc(1);
		rc = consume(&s);
		fail_next_malloc(0);
		malloc_lib = "libdtrace.so";
		if (want_err(name, &s, rc, EDT_NOMEM) == 0)
			pass(name);
	}
	close_session(&s);
}

/* ------------------------------------------------------------------ */
/* Descriptor (non-vector) handle: user symbols through libproc.         */

/* Symbols in this executable resolved by libproc for our own pid. */
void cr_ustack_target(void);
void
cr_ustack_target(void)
{
	(void) getpid();
}

static int nodev_nogo;

static int
nodev_open(struct session *s, const char *name, const char *const *opts,
    const char *prog)
{
	struct stat st;
	int fd, err, i;
	dtrace_prog_t *p;
	dtrace_proginfo_t info;

	memset(s, 0, sizeof (*s));
	fd = open("model.dev", O_RDWR | O_CREAT, 0600);
	assert(fd >= 0 && fstat(fd, &st) == 0);
	model_dev = st.st_dev;
	model_ino = st.st_ino;
	model_fd_live = 1;
	s->dtp = dtrace_fdopen(fd, DTRACE_VERSION, DTRACE_O_NOSYS |
	    DTRACE_O_LP64, &err);
	close(fd);
	if (s->dtp == NULL) {
		fail(name, "dtrace_fdopen", "", dtrace_errmsg(NULL, err));
		return (-1);
	}
	s->out = open_memstream(&s->text, &s->len);
	(void) dtrace_setopt(s->dtp, "bufsize", "64k");
	for (i = 0; opts != NULL && opts[i] != NULL; i += 2)
		(void) dtrace_setopt(s->dtp, opts[i], opts[i + 1]);
	if ((p = dtrace_program_strcompile(s->dtp, prog,
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL)) == NULL ||
	    dtrace_program_exec(s->dtp, p, &info) != 0 ||
	    (!nodev_nogo && dtrace_go(s->dtp) != 0)) {
		fail(name, "setup", "", dtrace_errmsg(s->dtp,
		    dtrace_errno(s->dtp)));
		return (-1);
	}
	return (0);
}

/*
 * Without a vector the consumer grabs the traced process read-only and
 * symbolizes user addresses with libproc: function+offset or the exact
 * function, a ustack helper string for a writable unmapped region (heap)
 * but not for a read-only mapping, the object and address for mapped
 * code without a symbol, and the raw address otherwise.  Expected names
 * come from this executable's own symbols (dladdr for the object base).
 */
static void
nodev_ustack_body(int oformat)
{
	const char *name = oformat ? "nodev-ustack-oformat" :
	    "nodev-ustack-usym-umod";
	struct session s;
	uint64_t ust[1 + 6 + 4];
	uint64_t us[2], um[2], uz[2], ua[2], gp[1 + 2];
	uintptr_t fn = (uintptr_t)cr_ustack_target;
	void *heap = malloc(64);
	Dl_info dli;
	char obj[64], want[1024];
	const char *base;

	assert(dladdr((void *)fn, &dli) != 0);
	base = strrchr(dli.dli_fname, '/');
	base = base != NULL ? base + 1 : dli.dli_fname;
	strlcpy(obj, base, sizeof (obj));
	memset(ust, 0, sizeof (ust));
	ust[0] = getpid();
	ust[1] = fn + 4;
	ust[2] = fn;
	ust[3] = (uintptr_t)heap;
	ust[4] = 0x10;
	ust[5] = (uintptr_t)dli.dli_fbase;
	memcpy(&ust[7], "s1\0\0jit\0\0nope\0", 14);
	us[0] = um[0] = ua[0] = getpid();
	us[1] = fn + 4;
	um[1] = fn;
	ua[1] = fn + 4;
	uz[0] = getpid();
	uz[1] = 0x10;
	gp[0] = 0;		/* pid 0 cannot be grabbed: raw addresses */
	gp[1] = fn;
	gp[2] = 0;
	r_reset();
	if (nodev_open(&s, name, oformat ? (const char *const[]){ "quiet",
	    NULL, NULL } : NULL, "test:kernel:alpha:entry { ustack(6, 32); "
	    "usym(arg0); umod(arg0); umod(arg1); uaddr(arg0); usym(arg1); } "
	    "test:kernel:beta:entry { ustack(2); }") != 0) {
		close_session(&s);
		free(heap);
		return;
	}
	if (oformat)
		json_begin(&s, "nodev-ustack.json");
	fire(0, "test:kernel:alpha:entry", 0, VALS(B(ust, sizeof (ust)),
	    B(us, 16), B(um, 16), B(uz, 16), B(ua, 16), B(uz, 16)));
	fire(0, "test:kernel:beta:entry", 0, VALS(B(gp, sizeof (gp))));
	if (consume(&s) != 0)
		fail(name, "consume", "", dtrace_errmsg(s.dtp,
		    dtrace_errno(s.dtp)));
	if (oformat) {
		json_end(&s);
		/* Expected values for consume-records.py. */
		printf("NODEV fn=%s`cr_ustack_target base=%s`%#lx heap=%#lx\n",
		    obj, obj, (unsigned long)dli.dli_fbase,
		    (unsigned long)heap);
		printf("WROTE %s\n", name);
	} else {
		xbegin();
		X("\n%14s%s`cr_ustack_target+0x4\n", "", obj);
		X("%14s%s`cr_ustack_target\n", "", obj);
		X("%14sjit\n", "");
		X("%14s0x10\n", "");
		X("%14s%s`%#lx\n", "", obj, (unsigned long)dli.dli_fbase);
		/* usym() reports the containing function, uaddr() the pc. */
		snprintf(want, sizeof (want), "%s`cr_ustack_target", obj);
		X("  %-50s", want);
		X("  %-50s", obj);
		X("  %-50s", "0x10");
		snprintf(want, sizeof (want), "%s`cr_ustack_target+0x4", obj);
		X("  %-50s", want);
		X("  %-50s", "0x10");
		/* pid 0 cannot be grabbed: the raw address. */
		X("\n%14s%#lx\n", "", (unsigned long)fn);
		check(name, &s, xend(), NULL);
		close_session(&s);
	}
	model_fd_live = 0;
	free(heap);
}

/*
 * dtrace_uaddr2str() returns the length of the whole name (as snprintf);
 * a name of exactly the first guess (256 bytes) must not lose its last
 * character.  "<object>`<230-character function>+0x4" is 256 bytes long
 * for this executable.
 */
/* 230 characters. */
#define	CR_LONG_NAME	\
cr_long_symbol_name_reaching_the_uaddr_buffer_boundary_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
#define	CR_STR2(x)	#x
#define	CR_STR(x)	CR_STR2(x)
void CR_LONG_NAME(void);
void
CR_LONG_NAME(void)
{
	(void) getpid();
}

static void
nodev_boundary_body(int oformat)
{
	const char *name = oformat ? "nodev-uaddr-256-oformat" :
	    "nodev-uaddr-256";
	struct session s;
	uint64_t ua[2];
	Dl_info dli;
	char want[512];
	const char *base;

	assert(dladdr((void *)(uintptr_t)CR_LONG_NAME, &dli) != 0);
	base = strrchr(dli.dli_fname, '/');
	base = base != NULL ? base + 1 : dli.dli_fname;
	snprintf(want, sizeof (want), "%s`%s+0x4", base, CR_STR(CR_LONG_NAME));
	if (strlen(want) != 256) {
		fail(name, "name length", "256", want);
		return;
	}
	ua[0] = getpid();
	ua[1] = (uintptr_t)CR_LONG_NAME + 4;
	r_reset();
	if (nodev_open(&s, name, oformat ? (const char *const[]){ "quiet",
	    NULL, NULL } : NULL, "test:kernel:alpha:entry { uaddr(arg0); }")
	    != 0) {
		close_session(&s);
		return;
	}
	if (oformat)
		json_begin(&s, "nodev-uaddr.json");
	fire(0, "test:kernel:alpha:entry", 0, VALS(B(ua, 16)));
	if (consume(&s) != 0)
		fail(name, "consume", "", dtrace_errmsg(s.dtp,
		    dtrace_errno(s.dtp)));
	if (oformat) {
		json_end(&s);
		printf("NODEVUADDR %s\n", want);
		printf("WROTE %s\n", name);
	} else {
		xbegin();
		X("  %-50s", want);
		check(name, &s, xend(), NULL);
		close_session(&s);
	}
	model_fd_live = 0;
}

/* 300 characters: longer than the first uaddr buffer guess. */
#define	CR_LONGER_NAME	\
cr_longer_symbol_name_for_the_uaddr_retry_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
void CR_LONGER_NAME(void);
void
CR_LONGER_NAME(void)
{
	(void) getpid();
}

/*
 * More user symbolization without a vector: a helper string is used for
 * an address in no mapping; guest stacks are never grabbed (raw, with the
 * guest header); pid 0 cannot be grabbed (raw); a name longer than the
 * first buffer guess is retried in full.
 */
static void
nodev_more_body(int oformat)
{
	const char *name = oformat ? "nodev-more-oformat" : "nodev-more";
	struct session s;
	uint64_t ust[1 + 2 + 1], gust[1 + 2], u0[2], ul[2];
	Dl_info dli;
	char want[512];
	const char *base;

	assert(dladdr((void *)(uintptr_t)CR_LONGER_NAME, &dli) != 0);
	base = strrchr(dli.dli_fname, '/');
	base = base != NULL ? base + 1 : dli.dli_fname;
	snprintf(want, sizeof (want), "%s`%s+0x8", base,
	    CR_STR(CR_LONGER_NAME));
	memset(ust, 0, sizeof (ust));
	ust[0] = getpid();
	ust[1] = 0x20;
	memcpy(&ust[3], "unm\0", 4);
	gust[0] = HYPERTRACE_USTACK_ENCODE(7, 42);
	gust[1] = 0x500100;
	gust[2] = 0;
	u0[0] = 0;
	u0[1] = 0x401234;
	ul[0] = getpid();
	ul[1] = (uintptr_t)CR_LONGER_NAME + 8;
	r_reset();
	if (nodev_open(&s, name, oformat ? (const char *const[]){ "quiet",
	    NULL, NULL } : NULL, "test:kernel:alpha:entry { ustack(2, 8); "
	    "ustack(2); usym(arg0); uaddr(arg1); }") != 0) {
		close_session(&s);
		return;
	}
	if (oformat)
		json_begin(&s, "nodev-more.json");
	fire(0, "test:kernel:alpha:entry", 0, VALS(B(ust, sizeof (ust)),
	    B(gust, sizeof (gust)), B(u0, 16), B(ul, 16)));
	if (consume(&s) != 0)
		fail(name, "consume", "", dtrace_errmsg(s.dtp,
		    dtrace_errno(s.dtp)));
	if (oformat) {
		json_end(&s);
		printf("NODEVLONG %s\n", want);
		printf("WROTE %s\n", name);
	} else {
		xbegin();
		X("\n%14sunm\n", "");
		X("\n%14s[guest vmid=7 pid=42]\n%14s0x500100\n", "", "");
		X("  %-50s", "0x401234");
		X("  %-50s", want);
		check(name, &s, xend(), NULL);
		close_session(&s);
	}
	model_fd_live = 0;
}

static void
case_nodev_more(void)
{
	nodev_more_body(0);
}

static void
case_nodev_more_oformat(void)
{
	nodev_more_body(1);
}

/*
 * Without a vector, a device that does not support ENABLE (ENOTTY) is an
 * error for the error enabling and for the program alike.
 */
static void
case_nodev_go_enotty(void)
{
	int i;

	for (i = 0; i < 2; i++) {
		const char *name = i == 0 ? "nodev-go-enotty-errprog" :
		    "nodev-go-enotty-program";
		struct session s;

		r_reset();
		nodev_nogo = 1;
		if (nodev_open(&s, name, NULL, TRACE_PROG) == 0) {
			if (dtrace_handle_err(s.dtp, r_err, NULL) != 0)
				fail(name, "handler", "", "");
			M.fail_cmd = CMD(DTRACEIOC_ENABLE);
			M.fail_errno = ENOTTY;
			M.fail_after = i;
			if (want_err(name, &s, dtrace_go(s.dtp), ENOTTY) == 0)
				pass(name);
			M.fail_cmd = 0;
		}
		nodev_nogo = 0;
		close_session(&s);
		model_fd_live = 0;
	}
}

static void
case_nodev_boundary(void)
{
	nodev_boundary_body(0);
}

static void
case_nodev_boundary_oformat(void)
{
	nodev_boundary_body(1);
}

static void
case_nodev_ustack(void)
{
	nodev_ustack_body(0);
}

static void
case_nodev_ustack_oformat(void)
{
	nodev_ustack_body(1);
}

/*
 * kern.smp.maxid failures: the CPU count is read once per process by the
 * consumer and once by the BEGIN/END ordering; until it has been read
 * successfully, a failure fails the consume.
 */
static void
case_cpu_count_failure(void)
{
	const char *name;
	struct session s;
	int rc;

	name = "cpu-count-consume";
	r_reset();
	if (r_open(&s, name, NULL, TRACE_PROG, 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		fail_maxid = 1;
		rc = consume(&s);
		fail_maxid = 0;
		if (want_err(name, &s, rc, EPERM) == 0) {
			if (consume(&s) != 0)
				fail(name, "retry", "", "");
			else {
				xbegin();
				X(" %16lld", 1LL);
				check(name, &s, xend(), NULL);
			}
		}
	}
	close_session(&s);

	name = "cpu-count-begin-end";
	r_reset();
	M.endcpu = 0;
	if (r_open(&s, name, NULL, "BEGIN { trace(1); } END { trace(3); }",
	    0) == 0) {
		fire(0, "dtrace:::BEGIN", 0, VALS(N(1)));
		fire(0, "dtrace:::END", 0, VALS(N(3)));
		if (dtrace_stop(s.dtp) != 0)
			fail(name, "stop", "", "");
		fail_maxid = 1;
		rc = consume(&s);
		fail_maxid = 0;
		if (want_err(name, &s, rc, EPERM) == 0)
			check(name, &s, NULL,
			    "probe cpu=0 dtrace:::BEGIN\nend-of-probe\n");
	}
	close_session(&s);
}
#endif	/* FAULT_MALLOC */

/* ------------------------------------------------------------------ */
/* Record edge cases.                                                   */

/*
 * A user stack recorded with no frames prints nothing; helper strings
 * stop once the string table (strsize bytes) is used up; zero-size
 * records (stop()) print nothing.
 */
static void
case_record_edges(void)
{
	const char *name;
	struct session s;
	static const char *const destructive[] = { "destructive", NULL,
	    NULL };
	uint64_t ust[1 + 3 + 1];

	name = "ustack-no-frames-and-strtab-end";
	r_reset();
	if (r_open(&s, name, NULL, "test:kernel:alpha:entry { ustack(3, 8); } "
	    "test:kernel:beta:entry { ustack(3, 8); }", 0) == 0) {
		memset(ust, 0, sizeof (ust));
		ust[1] = 0x400100;
		ust[2] = 0x400200;
		ust[3] = 0x400300;
		/* Exactly 8 bytes of strings: "@a" "@bcde"; none for #3. */
		memcpy(&ust[4], "@a\0@bcde", 8);
		recn("test:kernel:beta:entry", 0, 0)->dtrd_arg =
		    DTRACE_USTACK_ARG(0, 8);
		fire(0, "test:kernel:alpha:entry", 0, VALS(B(ust,
		    sizeof (ust))));
		fire(0, "test:kernel:beta:entry", 0, VALS(B(ust,
		    sizeof (ust))));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		check(name, &s, "\n"
		    "              0x400100\n                [ a ]\n"
		    "              0x400200\n                [ bcde ]\n"
		    "              0x400300\n", NULL);
	}
	close_session(&s);

	name = "zero-size-record";
	r_reset();
	if (r_open(&s, name, destructive,
	    "test:kernel:alpha:entry { stop(); trace(arg0); }", 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(0), N(5)));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X(" %16lld", 5LL);
		check(name, &s, xend(), "probe cpu=0 test:kernel:alpha:entry\n"
		    "end-of-probe\n");
	}
	close_session(&s);

	/* printa() of a stack-keyed aggregation whose key has no frames. */
	name = "printa-stack-key-no-frames";
	r_reset();
	if (r_open(&s, name, NULL, "test:kernel:alpha:entry { "
	    "@a[stack(2)] = count(); } test:kernel:alpha:return { "
	    "printa(@a); }", 0) == 0) {
		static const uint64_t pcs[2] = { 0xffffffff80001010ULL, 0 };

		recn("test:kernel:alpha:entry", 0, 1)->dtrd_arg = 0;
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), B(pcs, 16),
		    AGG(0, 1)));
		if (dtrace_aggregate_snap(s.dtp) != 0)
			fail(name, "snap", "", "");
		fire(0, "test:kernel:alpha:return", 0, VALS(N(1)));
		if (want_err(name, &s, consume(&s), EDT_BADSTACKPC) == 0)
			pass(name);
	}
	close_session(&s);

	/*
	 * A printa() of several aggregations is a run of PRINTA records of
	 * one statement; a different action inside the run is EDT_BADAGG.
	 */
	name = "printa-mixed-record-run";
	r_reset();
	if (r_open(&s, name, NULL, "test:kernel:alpha:entry { "
	    "@a = count(); @b = sum(arg0); } test:kernel:alpha:return { "
	    "printa(@a, @b); }", 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), AGG(0, 1),
		    N(2), AGG(3, 1)));
		recn("test:kernel:alpha:return", 0, 1)->dtrd_action =
		    DTRACEACT_DIFEXPR;
		if (dtrace_aggregate_snap(s.dtp) != 0)
			fail(name, "snap", "", "");
		fire(0, "test:kernel:alpha:return", 0, VALS(N(1), N(2)));
		if (want_err(name, &s, consume(&s), EDT_BADAGG) == 0)
			pass(name);
	}
	close_session(&s);

	/*
	 * denormalize() affects only its aggregation: @s (12) prints raw,
	 * @c (4 firings) stays normalized by 2.
	 */
	name = "denormalize-one-of-two";
	r_reset();
	{
		static const char *const quiet[] = { "quiet", NULL, NULL };

		if (r_open(&s, name, quiet, "test:kernel:alpha:entry { "
		    "@s = sum(arg0); @c = count(); } "
		    "test:kernel:alpha:return { normalize(@s, 2); "
		    "normalize(@c, 2); denormalize(@s); printa(@s); "
		    "printa(@c); }", 0) == 0) {
			int i;

			for (i = 0; i < 4; i++)
				fire(0, "test:kernel:alpha:entry", 0,
				    VALS(N(1), AGG(3, 1), N(2), AGG(0, 1)));
			if (dtrace_aggregate_snap(s.dtp) != 0)
				fail(name, "snap", "", "");
			fire(0, "test:kernel:alpha:return", 0, VALS(N(1),
			    N(2), N(2), N(2), N(1), N(1), N(2)));
			if (consume(&s) != 0)
				fail(name, "consume", "", dtrace_errmsg(s.dtp,
				    dtrace_errno(s.dtp)));
			xbegin();
			X("\n %16lld\n", 12LL);
			X("\n %16lld\n", 2LL);
			check(name, &s, xend(), NULL);
		}
		close_session(&s);
	}

	/* agghist of a cleared avg() draws zero-count bars (average 0). */
	name = "agghist-cleared-avg";
	r_reset();
	{
		static const char *const opts[] = { "agghist", NULL,
		    "encoding", "ascii", NULL };

		if (r_open(&s, name, opts, "test:kernel:alpha:entry { "
		    "@a[probefunc] = avg(arg0); @c[probefunc] = count(); }",
		    0) == 0) {
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(1),
			    S("alpha"), AGG(4, 1), N(2), S("alpha"),
			    AGG(0, 1)));
			if (dtrace_aggregate_snap(s.dtp) != 0)
				fail(name, "snap", "", "");
			dtrace_aggregate_clear(s.dtp);
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(1),
			    S("alpha"), AGG(0, 0), N(2), S("alpha"),
			    AGG(0, 1)));
			if (dtrace_aggregate_snap(s.dtp) != 0 ||
			    dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
				fail(name, "print", "", dtrace_errmsg(s.dtp,
				    dtrace_errno(s.dtp)));
			xbegin();
			X("\n%17s %41s %-9s\n", "key",
			    "------------- Distribution -------------",
			    "count");
			X(" %16s |%40s %-9d\n", "alpha", "", 0);
			X("\n%17s %41s %-9s\n", "key",
			    "------------- Distribution -------------",
			    "count");
			X(" %16s |%.40s %-9d\n", "alpha",
			    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@", 1);
			check(name, &s, xend(), NULL);
		}
		close_session(&s);
	}
}

/*
 * More structured output (consume-records.py checks the document): 32-bit
 * stack frames ending at a zero PC, an unknown kernel symbol, a user stack
 * without frames and one whose helper strings run out, a printf() whose
 * format is unknown (consumed as data), and agghist with a sum.
 */
static void
case_oformat_edges(void)
{
	const char *name = "oformat-edges";
	static const char *const opts[] = { "quiet", NULL, "agghist", NULL,
	    NULL };
	struct session s;
	uint32_t pcs32[6] = { 0x1010, 0x2000, 0 };
	uint64_t ust[1 + 3 + 1];

	memset(ust, 0, sizeof (ust));
	ust[1] = 0x400100;
	ust[2] = 0x400200;
	ust[3] = 0x400300;
	memcpy(&ust[4], "@a\0@bcde", 8);
	r_reset();
	if (r_open(&s, name, opts, "test:kernel:alpha:entry { stack(3); "
	    "sym(arg0); ustack(3, 8); printf(\"%d\\n\", arg0); } "
	    "test:kernel:beta:entry { ustack(3, 8); @s[probefunc] = "
	    "sum(arg0); }", 0) != 0) {
		close_session(&s);
		return;
	}
	recn("test:kernel:alpha:entry", 0, 0)->dtrd_size = 12;
	recn("test:kernel:alpha:entry", 0, 3)->dtrd_format = 0;
	recn("test:kernel:beta:entry", 0, 0)->dtrd_arg =
	    DTRACE_USTACK_ARG(0, 8);
	json_begin(&s, "oformat-edges.json");
	fire(0, "test:kernel:alpha:entry", 0, VALS(B(pcs32, 24), N(0x1234),
	    B(ust, sizeof (ust)), N(77)));
	fire(1, "test:kernel:beta:entry", 0, VALS(B(ust, sizeof (ust)),
	    N(1), S("beta"), AGG(6, 1)));
	if (consume(&s) != 0 || dtrace_aggregate_snap(s.dtp) != 0 ||
	    dtrace_aggregate_print(s.dtp, NULL, NULL) != 0)
		fail(name, "consume", "", dtrace_errmsg(s.dtp,
		    dtrace_errno(s.dtp)));
	json_end(&s);
	printf("WROTE %s\n", name);
}

/* ------------------------------------------------------------------ */
/* Remaining record semantics.                                          */

/*
 * More flow names: "entrypoint" and "returned" contain the words without
 * ending in them, "xreturn" lacks the dash; none of them indent.  The same
 * entry ECB twice in a row indents twice, the same return ECB twice in a
 * row unindents twice, and a return as the first record stays at zero.
 */
static void
case_flow_more(void)
{
	const char *name = "flowindent-more";
	static const char *const opts[] = { "flowindent", NULL, NULL };
	struct session s;

	r_reset();
	log_flow = 1;
	if (r_open(&s, name, opts,
	    "test:kernel:alpha:entry { trace(arg0); } "
	    "test:kernel:alpha:return { trace(arg0); } "
	    "test:kernel:beta:entry { trace(arg0); } "
	    "test:kernel:beta:return { trace(arg0); } "
	    "profile:::tick-1sec { trace(arg0); }", 0) == 0) {
		r_rename[0].id = 6;
		r_rename[0].prov = "test";
		r_rename[0].name = "entrypoint";
		r_rename[1].id = 7;
		r_rename[1].prov = "test";
		r_rename[1].name = "returned";
		r_rename[2].id = 8;
		r_rename[2].prov = "profile";
		r_rename[2].name = "xreturn";
		fire(0, "test:kernel:alpha:return", 0, VALS(N(1)));
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(2)));
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(3)));
		fire(0, "test:kernel:beta:entry", 0, VALS(N(4)));
		fire(0, "test:kernel:beta:return", 0, VALS(N(5)));
		fire(0, "profile:::tick-1sec", 0, VALS(N(6)));
		fire(0, "test:kernel:alpha:return", 0, VALS(N(7)));
		fire(0, "test:kernel:alpha:return", 0, VALS(N(8)));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X(" %16lld %16lld %16lld %16lld %16lld %16lld %16lld %16lld",
		    1LL, 2LL, 3LL, 4LL, 5LL, 6LL, 7LL, 8LL);
		check(name, &s, xend(),
		    "probe cpu=0 test:kernel:alpha:return\n"
		    "flow 1 indent 0 prefix \" <- \"\nend-of-probe\n"
		    "probe cpu=0 test:kernel:alpha:entry\n"
		    "flow 0 indent 0 prefix \" -> \"\nend-of-probe\n"
		    "probe cpu=0 test:kernel:alpha:entry\n"
		    "flow 0 indent 2 prefix \" -> \"\nend-of-probe\n"
		    "probe cpu=0 test:kernel:beta:entrypoint\n"
		    "flow 2 indent 4 prefix \"| \"\nend-of-probe\n"
		    "probe cpu=0 test:kernel:beta:returned\n"
		    "flow 2 indent 4 prefix \"| \"\nend-of-probe\n"
		    "probe cpu=0 profile:::xreturn\n"
		    "flow 2 indent 4 prefix \"| \"\nend-of-probe\n"
		    "probe cpu=0 test:kernel:alpha:return\n"
		    "flow 1 indent 2 prefix \" <- \"\nend-of-probe\n"
		    "probe cpu=0 test:kernel:alpha:return\n"
		    "flow 1 indent 0 prefix \" <- \"\nend-of-probe\n");
	}
	close_session(&s);
}

/* Raw dump of n bytes with trace()'s layout (as in case_tracemem). */
static void
xdump(const unsigned char *p, int n)
{
	int i, j;

	X("\n%11s", "");
	for (i = 0; i < 16; i++)
		X("  %c", "0123456789abcdef"[i]);
	X("  0123456789abcdef\n");
	for (i = 0; i < n; i += 16) {
		X("%5s%5x:", "", i);
		for (j = i; j < i + 16 && j < n; j++)
			X(" %02x", p[j]);
		for (; j % 16; j++)
			X("   ");
		X("  ");
		for (j = i; j < i + 16 && j < n; j++)
			X("%c", p[j] < ' ' || p[j] > '~' ? '.' : p[j]);
		X("\n");
	}
}

/*
 * Printable bytes include whitespace, backspace and bell; a leading NUL
 * or a byte outside ASCII makes the record binary.  ECBs with a library
 * argument other than the error handler's are ordinary ECBs.  A
 * tracemem() size record that is not 8 bytes is ordinary data.  print()
 * of a type the consumer cannot resolve falls back to trace().  A
 * printf() whose format consumes no record (only "%%") moves on.
 * jstack() prints like ustack().  A print-immstack record prints like
 * immstack().
 */
static void
case_record_more(void)
{
	const char *name;
	struct session s;
	static const char *const quiet[] = { "quiet", NULL, NULL };
	/* 10 bytes: records of 1, 2, 4 or 8 bytes print as integers. */
	static const unsigned char ws[10] = { 'a', '\t', 'b', '\b', '\a',
	    'c', 0, 0, 0, 0 };
	static const unsigned char lead0[10] = { 0, 'a', 'b', 0, 0, 0, 0, 0,
	    0, 0 };
	static const unsigned char hi[10] = { 'a', 0x7f, 0x80, 'b', 0, 0, 0,
	    0, 0, 0 };

	name = "bytes-whitespace-and-binary";
	r_reset();
	if (r_open(&s, name, quiet, "typedef char b10_t[10]; "
	    "test:kernel:alpha:entry { trace(*(b10_t *)arg0); "
	    "trace(*(b10_t *)arg1); trace(*(b10_t *)arg2); }", 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(B(ws, 10),
		    B(lead0, 10), B(hi, 10)));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X("%s", (const char *)ws);
		xdump(lead0, 10);
		xdump(hi, 10);
		check(name, &s, xend(), NULL);
	}
	close_session(&s);

	name = "ecb-with-library-argument";
	r_reset();
	if (r_open(&s, name, NULL, TRACE_PROG, 0) == 0) {
		M.ecb[find_ecb("test:kernel:alpha:entry", 0)].uarg = 7;
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(3)));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X(" %16lld", 3LL);
		check(name, &s, xend(), "probe cpu=0 test:kernel:alpha:entry\n"
		    "end-of-probe\n");
	}
	close_session(&s);

	name = "tracemem-size-record-not-8-bytes";
	r_reset();
	if (r_open(&s, name, NULL,
	    "test:kernel:alpha:entry { tracemem(arg0, 8, arg1); }", 0) == 0) {
		static const char mem[8] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G',
		    'H' };

		recn("test:kernel:alpha:entry", 0, 0)->dtrd_size = 4;
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(3), B(mem, 8)));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X(" %8d", 3);
		xdump((const unsigned char *)mem, 8);
		check(name, &s, xend(), NULL);
	}
	close_session(&s);

	name = "print-unresolvable-type";
	r_reset();
	if (r_open(&s, name, NULL, "struct pf { int a; char b[4]; long c; "
	    "unsigned int lo:3; unsigned int hi:5; void *p; }; "
	    "test:kernel:alpha:entry { print(*(struct pf *)arg0); }", 0) == 0) {
		static const struct print_fixture pv = { 1, { 'a', 0, 0, 0 },
		    2, 0, 0, { 0 }, NULL };
		int f = recn("test:kernel:alpha:entry", 0, 0)->dtrd_format;

		/* The type name the kernel returns names no module. */
		free(M.fmt[f - 1]);
		M.fmt[f - 1] = strdup("nosuchmodule`1");
		fire(0, "test:kernel:alpha:entry", 0, VALS(B(&pv,
		    sizeof (pv))));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		xdump((const unsigned char *)&pv, sizeof (pv));
		check(name, &s, xend(), NULL);
	}
	close_session(&s);

	name = "printf-percent-only";
	r_reset();
	if (r_open(&s, name, quiet,
	    "test:kernel:alpha:entry { printf(\"100%%\\n\"); trace(arg0); }",
	    0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(0), N(4)));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		/* The printf record is consumed (not traced) either way. */
		check(name, &s, "100%\n4", NULL);
	}
	close_session(&s);

	name = "jstack-and-print-immstack";
	r_reset();
	if (r_open(&s, name, NULL, "test:kernel:alpha:entry { jstack(2, 8); "
	    "immstack(1); }", 0) == 0) {
		uint64_t js[1 + 2 + 1] = { 0, 0x400100, 0, 0 };
		char imm[64];
		uint64_t off = 0x4;

		memset(imm, 0, sizeof (imm));
		strcpy(imm, "zio_wait");
		memcpy(imm + 16, &off, sizeof (off));
		recn("test:kernel:alpha:entry", 0, 1)->dtrd_action =
		    DTRACEACT_PRINTIMMSTACK;
		fire(0, "test:kernel:alpha:entry", 0, VALS(B(js, sizeof (js)),
		    B(imm, sizeof (imm))));
		if (consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		check(name, &s, "\n              0x400100\n"
		    "\n              zio_wait+0x4\n", NULL);
	}
	close_session(&s);

	/*
	 * Aggregation keys: jstack, print-immstack, uaddr; an integer key
	 * under agghist (header width from its size); formatted printa()
	 * of stack, ustack, mod and umod keys.
	 */
	name = "aggregation-more-keys";
	r_reset();
	if (r_open(&s, name, quiet, "test:kernel:alpha:entry { "
	    "@j[jstack(2, 8)] = count(); @i[immstack(1)] = count(); "
	    "@u[uaddr(arg0)] = count(); } test:kernel:beta:entry { "
	    "@x[stack(2), ustack(2), mod(arg0), umod(arg0)] = count(); } "
	    "test:kernel:beta:return { printa(\"%k%k%a %A %@d\\n\", @x); }",
	    0) == 0) {
		uint64_t js[1 + 2 + 1] = { 0, 0x400100, 0, 0 };
		uint64_t us[1 + 2] = { 0, 0x400100, 0 };
		uint64_t pcs[2] = { 0xffffffff80001010ULL, 0 };
		uint64_t ua[2] = { 0, 0x401234 };
		char imm[64];
		uint64_t off = 0x4;

		memset(imm, 0, sizeof (imm));
		strcpy(imm, "zio_wait");
		memcpy(imm + 16, &off, sizeof (off));
		recn("test:kernel:alpha:entry", 0, 4)->dtrd_action =
		    DTRACEACT_PRINTIMMSTACK;
		fire(0, "test:kernel:alpha:entry", 0, VALS(
		    N(1), B(js, sizeof (js)), AGG(0, 1),
		    N(2), B(imm, sizeof (imm)), AGG(0, 1),
		    N(3), B(ua, 16), AGG(0, 1)));
		fire(0, "test:kernel:beta:entry", 0, VALS(N(4), B(pcs, 16),
		    B(us, sizeof (us)), N(0xffffffff90000010ULL),
		    B(ua, 16), AGG(0, 1)));
		if (dtrace_aggregate_snap(s.dtp) != 0)
			fail(name, "snap", "", "");
		fire(0, "test:kernel:beta:return", 0, VALS(N(4)));
		if (consume(&s) != 0 ||
		    dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
			fail(name, "print", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		/* printa(): stacks with indent 0, then mod and umod. */
		X("\nkernel`vm_fault+0x10\n\n0x400100\nzfs 0x401234 1\n");
		X("\n%14s0x400100\n %16d\n", "", 1);
		X("\n%14szio_wait+0x4\n %16d\n", "", 1);
		X("  %-50s %16d\n", "0x401234", 1);
		check(name, &s, xend(), NULL);
	}
	close_session(&s);

	name = "agghist-integer-key";
	r_reset();
	{
		static const char *const opts[] = { "agghist", NULL,
		    "encoding", "ascii", NULL };

		if (r_open(&s, name, opts, "test:kernel:alpha:entry { "
		    "@c[(int)arg0] = count(); }", 0) == 0) {
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), N(7),
			    AGG(0, 1)));
			if (dtrace_aggregate_snap(s.dtp) != 0 ||
			    dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
				fail(name, "print", "", "");
			xbegin();
			/* A 4-byte key: packed width 8 + 1. */
			X("\n%9s %41s %-9s\n", "key",
			    "------------- Distribution -------------",
			    "count");
			X(" %8d |%.40s %-9d\n", 7,
			    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@", 1);
			check(name, &s, xend(), NULL);
		}
		close_session(&s);
	}

	/* avg() and stddev() of a cleared aggregation print 0. */
	name = "avg-stddev-cleared";
	r_reset();
	if (r_open(&s, name, NULL, "test:kernel:alpha:entry { "
	    "@a = avg(arg0); @d = stddev(arg0); }", 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1), AGG(5, 1),
		    N(2), AGG(5, 1)));
		if (dtrace_aggregate_snap(s.dtp) != 0)
			fail(name, "snap", "", "");
		dtrace_aggregate_clear(s.dtp);
		if (dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
			fail(name, "print", "", "");
		xbegin();
		X(" %16lld\n %16llu\n", 0LL, 0ULL);
		check(name, &s, xend(), NULL);
	}
	close_session(&s);

	/* aggpack quantize whose lowest bucket is zero: no bucket below. */
	name = "aggpack-zero-bucket-minimum";
	r_reset();
	{
		static const char *const opts[] = { "aggpack", NULL,
		    "encoding", "ascii", NULL };

		if (r_open(&s, name, opts, "test:kernel:alpha:entry { "
		    "@q = quantize(arg0); }", 0) == 0) {
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(1),
			    AGG(0, 1)));
			if (dtrace_aggregate_snap(s.dtp) != 0 ||
			    dtrace_aggregate_print(s.dtp, s.out, NULL) != 0)
				fail(name, "print", "", "");
			xbegin();
			/* Buckets 0 and 1; labels are at least 4 wide. */
			X("\n %4s .--. %-4s | count\n", "min", "max");
			X(" %4d :X : %-4d | 1\n", 0, 1);
			check(name, &s, xend(), NULL);
		}
		close_session(&s);
	}

	/*
	 * Stopped, with BEGIN and END on one CPU: errors induced by BEGIN are
	 * reported in the first pass, the others in the second.
	 */
	name = "begin-pass-errors";
	r_reset();
	M.endcpu = 0;
	if (r_open(&s, name, NULL, "BEGIN { trace(1); } "
	    "test:kernel:alpha:entry { trace(arg0); } END { trace(3); }",
	    0) == 0) {
		int begin = find_ecb("dtrace:::BEGIN", 0) + 1;
		int alpha = find_ecb("test:kernel:alpha:entry", 0) + 1;
		int end = find_ecb("dtrace:::END", 0) + 1;

		fire(0, "dtrace:::BEGIN", 0, VALS(N(1)));
		fire(0, "dtrace:::ERROR", 0, VALS(N(alpha), N(1), N(4),
		    N(DTRACEFLT_DIVZERO), N(0)));
		fire(0, "dtrace:::ERROR", 0, VALS(N(begin), N(1), N(8),
		    N(DTRACEFLT_BADADDR), N(0x20)));
		/* dtrace:::END is a dtrace probe but not BEGIN. */
		fire(0, "dtrace:::ERROR", 0, VALS(N(end), N(1), N(12),
		    N(DTRACEFLT_BADALIGN), N(0x31)));
		fire(0, "dtrace:::END", 0, VALS(N(3)));
		if (dtrace_stop(s.dtp) != 0 || consume(&s) != 0)
			fail(name, "consume", "", dtrace_errmsg(s.dtp,
			    dtrace_errno(s.dtp)));
		xbegin();
		X(" %8d %8d", 1, 3);
		{
			char ev[1024];

			snprintf(ev, sizeof (ev),
			    "probe cpu=0 dtrace:::BEGIN\nend-of-probe\n"
			    "error: error on enabled probe ID %d (ID 1: "
			    "dtrace:::BEGIN): invalid address (0x20) in action "
			    "#1 at DIF offset 8\n"
			    "error: error on enabled probe ID %d (ID 4: "
			    "test:kernel:alpha:entry): divide-by-zero in "
			    "action #1 at DIF offset 4\n"
			    "error: error on enabled probe ID %d (ID 2: "
			    "dtrace:::END): invalid alignment (0x31) in "
			    "action #1 at DIF offset 12\n"
			    "probe cpu=0 dtrace:::END\nend-of-probe\n", begin,
			    alpha, end);
			check(name, &s, xend(), ev);
		}
	}
	close_session(&s);

	/* Temporal consumption skips unconfigured CPUs. */
	name = "temporal-unconfigured-cpu";
	r_reset();
	{
		static const char *const temporal[] = { "temporal", NULL,
		    NULL };

		if (r_open(&s, name, temporal, TRACE_PROG, 0) == 0) {
			fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
			fire(1, "test:kernel:alpha:entry", 0, VALS(N(2)));
			r_enoent_cpu = 1;
			if (dtrace_stop(s.dtp) != 0 || consume(&s) != 0)
				fail(name, "consume", "", "");
			xbegin();
			X(" %16lld", 1LL);
			check(name, &s, xend(), NULL);
		}
		close_session(&s);
	}
}

/*
 * A consumer may supply its own buffer retrieval: dc_get_buf fills a
 * buffer description (here with the kernel snapshot), dc_put_buf releases
 * it, and every retrieved buffer is released once.  A get_buf failure
 * fails the consume; a NULL buffer means no data for that CPU.
 */
static int cb_gets, cb_puts, cb_mode;

static int
cb_get_buf(dtrace_hdl_t *dtp, int cpu, dtrace_bufdesc_t **bufp)
{
	dtrace_bufdesc_t *b;

	(void) dtp;
	if (cb_mode == 1)
		return (-1);
	if (cb_mode == 2 && cpu != 0) {
		*bufp = NULL;
		return (0);
	}
	b = calloc(1, sizeof (*b));
	b->dtbd_size = 65536;
	b->dtbd_data = calloc(1, b->dtbd_size);
	b->dtbd_cpu = cpu;
	if (model_ioctl(&M, DTRACEIOC_BUFSNAP, &b) != 0) {
		free(b->dtbd_data);
		free(b);
		*bufp = NULL;
		return (0);
	}
	cb_gets++;
	*bufp = b;
	return (0);
}

static void
cb_put_buf(dtrace_hdl_t *dtp, dtrace_bufdesc_t *b)
{
	(void) dtp;
	cb_puts++;
	free(b->dtbd_data);
	free(b);
}

static void
case_consumer_buffers(void)
{
	const char *name;
	struct session s;
	int mode;

	for (mode = 0; mode < 3; mode++) {
		dtrace_consumer_t con = { .dc_consume_probe = probe_cb,
		    .dc_consume_rec = rec_cb, .dc_get_buf = cb_get_buf,
		    .dc_put_buf = cb_put_buf };
		int rc;

		name = mode == 0 ? "consumer-buffer-callbacks" : mode == 1 ?
		    "consumer-buffer-get-failure" :
		    "consumer-buffer-get-empty";
		r_reset();
		cb_gets = cb_puts = 0;
		cb_mode = mode;
		if (r_open(&s, name, NULL, TRACE_PROG, 0) != 0) {
			close_session(&s);
			continue;
		}
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		fire(1, "test:kernel:beta:entry", 0, VALS(N(2)));
		rc = dtrace_consume_consumer(s.dtp, s.out, &con, NULL);
		if (mode == 1) {
			if (rc != -1 || cb_gets != 0)
				fail(name, "consume", "-1", "");
			else
				pass(name);
		} else if (rc != 0 || cb_gets != cb_puts || cb_gets == 0) {
			fail(name, "consume", "0, balanced", "");
		} else {
			xbegin();
			X(" %16lld", 1LL);
			if (mode == 0)
				X(" %16lld", 2LL);
			check(name, &s, xend(), NULL);
		}
		close_session(&s);
	}
}

/*
 * dt_work additions: a status within statusrate is NONE (no snapshot);
 * once statusrate has passed the next check advances the status time;
 * the work loop reports DONE once tracing stopped or filled; a drain
 * after an earlier snapshot already found foreign aggregation data, and
 * a failing aggregation snapshot, are refused.
 */
static void
case_work_more(void)
{
	const char *name;
	struct session s, ext;
	static const char *const slow[] = { "statusrate", "10s",
	    "switchrate", "1ns", NULL };
	static const char *const fast[] = { "statusrate", "1ns", NULL };
	static const char *const fill[] = { "bufpolicy", "fill",
	    "statusrate", "1ns", NULL };
	dtrace_consumer_t con = { .dc_consume_probe = probe_cb,
	    .dc_consume_rec = rec_cb };
	dtrace_workstatus_t st;
	unsigned before;
	int rc;

	name = "work-status-none";
	r_reset();
	if (r_open(&s, name, slow, TRACE_PROG, 0) == 0) {
		(void) dtrace_status(s.dtp);
		before = M.bufsnaps;
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		st = dtrace_work(s.dtp, s.out, probe_cb, rec_cb, NULL);
		if (st != DTRACE_WORKSTATUS_OKAY || M.bufsnaps == before)
			fail(name, "work", "OKAY and consumed", "");
		else
			pass(name);
	}
	close_session(&s);

	name = "status-rate-advances";
	r_reset();
	if (r_open(&s, name, fast, TRACE_PROG, 0) == 0) {
		if (dtrace_status(s.dtp) != DTRACE_STATUS_OKAY ||
		    dtrace_status(s.dtp) != DTRACE_STATUS_OKAY)
			fail(name, "status", "OKAY twice", "");
		else
			pass(name);
	}
	close_session(&s);

	name = "work-after-stop";
	r_reset();
	if (r_open(&s, name, fast, TRACE_PROG, 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		(void) dtrace_stop(s.dtp);
		st = dtrace_work(s.dtp, s.out, probe_cb, rec_cb, NULL);
		xbegin();
		X(" %16lld", 1LL);
		if (st != DTRACE_WORKSTATUS_DONE)
			fail(name, "work", "DONE", "");
		else
			check(name, &s, xend(), NULL);
	}
	close_session(&s);

	name = "work-filled";
	r_reset();
	if (r_open(&s, name, fill, TRACE_PROG, 0) == 0) {
		fire(0, "test:kernel:alpha:entry", 0, VALS(N(1)));
		M.buf[0].flags |= BUF_FULL;
		st = dtrace_work(s.dtp, s.out, probe_cb, rec_cb, NULL);
		xbegin();
		X(" %16lld", 1LL);
		if (st != DTRACE_WORKSTATUS_DONE || M.activity != ACT_STOPPED)
			fail(name, "work", "DONE, stopped", "");
		else
			check(name, &s, xend(), NULL);
	}
	close_session(&s);

	for (rc = 0; rc < 2; rc++) {
		name = rc == 0 ? "quiesced-external-aggregation-retained" :
		    "quiesced-snapshot-failure";
		r_reset();
		if (r_open(&s, name, NULL, TRACE_PROG, RO_NOGO) != 0 ||
		    r_open(&ext, name, NULL,
		    "test:kernel:beta:entry { @c = count(); }", RO_NOGO) != 0) {
			close_session(&s);
			continue;
		}
		(void) dtrace_go(ext.dtp);
		M.activity = ACT_INACTIVE;
		(void) dtrace_go(s.dtp);
		fire(0, "test:kernel:beta:entry", 1, VALS(N(1), AGG(0, 1)));
		if (rc == 0) {
			(void) dtrace_consume_quiesced(s.dtp, s.out, &con,
			    NULL);
			before = M.drainables;
			if (want_err(name, &s, dtrace_consume_quiesced(s.dtp,
			    s.out, &con, NULL), EOPNOTSUPP) == 0 &&
			    M.drainables == before)
				pass(name);
		} else {
			M.fail_cmd = CMD(DTRACEIOC_AGGSNAP);
			M.fail_errno = EIO;
			if (want_err(name, &s, dtrace_consume_quiesced(s.dtp,
			    s.out, &con, NULL), EIO) == 0)
				pass(name);
			M.fail_cmd = 0;
		}
		close_session(&ext);
		close_session(&s);
	}
}

/*
 * Structured output, part three (checked by consume-records.py): bytes
 * with whitespace, a leading NUL and a byte above '~'; a zero-size record
 * (stop()); jstack() as a record and as a key; llquantize without data
 * below its range and with several orders whose step is 1; avg() and
 * stddev() after clear().
 */
static void
case_oformat_more(void)
{
	const char *name = "oformat-more";
	static const char *const opts[] = { "quiet", NULL, "destructive",
	    NULL, NULL };
	static const unsigned char ws[10] = { 'a', '\t', 'b', '\b', '\a',
	    'c', 0, 0, 0, 0 };
	static const unsigned char lead0[10] = { 0, 'a', 'b', 0, 0, 0, 0, 0,
	    0, 0 };
	static const unsigned char hi[10] = { 'a', 0x7f, 0x80, 'b', 0, 0, 0,
	    0, 0, 0 };
	uint64_t js[1 + 2 + 1] = { 0, 0x400100, 0, 0 };
	struct session s;

	r_reset();
	if (r_open(&s, name, opts, "typedef char b10_t[10]; "
	    "test:kernel:alpha:entry { trace(*(b10_t *)arg0); "
	    "trace(*(b10_t *)arg1); trace(*(b10_t *)arg2); stop(); "
	    "jstack(2, 8); } "
	    "test:kernel:beta:entry { @j[jstack(2, 8)] = count(); "
	    "@ll = llquantize(arg0, 10, 0, 2, 10); "
	    "@l2 = llquantize(arg0, 2, 0, 4, 4); } "
	    "test:kernel:beta:return { @a = avg(arg0); @d = stddev(arg0); }",
	    0) != 0) {
		close_session(&s);
		return;
	}
	json_begin(&s, "oformat-more.json");
	fire(0, "test:kernel:alpha:entry", 0, VALS(B(ws, 10), B(lead0, 10),
	    B(hi, 10), N(0), B(js, sizeof (js))));
	fire(0, "test:kernel:beta:return", 0, VALS(N(4), AGG(5, 1), N(5),
	    AGG(5, 1)));
	if (dtrace_aggregate_snap(s.dtp) != 0)
		fail(name, "snap", "", "");
	dtrace_aggregate_clear(s.dtp);
	fire(0, "test:kernel:beta:entry", 0, VALS(N(1), B(js, sizeof (js)),
	    AGG(0, 1), N(2), AGG(50, 1), N(3), AGG(5, 1)));
	if (consume(&s) != 0 || dtrace_aggregate_snap(s.dtp) != 0 ||
	    dtrace_aggregate_print(s.dtp, NULL, NULL) != 0)
		fail(name, "consume", "", dtrace_errmsg(s.dtp,
		    dtrace_errno(s.dtp)));
	json_end(&s);
	printf("WROTE %s\n", name);
}

/* ------------------------------------------------------------------ */

/*
 * libxo keeps one default handle per process and a finished document
 * cannot be followed by another, so each structured-output case runs in
 * a process of its own ("separate"), started by consume-records.py.
 */
static const struct {
	const char *name;
	void (*fn)(void);
	int separate;
} cases[] = {
	{ "write-failures", case_write_failures, 0 },
	{ "buf", case_buf, 0 },
	{ "sleep", case_sleep, 0 },
	{ "status", case_status, 0 },
	{ "work", case_work, 0 },
	{ "go", case_go, 0 },
	{ "quiesced", case_quiesced, 0 },
	{ "flow", case_flow_heuristics, 0 },
	{ "libact", case_libact_records, 0 },
	{ "setopt", case_setopt_records, 0 },
	{ "ftruncate", case_ftruncate, 0 },
	{ "tracemem", case_tracemem_dynsize, 0 },
	{ "printf-noformat", case_printf_noformat, 0 },
	{ "freopen", case_freopen_system, 0 },
	{ "stack", case_stack_frames, 0 },
	{ "hist-mismatch", case_hist_mismatch, 0 },
	{ "hist-empty", case_hist_empty, 0 },
	{ "hist-utf8", case_hist_utf8, 0 },
	{ "stddev", case_stddev_property, 0 },
	{ "aggpack-extremes", case_aggpack_extremes, 0 },
	{ "agghist-avg", case_agghist_avg, 0 },
	{ "agg-keys", case_agg_symbolic_keys, 0 },
	{ "bytes", case_bytes, 0 },
	{ "immstack-indent", case_immstack_indent, 0 },
	{ "ustack-indent", case_ustack_indent, 0 },
	{ "immstack-format", case_immstack_format, 0 },
	{ "aggdesc-value-only", case_aggdesc_value_only, 0 },
	{ "consume-paths", case_consume_paths, 0 },
	{ "begin-paths", case_begin_paths, 0 },
	{ "temporal-paths", case_temporal_paths, 0 },
	{ "buffered", case_buffered, 0 },
	{ "record-edges", case_record_edges, 0 },
	{ "flow-more", case_flow_more, 0 },
	{ "record-more", case_record_more, 0 },
	{ "consumer-buffers", case_consumer_buffers, 0 },
	{ "work-more", case_work_more, 0 },
	{ "oformat-records", case_oformat_records, 1 },
	{ "oformat-aggregations", case_oformat_tuples, 1 },
	{ "oformat-drops", case_oformat_drops, 1 },
	{ "oformat-drops-temporal", case_oformat_drops_temporal, 1 },
	{ "oformat-errors", case_oformat_errors, 1 },
	{ "quiesced-oformat", case_quiesced_oformat, 1 },
	{ "oformat-edges", case_oformat_edges, 1 },
	{ "oformat-more", case_oformat_more, 1 },
#ifdef FAULT_MALLOC
	{ "malloc-failures", case_malloc_failures, 1 },
	{ "malloc-failures-oformat", case_malloc_failures_oformat, 1 },
	{ "nodev-ustack", case_nodev_ustack, 1 },
	{ "nodev-ustack-oformat", case_nodev_ustack_oformat, 1 },
	{ "nodev-uaddr-256", case_nodev_boundary, 1 },
	{ "nodev-uaddr-256-oformat", case_nodev_boundary_oformat, 1 },
	{ "nodev-more", case_nodev_more, 1 },
	{ "nodev-more-oformat", case_nodev_more_oformat, 1 },
	{ "nodev-go-enotty", case_nodev_go_enotty, 1 },
	{ "print-xo-allocation", case_print_xo_allocation, 1 },
	{ "cpu-count-failure", case_cpu_count_failure, 1 },
#endif
};

int
main(int argc, char **argv)
{
	size_t i;

	check_phaseup();
	if (argc >= 2 && strcmp(argv[1], "packed-term") == 0) {
		case_packed_term(argc >= 3 && strcmp(argv[2], "auto") != 0 ?
		    argv[2] : NULL);
		reset_model();
		printf("%d passed, %d failed\n", passes, failures);
		return (failures != 0);
	}
	for (i = 0; i < sizeof (cases) / sizeof (cases[0]); i++)
		if ((argc < 2 && !cases[i].separate) ||
		    (argc >= 2 && strcmp(argv[1], cases[i].name) == 0))
			cases[i].fn();
	reset_model();
	printf("%d passed, %d failed\n", passes, failures);
	return (failures != 0);
}
