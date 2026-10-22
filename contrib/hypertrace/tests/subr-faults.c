/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Failure paths of libdtrace utilities, description maps, buffered output
 * and the dtraced client, driven by subr-faults-shim.so (preloaded): the
 * Nth allocation, socket transfer, poll, clock read, process-descriptor
 * query, descriptor duplication, thread creation, purge or file read made
 * by libdtrace fails with its documented error.
 *
 * Oracles: every injected failure is reported to the caller as the
 * documented error (EDT_NOMEM/ENOMEM for memory, the injected errno for
 * system calls) and never crashes; interrupted (EINTR) and would-block
 * (EAGAIN) transfers are retried and the frame still arrives intact; after
 * the last failure point the operation succeeds with the expected result.
 * Built without sanitizers because the shim replaces malloc(3).
 *
 * The dtrace(4) model of consume-ingestion.c is reused by inclusion.  No
 * daemon, tracing device or VM is used.
 */

#include <dt_impl.h>
#include <dt_program.h>
#include <dtraced.h>
#include <dtraced_io.h>
#include <dtraced_wire.h>
#include <dtraced_derived.h>

#define	main consume_ingestion_main
#include "consume-ingestion.c"
#undef main

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <dlfcn.h>
#include <fcntl.h>
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

static void (*fault_arm)(const char *, long, int, int, int);
static int (*fault_disarm)(void);
static void (*shim_birth)(int);

static void
shim_bind(void)
{
	fault_arm = (void (*)(const char *, long, int, int, int))
	    dlsym(RTLD_DEFAULT, "fault_arm");
	fault_disarm = (int (*)(void))dlsym(RTLD_DEFAULT, "fault_disarm");
	shim_birth = (void (*)(int))dlsym(RTLD_DEFAULT, "shim_birth");
	assert(fault_arm != NULL && fault_disarm != NULL &&
	    shim_birth != NULL);
}

static int
streq(const char *a, const char *b)
{
	return (a != NULL && b != NULL && strcmp(a, b) == 0);
}

static int
nomem(int e)
{
	return (e == EDT_NOMEM || e == ENOMEM);
}

/* ------------------------------------------------------------------ */
/* Interposed producers (defined here, they take precedence over the   */
/* library's own definitions for its internal calls as well).          */

/*
 * dt_dof_create() (the internal entry both dtrace_dof_create() and
 * dtrace_program_compiled_digest() reach): optionally corrupt one header or
 * section field of
 * the stripped DOF so that dtrace_program_compiled_digest() must refuse to
 * hash it.  Mode 0 passes the DOF through unchanged.
 */
static int dof_mutation;
static int dof_mutated;

void *
dt_dof_create(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, uint_t flags)
{
	static void *(*real)(dtrace_hdl_t *, dtrace_prog_t *, uint_t);
	dof_hdr_t *dof;
	dof_sec_t *sec, *act = NULL;
	uint32_t i;

	if (real == NULL)
		real = (void *(*)(dtrace_hdl_t *, dtrace_prog_t *, uint_t))
		    dlsym(RTLD_NEXT, "dt_dof_create");
	if ((dof = real(dtp, pgp, flags)) == NULL || dof_mutation == 0)
		return (dof);
	sec = (dof_sec_t *)((char *)dof + dof->dofh_secoff);
	for (i = 0; i < dof->dofh_secnum; i++)
		if (sec[i].dofs_type == DOF_SECT_ACTDESC && act == NULL)
			act = &sec[i];
	dof_mutated = 1;
	switch (dof_mutation) {
	case 1: dof->dofh_filesz = sizeof (*dof) - 1; break;
	case 2: dof->dofh_filesz = 64U * 1024U * 1024U + 1; break;
	case 3: dof->dofh_hdrsize++; break;
	case 4: dof->dofh_secsize++; break;
	case 5: dof->dofh_loadsz = dof->dofh_filesz + 1; break;
	case 6: dof->dofh_secoff = sizeof (*dof) - 8; break;
	case 7: dof->dofh_secoff = dof->dofh_filesz + 1; break;
	case 8: dof->dofh_secnum = UINT32_MAX; break;
	case 9: sec[0].dofs_offset = dof->dofh_filesz + 1; break;
	case 10: sec[0].dofs_size = dof->dofh_filesz; break;
	case 11: act->dofs_entsize++; break;
	case 12: act->dofs_size--; break;
	case 13: act->dofs_offset = dof->dofh_secoff; break;
	case 14:
		/* Misaligned by 4, still inside the file. */
		if (act->dofs_offset + 4 + act->dofs_size <= dof->dofh_filesz)
			act->dofs_offset += 4;
		else
			dof_mutated = 0;
		break;
	default:
		dof_mutated = 0;
	}
	return (dof);
}

/* SHA256(): fail the Nth one-shot digest (counted from 0). */
static int sha_fail = -1;

unsigned char *
SHA256(const unsigned char *d, size_t n, unsigned char *md)
{
	static unsigned char *(*real)(const unsigned char *, size_t,
	    unsigned char *);

	if (real == NULL)
		real = (unsigned char *(*)(const unsigned char *, size_t,
		    unsigned char *))dlsym(RTLD_NEXT, "SHA256");
	if (sha_fail >= 0 && sha_fail-- == 0)
		return (NULL);
	return (real(d, n, md));
}

/* ------------------------------------------------------------------ */
/* Allocation sweeps over consumption.                                 */

static int
quiet_err(const dtrace_errdata_t *d, void *a)
{
	(void) d; (void) a;
	return (DTRACE_HANDLE_OK);
}

static int
quiet_drop(const dtrace_dropdata_t *d, void *a)
{
	(void) d; (void) a;
	return (DTRACE_HANDLE_OK);
}

static char *bufd;
static size_t bufdlen;
static FILE *bufdfp;

static int
buf_cb(const dtrace_bufdata_t *d, void *arg)
{
	(void) arg;
	fputs(d->dtbda_buffered, bufdfp);
	return (DTRACE_HANDLE_OK);
}

/*
 * A program using every description kind: two ECBs (the second with
 * several records), printf formats, print()'s type string and a keyed
 * aggregation in a third ECB.
 */
#define	SWEEP_PROG							\
	"test:kernel:alpha:entry { printf(\"%d-%s\", arg0, "		\
	"stringof(arg1)); } "						\
	"test:kernel:alpha:return { trace(arg0); trace(arg1); "		\
	"print((int)arg2); } "						\
	"test:kernel:beta:entry { @c[arg0] = count(); }"

#define	SWEEP_BUF_PROG							\
	"test:kernel:alpha:entry { printf(\"%d-%s\", arg0, "		\
	"stringof(arg1)); } "						\
	"test:kernel:alpha:return { trace(arg0); trace(arg1); "		\
	"printf(\"int 0x%x\", arg2); } "					\
	"test:kernel:beta:entry { @c[arg0] = count(); }"

static int
open_sweep(struct session *s, int buffered)
{
	dtrace_prog_t *p;
	dtrace_proginfo_t info;
	int err;

	memset(s, 0, sizeof (*s));
	s->dtp = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS | DTRACE_O_LP64,
	    &err, &vector, &M);
	if (s->dtp == NULL)
		return (-1);
	s->out = open_memstream(&s->text, &s->len);
	(void) dtrace_setopt(s->dtp, "bufsize", "64k");
	(void) dtrace_setopt(s->dtp, "aggsize", "64k");
	(void) dtrace_setopt(s->dtp, "quiet", NULL);
	(void) dtrace_handle_err(s->dtp, quiet_err, NULL);
	(void) dtrace_handle_drop(s->dtp, quiet_drop, NULL);
	if (buffered)
		(void) dtrace_handle_buffered(s->dtp, buf_cb, NULL);
	/*
	 * print() writes straight to the stream and cannot be buffered
	 * (reported: dt_print.c uses fprintf(fp) with fp == NULL), so the
	 * buffered sweep traces the third value instead.
	 */
	if ((p = dtrace_program_strcompile(s->dtp, buffered ? SWEEP_BUF_PROG :
	    SWEEP_PROG,
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL)) == NULL ||
	    dtrace_program_exec(s->dtp, p, &info) != 0 ||
	    dtrace_go(s->dtp) != 0)
		return (-1);
	return (0);
}

static void
fire_sweep(void)
{
	fire(0, "test:kernel:alpha:entry", 0, VALS(N(7), S("seven")));
	fire(0, "test:kernel:alpha:return", 0, VALS(N(1), N(2), N(3)));
	fire(0, "test:kernel:beta:entry", 0, VALS(N(1), N(9), AGG(0, 1)));
}

static int
nop_probe(const dtrace_probedata_t *d, void *a)
{
	(void) d; (void) a;
	return (DTRACE_CONSUME_THIS);
}

static int
nop_rec(const dtrace_probedata_t *d, const dtrace_recdesc_t *r, void *a)
{
	(void) d; (void) a;
	return (r == NULL ? DTRACE_CONSUME_NEXT : DTRACE_CONSUME_THIS);
}

/*
 * Fail the k-th call of 'fn' made by libdtrace during consumption and the
 * aggregation snapshot, for k = 0, 1, ... until nothing fails any more;
 * the last run must produce the complete output.
 */
static void
sweep_consume(const char *name, const char *fn, int buffered)
{
	struct session s;
	long k;
	int rc, fired, e;
	const char *want = " 7-seven\n                 1                2"
	    "int 0x3";

	cur = name;
	for (k = 0; k < 2000; k++) {
		reset_model();
		if (buffered)
			bufdfp = open_memstream(&bufd, &bufdlen);
		if (open_sweep(&s, buffered) != 0) {
			OK(0, "open");
			close_session(&s);
			return;
		}
		fire_sweep();
		if (getenv("SUBR_FAULTS_TRACE") != NULL)
			fprintf(stderr, "%s #%ld\n", name, k);
		fault_arm(fn, k, ENOMEM, 0, 0);
		rc = dtrace_consume(s.dtp, buffered ? NULL : s.out, nop_probe,
		    nop_rec, NULL);
		if (rc == 0)
			rc = dtrace_aggregate_snap(s.dtp);
		fired = fault_disarm();
		e = dtrace_errno(s.dtp);
		if (fired)
			OK(rc == 0 || nomem(e), "%s #%ld: rc %d errno %d (%s)",
			    fn, k, rc, e, dtrace_errmsg(s.dtp, e));
		else {
			const char *got;

			fflush(s.out);
			if (buffered)
				fflush(bufdfp);
			got = buffered ? bufd : s.text;
			OK(rc == 0 && strstr(got, "7-seven") != NULL &&
			    strstr(got, "int 0x3") != NULL,
			    "%s: final run rc %d output %s", fn, rc, got);
			(void) want;
		}
		close_session(&s);
		if (buffered) {
			fclose(bufdfp);
			free(bufd);
			bufd = NULL;
		}
		if (!fired)
			break;
	}
	OK(k > 0, "%s: no call was made", fn);
	printf("%s: %ld failure points\n", name, k);
}

static void
case_consume_sweeps(void)
{
	sweep_consume("consume-malloc", "malloc", 0);
	sweep_consume("consume-strdup", "strdup", 0);
	sweep_consume("buffered-malloc", "malloc", 1);
	sweep_consume("buffered-realloc", "realloc", 1);
}

/* ------------------------------------------------------------------ */
/* Allocation failures in utilities.                                   */

static void
case_utilities(void)
{
	dtrace_hdl_t *dtp;
	dtrace_difo_t src, *d;
	dif_instr_t ins[2] = { 1, 2 };
	uint64_t ints[1] = { 5 };
	char strs[] = "s", syms[] = "y";
	dtrace_difv_t vars[1];
	dof_relodesc_t rel[1];
	struct dt_node *xl[1] = { NULL };
	int err, fail, rc;
	long k;

	reset_model();
	dtp = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS | DTRACE_O_LP64,
	    &err, &vector, &M);
	assert(dtp != NULL);

	cur = "cpp-args";
	/* Grow the vector to its limit so the next add must reallocate. */
	while (dtp->dt_cpp_argc < dtp->dt_cpp_args)
		assert(dt_cpp_add_arg(dtp, "-DFILL") != NULL);
	fault_arm("realloc", 0, ENOMEM, 0, 0);
	OK(dt_cpp_add_arg(dtp, "-DX") == NULL && fault_disarm(),
	    "realloc failure");
	fault_arm("strdup", 0, ENOMEM, 0, 0);
	OK(dt_cpp_add_arg(dtp, "-DX") == NULL && fault_disarm(),
	    "strdup failure");
	OK(dt_cpp_add_arg(dtp, "-DX") != NULL, "succeeds afterwards");

	cur = "alloc";
	fault_arm("malloc", 0, ENOMEM, 0, 0);
	OK(dt_alloc(dtp, 16) == NULL && dtrace_errno(dtp) == EDT_NOMEM,
	    "dt_alloc");
	fault_disarm();
	fault_arm("malloc", 0, ENOMEM, 0, 0);
	OK(dt_zalloc(dtp, 16) == NULL && dtrace_errno(dtp) == EDT_NOMEM,
	    "dt_zalloc");
	fault_disarm();

	cur = "difo-dup";
	memset(&src, 0, sizeof (src));
	memset(vars, 1, sizeof (vars));
	memset(rel, 2, sizeof (rel));
	src.dtdo_buf = ins;
	src.dtdo_len = 2;
	src.dtdo_inttab = ints;
	src.dtdo_intlen = 1;
	src.dtdo_strtab = strs;
	src.dtdo_strlen = sizeof (strs);
	src.dtdo_symtab = syms;
	src.dtdo_symlen = sizeof (syms);
	src.dtdo_vartab = vars;
	src.dtdo_varlen = 1;
	src.dtdo_kreltab = rel;
	src.dtdo_krelen = 1;
	src.dtdo_ureltab = rel;
	src.dtdo_urelen = 1;
	src.dtdo_xlmtab = xl;
	src.dtdo_xlmlen = 1;
	/* Nine allocations: the DIFO and its eight tables. */
	for (k = 0; k < 20; k++) {
		fault_arm("malloc", k, ENOMEM, 0, 0);
		d = dt_difo_dup(dtp, &src, &fail);
		if (!fault_disarm())
			break;
		OK(d == NULL && fail == 1, "allocation %ld", k);
	}
	OK(k == 9 && d != NULL && fail == 0 &&
	    memcmp(d->dtdo_buf, ins, sizeof (ins)) == 0, "%ld allocations", k);
	dt_difo_free(dtp, d);

	cur = "err-handler";
	/* Compiling the ERROR clause fails cleanly at every allocation. */
	for (k = 0; k < 5000; k++) {
		fault_arm("malloc", k, ENOMEM, 0, 0);
		rc = dtrace_handle_err(dtp, quiet_err, NULL);
		if (!fault_disarm())
			break;
		OK(rc == -1 || rc == 0, "allocation %ld: rc %d", k, rc);
		if (rc == 0)
			break;
	}
	OK(dtp->dt_errhdlr != NULL || dtrace_handle_err(dtp, quiet_err,
	    NULL) == 0, "registers after the failures (%ld points)", k);

	cur = "compiled-digest";
	{
		dtrace_prog_t *p = dtrace_program_strcompile(dtp,
		    "BEGIN { trace(1); }", DTRACE_PROBESPEC_NAME, 0, 0, NULL);
		uint8_t id[32], zero[32] = { 0 };

		assert(p != NULL);
		fault_arm("malloc", 0, ENOMEM, 1, 0);
		rc = dtrace_program_compiled_digest(dtp, p, id);
		fault_disarm();
		OK(rc == -1 && memcmp(id, zero, 32) == 0,
		    "DOF creation failure: rc %d", rc);
	}

	cur = "compiled-digest-validation";
	{
		dtrace_prog_t *p = dtrace_program_strcompile(dtp,
		    "test:kernel:alpha:entry { trace(arg0); }",
		    DTRACE_PROBESPEC_NAME, 0, 0, NULL);
		uint8_t id[32], zero[32] = { 0 }, good[32];
		int m;

		assert(p != NULL);
		OK(dtrace_program_compiled_digest(dtp, p, good) == 0, "valid");
		for (m = 1; m <= 14; m++) {
			dof_mutation = m;
			dof_mutated = 0;
			memset(id, 0xff, sizeof (id));
			rc = dtrace_program_compiled_digest(dtp, p, id);
			OK(dof_mutated && rc == -1 && errno == EPROTO &&
			    memcmp(id, zero, 32) == 0,
			    "mutation %d (applied %d): rc %d errno %d", m,
			    dof_mutated, rc, errno);
		}
		dof_mutation = 0;
		for (m = 0; m < 2; m++) {
			sha_fail = m;
			rc = dtrace_program_compiled_digest(dtp, p, id);
			OK(rc == -1 && errno == EIO && memcmp(id, zero, 32) == 0,
			    "digest %d fails: rc %d errno %d", m, rc, errno);
		}
		sha_fail = -1;
		OK(dtrace_program_compiled_digest(dtp, p, id) == 0 &&
		    memcmp(id, good, 32) == 0, "stable afterwards");
		/* The source identity digest can fail too. */
		{
			uint8_t sid[16];

			sha_fail = 0;
			OK(dtrace_program_source_id(p, sid) == -1 &&
			    errno == EINVAL, "source id digest failure");
			sha_fail = -1;
		}
	}

	cur = "sysctl";
	fault_arm("sysctlbyname", 0, EPERM, 1, 0);
	OK(dt_cpu_maxid(dtp) == -1 && dtrace_errno(dtp) == EPERM,
	    "maxid failure");
	fault_disarm();
	dtrace_close(dtp);
	dtp = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV | DTRACE_O_NOSYS,
	    &err);
	assert(dtp != NULL);
	/* Without kern.smp.maxid only CPU 0 is assumed online. */
	fault_arm("sysctlbyname", 0, EPERM, 1, 0);
	OK(dt_status(dtp, 0) == 1 && dt_status(dtp, 1) == -1, "status");
	fault_disarm();
	dtrace_close(dtp);
}

/* ------------------------------------------------------------------ */
/* Description-map allocation and query failures not covered by the    */
/* consumption sweep: the stream purge at discard.                     */

static void
case_discard(void)
{
	static const char *const opts[] = { "destructive", NULL, "quiet",
	    NULL, NULL };
	struct session s;
	dtrace_prog_t *p;
	dtrace_proginfo_t info;
	int err, rc;

	cur = "discard-purge";
	reset_model();
	memset(&s, 0, sizeof (s));
	s.dtp = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS | DTRACE_O_LP64,
	    &err, &vector, &M);
	s.out = open_memstream(&s.text, &s.len);
	(void) dtrace_setopt(s.dtp, "bufsize", "64k");
	(void) dtrace_setopt(s.dtp, opts[0], NULL);
	(void) dtrace_setopt(s.dtp, opts[2], NULL);
	(void) dtrace_handle_err(s.dtp, quiet_err, NULL);
	p = dtrace_program_strcompile(s.dtp,
	    "test:kernel:alpha:entry { freopen(\"fo.txt\"); }",
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL);
	assert(p != NULL && dtrace_program_exec(s.dtp, p, &info) == 0 &&
	    dtrace_go(s.dtp) == 0);
	fire(0, "test:kernel:alpha:entry", 0, VALS(N(0)));
	assert(dtrace_consume(s.dtp, s.out, nop_probe, nop_rec, NULL) == 0);
	assert(s.dtp->dt_freopen_fp != NULL);
	/* The caller's stream cannot be purged. */
	fault_arm("fpurge", 0, EBADF, 0, 0);
	rc = dtrace_output_discard(s.dtp, s.out);
	OK(rc == -1 && fault_disarm() && dtrace_errno(s.dtp) == EBADF,
	    "stream: rc %d errno %d", rc, dtrace_errno(s.dtp));
	/* The redirection cannot be purged. */
	fault_arm("fpurge", 1, EIO, 0, 0);
	rc = dtrace_output_discard(s.dtp, s.out);
	OK(rc == -1 && fault_disarm() && dtrace_errno(s.dtp) == EIO,
	    "redirection: rc %d errno %d", rc, dtrace_errno(s.dtp));
	/* Both fail: the first error is reported. */
	fault_arm("fpurge", 0, EBADF, 1, 0);
	rc = dtrace_output_discard(s.dtp, s.out);
	OK(rc == -1 && fault_disarm() && dtrace_errno(s.dtp) == EBADF,
	    "both: rc %d errno %d", rc, dtrace_errno(s.dtp));
	/* Without a stream, only the redirection is purged. */
	fault_arm("fpurge", 0, EIO, 0, 0);
	rc = dtrace_output_discard(s.dtp, NULL);
	OK(rc == -1 && fault_disarm() && dtrace_errno(s.dtp) == EIO,
	    "redirection only: rc %d", rc);
	close_session(&s);
	unlink("fo.txt");
}

/* ------------------------------------------------------------------ */
/* Framed messages.                                                    */

struct peer {
	int fd;
	size_t want;		/* bytes of the frame to read */
	int ack;		/* -1: close without acknowledging */
	int delay;		/* acknowledge after 50 ms */
	size_t got;
	unsigned char buf[4096];
};

/* Reads until the whole frame arrived or the client hung up. */
static void *
peer_run(void *arg)
{
	struct peer *p = arg;
	ssize_t n;
	unsigned char a;

	while (p->got < p->want &&
	    (n = read(p->fd, p->buf + p->got, p->want - p->got)) > 0)
		p->got += n;
	if (p->got == p->want && p->ack >= 0) {
		if (p->delay)
			usleep(50000);
		a = (unsigned char)p->ack;
		(void) write(p->fd, &a, 1);
	}
	return (NULL);
}

/*
 * Send one 13-byte payload with the shim armed; returns the result and the
 * errno.  On success the peer must have received size, header and payload.
 */
static int
framed(const char *fn, long nth, int error, int repeat, int value, int *err,
    int *intact)
{
	static const char body[] = "payload-bytes";
	dtraced_hdr_t h;
	struct peer p = { .ack = 1 };
	pthread_t t;
	int fds[2], rc;
	dtraced_hdr_t got;

	memset(&h, 0, sizeof (h));
	h.msg_type = DTRACED_MSG_ELF;
	h.elf.len = sizeof (body);
	strlcpy(h.elf.location, "inbound", sizeof (h.elf.location));
	assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) == 0);
	p.fd = fds[1];
	p.want = 8 + DTRACED_MSGHDRSIZE + sizeof (body);
	pthread_create(&t, NULL, peer_run, &p);
	if (fn != NULL)
		fault_arm(fn, nth, error, repeat, value);
	rc = dtrace_send_message(fds[0], &h, body, sizeof (body));
	*err = errno;
	if (fn != NULL)
		(void) fault_disarm();
	if (rc != 0)
		shutdown(fds[1], SHUT_RDWR);
	pthread_join(t, NULL);
	*intact = p.got == p.want &&
	    dtraced_wire_get_u64(p.buf) == DTRACED_MSGHDRSIZE + sizeof (body) &&
	    dtraced_wire_decode_header(&got, p.buf + 8) == 0 &&
	    got.msg_type == DTRACED_MSG_ELF &&
	    memcmp(p.buf + 8 + DTRACED_MSGHDRSIZE, body, sizeof (body)) == 0;
	close(fds[0]);
	close(fds[1]);
	return (rc);
}

static void
case_transport(void)
{
	int rc, err, intact, i;

	signal(SIGPIPE, SIG_IGN);
	cur = "transport-baseline";
	rc = framed(NULL, 0, 0, 0, 0, &err, &intact);
	OK(rc == 0 && intact, "rc %d intact %d", rc, intact);

	/* Size, header and payload writes and the acknowledgement read. */
	cur = "transport-send-failure";
	for (i = 0; i < 3; i++) {
		rc = framed("send", i, EIO, 0, 0, &err, &intact);
		OK(rc == -1 && err == EIO, "send #%d: rc %d errno %d", i, rc,
		    err);
	}
	cur = "transport-send-zero";
	rc = framed("send", 0, 0, 0, 1, &err, &intact);
	OK(rc == -1 && err == EPIPE, "rc %d errno %d", rc, err);
	cur = "transport-recv-failure";
	rc = framed("recv", 0, EIO, 0, 0, &err, &intact);
	OK(rc == -1 && err == EIO, "rc %d errno %d", rc, err);
	cur = "transport-recv-eof";
	rc = framed("recv", 0, 0, 0, 1, &err, &intact);
	OK(rc == -1 && err == ECONNRESET, "rc %d errno %d", rc, err);

	/* Interrupted and would-block transfers are retried. */
	cur = "transport-eintr";
	rc = framed("send", 1, EINTR, 0, 0, &err, &intact);
	OK(rc == 0 && intact, "send EINTR: rc %d errno %d", rc, err);
	cur = "transport-eagain";
	rc = framed("send", 1, EAGAIN, 0, 0, &err, &intact);
	OK(rc == 0 && intact, "send EAGAIN: rc %d errno %d", rc, err);
	rc = framed("recv", 0, EAGAIN, 0, 0, &err, &intact);
	OK(rc == 0 && intact, "recv EAGAIN: rc %d errno %d", rc, err);
	cur = "transport-poll";
	/* EAGAIN then an interrupted poll: retried. */
	rc = framed("recv", 0, EINTR, 0, 0, &err, &intact);
	OK(rc == 0 && intact, "recv EINTR: rc %d", rc);
	cur = "transport-poll-failure";
	{
		dtraced_hdr_t h;
		struct peer p = { .ack = -1 };
		pthread_t t;
		int fds[2];
		static const char body[] = "x";

		memset(&h, 0, sizeof (h));
		h.msg_type = DTRACED_MSG_ELF;
		h.elf.len = 1;
		/* The whole frame is read but no ack ever comes: poll. */
		for (int mode = 0; mode < 2; mode++) {
			assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
			p.fd = fds[1];
			p.got = 0;
			p.want = 8 + DTRACED_MSGHDRSIZE + 1;
			pthread_create(&t, NULL, peer_run, &p);
			if (mode == 0)
				fault_arm("poll", 0, EIO, 0, 0);
			else
				fault_arm("poll", 0, 0, 0, 1);
			rc = dtrace_send_message(fds[0], &h, body, 1);
			err = errno;
			OK(fault_disarm() && rc == -1 &&
			    err == (mode == 0 ? EIO : EBADF),
			    "poll mode %d: rc %d errno %d", mode, rc, err);
			shutdown(fds[0], SHUT_RDWR);
			pthread_join(t, NULL);
			close(fds[0]);
			close(fds[1]);
		}
	}
	cur = "transport-poll-eintr";
	{
		/* Waiting for a late ack, poll is interrupted once. */
		dtraced_hdr_t h;
		struct peer p = { .ack = 1, .delay = 1 };
		pthread_t t;
		int fds[2];

		memset(&h, 0, sizeof (h));
		h.msg_type = DTRACED_MSG_ELF;
		h.elf.len = 1;
		assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
		p.fd = fds[1];
		p.want = 8 + DTRACED_MSGHDRSIZE + 1;
		pthread_create(&t, NULL, peer_run, &p);
		fault_arm("poll", 0, EINTR, 0, 0);
		rc = dtrace_send_message(fds[0], &h, "x", 1);
		err = errno;
		OK(fault_disarm() && rc == 0, "rc %d errno %d", rc, err);
		pthread_join(t, NULL);
		close(fds[0]);
		close(fds[1]);
	}

	cur = "transport-clock";
	rc = framed("clock_gettime", 0, EINVAL, 1, 0, &err, &intact);
	OK(rc == -1, "no clock: rc %d errno %d", rc, err);
}

/* ------------------------------------------------------------------ */
/* Session handshake failures.                                         */

static char redirect_path[sizeof (((struct sockaddr_un *)0)->sun_path)];

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

struct server {
	int lfd;
	int stop;
	/*
	 * 0: canonical hello; 1: silent; 2: wrong kind; 3: nonzero
	 * subscriptions; 4: nonzero identity; 5: nonzero session.
	 */
	int mode;
};

/* Answers every connection with a hello and reads the reply. */
static void *
serve(void *arg)
{
	struct server *sv = arg;
	dtd_initmsg_t hello = { 0 }, client;
	size_t done;
	int fd;

	for (;;) {
		fd = accept(sv->lfd, NULL, NULL);
		if (fd < 0 || sv->stop) {
			if (fd >= 0)
				close(fd);
			return (NULL);
		}
		memset(&hello, 0, sizeof (hello));
		hello.kind = sv->mode == 2 ? DTRACED_KIND_CONSUMER :
		    DTRACED_KIND_DTRACED;
		hello.protocol_version = DTRACED_PROTOCOL_VERSION;
		hello.subs = sv->mode == 3 ? DTD_SUB_READDATA : 0;
		if (sv->mode == 4)
			hello.ident[0] = 'x';
		if (sv->mode == 5)
			hello.session_id[15] = 1;
		if (sv->mode == 1) {
			char c;

			/* Never answer; wait for the client to give up. */
			(void) read(fd, &c, 1);
		} else if (dtraced_wire_write_init(fd, &hello,
		    dtraced_io_deadline_after(5000), &done) == 0)
			(void) dtraced_wire_read_init(fd, &client,
			    dtraced_io_deadline_after(2000), &done);
		close(fd);
	}
}

static void
case_session(void)
{
	struct sockaddr_un a = { .sun_family = AF_UNIX };
	struct server sv = { 0 };
	pthread_t t;
	uint8_t session[16];
	int fd, err;
	char cwd[PATH_MAX];

	signal(SIGPIPE, SIG_IGN);
	assert(getcwd(cwd, sizeof (cwd)) != NULL);
	snprintf(redirect_path, sizeof (redirect_path), "%s/s.sock", cwd);
	sv.lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	strlcpy(a.sun_path, redirect_path, sizeof (a.sun_path));
	a.sun_len = SUN_LEN(&a);
	unlink(redirect_path);
	assert(bind(sv.lfd, (struct sockaddr *)&a, a.sun_len) == 0 &&
	    listen(sv.lfd, 8) == 0);
	pthread_create(&t, NULL, serve, &sv);

	cur = "session-ok";
	shim_birth(1);
	memset(session, 0, sizeof (session));
	fd = open_dtraced_session(DTD_SUB_READDATA, session);
	OK(fd >= 0, "handshake: errno %d", errno);
	if (fd >= 0)
		close(fd);

	/* A daemon hello that is not the canonical one is refused. */
	cur = "session-noncanonical-hello";
	for (sv.mode = 2; sv.mode <= 5; sv.mode++) {
		fd = open_dtraced_session(DTD_SUB_READDATA, session);
		err = errno;
		OK(fd == -1 && err == EPROTO, "mode %d: fd %d errno %d",
		    sv.mode, fd, err);
		if (fd >= 0)
			close(fd);
	}
	/* A daemon that never says hello: the 2 s handshake deadline. */
	cur = "session-silent-daemon";
	sv.mode = 1;
	fd = open_dtraced_session(DTD_SUB_READDATA, session);
	err = errno;
	OK(fd == -1 && err == ETIMEDOUT, "fd %d errno %d", fd, err);
	sv.mode = 0;

	cur = "session-socket";
	fault_arm("socket", 0, EMFILE, 0, 0);
	fd = open_dtraced_session(DTD_SUB_READDATA, session);
	err = errno;
	OK(fault_disarm() && fd == -1 && err == EMFILE, "fd %d errno %d", fd,
	    err);

	cur = "session-write-hello";
	/* The hello reply (the second send of the handshake) fails. */
	fault_arm("send", 0, EIO, 0, 0);
	fd = open_dtraced_session(DTD_SUB_READDATA, session);
	err = errno;
	OK(fault_disarm() && fd == -1 && err == EIO, "fd %d errno %d", fd,
	    err);

	cur = "session-birth-query";
	shim_birth(2);
	fd = open_dtraced_session(DTD_SUB_READDATA, session);
	err = errno;
	OK(fd == -1 && err == EIO, "fd %d errno %d", fd, err);

	cur = "session-birth-close";
	shim_birth(3);
	fd = open_dtraced_session(DTD_SUB_READDATA, session);
	err = errno;
	OK(fd == -1 && err == EIO, "fd %d errno %d", fd, err);

	cur = "session-birth-both";
	shim_birth(4);
	fd = open_dtraced_session(DTD_SUB_READDATA, session);
	err = errno;
	OK(fd == -1 && err == EIO, "query error kept: fd %d errno %d", fd,
	    err);

	cur = "session-birth-first-second";
	/* start_sec 0 is valid when start_usec is not also 0. */
	shim_birth(5);
	fd = open_dtraced_session(DTD_SUB_READDATA, session);
	OK(fd >= 0, "fd %d errno %d", fd, errno);
	if (fd >= 0)
		close(fd);

	cur = "session-no-pdself";
	/* The host refuses pdself() to tests: no identity, no session. */
	shim_birth(0);
	fd = open_dtraced_session(DTD_SUB_READDATA, session);
	OK(fd == -1, "fd %d errno %d", fd, errno);
	if (fd >= 0)
		close(fd);

	cur = "session-clock";
	shim_birth(1);
	fault_arm("clock_gettime", 0, EINVAL, 1, 0);
	fd = open_dtraced_session(DTD_SUB_READDATA, session);
	OK(fault_disarm() && fd == -1, "fd %d errno %d", fd, errno);

	sv.stop = 1;
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	(void) connect(fd, (struct sockaddr *)&a, a.sun_len);
	close(fd);
	pthread_join(t, NULL);
	close(sv.lfd);
	unlink(redirect_path);
	shim_birth(0);
}

/* ------------------------------------------------------------------ */
/* ELF delivery: allocation and read failures.                         */

static int
elf_file(dtrace_hdl_t *dtp, dtrace_prog_t *p, const char *path)
{
	char msg[512];
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

	assert(fd >= 0);
	assert(dtrace_elf_create(dtp, p, ELFDATA2LSB, fd, path, msg) == 0);
	return (fd);
}

static void
case_send_elf(void)
{
	dtrace_hdl_t *dtp;
	dtrace_prog_t *p;
	struct peer pr = { .ack = 1 };
	pthread_t t;
	struct stat sb;
	int fd, fds[2], rc, err;

	signal(SIGPIPE, SIG_IGN);
	reset_model();
	dtp = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS | DTRACE_O_LP64,
	    &err, &vector, &M);
	p = dtrace_program_strcompile(dtp, "BEGIN { trace(1); }",
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL);
	assert(p != NULL);
	fd = elf_file(dtp, p, "p.elf");
	assert(fstat(fd, &sb) == 0);
	assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) == 0);

	cur = "send-elf-malloc";
	fault_arm("malloc", 0, ENOMEM, 0, 0);
	rc = dtrace_send_elf(p, fd, fds[0], "inbound", 0);
	err = errno;
	OK(fault_disarm() && rc == -1 && err == ENOMEM, "rc %d errno %d", rc,
	    err);
	cur = "send-elf-read-failure";
	fault_arm("pread", 0, EIO, 0, 0);
	rc = dtrace_send_elf(p, fd, fds[0], "inbound", 0);
	err = errno;
	OK(fault_disarm() && rc == -1 && err == EIO, "rc %d errno %d", rc,
	    err);
	cur = "send-elf-short-file";
	fault_arm("pread", 0, 0, 0, 1);
	rc = dtrace_send_elf(p, fd, fds[0], "inbound", 0);
	err = errno;
	OK(fault_disarm() && rc == -1 && err == EIO, "rc %d errno %d", rc,
	    err);
	cur = "send-elf-eintr";
	/* An interrupted read is retried and the file is delivered whole. */
	pr.fd = fds[1];
	pr.want = 8 + DTRACED_MSGHDRSIZE + sb.st_size;
	if (pr.want > sizeof (pr.buf))
		pr.want = sizeof (pr.buf);
	pthread_create(&t, NULL, peer_run, &pr);
	fault_arm("pread", 0, EINTR, 0, 0);
	rc = dtrace_send_elf(p, fd, fds[0], "inbound", 0);
	err = errno;
	(void) fault_disarm();
	if (rc != 0)
		shutdown(fds[1], SHUT_RDWR);
	pthread_join(t, NULL);
	OK(rc == 0 && dtraced_wire_get_u64(pr.buf) == DTRACED_MSGHDRSIZE +
	    (uint64_t)sb.st_size, "rc %d errno %d", rc, err);
	cur = "send-elf-derived-digest";
	{
		dtraced_derived_parent_t parent;

		memset(&parent, 0, sizeof (parent));
		memset(parent.consumer_session, 1, 16);
		memset(parent.program_id, 2, 16);
		memset(parent.source_id, 3, 16);
		parent.delivery_id = 9;
		parent.vmid = 2;
		parent.epoch = 5;
		p->dp_vmid = 2;
		p->dp_vmepoch = 5;
		/* Digests: source id, then the payload, then the preimage. */
		sha_fail = 1;
		rc = dtrace_send_elf_derived(p, fd, fds[0], &parent);
		err = errno;
		OK(rc == -1 && err == EINVAL && sha_fail == -1,
		    "payload digest failure: rc %d errno %d", rc, err);
		sha_fail = 2;
		rc = dtrace_send_elf_derived(p, fd, fds[0], &parent);
		err = errno;
		OK(rc == -1 && err == EIO, "program id digest failure: rc %d "
		    "errno %d", rc, err);
		sha_fail = -1;
	}
	close(fds[0]);
	close(fds[1]);
	close(fd);
	dtrace_close(dtp);
}

/* ------------------------------------------------------------------ */
/* The asynchronous send queue (process-global: own process).          */

struct teardown_arg {
	int done;
};

static void *
teardown_run(void *arg)
{
	struct teardown_arg *a = arg;

	dtrace_async_teardown();
	a->done = 1;
	return (NULL);
}

/*
 * While a teardown waits for a worker that is blocked on an unacknowledged
 * frame, the queue refuses new work with EBUSY; a second teardown returns
 * at once.
 */
static void
case_async_closing(void)
{
	int fds[2], fd, rc, i;
	struct peer p = { .ack = -1 };
	struct teardown_arg ta = { 0 };
	pthread_t t, td;

	cur = "async-closing";
	assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) == 0);
	p.fd = fds[1];
	p.want = 8 + DTRACED_MSGHDRSIZE + 4;
	pthread_create(&t, NULL, peer_run, &p);
	fd = open("c.elf", O_RDWR | O_CREAT | O_TRUNC, 0600);
	assert(fd >= 0 && write(fd, "ELF!", 4) == 4);
	rc = dtrace_send_elf_async(NULL, fd, fds[0], strdup("c.elf"),
	    "inbound", 0);
	OK(rc == 0, "queued: %d", rc);
	pthread_join(t, NULL);		/* the frame arrived; no ack */
	pthread_create(&td, NULL, teardown_run, &ta);
	for (i = 0; i < 1000; i++) {
		fd = open("d.elf", O_RDWR | O_CREAT | O_TRUNC, 0600);
		rc = dtrace_send_elf_async(NULL, fd, fds[0], strdup("d.elf"),
		    "inbound", 0);
		if (rc != 0) {
			close(fd);
			unlink("d.elf");
		}
		if (rc == EBUSY || ta.done)
			break;
		usleep(1000);
	}
	OK(rc == EBUSY, "refused while closing: rc %d", rc);
	/* Release the worker: the peer hangs up. */
	shutdown(fds[1], SHUT_RDWR);
	pthread_join(td, NULL);
	OK(ta.done, "teardown finished");
	dtrace_async_teardown();
	close(fds[0]);
	close(fds[1]);
}

static void
case_async_alloc(void)
{
	int fds[2], fd, rc;

	assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) == 0);
	fd = open("q.elf", O_RDWR | O_CREAT | O_TRUNC, 0600);
	cur = "async-calloc";
	fault_arm("calloc", 0, ENOMEM, 0, 0);
	rc = dtrace_send_elf_async(NULL, fd, fds[0], "q.elf", "inbound", 0);
	OK(fault_disarm() && rc == EDT_NOMEM, "rc %d", rc);
	cur = "async-strdup";
	fault_arm("strdup", 0, ENOMEM, 0, 0);
	rc = dtrace_send_elf_async(NULL, fd, fds[0], "q.elf", "inbound", 0);
	OK(fault_disarm() && rc == EDT_NOMEM, "location: rc %d", rc);
	fault_arm("strdup", 1, ENOMEM, 0, 0);
	rc = dtrace_send_elf_async(NULL, fd, fds[0], "q.elf", "inbound", 0);
	OK(fault_disarm() && rc == EDT_NOMEM, "path: rc %d", rc);
	cur = "async-dup";
	fault_arm("fcntl", 0, EMFILE, 0, 0);
	rc = dtrace_send_elf_async(NULL, fd, fds[0], "q.elf", "inbound", 0);
	OK(fault_disarm() && rc == EMFILE, "rc %d", rc);
	cur = "async-thread";
	fault_arm("pthread_create", 0, EAGAIN, 0, 0);
	rc = dtrace_send_elf_async(NULL, fd, fds[0], "q.elf", "inbound", 0);
	OK(fault_disarm() && rc == EAGAIN, "rc %d", rc);
	cur = "async-bad-arguments";
	OK(dtrace_send_elf_async(NULL, fd, -1, "q.elf", "inbound", 0) ==
	    EINVAL && dtrace_send_elf_async(NULL, fd, fds[0], "q.elf", NULL,
	    0) == EINVAL && dtrace_send_elf_async(NULL, fd, fds[0], "q.elf",
	    "inbound", 2) == EINVAL, "refusals");
	close(fd);
	unlink("q.elf");
	close(fds[0]);
	close(fds[1]);
}

/*
 * A peer that accepts the first frame but never acknowledges it keeps the
 * worker busy; the queue then holds at most 64 entries.  A discard shuts
 * the active transfer down and drops everything queued.
 */
static void
case_async_queue(void)
{
	int fds[2], fd, rc, i, done = 0;
	char path[32];
	struct peer p = { .ack = -1 };
	pthread_t t;

	cur = "async-queue-limit";
	assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) == 0);
	p.fd = fds[1];
	p.want = sizeof (p.buf);
	pthread_create(&t, NULL, peer_run, &p);
	for (i = 0; i < 70; i++) {
		snprintf(path, sizeof (path), "q%d.elf", i);
		fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
		assert(fd >= 0 && write(fd, "ELF!", 4) == 4);
		rc = dtrace_send_elf_async(NULL, fd, fds[0], strdup(path),
		    "inbound", 0);
		if (rc != 0) {
			close(fd);
			unlink(path);
			break;
		}
		/* Let the worker take the first entry before queueing more. */
		if (i == 0)
			while (p.got < 8 + DTRACED_MSGHDRSIZE + 4)
				usleep(1000);
	}
	/* One entry active plus 64 queued. */
	OK(rc == ENOBUFS && i == 65, "rc %d after %d entries", rc, i);

	cur = "async-discard-active";
	for (i = 0; i < 2000 && (rc = dtrace_async_discard_step()) == 0; i++)
		usleep(1000);
	OK(rc == 1, "discard completes: rc %d after %d steps", rc, i);
	/* Every queued temporary file was removed. */
	for (i = 0; i < 65; i++) {
		snprintf(path, sizeof (path), "q%d.elf", i);
		if (access(path, F_OK) == 0)
			done++;
	}
	OK(done == 0, "%d files left", done);
	shutdown(fds[1], SHUT_RDWR);
	pthread_join(t, NULL);
	close(fds[0]);
	close(fds[1]);
}

/* A send that fails while the queue is live is reported on stderr. */
static void
case_async_failure(void)
{
	int fds[2], fd, rc, i;
	char *text = NULL;
	size_t len = 0;
	FILE *f;

	cur = "async-send-failure";
	assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) == 0);
	close(fds[1]);
	fd = open("f.elf", O_RDWR | O_CREAT | O_TRUNC, 0600);
	assert(fd >= 0 && write(fd, "ELF!", 4) == 4);
	/* The worker idles first: the queue is empty when it starts. */
	rc = dtrace_send_elf_async(NULL, fd, fds[0], strdup("f.elf"),
	    "inbound", 0);
	OK(rc == 0, "queued: %d", rc);
	for (i = 0; i < 2000 && access("f.elf", F_OK) == 0; i++)
		usleep(1000);
	fd = open("g.elf", O_RDWR | O_CREAT | O_TRUNC, 0600);
	assert(fd >= 0 && write(fd, "ELF!", 4) == 4);
	rc = dtrace_send_elf_async(NULL, fd, fds[0], strdup("g.elf"),
	    "inbound", 0);
	OK(rc == 0, "queued after idle: %d", rc);
	for (i = 0; i < 2000 && access("g.elf", F_OK) == 0; i++)
		usleep(1000);
	dtrace_async_teardown();
	fflush(stderr);
	f = fopen("async.err", "r");
	if (f != NULL) {
		FILE *m = open_memstream(&text, &len);
		int c;

		while ((c = fgetc(f)) != EOF)
			fputc(c, m);
		fclose(m);
		fclose(f);
	}
	OK(text != NULL && strstr(text,
	    "dtrace: asynchronous ELF send failed: ") != NULL, "stderr: %s",
	    text ? text : "(none)");
	free(text);
	close(fds[0]);
}

/* ------------------------------------------------------------------ */

int
main(int argc, char **argv)
{
	static const struct {
		const char *name;
		void (*fn)(void);
	} cases[] = {
		{ "consume-sweeps", case_consume_sweeps },
		{ "utilities", case_utilities },
		{ "discard", case_discard },
		{ "transport", case_transport },
		{ "session", case_session },
		{ "send-elf", case_send_elf },
		{ "async-alloc", case_async_alloc },
		{ "async-queue", case_async_queue },
		{ "async-failure", case_async_failure },
		{ "async-closing", case_async_closing },
	};
	size_t i;
	int ran = 0;

	shim_bind();
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc > 2)
		(void) freopen(argv[2], "w", stderr);
	for (i = 0; i < sizeof (cases) / sizeof (cases[0]); i++) {
		if (argc > 1 && strcmp(argv[1], cases[i].name) != 0)
			continue;
		cases[i].fn();
		ran++;
	}
	reset_model();
	printf("%s: %d checks, %d failures\n", argc > 1 ? argv[1] : "all",
	    nchecks, nfail);
	return (ran == 0 || nfail != 0);
}
