/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Program errors are returned, not fatal.
 *
 * A type or link error found by hypertrace_link() marks the program
 * (dp_haserror, dp_err) and is returned to the caller as an
 * E_HYPERTRACE_* code with the message; the process continues.  For a
 * guest (dt_is_guest), the erroneous program is first forwarded to dtraced;
 * a forwarding failure is returned too, and the temporary file is removed
 * in every case.  Before this change dt_set_progerr() ended the process
 * (errx), so every case here failed with exit status 1 (evidence:
 * lib-typing-20261021/progerr-before.log in the validation tree).
 *
 * The guest cases redirect connect() to a fake dtraced on a socket in
 * TMPDIR; dtraced-client-shim.so (preloaded by typing-inference.py)
 * supplies the process birth identity the client handshake needs.
 */
#include "typing-unit.h"

#include <sys/socket.h>
#include <sys/un.h>

#include <dirent.h>
#include <dlfcn.h>
#include <glob.h>
#include <malloc_np.h>
#include <pthread.h>

#include <dtraced.h>
#include <dtraced_io.h>
#include <dtraced_wire.h>

namespace {

/* A program whose action casts a value to a type no module has. */
dtrace_prog_t *
ill_typed()
{
	Difo d;
	d.code = { DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_ARG0, 1),
		DIF_INSTR_TYPECAST(d.sym("struct no_such_type *"), 1),
		DIF_INSTR_RET(1) };
	return (program_with(d));
}

const char *const ILL_TYPED_MSG = "failed to get type struct no_such_type *";

size_t
allocated()
{
	uint64_t epoch = 1;
	size_t sz = sizeof(epoch), v = 0, vs = sizeof(v);
	/* Objects cached by the thread count as allocated: flush them. */
	mallctl("thread.tcache.flush", nullptr, nullptr, nullptr, 0);
	mallctl("epoch", &epoch, &sz, &epoch, sz);
	if (mallctl("stats.allocated", &v, &vs, nullptr, 0) != 0)
		return (0);
	return (v);
}

/* ---- connect() redirection and a fake dtraced ----------------------- */

char redirect_path[sizeof(((struct sockaddr_un *)0)->sun_path)];

} // namespace

extern "C" int
connect(int s, const struct sockaddr *name, socklen_t namelen)
{
	static int (*real)(int, const struct sockaddr *, socklen_t);
	if (real == nullptr)
		real = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(
		    RTLD_NEXT, "connect");
	if (name->sa_family == AF_UNIX &&
	    strcmp(((const struct sockaddr_un *)name)->sun_path,
	    DTRACED_SOCKPATH) == 0) {
		if (redirect_path[0] == '\0') {
			errno = ENOENT;
			return (-1);
		}
		struct sockaddr_un alt;
		memset(&alt, 0, sizeof(alt));
		alt.sun_family = AF_UNIX;
		strlcpy(alt.sun_path, redirect_path, sizeof(alt.sun_path));
		alt.sun_len = SUN_LEN(&alt);
		return (real(s, (struct sockaddr *)&alt, alt.sun_len));
	}
	return (real(s, name, namelen));
}

/* Fault points of the guest's forwarding, armed one at a time. */
namespace {
enum Fault { NONE, ELF_CREATE, FSYNC, LSEEK } fault = NONE;
bool lseek_armed; /* LSEEK: the lseek() after the fsync() fails */
} // namespace

extern "C" int
dtrace_elf_create(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, int endian, int fd,
    const char *name, hypertrace_errmsg_t msg)
{
	static int (*real)(dtrace_hdl_t *, dtrace_prog_t *, int, int,
	    const char *, char *);
	if (real == nullptr)
		real = (int (*)(dtrace_hdl_t *, dtrace_prog_t *, int, int,
		    const char *, char *))dlsym(RTLD_NEXT, "dtrace_elf_create");
	if (fault == ELF_CREATE) {
		strlcpy(msg, "injected", HYPERTRACE_ERRMSGLEN);
		return (E_HYPERTRACE_ELFCREATE);
	}
	return (real(dtp, pgp, endian, fd, name, msg));
}

extern "C" int
fsync(int fd)
{
	static int (*real)(int);
	if (real == nullptr)
		real = (int (*)(int))dlsym(RTLD_NEXT, "fsync");
	if (fault == FSYNC) {
		errno = EIO;
		return (-1);
	}
	lseek_armed = fault == LSEEK;
	return (real(fd));
}

extern "C" off_t
lseek(int fd, off_t off, int whence)
{
	static off_t (*real)(int, off_t, int);
	if (real == nullptr)
		real = (off_t (*)(int, off_t, int))dlsym(RTLD_NEXT, "lseek");
	if (fault == LSEEK && lseek_armed) {
		lseek_armed = false;
		errno = ESPIPE;
		return (-1);
	}
	return (real(fd, off, whence));
}

namespace {

struct FakeDtraced {
	enum Mode { ACK, NO_ACK } mode = ACK;
	int lfd = -1;
	pthread_t thr;
	bool got_frame = false;
	std::string payload;

	explicit FakeDtraced(Mode m) : mode(m)
	{
		/* The case's TMPDIR when the process started (cases change
		 * TMPDIR itself). */
		static const std::string dir = getenv("TMPDIR");
		snprintf(redirect_path, sizeof(redirect_path), "%s/sub.sock",
		    dir.c_str());
		unlink(redirect_path);
		struct sockaddr_un a;
		memset(&a, 0, sizeof(a));
		a.sun_family = AF_UNIX;
		strlcpy(a.sun_path, redirect_path, sizeof(a.sun_path));
		a.sun_len = SUN_LEN(&a);
		lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
		CHECK(lfd >= 0 && bind(lfd, (struct sockaddr *)&a, a.sun_len) == 0 &&
		    listen(lfd, 4) == 0);
		pthread_create(&thr, nullptr, serve, this);
	}
	~FakeDtraced()
	{
		pthread_join(thr, nullptr);
		close(lfd);
		unlink(redirect_path);
		redirect_path[0] = '\0';
	}
	static void *
	serve(void *arg)
	{
		auto *f = (FakeDtraced *)arg;
		int fd = accept(f->lfd, nullptr, nullptr);
		if (fd < 0)
			return (nullptr);
		dtd_initmsg_t hello, client;
		size_t done;
		memset(&hello, 0, sizeof(hello));
		hello.kind = DTRACED_KIND_DTRACED;
		hello.protocol_version = DTRACED_PROTOCOL_VERSION;
		int64_t deadline = dtraced_io_deadline_after(5000);
		if (dtraced_wire_write_init(fd, &hello, deadline, &done) != 0 ||
		    dtraced_wire_read_init(fd, &client, deadline, &done) != 0) {
			close(fd);
			return (nullptr);
		}
		size_t len;
		unsigned char wire[DTRACED_MSGHDRSIZE];
		if (dtraced_io_read_size(fd, &len, deadline, &done) == 0 &&
		    len >= DTRACED_MSGHDRSIZE &&
		    dtraced_io_transfer(fd, wire, sizeof(wire), false, deadline,
		    &done) == 0) {
			std::string p(len - DTRACED_MSGHDRSIZE, '\0');
			if (p.empty() || dtraced_io_transfer(fd, p.data(),
			    p.size(), false, deadline, &done) == 0) {
				f->payload = p;
				f->got_frame = true;
			}
		}
		if (f->mode == ACK) {
			unsigned char ack = 1;
			(void)send(fd, &ack, 1, MSG_NOSIGNAL);
		}
		close(fd);
		return (nullptr);
	}
};

size_t
progerr_temp_files()
{
	glob_t g;
	std::string pat = std::string(getenv("TMPDIR")) +
	    "/ddtrace-set-prog-err.*";
	size_t n = 0;
	if (glob(pat.c_str(), 0, nullptr, &g) == 0)
		n = g.gl_pathc;
	globfree(&g);
	return (n);
}

void
birth_identity(int on)
{
	auto set = (void (*)(int, int))dlsym(RTLD_DEFAULT, "dtc_birth_set");
	CHECK(set != nullptr);
	set(on, 0);
}

} // namespace

CASE("error-returned-and-process-continues")
{
	dtrace_prog_t *p = ill_typed();
	std::string msg;
	int r = link(p, &msg);
	CHECKF(r == E_HYPERTRACE_TYPING, "link returned %d", r);
	CHECKF(msg.find(ILL_TYPED_MSG) != std::string::npos, "%s", msg.c_str());
	CHECK(p->dp_haserror && strstr(p->dp_err, ILL_TYPED_MSG) != nullptr);
	/* The process (and the handle) carry on: a valid program links. */
	dtrace_prog_t *q = compile("BEGIN { trace(curthread->td_tid); }");
	link_ok(q);
	CHECK(!q->dp_haserror);
	dt_program_destroy(handle(), p);
	dt_program_destroy(handle(), q);
}

CASE("kernel-dof-link-error-returned")
{
	/* A program that is not linked yet is linked for the kernel by
	 * dtrace_dof_create() (dtrace_program_exec(), anonymous DOF, the
	 * error program); a failed link is returned as a compiler error, with
	 * the type checker's message, and the process carries on. */
	/* Ill-typed, and holding a member offset only the linker resolves
	 * (USETX): it must be linked before the kernel can take it. */
	auto unlinked_ill_typed = []() {
		Difo d;
		d.code = { DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_ARG0, 1),
			DIF_INSTR_TYPECAST(d.sym("struct no_such_type *"), 1),
			DIF_INSTR_USETX(d.sym("p_pid"), 2),
			DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1),
			DIF_INSTR_RET(1) };
		return (program_with(d));
	};
	/* Only annotations: nothing to link, the DOF is made. */
	void *plain = dtrace_dof_create(handle(), ill_typed(), 0);
	CHECK(plain != nullptr);
	dtrace_dof_destroy(handle(), plain);
	dtrace_prog_t *p = unlinked_ill_typed();
	CHECK(dtrace_dof_create(handle(), p, 0) == nullptr);
	CHECK(dtrace_errno(handle()) == EDT_COMPILER);
	const char *m = dtrace_errmsg(handle(), EDT_COMPILER);
	CHECKF(strstr(m, ILL_TYPED_MSG) != nullptr, "%s", m);
	CHECK(p->dp_haserror);
	/* A link failure that is no program error: the linker's message. */
	dtrace_prog_t *q = unlinked_ill_typed();
	dt_stmt_t *st = (dt_stmt_t *)dt_list_next(&q->dp_stmts);
	st->ds_desc->dtsd_action_last = nullptr;
	CHECK(dtrace_dof_create(handle(), q, 0) == nullptr);
	CHECK(dtrace_errno(handle()) == EDT_COMPILER);
	m = dtrace_errmsg(handle(), EDT_COMPILER);
	CHECKF(strstr(m, "failed to link the program: ") != nullptr &&
	    strstr(m, "last action is NULL") != nullptr, "%s", m);
	CHECK(!q->dp_haserror);
	/* A valid program still makes its DOF. */
	dtrace_prog_t *r = compile("BEGIN { trace(curthread->td_tid); }");
	void *dof = dtrace_dof_create(handle(), r, 0);
	CHECK(dof != nullptr);
	dtrace_dof_destroy(handle(), dof);
}

CASE("kernel-dof-needs-link-by-instruction")
{
	/* Linking is needed exactly when a DIFO holds USETX, ULOAD or
	 * UULOAD (TYPECAST alone becomes a nop in the DOF). */
	struct {
		dif_instr_t op;
		int unlinked;
	} rows[] = {
		{ DIF_INSTR_LOAD(DIF_OP_ULOAD, 1, 1), 1 },
		{ DIF_INSTR_LOAD(DIF_OP_UULOAD, 1, 1), 1 },
		{ DIF_INSTR_LOAD(DIF_OP_LDX, 1, 1), 0 },
		{ DIF_INSTR_NOP, 0 },
	};
	for (auto &r : rows) {
		Difo d;
		d.code = { DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_ARG0, 1), r.op,
			DIF_INSTR_RET(1) };
		dtrace_prog_t *p = program_with(d);
		CHECK(dt_prog_unlinked(p) == r.unlinked);
	}
	Difo t;
	t.code = { DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_ARG0, 1),
		DIF_INSTR_TYPECAST(t.sym("int"), 1), DIF_INSTR_RET(1) };
	CHECK(dt_prog_unlinked(program_with(t)) == 0);
	/* A DIFO without code needs nothing. */
	dtrace_prog_t *p = compile("BEGIN { trace(1); }");
	dtrace_difo_t *d = first_action_difo(p);
	dif_instr_t *buf = d->dtdo_buf;
	d->dtdo_buf = nullptr;
	CHECK(dt_prog_unlinked(p) == 0);
	d->dtdo_buf = buf;
}

CASE("kernel-dof-link-allocation-failure-returned")
{
	/*
	 * dtrace_dof_create() (dtrace_program_exec()) links a program that
	 * needs it, so every allocation of the link may fail under a consumer
	 * such as lockstat.  Each failure is returned as EDT_NOMEM -- the
	 * linker's containers throw std::bad_alloc, which hypertrace_link()
	 * catches, and libctf's EAGAIN is not a program error -- and never
	 * terminates the process.  Every allocation is failed in turn (in a
	 * child each) until the DOF is made.
	 */
	const char *src = "BEGIN { trace(((struct proc *)arg0)->p_pid); }";
	int nomem = 0, bad = 0, n;
	std::string first_bad;
	for (n = 1; n <= 20000; n++) {
		fflush(stdout);
		pid_t pid = fork();
		if (pid == 0) {
			int fd = open("/dev/null", O_WRONLY);
			dup2(fd, STDERR_FILENO);
			dtrace_prog_t *p = compile(src, 0);
			fail_malloc_after(n);
			void *dof = dtrace_dof_create(handle(), p, 0);
			int e = dtrace_errno(handle());
			bool hit = fail_countdown() == 0;
			fail_malloc_after(0);
			if (dof != nullptr)
				exit(hit ? 11 : 0);	/* 0: nothing left to fail */
			exit(e == EDT_NOMEM ? 10 : 20);
		}
		int st;
		waitpid(pid, &st, 0);
		int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
		if (code == 0)
			break;
		if (code == 10)
			nomem++;
		else if (code != 11) {
			if (bad++ == 0)
				first_bad = std::to_string(n) + ": status " +
				    std::to_string(st);
		}
	}
	printf("  %d allocations failed in turn: %d EDT_NOMEM, %d bad%s%s\n",
	    n - 1, nomem, bad, bad ? ", first " : "", first_bad.c_str());
	fflush(stdout);
	CHECK(n <= 20000 && bad == 0 && nomem > 0);
}

CASE("errors-repeated-without-leaks")
{
	/* Warm up the handle's lazily built state, then fail many links. */
	for (int i = 0; i < 5; i++) {
		dtrace_prog_t *p = ill_typed();
		CHECK(link(p) == E_HYPERTRACE_TYPING);
		dt_program_destroy(handle(), p);
	}
	size_t before = allocated();
	const int N = 200;
	for (int i = 0; i < N; i++) {
		dtrace_prog_t *p = ill_typed();
		std::string msg;
		CHECK(link(p, &msg) == E_HYPERTRACE_TYPING);
		CHECK(msg.find(ILL_TYPED_MSG) != std::string::npos);
		dt_program_destroy(handle(), p);
	}
	size_t after = allocated();
	printf("errors-repeated-without-leaks: allocated before %zu after %zu "
	    "(%d failed links)\n", before, after, N);
	fflush(stdout);
	/* Allow a few KiB of caches; a per-link leak would grow by at least
	 * N times its size. */
	CHECKF(before == 0 || after < before + 64 * 1024,
	    "grew by %zu bytes over %d failed links", after - before, N);
	/* State is intact: a valid program still links with its types. */
	dtrace_prog_t *q = compile("BEGIN { trace(curthread->td_tid); }");
	link_ok(q);
}

CASE("valid-links-repeated-without-leaks")
{
	/*
	 * Regressions: the variable stacks of every link (dtdv_stack) were
	 * kept on a process-global list that was never released, and the
	 * per-instruction type names (dtdo_types) were never freed.  The D
	 * compiler leaks about 3 KB per further statement of a clause, which
	 * is not under test: single-statement clauses avoid it, and the
	 * growth of compiling alone is subtracted.
	 */
	const char *src = "BEGIN { x = 1; } BEGIN { self->y = 2; } "
	    "BEGIN { this->z = 3; } END { trace(x); }";
	auto growth = [&](bool dolink, int n) {
		for (int i = 0; i < 5; i++) {
			dtrace_prog_t *p = compile(src);
			if (dolink)
				link_ok(p);
			dt_program_destroy(handle(), p);
		}
		size_t before = allocated();
		for (int i = 0; i < n; i++) {
			dtrace_prog_t *p = compile(src);
			if (dolink)
				link_ok(p);
			dt_program_destroy(handle(), p);
		}
		return ((ssize_t)allocated() - (ssize_t)before);
	};
	const int N = 1000;
	ssize_t compiling = growth(false, N), linking = growth(true, N);
	printf("valid-links-repeated-without-leaks: %d compiles grew %zd "
	    "bytes, %d compiles and links %zd\n", N, compiling, N, linking);
	fflush(stdout);
	CHECKF(linking - compiling < 64 * 1024,
	    "linking added %zd bytes over %d links", linking - compiling, N);
}

CASE("type-files-released-after-link")
{
	/* No type file outlives its link: they refer to the handle's
	 * modules, which dtrace_close() frees, and the next link may be on
	 * another handle. */
	link_ok(compile("BEGIN { trace(curthread->td_tid); }"));
	CHECK(dt_typefile_kernel() == nullptr && dt_typefile_D() == nullptr);
	int err;
	for (int i = 0; i < 3; i++) {
		dtrace_hdl_t *h = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV,
		    &err);
		CHECK(h != nullptr);
		dtrace_hdl_t *saved = handle();
		handle() = h;
		link_ok(compile("BEGIN { x = curthread; trace(x->td_tid); }"));
		handle() = saved;
		dtrace_close(h);
		link_ok(compile("BEGIN { trace(curthread->td_proc->p_pid); }"));
	}
}

/*
 * Identifier hashes are populated from their template on first use.  An
 * allocation failure there used to longjmp() through yypcb, which is NULL
 * outside of a compilation (dtrace_open(), library callers): a crash.  It is
 * now returned (NULL / ENOMEM), and the next use resumes populating.
 */
namespace {
#define	DT_ATTR_STABCMN	{ DTRACE_STABILITY_STABLE, \
	DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON }
#define	DT_VERS_1_0	DT_VERSION_NUMBER(1, 0, 0)
dt_ident_t idhash_tmpl[] = {
	{ (char *)"alpha", DT_IDENT_SCALAR, 0, 1, DT_ATTR_STABCMN, DT_VERS_1_0,
	    nullptr, nullptr, nullptr, nullptr, nullptr, 0, nullptr, 0, 0 },
	{ (char *)"beta", DT_IDENT_SCALAR, 0, 2, DT_ATTR_STABCMN, DT_VERS_1_0,
	    nullptr, nullptr, nullptr, nullptr, nullptr, 0, nullptr, 0, 0 },
	{ (char *)"gamma", DT_IDENT_SCALAR, 0, 3, DT_ATTR_STABCMN, DT_VERS_1_0,
	    nullptr, nullptr, nullptr, nullptr, nullptr, 0, nullptr, 0, 0 },
	{ nullptr, 0, 0, 0, DT_ATTR_STABCMN, 0, nullptr, nullptr, nullptr,
	    nullptr, nullptr, 0, nullptr, 0, 0 },
};

int
count_ident(dt_idhash_t *, dt_ident_t *, void *data)
{
	(*(int *)data)++;
	return (0);
}
} // namespace

CASE("idhash-population-failure-outside-compilation")
{
	CHECK(yypcb == nullptr);
	for (int nth = 1; nth <= 4; nth++) {
		dt_idhash_t *h = dt_idhash_create("test", idhash_tmpl, 0, 100);
		CHECK(h != nullptr);
		/* Fail an allocation of the first population. */
		errno = 0;
		fail_malloc_after(nth);
		dt_ident_t *a = dt_idhash_lookup(h, "alpha");
		bool failed = fail_countdown() == 0;
		fail_malloc_after(0);
		if (failed)
			CHECKF(a == nullptr && errno == ENOMEM, "nth %d", nth);
		/* Iterating after a failure visits what is there; the next
		 * lookup resumes populating and finds every entry. */
		int n = 0;
		fail_malloc_after(1);
		(void)dt_idhash_iter(h, count_ident, &n);
		fail_malloc_after(0);
		CHECK(dt_idhash_lookup(h, "alpha") != nullptr &&
		    dt_idhash_lookup(h, "beta") != nullptr &&
		    dt_idhash_lookup(h, "gamma") != nullptr);
		n = 0;
		CHECK(dt_idhash_iter(h, count_ident, &n) == 0 && n == 3);
		dt_idhash_destroy(h);
	}
	/* Insertion reports the failure as an allocation failure. */
	dt_idhash_t *h = dt_idhash_create("test", idhash_tmpl, 0, 100);
	fail_malloc_after(1);
	const dtrace_attribute_t attr = DT_ATTR_STABCMN;
	dt_ident_t *d = dt_idhash_insert(h, "delta", DT_IDENT_SCALAR, 0, 4,
	    attr, DT_VERS_1_0, &dt_idops_thaw, nullptr, 0);
	fail_malloc_after(0);
	CHECK(d == nullptr);
	CHECK(dt_idhash_insert(h, "delta", DT_IDENT_SCALAR, 0, 4,
	    attr, DT_VERS_1_0, &dt_idops_thaw, nullptr, 0) != nullptr);
	CHECK(dt_idhash_lookup(h, "alpha") != nullptr);
	dt_idhash_destroy(h);
	/* A compilation (which populates the handle's hashes) still works. */
	link_ok(compile("BEGIN { trace(execname); }"));
}

CASE("guest-error-forwarded-to-dtraced")
{
	birth_identity(1);
	handle()->dt_is_guest = B_TRUE;
	size_t temps = progerr_temp_files();
	std::string payload;
	{
		FakeDtraced d(FakeDtraced::ACK);
		dtrace_prog_t *p = ill_typed();
		std::string msg;
		int r = link(p, &msg);
		CHECKF(r == E_HYPERTRACE_TYPING, "link returned %d: %s", r,
		    msg.c_str());
		CHECK(msg.find(ILL_TYPED_MSG) != std::string::npos);
		CHECK(d.got_frame);
		payload = d.payload;
	}
	/* dtraced received the erroneous program as an ELF file, and the
	 * temporary file is gone. */
	CHECK(payload.find("\x7f" "ELF") != std::string::npos);
	CHECK(progerr_temp_files() == temps);
	handle()->dt_is_guest = B_FALSE;
}

CASE("guest-error-without-dtraced")
{
	birth_identity(1);
	handle()->dt_is_guest = B_TRUE;
	size_t temps = progerr_temp_files();
	redirect_path[0] = '\0'; /* nothing listens */
	dtrace_prog_t *p = ill_typed();
	std::string msg;
	int r = link(p, &msg);
	CHECKF(r == E_HYPERTRACE_SYS, "link returned %d: %s", r, msg.c_str());
	CHECK(msg.find(ILL_TYPED_MSG) != std::string::npos);
	CHECK(msg.find("failed to open dtraced") != std::string::npos);
	CHECK(progerr_temp_files() == temps);
	handle()->dt_is_guest = B_FALSE;
}

CASE("guest-error-forwarding-not-acknowledged")
{
	birth_identity(1);
	handle()->dt_is_guest = B_TRUE;
	size_t temps = progerr_temp_files();
	{
		FakeDtraced d(FakeDtraced::NO_ACK);
		dtrace_prog_t *p = ill_typed();
		std::string msg;
		int r = link(p, &msg);
		CHECKF(r == E_HYPERTRACE_SYS, "link returned %d: %s", r,
		    msg.c_str());
		CHECK(msg.find("dtrace_send_elf() failed") != std::string::npos);
	}
	CHECK(progerr_temp_files() == temps);
	handle()->dt_is_guest = B_FALSE;
}

CASE("guest-forwards-once-for-several-errors")
{
	/* Three program errors in one link (the TypeInference constructor's
	 * lock type names): the program is forwarded once, with the first;
	 * the others are printed. */
	birth_identity(1);
	handle()->dt_is_guest = B_TRUE;
	strlcpy(mtx_str, "struct mtx", sizeof(mtx_str));
	strlcpy(rw_str, "struct rwlock", sizeof(rw_str));
	strlcpy(sx_str, "struct sx", sizeof(sx_str));
	size_t temps = progerr_temp_files();
	std::string payload;
	int frames = 0;
	{
		FakeDtraced d(FakeDtraced::ACK);
		dtrace_prog_t *p = compile("BEGIN { trace(1); }");
		std::string msg;
		int r = 0;
		std::string err = capture_stderr([&] { r = link(p, &msg); });
		CHECKF(r == E_HYPERTRACE_TYPING, "link returned %d: %s", r,
		    msg.c_str());
		CHECK(msg.find("mtx_str does not start") == 0);
		CHECK(strstr(p->dp_err, "mtx_str does not start") == p->dp_err);
		CHECK(err.find("rw_str does not start") != std::string::npos &&
		    err.find("sx_str does not start") != std::string::npos);
		frames = d.got_frame;
	}
	CHECK(frames == 1);
	CHECK(progerr_temp_files() == temps);
	handle()->dt_is_guest = B_FALSE;
}

CASE("guest-forwarding-failure-points")
{
	/* Each step of forwarding can fail; the failure is returned with its
	 * reason, the program error is kept, and no temporary file is left. */
	signal(SIGPIPE, SIG_IGN); /* the fake daemon outlives the client */
	birth_identity(1);
	handle()->dt_is_guest = B_TRUE;
	std::string tmp = getenv("TMPDIR");
	size_t temps = progerr_temp_files();
	struct Point {
		Fault f;
		const char *tmpdir;
		const char *reason;
	} points[] = {
		{ ELF_CREATE, nullptr, "dt_elf_create() failed: " },
		{ FSYNC, nullptr, "fsync() failed: Input/output error" },
		{ LSEEK, nullptr, "lseek() failed: Illegal seek" },
		{ NONE, "/nonexistent-typing-progerr", "mkstemp() failed: " },
	};
	for (const Point &pt : points) {
		if (pt.tmpdir != nullptr)
			setenv("TMPDIR", pt.tmpdir, 1);
		{
			FakeDtraced d(FakeDtraced::ACK);
			fault = pt.f;
			dtrace_prog_t *p = ill_typed();
			std::string msg;
			int r = 0;
			r = link(p, &msg); /* (TMPDIR may be unusable here) */
			fault = NONE;
			CHECKF(r == E_HYPERTRACE_SYS, "%s: link returned %d: %s",
			    pt.reason, r, msg.c_str());
			CHECKF(msg.find(ILL_TYPED_MSG) != std::string::npos &&
			    msg.find(pt.reason) != std::string::npos, "%s", msg.c_str());
		}
		setenv("TMPDIR", tmp.c_str(), 1);
	}
	CHECK(progerr_temp_files() == temps);
	/* A TMPDIR too long for a path: refused before connecting. */
	setenv("TMPDIR", std::string(MAXPATHLEN, 'd').c_str(), 1);
	dtrace_prog_t *p = ill_typed();
	std::string msg;
	int r = 0;
	r = link(p, &msg);
	setenv("TMPDIR", tmp.c_str(), 1);
	CHECK(r == E_HYPERTRACE_SYS &&
	    msg.find("temporary file name too long") != std::string::npos);
	/* Without TMPDIR the file is made in /tmp, and removed. */
	unsetenv("TMPDIR");
	{
		FakeDtraced d(FakeDtraced::ACK);
		dtrace_prog_t *q = ill_typed();
		r = link(q, &msg);
	}
	setenv("TMPDIR", tmp.c_str(), 1);
	CHECKF(r == E_HYPERTRACE_TYPING, "%d %s", r, msg.c_str());
	glob_t g;
	CHECK(glob("/tmp/ddtrace-set-prog-err.*", 0, nullptr, &g) != 0 ||
	    g.gl_pathc == 0);
	globfree(&g);
	handle()->dt_is_guest = B_FALSE;
	/* No program: nothing to mark. */
	CHECK(dt_set_progerr(handle(), nullptr, "%s", "nothing") == 0);
}

CASE("unformattable-error-is-printed")
{
	/* vsnprintf() fails (EILSEQ: a lone UTF-16 surrogate has no
	 * multibyte form); the fallback text is recorded and printed. */
	dtrace_prog_t *p = compile("BEGIN { trace(1); }");
	static const wchar_t bad[] = { (wchar_t)0xd800, 0 };
	int r = 0;
	std::string err = capture_stderr([&] {
		r = dt_set_progerr(handle(), p, "bad %ls", bad);
	});
	CHECK(r == 0 && p->dp_haserror);
	CHECKF(strcmp(p->dp_err, "failed to format program error") == 0, "%s",
	    p->dp_err);
	CHECKF(err == "failed to format program error\n", "'%s'", err.c_str());
}

CASE("long-error-keeps-forwarding-reason")
{
	/* A program error filling dp_err is cut short ("...") so that the
	 * reason the guest could not forward it still fits. */
	birth_identity(1);
	handle()->dt_is_guest = B_TRUE;
	redirect_path[0] = '\0'; /* nothing listens */
	dtrace_prog_t *p = compile("BEGIN { trace(1); }");
	std::string longmsg(5000, 'x');
	int r = 0;
	std::string err = capture_stderr([&] {
		r = dt_set_progerr(handle(), p, "%s", longmsg.c_str());
	});
	handle()->dt_is_guest = B_FALSE;
	CHECK(r == -1 && p->dp_haserror);
	size_t len = strlen(p->dp_err);
	CHECKF(len == sizeof(p->dp_err) - 1, "length %zu", len);
	const char *sep = strstr(p->dp_err, "...; failed to open dtraced: ");
	CHECKF(sep != nullptr, "%s", p->dp_err + len - 80);
	CHECK(strspn(p->dp_err, "x") == (size_t)(sep - p->dp_err));
	CHECK(err.find("program error message truncated") != std::string::npos);
	CHECK(err.find("failed to open dtraced") != std::string::npos);
}

CASE("short-error-appends-forwarding-reason")
{
	birth_identity(1);
	handle()->dt_is_guest = B_TRUE;
	redirect_path[0] = '\0';
	dtrace_prog_t *p = compile("BEGIN { trace(1); }");
	int r = 0;
	capture_stderr([&] { r = dt_set_progerr(handle(), p, "oops %d", 7); });
	handle()->dt_is_guest = B_FALSE;
	CHECK(r == -1);
	CHECKF(strncmp(p->dp_err, "oops 7; failed to open dtraced: ", 32) == 0,
	    "%s", p->dp_err);
}

int
main(int argc, char **argv)
{
	int err;
	handle() = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV, &err);
	if (handle() == nullptr) {
		fprintf(stderr, "dtrace_open: %s\n", dtrace_errmsg(nullptr, err));
		return (3);
	}
	return (run_all(argc, argv));
}
