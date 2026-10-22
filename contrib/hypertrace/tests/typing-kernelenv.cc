/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Type checking against other kernel type information.
 *
 * typing-inference.py runs this harness three times with a different
 * "kernel" in the module inventory (TYPING_INVENTORY selects the cases):
 *  min      a kernel whose CTF has only char, char * and the lock
 *           structures: every lookup of an integer or system type fails;
 *  illumos  a kernel with the illumos types (mblk_t, file_t, size_t) that
 *           some D subroutines are declared with;
 *  none     no kernel module at all.
 * Each case states the diagnostic the type checker must give, or the type
 * it must infer, in that environment.
 */
#include "typing-unit.h"

namespace {

/* A call of `subr' whose tuple stack holds `args' (pushed values). */
DFGNode *
call(Unit &u, uint16_t subr, std::initializer_list<DFGNode *> args)
{
	DFGNode *n = u.node(DIF_INSTR_CALL(subr, 1));
	if (args.size() != 0) {
		Vec<BasicBlock *> path;
		n->stacks.emplace_back(path);
		for (auto a : args)
			n->stacks.back().nodesOnStack.push_back(a);
	}
	return (n);
}

/* A pushed argument of a type from a type file. */
DFGNode *
arg(Unit &u, const char *mod, const char *type)
{
	Typefile *tf = TF(mod);
	return (u.def(DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_CTF, 0, 1),
	    DIF_TYPE_CTF, tf, ID(tf, type)));
}

DFGNode *
sarg(Unit &u)
{
	return (u.def(DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 0, 1),
	    DIF_TYPE_STRING));
}

DFGNode *
builtin(Unit &u, uint16_t var)
{
	return (u.node(DIF_INSTR_LDV(DIF_OP_LDGS, var, 1)));
}

} // namespace

/* ---- min: the kernel lacks the types ------------------------------ */

#define MIN_BUILTIN(name, var, text) \
	PROGERR_CASE("min-builtin-" name, text) \
	{ \
		Unit u; \
		u.infer(builtin(u, var)); \
	}
MIN_BUILTIN("curthread", DIF_VAR_CURTHREAD, "failed to get type struct thread *")
MIN_BUILTIN("hcurthread", DIF_VAR_HCURTHREAD, "failed to get type struct thread *")
MIN_BUILTIN("pid", DIF_VAR_PID, "failed to get type pid_t")
MIN_BUILTIN("hppid", DIF_VAR_HPPID, "failed to get type pid_t")
MIN_BUILTIN("uid", DIF_VAR_UID, "failed to get type uid_t")
MIN_BUILTIN("huid", DIF_VAR_HUID, "failed to get type uid_t")
MIN_BUILTIN("gid", DIF_VAR_GID, "failed to get type gid_t")
MIN_BUILTIN("hgid", DIF_VAR_HGID, "failed to get type gid_t")
MIN_BUILTIN("hostid", DIF_VAR_HOSTID, "failed to get type hostid_t")

CASE("min-builtins-from-d")
{
	/* Builtins typed from the D definitions do not need the kernel. */
	static const struct {
		uint16_t var;
		const char *type;
	} rows[] = { { DIF_VAR_TIMESTAMP, "uint64_t" },
		{ DIF_VAR_EPID, "uint_t" }, { DIF_VAR_ARG0, "int64_t" },
		{ DIF_VAR_WALLTIMESTAMP, "int64_t" },
		{ DIF_VAR_STACKDEPTH, "uint32_t" },
		{ DIF_VAR_CALLER, "uintptr_t" }, { DIF_VAR_TID, "id_t" },
		{ DIF_VAR_CPU, "int" } };
	for (auto &r : rows) {
		Unit u;
		DFGNode *n = builtin(u, r.var);
		CHECK(u.infer(n) == DIF_TYPE_CTF && u.tname(n) == r.type);
	}
}

#define MIN_ERROR_ARG(i, text) \
	PROGERR_CASE("min-error-probe-arg" #i, text) \
	{ \
		Unit u; \
		strlcpy(u.edp.dted_probe.dtpd_name, "ERROR", \
		    sizeof(u.edp.dted_probe.dtpd_name)); \
		DFGNode *idx = u.node(DIF_INSTR_SETX(u.integer(i), 2)); \
		u.infer(idx); \
		DFGNode *n = u.node(DIF_INSTR_LDA(DIF_OP_LDGA, DIF_VAR_ARGS, 2, 3)); \
		Unit::uses(n, {}, { idx }); \
		u.infer(n); \
	}
MIN_ERROR_ARG(1, "failed to get type uint32_t")
MIN_ERROR_ARG(3, "failed to get type int")

PROGERR_CASE("min-args-only-returned", "failed to get type uint64_t")
{
	/* The kernel's uint64_t is missing. */
	Unit u;
	strlcpy(u.edp.dted_probe.dtpd_provider, "fbt",
	    sizeof(u.edp.dted_probe.dtpd_provider));
	DFGNode *idx = u.node(DIF_INSTR_SETX(u.integer(1), 2));
	u.infer(idx);
	DFGNode *n = u.node(DIF_INSTR_LDA(DIF_OP_LDGA, DIF_VAR_ARGS, 2, 3));
	Unit::uses(n, {}, { idx });
	DFGNode *ret = u.node(DIF_INSTR_RET(3));
	Unit::uses(ret, { n });
	u.infer(n);
}

/* Subroutine return types looked up in the kernel. */
#define MIN_SUBR(name, subr, text, ...) \
	PROGERR_CASE("min-subr-" name, text) \
	{ \
		Unit u; \
		u.infer(call(u, subr, { __VA_ARGS__ })); \
	}
MIN_SUBR("rand", DIF_SUBR_RAND, "rand(): failed to get type int")
MIN_SUBR("random", DIF_SUBR_RANDOM, "random(): failed to get type uint64_t")
MIN_SUBR("speculation", DIF_SUBR_SPECULATION,
    "speculation(): failed to get type int")
MIN_SUBR("mutex-owned", DIF_SUBR_MUTEX_OWNED,
    "mutex_owned(): failed to get type int", arg(u, "kernel", "struct mtx *"))
MIN_SUBR("mutex-owner", DIF_SUBR_MUTEX_OWNER,
    "mutex_owner(): failed to get thread type",
    arg(u, "kernel", "struct mtx *"))
MIN_SUBR("rw-read-held", DIF_SUBR_RW_READ_HELD,
    "rw_read_held(): failed to get type int",
    arg(u, "kernel", "struct rwlock *"))
MIN_SUBR("rw-write-held", DIF_SUBR_RW_WRITE_HELD,
    "rw_write_held(): failed to get type int",
    arg(u, "kernel", "struct rwlock *"))
MIN_SUBR("rw-iswriter", DIF_SUBR_RW_ISWRITER,
    "rw_iswriter(): failed to get type int",
    arg(u, "kernel", "struct rwlock *"))
MIN_SUBR("sx-shared-held", DIF_SUBR_SX_SHARED_HELD,
    "sx_shared_held(): failed to get type int", arg(u, "kernel", "struct sx *"))
MIN_SUBR("copyin", DIF_SUBR_COPYIN, "copyin(): failed to get type void *",
    arg(u, "D", "uintptr_t"), arg(u, "D", "size_t"))
MIN_SUBR("strlen", DIF_SUBR_STRLEN, "strlen(): failed to get type size_t",
    sarg(u))
MIN_SUBR("alloca", DIF_SUBR_ALLOCA, "alloca(): failed to get type void *",
    arg(u, "D", "size_t"))
MIN_SUBR("index", DIF_SUBR_INDEX, "index(): failed to get type int", sarg(u),
    sarg(u))
MIN_SUBR("htons", DIF_SUBR_HTONS, "htons(): failed to get type uint16_t",
    arg(u, "D", "uint16_t"))
MIN_SUBR("htonl", DIF_SUBR_HTONL, "htonl(): failed to get type uint32_t",
    arg(u, "D", "uint32_t"))
MIN_SUBR("htonll", DIF_SUBR_HTONLL, "htonll(): failed to get type uint64_t",
    arg(u, "D", "uint64_t"))
MIN_SUBR("memref", DIF_SUBR_MEMREF, "memref(): failed to get type uintptr_t *",
    arg(u, "D", "void *"), arg(u, "D", "size_t"))
MIN_SUBR("strtoll", DIF_SUBR_STRTOLL, "strtoll(): failed to get type int64_t",
    sarg(u))
MIN_SUBR("ptinfo", DIF_SUBR_PTINFO, "ptinfo(): failed to get type void *",
    arg(u, "D", "uintptr_t"))
MIN_SUBR("progenyof-argument", DIF_SUBR_PROGENYOF,
    "progenyof(): failed to get type pid_t", arg(u, "kernel", "char *"))

PROGERR_CASE("min-store-width-type", "failed getting ctfid from kernel for "
    "uint64_t")
{
	/* The width check of a symbolic store needs the kernel's uintN_t. */
	Unit u;
	Typefile *pf = TF("typingfix");
	u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, DIF_TYPE_CTF, pf,
	    ID(pf, "struct tf_pair"));
	DFGNode *ld = u.def(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 1), DIF_TYPE_CTF,
	    pf, ID(pf, "struct tf_pair"));
	DFGNode *v = u.ctf("D", "uint64_t", "b",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	Unit::uses(v, { ld });
	DFGNode *dst = u.ctf("D", "uintptr_t", nullptr, DIF_INSTR_MOV(4, 3));
	DFGNode *n = u.node(DIF_INSTR_STORE(DIF_OP_STX, 1, 3));
	Unit::uses(n, { v }, { dst });
	u.infer(n);
}

/* ---- illumos: subroutines declared with illumos types -------------- */

CASE("illumos-subr-types")
{
	{
		Unit u;
		DFGNode *n = call(u, DIF_SUBR_MSGSIZE,
		    { arg(u, "kernel", "mblk_t *") });
		CHECK(u.infer(n) == DIF_TYPE_CTF && u.tname(n) == "size_t");
	}
	{
		Unit u;
		DFGNode *n = call(u, DIF_SUBR_MSGDSIZE,
		    { arg(u, "kernel", "mblk_t *") });
		CHECK(u.infer(n) == DIF_TYPE_CTF && u.tname(n) == "size_t");
	}
	{
		Unit u;
		DFGNode *n = call(u, DIF_SUBR_GETF, { arg(u, "D", "int") });
		CHECK(u.infer(n) == DIF_TYPE_CTF && u.tname(n) == "file_t *");
	}
}

/* ---- none: no kernel type information at all ----------------------- */

PROGERR_CASE("none-builtin-pid",
    "variable 116: kernel type information is unavailable")
{
	Unit u;
	u.infer(builtin(u, DIF_VAR_PID));
}

PROGERR_CASE("none-builtin-curthread",
    "variable 100: kernel type information is unavailable")
{
	Unit u;
	u.infer(builtin(u, DIF_VAR_CURTHREAD));
}

PROGERR_CASE("none-error-probe-arg",
    "variable 0: kernel type information is unavailable")
{
	Unit u;
	strlcpy(u.edp.dted_probe.dtpd_name, "ERROR",
	    sizeof(u.edp.dted_probe.dtpd_name));
	DFGNode *idx = u.node(DIF_INSTR_SETX(u.integer(2), 2));
	u.infer(idx);
	DFGNode *n = u.node(DIF_INSTR_LDA(DIF_OP_LDGA, DIF_VAR_ARGS, 2, 3));
	Unit::uses(n, {}, { idx });
	u.infer(n);
}

PROGERR_CASE("none-args-only-returned",
    "kernel type information is unavailable")
{
	/* args[1] of a non-dtrace probe that is only returned is typed
	 * uint64_t from the kernel's CTF: there is none. */
	Unit u;
	strlcpy(u.edp.dted_probe.dtpd_provider, "sdt",
	    sizeof(u.edp.dted_probe.dtpd_provider));
	DFGNode *idx = u.node(DIF_INSTR_SETX(u.integer(1), 2));
	u.infer(idx);
	DFGNode *n = u.node(DIF_INSTR_LDA(DIF_OP_LDGA, DIF_VAR_ARGS, 2, 3));
	Unit::uses(n, {}, { idx });
	DFGNode *ret = u.node(DIF_INSTR_RET(3));
	Unit::uses(ret, { n });
	CHECK(u.infer(n) == -1);
}

PROGERR_CASE("none-store-width", "kernel type information is unavailable")
{
	Unit u;
	Typefile *pf = TF("typingfix");
	u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, DIF_TYPE_CTF, pf,
	    ID(pf, "struct tf_pair"));
	DFGNode *ld = u.def(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 1), DIF_TYPE_CTF,
	    pf, ID(pf, "struct tf_pair"));
	DFGNode *v = u.ctf("D", "uint64_t", "b",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	Unit::uses(v, { ld });
	DFGNode *dst = u.ctf("D", "uintptr_t", nullptr, DIF_INSTR_MOV(4, 3));
	DFGNode *n = u.node(DIF_INSTR_STORE(DIF_OP_STX, 1, 3));
	Unit::uses(n, { v }, { dst });
	u.infer(n);
}

PROGERR_CASE("none-link-builtin", "kernel type information is unavailable")
{
	/* Regression: linking a program that reads pid without kernel CTF
	 * dereferenced the missing kernel type file. */
	dtrace_prog_t *p = compile("BEGIN { trace(pid); }");
	link(p);
}

/* ---- kldfail: a listed module whose kldstat() fails ----------------- */

CASE("kldfail-link")
{
	/* The type files cannot be opened without the module list: the link
	 * fails with kldstat()'s error, and the process carries on (it used
	 * to end in errx()). */
	for (int i = 0; i < 2; i++) {
		dtrace_prog_t *p = compile("BEGIN { trace(1); }");
		std::string msg;
		int r = link(p, &msg);
		CHECKF(r == E_HYPERTRACE_SYS, "link returned %d: %s", r,
		    msg.c_str());
		CHECKF(msg == "kldstat() failed with: Input/output error", "%s",
		    msg.c_str());
		CHECK(!p->dp_haserror);
	}
}

/* ---- missing: a listed module whose file cannot be read ------------- */

CASE("missing-module-is-skipped")
{
	dtrace_prog_t *p = compile("BEGIN { trace(1); }");
	int pfd[2];
	CHECK(pipe(pfd) == 0);
	int saved = dup(STDERR_FILENO);
	dup2(pfd[1], STDERR_FILENO);
	int r = link(p);
	fflush(stderr);
	dup2(saved, STDERR_FILENO);
	close(pfd[1]);
	char buf[4096] = { 0 };
	CHECK(read(pfd[0], buf, sizeof(buf) - 1) > 0);
	CHECK(r == 0);
	CHECK(strstr(buf, "WARNING - skipping module bogus") != nullptr);
	/* The type files of the other modules were opened (the link
	 * releases them; reopen to look). */
	CHECK(dt_typefile_openall(handle()) == 0);
	CHECK(dt_typefile_mod("bogus") == nullptr);
	CHECK(dt_typefile_kernel() != nullptr);
	/* A program using kernel types links. */
	link_ok(compile("BEGIN { trace(curthread->td_tid); }"));
}

int
main(int argc, char **argv)
{
	int err;
	const char *inv = getenv("TYPING_INVENTORY");
	handle() = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV, &err);
	if (handle() == nullptr || inv == nullptr) {
		fprintf(stderr, "dtrace_open: %s\n", dtrace_errmsg(nullptr, err));
		return (3);
	}
	/* The D system libraries need the real kernel's types. */
	if (strcmp(inv, "none") != 0 &&
	    dtrace_setopt(handle(), "nolibs", nullptr) != 0)
		return (3);
	std::vector<char *> names = { argv[0] };
	std::string prefix = std::string(inv) + "-";
	for (auto &c : registry())
		if (c.name.rfind(prefix, 0) == 0 &&
		    (argc == 1 || std::find(argv + 1, argv + argc, c.name) !=
		    argv + argc))
			names.push_back((char *)c.name.c_str());
	if (names.size() == 1)
		return (3);
	return (run_all((int)names.size(), names.data()));
}
