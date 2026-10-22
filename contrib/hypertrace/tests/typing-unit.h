/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Constructed type-inference contexts for the typing unit harnesses
 * (typing-units.cc, typing-rules.cc).  See typing-units.cc.
 */
#ifndef _TYPING_UNIT_H_
#define _TYPING_UNIT_H_

#include "typing-oracle.h"

#include <sys/param.h>
#include <errno.h>

using namespace th;
using namespace dtrace;

/*
 * Allocation failure injection: the n-th following malloc()/calloc() call
 * (n >= 1) made by this process fails with ENOMEM.  The harness binary's
 * definitions interpose on libc's for libdtrace and libctf as well.
 */
extern "C" void *__malloc(size_t);
extern "C" void *__calloc(size_t, size_t);
inline int &
fail_countdown()
{
	static int n;
	return (n);
}
extern "C" void *
malloc(size_t size)
{
	if (fail_countdown() > 0 && --fail_countdown() == 0) {
		errno = ENOMEM;
		return (nullptr);
	}
	return (__malloc(size));
}
extern "C" void *
calloc(size_t n, size_t size)
{
	if (fail_countdown() > 0 && --fail_countdown() == 0) {
		errno = ENOMEM;
		return (nullptr);
	}
	return (__calloc(n, size));
}
inline void
fail_malloc_after(int n)
{
	fail_countdown() = n;
}

/*
 * The ordinal (>= 1) of the allocation inside fn() whose failure makes
 * fn() return true (tried in forked children); 0 if none up to `limit'.
 */
inline int
find_alloc_where(const std::function<bool()> &fn, int limit = 400)
{
	for (int i = 1; i <= limit; i++) {
		pid_t pid = fork();
		if (pid == 0) {
			int fd = open("/dev/null", O_WRONLY);
			dup2(fd, STDERR_FILENO);
			fail_malloc_after(i);
			bool r = fn();
			fail_malloc_after(0);
			exit(r ? 10 : 0);
		}
		int st;
		waitpid(pid, &st, 0);
		if (WIFEXITED(st) && WEXITSTATUS(st) == 10)
			return (i);
	}
	return (0);
}

/*
 * The ordinal (>= 1) of the allocation inside fn() whose failure makes fn()
 * print `text': each candidate is tried in a forked child with stderr
 * captured.  Returns 0 if no allocation up to `limit' does.
 */
inline int
find_failing_alloc(const std::function<void()> &fn, const char *text,
    int limit = 400)
{
	for (int i = 1; i <= limit; i++) {
		int pfd[2];
		if (pipe(pfd) != 0)
			return (0);
		pid_t pid = fork();
		if (pid == 0) {
			close(pfd[0]);
			dup2(pfd[1], STDERR_FILENO);
			fail_malloc_after(i);
			fn();
			exit(0);
		}
		close(pfd[1]);
		std::string err;
		char buf[1024];
		ssize_t r;
		while ((r = read(pfd[0], buf, sizeof(buf))) > 0)
			err.append(buf, (size_t)r);
		close(pfd[0]);
		int st;
		waitpid(pid, &st, 0);
		if (err.find(text) != std::string::npos)
			return (i);
	}
	return (0);
}


/* Run fn with stderr redirected to a file and return what it wrote. */
inline std::string
capture_stderr(const std::function<void()> &fn)
{
	char path[MAXPATHLEN];
	snprintf(path, sizeof(path), "%s/stderr.XXXXXX",
	    getenv("TMPDIR") ? getenv("TMPDIR") : ".");
	int fd = mkstemp(path);
	CHECK(fd >= 0);
	fflush(stderr);
	int saved = dup(STDERR_FILENO);
	dup2(fd, STDERR_FILENO);
	fn();
	fflush(stderr);
	dup2(saved, STDERR_FILENO);
	close(saved);
	std::string text;
	char buf[4096];
	ssize_t n;
	lseek(fd, 0, SEEK_SET);
	while ((n = read(fd, buf, sizeof(buf))) > 0)
		text.append(buf, (size_t)n);
	close(fd);
	unlink(path);
	return (text);
}

inline Typefile *
TF(const char *name)
{
	Typefile *tf = dt_typefile_mod(name);
	CHECKF(tf != nullptr, "no typefile %s", name);
	return (tf);
}

inline ctf_id_t
ID(Typefile *tf, const char *type)
{
	ctf_id_t id = tf->getCtfID(type);
	CHECKF(id != CTF_ERR, "no type %s in %s", type, tf->name().c_str());
	return (id);
}

/* The CTF id of a type exactly as written in a fixture container. */
inline ctf_id_t
FID(const char *mod, const char *type)
{
	return (ID(TF(mod), type));
}

/*
 * A linker and type inference context with one hand-built DIFO.  The
 * program is a compiled stub so that dt_set_progerr() has a program to
 * mark.
 */
struct Unit {
	dtrace_hdl_t *dtp;
	dtrace_prog_t *pgp;
	HyperTraceLinker L;
	TypeInference ti;
	dtrace_difo_t difo;
	dif_instr_t buf[256];
	char symtab[8192];
	uint64_t ints[64];
	dtrace_ecbdesc_t edp;

	/*
	 * With `noprog', the type checker is given no program (the linker
	 * still marks its own).
	 */
	Unit(const char *src = "BEGIN { trace(1); }", bool noprog = false)
	    : dtp(handle())
	    , pgp(compile(src))
	    , L(dtp, pgp)
	    , ti(L, dtp, noprog ? nullptr : pgp)
	{
		dt_typefile_openall(dtp);
		L.dfgNodes.push_front(std::make_unique<DFGNode>(dtp, pgp,
		    nullptr, nullptr, nullptr, UINT_MAX));
		L.r0node = L.dfgNodes.front().get();
		L.r0node->dType = DIF_TYPE_BOTTOM;
		memset(&difo, 0, sizeof(difo));
		memset(buf, 0, sizeof(buf));
		memset(symtab, 0, sizeof(symtab));
		memset(ints, 0, sizeof(ints));
		difo.dtdo_buf = buf;
		/* Variables are named "v" (dtdv_name 0) unless a case
		 * says otherwise. */
		difo.dtdo_strtab = (char *)"v";
		difo.dtdo_strlen = 2;
		difo.dtdo_symtab = symtab;
		difo.dtdo_symlen = 1;
		difo.dtdo_inttab = ints;
		memset(&edp, 0, sizeof(edp));
		strlcpy(edp.dted_probe.dtpd_provider, "dtrace",
		    sizeof(edp.dted_probe.dtpd_provider));
		strlcpy(edp.dted_probe.dtpd_name, "BEGIN",
		    sizeof(edp.dted_probe.dtpd_name));
	}

	DFGNode *
	r0()
	{
		return (L.r0node);
	}

	/* A node for instruction `ins' that still has to be inferred. */
	DFGNode *
	node(dif_instr_t ins)
	{
		uint_t idx = difo.dtdo_len++;
		CHECK(idx < 256);
		buf[idx] = ins;
		L.dfgNodes.push_back(std::make_unique<DFGNode>(dtp, pgp, &edp,
		    &difo, nullptr, idx));
		return (L.dfgNodes.back().get());
	}

	/* A definition whose type is already known. */
	DFGNode *
	def(dif_instr_t ins, int dtype, Typefile *tf = nullptr,
	    ctf_id_t id = CTF_ERR, const char *sym = nullptr)
	{
		DFGNode *n = node(ins);
		n->dType = dtype;
		n->tf = tf;
		n->ctfid = id;
		/* A node's symbol points into its DIFO's symbol table. */
		n->sym = sym ? symtab + this->sym(sym) : nullptr;
		n->isNull = false;
		return (n);
	}

	DFGNode *
	ctf(const char *mod, const char *type, const char *sym = nullptr,
	    dif_instr_t ins = DIF_INSTR_NOP)
	{
		Typefile *tf = TF(mod);
		return (def(ins, DIF_TYPE_CTF, tf, ID(tf, type), sym));
	}

	DFGNode *
	str(dif_instr_t ins = DIF_INSTR_NOP)
	{
		return (def(ins, DIF_TYPE_STRING));
	}

	uint_t
	sym(const char *s)
	{
		uint_t off = (uint_t)difo.dtdo_symlen;
		size_t l = strlen(s) + 1;
		CHECK(off + l <= sizeof(symtab));
		memcpy(symtab + off, s, l);
		difo.dtdo_symlen += l;
		return (off);
	}

	uint_t
	integer(uint64_t v)
	{
		ints[difo.dtdo_intlen] = v;
		return (difo.dtdo_intlen++);
	}

	dtrace_difv_t *
	var(uint_t id, uint8_t scope, uint8_t kind, int dkind = DIF_TYPE_BOTTOM,
	    Typefile *tf = nullptr, ctf_id_t ctfid = CTF_ERR,
	    const char *sym = nullptr)
	{
		L.varVector.push_back(std::make_unique<dtrace_difv_t>());
		dtrace_difv_t *v = L.varVector.back().get();
		memset(v, 0, sizeof(*v));
		v->dtdv_id = id;
		v->dtdv_scope = scope;
		v->dtdv_kind = kind;
		v->dtdv_type.dtdt_kind = dkind;
		v->dtdv_tf = tf;
		v->dtdv_ctfid = ctfid;
		v->dtdv_sym = sym ? strdup(sym) : nullptr;
		return (v);
	}

	static void
	uses(DFGNode *n, std::initializer_list<DFGNode *> r1,
	    std::initializer_list<DFGNode *> r2 = {})
	{
		for (auto d : r1) {
			n->r1Defs.insert(d);
			n->r1DataDefs.insert(d);
			d->r1Children.insert(n);
		}
		for (auto d : r2) {
			n->r2Defs.insert(d);
			n->r2DataDefs.insert(d);
			d->r2Children.insert(n);
		}
	}

	~Unit()
	{
		th::note_progerr(L.hadProgErr(), true);
	}

	/* inferNode(); a program error it records must make it fail. */
	int
	infer(DFGNode *n)
	{
		unsigned before = L.progErrors;
		int r = ti.inferNode(n);
		th::note_progerr(L.progErrors != before, r == -1);
		return (r);
	}

	std::string
	tname(DFGNode *n)
	{
		CHECK(n->tf != nullptr);
		return (n->tf->getTypename(n->ctfid).value_or("?"));
	}
};

/* libctf's own answer for a member's type name (independent oracle). */
inline std::string
ctf_member_type(ctf_file_t *fp, const char *type, const char *member,
    ulong_t *offset = nullptr)
{
	ctf_id_t id = ctf_lookup_by_name(fp, type);
	CHECKF(id != CTF_ERR, "libctf: no %s", type);
	ctf_membinfo_t mi;
	CHECKF(ctf_member_info(fp, ctf_type_resolve(fp, id), member, &mi) == 0,
	    "libctf: no %s.%s", type, member);
	if (offset)
		*offset = mi.ctm_offset;
	return (ctf_name(fp, mi.ctm_type));
}


#endif
