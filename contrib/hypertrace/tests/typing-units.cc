/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * HyperTrace typing rules on constructed data-flow graphs.
 *
 * Each case builds DFG nodes by hand (instruction, definitions and, for
 * definitions, an already-inferred type) and asks TypeInference for the
 * type of one node, or calls one helper (subtype relation, CTF comparison,
 * type file lookup) directly.  Expected results come from the inference
 * rules documented above each case of TypeInference::inferNode(), from the
 * CTF fixture layouts in typing-inference.py and from libctf queries made
 * here, and expected diagnostics from the documented error conditions.
 * Cases that must end in a program error (dt_set_progerr()) are
 * PROGERR_CASEs: the error must be recorded with the diagnostic text and
 * returned, and the child must carry on to complete.
 */
#include "typing-unit.h"

static inline dif_instr_t
NOP_INSTR()
{
	return (DIF_INSTR_NOP);
}


/* ------------------------------------------------------------------ */
/* Regression cases for defects fixed in the typing files.             */
/* ------------------------------------------------------------------ */

/*
 * TypeInference::ctfTypeCompare() of two same-named structures: equal
 * layouts in different containers are equal, different layouts are not.
 * The fixtures define struct tf_pair { int a; long b; } in typingfix and
 * typingfix3 (with the member types numbered differently) and a
 * differently laid out struct thread in typingfix.
 */
CASE("regress-ctfcompare-identical-structs-across-containers")
{
	Unit u;
	CHECK(u.ti.ctfTypeCompare(TF("typingfix"), FID("typingfix",
	    "struct tf_pair"), TF("typingfix3"), FID("typingfix3",
	    "struct tf_pair")) == 0);
	CHECK(u.ti.ctfTypeCompare(TF("typingfix"), FID("typingfix",
	    "struct tf_pair"), TF("typingfix2"), FID("typingfix2",
	    "struct tf_pair")) == 0);
}

CASE("regress-ctfcompare-same-name-different-layout")
{
	Unit u;
	Typefile *k = dt_typefile_kernel();
	CHECK(k != nullptr);
	std::string err = capture_stderr([&] {
		CHECK(u.ti.ctfTypeCompare(k, ID(k, "struct thread"),
		    TF("typingfix"), FID("typingfix", "struct thread")) != 0);
		/* struct tf_big { int; long; char; } vs { int; long; }. */
		CHECK(u.ti.ctfTypeCompare(TF("typingfix"), FID("typingfix",
		    "struct tf_big"), TF("typingfix3"), FID("typingfix3",
		    "struct tf_big")) != 0);
	});
	CHECK(err.find("don't match") != std::string::npos ||
	    err.find("failed") != std::string::npos);
}

/*
 * Typefile::getMembInfo() on a forward declaration must find the member in
 * the definition (typingfix declares struct tf_fwd; typingfix2 defines
 * it as { int fa; long fb; }, so fb is at bit offset 64).
 */
CASE("regress-membinfo-follows-forward-declaration")
{
	Unit u;
	Typefile *tf = TF("typingfix");
	ctf_id_t fwd = ID(tf, "struct tf_fwd");
	CHECK(tf->getKind(fwd) == CTF_K_FORWARD);
	ctf_membinfo_t mi;
	memset(&mi, 0, sizeof(mi));
	ctf_file_t *fp = tf->getMembInfo(fwd, "fb", &mi);
	CHECK(fp != nullptr);
	CHECK(mi.ctm_offset == 64);
	CHECK(ctf_name(fp, mi.ctm_type) == "long");
	CHECK(fp == TF("typingfix2")->getCtfPointer());
}

/*
 * The diagnostic for conflicting register definitions names both types.
 */
CASE("regress-regdefs-mismatch-names-both-types")
{
	Unit u;
	Typefile *k = dt_typefile_kernel();
	DFGNode *a = u.def(DIF_INSTR_NOP, DIF_TYPE_CTF, k,
	    ID(k, "struct thread *"));
	DFGNode *b = u.def(DIF_INSTR_NOP, DIF_TYPE_CTF, k,
	    ID(k, "struct proc *"));
	DFGNode *n = u.node(DIF_INSTR_MOV(1, 2));
	Unit::uses(n, { a, b });
	bool empty = true;
	DFGNode *r = nullptr;
	std::string err = capture_stderr([&] {
		r = u.ti.checkRegDefs(n, n->r1Defs, empty);
	});
	CHECK(r == nullptr && empty); /* set: definitions that fail */
	size_t at = err.find("do not match");
	CHECKF(at != std::string::npos, "%s", err.c_str());
	std::string line = err.substr(err.rfind('\n', at) + 1,
	    at - err.rfind('\n', at));
	CHECKF(line.find("struct thread *") != std::string::npos &&
	    line.find("struct proc *") != std::string::npos, "%s", line.c_str());
}

/*
 * checkVarDefs(): when two definitions agree on a symbol but the variable
 * records another, the diagnostic shows the variable's symbol; a kind
 * mismatch reports the inferred CTF type by name.
 */
CASE("regress-vardefs-symbol-diagnostic")
{
	Unit u;
	Typefile *k = dt_typefile_kernel();
	ctf_id_t td = ID(k, "struct thread *");
	u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, DIF_TYPE_CTF, k, td,
	    "td_proc");
	DFGNode *a = u.def(DIF_INSTR_STV(DIF_OP_STLS, 1280, 1), DIF_TYPE_CTF, k,
	    td, "td_ucred");
	DFGNode *b = u.def(DIF_INSTR_STV(DIF_OP_STLS, 1280, 2), DIF_TYPE_CTF, k,
	    td, "td_ucred");
	DFGNode *n = u.node(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 3));
	n->varDefs.insert(a);
	n->varDefs.insert(b);
	bool empty;
	DFGNode *r = nullptr;
	std::string err = capture_stderr([&] {
		r = u.ti.checkVarDefs(n, &u.difo, n->varDefs, empty);
	});
	CHECK(r == nullptr);
	CHECKF(err.find("struct thread * | td_ucred, struct thread * | "
	    "td_proc") != std::string::npos, "%s", err.c_str());
}

CASE("regress-vardefs-kind-diagnostic-names-type")
{
	Unit u;
	Typefile *k = dt_typefile_kernel();
	u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, DIF_TYPE_STRING);
	DFGNode *a = u.def(DIF_INSTR_STV(DIF_OP_STLS, 1280, 1), DIF_TYPE_CTF, k,
	    ID(k, "struct thread *"));
	DFGNode *n = u.node(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 3));
	n->varDefs.insert(a);
	bool empty;
	DFGNode *r = nullptr;
	std::string err = capture_stderr([&] {
		r = u.ti.checkVarDefs(n, &u.difo, n->varDefs, empty);
	});
	CHECK(r == nullptr && empty);
	CHECKF(err.find("struct thread *") != std::string::npos &&
	    err.find("D string") != std::string::npos, "%s", err.c_str());
}

/*
 * A typefile list must not outlive the handle it was opened for: linking
 * with a second handle after closing the first must use the new handle.
 */
CASE("regress-typefiles-second-handle")
{
	int err;
	const char *src = "BEGIN { trace(curthread->td_tid); }";
	dtrace_hdl_t *h1 = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV, &err);
	CHECK(h1 != nullptr);
	dtrace_prog_t *p1 = dtrace_program_strcompile(h1, src,
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL);
	CHECK(p1 != nullptr);
	char msg[HYPERTRACE_ERRMSGLEN];
	CHECK(hypertrace_link(h1, p1, msg) == 0);
	size_t first = typefiles.size();
	dtrace_close(h1);
	/* Overwrite the freed memory so that a stale handle is noticed. */
	for (int i = 0; i < 64; i++)
		free(malloc(1 << 16));
	dtrace_hdl_t *h2 = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV, &err);
	CHECK(h2 != nullptr);
	dtrace_prog_t *p2 = dtrace_program_strcompile(h2, src,
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL);
	CHECK(p2 != nullptr);
	CHECK(hypertrace_link(h2, p2, msg) == 0);
	for (auto &tf : typefiles)
		CHECK(tf->dtp == h2);
	CHECK(typefiles.size() == first);
	dtrace_close(h2);
}


/* ------------------------------------------------------------------ */
/* getSubtypeRelation(): which of two types is the other's subtype.     */
/* ------------------------------------------------------------------ */

namespace {
int
subtype(Unit &u, Typefile *a, ctf_id_t ia, Typefile *b, ctf_id_t ib,
    int *which)
{
	int w = -99;
	int r;
	std::string err = capture_stderr([&] {
		r = u.ti.getSubtypeRelation(a, ia, b, ib, w);
	});
	*which = w;
	return (r);
}

/* Struct/union member type ids are taken from the containers directly. */
ctf_id_t
member_id(Typefile *tf, const char *type, const char *member)
{
	ctf_membinfo_t mi;
	CHECK(ctf_member_info(tf->getCtfPointer(), ID(tf, type), member,
	    &mi) == 0);
	return (mi.ctm_type);
}
} // namespace

CASE("subtype-void-pointers")
{
	Unit u;
	Typefile *k = dt_typefile_kernel();
	int w;
	CHECK(subtype(u, k, ID(k, "void *"), k, ID(k, "void *"), &w) == 0 &&
	    w == SUBTYPE_EQUAL);
	CHECK(subtype(u, k, ID(k, "void *"), k, ID(k, "struct proc *"), &w) ==
	    0 && w == SUBTYPE_FST);
	CHECK(subtype(u, k, ID(k, "struct proc *"), k, ID(k, "const void *"),
	    &w) == 0 && w == SUBTYPE_SND);
}

CASE("subtype-integers-by-size")
{
	Unit u;
	Typefile *d = dt_typefile_D();
	int w;
	CHECK(subtype(u, d, ID(d, "int"), d, ID(d, "unsigned int"), &w) == 0 &&
	    w == SUBTYPE_EQUAL);
	CHECK(subtype(u, d, ID(d, "int"), d, ID(d, "long"), &w) == 0 &&
	    w == SUBTYPE_SND);
	CHECK(subtype(u, d, ID(d, "int64_t"), d, ID(d, "char"), &w) == 0 &&
	    w == SUBTYPE_FST);
	/* Through typedefs and across containers. */
	Typefile *k = dt_typefile_kernel();
	CHECK(subtype(u, k, ID(k, "pid_t"), d, ID(d, "int32_t"), &w) == 0 &&
	    w == SUBTYPE_EQUAL);
}

CASE("subtype-pointer-depth-mismatch")
{
	Unit u;
	Typefile *k = dt_typefile_kernel();
	int w;
	CHECK(subtype(u, k, ID(k, "struct proc *"), k, ID(k, "struct proc"),
	    &w) == -1 && w == SUBTYPE_NONE);
}

CASE("subtype-unnamed-type")
{
	Unit u;
	Typefile *k = dt_typefile_kernel();
	int w;
	CHECK(subtype(u, k, 0x7ffffff, k, ID(k, "int"), &w) == -1);
	CHECK(subtype(u, k, ID(k, "int"), k, 0x7ffffff, &w) == -1);
}

CASE("subtype-different-names")
{
	Unit u;
	Typefile *k = dt_typefile_kernel();
	int w;
	CHECK(subtype(u, k, ID(k, "struct proc *"), k, ID(k, "struct thread *"),
	    &w) == -1);
}

CASE("subtype-struct-prefix")
{
	/* typingfix: struct tf_big { int a; long b; char c; };
	 * typingfix3: struct tf_big { int a; long b; }: the shorter one is a
	 * prefix (slice) of the longer one. */
	Unit u;
	Typefile *f1 = TF("typingfix"), *f3 = TF("typingfix3");
	int w;
	CHECK(subtype(u, f1, ID(f1, "struct tf_big"), f3, ID(f3,
	    "struct tf_big"), &w) == 0 && w == SUBTYPE_SND);
	CHECK(subtype(u, f3, ID(f3, "struct tf_big"), f1, ID(f1,
	    "struct tf_big"), &w) == 0 && w == SUBTYPE_FST);
	CHECK(subtype(u, f1, ID(f1, "struct tf_pair"), f3, ID(f3,
	    "struct tf_pair"), &w) == 0 && w == SUBTYPE_EQUAL);
	/* Pointers to them relate the same way. */
	Typefile *k = dt_typefile_kernel();
	CHECK(subtype(u, k, ID(k, "struct proc *"), k, ID(k, "struct proc *"),
	    &w) == 0 && w == SUBTYPE_EQUAL);
}

CASE("subtype-struct-member-mismatch")
{
	/* Same name, but the first members differ (kernel struct thread vs
	 * typingfix's { int td_tid; long td_x; }). */
	Unit u;
	Typefile *k = dt_typefile_kernel(), *f1 = TF("typingfix");
	int w;
	CHECK(subtype(u, k, ID(k, "struct thread"), f1, ID(f1,
	    "struct thread"), &w) == -1);
}

CASE("subtype-union-enum-forward")
{
	/* Unions, enums and forward declarations relate only if libctf calls
	 * them compatible; the oracle is ctf_type_compat() itself. */
	Unit u;
	Typefile *f1 = TF("typingfix"), *f2 = TF("typingfix2"),
	    *f3 = TF("typingfix3");
	struct {
		Typefile *a;
		const char *ta;
		Typefile *b;
		const char *tb;
	} rows[] = {
		{ f1, "union tf_u", f2, "union tf_u" },
		{ f1, "union tf_u", f3, "union tf_u" },
		{ f1, "enum tf_e", f2, "enum tf_e" },
		{ f1, "enum tf_e", f3, "enum tf_e" },
		{ f1, "struct tf_fwd *", f1, "struct tf_fwd *" },
	};
	for (auto &r : rows) {
		int w;
		ctf_id_t ia = ID(r.a, r.ta), ib = ID(r.b, r.tb);
		size_t n;
		ctf_id_t sa = ia, sb = ib;
		r.a->stripReference(sa, n);
		r.b->stripReference(sb, n);
		bool compat = (r.a == r.b && sa == sb) ||
		    ctf_type_compat(r.a->getCtfPointer(), sa,
		    r.b->getCtfPointer(), sb);
		int got = subtype(u, r.a, ia, r.b, ib, &w);
		CHECKF((got == 0) == compat, "%s/%s: %d vs compat %d", r.ta,
		    r.b->name().c_str(), got, compat);
		if (compat)
			CHECK(w == SUBTYPE_EQUAL);
	}
}

CASE("subtype-unsupported-kind")
{
	/* Floats (and functions) have no subtype rule. */
	Unit u;
	Typefile *f1 = TF("typingfix");
	int w;
	CHECK(subtype(u, f1, ID(f1, "float"), f1, ID(f1, "float"), &w) == -1);
	Typefile *k = dt_typefile_kernel();
	/* A function type: a kernel function pointer's target. */
	ctf_id_t fp = member_id(k, "struct sysent", "sy_call");
	ctf_id_t fn = k->getReference(fp);
	CHECK(k->getKind(fn) == CTF_K_FUNCTION || k->getKind(fn) ==
	    CTF_K_TYPEDEF);
	CHECK(subtype(u, k, fp, k, fp, &w) == -1);
}

/* ------------------------------------------------------------------ */
/* ctfTypeCompare(): structural equality across containers.            */
/* ------------------------------------------------------------------ */

CASE("ctfcompare-kinds")
{
	Unit u;
	Typefile *f1 = TF("typingfix"), *f2 = TF("typingfix2"),
	    *f3 = TF("typingfix3");
	Typefile *d = dt_typefile_D(), *k = dt_typefile_kernel();
	std::string err = capture_stderr([&] {
		/* Same type: equal without looking. */
		CHECK(u.ti.ctfTypeCompare(f1, ID(f1, "int"), f1, ID(f1, "int"))
		    == 0);
		/* Compatible integers across containers. */
		CHECK(u.ti.ctfTypeCompare(f1, ID(f1, "int"), d, ID(d, "int"))
		    == 0);
		/* Incompatible integers (sizes differ). */
		CHECK(u.ti.ctfTypeCompare(f1, ID(f1, "int"), d, ID(d, "long"))
		    != 0);
		/* Floats need compatible encodings too. */
		CHECK(u.ti.ctfTypeCompare(f1, ID(f1, "float"), f1,
		    ID(f1, "double")) != 0);
		/* Different kinds. */
		CHECK(u.ti.ctfTypeCompare(f1, ID(f1, "int"), f1,
		    ID(f1, "struct tf_pair")) != 0);
		/* Different indirection. */
		CHECK(u.ti.ctfTypeCompare(k, ID(k, "struct proc *"), k,
		    ID(k, "struct proc")) != 0);
		/* Different names of the same kind. */
		CHECK(u.ti.ctfTypeCompare(f1, ID(f1, "struct tf_pair"), f1,
		    ID(f1, "struct tf_big")) != 0);
		/* Unions and enums by libctf compatibility. */
		CHECK(u.ti.ctfTypeCompare(f1, ID(f1, "union tf_u"), f2,
		    ID(f2, "union tf_u")) == 0);
		CHECK((u.ti.ctfTypeCompare(f1, ID(f1, "union tf_u"), f3,
		    ID(f3, "union tf_u")) == 0) ==
		    (bool)ctf_type_compat(f1->getCtfPointer(), ID(f1,
		    "union tf_u"), f3->getCtfPointer(), ID(f3, "union tf_u")));
		/* Structures with union, enum and array members. */
		CHECK(u.ti.ctfTypeCompare(f1, ID(f1, "struct tf_withu"), f2,
		    ID(f2, "struct tf_withu")) == 0);
		/* Pointers to structures compare the structures. */
		CHECK(u.ti.ctfTypeCompare(k, ID(k, "struct proc *"), k,
		    ID(k, "struct proc *")) == 0);
		/* Typedefs are stripped. */
		CHECK(u.ti.ctfTypeCompare(f1, ID(f1, "tf_pair_t"), f2,
		    ID(f2, "struct tf_pair")) == 0);
		/* Members with float types compare by encoding. */
		CHECK(u.ti.ctfTypeCompare(f1, ID(f1, "struct tf_flt"), f1,
		    ID(f1, "struct tf_flt")) == 0);
		/* Functions (and other kinds) compare by name. */
		ctf_id_t fp = member_id(k, "struct sysent", "sy_call");
		CHECK(u.ti.ctfTypeCompare(k, fp, k, fp) == 0);
	});
}

CASE("ctfcompare-unresolvable")
{
	Unit u;
	Typefile *f1 = TF("typingfix");
	std::string err = capture_stderr([&] {
		CHECK(u.ti.ctfTypeCompare(f1, 0x7ffffff, f1, ID(f1, "int")) != 0);
		CHECK(u.ti.ctfTypeCompare(f1, ID(f1, "int"), f1, 0x7ffffff) != 0);
	});
	CHECK(err.find("cannot resolve type") != std::string::npos);
}

CASE("ctfcompare-struct-member-differs-after-same-name")
{
	/* struct tf_rep { int a; int b; } against { int a; long b; }: the
	 * second member's type name (int) was compared already, but with a
	 * different counterpart (long), so it is compared again and fails. */
	Unit u;
	Typefile *f1 = TF("typingfix"), *f2 = TF("typingfix2");
	int r = 0;
	std::string err = capture_stderr([&] {
		r = u.ti.ctfTypeCompare(f1, ID(f1, "struct tf_rep"), f2,
		    ID(f2, "struct tf_rep"));
	});
	CHECK(r != 0);
	CHECK(err.find("comparison between int and long failed") !=
	    std::string::npos);
	CHECK(ctf_type_compat(f1->getCtfPointer(), ID(f1, "struct tf_rep"),
	    f2->getCtfPointer(), ID(f2, "struct tf_rep")) == 0);
}

CASE("typecompare-incomparable-classes")
{
	/* Pairs of classes with no order (dt_get_class()): a union, a
	 * forward declaration or an enum against a structure. */
	Unit u;
	auto cmp = [&](const char *m1, const char *t1, const char *m2,
	    const char *t2) {
		DFGNode *a = u.ctf(m1, t1), *b = u.ctf(m2, t2);
		return (u.ti.typeCompare(a, b));
	};
	CHECK(cmp("typingfix", "union tf_u", "typingfix", "struct tf_pair") ==
	    -1);
	CHECK(cmp("typingfix", "struct tf_undef", "typingfix",
	    "struct tf_pair") == -1);
	CHECK(cmp("typingfix", "enum tf_e", "typingfix", "struct tf_pair") ==
	    -1);
	CHECK(!u.L.hadProgErr());
}

CASE("diagname-and-string-check-kinds")
{
	Unit u;
	CHECK(dt_type_diagname(DIF_TYPE_BOTTOM, nullptr, CTF_ERR, true) ==
	    "bottom");
	CHECK(dt_type_diagname(DIF_TYPE_NONE, nullptr, CTF_ERR, false) ==
	    "none");
	CHECK(dt_type_diagname(99, nullptr, CTF_ERR, false) == "unknown");
	/* A D string and a value of unknown type are not both strings. */
	CHECK(!dt_typecheck_string(handle(), DIF_TYPE_STRING, DIF_TYPE_BOTTOM,
	    0, 0, nullptr, nullptr));
}

CASE("ctfcompare-self-referential-kernel-structs")
{
	/* struct thread refers to itself (directly and through struct proc);
	 * comparing it with itself across two type files of the same module
	 * must terminate and succeed. */
	Unit u;
	Typefile *k = dt_typefile_kernel();
	Typefile copy(k->dtp, k->modhdl, String("kernel"));
	CHECK(u.ti.ctfTypeCompare(k, ID(k, "struct thread"), &copy,
	    copy.getCtfID("struct thread")) == 0);
}


/* ------------------------------------------------------------------ */
/* inferVar(): a store's type against the variable's.                  */
/* ------------------------------------------------------------------ */

namespace {
int
infer_var(Unit &u, DFGNode *dr, dtrace_difv_t *v, std::string *err = nullptr)
{
	int r;
	std::string e = capture_stderr([&] { r = u.ti.inferVar(dr, v); });
	if (err)
		*err = e;
	return (r);
}
} // namespace

CASE("infervar-missing-operands")
{
	Unit u;
	std::string err;
	CHECK(infer_var(u, nullptr, nullptr, &err) == -1);
	CHECK(err.find("both dr and dif_var are nullptr") != std::string::npos);
	DFGNode *dr = u.ctf("D", "int");
	CHECK(infer_var(u, dr, nullptr, &err) == -1);
	CHECK(err.find("dif_var is nullptr") != std::string::npos);
	dtrace_difv_t *v = u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
	    DIF_TYPE_STRING);
	CHECK(infer_var(u, nullptr, v) == DIF_TYPE_STRING);
}

CASE("infervar-untyped-variable-takes-store")
{
	for (int kind : { DIF_TYPE_BOTTOM, DIF_TYPE_NONE }) {
		Unit u;
		dtrace_difv_t *v = u.var(1280, DIFV_SCOPE_LOCAL,
		    DIFV_KIND_SCALAR, kind);
		DFGNode *dr = u.ctf("kernel", "struct proc *", "p_pid");
		CHECK(infer_var(u, dr, v) == DIF_TYPE_CTF);
		CHECK(v->dtdv_type.dtdt_kind == DIF_TYPE_CTF &&
		    v->dtdv_ctfid == dr->ctfid && v->dtdv_tf == dr->tf &&
		    v->dtdv_type.dtdt_size == 8 && v->dtdv_sym == dr->sym);
		Unit w;
		v = w.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, kind);
		CHECK(infer_var(w, w.str(), v) == DIF_TYPE_STRING);
		CHECK(v->dtdv_type.dtdt_kind == DIF_TYPE_STRING);
	}
}

CASE("infervar-bottom-store-keeps-variable")
{
	Unit u;
	dtrace_difv_t *v = u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
	    DIF_TYPE_STRING);
	CHECK(infer_var(u, u.def(NOP_INSTR(), DIF_TYPE_BOTTOM), v) ==
	    DIF_TYPE_STRING);
}

CASE("infervar-strings")
{
	Unit u;
	dtrace_difv_t *v = u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
	    DIF_TYPE_STRING);
	/* NULL (setx 0) may be stored in a string variable. */
	DFGNode *z = u.node(DIF_INSTR_SETX(u.integer(0), 1));
	CHECK(u.infer(z) == DIF_TYPE_CTF && z->isNull);
	CHECK(infer_var(u, z, v) == DIF_TYPE_STRING);
	/* So may another D string. */
	CHECK(infer_var(u, u.str(), v) == DIF_TYPE_STRING);
	/* A CTF variable of D's string type accepts a D string and
	 * becomes a string variable. */
	Typefile *d = dt_typefile_D();
	dtrace_difv_t *w = u.var(1281, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
	    DIF_TYPE_CTF, d, handle()->dt_type_str);
	CHECK(infer_var(u, u.str(), w) == DIF_TYPE_STRING);
	CHECK(w->dtdv_type.dtdt_kind == DIF_TYPE_STRING);
	/* And a D string variable accepts a CTF value of D's string type. */
	dtrace_difv_t *x = u.var(1282, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
	    DIF_TYPE_STRING);
	CHECK(infer_var(u, u.def(NOP_INSTR(), DIF_TYPE_CTF, d,
	    handle()->dt_type_str), x) == DIF_TYPE_STRING);
}

CASE("infervar-kind-mismatch-diagnostics")
{
	Unit u;
	std::string err;
	Typefile *k = dt_typefile_kernel();
	dtrace_difv_t *s = u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
	    DIF_TYPE_STRING);
	CHECK(infer_var(u, u.ctf("kernel", "struct proc *"), s, &err) == -1);
	CHECKF(err.find("D string (1) != struct proc *@") != std::string::npos,
	    "%s", err.c_str());
	dtrace_difv_t *c = u.var(1281, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
	    DIF_TYPE_CTF, k, ID(k, "struct proc *"));
	CHECK(infer_var(u, u.str(), c, &err) == -1);
	CHECKF(err.find("struct proc *@") != std::string::npos &&
	    err.find("!= D string (1)") != std::string::npos, "%s", err.c_str());
	CHECK(infer_var(u, u.def(NOP_INSTR(), DIF_TYPE_NONE), c, &err) == -1);
	CHECK(err.find("!= none (254)") != std::string::npos);
	CHECK(infer_var(u, u.def(NOP_INSTR(), 7), c, &err) == -1);
	CHECK(err.find("!= unknown (7)") != std::string::npos);
}

CASE("infervar-ctf-relations")
{
	Unit u;
	std::string err;
	Typefile *d = dt_typefile_D(), *k = dt_typefile_kernel();
	/* A variable without a CTF id yet (D-declared kind, no type)
	 * takes the stored type. */
	dtrace_difv_t *v = u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
	    DIF_TYPE_CTF, d, CTF_ERR);
	DFGNode *i32 = u.ctf("D", "int32_t");
	CHECK(infer_var(u, i32, v) == DIF_TYPE_CTF);
	CHECK(v->dtdv_ctfid == i32->ctfid && v->dtdv_type.dtdt_size == 4);
	/* getSubtypeRelation(var, store) == SUBTYPE_FST replaces the
	 * variable's type by the store's: for integers the first (the
	 * variable) is the larger one; for structures the shorter one. */
	DFGNode *i8 = u.ctf("D", "int8_t");
	CHECK(infer_var(u, i8, v) == DIF_TYPE_CTF);
	CHECK(v->dtdv_ctfid == i8->ctfid && v->dtdv_type.dtdt_size == 1);
	DFGNode *i64 = u.ctf("D", "int64_t");
	CHECK(infer_var(u, i64, v) == DIF_TYPE_CTF);
	CHECK(v->dtdv_ctfid == i8->ctfid); /* SUBTYPE_SND: unchanged */
	/* Incompatible CTF types. */
	dtrace_difv_t *p = u.var(1281, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
	    DIF_TYPE_CTF, k, ID(k, "struct proc *"));
	CHECK(infer_var(u, u.ctf("kernel", "struct thread *"), p, &err) == -1);
	CHECK(err.find("type mismatch in variable store: struct proc * != "
	    "struct thread *") != std::string::npos);
}

CASE("infervar-symbols")
{
	/*
	 * `t | sym' is the address of member sym of a t (C: &x->sym).  Oracle:
	 * C's pointer compatibility -- two member addresses, or a member
	 * address and a pointer, are the same kind of value iff they point at
	 * compatible types (libctf); a member address and the structure
	 * pointer itself are not.
	 */
	Unit u;
	std::string err;
	Typefile *k = dt_typefile_kernel();
	ctf_id_t t = ID(k, "struct thread *");
	dtrace_difv_t *v = u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
	    DIF_TYPE_CTF, k, t, "td_proc");
	CHECK(infer_var(u, u.ctf("kernel", "struct thread *", "td_proc"), v) ==
	    DIF_TYPE_CTF);
	CHECK(infer_var(u, u.ctf("kernel", "struct proc **"), v) ==
	    DIF_TYPE_CTF);
	CHECK(infer_var(u, u.ctf("kernel", "struct thread *", "td_tid"), v,
	    &err) == -1);
	CHECK(err.find("struct thread * | td_proc and struct thread * | "
	    "td_tid point at different types") != std::string::npos);
	CHECK(infer_var(u, u.ctf("kernel", "struct thread *"), v, &err) == -1);
	CHECK(err.find("point at different types") != std::string::npos);
	/* A structure pointer variable does not take a member address. */
	dtrace_difv_t *w = u.var(1281, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
	    DIF_TYPE_CTF, k, t);
	CHECK(infer_var(u, u.ctf("kernel", "struct thread *", "td_tid"), w,
	    &err) == -1);
	CHECK(err.find("point at different types") != std::string::npos);
	/* Member addresses of the same type agree (td_tid: lwpid_t,
	 * td_oncpu: int). */
	dtrace_difv_t *x = u.var(1282, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
	    DIF_TYPE_CTF, k, t, "td_tid");
	CHECK(infer_var(u, u.ctf("kernel", "struct thread *", "td_oncpu"), x) ==
	    DIF_TYPE_CTF);
}

/* ------------------------------------------------------------------ */
/* checkRegDefs(): all definitions of a register must agree.           */
/* ------------------------------------------------------------------ */

namespace {
DFGNode *
regdefs(Unit &u, std::initializer_list<DFGNode *> defs, bool *failed,
    std::string *err = nullptr)
{
	DFGNode *n = u.node(DIF_INSTR_MOV(1, 2));
	Unit::uses(n, defs);
	bool f = false;
	DFGNode *r = nullptr;
	std::string e = capture_stderr([&] {
		r = u.ti.checkRegDefs(n, n->r1Defs, f);
	});
	*failed = f;
	if (err)
		*err = e;
	return (r);
}
} // namespace

CASE("regdefs-none-r0-single")
{
	Unit u;
	bool f;
	CHECK(regdefs(u, {}, &f) == nullptr && !f);
	CHECK(regdefs(u, { u.r0() }, &f) == u.r0() && !f);
	DFGNode *a = u.ctf("D", "int");
	CHECK(regdefs(u, { a }, &f) == a && !f);
	/* A float definition alone is not compared with itself. */
	DFGNode *fl = u.ctf("typingfix", "float");
	CHECK(regdefs(u, { fl }, &f) == fl && !f);
}

CASE("regdefs-bottom-is-skipped")
{
	Unit u;
	bool f;
	DFGNode *b = u.def(NOP_INSTR(), DIF_TYPE_BOTTOM);
	DFGNode *a = u.ctf("kernel", "struct proc *");
	CHECK(regdefs(u, { b, a }, &f) == a && !f);
	DFGNode *c = u.ctf("kernel", "struct proc *");
	CHECK(regdefs(u, { a, b, c }, &f) != nullptr && !f);
}

CASE("regdefs-agreeing-definitions")
{
	Unit u;
	bool f;
	DFGNode *a = u.ctf("D", "int");
	DFGNode *b = u.ctf("D", "int");
	DFGNode *r = regdefs(u, { a, b }, &f);
	CHECK((r == a || r == b) && !f);
	/* Integers of different sizes are related. */
	DFGNode *c = u.ctf("D", "long");
	CHECK(regdefs(u, { a, c }, &f) != nullptr && !f);
	/* A NULL definition is not compared. */
	DFGNode *z = u.ctf("kernel", "struct thread *");
	z->isNull = true;
	DFGNode *p = u.ctf("kernel", "struct proc *");
	CHECK(regdefs(u, { z, p }, &f) != nullptr && !f);
	/* Symbols must agree. */
	DFGNode *s1 = u.ctf("kernel", "struct proc *", "p_pid");
	DFGNode *s2 = u.ctf("kernel", "struct proc *", "p_pid");
	CHECK(regdefs(u, { s1, s2 }, &f) != nullptr && !f);
	/* r0 among other definitions. */
	CHECK(regdefs(u, { u.r0(), a }, &f) != nullptr && !f);
}

CASE("regdefs-strings")
{
	Unit u;
	bool f;
	/* D strings with each other, and with char pointers. */
	DFGNode *s1 = u.str(), *s2 = u.str();
	CHECK(regdefs(u, { s1, s2 }, &f) != nullptr && !f);
	for (const char *t : { "char *", "const char *" }) {
		Unit v;
		DFGNode *s = v.str();
		DFGNode *c = v.ctf("D", t);
		CHECK(regdefs(v, { s, c }, &f) != nullptr && !f);
		CHECK(regdefs(v, { c, s }, &f) != nullptr && !f);
	}
	Unit w;
	DFGNode *s = w.str();
	DFGNode *b = w.def(NOP_INSTR(), DIF_TYPE_BOTTOM);
	CHECK(regdefs(w, { s, b }, &f) != nullptr && !f);
}

PROGERR_CASE("regdefs-string-and-integer",
    "failed to typecheck conditional")
{
	/* Whichever order the definitions are visited in, a D string and an
	 * int do not agree. */
	Unit u;
	DFGNode *s = u.str();
	DFGNode *i = u.ctf("D", "int");
	DFGNode *n = u.node(DIF_INSTR_MOV(1, 2));
	Unit::uses(n, { s, i });
	bool f;
	CHECK(u.ti.checkRegDefs(n, n->r1Defs, f) == nullptr);
}

CASE("regdefs-orders-and-string-forms")
{
	/*
	 * Definitions are visited in hash order, so each pair is tried on
	 * fresh nodes until both orders were seen.  Oracle (D): a register
	 * set on two paths has one type; a D string agrees with the C string
	 * types (char *, const char *, D's own string type); r0 (no value)
	 * agrees with anything; a zero constant is not type-checked.
	 */
	auto run = [](auto make, bool want_ok, const char *what) {
		int firsts = 0;
		for (int i = 0; i < 64 && firsts != 3; i++) {
			Unit u;
			/* Vary the nodes' addresses (and so the order). */
			std::vector<char> pad((size_t)(i * 40 + 8));
			for (int k = 0; k < i % 7; k++)
				u.node(DIF_INSTR_NOP);
			auto [a, b] = make(u);
			DFGNode *first_made = a;
			if (i % 2)
				std::swap(a, b);
			DFGNode *n = u.node(DIF_INSTR_MOV(1, 2));
			Unit::uses(n, { a, b });
			bool failed = false;
			DFGNode *r = nullptr;
			capture_stderr([&] {
				r = u.ti.checkRegDefs(n, n->r1Defs, failed);
			});
			CHECKF((r != nullptr && !failed) == want_ok, "%s", what);
			firsts |= *n->r1Defs.begin() == first_made ? 1 : 2;
		}
		CHECKF(firsts == 3, "%s: one order only", what);
	};
	using P = std::pair<DFGNode *, DFGNode *>;
	run([](Unit &u) { return (P(u.r0(), u.ctf("D", "int"))); }, true,
	    "r0 and int");
	/* (D's own container has no `const char *': typingfix has.) */
	run([](Unit &u) {
		/* Found by walking typingfix's types: libctf's lookup by
		 * name drops the qualifier. */
		Typefile *f = TF("typingfix");
		struct W { ctf_file_t *fp; ctf_id_t id; } w { f->getCtfPointer(),
		    CTF_ERR };
		ctf_type_iter(w.fp, [](ctf_id_t id, void *arg) {
			W *w = (W *)arg;
			char nb[64];
			if (ctf_type_name(w->fp, id, nb, sizeof(nb)) != nullptr &&
			    strcmp(nb, "const char *") == 0)
				w->id = id;
			return (0);
		}, &w);
		CHECK(w.id != CTF_ERR);
		return (P(u.str(), u.def(DIF_INSTR_NOP, DIF_TYPE_CTF, f,
		    w.id)));
	}, true, "const char *");
	for (const char *t : { "char *", "string" })
		run([t](Unit &u) { return (P(u.str(), u.ctf("D", t))); }, true,
		    t);
	run([](Unit &u) {
		return (P(u.str(), u.def(DIF_INSTR_NOP, DIF_TYPE_CTF, TF("D"),
		    0x7ffffff)));
	}, false, "string and an unnamed type");
	run([](Unit &u) {
		DFGNode *z = u.ctf("D", "int");
		z->isNull = true;
		return (P(z, u.ctf("kernel", "struct proc *")));
	}, true, "zero and pointer");
	run([](Unit &u) {
		return (P(u.str(), u.def(DIF_INSTR_NOP, DIF_TYPE_NONE)));
	}, false, "string and none");
	run([](Unit &u) {
		return (P(u.ctf("kernel", "struct proc *", "p_pid"),
		    u.ctf("kernel", "struct proc *")));
	}, false, "symbol on one path");
}

CASE("typefile-forward-defined-in-an-earlier-module")
{
	/* typingfix3 only declares struct tf_nested; the lookup of a member
	 * finds the definition in typingfix (another container). */
	Unit u;
	Typefile *f3 = TF("typingfix3");
	ctf_id_t fwd = f3->getCtfID("struct tf_nested");
	CHECK(fwd != CTF_ERR && f3->getKind(fwd) == CTF_K_FORWARD);
	ctf_membinfo_t mi;
	ctf_file_t *where = f3->getMembInfo(fwd, "sp", &mi);
	CHECK(where != nullptr && where != f3->getCtfPointer());
	CHECK(mi.ctm_offset == (ulong_t)ctf_type_size(where,
	    ctf_lookup_by_name(where, "struct tf_pair")) * 8);
}

CASE("typefile-without-ctf-is-compatible-with-nothing")
{
	Unit u;
	dt_module_t *m = dt_module_lookup_by_name(handle(), "typingnoctf");
	CHECK(m != nullptr);
	Typefile t(handle(), m, "typingnoctf");
	CHECK(t.typeIsCompatibleWith(1, TF("D"), 1) == 0);
	CHECK(TF("D")->typeIsCompatibleWith(1, &t, 1) == 0);
}

CASE("same-value-type")
{
	/* Two CTF values have the same type: the same id of the same type
	 * file; with a member address on either side, the same target. */
	Unit u;
	Typefile *k = dt_typefile_kernel(), *d = TF("D");
	ctf_id_t th = ID(k, "struct thread *");
	CHECK(u.ti.sameValueType(k, th, nullptr, k, th, nullptr));
	CHECK(!u.ti.sameValueType(k, ID(k, "int"), nullptr, d, ID(d, "int"),
	    nullptr));
	CHECK(!u.ti.sameValueType(k, th, nullptr, k, ID(k, "struct proc *"),
	    nullptr));
	CHECK(u.ti.sameValueType(k, th, "td_tid", k, th, "td_tid"));
	CHECK(u.ti.sameValueType(k, th, "td_tid", k, th, "td_oncpu"));
	CHECK(!u.ti.sameValueType(k, th, "td_tid", k, th, "td_proc"));
	CHECK(u.ti.sameValueType(k, th, "td_tid", k, ID(k, "lwpid_t *"),
	    nullptr));
	/* The same member of structures of different type files. */
	CHECK(u.ti.sameValueType(k, th, "td_tid", k, ID(k, "struct thread"),
	    "td_tid"));
}

CASE("vardefs-untyped-variable-member-addresses")
{
	/* A variable without a recorded CTF type: the definitions are only
	 * compared with each other; member addresses of different types
	 * disagree, and the report names both members. */
	Unit u;
	Typefile *k = dt_typefile_kernel();
	ctf_id_t th = ID(k, "struct thread *");
	u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, DIF_TYPE_CTF, k,
	    CTF_ERR);
	DFGNode *a = u.def(DIF_INSTR_STV(DIF_OP_STLS, 1280, 1), DIF_TYPE_CTF, k,
	    th, "td_proc");
	DFGNode *b = u.def(DIF_INSTR_STV(DIF_OP_STLS, 1280, 2), DIF_TYPE_CTF, k,
	    th, "td_tid");
	DFGNode *n = u.node(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 3));
	n->varDefs.insert(a);
	n->varDefs.insert(b);
	bool empty;
	DFGNode *r = nullptr;
	std::string err = capture_stderr([&] {
		r = u.ti.checkVarDefs(n, &u.difo, n->varDefs, empty);
	});
	CHECK(r == nullptr && empty);
	CHECKF((err.find("struct thread * | td_tid and struct thread * | "
	    "td_proc do not match") != std::string::npos) ||
	    (err.find("struct thread * | td_proc and struct thread * | "
	    "td_tid do not match") != std::string::npos), "%s", err.c_str());
}

CASE("var-equal-ctf-fields")
{
	Unit u;
	/* Two variable records are the same CTF variable iff every field
	 * agrees, the type file included. */
	dtrace_difv_t a, b;
	memset(&a, 0, sizeof(a));
	a.dtdv_id = 1280;
	a.dtdv_type.dtdt_kind = DIF_TYPE_CTF;
	a.dtdv_tf = TF("typingfix");
	a.dtdv_ctfid = 3;
	b = a;
	CHECK(TypeInference::varEqualCTF(&a, &b));
	b.dtdv_tf = TF("typingfix2");
	CHECK(!TypeInference::varEqualCTF(&a, &b));
	b = a;
	b.dtdv_ctfid = 4;
	CHECK(!TypeInference::varEqualCTF(&a, &b));
}

CASE("byref-stored-type")
{
	/*
	 * The type a store gives a by-reference variable (the compiler's
	 * DIF_TF_BYREF/BYUREF): a struct or union is stored from its address,
	 * so a pointer to one stores its target; anything else stores itself.
	 */
	Unit u;
	dtrace_difv_t v;
	memset(&v, 0, sizeof(v));
	Typefile *f = TF("typingfix");
	auto stored = [&](DFGNode *dr) { return (u.ti.byRefStoredType(dr, &v)); };
	DFGNode *ps = u.ctf("typingfix", "struct tf_pair *");
	DFGNode *pu = u.ctf("typingfix", "union tf_u *");
	DFGNode *pi = u.ctf("D", "int *");
	DFGNode *st = u.ctf("typingfix", "struct tf_pair");
	DFGNode *str = u.str();
	/* Not by reference: always the stored type. */
	CHECK(stored(ps) == ps->ctfid);
	for (uint8_t fl : { DIF_TF_BYREF, DIF_TF_BYUREF }) {
		v.dtdv_type.dtdt_flags = fl;
		CHECK(stored(ps) == ID(f, "struct tf_pair"));
		CHECK(stored(pu) == ID(f, "union tf_u"));
		CHECK(stored(pi) == pi->ctfid);	/* pointer to an integer */
		CHECK(stored(st) == st->ctfid);	/* not a pointer */
		CHECK(stored(str) == str->ctfid);	/* a D string */
		DFGNode *notf = u.def(DIF_INSTR_NOP, DIF_TYPE_CTF, nullptr, 7);
		CHECK(stored(notf) == 7);		/* no type file */
	}
}

PROGERR_CASE("regdefs-unnamed-string-counterpart", "failed at getting type name")
{
	/* A D string against a CTF type without a name (an invalid id). */
	Unit u;
	DFGNode *s = u.str();
	DFGNode *c = u.def(DIF_INSTR_NOP, DIF_TYPE_CTF, TF("D"), 0x7ffffff);
	DFGNode *n = u.node(DIF_INSTR_MOV(1, 2));
	Unit::uses(n, { s, c });
	bool f;
	CHECK(u.ti.checkRegDefs(n, n->r1Defs, f) == nullptr && f);
}

PROGERR_CASE("regdefs-kinds-disagree", "failed to typecheck conditional")
{
	/* A value with no type and a CTF value; the report names both
	 * kinds (dt_type_diagname()). */
	Unit u;
	DFGNode *a = u.def(NOP_INSTR(), DIF_TYPE_NONE);
	DFGNode *b = u.ctf("D", "int");
	DFGNode *c = u.def(NOP_INSTR(), 7);
	DFGNode *n = u.node(DIF_INSTR_MOV(1, 2));
	Unit::uses(n, { a, b, c });
	bool f;
	CHECK(u.ti.checkRegDefs(n, n->r1Defs, f) == nullptr);
}

CASE("regdefs-failing-definition")
{
	Unit u;
	bool f;
	/* A definition whose own type cannot be inferred. */
	DFGNode *bad = u.node(DIF_INSTR_MOV(5, 1));
	CHECK(regdefs(u, { bad }, &f) == nullptr && f);
}

PROGERR_CASE("regdefs-symbol-missing", "symbol is missing in a node")
{
	Unit u;
	DFGNode *a = u.ctf("kernel", "struct proc *", "p_pid");
	DFGNode *b = u.ctf("kernel", "struct proc *");
	DFGNode *n = u.node(DIF_INSTR_MOV(1, 2));
	Unit::uses(n, { a, b });
	bool f;
	CHECK(u.ti.checkRegDefs(n, n->r1Defs, f) == nullptr);
}

PROGERR_CASE("regdefs-symbols-differ", "nodes have different symbols")
{
	Unit u;
	DFGNode *a = u.ctf("kernel", "struct proc *", "p_pid");
	DFGNode *b = u.ctf("kernel", "struct proc *", "p_ppid");
	DFGNode *n = u.node(DIF_INSTR_MOV(1, 2));
	Unit::uses(n, { a, b });
	bool f;
	CHECK(u.ti.checkRegDefs(n, n->r1Defs, f) == nullptr);
}

PROGERR_CASE("regdefs-unnamed-type", "failed at getting type name")
{
	Unit u;
	DFGNode *a = u.def(NOP_INSTR(), DIF_TYPE_CTF, dt_typefile_kernel(),
	    0x7ffffff);
	DFGNode *n = u.node(DIF_INSTR_MOV(1, 2));
	Unit::uses(n, { a });
	bool f;
	CHECK(u.ti.checkRegDefs(n, n->r1Defs, f) == nullptr);
}

/* ------------------------------------------------------------------ */
/* checkVarDefs(): definitions of a variable within a DIFO.            */
/* ------------------------------------------------------------------ */

namespace {
/* For cases that end in dt_set_progerr(): stderr is not captured. */
void
vardefs_direct(Unit &u, std::initializer_list<DFGNode *> defs)
{
	DFGNode *n = u.node(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 9));
	for (auto d : defs)
		n->varDefs.insert(d);
	bool e = false;
	/* A program error is returned as no definition. */
	CHECK(u.ti.checkVarDefs(n, &u.difo, n->varDefs, e) == nullptr);
}

DFGNode *
vardefs(Unit &u, std::initializer_list<DFGNode *> defs, bool *nonempty,
    std::string *err = nullptr)
{
	DFGNode *n = u.node(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 9));
	for (auto d : defs)
		n->varDefs.insert(d);
	bool e = false;
	DFGNode *r = nullptr;
	std::string text = capture_stderr([&] {
		r = u.ti.checkVarDefs(n, &u.difo, n->varDefs, e);
	});
	*nonempty = e;
	if (err)
		*err = text;
	return (r);
}

DFGNode *
stls(Unit &u, int dtype, Typefile *tf = nullptr, ctf_id_t id = CTF_ERR,
    const char *sym = nullptr)
{
	return (u.def(DIF_INSTR_STV(DIF_OP_STLS, 1280, 1), dtype, tf, id, sym));
}
} // namespace

CASE("vardefs-none-and-agreeing")
{
	Unit u;
	bool ne;
	Typefile *k = dt_typefile_kernel();
	ctf_id_t p = ID(k, "struct proc *");
	u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, DIF_TYPE_CTF, k, p);
	CHECK(vardefs(u, {}, &ne) == nullptr && !ne);
	DFGNode *a = stls(u, DIF_TYPE_CTF, k, p), *b = stls(u, DIF_TYPE_CTF, k, p);
	CHECK(vardefs(u, { a, b }, &ne) != nullptr && ne);
	/* Bottom definitions are not compared with the variable. */
	DFGNode *z = stls(u, DIF_TYPE_BOTTOM);
	CHECK(vardefs(u, { z }, &ne) == z);
	/* Symbols that agree everywhere. */
	Unit v;
	v.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, DIF_TYPE_CTF,
	    dt_typefile_kernel(), ID(dt_typefile_kernel(), "struct proc *"),
	    "p_pid");
	k = dt_typefile_kernel();
	p = ID(k, "struct proc *");
	a = stls(v, DIF_TYPE_CTF, k, p, "p_pid");
	b = stls(v, DIF_TYPE_CTF, k, p, "p_pid");
	CHECK(vardefs(v, { a, b }, &ne) != nullptr);
}

CASE("vardefs-rejections")
{
	struct Row {
		const char *text;
		std::function<std::vector<DFGNode *>(Unit &)> make;
	};
	std::vector<Row> rows = {
		{ "otype and type mismatch", [](Unit &u) {
			  /* A bottom and a CTF definition (in either order). */
			  u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
			      DIF_TYPE_CTF, TF("D"), ID(TF("D"), "int"));
			  return std::vector<DFGNode *> { stls(u, DIF_TYPE_BOTTOM),
				  stls(u, DIF_TYPE_CTF, TF("D"),
				      ID(TF("D"), "int")) };
		  } },
		{ "comparing node with typefile", [](Unit &u) {
			  u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
			      DIF_TYPE_CTF, TF("D"), CTF_ERR);
			  return std::vector<DFGNode *> { stls(u, DIF_TYPE_CTF,
			      TF("typingfix"), ID(TF("typingfix"), "int")) };
		  } },
		{ "variable (x) type and inferred type mismatch: int, long",
		    [](Unit &u) {
			    u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
				DIF_TYPE_CTF, TF("D"), ID(TF("D"), "long"));
			    u.difo.dtdo_strtab = (char *)"x";
			    u.difo.dtdo_strlen = 2;
			    return std::vector<DFGNode *> { stls(u, DIF_TYPE_CTF,
				TF("D"), ID(TF("D"), "int")) };
		    } },
		{ "types int and long do not match", [](Unit &u) {
			  u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
			      DIF_TYPE_CTF, TF("D"), CTF_ERR);
			  return std::vector<DFGNode *> { stls(u, DIF_TYPE_CTF,
			      TF("D"), ID(TF("D"), "long")), stls(u,
			      DIF_TYPE_CTF, TF("D"), ID(TF("D"), "int")) };
		  } },
		/* A member address against a structure pointer, either way
		 * round, and member addresses of types that differ (`t | sym'
		 * values agree when they point at the same type). */
		{ "struct proc *, struct proc * | p_pid", [](Unit &u) {
			  Typefile *k = dt_typefile_kernel();
			  ctf_id_t p = ID(k, "struct proc *");
			  u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
			      DIF_TYPE_CTF, k, p, "p_pid");
			  return std::vector<DFGNode *> { stls(u, DIF_TYPE_CTF,
			      k, p, "p_pid"), stls(u, DIF_TYPE_CTF, k, p) };
		  } },
		{ "struct proc * | p_pid, struct proc *", [](Unit &u) {
			  Typefile *k = dt_typefile_kernel();
			  ctf_id_t p = ID(k, "struct proc *");
			  u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
			      DIF_TYPE_CTF, k, p);
			  return std::vector<DFGNode *> { stls(u, DIF_TYPE_CTF,
			      k, p, "p_pid"), stls(u, DIF_TYPE_CTF, k, p,
			      "p_pid") };
		  } },
		{ "struct proc * | p_comm, struct proc * | p_pid", [](Unit &u) {
			  Typefile *k = dt_typefile_kernel();
			  ctf_id_t p = ID(k, "struct proc *");
			  u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
			      DIF_TYPE_CTF, k, p, "p_pid");
			  return std::vector<DFGNode *> { stls(u, DIF_TYPE_CTF,
			      k, p, "p_pid"), stls(u, DIF_TYPE_CTF, k, p,
			      "p_comm") };
		  } },
		{ "failed to infer", [](Unit &u) {
			  /* A store whose source is undefined. */
			  u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);
			  return std::vector<DFGNode *> { u.node(
			      DIF_INSTR_STV(DIF_OP_STLS, 1280, 4)) };
		  } },
	};
	for (auto &row : rows) {
		Unit u;
		auto defs = row.make(u);
		DFGNode *n = u.node(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 9));
		for (auto d : defs)
			n->varDefs.insert(d);
		bool ne = false;
		DFGNode *r = nullptr;
		std::string err = capture_stderr([&] {
			r = u.ti.checkVarDefs(n, &u.difo, n->varDefs, ne);
		});
		/* The order the definitions are visited in is unspecified. */
		bool mentioned = err.find(row.text) != std::string::npos ||
		    (strcmp(row.text, "types int and long do not match") == 0 &&
		    err.find("types long and int do not match") !=
		    std::string::npos) ||
		    (strcmp(row.text, "failed to infer") == 0 &&
		    err.find("dn2 is nullptr in stls") != std::string::npos);
		CHECKF(r == nullptr && ne && mentioned, "%s: %s", row.text,
		    err.c_str());
	}
}

PROGERR_CASE("vardefs-definition-is-not-a-store",
    "failed to get variable information")
{
	Unit u;
	u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);
	vardefs_direct(u, { u.ctf("D", "int") });
}

PROGERR_CASE("vardefs-unknown-variable",
    "could not find variable (1280, 2, 1) in varlist")
{
	Unit u;
	vardefs_direct(u, { stls(u, DIF_TYPE_CTF, TF("D"), ID(TF("D"), "int")) });
}

PROGERR_CASE("vardefs-unnamed-definition-type", "failed at getting type name")
{
	Unit u;
	u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, DIF_TYPE_CTF, TF("D"),
	    CTF_ERR);
	vardefs_direct(u, { stls(u, DIF_TYPE_CTF, TF("D"), 0x7ffffff) });
}

PROGERR_CASE("vardefs-variable-name-outside-strtab",
    "variable name outside strtab")
{
	Unit u;
	dtrace_difv_t *v = u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
	    DIF_TYPE_CTF, TF("D"), ID(TF("D"), "long"));
	v->dtdv_name = 400;
	vardefs_direct(u, { stls(u, DIF_TYPE_CTF, TF("D"), ID(TF("D"), "int")) });
}

PROGERR_CASE("vardefs-unnamed-variable-type", "failed at getting type name")
{
	Unit u;
	u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, DIF_TYPE_CTF, TF("D"),
	    0x7ffffff);
	u.difo.dtdo_strtab = (char *)"x";
	u.difo.dtdo_strlen = 2;
	vardefs_direct(u, { stls(u, DIF_TYPE_CTF, TF("D"), ID(TF("D"), "int")) });
}

/* ------------------------------------------------------------------ */
/* Error message formatting.                                           */
/* ------------------------------------------------------------------ */

CASE("error-messages")
{
	Unit u;
	u.ti.setErrorMessage("%s %d", "first", 1);
	CHECK(u.ti.getErrorMessage() == "first 1");
	/* An empty message replaces the previous one. */
	u.ti.setErrorMessage("%s", "");
	CHECK(u.ti.getErrorMessage().empty());
	/* A message longer than INT_MAX cannot be formatted (vsnprintf()
	 * fails with EOVERFLOW); a fixed text replaces it. */
	u.ti.setErrorMessage("%2147483647d%d", 1, 2);
	CHECK(u.ti.getErrorMessage().find("could not be formatted") !=
	    std::string::npos);
	u.L.setErrorMessage("%s", "linker");
	CHECK(u.L.getErrorMessage() == "linker");
	u.L.setErrorMessage("%2147483647d%d", 1, 2);
	CHECK(u.L.getErrorMessage().find("could not be formatted") !=
	    std::string::npos);
}

/* ------------------------------------------------------------------ */
/* Linker: return types by action kind (relocateRet()).                */
/* ------------------------------------------------------------------ */

namespace {
struct RetUnit : Unit {
	DFGNode *ret;
	dtrace_diftype_t orig;
	/* The type is named (module, type) or given as a raw id in the
	 * kernel ("#<id>"); type files are looked up after Unit() has opened
	 * them. */
	RetUnit(int dtype, const char *mod = nullptr, const char *type = nullptr)
	    : Unit()
	{
		Typefile *tf = nullptr;
		ctf_id_t id = CTF_ERR;
		if (mod != nullptr && strcmp(mod, "none") == 0) {
			id = 1;
		} else if (mod != nullptr) {
			tf = TF(mod);
			id = type[0] == '#' ? strtol(type + 1, nullptr, 0) :
			    ID(tf, type);
		}
		DFGNode *src = def(DIF_INSTR_LOAD(DIF_OP_LDX, 1, 1), dtype, tf, id);
		ret = node(DIF_INSTR_RET(1));
		uses(ret, { src });
		ret->dType = dtype;
		ret->tf = tf;
		ret->ctfid = id;
		/* The compiler could not type the result (guest data):
		 * the linker types it. */
		memset(&orig, 0, sizeof(orig));
		orig.dtdt_kind = DIF_TYPE_BOTTOM;
	}
	int
	relocate(dtrace_actkind_t kind, dtrace_actdesc_t *ad = nullptr)
	{
		return (L.relocateRet(ret, kind, ad, &orig));
	}
	dtrace_diftype_t &
	rtype()
	{
		return (difo.dtdo_rtype);
	}
};
} // namespace

CASE("ret-rtype-compiler-type-is-kept")
{
	/* A result the compiler typed keeps the compiler's type (D's source
	 * of truth, and what the consumer formats the record by): `(char)x +
	 * (char)y' stays a 1-byte char whatever the linker infers. */
	RetUnit u(DIF_TYPE_CTF, "kernel", "int");
	u.orig = { DIF_TYPE_CTF, CTF_K_INTEGER, 0, 0, 1 };
	dtrace_actdesc_t ad;
	memset(&ad, 0, sizeof(ad));
	ad.dtad_kind = DTRACEACT_DIFEXPR;
	ad.dtad_return = 1;
	CHECK(u.relocate(DTRACEACT_DIFEXPR, &ad) == 0);
	CHECK(memcmp(&u.rtype(), &u.orig, sizeof(u.orig)) == 0);
	/* By reference too (and the load defining it is dropped). */
	RetUnit v(DIF_TYPE_CTF, "kernel", "struct proc *");
	v.orig = { DIF_TYPE_CTF, CTF_K_STRUCT, DIF_TF_BYREF, 0, 1234 };
	CHECK(v.relocate(DTRACEACT_DIFEXPR, &ad) == 0);
	CHECK(memcmp(&v.rtype(), &v.orig, sizeof(v.orig)) == 0);
	CHECK(v.buf[0] == DIF_INSTR_NOP);
}

CASE("ret-rtype-linker-typed-results")
{
	/* Results the compiler could not type (BOTTOM base): the linker
	 * types them from the type checker's type. */
	dtrace_actdesc_t ad;
	memset(&ad, 0, sizeof(ad));
	ad.dtad_return = 1;
	{
		/* No compiler type at all (a caller without one). */
		RetUnit u(DIF_TYPE_CTF, "kernel", "int");
		ad.dtad_kind = DTRACEACT_EXIT;
		CHECK(u.L.relocateRet(u.ret, DTRACEACT_EXIT, &ad, nullptr) == 0);
		CHECK(u.rtype().dtdt_size == sizeof(int));
	}
	{
		/* An action kind without a rule of its own (usym()): the
		 * value's type. */
		RetUnit u(DIF_TYPE_CTF, "kernel", "long");
		ad.dtad_kind = DTRACEACT_USYM;
		CHECK(u.relocate(DTRACEACT_USYM, &ad) == 0);
		CHECK(u.rtype().dtdt_kind == DIF_TYPE_CTF &&
		    u.rtype().dtdt_size == sizeof(long));
	}
	{
		/* A value of unknown type keeps the compiler's flags. */
		RetUnit u(DIF_TYPE_BOTTOM);
		u.orig.dtdt_flags = DIF_TF_BYREF;
		ad.dtad_kind = DTRACEACT_DIFEXPR;
		CHECK(u.relocate(DTRACEACT_DIFEXPR, &ad) == 0);
		CHECK(u.rtype().dtdt_kind == DIF_TYPE_BOTTOM &&
		    u.rtype().dtdt_flags == DIF_TF_BYREF);
	}
	{
		/* A userland D string by reference: a string, still by user
		 * reference, of D's string size. */
		RetUnit u(DIF_TYPE_CTF, "D", "int *");
		/* D's container is the compiler's own, writable: add the
		 * pointer to D's string type a typecast would name. */
		Typefile *dd = TF("D");
		ctf_file_t *fp = dd->getCtfPointer();
		ctf_id_t sp = ctf_add_pointer(fp, CTF_ADD_ROOT, ID(dd, "string"));
		CHECK(sp != CTF_ERR && ctf_update(fp) == 0);
		u.ret->ctfid = sp;
		u.orig.dtdt_flags = DIF_TF_BYUREF;
		ad.dtad_kind = DTRACEACT_DIFEXPR;
		CHECK(u.relocate(DTRACEACT_DIFEXPR, &ad) == 0);
		Typefile *d = TF("D");
		CHECK(u.rtype().dtdt_kind == DIF_TYPE_STRING &&
		    u.rtype().dtdt_flags == DIF_TF_BYUREF &&
		    u.rtype().dtdt_ckind == CTF_K_UNKNOWN &&
		    u.rtype().dtdt_size == (uint32_t)d->getSize(ID(d, "string")));
	}
	{
		/* Another D type by reference is no string. */
		RetUnit u(DIF_TYPE_CTF, "D", "int *");
		u.orig.dtdt_flags = DIF_TF_BYREF;
		ad.dtad_kind = DTRACEACT_DIFEXPR;
		CHECK(u.relocate(DTRACEACT_DIFEXPR, &ad) == 0);
		CHECK(u.rtype().dtdt_kind == DIF_TYPE_CTF &&
		    u.rtype().dtdt_ckind == CTF_K_INTEGER &&
		    u.rtype().dtdt_size == sizeof(int));
	}
}

CASE("ret-rtype-by-action")
{
	{
		/* exit(): an int, whatever the expression's type. */
		RetUnit u(DIF_TYPE_CTF, "kernel", "struct proc *");
		dtrace_actdesc_t ad;
		memset(&ad, 0, sizeof(ad));
		CHECK(u.relocate(DTRACEACT_EXIT, &ad) == 0);
		CHECK(u.rtype().dtdt_kind == DIF_TYPE_CTF &&
		    u.rtype().dtdt_size == sizeof(int));
	}
	for (dtrace_actkind_t kind : { DTRACEACT_PRINTA, DTRACEACT_PRINTM,
	    DTRACEACT_TRACEMEM, DTRACEACT_TRACEMEM_DYNSIZE,
	    DTRACEAGG_QUANTIZE, DTRACEAGG_LQUANTIZE, DTRACEAGG_LLQUANTIZE }) {
		/* The CTF kind is recorded (a kind, as dt_node_diftype()
		 * gives it: libctf's kind of the resolved type, never the type
		 * id); the size is the compiler's. */
		RetUnit u(DIF_TYPE_CTF, "kernel", "lwpid_t");
		u.rtype().dtdt_size = 77;
		dtrace_actdesc_t ad;
		memset(&ad, 0, sizeof(ad));
		ad.dtad_kind = kind;
		CHECK(u.relocate(kind, &ad) == 0);
		ctf_file_t *fp = dt_module_getctf(handle(),
		    dt_module_lookup_by_name(handle(), "kernel"));
		ctf_id_t id = ctf_lookup_by_name(fp, "lwpid_t");
		int kind_oracle = ctf_type_kind(fp, ctf_type_resolve(fp, id));
		CHECK(kind_oracle == CTF_K_INTEGER && (id & 0xff) != CTF_K_INTEGER);
		CHECKF(u.rtype().dtdt_ckind == kind_oracle &&
		    u.rtype().dtdt_size == 77, "ckind %u", u.rtype().dtdt_ckind);
	}
	{
		/* An expression whose value is not returned is void. */
		RetUnit u(DIF_TYPE_CTF, "kernel", "int");
		dtrace_actdesc_t ad;
		memset(&ad, 0, sizeof(ad));
		ad.dtad_kind = DTRACEACT_PRINTF;
		ad.dtad_return = 0;
		CHECK(u.relocate(DTRACEACT_PRINTF, &ad) == 0);
		CHECK(u.rtype().dtdt_size == 0);
		ad.dtad_return = 1;
		RetUnit v(DIF_TYPE_CTF, "kernel", "int");
		CHECK(v.relocate(DTRACEACT_DIFEXPR, &ad) == 0);
		CHECK(v.rtype().dtdt_size == 4);
	}
}

CASE("ret-rtype-values")
{
	Typefile *k;
	{
		/* A by-reference return of a pointer describes what it points
		 * to; the loads defining it are dropped. */
		RetUnit u(DIF_TYPE_CTF, "kernel", "struct proc *");
		k = dt_typefile_kernel();
		u.orig.dtdt_flags = DIF_TF_BYREF;
		CHECK(u.relocate(DTRACEACT_DIFEXPR) == 0);
		CHECK((u.rtype().dtdt_flags & DIF_TF_BYREF) &&
		    u.rtype().dtdt_size ==
		    (uint32_t)k->getSize(ID(k, "struct proc")));
		CHECK(u.buf[0] == DIF_INSTR_NOP);
	}
	{
		/* By user reference: likewise, but user loads are kept. */
		RetUnit u(DIF_TYPE_CTF, "kernel", "int");
		u.buf[0] = DIF_INSTR_LOAD(DIF_OP_ULOAD, 1, 1);
		u.orig.dtdt_flags = DIF_TF_BYUREF;
		CHECK(u.relocate(DTRACEACT_DIFEXPR) == 0);
		CHECK(DIF_INSTR_OP(u.buf[0]) == DIF_OP_ULOAD);
		static const uint8_t loads[] = { DIF_OP_LDUB, DIF_OP_LDSB,
			DIF_OP_LDUH, DIF_OP_LDSH, DIF_OP_LDUW, DIF_OP_LDSW,
			DIF_OP_LDX, DIF_OP_UULOAD, DIF_OP_MOV };
		for (uint8_t op : loads) {
			RetUnit v(DIF_TYPE_CTF, "kernel", "int");
			v.buf[0] = DIF_INSTR_LOAD(op, 1, 1);
			v.orig.dtdt_flags = DIF_TF_BYREF;
			CHECK(v.relocate(DTRACEACT_DIFEXPR) == 0);
			bool dropped = v.buf[0] == DIF_INSTR_NOP;
			CHECK(dropped == (op != DIF_OP_UULOAD && op != DIF_OP_MOV));
		}
	}
	{
		/* A string is returned by reference (kind CTF_K_UNKNOWN, as
		 * the compiler gives D strings). */
		RetUnit u(DIF_TYPE_STRING);
		CHECK(u.relocate(DTRACEACT_DIFEXPR) == 0);
		CHECK((u.rtype().dtdt_flags & DIF_TF_BYREF) &&
		    u.rtype().dtdt_ckind == CTF_K_UNKNOWN);
	}
	{
		/* Regression: a store of a string (`s = execname') returns
		 * nothing; its void type was marked by reference with kind
		 * 0xff, so the host round trip failed verification. */
		RetUnit u(DIF_TYPE_STRING);
		dtrace_actdesc_t ad;
		memset(&ad, 0, sizeof(ad));
		ad.dtad_kind = DTRACEACT_DIFEXPR;
		ad.dtad_return = 0;
		CHECK(u.relocate(DTRACEACT_DIFEXPR, &ad) == 0);
		CHECK(memcmp(&u.rtype(), &dt_void_rtype, sizeof(dt_void_rtype)) ==
		    0);
	}
	{
		/* Bottom keeps the compiler's flags. */
		RetUnit u(DIF_TYPE_BOTTOM);
		u.orig.dtdt_flags = DIF_TF_BYUREF;
		CHECK(u.relocate(DTRACEACT_DIFEXPR) == 0);
		CHECK(u.rtype().dtdt_flags == DIF_TF_BYUREF &&
		    u.rtype().dtdt_ckind == (uint8_t)CTF_BOTTOM_TYPE);
	}
}

CASE("ret-rtype-rejections")
{
	{
		RetUnit u(DIF_TYPE_NONE);
		CHECK(u.relocate(DTRACEACT_DIFEXPR) == E_HYPERTRACE_LINKING);
		CHECK(u.L.getErrorMessage().find("unexpected node->din_type")
		    != std::string::npos);
	}
	{
		RetUnit u(DIF_TYPE_CTF, "none");
		CHECK(u.relocate(DTRACEACT_DIFEXPR) == E_HYPERTRACE_LINKING);
		CHECK(u.L.getErrorMessage() == "missing CTF typefile for return");
	}
	{
		RetUnit u(DIF_TYPE_CTF, "kernel", "#0x7ffffff");
		CHECK(u.relocate(DTRACEACT_DIFEXPR) == E_HYPERTRACE_LINKING);
		CHECK(u.L.getErrorMessage() ==
		    "failed to resolve return CTF kind");
	}
	{
		/* void has no size. */
		RetUnit u(DIF_TYPE_CTF, "kernel", "void");
		CHECK(u.relocate(DTRACEACT_DIFEXPR) == E_HYPERTRACE_LINKING);
		CHECK(u.L.getErrorMessage() == "invalid return CTF size 0");
	}
}

/* ------------------------------------------------------------------ */
/* Linker: integer tables (relocateProgram(), assembleProgram()).      */
/* ------------------------------------------------------------------ */

CASE("linker-integer-table-rebuild")
{
	Unit u;
	u.node(DIF_INSTR_NOP);
	dtrace_diftype_t rt;
	memset(&rt, 0, sizeof(rt));
	/* Every entry keeps its index, duplicates included (the hash does
	 * not share entries inserted without DT_INT_SHARED). */
	u.ints[0] = 5;
	u.ints[1] = 5;
	u.difo.dtdo_intlen = 2;
	CHECK(u.L.relocateProgram(DTRACEACT_DIFEXPR, nullptr, &u.difo, &rt) ==
	    0);
	CHECK(dt_inttab_size(u.difo.dtdo_inthash) == 2);
	/* An entry that cannot be inserted (allocation failure). */
	Unit w;
	w.node(DIF_INSTR_NOP);
	w.ints[0] = 5;
	w.difo.dtdo_intlen = 1;
	int k = find_alloc_where([&] {
		return (w.L.relocateProgram(DTRACEACT_DIFEXPR, nullptr, &w.difo,
		    &rt) == E_HYPERTRACE_LIBDTRACE &&
		    w.L.getErrorMessage().find("failed to insert 5") !=
		    std::string::npos);
	});
	CHECK(k > 0);
	/* An allocation failure of the hash. */
	Unit v;
	v.node(DIF_INSTR_NOP);
	v.ints[0] = 5;
	v.difo.dtdo_intlen = 1;
	int i = find_alloc_where([&] {
		return (v.L.relocateProgram(DTRACEACT_DIFEXPR, nullptr, &v.difo,
		    &rt) == E_HYPERTRACE_LIBDTRACE &&
		    v.L.getErrorMessage() == "failed to allocate inthash");
	});
	CHECK(i > 0);
}

CASE("linker-assemble-integer-table")
{
	Array<UMap<uint32_t, dtrace_diftype_t>, DIFV_NSCOPES> biggest;
	{
		/* An empty hash cannot be written out. */
		Unit u;
		u.difo.dtdo_inthash = dt_inttab_create(u.dtp);
		CHECK(u.L.assembleProgram(&u.difo, biggest) ==
		    E_HYPERTRACE_LINKING);
		CHECK(u.L.getErrorMessage() ==
		    "inthash_size is 0, but inthash is not NULL");
	}
	{
		/* The table is replaced by the hash's contents, and the hash is
		 * released. */
		Unit u;
		u.difo.dtdo_inthash = dt_inttab_create(u.dtp);
		dt_inttab_insert(u.difo.dtdo_inthash, 42, 0);
		u.difo.dtdo_inttab = (uint64_t *)malloc(8);
		CHECK(u.L.assembleProgram(&u.difo, biggest) == 0);
		CHECK(u.difo.dtdo_intlen == 1 && u.difo.dtdo_inttab[0] == 42);
		CHECK(u.difo.dtdo_inthash == nullptr);
	}
	{
		Unit u;
		u.difo.dtdo_inthash = dt_inttab_create(u.dtp);
		dt_inttab_insert(u.difo.dtdo_inthash, 42, 0);
		u.difo.dtdo_inttab = nullptr;
		fail_malloc_after(1);
		int r = u.L.assembleProgram(&u.difo, biggest);
		fail_malloc_after(0);
		CHECK(r == E_HYPERTRACE_SYS);
		CHECK(u.L.getErrorMessage().find("malloc of inttab failed") !=
		    std::string::npos);
	}
}

CASE("linker-usetx-patch-failures")
{
	/* patchUsetxDefs(): allocation of the hash and of an entry. */
	Unit u;
	DFGNode *usetx = u.node(DIF_INSTR_USETX(u.sym("b"), 1));
	DFGNode *n = u.node(DIF_INSTR_RET(1));
	ctf_membinfo_t mi = { 0, 64 };
	n->mip = &mi;
	n->usetxDefs.insert(usetx);
	int i = find_alloc_where([&] {
		return (u.L.patchUsetxDefs(n) == E_HYPERTRACE_LIBDTRACE &&
		    u.L.getErrorMessage() == "failed to allocate inttab");
	});
	CHECK(i > 0);
	int j = find_alloc_where([&] {
		return (u.L.patchUsetxDefs(n) == E_HYPERTRACE_LIBDTRACE &&
		    u.L.getErrorMessage().find("into inthash") !=
		    std::string::npos);
	});
	CHECK(j > 0);
	CHECK(u.L.patchUsetxDefs(n) == 0 && usetx->isRelocated);
}

CASE("linker-member-allocation-failure")
{
	/* relocateUloadOrAdd(): the member information of a symbol. */
	Unit u;
	Typefile *pf = TF("typingfix");
	DFGNode *n = u.def(DIF_INSTR_LOAD(DIF_OP_ULOAD, 1, 2), DIF_TYPE_CTF, pf,
	    ID(pf, "struct tf_pair"), "b");
	int i = find_alloc_where([&] {
		return (u.L.relocateUloadOrAdd(n) == E_HYPERTRACE_SYS);
	});
	CHECK(i > 0);
	/* And a symbol that is no member. */
	DFGNode *m = u.def(DIF_INSTR_LOAD(DIF_OP_ULOAD, 1, 2), DIF_TYPE_CTF, pf,
	    ID(pf, "struct tf_pair"), "zz");
	CHECK(u.L.relocateUloadOrAdd(m) == E_HYPERTRACE_LINKING);
	CHECK(u.L.getErrorMessage().find("failed to resolve member zz") !=
	    std::string::npos);
	/* A member type without a size. */
	ctf_membinfo_t bad = { 0x7ffffff, 0 };
	DFGNode *b = u.def(DIF_INSTR_LOAD(DIF_OP_ULOAD, 1, 2), DIF_TYPE_CTF, pf,
	    ID(pf, "struct tf_pair"));
	b->mip = &bad;
	CHECK(u.L.relocateUloadOrAdd(b) == E_HYPERTRACE_LINKING);
	CHECK(u.L.getErrorMessage().find("failed to resolve size") !=
	    std::string::npos);
}

/* ------------------------------------------------------------------ */
/* Type files.                                                         */
/* ------------------------------------------------------------------ */

CASE("typefile-without-handle")
{
	/* A type file without a handle or module answers every query with
	 * its error value. */
	Unit u;
	Typefile t(nullptr, nullptr, "detached");
	char buf[64];
	ctf_membinfo_t mi;
	ctf_encoding_t e;
	CHECK(t.getCtfID("int") == CTF_ERR);
	CHECK(t.getTypename(1, buf, sizeof(buf)) == nullptr);
	CHECK(t.getReference(1) == CTF_ERR);
	CHECK(t.getSize(1) == -1);
	CHECK(strcmp(t.getErrMsg(), "NOT INITIALIZED") == 0);
	CHECK(t.getMembInfo(1, "a", &mi) == nullptr);
	CHECK(t.getKind(1) == CTF_ERR);
	CHECK(t.resolve(1) == CTF_ERR);
	CHECK(t.getEncoding(1, &e) == -1);
	CHECK(t.buildStruct(1) == nullptr);
	CHECK(!t.getTypename(1).has_value());
	CHECK(t.name() == "detached");
	Typefile c(handle(), nullptr, (char *)"c-string");
	CHECK(c.name() == "c-string");
	/* A handle but no module: likewise. */
	CHECK(c.getCtfID("int") == CTF_ERR);
	CHECK(c.getTypename(1, buf, sizeof(buf)) == nullptr);
	CHECK(c.getReference(1) == CTF_ERR && c.getSize(1) == -1);
	CHECK(c.getMembInfo(1, "a", &mi) == nullptr);
	CHECK(c.getKind(1) == CTF_ERR && c.resolve(1) == CTF_ERR);
	CHECK(c.getEncoding(1, &e) == -1 && c.buildStruct(1) == nullptr);
	CHECK(strcmp(c.getErrMsg(), "NOT INITIALIZED") == 0);
	CHECK(t.typeIsCompatibleWith(1, nullptr, 1) == 0);
}

CASE("typefile-module-without-ctf")
{
	/* typingnoctf is in the inventory but has no CTF. */
	Unit u;
	Typefile *t = TF("typingnoctf");
	char buf[64];
	ctf_membinfo_t mi;
	ctf_encoding_t e;
	CHECK(t->getCtfID("int") == CTF_ERR);
	CHECK(t->getTypename(1, buf, sizeof(buf)) == nullptr);
	CHECK(t->getReference(1) == CTF_ERR);
	CHECK(t->getSize(1) == CTF_ERR);
	CHECK(strcmp(t->getErrMsg(), "CTF file is nullptr") == 0);
	CHECK(t->getMembInfo(1, "a", &mi) == nullptr);
	CHECK(t->getKind(1) == CTF_ERR);
	CHECK(t->resolve(1) == CTF_ERR);
	CHECK(t->getEncoding(1, &e) == -1);
	CHECK(t->buildStruct(1) == nullptr);
	CHECK(t->getArrayInfo(1) == nullptr);
	CHECK(t->typeIsCompatibleWith(1, TF("D"), 1) == 0);
}

CASE("typefile-lookups")
{
	Unit u;
	Typefile *k = dt_typefile_kernel(), *f = TF("typingfix");
	/* "userland " is ignored by lookups. */
	CHECK(k->getCtfID("userland struct proc *") ==
	    k->getCtfID("struct proc *"));
	/* The C and D definitions. */
	CHECK(TF("C")->getCtfID("int") != CTF_ERR);
	CHECK(TF("D")->getCtfID("no_such_type_t") == CTF_ERR);
	CHECK(dt_typefile_mod(nullptr) == nullptr);
	CHECK(dt_typefile_mod("no_such_module") == nullptr);
	/* Encodings and resolution through typedefs. */
	ctf_encoding_t e;
	CHECK(f->getEncoding(ID(f, "unsigned short"), &e) == 0 &&
	    e.cte_bits == 16 && (e.cte_format & CTF_INT_SIGNED) == 0);
	CHECK(f->resolve(ID(f, "tf_pair_t")) == ID(f, "struct tf_pair"));
	/* A structure's members are enumerated once and reused. */
	auto *m1 = f->buildStruct(ID(f, "struct tf_pair"));
	auto *m2 = f->buildStruct(ID(f, "struct tf_pair"));
	CHECK(m1 != nullptr && m1 == m2 && m1->size() == 2);
	CHECK(f->buildStruct(ID(f, "int")) == nullptr);
	/* Arrays. */
	ctf_membinfo_t mi;
	CHECK(ctf_member_info(f->getCtfPointer(), ID(f, "struct tf_arr"),
	    "arr", &mi) == 0);
	ctf_arinfo_t *ai = f->getArrayInfo(mi.ctm_type);
	CHECK(ai != nullptr && ai->ctr_nelems == 4);
	free(ai);
	CHECK(f->getArrayInfo(ID(f, "int")) == nullptr);
	fail_malloc_after(1);
	CHECK(f->getArrayInfo(mi.ctm_type) == nullptr);
	fail_malloc_after(0);
	/* stripReference(): typedefs, pointers and arrays, counting the
	 * indirections. */
	size_t stars;
	ctf_id_t id = mi.ctm_type;
	CHECK(f->stripReference(id, stars) == CTF_K_INTEGER && stars == 1);
	id = k->getCtfID("struct proc **");
	if (id != CTF_ERR) {
		CHECK(k->stripReference(id, stars) == CTF_K_STRUCT && stars == 2);
	}
	id = ID(f, "tf_pair_t");
	CHECK(f->stripTypedef(id) == CTF_K_STRUCT && id == ID(f,
	    "struct tf_pair"));
	id = ID(f, "int");
	CHECK(f->stripTypedef(id) == CTF_K_INTEGER);
}

CASE("typefile-membinfo-undefined-forward")
{
	/* typingfix's struct tf_undef is defined nowhere: the forward
	 * declaration has no members. */
	Unit u;
	Typefile *f = TF("typingfix");
	ctf_membinfo_t mi;
	CHECK(f->getMembInfo(ID(f, "struct tf_undef"), "x", &mi) == nullptr);
}

CASE("typefile-reopen-replaces-list")
{
	/* dt_typefile_openall() describes the handle's modules only. */
	Unit u;
	size_t n = typefiles.size();
	dt_typefile_openall(handle());
	CHECK(typefiles.size() == n);
	CHECK(dt_typefile_kernel() != nullptr && dt_typefile_D() != nullptr);
}

/* ------------------------------------------------------------------ */
/* dt_get_class(), with CTF parent containers built with libctf.        */
/* ------------------------------------------------------------------ */

namespace {
/* A type file over a CTF container made here, whose parent is `parent'. */
struct ChildCTF {
	ctf_file_t *fp;
	dt_module_t mod;
	Typefile *tf;
	ctf_id_t fwd_pair, fwd_fwd, fwd_only;
	ctf_id_t self_typedef, long1, long2, short1;
	ChildCTF(ctf_file_t *parent)
	{
		int err;
		fp = ctf_create(&err);
		CHECK(fp != nullptr);
		if (parent != nullptr)
			CHECK(ctf_import(fp, parent) == 0);
		fwd_pair = ctf_add_forward(fp, CTF_ADD_ROOT, "tf_pair",
		    CTF_K_STRUCT);
		fwd_fwd = ctf_add_forward(fp, CTF_ADD_ROOT, "tf_fwd",
		    CTF_K_STRUCT);
		fwd_only = ctf_add_forward(fp, CTF_ADD_ROOT, "tf_childonly",
		    CTF_K_STRUCT);
		/* A typedef of itself (ids are handed out in order), and two
		 * structures whose names do not fit a type name buffer. */
		self_typedef = ctf_add_typedef(fp, CTF_ADD_ROOT, "tf_loop",
		    fwd_only + 1);
		std::string longname(DT_TYPE_NAMELEN + 64, 'n');
		long1 = ctf_add_struct(fp, CTF_ADD_ROOT, longname.c_str());
		longname[0] = 'm';
		long2 = ctf_add_struct(fp, CTF_ADD_ROOT, longname.c_str());
		short1 = ctf_add_struct(fp, CTF_ADD_ROOT, "tf_shortname");
		CHECK(ctf_update(fp) == 0);
		memset(&mod, 0, sizeof(mod));
		strlcpy(mod.dm_name, "child", sizeof(mod.dm_name));
		mod.dm_ctfp = fp;
		tf = new Typefile(handle(), &mod, "child");
	}
};
} // namespace

CASE("class-forward-through-parent")
{
	Unit u;
	ChildCTF c(TF("typingfix2")->getCtfPointer());
	/* tf_pair: typingfix (searched before the parent) defines it. */
	CHECK(dt_get_class(c.tf, c.fwd_pair, 1) == DTC_STRUCT);
	/* tf_fwd: only a forward declaration before the parent, which
	 * defines it. */
	CHECK(dt_get_class(c.tf, c.fwd_fwd, 1) == DTC_STRUCT);
	/* Defined nowhere. */
	CHECK(dt_get_class(c.tf, c.fwd_only, 1) == DTC_FORWARD);
	/* A typedef of itself ends the reference walk: no class. */
	CHECK(ctf_type_reference(c.fp, c.self_typedef) == c.self_typedef);
	CHECK(dt_get_class(c.tf, c.self_typedef, 1) == DTC_BOTTOM);
	/* A name longer than a type name buffer cannot be compared. */
	std::string err = capture_stderr([&] {
		CHECK(u.ti.ctfTypeCompare(c.tf, c.long1, c.tf, c.long2) != 0);
		CHECK(u.ti.ctfTypeCompare(c.tf, c.short1, c.tf, c.long1) != 0);
	});
	CHECK(err.find("cannot resolve type") != std::string::npos);
	/* Without following, a forward declaration is just that. */
	CHECK(dt_get_class(c.tf, c.fwd_pair, 0) == DTC_FORWARD);
}

CASE("class-forward-parent-not-a-typefile")
{
	Unit u;
	int err;
	ctf_file_t *orphan = ctf_create(&err);
	CHECK(orphan != nullptr && ctf_update(orphan) == 0);
	ChildCTF c(orphan);
	CHECK(dt_get_class(c.tf, c.fwd_only, 1) == DTC_FORWARD);
}

CASE("class-misc")
{
	Unit u;
	Typefile *f = TF("typingfix"), *k = dt_typefile_kernel();
	CHECK(dt_get_class(f, 0x7ffffff, 1) == DTC_BOTTOM);
	CHECK(dt_get_class(f, ID(f, "float"), 1) == DTC_BOTTOM);
	CHECK(dt_get_class(f, ID(f, "enum tf_e"), 1) == DTC_ENUM);
	CHECK(dt_get_class(f, ID(f, "union tf_u"), 1) == DTC_UNION);
	CHECK(dt_get_class(k, ID(k, "struct proc *"), 1) == DTC_STRUCT);
	CHECK(dt_get_class(f, ID(f, "struct tf_fwd *"), 1) == DTC_FORWARD);
}

/* ------------------------------------------------------------------ */
/* D string checks.                                                    */
/* ------------------------------------------------------------------ */

CASE("string-checks")
{
	Unit u;
	dtrace_hdl_t *h = handle();
	Typefile *d = TF("D"), *k = dt_typefile_kernel();
	CHECK(dt_typecheck_string(h, DIF_TYPE_STRING, DIF_TYPE_STRING, 0, 0,
	    nullptr, nullptr));
	CHECK(dt_typecheck_string(h, DIF_TYPE_STRING, DIF_TYPE_CTF, 0,
	    h->dt_type_str, nullptr, d));
	CHECK(dt_typecheck_string(h, DIF_TYPE_CTF, DIF_TYPE_STRING,
	    h->dt_type_str, 0, d, nullptr));
	/* Another type, or D's string id in another module, is no string. */
	CHECK(!dt_typecheck_string(h, DIF_TYPE_STRING, DIF_TYPE_CTF, 0,
	    ID(d, "int"), nullptr, d));
	CHECK(!dt_typecheck_string(h, DIF_TYPE_STRING, DIF_TYPE_CTF, 0,
	    h->dt_type_str, nullptr, k));
	CHECK(!dt_typecheck_string(h, DIF_TYPE_CTF, DIF_TYPE_CTF, 1, 1, d, d));
	DFGNode *a = u.str(), *b = u.str();
	CHECK(dt_typecheck_stringii(h, a, b));
}

/* ------------------------------------------------------------------ */
/* getTypenameChecked(): a node's type must come from the given files. */
/* ------------------------------------------------------------------ */

PROGERR_CASE("typename-checked-foreign-typefile",
    "loc: node 0' could not find typefile 'typingfix'")
{
	Unit u;
	DFGNode *n = u.ctf("typingfix", "int");
	Vec<Typefile *> tfs = { dt_typefile_D(), dt_typefile_kernel() };
	char buf[64];
	u.L.getTypenameChecked(n, tfs, buf, sizeof(buf), "loc");
}

PROGERR_CASE("typename-checked-unnamed", "loc: (0) failed getting type name")
{
	Unit u;
	DFGNode *n = u.def(DIF_INSTR_NOP, DIF_TYPE_CTF, TF("D"), 0x7ffffff);
	Vec<Typefile *> tfs = { dt_typefile_D() };
	char buf[64];
	u.L.getTypenameChecked(n, tfs, buf, sizeof(buf), "loc");
}

/* ------------------------------------------------------------------ */
/* Assertions of internal invariants (death tests).                    */
/* ------------------------------------------------------------------ */

ABORT_CASE("assert-ctfcompare-typefiles", "tf1 != nullptr")
{
	Unit u;
	u.ti.ctfTypeCompare(nullptr, 1, TF("D"), 1);
}

ABORT_CASE("assert-ctfcompare-second-typefile", "tf2 != nullptr")
{
	Unit u;
	u.ti.ctfTypeCompare(TF("D"), 1, nullptr, 1);
}

PROGERR_CASE("typecompare-both-bottom", "both types are bottom")
{
	/* Two values of unknown type cannot be ordered. */
	Unit u;
	DFGNode *a = u.def(DIF_INSTR_NOP, DIF_TYPE_BOTTOM);
	DFGNode *b = u.def(DIF_INSTR_NOP, DIF_TYPE_BOTTOM);
	CHECK(u.ti.typeCompare(a, b) == -1);
}

PROGERR_CASE("typecompare-unnamed-first", "dt_type_compare(): failed at "
    "getting type name")
{
	/* A type libctf cannot name (an id past the container) is a program
	 * error; libctf's allocation failure is not (see
	 * typename-allocation-failure-throws). */
	Unit u;
	DFGNode *a = u.def(DIF_INSTR_NOP, DIF_TYPE_CTF, dt_typefile_kernel(),
	    0x7ffffff);
	DFGNode *b = u.ctf("D", "int");
	CHECK(u.ti.typeCompare(a, b) == -1);
}

PROGERR_CASE("typecompare-unnamed-second", "dt_type_compare(): failed at "
    "getting type name")
{
	Unit u;
	DFGNode *a = u.ctf("D", "int");
	DFGNode *b = u.def(DIF_INSTR_NOP, DIF_TYPE_CTF, dt_typefile_kernel(),
	    0x7ffffff);
	CHECK(u.ti.typeCompare(a, b) == -1);
}

CASE("typename-allocation-failure-throws")
{
	/* libctf reports its allocation failure as EAGAIN: the type file
	 * throws std::bad_alloc (hypertrace_link() returns it as an
	 * allocation failure) instead of a name lookup failing. */
	Unit u;
	Typefile *f = TF("typingfix");
	ctf_id_t id = ID(f, "struct tf_pair");
	bool thrown = false;
	fail_malloc_after(1);
	try {
		(void)f->getTypename(id);
	} catch (const std::bad_alloc &) {
		thrown = true;
	}
	fail_malloc_after(0);
	CHECK(thrown);
	CHECK(f->getTypename(id).value_or("") == "struct tf_pair");
}

ABORT_CASE("assert-typecompare-none", "dn1->dType != DIF_TYPE_NONE")
{
	Unit u;
	DFGNode *a = u.def(DIF_INSTR_NOP, DIF_TYPE_NONE);
	DFGNode *b = u.ctf("D", "int");
	u.ti.typeCompare(a, b);
}

ABORT_CASE("assert-typecompare-none-second", "dn2->dType != DIF_TYPE_NONE")
{
	Unit u;
	DFGNode *a = u.ctf("D", "int");
	DFGNode *b = u.def(DIF_INSTR_NOP, DIF_TYPE_NONE);
	u.ti.typeCompare(a, b);
}

ABORT_CASE("assert-ret-action-kind", "actionKind != DTRACEACT_NONE")
{
	RetUnit u(DIF_TYPE_BOTTOM);
	u.relocate(DTRACEACT_NONE);
}

ABORT_CASE("assert-ret-action-description", "ad != nullptr")
{
	RetUnit u(DIF_TYPE_BOTTOM);
	u.relocate(DTRACEACT_EXIT, nullptr);
}

ABORT_CASE("assert-assemble-unknown-variable", "vlvar != nullptr")
{
	Unit u;
	dtrace_difv_t v;
	memset(&v, 0, sizeof(v));
	v.dtdv_id = 1280;
	v.dtdv_scope = DIFV_SCOPE_LOCAL;
	v.dtdv_kind = DIFV_KIND_SCALAR;
	u.difo.dtdo_vartab = &v;
	u.difo.dtdo_varlen = 1;
	Array<UMap<uint32_t, dtrace_diftype_t>, DIFV_NSCOPES> biggest;
	u.L.assembleProgram(&u.difo, biggest);
}

/* ------------------------------------------------------------------ */
/* Linker odds and ends.                                               */
/* ------------------------------------------------------------------ */

CASE("linker-assemble-invalid-scope")
{
	Unit u;
	dtrace_difv_t v;
	memset(&v, 0, sizeof(v));
	v.dtdv_id = 1280;
	v.dtdv_scope = 9;
	u.difo.dtdo_vartab = &v;
	u.difo.dtdo_varlen = 1;
	Array<UMap<uint32_t, dtrace_diftype_t>, DIFV_NSCOPES> biggest;
	CHECK(u.L.assembleProgram(&u.difo, biggest) == E_HYPERTRACE_LINKING);
	CHECK(u.L.getErrorMessage() == "variable 1280 has an invalid scope 9");
}

CASE("linker-assemble-widest-variable-type")
{
	/* The widest type seen for a variable is kept for the final table. */
	Unit u;
	dtrace_difv_t *vv = u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
	    DIF_TYPE_CTF, TF("D"), ID(TF("D"), "int"));
	vv->dtdv_type.dtdt_size = 4;
	dtrace_difv_t v = *vv;
	u.difo.dtdo_vartab = &v;
	u.difo.dtdo_varlen = 1;
	Array<UMap<uint32_t, dtrace_diftype_t>, DIFV_NSCOPES> biggest;
	CHECK(u.L.assembleProgram(&u.difo, biggest) == 0);
	CHECK(biggest[DIFV_SCOPE_LOCAL][1280].dtdt_size == 4);
	vv->dtdv_type.dtdt_size = 2;
	CHECK(u.L.assembleProgram(&u.difo, biggest) == 0);
	CHECK(biggest[DIFV_SCOPE_LOCAL][1280].dtdt_size == 4);
}

CASE("linker-empty-integer-table-is-no-table")
{
	Unit u;
	u.node(DIF_INSTR_NOP);
	u.difo.dtdo_intlen = 0; /* the table pointer is set */
	dtrace_diftype_t rt;
	memset(&rt, 0, sizeof(rt));
	CHECK(u.L.relocateProgram(DTRACEACT_DIFEXPR, nullptr, &u.difo, &rt) ==
	    0);
	CHECK(u.difo.dtdo_inthash == nullptr);
	/* A hash left behind by an earlier link is replaced. */
	u.difo.dtdo_inthash = dt_inttab_create(u.dtp);
	u.ints[0] = 9;
	u.difo.dtdo_intlen = 1;
	CHECK(u.L.relocateProgram(DTRACEACT_DIFEXPR, nullptr, &u.difo, &rt) ==
	    0);
	CHECK(dt_inttab_size(u.difo.dtdo_inthash) == 1);
}

CASE("store-without-definitions")
{
	Unit u;
	DFGNode *n = u.node(DIF_INSTR_STORE(DIF_OP_STX, 1, 3));
	std::string err = capture_stderr([&] { CHECK(u.infer(n) == -1); });
	CHECK(u.ti.getErrorMessage().find("the value register has no "
	    "definition") != std::string::npos);
	Unit v;
	n = v.node(DIF_INSTR_STORE(DIF_OP_STX, 1, 3));
	Unit::uses(n, { v.ctf("D", "int") });
	CHECK(v.infer(n) == -1);
	CHECK(v.ti.getErrorMessage().find("the address register has no "
	    "definition") != std::string::npos);
}

/* ------------------------------------------------------------------ */
/* Data-flow graph construction (computeDFG()).                         */
/* The expected definitions are read off the DIF by hand: an operand's  */
/* definitions are the reachable earlier writes of its register; a      */
/* variable load's are the reachable earlier stores of the variable; a  */
/* subroutine's tuple stack holds the pushes not yet popped.            */
/* ------------------------------------------------------------------ */

namespace {
struct DfgUnit : Unit {
	std::vector<DFGNode *> at;
	DfgUnit() : Unit() {}
	void
	set(std::initializer_list<dif_instr_t> code)
	{
		for (auto i : code)
			buf[difo.dtdo_len++] = i;
	}
	int
	build()
	{
		auto before = L.dfgNodes.size();
		L.computeDFG(&edp, &difo);
		int r = 0;
		at.clear();
		auto it = L.dfgNodes.begin();
		std::advance(it, before);
		for (; it != L.dfgNodes.end(); ++it)
			at.push_back(it->get());
		return (r);
	}
	static bool
	is(const NodeSet &s, std::initializer_list<DFGNode *> want)
	{
		return (s == NodeSet(want));
	}
};
} // namespace

CASE("dfg-register-definitions")
{
	DfgUnit u;
	u.set({ DIF_INSTR_SETX(u.integer(1), 1),	/* 0 */
	    DIF_INSTR_SETX(u.integer(2), 2),		/* 1 */
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 3),	/* 2 */
	    DIF_INSTR_MOV(3, 4),			/* 3 */
	    DIF_INSTR_LOAD(DIF_OP_LDX, 4, 5),		/* 4: ldx [%r4], %r5 */
	    DIF_INSTR_FMT(DIF_OP_SUB, 0, 5, 1),	/* 5: uses r0 */
	    DIF_INSTR_RET(1) });			/* 6 */
	CHECK(u.build() == 0 && u.at.size() == 7);
	auto &n = u.at;
	CHECK(DfgUnit::is(n[2]->r1Defs, { n[0] }) &&
	    DfgUnit::is(n[2]->r2Defs, { n[1] }));
	CHECK(DfgUnit::is(n[3]->r1Defs, { n[2] }));
	/* The load's address is %r4 (r1), not its destination. */
	CHECK(DfgUnit::is(n[4]->r1Defs, { n[3] }));
	CHECK(DfgUnit::is(n[5]->r1Defs, { u.r0() }) &&
	    DfgUnit::is(n[5]->r2Defs, { n[4] }));
	/* %r1 is redefined at 5: the return sees only that. */
	CHECK(DfgUnit::is(n[6]->r1Defs, { n[5] }));
	CHECK(DfgUnit::is(n[0]->r1Children, { n[2] }));
}

CASE("dfg-every-register-reader")
{
	/* One reader of each operand form: loads (r1), stores (r1 value,
	 * rd address), unary (r1), binary (r1, r2), copys, allocs (r1),
	 * ld{g,t}a (r2), variable stores (rs), pushes (rs), returns. */
	static const uint8_t loads[] = { DIF_OP_LDSB, DIF_OP_LDSH, DIF_OP_LDSW,
		DIF_OP_LDUB, DIF_OP_LDUH, DIF_OP_LDUW, DIF_OP_LDX, DIF_OP_ULDSB,
		DIF_OP_ULDSH, DIF_OP_ULDSW, DIF_OP_ULDUB, DIF_OP_ULDUH,
		DIF_OP_ULDUW, DIF_OP_ULDX, DIF_OP_RLDSB, DIF_OP_RLDSH,
		DIF_OP_RLDSW, DIF_OP_RLDUB, DIF_OP_RLDUH, DIF_OP_RLDUW,
		DIF_OP_RLDX, DIF_OP_ULOAD, DIF_OP_UULOAD };
	for (uint8_t op : loads) {
		DfgUnit u;
	u.set({ DIF_INSTR_SETX(u.integer(1), 1),
		    (dif_instr_t)DIF_INSTR_LOAD(op, 1, 2), DIF_INSTR_RET(2) });
		CHECK(u.build() == 0);
		CHECK(DfgUnit::is(u.at[1]->r1Defs, { u.at[0] }));
		CHECK(DfgUnit::is(u.at[2]->r1Defs, { u.at[1] }));
	}
	static const uint8_t stores[] = { DIF_OP_STB, DIF_OP_STH, DIF_OP_STW,
		DIF_OP_STX };
	for (uint8_t op : stores) {
		DfgUnit u;
	u.set({ DIF_INSTR_SETX(u.integer(1), 1),
		    DIF_INSTR_SETX(u.integer(2), 2), (dif_instr_t)DIF_INSTR_STORE(op, 1, 2),
		    DIF_INSTR_RET(1) });
		CHECK(u.build() == 0);
		CHECK(DfgUnit::is(u.at[2]->r1Defs, { u.at[0] }) &&
		    DfgUnit::is(u.at[2]->r2Defs, { u.at[1] }));
	}
	{
		DfgUnit u;
	u.set({ DIF_INSTR_SETX(u.integer(1), 1),
		    DIF_INSTR_SETX(u.integer(2), 2), DIF_INSTR_COPYS(1, 2, 3),
		    DIF_INSTR_ALLOCS(2, 4), DIF_INSTR_NOT(1, 5),
		    DIF_INSTR_LDA(DIF_OP_LDGA, DIF_VAR_ARGS, 2, 6),
		    DIF_INSTR_LDA(DIF_OP_LDTA, 3, 2, 7), DIF_INSTR_RET(3) });
		CHECK(u.build() == 0);
		auto &n = u.at;
		CHECK(DfgUnit::is(n[2]->r1Defs, { n[0] }) &&
		    DfgUnit::is(n[2]->r2Defs, { n[1] }));
		CHECK(DfgUnit::is(n[3]->r1Defs, { n[1] })); /* allocs r1 */
		CHECK(DfgUnit::is(n[4]->r1Defs, { n[0] }));
		CHECK(DfgUnit::is(n[5]->r2Defs, { n[1] }));
		CHECK(DfgUnit::is(n[6]->r2Defs, { n[1] }));
		CHECK(DfgUnit::is(n[7]->r1Defs, { n[2] }));
	}
}

CASE("dfg-variable-definitions")
{
	u_int x = 1280;
	DfgUnit u;
	u.set({ DIF_INSTR_SETX(u.integer(1), 1),	/* 0 */
	    DIF_INSTR_STV(DIF_OP_STLS, x, 1),		/* 1 */
	    DIF_INSTR_LDV(DIF_OP_LDLS, x, 2),		/* 2 */
	    DIF_INSTR_STV(DIF_OP_STLS, x, 2),		/* 3: redefines x */
	    DIF_INSTR_LDV(DIF_OP_LDLS, x, 3),		/* 4 */
	    DIF_INSTR_STV(DIF_OP_STGS, 1300, 1),	/* 5 */
	    DIF_INSTR_LDV(DIF_OP_LDGS, 1300, 4),	/* 6 */
	    DIF_INSTR_LDV(DIF_OP_LDTS, 1300, 4),	/* 7: another scope */
	    DIF_INSTR_STV(DIF_OP_STTS, 1300, 1),	/* 8 */
	    DIF_INSTR_LDV(DIF_OP_LDTS, 1300, 5),	/* 9 */
	    DIF_INSTR_LDV(DIF_OP_LDGS, 1300, 6),	/* 10 */
	    DIF_INSTR_LDV(DIF_OP_LDLS, x, 6),		/* 11 */
	    DIF_INSTR_RET(6) });
	CHECK(u.build() == 0);
	auto &n = u.at;
	CHECK(DfgUnit::is(n[2]->varDefs, { n[1] }));
	CHECK(DfgUnit::is(n[4]->varDefs, { n[3] }));
	CHECK(DfgUnit::is(n[6]->varDefs, { n[5] }));
	CHECK(n[7]->varDefs.empty());
	CHECK(DfgUnit::is(n[9]->varDefs, { n[8] }));
	CHECK(DfgUnit::is(n[10]->varDefs, { n[5] }));
	CHECK(DfgUnit::is(n[11]->varDefs, { n[3] }));
}

CASE("dfg-array-variable-definitions")
{
	/* Stores to arrays do not end the search (a later key may differ). */
	DfgUnit u;
	u.set({ DIF_INSTR_SETX(u.integer(1), 1),
	    DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, DIF_TYPE_CTF, 0, 1),
	    DIF_INSTR_STV(DIF_OP_STGAA, 1300, 1),	/* 2 */
	    DIF_INSTR_STV(DIF_OP_STGAA, 1300, 1),	/* 3 */
	    DIF_INSTR_LDV(DIF_OP_LDGAA, 1300, 2),	/* 4 */
	    DIF_INSTR_STV(DIF_OP_STTAA, 1300, 1),	/* 5 */
	    DIF_INSTR_LDV(DIF_OP_LDTAA, 1300, 3),	/* 6 */
	    DIF_INSTR_LDV(DIF_OP_LDGA, 1300 & 0xff, 3), /* 7 */
	    DIF_INSTR_RET(2) });
	CHECK(u.build() == 0);
	auto &n = u.at;
	CHECK(DfgUnit::is(n[4]->varDefs, { n[2], n[3] }));
	CHECK(DfgUnit::is(n[6]->varDefs, { n[5] }));
}

CASE("dfg-variable-identity-matrix")
{
	/*
	 * Every store against every load of the same variable number: a load
	 * is defined by a store iff both name the same variable, i.e. the same
	 * id, scope and kind (sys/dtrace.h dtrace_difv_t): ldgs/stgs global
	 * scalars, ldts/stts thread scalars, ldls/stls clause-locals,
	 * ldga/ldgaa/stgaa global arrays, ldta/ldtaa/sttaa thread arrays.
	 */
	struct Op { uint8_t op; uint8_t scope, kind; };
	const Op stores[] = {
		{ DIF_OP_STGS, DIFV_SCOPE_GLOBAL, DIFV_KIND_SCALAR },
		{ DIF_OP_STTS, DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR },
		{ DIF_OP_STLS, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR },
		{ DIF_OP_STGAA, DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY },
		{ DIF_OP_STTAA, DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY },
	};
	const Op loads[] = {
		{ DIF_OP_LDGS, DIFV_SCOPE_GLOBAL, DIFV_KIND_SCALAR },
		{ DIF_OP_LDTS, DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR },
		{ DIF_OP_LDLS, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR },
		{ DIF_OP_LDGAA, DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY },
		{ DIF_OP_LDTAA, DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY },
		{ DIF_OP_LDGA, DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY },
		{ DIF_OP_LDTA, DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY },
	};
	const u_int var = 0x60; /* fits ld{g,t}a's 8-bit variable field */
	int pairs = 0;
	for (const Op &st : stores) {
		for (const Op &ld : loads) {
			DfgUnit u;
			dif_instr_t load = ld.op == DIF_OP_LDGA ||
			    ld.op == DIF_OP_LDTA ?
			    DIF_INSTR_LDA(ld.op, var, 1, 2) :
			    DIF_INSTR_LDV(ld.op, var, 2);
			u.set({ DIF_INSTR_SETX(u.integer(1), 1),
			    DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, DIF_TYPE_CTF, 0, 1),
			    DIF_INSTR_STV(st.op, var, 1),	/* 2 */
			    load,				/* 3 */
			    DIF_INSTR_LDV(ld.op == DIF_OP_LDGS ? DIF_OP_LDTS :
				DIF_OP_LDGS, var + 1, 3),	/* 4: another */
			    DIF_INSTR_RET(2) });
			CHECK(u.build() == 0);
			bool same = st.scope == ld.scope && st.kind == ld.kind;
			CHECKF(u.at[3]->varDefs.contains(u.at[2]) == same,
			    "store %u, load %u", st.op, ld.op);
			CHECK(!u.at[4]->varDefs.contains(u.at[2]));
			pairs++;
		}
	}
	CHECK(pairs == 35);
}

CASE("dfg-r0-operand-and-non-clobbering-call")
{
	/*
	 * %r0 is always zero: an operand %r0 is defined by r0 only (DIF).  A
	 * subroutine without a result (bcopy(); subrClobbers()) does not
	 * define its destination register: a later read of that register sees
	 * the earlier definition.
	 */
	DfgUnit u;
	u.set({ DIF_INSTR_SETX(u.integer(5), 1),			/* 0 */
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 0, 2),			/* 1: r1 + r0 */
	    DIF_INSTR_CALL(DIF_SUBR_BCOPY, 1),				/* 2 */
	    DIF_INSTR_MOV(1, 3),					/* 3 */
	    DIF_INSTR_CALL(DIF_SUBR_RAND, 1),				/* 4 */
	    DIF_INSTR_MOV(1, 4),					/* 5 */
	    DIF_INSTR_RET(4) });
	CHECK(u.build() == 0);
	auto &n = u.at;
	CHECK(DfgUnit::is(n[1]->r1Defs, { n[0] }));
	CHECK(DfgUnit::is(n[1]->r2Defs, { u.r0() }));
	CHECK(DfgUnit::is(n[3]->r1Defs, { n[0] }));
	CHECK(DfgUnit::is(n[5]->r1Defs, { n[4] }));
}

CASE("dfg-tuple-stacks")
{
	DfgUnit u;
	u.set({ DIF_INSTR_SETX(u.integer(1), 1),			/* 0 */
	    DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, DIF_TYPE_CTF, 0, 1),	/* 1 */
	    DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, DIF_TYPE_CTF, 0, 1),	/* 2 */
	    DIF_INSTR_POPTS,						/* 3 */
	    DIF_INSTR_CALL(DIF_SUBR_STRLEN, 2),			/* 4 */
	    DIF_INSTR_FLUSHTS,						/* 5 */
	    DIF_INSTR_CALL(DIF_SUBR_RAND, 3),				/* 6 */
	    DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 0, 1),	/* 7 */
	    DIF_INSTR_POPTS,						/* 8 */
	    DIF_INSTR_CALL(DIF_SUBR_RAND, 3),				/* 9 */
	    DIF_INSTR_RET(2) });
	CHECK(u.build() == 0);
	auto &n = u.at;
	/* The second push was popped before the call. */
	CHECK(n[4]->stacks.size() == 1 &&
	    n[4]->stacks[0].nodesOnStack == NodeVec({ n[1] }));
	CHECK(n[6]->stacks.empty() && n[9]->stacks.empty());
}

CASE("dfg-branches")
{
	/* setx 1 -> r1; tst; be L; setx 2 -> r1; ba L; L: ret r1: both
	 * definitions reach the return. */
	DfgUnit u;
	u.set({ DIF_INSTR_SETX(u.integer(1), 1),	/* 0 */
	    DIF_INSTR_TST(1),				/* 1 */
	    DIF_INSTR_BRANCH(DIF_OP_BE, 5),		/* 2 */
	    DIF_INSTR_SETX(u.integer(2), 1),		/* 3 */
	    DIF_INSTR_BRANCH(DIF_OP_BA, 5),		/* 4 */
	    DIF_INSTR_RET(1) });			/* 5 */
	CHECK(u.build() == 0);
	auto &n = u.at;
	CHECK(DfgUnit::is(n[5]->r1Defs, { n[0], n[3] }));
	/* Comparisons have no type of their own: their operands are not
	 * recorded (usiteContainsReg()). */
	CHECK(n[1]->r1Defs.empty());
}

CASE("dfg-fall-through-into-a-label")
{
	/*
	 * Regression: a block that ends only because the next instruction is
	 * a branch target falls through into it (DIF executes in order), but
	 * the CFG had no edge for that, so the definition on the
	 * fall-through path did not reach the label.
	 *   setx 1 -> r1; tst r1; be L; setx 2 -> r1; L: ret r1
	 */
	DfgUnit u;
	u.set({ DIF_INSTR_SETX(u.integer(1), 1),	/* 0 */
	    DIF_INSTR_TST(1),				/* 1 */
	    DIF_INSTR_BRANCH(DIF_OP_BE, 4),		/* 2 */
	    DIF_INSTR_SETX(u.integer(2), 1),		/* 3: falls into 4 */
	    DIF_INSTR_RET(1) });			/* 4 */
	CHECK(u.build() == 0);
	auto &n = u.at;
	CHECK(DfgUnit::is(n[4]->r1Defs, { n[0], n[3] }));
	BasicBlock *b3 = n[3]->bb, *b4 = n[4]->bb;
	CHECK(b3 != b4);
	bool edge = false;
	for (auto &c : b3->children)
		edge |= c.first == b4;
	CHECK(edge);
	/* A block ending in ret continues nowhere. */
	CHECK(b4->children.empty());
}

CASE("same-target-of-member-addresses-and-pointers")
{
	/* Oracle: libctf's compatibility of what the values point at. */
	Unit u;
	Typefile *k = dt_typefile_kernel();
	ctf_id_t th = ID(k, "struct thread *");
	CHECK(u.ti.sameTarget(k, th, "td_tid", k, ID(k, "lwpid_t *"), nullptr));
	CHECK(u.ti.sameTarget(k, th, "td_tid", k, th, "td_oncpu"));
	CHECK(u.ti.sameTarget(k, ID(k, "int *"), nullptr, k, th, "td_tid"));
	CHECK(!u.ti.sameTarget(k, th, "td_tid", k, ID(k, "struct proc **"),
	    nullptr));
	CHECK(!u.ti.sameTarget(k, th, "td_tid", k, th, "td_proc"));
	/* No pointer, or no such member: no target. */
	CHECK(!u.ti.sameTarget(k, ID(k, "int"), nullptr, k, th, "td_tid"));
	CHECK(!u.ti.sameTarget(k, th, "no_such_member", k, th, "td_tid"));
	CHECK(!u.ti.sameTarget(k, th, "td_tid", k, ID(k, "int"), nullptr));
	CHECK(!u.ti.sameTarget(nullptr, th, nullptr, k, th, "td_tid"));
	CHECK(!u.ti.sameTarget(k, CTF_ERR, nullptr, k, th, "td_tid"));
	/* The member of a structure value (not a pointer to one). */
	CHECK(u.ti.sameTarget(k, ID(k, "struct thread"), "td_tid", k, th,
	    "td_tid"));
}

CASE("variable-info-decoding")
{
	/* Oracle: sys/dtrace.h -- the variable each load and store names
	 * (ld{g,t}a in r1), with its scope and kind. */
	struct {
		dif_instr_t ins;
		int what, scope, kind;
		uint16_t var;
	} rows[] = {
		{ DIF_INSTR_STV(DIF_OP_STGS, 1280, 1), DT_VARINFO_STORE,
		    DIFV_SCOPE_GLOBAL, DIFV_KIND_SCALAR, 1280 },
		{ DIF_INSTR_STV(DIF_OP_STTS, 1281, 1), DT_VARINFO_STORE,
		    DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR, 1281 },
		{ DIF_INSTR_STV(DIF_OP_STLS, 1282, 1), DT_VARINFO_STORE,
		    DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, 1282 },
		{ DIF_INSTR_STV(DIF_OP_STGAA, 1283, 1), DT_VARINFO_STORE,
		    DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY, 1283 },
		{ DIF_INSTR_STV(DIF_OP_STTAA, 1284, 1), DT_VARINFO_STORE,
		    DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY, 1284 },
		{ DIF_INSTR_LDV(DIF_OP_LDGS, 1285, 1), DT_VARINFO_LOAD,
		    DIFV_SCOPE_GLOBAL, DIFV_KIND_SCALAR, 1285 },
		{ DIF_INSTR_LDV(DIF_OP_LDTS, 1286, 1), DT_VARINFO_LOAD,
		    DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR, 1286 },
		{ DIF_INSTR_LDV(DIF_OP_LDLS, 1287, 1), DT_VARINFO_LOAD,
		    DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, 1287 },
		{ DIF_INSTR_LDV(DIF_OP_LDGAA, 1288, 1), DT_VARINFO_LOAD,
		    DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY, 1288 },
		{ DIF_INSTR_LDV(DIF_OP_LDTAA, 1289, 1), DT_VARINFO_LOAD,
		    DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY, 1289 },
		{ DIF_INSTR_LDA(DIF_OP_LDGA, 0x41, 2, 1), DT_VARINFO_LOAD,
		    DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY, 0x41 },
		{ DIF_INSTR_LDA(DIF_OP_LDTA, 0x42, 2, 1), DT_VARINFO_LOAD,
		    DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY, 0x42 },
		{ DIF_INSTR_MOV(1, 2), DT_VARINFO_NONE, -1, -1, 0 },
	};
	for (auto &r : rows) {
		uint16_t v;
		int scope, kind;
		int what = getVariableInfo(r.ins, &v, &scope, &kind);
		CHECKF(what == r.what && scope == r.scope && kind == r.kind &&
		    v == r.var, "op %u: %d %d %d %u", DIF_INSTR_OP(r.ins), what,
		    scope, kind, v);
	}
}

CASE("variable-source-through-an-array-element")
{
	/* A store through a pointer loaded from an associative array has
	 * that array as its variable source (it used to have none: only
	 * scalar loads were decoded). */
	DfgUnit u;
	u.set({ DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, DIF_TYPE_CTF, 0, 0),
	    DIF_INSTR_LDV(DIF_OP_LDGAA, 1300, 1),
	    DIF_INSTR_SETX(u.integer(8), 2), DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 3),
	    DIF_INSTR_STORE(DIF_OP_STW, 2, 3), DIF_INSTR_RET(2) });
	dtrace_difv_t *a = u.var(1300, DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY);
	CHECK(u.build() == 0);
	CHECK(u.ti.findVariableFromNodeDefs(u.at[3]->r1Defs) == a);
}

CASE("stack-checks")
{
	/*
	 * Tuple stacks on different paths: none (no stack, no failure); the
	 * same types (accepted, even when each path resolved the type in
	 * another type file); a different number of entries (rejected: it
	 * used to read past the shorter stack).
	 */
	Unit u;
	Vec<StackData> none;
	bool failed = true;
	CHECK(u.ti.checkStack(none, failed) == nullptr && !failed);

	Typefile *k = dt_typefile_kernel(), *d = dt_typefile_D();
	auto stack = [&](std::initializer_list<DFGNode *> nodes) {
		Vec<BasicBlock *> path;
		StackData sd(path);
		for (auto n : nodes)
			sd.nodesOnStack.push_back(n);
		return (sd);
	};
	auto pushed = [&](Typefile *tf, const char *t) {
		return (u.def(DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, DIF_TYPE_CTF, 0, 1),
		    DIF_TYPE_CTF, tf, ID(tf, t)));
	};
	Vec<StackData> same;
	same.push_back(stack({ pushed(k, "int") }));
	same.push_back(stack({ pushed(d, "int") }));
	NodeVec *r = u.ti.checkStack(same, failed);
	CHECK(r != nullptr && r == &same.front().nodesOnStack);

	Vec<StackData> arity;
	arity.push_back(stack({ pushed(d, "int"), pushed(d, "int") }));
	arity.push_back(stack({ pushed(d, "int") }));
	std::string err = capture_stderr([&] {
		r = u.ti.checkStack(arity, failed);
	});
	CHECK(r == nullptr && failed);
	CHECK(err.find("2 stack entries on one path, 1 on another") !=
	    std::string::npos ||
	    err.find("1 stack entries on one path, 2 on another") !=
	    std::string::npos);

	Vec<StackData> types;
	types.push_back(stack({ pushed(d, "int") }));
	types.push_back(stack({ pushed(d, "long") }));
	capture_stderr([&] { r = u.ti.checkStack(types, failed); });
	CHECK(r == nullptr && failed);
}

CASE("dfg-typecast-is-transparent-for-types")
{
	/* setx -> r1; typecast r1; ret r1: the return's type definition is
	 * the cast; its data definition is the setx. */
	DfgUnit u;
	u.set({ DIF_INSTR_SETX(u.integer(1), 1),
	    DIF_INSTR_TYPECAST(u.sym("int"), 1), DIF_INSTR_RET(1) });
	CHECK(u.build() == 0);
	auto &n = u.at;
	CHECK(DfgUnit::is(n[2]->r1Defs, { n[1] }));
	CHECK(DfgUnit::is(n[2]->r1DataDefs, { n[0] }));
	CHECK(n[2]->findChild(n[0]) == n[0] && n[2]->findChild(n[2]) == n[2]);
	CHECK(n[0]->findChild(n[2]) == nullptr);
}

CASE("dfg-variable-sources-of-stores")
{
	/* ldls p (a pointer variable); add an offset; stw through it: the
	 * store's variable source is p.  A store through a builtin's value
	 * has none. */
	Unit base;
	(void)base;
	DfgUnit u;
	u.set({ DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 1),
	    DIF_INSTR_SETX(u.integer(8), 2), DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 3),
	    DIF_INSTR_MOV(3, 4), DIF_INSTR_STORE(DIF_OP_STW, 2, 4),
	    DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_CURTHREAD, 5),
	    DIF_INSTR_STORE(DIF_OP_STB, 2, 5), DIF_INSTR_RET(2) });
	dtrace_difv_t *p = u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);
	CHECK(u.build() == 0);
	CHECK(u.at[4]->varSources.size() == 1 && u.at[4]->varSources[0] == p);
	CHECK(u.at[6]->varSources.empty());
}

CASE("dfg-variable-source-through-non-writing-instructions")
{
	/*
	 * Instructions that write no register (stores, compares, branches,
	 * nop, stack pushes and pops; DIF) leave the variable's address where
	 * it is: each width of store through it gets the variable as source.
	 * A store of an unrelated register gets none.
	 */
	DfgUnit u;
	u.set({ DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 1),		/* 0 */
	    DIF_INSTR_SETX(u.integer(0), 2),			/* 1 */
	    DIF_INSTR_NOP,					/* 2 */
	    DIF_INSTR_CMP(DIF_OP_CMP, 2, 2),			/* 3 */
	    DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, DIF_TYPE_CTF, 0, 2),	/* 4 */
	    DIF_INSTR_POPTS,					/* 5 */
	    DIF_INSTR_STORE(DIF_OP_STH, 2, 1),			/* 6 */
	    DIF_INSTR_STORE(DIF_OP_STX, 2, 1),			/* 7 */
	    DIF_INSTR_STORE(DIF_OP_STX, 1, 2),			/* 8 */
	    DIF_INSTR_BRANCH(DIF_OP_BGE, 12),			/* 9 */
	    DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 3),		/* 10 */
	    DIF_INSTR_BRANCH(DIF_OP_BLE, 12),			/* 11 */
	    DIF_INSTR_RET(2) });				/* 12 */
	dtrace_difv_t *p = u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);
	CHECK(u.build() == 0);
	for (int i : { 6, 7 })
		CHECKF(u.at[i]->varSources.size() == 1 &&
		    u.at[i]->varSources[0] == p, "store %d", i);
	CHECK(u.at[8]->varSources.empty());
}

CASE("dfg-no-symbol-table")
{
	DfgUnit u;
	u.set({ DIF_INSTR_RET(0) });
	u.difo.dtdo_symtab = nullptr;
	u.difo.dtdo_symlen = 0;
	CHECK(u.build() == 0 && u.at.empty());
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
