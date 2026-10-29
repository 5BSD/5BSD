/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * TypeInference::inferNode() rule by rule on constructed DFGs.
 *
 * Every case names the inference rule (the comment above the opcode's case
 * in dt_typing.cc) or the documented rejection it exercises.  Definitions
 * are given their types up front; the node under test is inferred and its
 * type, symbol and member information compared with what the rule states,
 * computed independently with libctf where a CTF type is involved.
 */
#include "typing-unit.h"

#include <type_traits>

namespace {

/* The CTF type name libctf gives a member of a kernel structure. */
std::string
kmember(const char *type, const char *member, ulong_t *off = nullptr)
{
	return (ctf_member_type(dt_typefile_kernel()->getCtfPointer(), type,
	    member, off));
}

void
expect_type(Unit &u, DFGNode *n, int dtype, const char *name = nullptr)
{
	int t = u.infer(n);
	CHECKF(t == dtype, "inferred %d, expected %d (%s)", t, dtype,
	    u.ti.getErrorMessage().c_str());
	if (name != nullptr)
		CHECKF(u.tname(n) == name, "type '%s', expected '%s'",
		    u.tname(n).c_str(), name);
}

void
expect_fail(Unit &u, DFGNode *n, const char *text)
{
	std::string err = capture_stderr([&] {
		CHECK(u.infer(n) == -1);
	});
	std::string all = err + u.ti.getErrorMessage();
	CHECKF(all.find(text) != std::string::npos, "'%s' lacks '%s'",
	    all.c_str(), text);
}

constexpr dif_instr_t NOP = DIF_INSTR_NOP;

} // namespace

/* ---- ULOAD / UULOAD -------------------------------------------------
 *  %r1 : t1 | sym   t2 = type_at(t1, symname)  =>  uload [%r1] : t2
 */
CASE("uload-member-type")
{
	Unit u;
	DFGNode *base = u.ctf("kernel", "struct thread *", "td_tid",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	DFGNode *n = u.node(DIF_INSTR_LOAD(DIF_OP_ULOAD, 1, 3));
	Unit::uses(n, { base });
	ulong_t off;
	std::string want = kmember("struct thread", "td_tid", &off);
	expect_type(u, n, DIF_TYPE_CTF, want.c_str());
	CHECK(n->mip != nullptr && n->mip->ctm_offset == off);
	CHECK(n->tf == dt_typefile_kernel());
}

CASE("uuload-member-of-struct-value")
{
	/* The base may be the structure itself, not only a pointer. */
	Unit u;
	DFGNode *base = u.ctf("typingfix", "struct tf_pair", "b",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	DFGNode *n = u.node(DIF_INSTR_LOAD(DIF_OP_UULOAD, 1, 3));
	Unit::uses(n, { base });
	expect_type(u, n, DIF_TYPE_CTF, "long");
	CHECK(n->mip->ctm_offset == 64);
}

CASE("uload-through-typedef")
{
	/* tf_pair_t is a typedef of struct tf_pair (getMipFromSymbol strips
	 * one level of typedef/pointer/qualifier). */
	Unit u;
	DFGNode *base = u.ctf("typingfix", "tf_pair_t", "a",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	DFGNode *n = u.node(DIF_INSTR_LOAD(DIF_OP_ULOAD, 1, 3));
	Unit::uses(n, { base });
	expect_type(u, n, DIF_TYPE_CTF, "int");
}

CASE("uload-no-definition")
{
	Unit u;
	DFGNode *n = u.node(DIF_INSTR_LOAD(DIF_OP_ULOAD, 1, 3));
	expect_fail(u, n, "expected a non-null r1 definition");
}

CASE("uload-without-symbol")
{
	Unit u;
	DFGNode *base = u.ctf("kernel", "struct thread *");
	DFGNode *n = u.node(DIF_INSTR_LOAD(DIF_OP_ULOAD, 1, 3));
	Unit::uses(n, { base });
	expect_fail(u, n, "expected a non-null r1 symbol");
}

CASE("uload-unknown-member")
{
	Unit u;
	DFGNode *base = u.ctf("kernel", "struct thread *", "no_such_member",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	DFGNode *n = u.node(DIF_INSTR_LOAD(DIF_OP_ULOAD, 1, 3));
	Unit::uses(n, { base });
	expect_fail(u, n, "failed to get mip [struct thread *:no_such_member]");
}

CASE("uload-member-of-integer")
{
	/* type_at() is only defined for structures. */
	Unit u;
	DFGNode *base = u.ctf("kernel", "uint64_t", "td_tid",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	DFGNode *n = u.node(DIF_INSTR_LOAD(DIF_OP_ULOAD, 1, 3));
	Unit::uses(n, { base });
	expect_fail(u, n, "failed to get mip");
}

CASE("uload-symbol-of-another-difo")
{
	/* A symbol outside this DIFO's table has no meaning here. */
	Unit u;
	DFGNode *base = u.ctf("kernel", "struct thread *");
	static char foreign[] = "td_tid";
	base->sym = foreign;
	DFGNode *n = u.node(DIF_INSTR_LOAD(DIF_OP_ULOAD, 1, 3));
	Unit::uses(n, { base });
	expect_fail(u, n, "failed to get mip");
}

/* ---- USETX ----------------------------------------------------------
 *  symtab(idx) = sym  =>  usetx idx, %r1 : uint64_t | sym
 */
CASE("usetx-symbol")
{
	Unit u;
	uint_t s = u.sym("td_proc");
	DFGNode *n = u.node(DIF_INSTR_USETX(s, 1));
	expect_type(u, n, DIF_TYPE_CTF, "uint64_t");
	CHECK(n->sym == u.symtab + s && strcmp(n->sym, "td_proc") == 0);
	CHECK(n->tf == dt_typefile_D());
}

CASE("usetx-index-out-of-range")
{
	Unit u;
	DFGNode *n = u.node(DIF_INSTR_USETX(4000, 1));
	expect_fail(u, n, "symbol 4000 is not a string in the 1-byte symbol table");
}

/* ---- TYPECAST -------------------------------------------------------
 *  symtab(idx) = t   t in ctf_file  =>  typecast idx, %r1 : t
 */
CASE("typecast-kernel-type")
{
	Unit u;
	DFGNode *src = u.ctf("D", "uint64_t");
	DFGNode *n = u.node(DIF_INSTR_TYPECAST(u.sym("struct proc *"), 1));
	Unit::uses(n, { src });
	expect_type(u, n, DIF_TYPE_CTF, "struct proc *");
	CHECK(n->tf == dt_typefile_kernel());
}

CASE("typecast-userland-prefix")
{
	Unit u;
	DFGNode *src = u.ctf("D", "uint64_t");
	DFGNode *n = u.node(DIF_INSTR_TYPECAST(
	    u.sym("userland struct proc *"), 1));
	Unit::uses(n, { src });
	expect_type(u, n, DIF_TYPE_CTF, "struct proc *");
}

CASE("typecast-d-string")
{
	Unit u;
	DFGNode *src = u.ctf("D", "uint64_t");
	DFGNode *n = u.node(DIF_INSTR_TYPECAST(u.sym("D string"), 1));
	Unit::uses(n, { src });
	expect_type(u, n, DIF_TYPE_STRING);
}

CASE("typecast-bottom")
{
	Unit u;
	DFGNode *src = u.ctf("D", "uint64_t");
	DFGNode *n = u.node(DIF_INSTR_TYPECAST(u.sym("bottom"), 1));
	Unit::uses(n, { src });
	expect_type(u, n, DIF_TYPE_BOTTOM);
}

CASE("typecast-keeps-member-of-symbolic-source")
{
	/* A cast of a symbolic member address keeps the member info. */
	Unit u;
	DFGNode *src = u.ctf("kernel", "struct thread *", "td_proc",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	DFGNode *n = u.node(DIF_INSTR_TYPECAST(u.sym("uintptr_t"), 1));
	Unit::uses(n, { src });
	expect_type(u, n, DIF_TYPE_CTF, "uintptr_t");
	CHECK(n->mip != nullptr);
	CHECK(u.tname(n) == "uintptr_t");
}

CASE("typecast-probe-module-first")
{
	/* The probe's module is searched first: typingfix's struct thread
	 * (16 bytes) shadows the kernel's for a typingfix probe.  (The
	 * fixture has no "struct thread *" type, so the structure is cast.) */
	Unit u;
	strlcpy(u.edp.dted_probe.dtpd_mod, "typingfix",
	    sizeof(u.edp.dted_probe.dtpd_mod));
	DFGNode *src = u.ctf("D", "uint64_t");
	DFGNode *n = u.node(DIF_INSTR_TYPECAST(u.sym("struct thread"), 1));
	Unit::uses(n, { src });
	expect_type(u, n, DIF_TYPE_CTF, "struct thread");
	CHECK(n->tf == TF("typingfix"));
	CHECK(n->tf->getSize(n->ctfid) == 16);
}

CASE("typecast-freebsd-module-is-kernel")
{
	Unit u;
	strlcpy(u.edp.dted_probe.dtpd_mod, "freebsd",
	    sizeof(u.edp.dted_probe.dtpd_mod));
	DFGNode *src = u.ctf("D", "uint64_t");
	DFGNode *n = u.node(DIF_INSTR_TYPECAST(u.sym("struct thread *"), 1));
	Unit::uses(n, { src });
	expect_type(u, n, DIF_TYPE_CTF, "struct thread *");
	CHECK(n->tf == dt_typefile_kernel());
}

CASE("typecast-falls-back-to-other-modules")
{
	/* struct tf_small * is not in the kernel; the search continues over
	 * every type file (only typingfix has the pointer type). */
	Unit u;
	DFGNode *src = u.ctf("D", "uint64_t");
	DFGNode *n = u.node(DIF_INSTR_TYPECAST(u.sym("struct tf_small *"), 1));
	Unit::uses(n, { src });
	expect_type(u, n, DIF_TYPE_CTF, "struct tf_small *");
	CHECK(n->tf == TF("typingfix"));
}

PROGERR_CASE("typecast-unknown-type",
    "failed to get type struct no_such *: no type file has it")
{
	Unit u;
	DFGNode *src = u.ctf("D", "uint64_t");
	DFGNode *n = u.node(DIF_INSTR_TYPECAST(u.sym("struct no_such *"), 1));
	Unit::uses(n, { src });
	u.infer(n);
}

CASE("typecast-no-definition")
{
	Unit u;
	DFGNode *n = u.node(DIF_INSTR_TYPECAST(u.sym("int"), 1));
	expect_fail(u, n, "r1 definition must not be NULL");
}

CASE("typecast-index-out-of-range")
{
	Unit u;
	DFGNode *src = u.ctf("D", "uint64_t");
	DFGNode *n = u.node(DIF_INSTR_TYPECAST(9000, 1));
	Unit::uses(n, { src });
	expect_fail(u, n, "symbol 9000 is not a string in the 1-byte symbol table");
}

CASE("typecast-name-too-long")
{
	Unit u;
	DFGNode *src = u.ctf("D", "uint64_t");
	std::string longname(5000, 'x');
	DFGNode *n = u.node(DIF_INSTR_TYPECAST(u.sym(longname.c_str()), 1));
	Unit::uses(n, { src });
	expect_fail(u, n, "length 5000 >= 4096 when copying type name");
}

/* ---- MOV / NOT:  %r1 : t  =>  opcode %r1, %r2 : t --------------------- */
CASE("mov-copies-type-symbol-and-nullness")
{
	Unit u;
	DFGNode *src = u.ctf("kernel", "struct thread *", "td_tid");
	src->isNull = true;
	DFGNode *n = u.node(DIF_INSTR_MOV(1, 2));
	Unit::uses(n, { src });
	expect_type(u, n, DIF_TYPE_CTF, "struct thread *");
	CHECK(n->sym == src->sym && n->isNull);
}

CASE("not-copies-type-not-nullness")
{
	Unit u;
	DFGNode *src = u.ctf("D", "int32_t");
	src->isNull = false;
	DFGNode *n = u.node(DIF_INSTR_NOT(1, 2));
	n->isNull = true;
	Unit::uses(n, { src });
	expect_type(u, n, DIF_TYPE_CTF, "int32_t");
	CHECK(n->isNull); /* not a copy of the value */
}

CASE("mov-string")
{
	Unit u;
	DFGNode *src = u.str();
	DFGNode *n = u.node(DIF_INSTR_MOV(1, 2));
	Unit::uses(n, { src });
	expect_type(u, n, DIF_TYPE_STRING);
}

CASE("mov-no-definition")
{
	Unit u;
	DFGNode *n = u.node(DIF_INSTR_MOV(1, 2));
	expect_fail(u, n, "dn1 is nullptr");
}

/* ---- Loads: the width and signedness of the opcode ----------------- */
CASE("loads-all-widths")
{
	static const struct {
		uint8_t op;
		const char *type;
	} loads[] = {
		{ DIF_OP_LDSB, "int8_t" }, { DIF_OP_RLDSB, "int8_t" },
		{ DIF_OP_ULDSB, "int8_t" }, { DIF_OP_LDSH, "int16_t" },
		{ DIF_OP_RLDSH, "int16_t" }, { DIF_OP_ULDSH, "int16_t" },
		{ DIF_OP_LDSW, "int32_t" }, { DIF_OP_RLDSW, "int32_t" },
		{ DIF_OP_ULDSW, "int32_t" }, { DIF_OP_LDUB, "uint8_t" },
		{ DIF_OP_RLDUB, "uint8_t" }, { DIF_OP_ULDUB, "uint8_t" },
		{ DIF_OP_LDUH, "uint16_t" }, { DIF_OP_RLDUH, "uint16_t" },
		{ DIF_OP_ULDUH, "uint16_t" }, { DIF_OP_LDUW, "uint32_t" },
		{ DIF_OP_RLDUW, "uint32_t" }, { DIF_OP_ULDUW, "uint32_t" },
		{ DIF_OP_LDX, "uint64_t" }, { DIF_OP_RLDX, "uint64_t" },
		{ DIF_OP_ULDX, "uint64_t" },
	};
	for (auto &l : loads) {
		Unit u;
		DFGNode *addr = u.ctf("kernel", "uintptr_t");
		DFGNode *n = u.node(DIF_INSTR_LOAD(l.op, 1, 2));
		Unit::uses(n, { addr });
		expect_type(u, n, DIF_TYPE_CTF, l.type);
		CHECK(n->tf == dt_typefile_D());
	}
}

/* ---- SETX / SETS ---------------------------------------------------- */
CASE("setx-value-and-nullness")
{
	Unit u;
	DFGNode *z = u.node(DIF_INSTR_SETX(u.integer(0), 1));
	DFGNode *v = u.node(DIF_INSTR_SETX(u.integer(0x1234), 2));
	/* A constant has the compiler's constant type (dt_node_int()). */
	expect_type(u, z, DIF_TYPE_CTF, "int");
	expect_type(u, v, DIF_TYPE_CTF, "int");
	CHECK(z->isNull && z->integer.value() == 0);
	CHECK(!v->isNull && v->integer.value() == 0x1234);
}

CASE("setx-64-bit-value")
{
	/* Regression: the value was truncated to an int, so 2^32 read as 0
	 * (and NULL). */
	Unit u;
	DFGNode *n = u.node(DIF_INSTR_SETX(u.integer(0x100000000ULL), 1));
	expect_type(u, n, DIF_TYPE_CTF, "long");
	CHECK(n->integer.value() == 0x100000000ULL && !n->isNull);
	DFGNode *m = u.node(DIF_INSTR_SETX(u.integer(~0ULL), 2));
	expect_type(u, m, DIF_TYPE_CTF, "unsigned long");
	CHECK(m->integer.value() == ~0ULL);
}

CASE("setx-index-out-of-range")
{
	Unit u;
	u.integer(1);
	expect_fail(u, u.node(DIF_INSTR_SETX(5, 1)), "integer index 5 >= 1");
}

CASE("sets-string")
{
	Unit u;
	DFGNode *n = u.node(DIF_INSTR_SETS(0, 1));
	expect_type(u, n, DIF_TYPE_STRING);
}


/* ---- Binary arithmetic -------------------------------------------------
 *  %r1 : t1  %r2 : t2  t2 <: t1                 =>  op %r1, %r2, %r3 : t1
 *  %r1 : t1  %r2 : uint64_t | sym  uint64_t <: t1 => op ... : t1 | sym
 * "Bigger" is typeCompare(): bottom < everything, int < struct/union/
 * string/forward (and pointers to them), enums and ints compare as the
 * first operand.
 */
namespace {
DFGNode *
arith(Unit &u, uint8_t op, DFGNode *a, DFGNode *b)
{
	DFGNode *n = u.node(DIF_INSTR_FMT(op, 1, 2, 3));
	Unit::uses(n, { a }, { b });
	return (n);
}
} // namespace

namespace {
/*
 * Integer arithmetic as D types it (dt_type_promote(), not C): no integer
 * promotions; the operand of the higher rank (bits, plus one if unsigned)
 * is the result's type; a shift has its left operand's type.  Oracle: the
 * rank computed here from libctf's encodings, and the compiler itself
 * (the compiled expression's return size).
 */
uint_t
d_rank(Typefile *tf, ctf_id_t id)
{
	ctf_encoding_t e;
	ctf_file_t *fp = tf->getCtfPointer();
	CHECK(ctf_type_encoding(fp, ctf_type_resolve(fp, id), &e) == 0);
	return (e.cte_bits + ((e.cte_format & CTF_INT_SIGNED) == 0));
}

void
arith_d(const char *ta, const char *tb, std::vector<std::string> &bad)
{
	static const uint8_t ops[] = { DIF_OP_OR, DIF_OP_XOR, DIF_OP_AND,
		DIF_OP_SLL, DIF_OP_SRL, DIF_OP_SRA, DIF_OP_ADD, DIF_OP_SUB,
		DIF_OP_MUL, DIF_OP_SDIV, DIF_OP_UDIV, DIF_OP_SREM, DIF_OP_UREM };
	uint_t ra = 0, rb = 0;
	for (uint8_t op : ops) {
		bool shift = op == DIF_OP_SLL || op == DIF_OP_SRL ||
		    op == DIF_OP_SRA;
		/* (Each Unit reopens the type files: look them up after.) */
		Unit u;
		Typefile *d = TF("D");
		ra = d_rank(d, ID(d, ta));
		rb = d_rank(d, ID(d, tb));
		const char *want = shift || ra >= rb ? ta : tb;
		DFGNode *a = u.ctf("D", ta);
		DFGNode *b = u.ctf("D", tb);
		DFGNode *n = arith(u, op, a, b);
		int t = u.infer(n);
		std::string got = t == DIF_TYPE_CTF ? u.tname(n) : "?";
		if (got != want && !(ra == rb && !shift && got == tb))
			bad.push_back(std::string(ta) + " op" + std::to_string(op) +
			    " " + tb + ": " + got + ", D " + want);
	}
	/* The compiler agrees (the size of the expression it compiles). */
	char src[160];
	snprintf(src, sizeof(src), "BEGIN { trace((%s)arg0 + (%s)arg1); }",
	    ta, tb);
	dtrace_prog_t *p = compile(src, 0);
	uint32_t size = first_action_difo(p)->dtdo_rtype.dtdt_size;
	Unit u;
	Typefile *d = TF("D");
	uint32_t want = (uint32_t)(ra >= rb ? ctf_type_size(d->getCtfPointer(),
	    ID(d, ta)) : ctf_type_size(d->getCtfPointer(), ID(d, tb)));
	if (size != want)
		bad.push_back(std::string(src) + ": compiler size " +
		    std::to_string(size) + ", rank rule " + std::to_string(want));
}
} // namespace

CASE("arith-int-int-d-ranks")
{
	std::vector<std::string> bad;
	static const char *types[][2] = {
		{ "int8_t", "int8_t" }, { "int16_t", "uint8_t" },
		{ "uint16_t", "int" }, { "int", "unsigned int" },
		{ "unsigned int", "int" }, { "uint32_t", "int64_t" },
		{ "int64_t", "uint32_t" }, { "int64_t", "uint64_t" },
		{ "uint64_t", "int8_t" }, { "long", "unsigned long" },
		{ "unsigned char", "short" }, { "char", "char" },
	};
	for (auto &t : types)
		arith_d(t[0], t[1], bad);
	for (auto &b : bad)
		printf("  %s\n", b.c_str());
	fflush(stdout);
	CHECK(bad.empty());
}

CASE("arith-int-and-constant")
{
	/* An integer constant has the compiler's type for its value (int,
	 * long or unsigned long), and the result is the operand of the higher
	 * rank (D, dt_type_promote(): no promotion); the other operand's
	 * value is kept. */
	struct {
		const char *t;
		uint64_t c;
		const char *want;
	} rows[] = {
		{ "int16_t", 5, "int" },
		{ "uint8_t", 0x7fffffff, "int" },
		{ "int16_t", 0x80000000ULL, "long" },
		{ "uint32_t", 5, "uint32_t" },
		{ "int32_t", 0x8000000000000000ULL, "unsigned long" },
		{ "uint64_t", 1, "uint64_t" },
	};
	for (auto &r : rows) {
		Unit u;
		DFGNode *a = u.ctf("D", r.t);
		DFGNode *b = u.node(DIF_INSTR_SETX(u.integer(r.c), 2));
		DFGNode *n = arith(u, DIF_OP_ADD, a, b);
		expect_type(u, n, DIF_TYPE_CTF, r.want);
		CHECK(n->integer.value() == r.c);
	}
	/* %r0 (no type) as an operand: the other operand's type. */
	Unit u;
	DFGNode *a = u.ctf("D", "int16_t");
	DFGNode *n = arith(u, DIF_OP_SUB, u.r0(), a);
	expect_type(u, n, DIF_TYPE_CTF, "int16_t");
}

CASE("arith-int-pointer-takes-pointer")
{
	Unit u;
	DFGNode *a = u.ctf("D", "uint64_t");
	DFGNode *b = u.ctf("kernel", "struct proc *");
	expect_type(u, arith(u, DIF_OP_ADD, a, b), DIF_TYPE_CTF, "struct proc *");
	Unit v;
	a = v.ctf("kernel", "struct proc *");
	b = v.ctf("D", "uint64_t");
	expect_type(v, arith(v, DIF_OP_SUB, a, b), DIF_TYPE_CTF, "struct proc *");
}

CASE("arith-bottom-and-int")
{
	Unit u;
	DFGNode *a = u.def(NOP, DIF_TYPE_BOTTOM);
	DFGNode *b = u.ctf("D", "uint32_t");
	expect_type(u, arith(u, DIF_OP_ADD, a, b), DIF_TYPE_CTF, "uint32_t");
	Unit v;
	a = v.ctf("D", "uint32_t");
	b = v.def(NOP, DIF_TYPE_BOTTOM);
	expect_type(v, arith(v, DIF_OP_ADD, a, b), DIF_TYPE_CTF, "uint32_t");
}

CASE("arith-class-order")
{
	/* (first, second, expected result) by typeCompare()'s classes. */
	static const struct {
		const char *m1, *t1, *m2, *t2, *want;
	} rows[] = {
		{ "typingfix", "union tf_u", "D", "int", "union tf_u" },
		{ "D", "int", "typingfix", "union tf_u", "union tf_u" },
		{ "typingfix", "struct tf_fwd", "D", "int", "struct tf_fwd" },
		{ "D", "int", "typingfix", "struct tf_fwd", "struct tf_fwd" },
		/* Enums are ints in arithmetic (C). */
		{ "typingfix", "enum tf_e", "typingfix", "enum tf_e2", "int" },
		{ "D", "int", "typingfix", "enum tf_e", "int" },
		{ "typingfix", "enum tf_e", "D", "int", "int" },
	};
	for (auto &r : rows) {
		Unit u;
		DFGNode *a = u.ctf(r.m1, r.t1);
		DFGNode *b = u.ctf(r.m2, r.t2);
		expect_type(u, arith(u, DIF_OP_SUB, a, b), DIF_TYPE_CTF, r.want);
	}
}

CASE("arith-array-and-int")
{
	/* An array's class is its element's: int[4] (struct tf_arr.arr)
	 * against long compares as int vs int, so the first operand wins. */
	Unit u;
	Typefile *tf = TF("typingfix");
	ctf_membinfo_t mi;
	CHECK(ctf_member_info(tf->getCtfPointer(), ID(tf, "struct tf_arr"),
	    "arr", &mi) == 0);
	DFGNode *a = u.def(NOP, DIF_TYPE_CTF, tf, mi.ctm_type);
	DFGNode *b = u.ctf("D", "long");
	expect_type(u, arith(u, DIF_OP_ADD, a, b), DIF_TYPE_CTF, "int [4]");
	Unit v; /* opens the type files again: look them up anew */
	tf = TF("typingfix");
	b = v.ctf("D", "long");
	a = v.def(NOP, DIF_TYPE_CTF, tf, mi.ctm_type);
	expect_type(v, arith(v, DIF_OP_ADD, b, a), DIF_TYPE_CTF, "long");
}

CASE("arith-string-and-int")
{
	Unit u;
	DFGNode *a = u.str();
	DFGNode *b = u.ctf("D", "uint64_t");
	expect_type(u, arith(u, DIF_OP_ADD, a, b), DIF_TYPE_STRING);
	Unit v;
	a = v.ctf("D", "uint64_t");
	b = v.str();
	expect_type(v, arith(v, DIF_OP_ADD, a, b), DIF_TYPE_STRING);
}

CASE("arith-incomparable")
{
	Unit u;
	DFGNode *a = u.ctf("kernel", "struct proc *");
	DFGNode *b = u.ctf("kernel", "struct thread *");
	expect_fail(u, arith(u, DIF_OP_ADD, a, b), "types can not be compared");
	Unit v;
	a = v.str();
	b = v.str();
	expect_fail(v, arith(v, DIF_OP_ADD, a, b), "types can not be compared");
}

PROGERR_CASE("arith-both-bottom", "both types are bottom")
{
	Unit u;
	DFGNode *a = u.def(NOP, DIF_TYPE_BOTTOM);
	DFGNode *b = u.def(NOP, DIF_TYPE_BOTTOM);
	u.infer(arith(u, DIF_OP_ADD, a, b));
}

PROGERR_CASE("arith-float-class-is-bottom",
    "dt_type_compare(): class1 is bottom because of float")
{
	Unit u;
	DFGNode *a = u.ctf("typingfix", "float");
	DFGNode *b = u.ctf("D", "int");
	u.infer(arith(u, DIF_OP_ADD, a, b));
}

PROGERR_CASE("arith-float-second-class-is-bottom",
    "dt_type_compare(): class2 is bottom because of double")
{
	Unit u;
	DFGNode *a = u.ctf("D", "int");
	DFGNode *b = u.ctf("typingfix", "double");
	u.infer(arith(u, DIF_OP_ADD, a, b));
}

CASE("arith-missing-operands")
{
	Unit u;
	DFGNode *b = u.ctf("D", "int");
	DFGNode *n = u.node(DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 3));
	Unit::uses(n, {}, { b });
	expect_fail(u, n, "dn1 is nullptr");
	Unit v;
	DFGNode *a = v.ctf("D", "int");
	n = v.node(DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 3));
	Unit::uses(n, { a });
	expect_fail(v, n, "dn2 is nullptr");
}

/* struct + constant: the member at that byte offset (getMipByOffset). */
CASE("add-struct-constant-selects-member")
{
	/* struct tf_pair { int a; long b; }: byte 8 is b, byte 0 is a. */
	Unit u;
	DFGNode *a = u.ctf("typingfix", "struct tf_pair");
	DFGNode *b = u.node(DIF_INSTR_SETX(u.integer(8), 2));
	DFGNode *n = arith(u, DIF_OP_ADD, a, b);
	expect_type(u, n, DIF_TYPE_CTF, "long");
	CHECK(n->mip == nullptr && n->sym == nullptr);
	Unit v;
	a = v.ctf("typingfix", "struct tf_pair");
	b = v.node(DIF_INSTR_SETX(v.integer(0), 2));
	expect_type(v, arith(v, DIF_OP_ADD, a, b), DIF_TYPE_CTF, "int");
	/* A union's members all start at 0: the first one is chosen. */
	Unit w;
	a = w.ctf("typingfix", "union tf_u");
	b = w.node(DIF_INSTR_SETX(w.integer(0), 2));
	expect_type(w, arith(w, DIF_OP_ADD, b, a), DIF_TYPE_CTF, "int");
}

CASE("add-struct-constant-between-members")
{
	/* Byte 4 is padding in struct tf_pair: the struct type is kept. */
	Unit u;
	DFGNode *a = u.ctf("typingfix", "struct tf_pair");
	DFGNode *b = u.node(DIF_INSTR_SETX(u.integer(4), 2));
	DFGNode *n = arith(u, DIF_OP_ADD, a, b);
	expect_type(u, n, DIF_TYPE_CTF, "struct tf_pair");
	CHECK(n->integer.value() == 4);
}

CASE("sub-struct-constant-is-not-a-member")
{
	/* Only an addition selects a member. */
	Unit u;
	DFGNode *a = u.ctf("typingfix", "struct tf_pair");
	DFGNode *b = u.node(DIF_INSTR_SETX(u.integer(8), 2));
	expect_type(u, arith(u, DIF_OP_SUB, a, b), DIF_TYPE_CTF,
	    "struct tf_pair");
}

CASE("add-struct-member-lookup-allocation-failure")
{
	/* Without memory for the member information the structure type is
	 * kept, as for an offset without a member. */
	Unit u;
	DFGNode *a = u.ctf("typingfix", "struct tf_pair");
	DFGNode *b = u.node(DIF_INSTR_SETX(u.integer(8), 2));
	DFGNode *n = arith(u, DIF_OP_ADD, a, b);
	CHECK(u.infer(a) == DIF_TYPE_CTF && u.infer(b) == DIF_TYPE_CTF);
	ctf_membinfo_t *mip;
	fail_malloc_after(1);
	mip = u.ti.getMipByOffset(TF("typingfix"), a->ctfid, 8);
	fail_malloc_after(0);
	CHECK(mip == nullptr);
	expect_type(u, n, DIF_TYPE_CTF, "long");
}

/* Symbolic operands. */
CASE("add-pointer-and-usetx")
{
	Unit u;
	DFGNode *base = u.ctf("kernel", "struct thread *");
	DFGNode *off = u.node(DIF_INSTR_USETX(u.sym("td_proc"), 2));
	DFGNode *n = arith(u, DIF_OP_ADD, base, off);
	expect_type(u, n, DIF_TYPE_CTF, "struct thread *");
	CHECK(n->sym != nullptr && strcmp(n->sym, "td_proc") == 0);
	/* Operand order does not matter. */
	Unit v;
	off = v.node(DIF_INSTR_USETX(v.sym("td_proc"), 1));
	base = v.ctf("kernel", "struct thread *");
	n = arith(v, DIF_OP_ADD, off, base);
	expect_type(v, n, DIF_TYPE_CTF, "struct thread *");
	CHECK(strcmp(n->sym, "td_proc") == 0);
}

CASE("add-symbolic-struct-and-uint64")
{
	/* symnode : t | sym bigger than other: other must be uint64_t, and
	 * the result is uint64_t | sym. */
	Unit u;
	DFGNode *s = u.ctf("kernel", "struct thread *", "td_proc",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	DFGNode *o = u.ctf("D", "uint64_t");
	DFGNode *n = arith(u, DIF_OP_SLL, s, o);
	expect_type(u, n, DIF_TYPE_CTF, "uint64_t");
	CHECK(strcmp(n->sym, "td_proc") == 0);
}

PROGERR_CASE("add-symbolic-struct-and-non-uint64",
    "the type of the other node must be uint64_t")
{
	Unit u;
	DFGNode *s = u.ctf("kernel", "struct thread *", "td_proc",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	DFGNode *o = u.ctf("D", "int32_t");
	u.infer(arith(u, DIF_OP_ADD, s, o));
}

CASE("add-usetx-to-symbolic-pointer-selects-member")
{
	/* other : t | sym (a member address) plus a usetx: the result is the
	 * member's type, with the usetx symbol, and no member information:
	 * the linker resolves the usetx's own member from the symbol in that
	 * type.  (The member information of `other' made the linker relocate
	 * the usetx to the enclosing member's offset: an embedded member such
	 * as tcp.d's p->t_inpcb.inp_inc read the wrong bytes.) */
	Unit u;
	DFGNode *other = u.ctf("kernel", "struct thread *", "td_proc",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	DFGNode *off = u.node(DIF_INSTR_USETX(u.sym("td_tid"), 2));
	DFGNode *n = arith(u, DIF_OP_ADD, other, off);
	std::string want = kmember("struct thread", "td_proc");
	expect_type(u, n, DIF_TYPE_CTF, want.c_str());
	CHECK(n->mip == nullptr && strcmp(n->sym, "td_tid") == 0);
	Unit v;
	off = v.node(DIF_INSTR_USETX(v.sym("td_tid"), 1));
	other = v.ctf("kernel", "struct thread *", "td_proc",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 2));
	expect_type(v, arith(v, DIF_OP_ADD, off, other), DIF_TYPE_CTF,
	    want.c_str());
}

CASE("add-two-usetx")
{
	/* Both operands are bare symbolic integers: no structure to select
	 * a member of. */
	Unit u;
	DFGNode *a = u.node(DIF_INSTR_USETX(u.sym("td_proc"), 1));
	DFGNode *b = u.node(DIF_INSTR_USETX(u.sym("td_tid"), 2));
	expect_fail(u, arith(u, DIF_OP_ADD, a, b),
	    "member td_tid of uint64_t, which is not a structure");
}

CASE("add-two-symbolic-without-usetx")
{
	Unit u;
	DFGNode *a = u.ctf("kernel", "struct thread *", "td_proc",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	DFGNode *b = u.ctf("kernel", "struct thread *", "td_tid",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 2));
	expect_fail(u, arith(u, DIF_OP_ADD, a, b),
	    "two symbolic operands and neither is a usetx");
}

PROGERR_CASE("add-usetx-to-unknown-member", "failed to get member info for "
    "struct thread *(no_such)")
{
	Unit u;
	DFGNode *other = u.ctf("kernel", "struct thread *", "no_such",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	DFGNode *off = u.node(DIF_INSTR_USETX(u.sym("td_tid"), 2));
	u.infer(arith(u, DIF_OP_ADD, other, off));
}

PROGERR_CASE("add-usetx-bottom-operand", "unexpected bottom type")
{
	Unit u;
	DFGNode *a = u.def(NOP, DIF_TYPE_BOTTOM);
	DFGNode *b = u.node(DIF_INSTR_USETX(u.sym("td_tid"), 2));
	u.infer(arith(u, DIF_OP_ADD, a, b));
}

CASE("add-usetx-incomparable")
{
	Unit u;
	DFGNode *s = u.ctf("kernel", "struct thread *", "td_proc",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	DFGNode *o = u.ctf("kernel", "struct proc *");
	expect_fail(u, arith(u, DIF_OP_ADD, s, o), "types can not be compared");
}

CASE("add-usetx-to-string")
{
	Unit u;
	DFGNode *s = u.node(DIF_INSTR_USETX(u.sym("td_tid"), 1));
	DFGNode *o = u.str();
	expect_fail(u, arith(u, DIF_OP_ADD, s, o),
	    "symbolic offset td_tid applied to a non-CTF value");
}

PROGERR_CASE("add-usetx-member-allocation-failure", "failed to malloc mip")
{
	Unit u;
	DFGNode *other = u.ctf("kernel", "struct thread *", "td_proc",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	DFGNode *off = u.node(DIF_INSTR_USETX(u.sym("td_tid"), 2));
	DFGNode *n = arith(u, DIF_OP_ADD, other, off);
	int i = find_failing_alloc([&] { u.infer(n); },
	    "failed to malloc mip");
	CHECK(i > 0);
	fail_malloc_after(i);
	u.infer(n);
}

/* ---- LDGA:  var : t[]   %r2 : int  =>  ldga var, %r2, %r1 : t ---------- */
CASE("ldga-args-in-error-probe")
{
	/* The ERROR probe's arguments (dtrace.c): arg1 epid, arg2 action
	 * index, arg3 DIF offset, arg4 fault, arg5 fault value. */
	static const char *want[] = { "", "uint32_t", "uint32_t", "int",
		"uint32_t", "uintptr_t" };
	for (int i = 1; i <= 5; i++) {
		Unit u;
		strlcpy(u.edp.dted_probe.dtpd_name, "ERROR",
		    sizeof(u.edp.dted_probe.dtpd_name));
		DFGNode *idx = u.node(DIF_INSTR_SETX(u.integer(i), 2));
		CHECK(u.infer(idx) == DIF_TYPE_CTF);
		DFGNode *n = u.node(DIF_INSTR_LDA(DIF_OP_LDGA, DIF_VAR_ARGS, 2, 3));
		Unit::uses(n, {}, { idx });
		expect_type(u, n, DIF_TYPE_CTF, want[i]);
		CHECK(n->tf == dt_typefile_kernel());
	}
}

PROGERR_CASE("ldga-error-probe-arg0",
    "accessing arg0 in the ERROR probe is not supported")
{
	Unit u;
	strlcpy(u.edp.dted_probe.dtpd_name, "ERROR",
	    sizeof(u.edp.dted_probe.dtpd_name));
	DFGNode *idx = u.node(DIF_INSTR_SETX(u.integer(0), 2));
	u.infer(idx);
	DFGNode *n = u.node(DIF_INSTR_LDA(DIF_OP_LDGA, DIF_VAR_ARGS, 2, 3));
	Unit::uses(n, {}, { idx });
	u.infer(n);
}

PROGERR_CASE("ldga-error-probe-arg6",
    "accessing arg6 in the ERROR probe is not supported")
{
	Unit u;
	strlcpy(u.edp.dted_probe.dtpd_name, "ERROR",
	    sizeof(u.edp.dted_probe.dtpd_name));
	DFGNode *idx = u.node(DIF_INSTR_SETX(u.integer(6), 2));
	u.infer(idx);
	DFGNode *n = u.node(DIF_INSTR_LDA(DIF_OP_LDGA, DIF_VAR_ARGS, 2, 3));
	Unit::uses(n, {}, { idx });
	u.infer(n);
}

PROGERR_CASE("ldga-args-in-dtrace-provider",
    "accessing arg1 in BEGIN probe is not supported")
{
	Unit u;
	DFGNode *idx = u.node(DIF_INSTR_SETX(u.integer(1), 2));
	u.infer(idx);
	DFGNode *n = u.node(DIF_INSTR_LDA(DIF_OP_LDGA, DIF_VAR_ARGS, 2, 3));
	Unit::uses(n, {}, { idx });
	u.infer(n);
}

CASE("ldga-args-only-returned-is-uint64")
{
	/* args[i] that is only returned or cast needs no probe argument type:
	 * it is a 64-bit value. */
	Unit u;
	strlcpy(u.edp.dted_probe.dtpd_provider, "fbt",
	    sizeof(u.edp.dted_probe.dtpd_provider));
	DFGNode *idx = u.node(DIF_INSTR_SETX(u.integer(1), 2));
	u.infer(idx);
	DFGNode *n = u.node(DIF_INSTR_LDA(DIF_OP_LDGA, DIF_VAR_ARGS, 2, 3));
	Unit::uses(n, {}, { idx });
	DFGNode *ret = u.node(DIF_INSTR_RET(3));
	Unit::uses(ret, { n });
	DFGNode *cast = u.node(DIF_INSTR_TYPECAST(u.sym("int"), 3));
	Unit::uses(cast, {}, { n });
	expect_type(u, n, DIF_TYPE_CTF, "uint64_t");
}

PROGERR_CASE("ldga-not-builtin", "5 is not a built-in variable")
{
	Unit u;
	DFGNode *idx = u.node(DIF_INSTR_SETX(u.integer(1), 2));
	u.infer(idx);
	DFGNode *n = u.node(DIF_INSTR_LDA(DIF_OP_LDGA, 1280 & 0xff, 2, 3));
	/* The variable field of LDGA is 8 bits wide (R1); use a value that
	 * is outside the builtin range. */
	u.buf[n->uidx] = DIF_INSTR_LDA(DIF_OP_LDGA, 5, 2, 3);
	Unit::uses(n, {}, { idx });
	u.infer(n);
}

PROGERR_CASE("ldga-index-not-setx", "is not assigned by a SETX instruction")
{
	Unit u;
	DFGNode *idx = u.ctf("D", "int", nullptr, DIF_INSTR_MOV(1, 2));
	DFGNode *n = u.node(DIF_INSTR_LDA(DIF_OP_LDGA, DIF_VAR_ARGS, 2, 3));
	Unit::uses(n, {}, { idx });
	u.infer(n);
}

CASE("ldga-no-index")
{
	Unit u;
	DFGNode *n = u.node(DIF_INSTR_LDA(DIF_OP_LDGA, DIF_VAR_ARGS, 2, 3));
	expect_fail(u, n, "the index register has no definition");
}

CASE("ldga-index-out-of-range")
{
	Unit u;
	DFGNode *idx = u.node(DIF_INSTR_SETX(u.integer(300), 2));
	u.infer(idx);
	DFGNode *n = u.node(DIF_INSTR_LDA(DIF_OP_LDGA, DIF_VAR_ARGS, 2, 3));
	Unit::uses(n, {}, { idx });
	expect_fail(u, n, "argument index 300 is out of range");
}

/* ---- Variable loads:  var : t  =>  ld*s var, %r1 : t ------------------ */
CASE("ldls-variable-type")
{
	Unit u;
	Typefile *k = dt_typefile_kernel();
	u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, DIF_TYPE_CTF, k,
	    ID(k, "struct proc *"));
	DFGNode *n = u.node(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 1));
	expect_type(u, n, DIF_TYPE_CTF, "struct proc *");
}

CASE("ldls-after-store-in-difo")
{
	/* With a definition in this DIFO, its type (which must agree with the
	 * variable's) is used. */
	Unit u;
	Typefile *k = dt_typefile_kernel();
	ctf_id_t p = ID(k, "struct proc *");
	u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, DIF_TYPE_CTF, k, p);
	DFGNode *st = u.def(DIF_INSTR_STV(DIF_OP_STLS, 1280, 1), DIF_TYPE_CTF, k,
	    p);
	DFGNode *n = u.node(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 2));
	n->varDefs.insert(st);
	expect_type(u, n, DIF_TYPE_CTF, "struct proc *");
}

CASE("ldls-store-symbol-checks")
{
	Typefile *k;
	ctf_id_t p;
	/* Symbols must agree between the store and the variable. */
	{
		Unit u;
		k = dt_typefile_kernel();
		p = ID(k, "struct proc *");
		u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, DIF_TYPE_CTF, k,
		    p, "p_pid");
		DFGNode *st = u.def(DIF_INSTR_STV(DIF_OP_STLS, 1280, 1),
		    DIF_TYPE_CTF, k, p, "p_pid");
		DFGNode *n = u.node(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 2));
		n->varDefs.insert(st);
		expect_type(u, n, DIF_TYPE_CTF, "struct proc *");
		CHECK(strcmp(n->sym, "p_pid") == 0);
	}
	{
		Unit u;
		k = dt_typefile_kernel();
		p = ID(k, "struct proc *");
		u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, DIF_TYPE_CTF, k,
		    p);
		DFGNode *st = u.def(DIF_INSTR_STV(DIF_OP_STLS, 1280, 1),
		    DIF_TYPE_CTF, k, p, "p_pid");
		DFGNode *n = u.node(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 2));
		n->varDefs.insert(st);
		expect_fail(u, n, "struct proc * | p_pid, struct proc *");
	}
}

PROGERR_CASE("ldls-missing-variable", "failed to find variable (1290, 2, 1)")
{
	Unit u;
	u.infer(u.node(DIF_INSTR_LDV(DIF_OP_LDLS, 1290, 1)));
}

CASE("ldgs-builtin-and-global")
{
	Unit u;
	u.var(1300, DIFV_SCOPE_GLOBAL, DIFV_KIND_SCALAR, DIF_TYPE_STRING);
	DFGNode *b = u.node(DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_PID, 1));
	DFGNode *g = u.node(DIF_INSTR_LDV(DIF_OP_LDGS, 1300, 2));
	expect_type(u, b, DIF_TYPE_CTF, "pid_t");
	expect_type(u, g, DIF_TYPE_STRING);
}

CASE("ldgs-unknown-global")
{
	Unit u;
	DFGNode *g = u.node(DIF_INSTR_LDV(DIF_OP_LDGS, 1300, 2));
	expect_fail(u, g, "variable 1300 and dn1 don't exist");
}

CASE("ldts-thread-variable")
{
	Unit u;
	Typefile *k = dt_typefile_kernel();
	u.var(1290, DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR, DIF_TYPE_CTF, k,
	    ID(k, "struct thread *"));
	DFGNode *n = u.node(DIF_INSTR_LDV(DIF_OP_LDTS, 1290, 1));
	expect_type(u, n, DIF_TYPE_CTF, "struct thread *");
}

PROGERR_CASE("ldts-missing-variable", "failed to find variable (1290, 1, 1)")
{
	Unit u;
	u.infer(u.node(DIF_INSTR_LDV(DIF_OP_LDTS, 1290, 1)));
}

/* ---- Variable stores ------------------------------------------------ */
CASE("stgs-stores-type-into-variable")
{
	Unit u;
	dtrace_difv_t *v = u.var(1300, DIFV_SCOPE_GLOBAL, DIFV_KIND_SCALAR);
	DFGNode *src = u.ctf("kernel", "struct proc *");
	DFGNode *n = u.node(DIF_INSTR_STV(DIF_OP_STGS, 1300, 1));
	Unit::uses(n, {}, { src });
	expect_type(u, n, DIF_TYPE_CTF, "struct proc *");
	CHECK(v->dtdv_type.dtdt_kind == DIF_TYPE_CTF);
	CHECK(v->dtdv_ctfid == src->ctfid && v->dtdv_type.dtdt_size == 8);
}

CASE("stgs-to-builtin")
{
	Unit u;
	DFGNode *src = u.ctf("D", "int");
	DFGNode *n = u.node(DIF_INSTR_STV(DIF_OP_STGS, DIF_VAR_PID, 1));
	Unit::uses(n, {}, { src });
	expect_fail(u, n, "trying to store to a builtin variable");
}

CASE("st-without-source")
{
	static const uint8_t ops[] = { DIF_OP_STGS, DIF_OP_STTS, DIF_OP_STLS };
	static const char *names[] = { "stgs", "stts", "stls" };
	for (int i = 0; i < 3; i++) {
		Unit u;
		DFGNode *n = u.node(DIF_INSTR_STV(ops[i], 1290, 1));
		std::string want = std::string("dn2 is nullptr in ") + names[i];
		expect_fail(u, n, want.c_str());
	}
}

PROGERR_CASE("stgs-missing-variable", "failed to find variable (1300, 0, 1)")
{
	Unit u;
	DFGNode *src = u.ctf("D", "int");
	DFGNode *n = u.node(DIF_INSTR_STV(DIF_OP_STGS, 1300, 1));
	Unit::uses(n, {}, { src });
	u.infer(n);
}

PROGERR_CASE("stts-missing-variable", "failed to find variable (1290, 1, 1)")
{
	Unit u;
	DFGNode *src = u.ctf("D", "int");
	DFGNode *n = u.node(DIF_INSTR_STV(DIF_OP_STTS, 1290, 1));
	Unit::uses(n, {}, { src });
	u.infer(n);
}

PROGERR_CASE("stls-missing-variable", "failed to find variable (1280, 2, 1)")
{
	Unit u;
	DFGNode *src = u.ctf("D", "int");
	DFGNode *n = u.node(DIF_INSTR_STV(DIF_OP_STLS, 1280, 1));
	Unit::uses(n, {}, { src });
	u.infer(n);
}

CASE("st-type-mismatch")
{
	/* A variable already typed as a string cannot store a pointer. */
	static const struct {
		uint8_t op, scope;
		uint_t id;
	} st[] = { { DIF_OP_STGS, DIFV_SCOPE_GLOBAL, 1300 },
		{ DIF_OP_STTS, DIFV_SCOPE_THREAD, 1290 },
		{ DIF_OP_STLS, DIFV_SCOPE_LOCAL, 1280 } };
	for (auto &s : st) {
		Unit u;
		u.var(s.id, s.scope, DIFV_KIND_SCALAR, DIF_TYPE_STRING);
		DFGNode *src = u.ctf("kernel", "struct proc *");
		DFGNode *n = u.node(DIF_INSTR_STV(s.op, s.id, 1));
		Unit::uses(n, {}, { src });
		expect_fail(u, n, "dif_var and dr have different types");
	}
}

CASE("stts-stls-store-types")
{
	Unit u;
	dtrace_difv_t *t = u.var(1290, DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR);
	dtrace_difv_t *l = u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);
	DFGNode *src = u.ctf("D", "uint16_t");
	DFGNode *a = u.node(DIF_INSTR_STV(DIF_OP_STTS, 1290, 1));
	DFGNode *b = u.node(DIF_INSTR_STV(DIF_OP_STLS, 1280, 1));
	Unit::uses(a, {}, { src });
	Unit::uses(b, {}, { src });
	expect_type(u, a, DIF_TYPE_CTF, "uint16_t");
	expect_type(u, b, DIF_TYPE_CTF, "uint16_t");
	CHECK(t->dtdv_type.dtdt_size == 2 && l->dtdv_type.dtdt_size == 2);
}

/* ---- Instructions without a value type ------------------------------ */
CASE("no-value-instructions")
{
	static const dif_instr_t ins[] = { DIF_INSTR_FLUSHTS, DIF_INSTR_POPTS,
		DIF_INSTR_CMP(DIF_OP_CMP, 1, 2), DIF_INSTR_CMP(DIF_OP_SCMP, 1, 2),
		(dif_instr_t)DIF_OP_HYPERCALL << 24, DIF_INSTR_TST(1),
		DIF_INSTR_BRANCH(DIF_OP_BA, 3), DIF_INSTR_BRANCH(DIF_OP_BE, 3),
		DIF_INSTR_BRANCH(DIF_OP_BNE, 3), DIF_INSTR_BRANCH(DIF_OP_BG, 3),
		DIF_INSTR_BRANCH(DIF_OP_BGU, 3), DIF_INSTR_BRANCH(DIF_OP_BGE, 3),
		DIF_INSTR_BRANCH(DIF_OP_BGEU, 3), DIF_INSTR_BRANCH(DIF_OP_BL, 3),
		DIF_INSTR_BRANCH(DIF_OP_BLU, 3), DIF_INSTR_BRANCH(DIF_OP_BLE, 3),
		DIF_INSTR_BRANCH(DIF_OP_BLEU, 3), DIF_INSTR_NOP };
	for (dif_instr_t i : ins) {
		Unit u;
		CHECK(u.infer(u.node(i)) == DIF_TYPE_NONE);
	}
}

CASE("ldta-is-untyped")
{
	/* Thread-local arrays by register (ldta) are not generated by the D
	 * compiler; the type checker rejects them. */
	Unit u;
	DFGNode *n = u.node(DIF_INSTR_LDA(DIF_OP_LDTA, 3, 2, 1));
	CHECK(u.infer(n) == -1);
}

PROGERR_CASE("invalid-opcode-is-unhandled", "unhandled instruction: 238")
{
	/* Every DIF opcode has a rule (XLATE and XLARG included); an
	 * invalid one is a program error. */
	Unit u;
	u.infer(u.node((dif_instr_t)0xee << 24));
}

/* ---- XLATE, XLARG (dynamic translators) ------------------------------
 *
 *  xlmtab(idx) = m   m : t
 * --------------------------------------------------------
 *  xlate idx, %r1 => %r1 : t      xlarg idx, %r1 => %r1 : t
 */
namespace {
struct XlUnit : Unit {
	dt_node_t member;
	dt_node_t *table[1];
	/* The member's type: (type file, type name) looked up once the type
	 * files are open, or a raw (container, id). */
	XlUnit(const char *tfname, const char *type, const char *name = "m")
	    : Unit()
	{
		init(TF(tfname)->getCtfPointer(), ID(TF(tfname), type), name);
	}
	XlUnit(ctf_file_t *fp, ctf_id_t type, const char *name = "m")
	    : Unit()
	{
		init(fp, type, name);
	}
	void
	init(ctf_file_t *fp, ctf_id_t type, const char *name)
	{
		memset(&member, 0, sizeof(member));
		member.dn_kind = DT_NODE_MEMBER;
		member.dn_ctfp = fp;
		member.dn_type = type;
		member.dn_membname = (char *)name;
		table[0] = &member;
		difo.dtdo_xlmtab = table;
		difo.dtdo_xlmlen = 1;
	}
};
} // namespace

CASE("xlarg-has-member-type")
{
	/* xlarg: the member's type, from D's container when it has it. */
	XlUnit u("D", "int");
	DFGNode *n = u.node(DIF_INSTR_XLATE(DIF_OP_XLARG, 0, 1));
	expect_type(u, n, DIF_TYPE_CTF, "int");
}

CASE("xlate-translates-its-input")
{
	XlUnit u("D", "uint64_t");
	DFGNode *in = u.ctf("D", "int");
	DFGNode *n = u.node(DIF_INSTR_XLATE(DIF_OP_XLATE, 0, 1));
	Unit::uses(n, { in });
	expect_type(u, n, DIF_TYPE_CTF, "uint64_t");
}

CASE("xlate-string-member")
{
	XlUnit u(nullptr, CTF_ERR);
	u.member.dn_ctfp = DT_STR_CTFP(u.dtp);
	u.member.dn_type = DT_STR_TYPE(u.dtp);
	DFGNode *n = u.node(DIF_INSTR_XLATE(DIF_OP_XLARG, 0, 1));
	CHECK(u.infer(n) == DIF_TYPE_STRING);
}

CASE("xlate-kernel-member-type")
{
	/* A type only a module has is resolved like a typecast's. */
	XlUnit u("typingfix", "struct tf_pair *");
	DFGNode *n = u.node(DIF_INSTR_XLATE(DIF_OP_XLARG, 0, 1));
	CHECK(u.infer(n) == DIF_TYPE_CTF);
	CHECK(u.tname(n) == "struct tf_pair *");
}

PROGERR_CASE("xlate-member-type-unknown", "failed to get translator member "
    "type struct xl_nowhere")
{
	/* A member type no container knows. */
	ctf_file_t *fp = ctf_create(nullptr);
	ctf_id_t id = ctf_add_struct(fp, CTF_ADD_ROOT, "xl_nowhere");
	CHECK(id != CTF_ERR && ctf_update(fp) == 0);
	XlUnit u(fp, id);
	u.infer(u.node(DIF_INSTR_XLATE(DIF_OP_XLARG, 0, 1)));
}

PROGERR_CASE("xlate-member-unnamed", "translator member m has no type name")
{
	XlUnit u("D", "int");
	u.member.dn_type = 0x7ffffff;
	u.infer(u.node(DIF_INSTR_XLATE(DIF_OP_XLARG, 0, 1)));
}

PROGERR_CASE("xlate-input-undefined", "the translator's input is not defined")
{
	XlUnit u("D", "int");
	u.infer(u.node(DIF_INSTR_XLATE(DIF_OP_XLATE, 0, 1)));
}

PROGERR_CASE("xlate-past-the-table", "translator member 1 is not in the "
    "1-entry translator table")
{
	XlUnit u("D", "int");
	u.infer(u.node(DIF_INSTR_XLATE(DIF_OP_XLARG, 1, 1)));
}

PROGERR_CASE("xlate-without-a-table", "translator member 0 is not in the "
    "0-entry translator table")
{
	Unit u;
	u.infer(u.node(DIF_INSTR_XLATE(DIF_OP_XLARG, 0, 1)));
}

PROGERR_CASE("xlate-null-table-entry", "translator member 0 is not in the "
    "1-entry translator table")
{
	XlUnit u("D", "int");
	u.table[0] = nullptr;
	u.infer(u.node(DIF_INSTR_XLATE(DIF_OP_XLARG, 0, 1)));
}

CASE("xlate-member-name-allocation-failure-throws")
{
	XlUnit u("typingfix", "struct tf_pair *");
	DFGNode *n = u.node(DIF_INSTR_XLATE(DIF_OP_XLARG, 0, 1));
	bool thrown = false;
	fail_malloc_after(1);
	try {
		u.infer(n);
	} catch (const std::bad_alloc &) {
		thrown = true;
	}
	fail_malloc_after(0);
	CHECK(thrown);
}

/* ---- ALLOCS, COPYS ------------------------------------------------- */
CASE("allocs-is-bottom")
{
	Unit u;
	DFGNode *sz = u.ctf("D", "uint64_t");
	DFGNode *n = u.node(DIF_INSTR_ALLOCS(1, 2));
	Unit::uses(n, { sz });
	CHECK(u.infer(n) == DIF_TYPE_BOTTOM);
	CHECK(n->tf == nullptr && n->ctfid == CTF_ERR);
}

CASE("copys-copies-source")
{
	Unit u;
	DFGNode *src = u.ctf("kernel", "struct proc *");
	DFGNode *n = u.node(DIF_INSTR_COPYS(1, 2, 3));
	Unit::uses(n, { src });
	expect_type(u, n, DIF_TYPE_CTF, "struct proc *");
	Unit v;
	n = v.node(DIF_INSTR_COPYS(1, 2, 3));
	expect_fail(v, n, "the source register has no definition");
}

/* ---- RET:  %r1 : t => ret : t; ret of t | sym : type_at(t, sym) ------- */
CASE("ret-plain-and-symbolic")
{
	Unit u;
	DFGNode *src = u.ctf("kernel", "struct proc *");
	DFGNode *n = u.node(DIF_INSTR_RET(1));
	Unit::uses(n, { src });
	expect_type(u, n, DIF_TYPE_CTF, "struct proc *");
	Unit v;
	src = v.ctf("kernel", "struct proc *", "p_pid",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	n = v.node(DIF_INSTR_RET(1));
	Unit::uses(n, { src });
	std::string want = kmember("struct proc", "p_pid");
	expect_type(v, n, DIF_TYPE_CTF, want.c_str());
	CHECK(n->mip != nullptr);
	Unit w;
	src = w.str();
	n = w.node(DIF_INSTR_RET(1));
	Unit::uses(n, { src });
	expect_type(w, n, DIF_TYPE_STRING);
}

CASE("ret-of-r0-is-bottom")
{
	Unit u;
	DFGNode *n = u.node(DIF_INSTR_RET(0));
	Unit::uses(n, { u.r0() });
	CHECK(u.infer(n) == DIF_TYPE_BOTTOM);
}

PROGERR_CASE("ret-unknown-member", "failed to get mip from symbol (no_such)")
{
	Unit u;
	DFGNode *src = u.ctf("kernel", "struct proc *", "no_such",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	DFGNode *n = u.node(DIF_INSTR_RET(1));
	Unit::uses(n, { src });
	u.infer(n);
}

CASE("ret-undefined-register")
{
	Unit u;
	expect_fail(u, u.node(DIF_INSTR_RET(5)),
	    "the returned register has no definition");
}

/* ---- PUSHTR / PUSHTV: the pushed value's type, no value of their own -- */
CASE("pushtr-records-pushed-type")
{
	Unit u;
	DFGNode *src = u.ctf("kernel", "struct proc *");
	DFGNode *n = u.node(DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_CTF, 0, 1));
	Unit::uses(n, { src });
	CHECK(u.infer(n) == DIF_TYPE_NONE);
	CHECK(n->dType == DIF_TYPE_CTF && u.tname(n) == "struct proc *");
	Unit v;
	src = v.ctf("kernel", "struct proc *", "p_pid",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	n = v.node(DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_CTF, 0, 1));
	Unit::uses(n, { src });
	CHECK(v.infer(n) == DIF_TYPE_NONE);
	CHECK(v.tname(n) == kmember("struct proc", "p_pid") && n->mip);
	Unit w;
	src = w.str();
	n = w.node(DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 0, 1));
	Unit::uses(n, { src });
	CHECK(w.infer(n) == DIF_TYPE_NONE && n->dType == DIF_TYPE_STRING);
}

PROGERR_CASE("pushtr-unknown-member", "failed to get mip from symbol (no_such)")
{
	Unit u;
	DFGNode *src = u.ctf("kernel", "struct proc *", "no_such",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	DFGNode *n = u.node(DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_CTF, 0, 1));
	Unit::uses(n, { src });
	u.infer(n);
}

CASE("pushtr-pushtv-undefined")
{
	Unit u;
	expect_fail(u, u.node(DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, 0, 0, 1)),
	    "pushtr dn1 is nullptr");
	Unit v;
	expect_fail(v, v.node(DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, 0, 0, 1)),
	    "the pushed register has no definition");
}

CASE("pushtv-records-pushed-type")
{
	Unit u;
	DFGNode *src = u.ctf("D", "int");
	DFGNode *n = u.node(DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, DIF_TYPE_CTF, 0, 1));
	Unit::uses(n, { src });
	CHECK(u.infer(n) == DIF_TYPE_NONE);
	CHECK(n->dType == DIF_TYPE_CTF && u.tname(n) == "int");
}

/* ---- Stores through a pointer (STB/STH/STW/STX) --------------------
 * The value (r1) may not be a string or untyped.  Without a symbol the
 * store is typed as its address; with one, the value must come from a
 * variable of structure type that has the member, and the member must be
 * compatible with the store's width.
 */
namespace {
struct StoreUnit : Unit {
	DFGNode *dst;
	StoreUnit() : Unit()
	{
		dst = ctf("kernel", "uintptr_t", nullptr, DIF_INSTR_MOV(4, 3));
	}
	DFGNode *
	store(uint8_t op, DFGNode *value)
	{
		DFGNode *n = node(DIF_INSTR_STORE(op, 1, 3));
		uses(n, { value }, { dst });
		return (n);
	}
	/* value = ldls var (struct tf_pair) + usetx member, typed as the
	 * arithmetic rule gives it (here preset to `vt'). */
	DFGNode *
	member_value(const char *member, const char *vmod, const char *vt,
	    int vkind = DIF_TYPE_CTF)
	{
		Typefile *pf = TF("typingfix");
		var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, vkind, pf,
		    ID(pf, "struct tf_pair"));
		DFGNode *ld = def(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 1),
		    DIF_TYPE_CTF, pf, ID(pf, "struct tf_pair"));
		DFGNode *off = def(DIF_INSTR_USETX(sym(member), 2),
		    DIF_TYPE_CTF, TF("D"), ID(TF("D"), "uint64_t"), member);
		DFGNode *v = vt == nullptr ?
		    def(DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1), DIF_TYPE_BOTTOM,
			nullptr, CTF_ERR, member) :
		    ctf(vmod, vt, member, DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
		uses(v, { ld }, { off });
		return (v);
	}
};
} // namespace

CASE("store-without-symbol-is-typed-as-address")
{
	static const uint8_t ops[] = { DIF_OP_STB, DIF_OP_STH, DIF_OP_STW,
		DIF_OP_STX };
	for (uint8_t op : ops) {
		StoreUnit u;
		DFGNode *v = u.ctf("D", "int");
		expect_type(u, u.store(op, v), DIF_TYPE_CTF, "uintptr_t");
	}
}

PROGERR_CASE("store-string", "can't store from a string type")
{
	StoreUnit u;
	u.infer(u.store(DIF_OP_STX, u.str()));
}

PROGERR_CASE("store-none", "can't store from type none")
{
	StoreUnit u;
	u.infer(u.store(DIF_OP_STX, u.def(NOP, DIF_TYPE_NONE)));
}

CASE("store-member-of-struct-variable")
{
	/* uint64_t value into struct tf_pair's member b (long) with stx. */
	StoreUnit u;
	DFGNode *v = u.member_value("b", "D", "uint64_t");
	expect_type(u, u.store(DIF_OP_STX, v), DIF_TYPE_CTF, "uintptr_t");
	/* A bottom value is accepted without a width check. */
	StoreUnit w;
	v = w.member_value("a", nullptr, nullptr);
	expect_type(w, w.store(DIF_OP_STW, v), DIF_TYPE_CTF, "uintptr_t");
}

PROGERR_CASE("store-member-width-incompatible", "are not compatible")
{
	/* A struct-typed value cannot be stored with a 1-byte store. */
	StoreUnit u;
	u.infer(u.store(DIF_OP_STB, u.member_value("a", "typingfix",
	    "struct tf_pair")));
}

PROGERR_CASE("store-value-not-from-variable", "is not within a variable")
{
	StoreUnit u;
	DFGNode *v = u.ctf("D", "uint64_t", "b",
	    DIF_INSTR_USETX(0, 1));
	u.infer(u.store(DIF_OP_STX, v));
}

PROGERR_CASE("store-variable-not-ctf",
    "instruction only makes sense on CTF variable types")
{
	StoreUnit u;
	DFGNode *v = u.member_value("b", "D", "uint64_t", DIF_TYPE_STRING);
	u.infer(u.store(DIF_OP_STX, v));
}

PROGERR_CASE("store-variable-not-struct", "expected a struct CTF kind")
{
	StoreUnit u;
	Typefile *k = dt_typefile_kernel();
	u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, DIF_TYPE_CTF, k,
	    ID(k, "struct proc *"));
	DFGNode *ld = u.def(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 1), DIF_TYPE_CTF,
	    k, ID(k, "struct proc *"));
	DFGNode *v = u.ctf("D", "uint64_t", "p_pid",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	Unit::uses(v, { ld });
	u.infer(u.store(DIF_OP_STX, v));
}

PROGERR_CASE("store-unknown-member", "failed to get member info")
{
	StoreUnit u;
	u.infer(u.store(DIF_OP_STX, u.member_value("no_such", "D",
	    "uint64_t")));
}

PROGERR_CASE("store-variable-sources-disagree",
    "mismatch in variable sources with inferred variable")
{
	/* Regression: the diagnostic's arguments were out of order. */
	StoreUnit u;
	DFGNode *v = u.member_value("b", "D", "uint64_t");
	DFGNode *n = u.store(DIF_OP_STX, v);
	dtrace_difv_t *other = u.var(1281, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
	    DIF_TYPE_CTF, TF("typingfix"), ID(TF("typingfix"),
	    "struct tf_big"));
	n->varSources.push_back(other);
	u.infer(n);
}

CASE("store-variable-sources-agree")
{
	StoreUnit u;
	DFGNode *v = u.member_value("b", "D", "uint64_t");
	DFGNode *n = u.store(DIF_OP_STX, v);
	n->varSources.push_back(u.L.getVarFromVarVec(1280, DIFV_SCOPE_LOCAL,
	    DIFV_KIND_SCALAR));
	expect_type(u, n, DIF_TYPE_CTF, "uintptr_t");
}

PROGERR_CASE("store-unnamed-variable-type", "failed getting type name")
{
	StoreUnit u;
	DFGNode *v = u.member_value("b", "D", "uint64_t");
	u.L.getVarFromVarVec(1280, DIFV_SCOPE_LOCAL,
	    DIFV_KIND_SCALAR)->dtdv_ctfid = 0x7ffffff;
	u.infer(u.store(DIF_OP_STX, v));
}

PROGERR_CASE("store-unnamed-source-type", "failed getting type name")
{
	StoreUnit u;
	DFGNode *v = u.member_value("b", "D", "uint64_t");
	DFGNode *n = u.store(DIF_OP_STX, v);
	dtrace_difv_t *other = u.var(1281, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
	    DIF_TYPE_CTF, TF("typingfix"), 0x7ffffff);
	n->varSources.push_back(other);
	u.infer(n);
}

PROGERR_CASE("store-member-allocation-failure", "malloc failed on mip")
{
	StoreUnit u;
	DFGNode *v = u.member_value("b", "D", "uint64_t");
	DFGNode *n = u.store(DIF_OP_STX, v);
	int i = find_failing_alloc([&] { u.infer(n); }, "malloc failed on mip");
	CHECK(i > 0);
	fail_malloc_after(i);
	u.infer(n);
}

/* findVariableFromNodeDefs(): through add/mul to a variable load. */
CASE("find-variable-through-arithmetic")
{
	Unit u;
	Typefile *pf = TF("typingfix");
	dtrace_difv_t *v = u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
	    DIF_TYPE_CTF, pf, ID(pf, "struct tf_pair"));
	DFGNode *ld = u.def(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 1), DIF_TYPE_CTF,
	    pf, ID(pf, "struct tf_pair"));
	DFGNode *c = u.ctf("D", "uint64_t", nullptr, DIF_INSTR_SETX(0, 2));
	DFGNode *mul = u.ctf("D", "uint64_t", nullptr,
	    DIF_INSTR_FMT(DIF_OP_MUL, 2, 2, 2));
	Unit::uses(mul, { c }, { c });
	DFGNode *add = u.ctf("D", "uint64_t", nullptr,
	    DIF_INSTR_FMT(DIF_OP_ADD, 2, 1, 1));
	Unit::uses(add, { mul }, { ld });
	NodeSet defs = { add };
	CHECK(u.ti.findVariableFromNodeDefs(defs) == v);
	NodeSet none = { c };
	CHECK(u.ti.findVariableFromNodeDefs(none) == nullptr);
	NodeSet empty;
	CHECK(u.ti.findVariableFromNodeDefs(empty) == nullptr);
}

/* getMipFromSymbol() preconditions. */
CASE("mip-from-symbol-preconditions")
{
	Unit u;
	CHECK(u.ti.getMipFromSymbol(nullptr) == nullptr);
	DFGNode *n = u.ctf("kernel", "struct proc *");
	CHECK(u.ti.getMipFromSymbol(n) == nullptr); /* no symbol */
	DFGNode *s = u.ctf("kernel", "struct proc *", "p_pid");
	dtrace_difo_t *d = s->difo;
	s->difo = nullptr;
	CHECK(u.ti.getMipFromSymbol(s) == nullptr);
	s->difo = d;
	/* A symbol just below the table is outside it. */
	char *saved = s->sym;
	s->sym = u.symtab - 1;
	CHECK(u.ti.getMipFromSymbol(s) == nullptr);
	s->sym = saved;
	ctf_membinfo_t *mip = u.ti.getMipFromSymbol(s);
	CHECK(mip != nullptr);
	/* Without memory for the member information there is none. */
	int i = find_alloc_where([&] {
		return (u.ti.getMipFromSymbol(s) == nullptr);
	});
	CHECK(i > 0);
	fail_malloc_after(i);
	CHECK(u.ti.getMipFromSymbol(s) == nullptr);
	fail_malloc_after(0);
	/* A member through a pointer to a forward declaration is found in
	 * the definition (typingfix2: struct tf_fwd { int fa; long fb; }). */
	DFGNode *f = u.ctf("typingfix", "struct tf_fwd *", "fb");
	mip = u.ti.getMipFromSymbol(f);
	CHECK(mip != nullptr && mip->ctm_offset == 64);
}

/* ---- Associative arrays: ld{g,t}aa / st{g,t}aa --------------------
 * The key tuple on the stack must match the one recorded for the variable
 * at its first use (checkVarStack()); the value's type is the variable's.
 */
namespace {
DFGNode *
with_stack(Unit &u, DFGNode *n, std::initializer_list<DFGNode *> keys)
{
	Vec<BasicBlock *> path;
	n->stacks.emplace_back(path);
	for (auto k : keys)
		n->stacks.back().nodesOnStack.push_back(k);
	return (n);
}

DFGNode *
key(Unit &u, const char *type)
{
	DFGNode *k = u.ctf("D", type, nullptr,
	    DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, DIF_TYPE_CTF, 0, 1));
	return (k);
}
} // namespace

CASE("ldaa-first-use-records-key-tuple")
{
	for (uint8_t op : { DIF_OP_LDGAA, DIF_OP_LDTAA }) {
		Unit u;
		uint8_t scope = op == DIF_OP_LDGAA ? DIFV_SCOPE_GLOBAL :
		    DIFV_SCOPE_THREAD;
		dtrace_difv_t *v = u.var(1300, scope, DIFV_KIND_ARRAY,
		    DIF_TYPE_STRING);
		DFGNode *n = with_stack(u, u.node(DIF_INSTR_LDV(op, 1300, 1)),
		    { key(u, "int") });
		expect_type(u, n, DIF_TYPE_STRING);
		CHECK(v->dtdv_stack != nullptr &&
		    ((NodeVec *)v->dtdv_stack)->size() == 1);
	}
}

CASE("ldaa-after-store-in-difo")
{
	Unit u;
	Typefile *k = dt_typefile_kernel();
	ctf_id_t p = ID(k, "struct proc *");
	u.var(1300, DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY, DIF_TYPE_CTF, k, p);
	DFGNode *st = u.def(DIF_INSTR_STV(DIF_OP_STGAA, 1300, 1), DIF_TYPE_CTF,
	    k, p);
	DFGNode *n = with_stack(u, u.node(DIF_INSTR_LDV(DIF_OP_LDGAA, 1300, 1)),
	    { key(u, "int") });
	n->varDefs.insert(st);
	expect_type(u, n, DIF_TYPE_CTF, "struct proc *");
	/* The same key tuple again is accepted. */
	DFGNode *m = with_stack(u, u.node(DIF_INSTR_LDV(DIF_OP_LDGAA, 1300, 2)),
	    { key(u, "int") });
	m->varDefs.insert(st);
	expect_type(u, m, DIF_TYPE_CTF, "struct proc *");
}

CASE("ldaa-without-key-tuple")
{
	Unit u;
	u.var(1300, DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY, DIF_TYPE_STRING);
	expect_fail(u, u.node(DIF_INSTR_LDV(DIF_OP_LDGAA, 1300, 1)),
	    "stack list is empty in ldgaa");
	Unit v;
	v.var(1300, DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY, DIF_TYPE_STRING);
	expect_fail(v, v.node(DIF_INSTR_LDV(DIF_OP_LDTAA, 1300, 1)),
	    "stack list is empty in ldtaa");
}

CASE("aa-key-tuple-mismatch")
{
	/* The variable was first used with an int key; a string key (with
	 * a definition to compare) is rejected. */
	for (uint8_t op : { DIF_OP_LDGAA, DIF_OP_LDTAA }) {
		Unit u;
		uint8_t scope = op == DIF_OP_LDGAA ? DIFV_SCOPE_GLOBAL :
		    DIFV_SCOPE_THREAD;
		Typefile *d = TF("D");
		u.var(1300, scope, DIFV_KIND_ARRAY, DIF_TYPE_CTF, d,
		    ID(d, "int"));
		DFGNode *first = with_stack(u, u.node(DIF_INSTR_LDV(op, 1300, 1)),
		    { key(u, "int") });
		CHECK(u.infer(first) == DIF_TYPE_CTF);
		uint8_t st = op == DIF_OP_LDGAA ? DIF_OP_STGAA : DIF_OP_STTAA;
		DFGNode *def = u.def(DIF_INSTR_STV(st, 1300, 1), DIF_TYPE_CTF, d,
		    ID(d, "int"));
		DFGNode *n = with_stack(u, u.node(DIF_INSTR_LDV(op, 1300, 2)),
		    { u.str(DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 0,
		    1)) });
		n->varDefs.insert(def);
		expect_fail(u, n, "type mismatch in variable");
	}
}

CASE("ldaa-value-type-mismatch")
{
	for (uint8_t op : { DIF_OP_LDGAA, DIF_OP_LDTAA }) {
		Unit u;
		uint8_t scope = op == DIF_OP_LDGAA ? DIFV_SCOPE_GLOBAL :
		    DIFV_SCOPE_THREAD;
		uint8_t st = op == DIF_OP_LDGAA ? DIF_OP_STGAA : DIF_OP_STTAA;
		u.var(1300, scope, DIFV_KIND_ARRAY, DIF_TYPE_STRING);
		DFGNode *def = u.def(DIF_INSTR_STV(st, 1300, 1), DIF_TYPE_STRING);
		DFGNode *n = with_stack(u, u.node(DIF_INSTR_LDV(op, 1300, 2)),
		    { key(u, "int") });
		n->varDefs.insert(def);
		expect_type(u, n, DIF_TYPE_STRING);
		/* A later definition with another kind does not agree. */
		Unit v;
		Typefile *k = dt_typefile_kernel();
		v.var(1300, scope, DIFV_KIND_ARRAY, DIF_TYPE_STRING);
		def = v.def(DIF_INSTR_STV(st, 1300, 1), DIF_TYPE_CTF, k,
		    ID(k, "struct proc *"));
		n = with_stack(v, v.node(DIF_INSTR_LDV(op, 1300, 2)),
		    { key(v, "int") });
		n->varDefs.insert(def);
		expect_fail(v, n, "failed to vardefs stack");
	}
}

PROGERR_CASE("ldgaa-missing-variable", "failed to find variable (1300, 0, 0)")
{
	Unit u;
	u.infer(with_stack(u, u.node(DIF_INSTR_LDV(DIF_OP_LDGAA, 1300, 1)),
	    { key(u, "int") }));
}

PROGERR_CASE("ldtaa-missing-variable", "failed to find variable (1300, 1, 0)")
{
	Unit u;
	u.infer(with_stack(u, u.node(DIF_INSTR_LDV(DIF_OP_LDTAA, 1300, 1)),
	    { key(u, "int") }));
}

CASE("staa-stores-value")
{
	for (uint8_t op : { DIF_OP_STGAA, DIF_OP_STTAA }) {
		Unit u;
		uint8_t scope = op == DIF_OP_STGAA ? DIFV_SCOPE_GLOBAL :
		    DIFV_SCOPE_THREAD;
		dtrace_difv_t *v = u.var(1300, scope, DIFV_KIND_ARRAY);
		DFGNode *val = u.ctf("kernel", "struct proc *");
		DFGNode *n = with_stack(u, u.node(DIF_INSTR_STV(op, 1300, 1)),
		    { key(u, "int") });
		Unit::uses(n, {}, { val });
		expect_type(u, n, DIF_TYPE_CTF, "struct proc *");
		CHECK(v->dtdv_type.dtdt_kind == DIF_TYPE_CTF);
	}
}

CASE("stgaa-bottom-value-takes-variable-type")
{
	Unit u;
	u.var(1300, DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY, DIF_TYPE_STRING);
	DFGNode *n = with_stack(u, u.node(DIF_INSTR_STV(DIF_OP_STGAA, 1300, 1)),
	    { key(u, "int") });
	Unit::uses(n, {}, { u.def(NOP, DIF_TYPE_BOTTOM) });
	expect_type(u, n, DIF_TYPE_STRING);
}

CASE("staa-rejections")
{
	for (uint8_t op : { DIF_OP_STGAA, DIF_OP_STTAA }) {
		const char *name = op == DIF_OP_STGAA ? "stgaa" : "sttaa";
		uint8_t scope = op == DIF_OP_STGAA ? DIFV_SCOPE_GLOBAL :
		    DIFV_SCOPE_THREAD;
		Unit u;
		std::string want = std::string("dn2 is nullptr in ") + name;
		expect_fail(u, u.node(DIF_INSTR_STV(op, 1300, 1)), want.c_str());
		/* Value of another kind than the variable's. */
		Unit v;
		v.var(1300, scope, DIFV_KIND_ARRAY, DIF_TYPE_STRING);
		DFGNode *n = with_stack(v, v.node(DIF_INSTR_STV(op, 1300, 1)),
		    { key(v, "int") });
		Unit::uses(n, {}, { v.ctf("kernel", "struct proc *") });
		expect_fail(v, n, "dif_var and dr have different types");
		/* Key tuple of another type than the first use's. */
		Unit w;
		w.var(1300, scope, DIFV_KIND_ARRAY, DIF_TYPE_STRING);
		DFGNode *a = with_stack(w, w.node(DIF_INSTR_STV(op, 1300, 1)),
		    { key(w, "int") });
		Unit::uses(a, {}, { w.str() });
		CHECK(w.infer(a) == DIF_TYPE_STRING);
		DFGNode *b = with_stack(w, w.node(DIF_INSTR_STV(op, 1300, 1)),
		    { key(w, "long") });
		Unit::uses(b, {}, { w.str() });
		expect_fail(w, b, "type mismatch in stgaa");
	}
}

PROGERR_CASE("stgaa-missing-variable", "failed to find variable (1300, 0, 0)")
{
	Unit u;
	DFGNode *n = with_stack(u, u.node(DIF_INSTR_STV(DIF_OP_STGAA, 1300, 1)),
	    { key(u, "int") });
	Unit::uses(n, {}, { u.str() });
	u.infer(n);
}

PROGERR_CASE("sttaa-missing-variable", "failed to find variable (1300, 1, 0)")
{
	Unit u;
	DFGNode *n = with_stack(u, u.node(DIF_INSTR_STV(DIF_OP_STTAA, 1300, 1)),
	    { key(u, "int") });
	Unit::uses(n, {}, { u.str() });
	u.infer(n);
}

/* ---- inferNode() preconditions ------------------------------------ */
CASE("infer-r0-is-bottom")
{
	Unit u;
	CHECK(u.infer(u.r0()) == DIF_TYPE_BOTTOM);
}

CASE("infer-failing-definitions")
{
	/* A definition that cannot be typed fails its uses. */
	Unit u;
	DFGNode *bad = u.node(DIF_INSTR_MOV(5, 1));
	DFGNode *n = u.node(DIF_INSTR_MOV(1, 2));
	Unit::uses(n, { bad });
	expect_fail(u, n, "failed to r1defs stack");
	Unit v;
	bad = v.node(DIF_INSTR_MOV(5, 1));
	DFGNode *a = v.ctf("D", "int");
	n = v.node(DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 3));
	Unit::uses(n, { a }, { bad });
	expect_fail(v, n, "failed to r2defs stack");
	Unit w;
	w.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);
	bad = w.node(DIF_INSTR_STV(DIF_OP_STLS, 1280, 4));
	n = w.node(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 2));
	n->varDefs.insert(bad);
	expect_fail(w, n, "failed to vardefs stack");
}

CASE("infer-stack-mismatch")
{
	/* Two paths push different types for the same call. */
	Unit u;
	DFGNode *n = u.node(DIF_INSTR_CALL(DIF_SUBR_STRLEN, 1));
	with_stack(u, n, { u.str(DIF_INSTR_PUSHTS(DIF_OP_PUSHTR,
	    DIF_TYPE_STRING, 0, 1)) });
	with_stack(u, n, { key(u, "int") });
	expect_fail(u, n, "failed to infer stack");
}

/* ---- TypeInference construction ------------------------------------ */
PROGERR_CASE("ctor-mtx-type-name", "mtx_str does not start with")
{
	strlcpy(mtx_str, "struct mtx", sizeof(mtx_str));
	Unit u;
}

PROGERR_CASE("ctor-rw-type-name", "rw_str does not start with")
{
	strlcpy(rw_str, "struct rwlock", sizeof(rw_str));
	Unit u;
}

PROGERR_CASE("ctor-sx-type-name", "sx_str does not start with")
{
	strlcpy(sx_str, "struct sx", sizeof(sx_str));
	Unit u;
}

PROGERR_CASE("ctor-every-type-name-and-link", "mtx_str does not start with")
{
	/* All three names are wrong: the first report is the one kept, the
	 * type check does not start, and hypertrace_link() returns it. */
	strlcpy(mtx_str, "struct mtx", sizeof(mtx_str));
	strlcpy(rw_str, "struct rwlock", sizeof(rw_str));
	strlcpy(sx_str, "struct sx", sizeof(sx_str));
	{
		Unit u;
		CHECK(u.L.progErrors == 3);
		u.node(DIF_INSTR_RET(0));
		CHECK(u.ti.inferDIFO(&u.difo) == E_HYPERTRACE_TYPING);
		CHECK(u.ti.getErrorMessage().find("mtx_str does not start") == 0);
	}
	dtrace_prog_t *p = compile("BEGIN { trace(1); }");
	std::string msg;
	CHECK(link(p, &msg) == E_HYPERTRACE_TYPING);
	CHECKF(msg.find("mtx_str does not start") == 0, "%s", msg.c_str());
}

PROGERR_CASE("definitions-disagree-stop-inference",
    "failed to typecheck conditional")
{
	/* A register defined as a D string on one path and an int on
	 * another: inferNode() stops after the definition check. */
	Unit u;
	DFGNode *s = u.str();
	DFGNode *i = u.ctf("D", "int");
	DFGNode *n = u.node(DIF_INSTR_MOV(1, 2));
	Unit::uses(n, { s, i });
	CHECK(u.infer(n) == -1);
}

/* ---- inferDIFO() --------------------------------------------------- */
namespace {
int
infer_difo(Unit &u, dtrace_difo_t *d)
{
	int r;
	capture_stderr([&] { r = u.ti.inferDIFO(d); });
	return (r);
}
} // namespace

CASE("infer-difo-shape-checks")
{
	struct {
		std::function<void(dtrace_difo_t *)> mutate;
		const char *text;
	} rows[] = {
		{ [](dtrace_difo_t *d) { d->dtdo_buf = nullptr; },
		    "DIFO has no instructions" },
		{ [](dtrace_difo_t *d) { d->dtdo_inttab = nullptr;
		      d->dtdo_intlen = 3; }, "inttab length is 3 but" },
		{ [](dtrace_difo_t *d) { d->dtdo_strtab = nullptr;
		      d->dtdo_strlen = 4; }, "strtab length is 4 but" },
		{ [](dtrace_difo_t *d) { d->dtdo_vartab = nullptr;
		      d->dtdo_varlen = 5; }, "vartab length is 5 but" },
		{ [](dtrace_difo_t *d) { d->dtdo_symtab = nullptr;
		      d->dtdo_symlen = 6; }, "symtab length is 6 but" },
	};
	for (auto &r : rows) {
		Unit u;
		u.node(DIF_INSTR_RET(0));
		r.mutate(&u.difo);
		CHECK(infer_difo(u, &u.difo) == E_HYPERTRACE_TYPING);
		CHECKF(u.ti.getErrorMessage().find(r.text) != std::string::npos,
		    "%s", u.ti.getErrorMessage().c_str());
	}
	Unit u;
	u.node(DIF_INSTR_RET(0));
	u.difo.dtdo_symtab = nullptr;
	u.difo.dtdo_symlen = 0;
	CHECK(infer_difo(u, &u.difo) == 0 && u.difo.dtdo_types == nullptr);
}

CASE("infer-difo-context-checks")
{
	Unit u("BEGIN { trace(1); }", true);
	u.node(DIF_INSTR_RET(0));
	CHECK(infer_difo(u, &u.difo) == E_HYPERTRACE_TYPING);
	CHECK(u.ti.getErrorMessage().find("program is NULL") != std::string::npos);
	Unit v;
	v.node(DIF_INSTR_RET(0));
	TypeInference ti(v.L, nullptr, v.pgp);
	int r;
	capture_stderr([&] { r = ti.inferDIFO(&v.difo); });
	CHECK(r == E_HYPERTRACE_TYPING);
	CHECK(ti.getErrorMessage().find("dtrace handle is NULL") !=
	    std::string::npos);
}

CASE("infer-difo-types-and-skips")
{
	Unit u;
	DFGNode *a = u.node(DIF_INSTR_SETS(0, 1));		/* string */
	DFGNode *b = u.node(DIF_INSTR_SETX(u.integer(1), 2)); /* int */
	DFGNode *c = u.node(DIF_INSTR_ALLOCS(2, 3));	/* bottom */
	Unit::uses(c, { b });
	DFGNode *d = u.node(DIF_INSTR_NOP);			/* none */
	/* Nodes of other DIFOs, and of a DIFO without code, are skipped. */
	static dif_instr_t other_code[1] = { DIF_INSTR_NOP };
	static dtrace_difo_t other, nocode;
	other.dtdo_buf = other_code;
	other.dtdo_len = 1;
	u.L.dfgNodes.push_back(std::make_unique<DFGNode>(u.dtp, u.pgp, &u.edp,
	    &other, nullptr, 0));
	u.L.dfgNodes.push_back(std::make_unique<DFGNode>(u.dtp, u.pgp, &u.edp,
	    &nocode, nullptr, 0));
	CHECK(infer_difo(u, &u.difo) == 0);
	CHECK(strcmp(u.difo.dtdo_types[a->uidx], "string") == 0);
	CHECK(strcmp(u.difo.dtdo_types[b->uidx], "int") == 0);
	CHECK(strcmp(u.difo.dtdo_types[c->uidx], "bottom") == 0);
	CHECK(strcmp(u.difo.dtdo_types[d->uidx], "none") == 0);
}

CASE("infer-difo-failure-message")
{
	Unit u;
	u.node(DIF_INSTR_MOV(5, 1));
	CHECK(infer_difo(u, &u.difo) == E_HYPERTRACE_TYPING);
	CHECK(u.ti.getErrorMessage().find("failed to infer the type of "
	    "instruction 0") != std::string::npos);
}

CASE("infer-difo-unknown-kind")
{
	Unit u;
	u.def(NOP, 7);
	CHECK(infer_difo(u, &u.difo) == E_HYPERTRACE_TYPING);
	CHECK(u.ti.getErrorMessage().find("unknown type kind 7") !=
	    std::string::npos);
}

PROGERR_CASE("infer-difo-ctf-without-typefile", "typefile nullptr at 0")
{
	Unit u;
	u.def(NOP, DIF_TYPE_CTF, nullptr, 1);
	u.ti.inferDIFO(&u.difo);
}

PROGERR_CASE("infer-difo-unnamed-ctf", "failed at getting type name")
{
	Unit u;
	u.def(NOP, DIF_TYPE_CTF, dt_typefile_kernel(), 0x7ffffff);
	u.ti.inferDIFO(&u.difo);
}

PROGERR_CASE("infer-difo-types-allocation", "failed to malloc dtdo_types")
{
	Unit u;
	u.node(DIF_INSTR_RET(0));
	fail_malloc_after(1);
	u.ti.inferDIFO(&u.difo);
}

/* ---- Further rule details -------------------------------------------- */

CASE("typecast-unknown-in-probe-module")
{
	/* The probe's module has a type file but not the type: the report
	 * comes from that type file, and the cast fails. */
	Unit u;
	strlcpy(u.edp.dted_probe.dtpd_mod, "typingfix",
	    sizeof(u.edp.dted_probe.dtpd_mod));
	DFGNode *src = u.ctf("D", "uint64_t");
	DFGNode *n = u.node(DIF_INSTR_TYPECAST(u.sym("struct no_such"), 1));
	Unit::uses(n, { src });
	std::string err = capture_stderr([&] { CHECK(u.infer(n) == -1); });
	CHECK(u.L.hadProgErr());
	CHECKF(err.find("struct no_such") != std::string::npos, "%s",
	    err.c_str());
}

CASE("typecast-without-symbol-table")
{
	Unit u;
	DFGNode *src = u.ctf("D", "uint64_t");
	DFGNode *n = u.node(DIF_INSTR_TYPECAST(0, 1));
	Unit::uses(n, { src });
	u.difo.dtdo_symtab = nullptr;
	u.difo.dtdo_symlen = 0;
	expect_fail(u, n, "symbol 0 is not a string in the 0-byte symbol table");
}

CASE("add-struct-variable-offset")
{
	/* A structure plus a value that is not a constant keeps the
	 * structure's type. */
	Unit u;
	DFGNode *a = u.ctf("typingfix", "struct tf_pair");
	DFGNode *b = u.ctf("D", "uint64_t");
	DFGNode *n = arith(u, DIF_OP_ADD, a, b);
	expect_type(u, n, DIF_TYPE_CTF, "struct tf_pair");
	CHECK(!n->integer.has_value());
}

CASE("add-struct-anonymous-member")
{
	/* Byte 8 of struct tf_anon is an anonymous union. */
	Unit u;
	DFGNode *a = u.ctf("typingfix", "struct tf_anon");
	DFGNode *b = u.node(DIF_INSTR_SETX(u.integer(8), 2));
	DFGNode *n = arith(u, DIF_OP_ADD, a, b);
	CHECK(u.infer(n) == DIF_TYPE_CTF);
	std::string t = u.tname(n);
	CHECKF(t == "struct tf_anon" || t == "union  {...}" ||
	    t.rfind("union", 0) == 0, "%s", t.c_str());
}

CASE("add-struct-second-anonymous-member")
{
	/*
	 * Regression: the member at an offset was looked up again by its
	 * name, and the name of every anonymous member is "": byte 16 of
	 * struct tf_anon2 resolved to the first anonymous union (byte 8).
	 * Oracle: libctf's own member iteration.
	 */
	Unit u;
	Typefile *tf = TF("typingfix");
	ctf_file_t *fp = tf->getCtfPointer();
	ctf_id_t s2 = ID(tf, "struct tf_anon2");
	struct Want { ulong_t off; ctf_id_t type; } want { 0, CTF_ERR };
	ctf_member_iter(fp, s2, [](const char *, ctf_id_t t, ulong_t off,
	    void *arg) {
		Want *w = (Want *)arg;
		if (off == 128)
			w->type = t;
		return (0);
	}, &want);
	CHECK(want.type != CTF_ERR);
	ctf_membinfo_t mi;
	CHECK(ctf_member_info(fp, want.type, "c1", &mi) == 0);
	DFGNode *a = u.ctf("typingfix", "struct tf_anon2");
	DFGNode *b = u.node(DIF_INSTR_SETX(u.integer(16), 2));
	DFGNode *n = arith(u, DIF_OP_ADD, a, b);
	CHECK(u.infer(n) == DIF_TYPE_CTF);
	/* The sum is a pointer into that member: its type. */
	CHECKF(n->tf == tf && n->ctfid == want.type, "type %ld (%s), want %ld",
	    n->ctfid, u.tname(n).c_str(), want.type);
}

PROGERR_CASE("add-usetx-bottom-symbolic", "unexpected bottom type")
{
	Unit u;
	DFGNode *s = u.def(DIF_INSTR_USETX(u.sym("x"), 1), DIF_TYPE_BOTTOM,
	    nullptr, CTF_ERR, "x");
	DFGNode *o = u.ctf("kernel", "struct proc *");
	u.infer(arith(u, DIF_OP_ADD, s, o));
}

CASE("add-usetx-to-symbolic-union-pointer")
{
	/* other : union tf_u * | l, plus a usetx: the member l (long). */
	Unit u;
	DFGNode *other = u.ctf("typingfix", "union tf_u *", "l",
	    DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1));
	DFGNode *off = u.node(DIF_INSTR_USETX(u.sym("i"), 2));
	expect_type(u, arith(u, DIF_OP_ADD, other, off), DIF_TYPE_CTF, "long");
}

CASE("mip-from-symbol-qualified-and-out-of-range")
{
	Unit u;
	/*
	 * Every qualifier or typedef of struct tf_pair in the container
	 * (volatile and const objects, tf_pair_t; found by walking libctf's
	 * types, as they have no names of their own): the member is the
	 * structure's.  A restrict-qualified pointer is one reference above
	 * the pointer, which has no members.
	 */
	Typefile *tf = TF("typingfix");
	ctf_file_t *fp = tf->getCtfPointer();
	ctf_id_t pair = ID(tf, "struct tf_pair");
	struct Walk {
		ctf_file_t *fp;
		ctf_id_t pair;
		std::vector<std::pair<ctf_id_t, int>> found;
	} w { fp, pair, {} };
	ctf_type_iter(fp, [](ctf_id_t id, void *arg) {
		Walk *w = (Walk *)arg;
		int k = ctf_type_kind(w->fp, id);
		ctf_id_t ref = ctf_type_reference(w->fp, id);
		if ((k == CTF_K_VOLATILE || k == CTF_K_CONST ||
		    k == CTF_K_TYPEDEF) && ref == w->pair)
			w->found.push_back({ id, k });
		if (k == CTF_K_RESTRICT && ctf_type_kind(w->fp, ref) ==
		    CTF_K_POINTER && ctf_type_reference(w->fp, ref) == w->pair)
			w->found.push_back({ id, k });
		return (0);
	}, &w);
	int kinds = 0;
	for (auto [id, k] : w.found) {
		DFGNode *n = u.def(DIF_INSTR_NOP, DIF_TYPE_CTF, tf, id, "b");
		ctf_membinfo_t *mip = u.ti.getMipFromSymbol(n);
		if (k == CTF_K_RESTRICT)
			CHECK(mip == nullptr);
		else
			CHECKF(mip != nullptr && mip->ctm_offset == 64, "kind %d", k);
		kinds |= 1 << k;
	}
	CHECKF(kinds == ((1 << CTF_K_VOLATILE) | (1 << CTF_K_CONST) |
	    (1 << CTF_K_TYPEDEF) | (1 << CTF_K_RESTRICT)), "kinds %#x", kinds);
	/* A restrict pointer: one reference down is the pointer, which has
	 * no members. */
	Typefile *f = TF("typingfix");
	ctf_membinfo_t mi;
	CHECK(ctf_member_info(f->getCtfPointer(), ID(f, "struct tf_pair"), "a",
	    &mi) == 0);
	DFGNode *s = u.ctf("typingfix", "struct tf_pair", "a");
	char *saved = s->sym;
	s->sym = u.symtab + u.difo.dtdo_symlen; /* just past the table */
	CHECK(u.ti.getMipFromSymbol(s) == nullptr);
	s->sym = saved;
}

CASE("find-variable-global-and-thread")
{
	Unit u;
	Typefile *pf = TF("typingfix");
	dtrace_difv_t *g = u.var(1300, DIFV_SCOPE_GLOBAL, DIFV_KIND_SCALAR,
	    DIF_TYPE_CTF, pf, ID(pf, "struct tf_pair"));
	dtrace_difv_t *t = u.var(1290, DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR,
	    DIF_TYPE_CTF, pf, ID(pf, "struct tf_pair"));
	DFGNode *lg = u.def(DIF_INSTR_LDV(DIF_OP_LDGS, 1300, 1), DIF_TYPE_CTF,
	    pf, ID(pf, "struct tf_pair"));
	DFGNode *lt = u.def(DIF_INSTR_LDV(DIF_OP_LDTS, 1290, 1), DIF_TYPE_CTF,
	    pf, ID(pf, "struct tf_pair"));
	NodeSet a = { lg }, b = { lt };
	CHECK(u.ti.findVariableFromNodeDefs(a) == g);
	CHECK(u.ti.findVariableFromNodeDefs(b) == t);
}

CASE("ldls-store-checks")
{
	Typefile *k;
	ctf_id_t p;
	{
		/* The store's kind differs from the variable's. */
		Unit u;
		u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, DIF_TYPE_STRING);
		DFGNode *st = u.def(DIF_INSTR_STV(DIF_OP_STLS, 1280, 1),
		    DIF_TYPE_BOTTOM);
		DFGNode *n = u.node(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 2));
		n->varDefs.insert(st);
		expect_fail(u, n, "type mismatch 1 != 255");
	}
	{
		/* The variable has a symbol, the store none (and the other way
		 * round), and different symbols. */
		Unit u;
		k = dt_typefile_kernel();
		p = ID(k, "struct proc *");
		u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, DIF_TYPE_CTF, k,
		    p, "p_pid");
		DFGNode *st = u.def(DIF_INSTR_STV(DIF_OP_STLS, 1280, 1),
		    DIF_TYPE_CTF, k, p);
		DFGNode *n = u.node(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 2));
		n->varDefs.insert(st);
		expect_fail(u, n, "struct proc *, struct proc * | p_pid");
	}
	{
		Unit u;
		k = dt_typefile_kernel();
		p = ID(k, "struct proc *");
		ctf_id_t th = ID(k, "struct thread *");
		u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, DIF_TYPE_CTF, k,
		    th, "td_tid");
		/* td_oncpu (int) and td_tid (lwpid_t, an int): the same kind
		 * of member address (C: both are int pointers). */
		DFGNode *st = u.def(DIF_INSTR_STV(DIF_OP_STLS, 1280, 1),
		    DIF_TYPE_CTF, k, th, "td_oncpu");
		DFGNode *n = u.node(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 2));
		n->varDefs.insert(st);
		expect_type(u, n, DIF_TYPE_CTF, "struct thread *");
		CHECK(strcmp(n->sym, "td_oncpu") == 0);
	}
}

CASE("ldls-store-into-untyped-variable")
{
	/* A CTF variable without a recorded type id accepts the store's. */
	Unit u;
	Typefile *k = dt_typefile_kernel();
	u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, DIF_TYPE_CTF, k,
	    CTF_ERR);
	DFGNode *st = u.def(DIF_INSTR_STV(DIF_OP_STLS, 1280, 1), DIF_TYPE_CTF, k,
	    ID(k, "struct proc *"));
	DFGNode *n = u.node(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 2));
	n->varDefs.insert(st);
	expect_type(u, n, DIF_TYPE_CTF, "struct proc *");
}

CASE("aa-load-symbol-mismatch")
{
	/* One store of the array with another symbol than the variable's:
	 * the stack and definition checks pass, inferVar() rejects it. */
	for (uint8_t op : { DIF_OP_LDGAA, DIF_OP_LDTAA }) {
		Unit u;
		uint8_t scope = op == DIF_OP_LDGAA ? DIFV_SCOPE_GLOBAL :
		    DIFV_SCOPE_THREAD;
		uint8_t stop = op == DIF_OP_LDGAA ? DIF_OP_STGAA : DIF_OP_STTAA;
		Typefile *k = dt_typefile_kernel();
		ctf_id_t p = ID(k, "struct proc *");
		u.var(1300, scope, DIFV_KIND_ARRAY, DIF_TYPE_CTF, k, p, "p_pid");
		/* p_pid (pid_t) and p_comm (a char array) differ. */
		DFGNode *st = u.def(DIF_INSTR_STV(stop, 1300, 1), DIF_TYPE_CTF, k,
		    p, "p_comm");
		DFGNode *n = with_stack(u, u.node(DIF_INSTR_LDV(op, 1300, 2)),
		    { key(u, "int") });
		n->varDefs.insert(st);
		expect_fail(u, n, "struct proc * | p_comm, struct proc * | p_pid");
	}
}

CASE("store-variable-source-fields")
{
	/* Each field varEqualCTF() compares makes the sources disagree. */
	for (int field = 0; field < 6; field++) {
		StoreUnit u;
		DFGNode *v = u.member_value("b", "D", "uint64_t");
		DFGNode *n = u.store(DIF_OP_STX, v);
		dtrace_difv_t *var = u.L.getVarFromVarVec(1280,
		    DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);
		dtrace_difv_t *o = u.var(1280, DIFV_SCOPE_LOCAL,
		    DIFV_KIND_SCALAR);
		*o = *var;
		switch (field) {
		case 0: o->dtdv_id = 1281; break;
		case 1: o->dtdv_scope = DIFV_SCOPE_GLOBAL; break;
		case 2: o->dtdv_kind = DIFV_KIND_ARRAY; break;
		case 3: o->dtdv_type.dtdt_kind = DIF_TYPE_STRING; break;
		case 4: {
			/* The same type name in another type file (so the
			 * name is still found, but the type file differs). */
			Typefile *vt = v2tf(var->dtdv_tf);
			std::string name = vt->getTypename(var->dtdv_ctfid)
			    .value_or("?");
			bool moved = false;
			for (Typefile *t : { TF("D"), dt_typefile_kernel(),
			    TF("typingfix"), TF("typingfix2") }) {
				ctf_id_t id = t->getCtfID(name.c_str());
				if (t == vt || id == CTF_ERR)
					continue;
				o->dtdv_tf = t;
				o->dtdv_ctfid = id;
				moved = true;
				break;
			}
			CHECKF(moved, "no other type file has %s", name.c_str());
			break;
		}
		case 5: o->dtdv_ctfid = ID(TF("typingfix"),
			    "struct tf_big"); break;
		}
		n->varSources.push_back(o);
		int r = 0;
		capture_stderr([&] { r = u.infer(n); });
		CHECKF(r == -1 && u.L.hadProgErr(), "field %d: %d", field, r);
	}
}

CASE("ldls-variable-symbol-in-difo")
{
	/* A variable whose symbol points into this DIFO keeps it. */
	Unit u;
	Typefile *k = dt_typefile_kernel();
	dtrace_difv_t *v = u.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR,
	    DIF_TYPE_CTF, k, ID(k, "struct proc *"));
	v->dtdv_sym = u.symtab + u.sym("p_pid");
	DFGNode *n = u.node(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 1));
	expect_type(u, n, DIF_TYPE_CTF, "struct proc *");
	CHECK(n->sym == v->dtdv_sym);
	/* ... but not one of a DIFO without a symbol table. */
	Unit w;
	k = dt_typefile_kernel();
	v = w.var(1280, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR, DIF_TYPE_CTF, k,
	    ID(k, "struct proc *"));
	v->dtdv_sym = w.symtab + w.sym("p_pid");
	n = w.node(DIF_INSTR_LDV(DIF_OP_LDLS, 1280, 1));
	w.difo.dtdo_symtab = nullptr;
	w.difo.dtdo_symlen = 0;
	expect_type(w, n, DIF_TYPE_CTF, "struct proc *");
	CHECK(n->sym == nullptr);
}

CASE("subtype-int-and-struct")
{
	Unit u;
	Typefile *f = TF("typingfix");
	int w;
	std::string e = capture_stderr([&] {
		CHECK(u.ti.getSubtypeRelation(f, ID(f, "int"), f,
		    ID(f, "struct tf_pair"), w) == -1);
		CHECK(u.ti.getSubtypeRelation(f, ID(f, "const void *"), f,
		    ID(f, "struct tf_pair *"), w) == 0 && w == SUBTYPE_FST);
	});
}

PROGERR_CASE("unknown-builtin-variable", "variable 126 does not exist")
{
	Unit u;
	u.infer(u.node(DIF_INSTR_LDV(DIF_OP_LDGS, 0x126, 1)));
}

/* ---- Subroutine argument checks (inferSubr(), argCmpWith()) --------
 * Each subroutine's arguments are checked against the types the D
 * prototypes in dt_open.c declare; a D string may stand for a
 * "const char *", r0 (bottom) for anything.
 */
namespace {
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

DFGNode *
carg(Unit &u, const char *mod, const char *type)
{
	return (u.ctf(mod, type, nullptr,
	    DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_CTF, 0, 1)));
}

DFGNode *
sarg(Unit &u)
{
	return (u.str(DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 0, 1)));
}

DFGNode *
narg(Unit &u)
{
	return (u.def(DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, 0, 0, 1), DIF_TYPE_NONE));
}

DFGNode *
barg(Unit &u)
{
	return (u.def(DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, 0, 0, 1),
	    DIF_TYPE_BOTTOM));
}

/* Run `fn' in a child: it must end in dt_set_progerr() with `text'. */
void
expect_progerr(const std::function<void()> &fn, const char *text)
{
	int pfd[2];
	CHECK(pipe(pfd) == 0);
	pid_t pid = fork();
	if (pid == 0) {
		close(pfd[0]);
		dup2(pfd[1], STDERR_FILENO);
		th::progerr_recorded = th::progerr_unreturned = 0;
		fn();
		exit(th::progerr_recorded && !th::progerr_unreturned ? 0 : 3);
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
	CHECKF(WIFEXITED(st) && WEXITSTATUS(st) == 0 &&
	    err.find(text) != std::string::npos,
	    "status %d: '%s' lacks a returned program error '%s'", st,
	    err.c_str(), text);
}
} // namespace

CASE("subr-string-arguments")
{
	/* Subroutines taking D strings: a string, a char pointer, or a
	 * value without a type (rejected). */
	struct {
		uint16_t subr;
		int nargs;
		const char *name;
		int strargs; /* leading string parameters */
	} rows[] = {
		{ DIF_SUBR_STRLEN, 1, "strlen()", 1 },
		{ DIF_SUBR_CLEANPATH, 1, "cleanpath()", 1 },
		{ DIF_SUBR_DIRNAME, 1, "dirname()", 1 },
		{ DIF_SUBR_BASENAME, 1, "basename()", 1 },
		{ DIF_SUBR_TOUPPER, 1, "toupper()", 1 },
		{ DIF_SUBR_TOLOWER, 1, "tolower()", 1 },
		{ DIF_SUBR_STRTOLL, 1, "strtoll()", 1 },
		{ DIF_SUBR_STRCHR, 2, "strchr()", 1 },
		{ DIF_SUBR_STRRCHR, 2, "strrchr()", 1 },
		{ DIF_SUBR_SUBSTR, 2, "substr()", 1 },
		{ DIF_SUBR_INDEX, 2, "index()", 2 },
		{ DIF_SUBR_RINDEX, 2, "rindex()", 2 },
		{ DIF_SUBR_STRTOK, 2, "strtok()", 2 },
		{ DIF_SUBR_STRSTR, 2, "strstr()", 2 },
		{ DIF_SUBR_STRJOIN, 2, "strjoin()", 2 },
		{ DIF_SUBR_JSON, 2, "json()", 2 },
	};
	for (auto &r : rows) {
		for (int which = 0; which < r.strargs; which++) {
			/* A char pointer where a string is expected. */
			{
				Unit u;
				std::vector<DFGNode *> a;
				for (int i = 0; i < r.nargs; i++)
					a.push_back(i == which ?
					    carg(u, "D", "char *") :
					    i < r.strargs ? sarg(u) :
					    carg(u, "D", r.subr == DIF_SUBR_SUBSTR ?
					    "int" : "char"));
				DFGNode *n = u.node(DIF_INSTR_CALL(r.subr, 1));
				Vec<BasicBlock *> path;
				n->stacks.emplace_back(path);
				for (auto x : a)
					n->stacks.back().nodesOnStack.push_back(x);
				CHECKF(u.infer(n) != -1, "%s ctf arg %d", r.name,
				    which);
			}
			/* No type at all. */
			expect_progerr([&] {
				Unit u;
				std::vector<DFGNode *> a;
				for (int i = 0; i < r.nargs; i++)
					a.push_back(i == which ? narg(u) :
					    i < r.strargs ? sarg(u) :
					    carg(u, "D", "char"));
				DFGNode *n = u.node(DIF_INSTR_CALL(r.subr, 1));
				Vec<BasicBlock *> path;
				n->stacks.emplace_back(path);
				for (auto x : a)
					n->stacks.back().nodesOnStack.push_back(x);
				u.infer(n);
			}, which == 0 ? "arg0 type is NONE" : "arg1 type is NONE");
		}
	}
	/* copyoutstr(): a string or a char pointer, then CTF arguments. */
	{
		Unit u;
		DFGNode *n = call(u, DIF_SUBR_COPYOUTSTR, { carg(u, "D", "char *"),
		    carg(u, "D", "uintptr_t"), carg(u, "D", "size_t") });
		CHECK(u.infer(n) == DIF_TYPE_NONE);
	}
	expect_progerr([] {
		Unit u;
		u.infer(call(u, DIF_SUBR_COPYOUTSTR, { narg(u),
		    carg(u, "D", "uintptr_t"), carg(u, "D", "size_t") }));
	}, "copyoutstr(): arg0 type is NONE");
}

CASE("subr-argument-kinds")
{
	{
		/* r0 stands for any argument. */
		Unit u;
		DFGNode *n = call(u, DIF_SUBR_MUTEX_OWNED, { barg(u) });
		CHECK(u.infer(n) == DIF_TYPE_CTF && u.tname(n) == "int");
	}
	{
		/* Any pointer converts to void * / uintptr_t. */
		Unit u;
		DFGNode *n = call(u, DIF_SUBR_COPYIN, {
		    carg(u, "kernel", "struct proc *"), carg(u, "D", "size_t") });
		CHECK(u.infer(n) == DIF_TYPE_CTF && u.tname(n) == "void *");
	}
	expect_progerr([] {
		Unit u;
		u.infer(call(u, DIF_SUBR_COPYIN, { carg(u, "D", "int"),
		    carg(u, "D", "size_t") }));
	}, "copyin(): int (D) can't be cast to void *");
	expect_progerr([] {
		Unit u;
		u.infer(call(u, DIF_SUBR_COPYIN, { narg(u),
		    carg(u, "D", "size_t") }));
	}, "copyin(): argument at 0 has no type where uintptr_t is expected");
	expect_progerr([] {
		Unit u;
		u.infer(call(u, DIF_SUBR_HTONS, {
		    carg(u, "kernel", "struct proc *") }));
	}, "htons() (argkind)");
	expect_progerr([] {
		Unit u;
		u.infer(call(u, DIF_SUBR_PROGENYOF, { carg(u, "D", "int64_t") }));
	}, "progenyof(): pid_t");
	expect_progerr([] {
		Unit u;
		u.infer(call(u, DIF_SUBR_MUTEX_OWNED, {
		    carg(u, "kernel", "struct proc *") }));
	}, "mutex_owned(): struct mtx *");
	expect_progerr([] {
		Unit u;
		/* A value typed by a module other than D and the kernel. */
		u.infer(call(u, DIF_SUBR_STRLEN, {
		    carg(u, "typingfix", "char") }));
	}, "could not find typefile 'typingfix'");
}

CASE("subr-return-types")
{
	/* Subroutines with nothing else covered: their declared types. */
	{
		Unit u;
		DFGNode *n = call(u, DIF_SUBR_DDI_PATHNAME, {
		    carg(u, "kernel", "struct proc *"), carg(u, "D", "int64_t") });
		CHECK(u.infer(n) == DIF_TYPE_STRING);
	}
	{
		Unit u;
		DFGNode *n = call(u, DIF_SUBR_PTINFO, { carg(u, "D", "uintptr_t") });
		CHECK(u.infer(n) == DIF_TYPE_CTF && u.tname(n) == "void *");
	}
	{
		Unit u;
		DFGNode *n = call(u, DIF_SUBR_MEMSTR, { carg(u, "D", "void *"),
		    carg(u, "D", "char"), carg(u, "D", "size_t") });
		CHECK(u.infer(n) == DIF_TYPE_STRING);
	}
	{
		Unit u;
		CHECK(u.infer(call(u, DIF_SUBR_GETMINOR, {})) == -1);
		CHECK(u.ti.getErrorMessage() == "getminor() is not supported");
	}
	/* The FreeBSD kernel has neither file_t nor mblk_t. */
	expect_progerr([] {
		Unit u;
		u.infer(call(u, DIF_SUBR_GETF, { carg(u, "D", "int") }));
	}, "getf(): failed to get type file_t *");
	expect_progerr([] {
		Unit u;
		u.infer(call(u, DIF_SUBR_MSGSIZE, { carg(u, "D", "void *") }));
	}, "msgsize(): failed to get type mblk_t *");
}

/*
 * Subroutine arguments against the D ident table (dt_open.c): every
 * subroutine prototype's typed parameters.  Oracle: no D subroutine takes a
 * struct by value, so a struct at any typed position is rejected with a
 * diagnostic naming the subroutine; a D string is accepted wherever the
 * prototype takes a string or a char pointer.
 */
namespace {
struct SubrProto {
	uint_t id;
	std::string name;
	std::vector<std::string> params;
};

int
collect_subr(dt_idhash_t *, dt_ident_t *idp, void *arg)
{
	if (idp->di_kind != DT_IDENT_FUNC || idp->di_iarg == nullptr)
		return (0);
	std::string proto = (const char *)idp->di_iarg;
	size_t open = proto.find('('), close = proto.rfind(')');
	if (open == std::string::npos || close == std::string::npos)
		return (0);
	SubrProto sp { idp->di_id, idp->di_name, {} };
	std::string list = proto.substr(open + 1, close - open - 1);
	size_t start = 0;
	while (start <= list.size() && !list.empty()) {
		size_t comma = list.find(',', start);
		std::string p = list.substr(start, comma == std::string::npos ?
		    std::string::npos : comma - start);
		while (!p.empty() && p.front() == ' ')
			p.erase(0, 1);
		sp.params.push_back(p);
		if (comma == std::string::npos)
			break;
		start = comma + 1;
	}
	if (sp.params.size() == 1 && sp.params[0] == "void")
		sp.params.clear();
	((std::vector<SubrProto> *)arg)->push_back(sp);
	return (0);
}

std::vector<SubrProto>
subr_prototypes()
{
	std::vector<SubrProto> v;
	dt_idhash_iter(handle()->dt_globals, collect_subr, &v);
	return (v);
}

bool
typed_param(const std::string &p)
{
	/* "@" is any type, "..." any further arguments. */
	return (p != "@" && p != "..." && p.find("...") == std::string::npos);
}

bool
string_param(const std::string &p)
{
	return (p == "string" || p == "const char *" || p == "char *");
}
} // namespace

CASE("subr-struct-argument-rejected-at-every-typed-position")
{
	int checked = 0;
	std::vector<std::string> wrong;
	for (const SubrProto &sp : subr_prototypes()) {
		for (size_t pos = 0; pos < sp.params.size(); pos++) {
			if (!typed_param(sp.params[pos]))
				continue;
			Unit u;
			DFGNode *n = u.node(DIF_INSTR_CALL(sp.id, 1));
			Vec<BasicBlock *> path;
			n->stacks.emplace_back(path);
			for (size_t i = 0; i < sp.params.size(); i++)
				n->stacks.back().nodesOnStack.push_back(i == pos ?
				    carg(u, "kernel", "struct proc") : barg(u));
			int r = 0;
			capture_stderr([&] { r = u.infer(n); });
			const std::string &msg = u.ti.getErrorMessage();
			bool unsupported = msg.find("is not supported") !=
			    std::string::npos;
			if (r != -1 || (!u.L.hadProgErr() && !unsupported) ||
			    msg.find(sp.name) == std::string::npos)
				wrong.push_back(sp.name + "() argument " +
				    std::to_string(pos) + " (" + sp.params[pos] +
				    "): " + std::to_string(r) + " '" + msg + "'");
			checked++;
		}
	}
	printf("subr-struct-argument-rejected-at-every-typed-position: %d "
	    "positions\n", checked);
	for (auto &w : wrong)
		printf("  accepted: %s\n", w.c_str());
	fflush(stdout);
	CHECK(checked > 60 && wrong.empty());
}

CASE("subr-string-accepted-at-every-string-position")
{
	int checked = 0;
	for (const SubrProto &sp : subr_prototypes()) {
		for (size_t pos = 0; pos < sp.params.size(); pos++) {
			if (!string_param(sp.params[pos]))
				continue;
			Unit u;
			DFGNode *n = u.node(DIF_INSTR_CALL(sp.id, 1));
			Vec<BasicBlock *> path;
			n->stacks.emplace_back(path);
			for (size_t i = 0; i < sp.params.size(); i++)
				n->stacks.back().nodesOnStack.push_back(i == pos ?
				    sarg(u) : barg(u));
			int r = 0;
			std::string err = capture_stderr([&] { r = u.infer(n); });
			CHECKF(r != -1 && !u.L.hadProgErr(), "%s() rejected a D "
			    "string as argument %zu (%s): %s %s", sp.name.c_str(),
			    pos, sp.params[pos].c_str(), err.c_str(),
			    u.ti.getErrorMessage().c_str());
			checked++;
		}
	}
	printf("subr-string-accepted-at-every-string-position: %d positions\n",
	    checked);
	fflush(stdout);
	CHECK(checked > 20);
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
