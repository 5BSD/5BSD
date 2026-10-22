/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * An independent per-instruction type oracle for HyperTrace type inference.
 *
 * The oracle walks a copy of the DIFO taken BEFORE hypertrace_link() and
 * derives the type every instruction must receive from three sources that do
 * not share code with dt_typing*.cc:
 *
 *  - the DIF instruction-set semantics (sys/dtrace.h: a ldsw yields a signed
 *    32-bit value, setx a 64-bit integer, sets a string, ...);
 *  - the D front end's builtin identifier table (dt_open.c _dtrace_globals:
 *    the declared type of every builtin variable and the declared return type
 *    of every subroutine), read from the handle's identifier hash;
 *  - libctf directly (ctf_lookup_by_name, ctf_member_info, ctf_type_name)
 *    for member and cast types.
 *
 * Register data flow is followed only for straight-line DIFOs (no branches),
 * which is where a single reaching definition is guaranteed.  The typing
 * rules followed are the inference rules written above each case of
 * TypeInference::inferNode().  Integer types are compared by name; when the
 * names differ but both are integers of the same size the difference is a
 * "divergence" which the caller must list explicitly (see KNOWN_DIVERGENCES
 * in typing-inference.cc), otherwise it is a failure.
 */
#ifndef _TYPING_ORACLE_H_
#define _TYPING_ORACLE_H_

#include "typing-harness.h"

#include <map>
#include <set>

namespace th {

struct OTy {
	enum Kind { UNKNOWN, CTF, STRING, BOTTOM, NONE } kind = UNKNOWN;
	std::string name; /* ctf_type_name() for CTF */
	ctf_file_t *fp = nullptr;
	ctf_id_t id = CTF_ERR;
	std::string sym; /* symbol (usetx) annotation, if any */
	std::string origin; /* identifier the type was declared by */
	bool isconst = false; /* an integer constant (setx) */
	uint64_t cval = 0;
};

struct Divergence {
	std::string subject; /* e.g. "var:arg0" or "subr:rand" */
	std::string inferred;
	std::string expected;
};

inline std::string
ctf_name(ctf_file_t *fp, ctf_id_t id)
{
	char buf[DT_TYPE_NAMELEN];
	if (ctf_type_name(fp, id, buf, sizeof(buf)) == nullptr)
		return ("?");
	return (buf);
}

/* Look a type up by name: the kernel first (as the typing pass does for
 * kernel types), then every other object, then the D definitions. */
inline OTy
lookup_type(const std::string &name)
{
	OTy t;
	if (name == "string") {
		t.kind = OTy::STRING;
		t.name = "string";
		return (t);
	}
	dtrace_typeinfo_t tip;
	if (dtrace_lookup_by_type(handle(), "kernel", name.c_str(), &tip) != 0 &&
	    dtrace_lookup_by_type(handle(), DTRACE_OBJ_EVERY, name.c_str(),
	    &tip) != 0)
		return (t);
	t.kind = OTy::CTF;
	t.fp = tip.dtt_ctfp;
	t.id = tip.dtt_type;
	t.name = ctf_name(t.fp, t.id);
	return (t);
}

inline OTy
ctf_type(const char *name)
{
	OTy t = lookup_type(name);
	CHECKF(t.kind == OTy::CTF, "oracle: no CTF type %s", name);
	return (t);
}

/* Identifier table: builtin variable id or subroutine id -> declared type. */
struct IdentTable {
	std::map<uint_t, std::string> vars, subrs;
	std::map<uint_t, std::string> varnames, subrnames;
	IdentTable()
	{
		dt_idhash_iter(handle()->dt_globals, collect, this);
	}
	static int
	collect(dt_idhash_t *, dt_ident_t *idp, void *arg)
	{
		IdentTable *t = (IdentTable *)arg;
		if (idp->di_iarg == nullptr)
			return (0);
		std::string proto = (const char *)idp->di_iarg;
		if (idp->di_kind == DT_IDENT_SCALAR) {
			t->vars[idp->di_id] = proto;
			t->varnames[idp->di_id] = idp->di_name;
		} else if (idp->di_kind == DT_IDENT_FUNC) {
			t->subrs[idp->di_id] = proto.substr(0, proto.find('('));
			t->subrnames[idp->di_id] = idp->di_name;
		}
		return (0);
	}
};

inline std::string
strip_scope(std::string s)
{
	/* "genunix`kthread_t *" style scoped names and the FreeBSD
	 * curthread_str ("kernel`struct thread *"). */
	size_t bq = s.find('`');
	if (bq == std::string::npos)
		return (s);
	size_t sp = s.rfind(' ', bq);
	std::string head = sp == std::string::npos ? "" : s.substr(0, sp + 1);
	return (head + s.substr(bq + 1));
}

struct Oracle {
	dtrace_hdl_t *dtp;
	IdentTable idents;
	std::vector<Divergence> divergences;
	std::vector<std::string> failures;
	size_t checked = 0;

	Oracle() : dtp(handle()) {}

	static bool
	is_branch(uint8_t op)
	{
		return (op >= DIF_OP_BA && op <= DIF_OP_BLEU);
	}

	OTy
	from_decl(const std::string &decl)
	{
		std::string d = strip_scope(decl);
		if (d == "string") {
			OTy t;
			t.kind = OTy::STRING;
			t.name = "string";
			return (t);
		}
		if (d == "void") {
			OTy t;
			t.kind = OTy::NONE;
			t.name = "none";
			return (t);
		}
		/* As the compiler resolves an identifier's declared type
		 * (dt_idops_type: every object, in the module list's order). */
		dtrace_typeinfo_t tip;
		if (decl.find('`') == std::string::npos &&
		    dtrace_lookup_by_type(handle(), DTRACE_OBJ_EVERY, d.c_str(),
		    &tip) == 0) {
			OTy t;
			t.kind = OTy::CTF;
			t.fp = tip.dtt_ctfp;
			t.id = tip.dtt_type;
			t.name = ctf_name(t.fp, t.id);
			return (t);
		}
		return (lookup_type(d));
	}

	OTy
	member_type(const OTy &base, const std::string &sym)
	{
		OTy t;
		if (base.kind != OTy::CTF)
			return (t);
		ctf_id_t id = ctf_type_resolve(base.fp, base.id);
		if (ctf_type_kind(base.fp, id) == CTF_K_POINTER)
			id = ctf_type_resolve(base.fp,
			    ctf_type_reference(base.fp, id));
		ctf_membinfo_t mi;
		if (ctf_member_info(base.fp, id, sym.c_str(), &mi) == CTF_ERR)
			return (t);
		t.kind = OTy::CTF;
		t.fp = base.fp;
		t.id = mi.ctm_type;
		t.name = ctf_name(t.fp, t.id);
		return (t);
	}

	static OTy
	named(const char *n)
	{
		return (ctf_type(n));
	}

	/*
	 * The compiler's integer rank of an operand (dt_type_promote()):
	 * bits, plus one if unsigned; an enum ranks as int; 0 if it is no
	 * integer.  (A constant's type is already its constant type.)
	 */
	static uint_t
	rank(const OTy &t)
	{
		if (t.kind != OTy::CTF)
			return (0);
		ctf_id_t id = ctf_type_resolve(t.fp, t.id);
		int k = ctf_type_kind(t.fp, id);
		if (k == CTF_K_ENUM)
			return (32);
		ctf_encoding_t e;
		if (k != CTF_K_INTEGER || ctf_type_encoding(t.fp, id, &e) != 0)
			return (0);
		return (e.cte_bits + ((e.cte_format & CTF_INT_SIGNED) == 0));
	}

	static int
	klass(const OTy &t)
	{
		if (t.kind == OTy::STRING)
			return (DTC_STRING);
		if (t.kind != OTy::CTF)
			return (DTC_BOTTOM);
		ctf_id_t id = ctf_type_resolve(t.fp, t.id);
		int k = ctf_type_kind(t.fp, id);
		/* A pointer's class is the class of what it ultimately
		 * points at (dt_get_class follows references). */
		while (k == CTF_K_POINTER) {
			id = ctf_type_resolve(t.fp, ctf_type_reference(t.fp, id));
			k = ctf_type_kind(t.fp, id);
		}
		switch (k) {
		case CTF_K_INTEGER:
			return (DTC_INT);
		case CTF_K_STRUCT:
			return (DTC_STRUCT);
		case CTF_K_UNION:
			return (DTC_UNION);
		case CTF_K_ENUM:
			return (DTC_ENUM);
		case CTF_K_FORWARD:
			return (DTC_FORWARD);
		default:
			return (DTC_BOTTOM);
		}
	}

	void
	compare(const char *where, size_t i, const char *inferred,
	    const OTy &want, const std::string &subject)
	{
		std::string got = inferred ? inferred : "(null)";
		std::string exp;
		switch (want.kind) {
		case OTy::UNKNOWN:
			return; /* not determinable here */
		case OTy::CTF:
			exp = want.name;
			break;
		case OTy::STRING:
			exp = "string";
			break;
		case OTy::BOTTOM:
			exp = "bottom";
			break;
		case OTy::NONE:
			exp = "none";
			break;
		}
		checked++;
		if (got == exp)
			return;
		std::string why = want.origin.empty() ? subject : want.origin;
		/* Same-size integers with different names: a divergence the
		 * caller must justify. */
		if (want.kind == OTy::CTF) {
			OTy g = lookup_type(got);
			if (g.kind == OTy::CTF) {
				ctf_id_t a = ctf_type_resolve(g.fp, g.id);
				ctf_id_t b = ctf_type_resolve(want.fp, want.id);
				if (ctf_type_kind(g.fp, a) == CTF_K_INTEGER &&
				    ctf_type_kind(want.fp, b) == CTF_K_INTEGER) {
					divergences.push_back({ why, got, exp });
					return;
				}
			}
		}
		failures.push_back(std::string(where) + "[" + std::to_string(i) +
		    "] " + why + ": inferred '" + got + "', expected '" +
		    exp + "'");
	}

	/* Check one DIFO.  `pre' is the code before linking; `post' is the
	 * linked DIFO whose dtdo_types[] holds the inferred names. */
	void
	check(const char *where, const std::vector<dif_instr_t> &pre,
	    const std::string &symtab, const std::vector<uint64_t> &ints,
	    dtrace_difo_t *post, bool symtab_absent = false)
	{
		if (symtab.size() <= 1 && symtab_absent) {
			/* inferDIFO() leaves DIFOs without a symbol table
			 * untouched. */
			if (post->dtdo_types != nullptr)
				failures.push_back(std::string(where) +
				    ": types inferred without a symbol table");
			return;
		}
		if (post->dtdo_types == nullptr) {
			failures.push_back(std::string(where) +
			    ": no inferred types");
			return;
		}
		bool straight = true;
		for (dif_instr_t ins : pre)
			if (is_branch(DIF_INSTR_OP(ins)))
				straight = false;
		OTy reg[256]; /* indexed by any 8-bit instruction field */
		reg[0].kind = OTy::BOTTOM;
		std::map<std::pair<int, uint_t>, OTy> vars; /* (scope, id) */
		for (size_t i = 0; i < pre.size(); i++) {
			dif_instr_t ins = pre[i];
			uint8_t op = DIF_INSTR_OP(ins);
			uint8_t r1 = DIF_INSTR_R1(ins), r2 = DIF_INSTR_R2(ins);
			uint8_t rd = DIF_INSTR_RD(ins);
			OTy t; /* expected type of this instruction */
			std::string subject = "op" + std::to_string(op);
			OTy a = straight ? reg[r1] : OTy();
			OTy b = straight ? reg[r2] : OTy();
			switch (op) {
			case DIF_OP_SETX:
				/* The compiler's type of a decimal constant
				 * (dt_node_int()): int, long, unsigned long. */
				t = named("uint64_t");
				if (DIF_INSTR_INTEGER(ins) < ints.size()) {
					uint64_t v = ints[DIF_INSTR_INTEGER(ins)];
					t = named(v <= INT32_MAX ? "int" :
					    v <= INT64_MAX ? "long" :
					    "unsigned long");
					t.isconst = true;
					t.cval = v;
				}
				break;
			case DIF_OP_USETX:
				t = named("uint64_t");
				t.sym = symtab.c_str() + DIF_INSTR_SYMBOL(ins);
				break;
			case DIF_OP_SETS:
				t.kind = OTy::STRING;
				break;
			case DIF_OP_LDSB: case DIF_OP_RLDSB: case DIF_OP_ULDSB:
				t = named("int8_t");
				break;
			case DIF_OP_LDSH: case DIF_OP_RLDSH: case DIF_OP_ULDSH:
				t = named("int16_t");
				break;
			case DIF_OP_LDSW: case DIF_OP_RLDSW: case DIF_OP_ULDSW:
				t = named("int32_t");
				break;
			case DIF_OP_LDUB: case DIF_OP_RLDUB: case DIF_OP_ULDUB:
				t = named("uint8_t");
				break;
			case DIF_OP_LDUH: case DIF_OP_RLDUH: case DIF_OP_ULDUH:
				t = named("uint16_t");
				break;
			case DIF_OP_LDUW: case DIF_OP_RLDUW: case DIF_OP_ULDUW:
				t = named("uint32_t");
				break;
			case DIF_OP_LDX: case DIF_OP_RLDX: case DIF_OP_ULDX:
				t = named("uint64_t");
				break;
			case DIF_OP_LDGS: {
				uint_t v = DIF_INSTR_VAR(ins);
				if (idents.vars.count(v)) {
					subject = "var:" + idents.varnames[v];
					t = from_decl(idents.vars[v]);
					t.origin = subject;
				} else if (straight && vars.count({ 0, v })) {
					t = vars[{ 0, v }];
				}
				break;
			}
			case DIF_OP_LDTS:
				if (straight && vars.count({ 2, DIF_INSTR_VAR(ins) }))
					t = vars[{ 2, DIF_INSTR_VAR(ins) }];
				break;
			case DIF_OP_LDLS:
				if (straight && vars.count({ 1, DIF_INSTR_VAR(ins) }))
					t = vars[{ 1, DIF_INSTR_VAR(ins) }];
				break;
			case DIF_OP_STGS:
			case DIF_OP_STTS:
			case DIF_OP_STLS: {
				/* stv var, rs: rs is in the low byte. */
				OTy s = straight ? reg[DIF_INSTR_RS(ins)] : OTy();
				int scope = op == DIF_OP_STGS ? 0 :
				    op == DIF_OP_STLS ? 1 : 2;
				if (straight && s.kind != OTy::UNKNOWN) {
					OTy keep = s;
					keep.sym.clear();
					/* A first store of bottom leaves the
					 * variable's type undetermined. */
					if (s.kind != OTy::BOTTOM &&
					    !vars.count({ scope,
					    DIF_INSTR_VAR(ins) }))
						vars[{ scope, DIF_INSTR_VAR(ins) }] =
						    keep;
				}
				t = s.kind == OTy::BOTTOM ? OTy() : s;
				t.sym.clear();
				break;
			}
			case DIF_OP_MOV:
			case DIF_OP_NOT:
				t = a;
				break;
			case DIF_OP_COPYS:
				t = a;
				break;
			case DIF_OP_ALLOCS:
				t.kind = OTy::BOTTOM;
				break;
			case DIF_OP_TYPECAST: {
				std::string s = symtab.c_str() +
				    DIF_INSTR_SYMBOL(ins);
				if (s.rfind("userland ", 0) == 0)
					s = s.substr(9);
				subject = "cast:" + s;
				if (s == "D string")
					t.kind = OTy::STRING;
				else if (s == "bottom")
					t.kind = OTy::BOTTOM;
				else
					t = lookup_type(s);
				break;
			}
			case DIF_OP_ULOAD:
			case DIF_OP_UULOAD:
				if (straight && !a.sym.empty())
					t = member_type(a, a.sym);
				break;
			case DIF_OP_OR: case DIF_OP_XOR: case DIF_OP_AND:
			case DIF_OP_SLL: case DIF_OP_SRL: case DIF_OP_SRA:
			case DIF_OP_ADD: case DIF_OP_SUB: case DIF_OP_MUL:
			case DIF_OP_SDIV: case DIF_OP_UDIV: case DIF_OP_SREM:
			case DIF_OP_UREM:
				if (!straight || a.kind == OTy::UNKNOWN ||
				    b.kind == OTy::UNKNOWN)
					break;
				if (!a.sym.empty() || !b.sym.empty()) {
					/* %r1 : t1  %r2 : uint64_t | sym
					 * => %r3 : t1 | sym */
					OTy other = a.sym.empty() ? a : b;
					OTy symn = a.sym.empty() ? b : a;
					if (!other.sym.empty())
						break; /* both symbolic: not modelled */
					t = other;
					t.sym = symn.sym;
				} else if (a.kind == OTy::BOTTOM) {
					t = b;
				} else if (b.kind == OTy::BOTTOM) {
					t = a;
				} else if (rank(a) != 0 && rank(b) != 0) {
					/* D (dt_type_promote()): no promotion; the
					 * operand of the higher rank (bits, plus one
					 * if unsigned; an enum is an int); a shift
					 * has its left operand's type. */
					bool left = op == DIF_OP_SLL ||
					    op == DIF_OP_SRL || op == DIF_OP_SRA ||
					    rank(a) > rank(b) ||
					    (rank(a) == rank(b) && (a.fp != b.fp ||
					    ctf_type_resolve(a.fp, a.id) >=
					    ctf_type_resolve(b.fp, b.id)));
					t = left ? a : b;
					if (ctf_type_kind(t.fp, ctf_type_resolve(t.fp,
					    t.id)) == CTF_K_ENUM)
						t = named("int");
					t.isconst = false;
				} else {
					int ca = klass(a), cb = klass(b);
					if (ca == DTC_INT && cb == DTC_INT)
						t = a;
					else if (ca == DTC_INT)
						t = b;
					else if (cb == DTC_INT)
						t = a;
					t.sym.clear();
				}
				break;
			case DIF_OP_CALL: {
				uint_t s = DIF_INSTR_SUBR(ins);
				if (idents.subrs.count(s)) {
					subject = "subr:" + idents.subrnames[s];
					t = from_decl(idents.subrs[s]);
					t.origin = subject;
				}
				break;
			}
			case DIF_OP_RET:
				if (straight) {
					t = reg[rd];
					if (!t.sym.empty())
						t = member_type(t, t.sym);
				}
				break;
			case DIF_OP_STB: case DIF_OP_STH: case DIF_OP_STW:
			case DIF_OP_STX:
				/* Typed as the destination address register. */
				t = straight ? reg[rd] : OTy();
				if (t.kind == OTy::BOTTOM)
					t = OTy();
				break;
			case DIF_OP_PUSHTR: case DIF_OP_PUSHTV:
			case DIF_OP_POPTS: case DIF_OP_FLUSHTS:
			case DIF_OP_CMP: case DIF_OP_SCMP: case DIF_OP_TST:
			case DIF_OP_NOP:
				t.kind = OTy::NONE;
				break;
			default:
				if (is_branch(op))
					t.kind = OTy::NONE;
				break;
			}
			if (i < post->dtdo_len)
				compare(where, i, post->dtdo_types[i], t, subject);
			/* Register effects for the data flow. */
			OTy res = t;
			switch (op) {
			case DIF_OP_SETX: case DIF_OP_USETX: case DIF_OP_SETS:
			case DIF_OP_LDSB: case DIF_OP_LDSH: case DIF_OP_LDSW:
			case DIF_OP_LDUB: case DIF_OP_LDUH: case DIF_OP_LDUW:
			case DIF_OP_LDX: case DIF_OP_RLDSB: case DIF_OP_RLDSH:
			case DIF_OP_RLDSW: case DIF_OP_RLDUB: case DIF_OP_RLDUH:
			case DIF_OP_RLDUW: case DIF_OP_RLDX: case DIF_OP_ULDSB:
			case DIF_OP_ULDSH: case DIF_OP_ULDSW: case DIF_OP_ULDUB:
			case DIF_OP_ULDUH: case DIF_OP_ULDUW: case DIF_OP_ULDX:
			case DIF_OP_LDGS: case DIF_OP_LDTS: case DIF_OP_LDLS:
			case DIF_OP_MOV: case DIF_OP_NOT: case DIF_OP_COPYS:
			case DIF_OP_ALLOCS: case DIF_OP_ULOAD: case DIF_OP_UULOAD:
			case DIF_OP_OR: case DIF_OP_XOR: case DIF_OP_AND:
			case DIF_OP_SLL: case DIF_OP_SRL: case DIF_OP_SRA:
			case DIF_OP_ADD: case DIF_OP_SUB: case DIF_OP_MUL:
			case DIF_OP_SDIV: case DIF_OP_UDIV: case DIF_OP_SREM:
			case DIF_OP_CALL:
				/* bcopy, copyout, copyoutstr and copyinto do not
				 * write their destination register (dtrace.c
				 * dtrace_dif_subr()). */
				switch (DIF_INSTR_SUBR(ins)) {
				case DIF_SUBR_BCOPY: case DIF_SUBR_COPYOUT:
				case DIF_SUBR_COPYOUTSTR: case DIF_SUBR_COPYINTO:
					break;
				default:
					reg[rd] = res;
				}
				break;
			case DIF_OP_UREM: case DIF_OP_LDGA:
			case DIF_OP_LDTA: case DIF_OP_LDGAA: case DIF_OP_LDTAA:
				reg[rd] = res;
				break;
			case DIF_OP_TYPECAST:
				/* A cast keeps the register's symbol. */
				res.sym = reg[rd].sym;
				reg[rd] = res;
				break;
			default:
				break;
			}
		}
	}
};

/* Compile, snapshot every DIFO, link, and run the oracle. */
struct Snapshot {
	std::string where;
	std::vector<dif_instr_t> code;
	std::string symtab;
	std::vector<uint64_t> ints;
	dtrace_difo_t *difo;
	bool symtab_absent;
};

inline std::vector<Snapshot>
snapshot(dtrace_prog_t *p)
{
	std::vector<Snapshot> v;
	int n = 0;
	for_each_difo(p, [&](dtrace_stmtdesc_t *, dtrace_actdesc_t *a,
			     dtrace_difo_t *d) {
		Snapshot s;
		s.where = (a == nullptr ? "pred" : "act") + std::to_string(n++);
		s.code.assign(d->dtdo_buf, d->dtdo_buf + d->dtdo_len);
		if (d->dtdo_symtab != nullptr)
			s.symtab.assign(d->dtdo_symtab, d->dtdo_symlen);
		s.symtab.push_back('\0');
		if (d->dtdo_inttab != nullptr)
			s.ints.assign(d->dtdo_inttab,
			    d->dtdo_inttab + d->dtdo_intlen);
		s.difo = d;
		s.symtab_absent = d->dtdo_symtab == nullptr;
		v.push_back(s);
	});
	return (v);
}

} // namespace th

#endif
