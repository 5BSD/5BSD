/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * hypertrace_link() on hand-assembled and mutated DIFOs.
 *
 * A compiled stub program ("BEGIN { trace(1); }") provides the statement,
 * ECB and action; its action DIFO is replaced by code assembled here with
 * the sys/dtrace.h DIF_INSTR_* encoders.  Each case states the outcome the
 * linker must produce: a successful link with specific relocations, an
 * E_HYPERTRACE_* return code with a diagnostic, or a program error
 * (dt_set_progerr()) recorded in the program and returned.
 */
#include "typing-oracle.h"

using namespace th;
using namespace dtrace;

namespace {

void
expect_link(dtrace_prog_t *p, int code, const char *text)
{
	std::string msg;
	int r = link(p, &msg);
	CHECKF(r == code, "link returned %d (%s), expected %d", r, msg.c_str(),
	    code);
	CHECKF(msg.find(text) != std::string::npos, "message '%s' lacks '%s'",
	    msg.c_str(), text);
}

/* setx 1, %r1; ret %r1 -- a minimal valid body to mutate. */
Difo
ret_one()
{
	Difo d;
	d.code = { DIF_INSTR_SETX(d.integer(1), 1), DIF_INSTR_RET(1) };
	return (d);
}

dtrace_difo_t *
act(dtrace_prog_t *p)
{
	return (first_action_difo(p));
}

} // namespace

/* ---- Malformed DIFO shapes (computeDFG) ---------------------------- */

CASE("dfo-empty-code")
{
	dtrace_prog_t *p = program_with(ret_one());
	act(p)->dtdo_len = 0;
	expect_link(p, E_HYPERTRACE_LINKING, "has no instructions");
}

CASE("dfo-null-code")
{
	dtrace_prog_t *p = program_with(ret_one());
	act(p)->dtdo_buf = nullptr;
	expect_link(p, E_HYPERTRACE_LINKING, "has no instructions");
}

CASE("dfo-missing-inttab")
{
	dtrace_prog_t *p = program_with(ret_one());
	act(p)->dtdo_inttab = nullptr;
	expect_link(p, E_HYPERTRACE_LINKING, "missing table");
}

CASE("dfo-missing-strtab")
{
	dtrace_prog_t *p = program_with(ret_one());
	act(p)->dtdo_strtab = nullptr;
	act(p)->dtdo_strlen = 4;
	expect_link(p, E_HYPERTRACE_LINKING, "missing table");
}

CASE("dfo-missing-vartab")
{
	dtrace_prog_t *p = program_with(ret_one());
	act(p)->dtdo_vartab = nullptr;
	act(p)->dtdo_varlen = 1;
	expect_link(p, E_HYPERTRACE_LINKING, "missing table");
}

CASE("dfo-missing-symtab")
{
	dtrace_prog_t *p = program_with(ret_one());
	act(p)->dtdo_symtab = nullptr;
	act(p)->dtdo_symlen = 3;
	expect_link(p, E_HYPERTRACE_LINKING, "missing table");
}

/* Without a symbol table there is nothing to relocate: the DIFO is left
 * untyped and its code unchanged. */
CASE("dfo-no-symtab-untouched")
{
	Difo d = ret_one();
	d.symtab = false;
	dtrace_prog_t *p = program_with(d);
	link_ok(p);
	CHECK(act(p)->dtdo_types == nullptr);
	CHECK(DIF_INSTR_OP(act(p)->dtdo_buf[0]) == DIF_OP_SETX);
}

/* ---- Subroutine calls ---------------------------------------------- */

/*
 * Branch labels (DIF: a branch's target is an instruction index of its own
 * DIFO, and code continues after a conditional branch).  Both used to end
 * the process (errx in computeBasicBlocks()).
 */
CASE("dfo-branch-outside-code")
{
	Difo d;
	d.code = { DIF_INSTR_SETX(d.integer(1), 1), DIF_INSTR_BRANCH(DIF_OP_BE, 7),
		DIF_INSTR_RET(1) };
	dtrace_prog_t *p = program_with(d);
	expect_link(p, E_HYPERTRACE_LINKING,
	    "branch at 1 to 7 is outside of the DIFO's 3 instructions");
}

CASE("dfo-branch-at-end")
{
	Difo d;
	d.code = { DIF_INSTR_SETX(d.integer(1), 1), DIF_INSTR_RET(1),
		DIF_INSTR_BRANCH(DIF_OP_BA, 0) };
	dtrace_prog_t *p = program_with(d);
	expect_link(p, E_HYPERTRACE_LINKING,
	    "branch at 2 to 0 is outside of the DIFO's 3 instructions");
}

/* ---- Malformed statements (link()) ---------------------------------- */
namespace {
dt_stmt_t *
first_stmt(dtrace_prog_t *p)
{
	return ((dt_stmt_t *)dt_list_next(&p->dp_stmts));
}
} // namespace

CASE("stmt-without-actions-links")
{
	/* A clause without actions has a statement without an action
	 * list: nothing to link, and the program links. */
	dtrace_prog_t *p = compile("BEGIN {} END { trace(1); }");
	CHECK(first_stmt(p)->ds_desc->dtsd_action == nullptr);
	link_ok(p);
}

CASE("stmt-without-description")
{
	dtrace_prog_t *p = compile("BEGIN { trace(1); }");
	first_stmt(p)->ds_desc = nullptr;
	expect_link(p, E_HYPERTRACE_LINKING, "description is NULL");
}

CASE("stmt-without-ecb-description")
{
	dtrace_prog_t *p = compile("BEGIN { trace(1); }");
	first_stmt(p)->ds_desc->dtsd_ecbdesc = nullptr;
	expect_link(p, E_HYPERTRACE_LINKING, "ecbdesc is NULL");
}

CASE("stmt-without-last-action")
{
	dtrace_prog_t *p = compile("BEGIN { trace(1); }");
	first_stmt(p)->ds_desc->dtsd_action_last = nullptr;
	expect_link(p, E_HYPERTRACE_LINKING, "but last action is NULL");
}

CASE("predicate-shape-and-variables")
{
	{
		/* A predicate is checked like an action. */
		dtrace_prog_t *p = compile("BEGIN /pid != 0/ { trace(1); }");
		dtrace_difo_t *pd =
		    first_stmt(p)->ds_desc->dtsd_ecbdesc->dted_pred.dtpdd_difo;
		CHECK(pd != nullptr);
		pd->dtdo_len = 0;
		expect_link(p, E_HYPERTRACE_LINKING, "has no instructions");
	}
	{
		/* A predicate reading a variable its table does not have. */
		dtrace_prog_t *p = compile("BEGIN { x = 1; } END /x == 1/ { trace(1); }");
		dt_stmt_t *st = (dt_stmt_t *)dt_list_next(first_stmt(p));
		dtrace_difo_t *pd =
		    st->ds_desc->dtsd_ecbdesc->dted_pred.dtpdd_difo;
		CHECK(pd != nullptr && pd->dtdo_varlen > 0);
		pd->dtdo_varlen = 0;
		expect_link(p, E_HYPERTRACE_LINKING, "failed to find variable");
	}
}

CASE("fall-through-definition-is-type-checked")
{
	/*
	 * r2 is a D string on the branch path and an integer on the
	 * fall-through path into the label: the use must see both
	 * definitions and reject the program (it saw only the string).
	 *   sets "a" -> r2; setx 1 -> r1; tst r1; be L; setx 7 -> r2;
	 *   L: ret r2
	 */
	Difo d;
	d.code = { DIF_INSTR_SETS(d.str("a"), 2),
		DIF_INSTR_SETX(d.integer(1), 1), DIF_INSTR_TST(1),
		DIF_INSTR_BRANCH(DIF_OP_BE, 5),
		DIF_INSTR_SETX(d.integer(7), 2), DIF_INSTR_RET(2) };
	dtrace_prog_t *p = program_with(d);
	std::string msg;
	int r = link(p, &msg);
	CHECKF(r == E_HYPERTRACE_TYPING, "link returned %d: %s", r,
	    msg.c_str());
}

CASE("call-unknown-subroutine")
{
	Difo d;
	d.code = { DIF_INSTR_CALL(DIF_SUBR_MAX + 7, 1), DIF_INSTR_RET(1) };
	dtrace_prog_t *p = program_with(d);
	expect_link(p, E_HYPERTRACE_TYPING, "unknown subroutine 62");
}

CASE("call-getmajor-unsupported")
{
	Difo d;
	d.code = { DIF_INSTR_CALL(DIF_SUBR_GETMAJOR, 1), DIF_INSTR_RET(1) };
	dtrace_prog_t *p = program_with(d);
	expect_link(p, E_HYPERTRACE_TYPING, "getmajor() is not supported");
}

PROGERR_CASE("call-missing-arguments",
    "strlen(): 1 argument(s) required, 0 on the stack")
{
	Difo d;
	d.code = { DIF_INSTR_FLUSHTS, DIF_INSTR_CALL(DIF_SUBR_STRLEN, 1),
		DIF_INSTR_RET(1) };
	link(program_with(d));
}

PROGERR_CASE("call-string-for-pointer",
    "mutex_owned(): argument at 1 has D string type where struct mtx * is "
    "expected")
{
	Difo d;
	uint_t s = d.str("lock");
	d.code = { DIF_INSTR_SETS(s, 1),
		DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 0, 1),
		DIF_INSTR_CALL(DIF_SUBR_MUTEX_OWNED, 1), DIF_INSTR_RET(1) };
	link(program_with(d));
}

/* ---- Member relocation ----------------------------------------------
 * ldgs arg0, %r1; typecast "struct S *", %r1; usetx "m", %r2;
 * add %r1, %r2, %r1; [u]uload [%r1], %r3; ret %r3
 * must become: setx <byte offset of m>, the load of m's width and
 * signedness (or ldx for pointers and arrays), and nops for the cast.  The
 * expected offset and load come from libctf on the fixture's CTF.
 */
namespace {
struct MemberLoad {
	Difo d;
	uint_t cast, member;
	MemberLoad(const char *type, const char *m, uint8_t load = DIF_OP_ULOAD)
	{
		cast = d.sym(type);
		member = d.sym(m);
		d.code = { DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_ARG0, 1),
			DIF_INSTR_TYPECAST(cast, 1), DIF_INSTR_USETX(member, 2),
			DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1),
			(dif_instr_t)DIF_INSTR_LOAD(load, 1, 3), DIF_INSTR_RET(3) };
	}
};

/* The load libctf's description of a member calls for. */
uint8_t
expected_load(ctf_file_t *fp, ctf_id_t type, bool user)
{
	ctf_id_t t = ctf_type_resolve(fp, type);
	int k = ctf_type_kind(fp, t);
	if (k == CTF_K_POINTER || k == CTF_K_ARRAY)
		return (user ? DIF_OP_ULDX : DIF_OP_LDX);
	ctf_encoding_t e;
	CHECK(ctf_type_encoding(fp, t, &e) == 0);
	bool sign = (e.cte_format & CTF_INT_SIGNED) != 0;
	static const uint8_t k_ops[2][4] = {
		{ DIF_OP_LDUB, DIF_OP_LDUH, DIF_OP_LDUW, DIF_OP_LDX },
		{ DIF_OP_LDSB, DIF_OP_LDSH, DIF_OP_LDSW, DIF_OP_LDX } };
	static const uint8_t u_ops[2][4] = {
		{ DIF_OP_ULDUB, DIF_OP_ULDUH, DIF_OP_ULDUW, DIF_OP_ULDX },
		{ DIF_OP_ULDSB, DIF_OP_ULDSH, DIF_OP_ULDSW, DIF_OP_ULDX } };
	int w = ctf_type_size(fp, t) == 1 ? 0 : ctf_type_size(fp, t) == 2 ? 1 :
	    ctf_type_size(fp, t) == 4 ? 2 : 3;
	return (user ? u_ops[sign][w] : k_ops[sign][w]);
}
} // namespace

CASE("reloc-member-loads")
{
	static const char *members[] = { "c", "s", "i", "l", "uc", "us", "ui",
		"ul", "vp" };
	for (uint8_t load : { DIF_OP_ULOAD, DIF_OP_UULOAD }) {
		for (const char *m : members) {
			MemberLoad ml("struct tf_sub8 *", m, load);
			dtrace_prog_t *p = program_with(ml.d);
			link_ok(p);
			dtrace_difo_t *d = act(p);
			dtrace_typeinfo_t tip;
			CHECK(dtrace_lookup_by_type(handle(), "typingfix",
			    "struct tf_sub8", &tip) == 0);
			ctf_membinfo_t mi;
			CHECK(ctf_member_info(tip.dtt_ctfp, tip.dtt_type, m,
			    &mi) == 0);
			dif_instr_t setx = d->dtdo_buf[2];
			CHECK(DIF_INSTR_OP(setx) == DIF_OP_SETX);
			CHECK(DIF_INSTR_RD(setx) == 2);
			CHECK(d->dtdo_inttab[DIF_INSTR_INTEGER(setx)] ==
			    mi.ctm_offset / 8);
			dif_instr_t ld = d->dtdo_buf[4];
			CHECKF(DIF_INSTR_OP(ld) == expected_load(tip.dtt_ctfp,
			    mi.ctm_type, load == DIF_OP_UULOAD), "%s: op %u", m,
			    DIF_INSTR_OP(ld));
			CHECK(DIF_INSTR_R1(ld) == 1 && DIF_INSTR_RD(ld) == 3);
			CHECK(d->dtdo_buf[1] == DIF_INSTR_NOP);
		}
	}
}

CASE("reloc-array-and-far-members")
{
	/* Returning an array member (char name[8] at byte 16) returns it by
	 * reference: the load is dropped so that the address is the result,
	 * and the return type is the 8-byte array. */
	MemberLoad a("struct tf_arr *", "name");
	dtrace_prog_t *p = program_with(a.d);
	/* The compiler could not type it (guest data): the linker does. */
	act(p)->dtdo_rtype.dtdt_kind = DIF_TYPE_BOTTOM;
	link_ok(p);
	CHECK(act(p)->dtdo_buf[4] == DIF_INSTR_NOP);
	CHECK(act(p)->dtdo_inttab[DIF_INSTR_INTEGER(act(p)->dtdo_buf[2])] == 16);
	CHECK((act(p)->dtdo_rtype.dtdt_flags & DIF_TF_BYREF) != 0);
	CHECK(act(p)->dtdo_rtype.dtdt_size == 8);
	/* A member 70000 bytes in keeps its full offset. */
	MemberLoad f("struct tf_huge *", "far");
	p = program_with(f.d);
	link_ok(p);
	CHECK(act(p)->dtdo_inttab[DIF_INSTR_INTEGER(act(p)->dtdo_buf[2])] ==
	    70000);
}

CASE("reloc-unsupported-members")
{
	struct {
		const char *type, *member, *text;
	} rows[] = {
		{ "struct tf_bits *", "x", "unsupported bitfield encoding" },
		{ "struct tf_flt *", "f", "a load of kind 2 is unsupported" },
		{ "struct tf_wide *", "s128", "unsupported size 16" },
		{ "struct tf_wide *", "u128", "unsupported size 16" },
		{ "struct tf_pair *", "a", "" },
	};
	for (auto &r : rows) {
		MemberLoad ml(r.type, r.member);
		dtrace_prog_t *p = program_with(ml.d);
		std::string msg;
		int e = link(p, &msg);
		if (*r.text == '\0') {
			CHECK(e == 0);
			continue;
		}
		CHECKF(e == E_HYPERTRACE_LINKING &&
		    msg.find(r.text) != std::string::npos, "%s.%s: %d %s",
		    r.type, r.member, e, msg.c_str());
	}
}

CASE("reloc-member-address-not-byte-aligned")
{
	/* Returning &((struct tf_bits *)arg0)->y: y starts at bit 3. */
	Difo d;
	d.code = { DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_ARG0, 1),
		DIF_INSTR_TYPECAST(d.sym("struct tf_bits *"), 1),
		DIF_INSTR_USETX(d.sym("y"), 2),
		DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1), DIF_INSTR_RET(1) };
	expect_link(program_with(d), E_HYPERTRACE_LINKING,
	    "member offset 3 is not byte aligned");
}

CASE("reloc-member-address-returned")
{
	/* &((struct tf_pair *)arg0)->b: the usetx becomes the offset 8 and
	 * the return describes the member. */
	Difo d;
	d.code = { DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_ARG0, 1),
		DIF_INSTR_TYPECAST(d.sym("struct tf_pair *"), 1),
		DIF_INSTR_USETX(d.sym("b"), 2),
		DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 1), DIF_INSTR_RET(1) };
	dtrace_prog_t *p = program_with(d);
	link_ok(p);
	dtrace_difo_t *a = act(p);
	CHECK(DIF_INSTR_OP(a->dtdo_buf[2]) == DIF_OP_SETX);
	CHECK(a->dtdo_inttab[DIF_INSTR_INTEGER(a->dtdo_buf[2])] == 8);
}

CASE("reloc-integer-table-index-limit")
{
	/* A DIFO whose integer table already holds 65536 distinct values
	 * cannot index a new member offset with 16 bits. */
	MemberLoad ml("struct tf_pair *", "b");
	for (uint64_t v = 0; v < 65536; v++)
		ml.d.integer(0x1000000 + v);
	expect_link(program_with(ml.d), E_HYPERTRACE_LINKING,
	    "DIF integer table index 65536 exceeds 16 bits");
}

CASE("reloc-unterminated-symbols")
{
	/* A symbol must be a NUL-terminated string inside the table: the
	 * last name of a table cut short is rejected before it is read. */
	for (int which = 0; which < 2; which++) {
		MemberLoad ml("struct tf_pair *", "b");
		dtrace_prog_t *p = program_with(ml.d);
		dtrace_difo_t *a = act(p);
		uint_t sym = which == 0 ? ml.member : ml.cast;
		a->dtdo_symlen = sym + 1; /* cuts the string after one byte */
		if (which == 1)
			a->dtdo_buf[2] = DIF_INSTR_USETX(0, 2);
		expect_link(p, E_HYPERTRACE_TYPING, "is not a string in the");
	}
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
