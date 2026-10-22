/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Integer result types inside a program: the linker's type of an arithmetic
 * instruction against the front end's type of the same expression.
 *
 * The linker types every arithmetic result by D's rules from its operands'
 * types (dt_type_promote(): no integer promotions; the operand of the higher
 * rank).  A constant operand must then have the front end's type for the
 * literal, not one guessed from the value the setx loads: `1u' is an
 * unsigned int, `1l' a long, `0xffffffff' an unsigned int, `sizeof (int)' a
 * size_t, and `-1' an int whose setx value is 2^64 - 1.  The returned record
 * keeps the compiler's type anyway; these intermediate types matter when the
 * value is stored (`this->r = this->v + -1' gives this->r its type) or used
 * again.  The compiler names such a constant's type with a TYPECAST
 * annotation (dt_cg.c, DT_TOK_INT).
 *
 * Programs: the frontend agent's fork A matrix
 * (lib-frontend-20261021/A/linktype; 79 of its 203 programs disagreed
 * before this change and 55 after round 4), plus a few more constants.
 *
 * Oracle: the front end, D's source of truth -- the type it records for
 * this->r in the DIFO's variable table, which the linker does not write.
 */
#include "typing-unit.h"

namespace {

const char *const VTYPES[] = { "int", "unsigned int", "long",
	"unsigned long", "char", "unsigned char", "short" };

const char *const OPERANDS[] = { "+ (1)", "* (1)", "<< (1)", "& (1)",
	"+ (1u)", "+ (1l)", "+ (1ul)", "+ (-1)", "* (-1)", "<< (-1)",
	"& (-1)", "+ (0xffffffff)", "+ (0x100000000)", "+ ((char)1)",
	"+ ((unsigned char)200)", "+ ((short)-1)", "+ ('a')",
	"+ (sizeof (int))", "+ (!5l)", "+ ((unsigned int)-1)", "+ (-1l)",
	"+ (0x80000000u)",
	/* Beyond fork A's matrix. */
	"+ (1ll)", "+ (0x7fffffff)", "+ (0x7fffffffffffffff)",
	"+ (0xffffffffffffffff)", "- (2147483648)", "| (-0x80000000)",
	"+ (1 ? 2u : 3u)", "+ (-(1u))" };

/* The front end's type of this->r, and the linker's type of the last
 * arithmetic instruction (after linking). */
void
types(dtrace_prog_t *p, std::string *fe, std::string *lk)
{
	*fe = *lk = "?";
	for_each_difo(p, [&](dtrace_stmtdesc_t *, dtrace_actdesc_t *,
	    dtrace_difo_t *d) {
		for (uint_t i = 0; i < d->dtdo_varlen; i++) {
			dtrace_difv_t *v = &d->dtdo_vartab[i];
			char buf[256];
			if (strcmp(d->dtdo_strtab + v->dtdv_name, "r") == 0 &&
			    v->dtdv_ctfp != nullptr &&
			    ctf_type_name(v->dtdv_ctfp, v->dtdv_ctfid, buf,
			    sizeof(buf)) != nullptr)
				*fe = buf;
		}
	});
	CHECK(link(p) == 0);
	for_each_difo(p, [&](dtrace_stmtdesc_t *, dtrace_actdesc_t *,
	    dtrace_difo_t *d) {
		if (d->dtdo_types == nullptr)
			return;
		for (uint_t i = 0; i < d->dtdo_len; i++) {
			uint_t o = DIF_INSTR_OP(d->dtdo_buf[i]);
			if (o >= DIF_OP_OR && o <= DIF_OP_UREM &&
			    d->dtdo_types[i] != nullptr)
				*lk = d->dtdo_types[i];
		}
	});
}

void
agree(const char *src, std::vector<std::string> &bad, int *n)
{
	std::string fe, lk;
	types(compile(src, 0), &fe, &lk);
	if (fe == "?" || fe != lk)
		bad.push_back(std::string(src) + ": front end " + fe +
		    ", linker " + lk);
	(*n)++;
}

} // namespace

CASE("constant-literal-types-agree")
{
	std::vector<std::string> bad;
	int n = 0;
	for (const char *t : VTYPES)
		for (const char *op : OPERANDS) {
			char src[256];
			snprintf(src, sizeof(src), "BEGIN { this->v = (%s)arg0; "
			    "this->r = this->v %s; }", t, op);
			agree(src, bad, &n);
		}
	for (auto &b : bad)
		printf("  %s\n", b.c_str());
	printf("  %d programs, %zu disagree\n", n, bad.size());
	fflush(stdout);
	CHECK(bad.empty() && n == 7 * 30);
}

CASE("variable-operand-types-agree")
{
	std::vector<std::string> bad;
	int n = 0;
	for (const char *a : VTYPES)
		for (const char *b : VTYPES) {
			char src[256];
			snprintf(src, sizeof(src), "BEGIN { this->v = (%s)arg0; "
			    "this->w = (%s)arg1; this->r = this->v + this->w; }",
			    a, b);
			agree(src, bad, &n);
		}
	for (auto &b : bad)
		printf("  %s\n", b.c_str());
	fflush(stdout);
	CHECK(bad.empty() && n == 49);
}

CASE("stored-constant-sum-reused")
{
	/* The stored intermediate's type carries on: this->r (an int from
	 * `(int)v + -1') shifted keeps the int, and -1 stays negative. */
	std::vector<std::string> bad;
	int n = 0;
	agree("BEGIN { this->v = (int)arg0; this->s = this->v + -1; "
	    "this->r = this->s << 1; }", bad, &n);
	agree("BEGIN { this->v = (short)arg0; this->s = this->v + 1u; "
	    "this->r = this->s * this->v; }", bad, &n);
	agree("BEGIN { this->v = (char)arg0; this->s = sizeof (int) + 1; "
	    "this->r = this->v + this->s; }", bad, &n);
	for (auto &b : bad)
		printf("  %s\n", b.c_str());
	fflush(stdout);
	CHECK(bad.empty());
}

CASE("annotated-constant-keeps-value")
{
	/* The annotation names the type; the linked program still loads
	 * the constant's value (the TYPECAST becomes a nop). */
	dtrace_prog_t *p = compile("BEGIN { trace((int)arg0 + -1); }", 0);
	dtrace_difo_t *d = first_action_difo(p);
	bool annotated = false;
	for (uint_t i = 0; i < d->dtdo_len; i++)
		if (DIF_INSTR_OP(d->dtdo_buf[i]) == DIF_OP_TYPECAST &&
		    strcmp(d->dtdo_symtab + DIF_INSTR_SYMBOL(d->dtdo_buf[i]),
		    "int") == 0)
			annotated = true;
	CHECK(annotated);
	link_ok(p);
	bool minus1 = false;
	for (uint_t i = 0; i < d->dtdo_len; i++) {
		CHECK(DIF_INSTR_OP(d->dtdo_buf[i]) != DIF_OP_TYPECAST);
		if (DIF_INSTR_OP(d->dtdo_buf[i]) == DIF_OP_SETX &&
		    d->dtdo_inttab[DIF_INSTR_INTEGER(d->dtdo_buf[i])] == ~0ULL)
			minus1 = true;
	}
	CHECK(minus1);
	/* A constant whose value gives its type is not annotated: only the
	 * cast of arg0 is. */
	auto casts = [](const char *src) {
		dtrace_difo_t *dd = first_action_difo(compile(src, 0));
		int c = 0;
		for (uint_t i = 0; i < dd->dtdo_len; i++)
			c += DIF_INSTR_OP(dd->dtdo_buf[i]) == DIF_OP_TYPECAST;
		return (c);
	};
	CHECK(casts("BEGIN { trace((int)arg0 + 1); }") ==
	    casts("BEGIN { trace((int)arg0); }"));
	CHECK(casts("BEGIN { trace((int)arg0 + 1u); }") ==
	    casts("BEGIN { trace((int)arg0); }") + 1);
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
