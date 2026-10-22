/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Integer casts and arithmetic after linking, against C where D follows C.
 *
 * The compiler implements a cast to a narrower or signed integer type with
 * sll/sra (sign extension) or sll/srl (truncation) before the TYPECAST
 * annotation (dt_cg).  The HyperTrace linker used to turn the sll/sra pair
 * into nops, so `(char)arg0 + 1' saw all 64 bits of arg0; and the type
 * checker gave `(char)x + 1' the type char, so the record shrank to one
 * byte where C (and the compiler) say int.
 *
 * Oracle: C, for what D takes from C -- casts, and arithmetic of a cast
 * value with an int constant (D's rank rule and C agree there: the result
 * is the operand of the higher rank).  D does not promote char and short
 * (dt_type_promote()), so where C and D differ (a shift, or two operands
 * narrower than int) the expected type is D's.  For every integer width
 * and signedness, and argument values at the boundaries, the linked DIFO
 * is run by a small DIF interpreter (sys/dtrace.h semantics, written here,
 * independent of libdtrace) and the record a consumer sees (the low
 * dtdt_size bytes of the returned register) is compared with the expected
 * value, and dtdt_size with the expected type's size.  The record size is
 * also the compiler's (the linker keeps the type the compiler knew).
 */
#include "typing-unit.h"

#include <type_traits>

namespace {

/* Run a linked DIFO with arg0 = a; true and the returned register, or false
 * for an instruction this interpreter does not know. */
bool
run(const dtrace_difo_t *d, uint64_t a, uint64_t *out, std::string *why)
{
	uint64_t r[DIF_DIR_NREGS] = { 0 };
	for (uint_t pc = 0; pc < d->dtdo_len; pc++) {
		dif_instr_t i = d->dtdo_buf[pc];
		uint_t r1 = DIF_INSTR_R1(i), r2 = DIF_INSTR_R2(i),
		    rd = DIF_INSTR_RD(i);
		switch (DIF_INSTR_OP(i)) {
		case DIF_OP_NOP:
			break;
		case DIF_OP_LDGS:
			if (DIF_INSTR_VAR(i) != DIF_VAR_ARG0) {
				*why = "ldgs of another variable";
				return (false);
			}
			r[rd] = a;
			break;
		case DIF_OP_SETX:
			r[rd] = d->dtdo_inttab[DIF_INSTR_INTEGER(i)];
			break;
		case DIF_OP_SLL: r[rd] = r[r1] << (r[r2] & 63); break;
		case DIF_OP_SRL: r[rd] = r[r1] >> (r[r2] & 63); break;
		case DIF_OP_SRA:
			r[rd] = (uint64_t)((int64_t)r[r1] >> (r[r2] & 63));
			break;
		case DIF_OP_ADD: r[rd] = r[r1] + r[r2]; break;
		case DIF_OP_SUB: r[rd] = r[r1] - r[r2]; break;
		case DIF_OP_MUL: r[rd] = r[r1] * r[r2]; break;
		case DIF_OP_AND: r[rd] = r[r1] & r[r2]; break;
		case DIF_OP_OR: r[rd] = r[r1] | r[r2]; break;
		case DIF_OP_XOR: r[rd] = r[r1] ^ r[r2]; break;
		case DIF_OP_MOV: r[rd] = r[r1]; break;
		case DIF_OP_RET:
			*out = r[rd];
			return (true);
		default:
			*why = "opcode " + std::to_string(DIF_INSTR_OP(i));
			return (false);
		}
		r[0] = 0;
	}
	*why = "no ret";
	return (false);
}

uint64_t
low(uint64_t v, size_t size)
{
	return (size >= 8 ? v : v & ((1ULL << (size * 8)) - 1));
}

const int64_t VALUES[] = { 0, 1, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000,
	0xffff, 0x10000, 0x7fffffff, 0x80000000LL, 0xffffffffLL,
	0x100000000LL, -1, -2, -128, -129, -32768, -32769,
	-2147483647LL - 1, INT64_MAX, INT64_MIN };

template <typename T>
void
check_type(const char *dname, int &checked, std::vector<std::string> &bad)
{
	struct E {
		const char *fmt;
		uint64_t (*c)(int64_t, size_t *);
	};
	static const E exprs[] = {
		{ "%s", [](int64_t v, size_t *sz) {
			T x = (T)v;
			*sz = sizeof(x);
			return ((uint64_t)x);
		} },
		{ "%s + 1", [](int64_t v, size_t *sz) {
			T x = (T)v;
			/* C's type for x + 1 (an int constant); wrap like DIF. */
			using R = decltype(x + 1);
			*sz = sizeof(R);
			return ((uint64_t)(R)((uint64_t)(R)x + 1));
		} },
		{ "%s * 2", [](int64_t v, size_t *sz) {
			T x = (T)v;
			using R = decltype(x * 2);
			*sz = sizeof(R);
			return ((uint64_t)(R)((uint64_t)(R)x * 2));
		} },
		{ "%s - 0x7fffffff", [](int64_t v, size_t *sz) {
			T x = (T)v;
			using R = decltype(x - 0x7fffffff);
			*sz = sizeof(R);
			return ((uint64_t)(R)((uint64_t)(R)x - 0x7fffffff));
		} },
	};
	for (const E &e : exprs) {
		char cast[64], expr[128], src[256];
		snprintf(cast, sizeof(cast), "(%s)arg0", dname);
		snprintf(expr, sizeof(expr), e.fmt, cast);
		snprintf(src, sizeof(src), "BEGIN { trace(%s); }", expr);
		dtrace_prog_t *p = compile(src, 0);
		dtrace_difo_t *d = first_action_difo(p);
		uint32_t compiled = d->dtdo_rtype.dtdt_size;
		link_ok(p);
		size_t csize;
		e.c(0, &csize);
		if (d->dtdo_rtype.dtdt_size != csize ||
		    compiled != csize) {
			bad.push_back(std::string(expr) + ": record size " +
			    std::to_string(d->dtdo_rtype.dtdt_size) +
			    " (compiled " + std::to_string(compiled) +
			    "), C " + std::to_string(csize));
			continue;
		}
		for (int64_t v : VALUES) {
			uint64_t got;
			std::string why;
			if (!run(d, (uint64_t)v, &got, &why)) {
				bad.push_back(std::string(expr) + ": " + why);
				break;
			}
			uint64_t want = e.c(v, &csize);
			if (low(got, csize) != low(want, csize)) {
				char m[256];
				snprintf(m, sizeof(m), "%s with arg0 %#jx: got "
				    "%#jx, C %#jx", expr, (uintmax_t)v,
				    (uintmax_t)low(got, csize),
				    (uintmax_t)low(want, csize));
				bad.push_back(m);
			}
			checked++;
		}
	}
}

} // namespace

CASE("integer-casts-match-c")
{
	int checked = 0;
	std::vector<std::string> bad;
	check_type<signed char>("char", checked, bad);
	check_type<unsigned char>("unsigned char", checked, bad);
	check_type<short>("short", checked, bad);
	check_type<unsigned short>("unsigned short", checked, bad);
	check_type<int>("int", checked, bad);
	check_type<unsigned int>("unsigned int", checked, bad);
	check_type<long>("long", checked, bad);
	check_type<unsigned long>("unsigned long", checked, bad);
	check_type<int8_t>("int8_t", checked, bad);
	check_type<uint8_t>("uint8_t", checked, bad);
	check_type<int16_t>("int16_t", checked, bad);
	check_type<uint16_t>("uint16_t", checked, bad);
	check_type<int32_t>("int32_t", checked, bad);
	check_type<uint32_t>("uint32_t", checked, bad);
	check_type<int64_t>("int64_t", checked, bad);
	check_type<uint64_t>("uint64_t", checked, bad);
	printf("integer-casts-match-c: %d evaluations\n", checked);
	for (auto &b : bad)
		printf("  %s\n", b.c_str());
	fflush(stdout);
	CHECK(bad.empty() && checked > 1000);
}

CASE("cast-of-cast-and-shift")
{
	/* Nested casts and a shift (its type is the promoted left
	 * operand's), against C. */
	struct {
		const char *src;
		uint64_t (*c)(int64_t);
		size_t size;
	} cases[] = {
		{ "BEGIN { trace((short)(char)arg0); }",
		    [](int64_t v) { return ((uint64_t)(short)(signed char)v); },
		    sizeof(short) },
		{ "BEGIN { trace((unsigned short)(char)arg0); }",
		    [](int64_t v) {
			return ((uint64_t)(unsigned short)(signed char)v);
		    }, sizeof(unsigned short) },
		{ "BEGIN { trace((int)(unsigned char)arg0); }",
		    [](int64_t v) { return ((uint64_t)(int)(unsigned char)v); },
		    sizeof(int) },
		{ "BEGIN { trace((long)(int)arg0); }",
		    [](int64_t v) { return ((uint64_t)(long)(int)v); },
		    sizeof(long) },
		/* D: a shift has its left operand's type, unpromoted (C
		 * says int; the compiler, D's source of truth, says char). */
		{ "BEGIN { trace((char)arg0 >> 1); }",
		    [](int64_t v) {
			return ((uint64_t)(signed char)((signed char)v >> 1));
		    }, sizeof(signed char) },
	};
	for (auto &c : cases) {
		dtrace_prog_t *p = compile(c.src, 0);
		dtrace_difo_t *d = first_action_difo(p);
		link_ok(p);
		CHECKF(d->dtdo_rtype.dtdt_size == c.size, "%s: size %u",
		    c.src, d->dtdo_rtype.dtdt_size);
		for (int64_t v : VALUES) {
			uint64_t got;
			std::string why;
			CHECKF(run(d, (uint64_t)v, &got, &why), "%s: %s", c.src,
			    why.c_str());
			CHECKF(low(got, c.size) == low(c.c(v), c.size),
			    "%s with %#jx: got %#jx, C %#jx", c.src, (uintmax_t)v,
			    (uintmax_t)low(got, c.size),
			    (uintmax_t)low(c.c(v), c.size));
		}
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
