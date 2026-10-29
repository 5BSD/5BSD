/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Bit-field members of linker-resolved types, through the D compiler and
 * hypertrace_link(), executed.
 *
 * The compiler leaves the load of a member of a type the program does not
 * define to the linker, followed by a field extraction with placeholder
 * shift counts (dt_cg_field_get_reloc()); the linker chooses the load, the
 * member address and the counts from the CTF (relocateBitfieldLoad()).  The
 * types are those of typing-bitfield.h, compiled into the typingbf fixture
 * with cc -g and ctfconvert, so the CTF comes from the compiler's DWARF.
 *
 * The oracle is the C++ compiler's own member access to the same
 * definitions: each linked DIFO is executed by the small DIF evaluator below
 * on a structure whose other bits are random, and its result must equal the
 * member as C++ reads it after storing the value.  The evaluator, like the
 * kernel, refuses a load that is not naturally aligned.
 *
 * The tcp:::state-change case (tcp_state_string[args[3]->tcps_state]) is
 * reproduced with a translator and an inline of the same shapes as tcp.d's:
 * the bit-field was refused, and the linker's walk of every control-flow
 * path for every usetx took time exponential in the inline's conditions (the
 * link never finished).  It must link within a time bound and select the
 * right string for every state.
 *
 * Built and run by typing-inference.py.  Usage: typing-bitfield [case-name].
 */
#include "typing-harness.h"
#include "typing-bitfield.h"

#include <time.h>

#include <algorithm>
#include <random>

using namespace th;

namespace {

/* ---- A DIF evaluator for the instructions these programs use -------- */

struct Eval {
	const dtrace_difo_t *d;
	uint64_t arg0 = 0;
	std::string error;

	bool
	load(uint64_t addr, size_t size, bool sign, uint64_t *v)
	{
		if (addr == 0 || addr % size != 0) {
			error = "misaligned or NULL load of " +
			    std::to_string(size) + " bytes";
			return (false);
		}
		const void *p = (const void *)(uintptr_t)addr;
		switch (size) {
		case 1:
			*v = sign ? (uint64_t)(int64_t)*(const int8_t *)p :
			    *(const uint8_t *)p;
			break;
		case 2:
			*v = sign ? (uint64_t)(int64_t)*(const int16_t *)p :
			    *(const uint16_t *)p;
			break;
		case 4:
			*v = sign ? (uint64_t)(int64_t)*(const int32_t *)p :
			    *(const uint32_t *)p;
			break;
		default:
			*v = *(const uint64_t *)p;
			break;
		}
		return (true);
	}

	/* Run the DIFO; false (with `error') on anything unsupported. */
	bool
	run(uint64_t *result)
	{
		uint64_t r[DIF_DIR_NREGS] = { 0 };
		bool cc_n = false, cc_z = false, cc_c = false;
		uint_t pc = 0;

		for (size_t steps = 0; steps < 100000; steps++) {
			if (pc >= d->dtdo_len) {
				error = "ran off the end";
				return (false);
			}
			dif_instr_t in = d->dtdo_buf[pc++];
			uint8_t op = DIF_INSTR_OP(in);
			uint8_t r1 = DIF_INSTR_R1(in), r2 = DIF_INSTR_R2(in);
			uint8_t rd = DIF_INSTR_RD(in);
			uint64_t v = 0;
			bool taken = false;
			switch (op) {
			case DIF_OP_NOP:
				continue;
			case DIF_OP_SETX:
				if (DIF_INSTR_INTEGER(in) >= d->dtdo_intlen) {
					error = "integer index out of range";
					return (false);
				}
				v = d->dtdo_inttab[DIF_INSTR_INTEGER(in)];
				break;
			case DIF_OP_SETS:
				v = (uint64_t)(uintptr_t)(d->dtdo_strtab +
				    DIF_INSTR_STRING(in));
				break;
			case DIF_OP_LDGS:
				if (DIF_INSTR_VAR(in) != DIF_VAR_ARG0) {
					error = "variable other than arg0";
					return (false);
				}
				v = arg0;
				break;
			case DIF_OP_MOV:
				v = r[r1];
				break;
			case DIF_OP_ADD:
				v = r[r1] + r[r2];
				break;
			case DIF_OP_SUB:
				v = r[r1] - r[r2];
				break;
			case DIF_OP_AND:
				v = r[r1] & r[r2];
				break;
			case DIF_OP_OR:
				v = r[r1] | r[r2];
				break;
			case DIF_OP_XOR:
				v = r[r1] ^ r[r2];
				break;
			case DIF_OP_SLL:
				v = r[r2] >= 64 ? 0 : r[r1] << r[r2];
				break;
			case DIF_OP_SRL:
				v = r[r2] >= 64 ? 0 : r[r1] >> r[r2];
				break;
			case DIF_OP_SRA:
				v = (uint64_t)((int64_t)r[r1] >>
				    (r[r2] >= 64 ? 63 : r[r2]));
				break;
			case DIF_OP_LDUB: case DIF_OP_ULDUB:
			case DIF_OP_LDSB: case DIF_OP_ULDSB:
				if (!load(r[r1], 1, op == DIF_OP_LDSB ||
				    op == DIF_OP_ULDSB, &v))
					return (false);
				break;
			case DIF_OP_LDUH: case DIF_OP_ULDUH:
			case DIF_OP_LDSH: case DIF_OP_ULDSH:
				if (!load(r[r1], 2, op == DIF_OP_LDSH ||
				    op == DIF_OP_ULDSH, &v))
					return (false);
				break;
			case DIF_OP_LDUW: case DIF_OP_ULDUW:
			case DIF_OP_LDSW: case DIF_OP_ULDSW:
				if (!load(r[r1], 4, op == DIF_OP_LDSW ||
				    op == DIF_OP_ULDSW, &v))
					return (false);
				break;
			case DIF_OP_LDX: case DIF_OP_ULDX:
				if (!load(r[r1], 8, false, &v))
					return (false);
				break;
			case DIF_OP_CMP:
			case DIF_OP_TST: {
				uint64_t a = r[r1];
				uint64_t b = op == DIF_OP_CMP ? r[r2] : 0;
				cc_n = (int64_t)(a - b) < 0;
				cc_z = a == b;
				cc_c = op == DIF_OP_CMP && a < b;
				continue;
			}
			case DIF_OP_BA: taken = true; break;
			case DIF_OP_BE: taken = cc_z; break;
			case DIF_OP_BNE: taken = !cc_z; break;
			case DIF_OP_BG: taken = !(cc_z || cc_n); break;
			case DIF_OP_BGU: taken = !(cc_c || cc_z); break;
			case DIF_OP_BGE: taken = !cc_n; break;
			case DIF_OP_BGEU: taken = !cc_c; break;
			case DIF_OP_BL: taken = cc_n; break;
			case DIF_OP_BLU: taken = cc_c; break;
			case DIF_OP_BLE: taken = cc_z || cc_n; break;
			case DIF_OP_BLEU: taken = cc_c || cc_z; break;
			case DIF_OP_RET:
				*result = r[rd];
				return (true);
			default:
				error = "unsupported opcode " + std::to_string(op);
				return (false);
			}
			if (op >= DIF_OP_BA && op <= DIF_OP_BLEU) {
				if (taken)
					pc = DIF_INSTR_LABEL(in);
				continue;
			}
			if (rd != 0)
				r[rd] = v;
		}
		error = "step limit";
		return (false);
	}
};

/* No instruction only the linker resolves may remain. */
void
check_linked(const dtrace_difo_t *d)
{
	for (uint_t i = 0; i < d->dtdo_len; i++) {
		uint8_t op = DIF_INSTR_OP(d->dtdo_buf[i]);
		CHECKF(op != DIF_OP_ULOAD && op != DIF_OP_UULOAD &&
		    op != DIF_OP_USETX && op != DIF_OP_TYPECAST,
		    "unresolved opcode %u at %u", op, i);
	}
}

dtrace_difo_t *
linked_action(const std::string &src)
{
	dtrace_prog_t *p = compile(src.c_str());
	link_ok(p);
	dtrace_difo_t *d = first_action_difo(p);
	check_linked(d);
	return (d);
}

/* The load opcode the linked DIFO uses for its (only) member load. */
uint8_t
member_load(const dtrace_difo_t *d)
{
	uint8_t found = 0;
	for (uint_t i = 0; i < d->dtdo_len; i++) {
		uint8_t op = DIF_INSTR_OP(d->dtdo_buf[i]);
		if ((op >= DIF_OP_LDSB && op <= DIF_OP_LDX) ||
		    (op >= DIF_OP_ULDSB && op <= DIF_OP_ULDX)) {
			CHECKF(found == 0, "more than one load");
			found = op;
		}
	}
	CHECKF(found != 0, "no load");
	return (found);
}

template <typename S>
struct Member {
	const char *name;
	void (*set)(S *, uint64_t);
	int64_t (*get)(const S *);
	unsigned bits;
};

#define BF(S, f, bits) \
	{ #f, [](S *s, uint64_t v) { s->f = v; }, \
	    [](const S *s) { return ((int64_t)s->f); }, bits }

const Member<struct tf_bf> bf_members[] = {
	BF(struct tf_bf, a, 3),
	BF(struct tf_bf, e, 7),
	BF(struct tf_bf, b, 5),
	BF(struct tf_bf, c, 12),
	BF(struct tf_bf, d, 4),
	BF(struct tf_bf, one, 1),
	BF(struct tf_bf, w, 40),
	BF(struct tf_bf, sw, 23),
	BF(struct tf_bf, g, 2),
	BF(struct tf_bf, sg, 3),
	BF(struct tf_bf, h, 9),
	BF(struct tf_bf, nb, 32),
	BF(struct tf_bf, hi, 60),
};

const Member<struct tf_bftcp> tcp_members[] = {
	BF(struct tf_bftcp, t_maxseg, 24),
	BF(struct tf_bftcp, _t_logstate, 8),
	BF(struct tf_bftcp, t_port, 16),
	BF(struct tf_bftcp, t_state, 4),
	BF(struct tf_bftcp, t_idle_reduce, 1),
	BF(struct tf_bftcp, t_delayed_ack, 7),
	BF(struct tf_bftcp, t_fin_is_rst, 1),
	BF(struct tf_bftcp, t_log_state_set, 1),
	BF(struct tf_bftcp, bits_spare, 2),
};

/*
 * The load that must hold member `m', from the C++ compiler's layout: the
 * bits a store of all ones sets, and the smallest naturally aligned unit of
 * 1, 2, 4 or 8 bytes containing them (unsigned, user or kernel).
 */
template <typename S>
uint8_t
expected_load(const Member<S> &m, bool user)
{
	alignas(16) unsigned char buf[sizeof(S)] = { 0 };
	m.set((S *)buf, ~0ULL);
	size_t first = SIZE_MAX, last = 0;
	for (size_t i = 0; i < sizeof(S) * 8; i++) {
		/* Little-endian bit numbering (the hosts the suite runs on). */
		if (buf[i / 8] & (1u << (i % 8))) {
			first = std::min(first, i);
			last = i;
		}
	}
	CHECKF(first != SIZE_MAX && last - first + 1 == m.bits,
	    "%s: %zu..%zu set for %u bits", m.name, first, last, m.bits);
	static const uint8_t k[] = { DIF_OP_LDUB, DIF_OP_LDUH, 0, DIF_OP_LDUW,
		0, 0, 0, DIF_OP_LDX };
	static const uint8_t u[] = { DIF_OP_ULDUB, DIF_OP_ULDUH, 0,
		DIF_OP_ULDUW, 0, 0, 0, DIF_OP_ULDX };
	for (size_t sz = 1; sz <= 8; sz <<= 1) {
		size_t start = first / 8 & ~(sz - 1);
		if (last < (start + sz) * 8)
			return (user ? u[sz - 1] : k[sz - 1]);
	}
	CHECKF(false, "%s: no aligned unit holds it", m.name);
	return (0);
}

/* Values at the edges of a field of `bits' bits, and random ones. */
std::vector<uint64_t>
values(unsigned bits, std::mt19937_64 &rng)
{
	uint64_t mask = bits == 64 ? ~0ULL : (1ULL << bits) - 1;
	std::vector<uint64_t> v = { 0, 1, mask, mask >> 1, (mask >> 1) + 1,
		0x5555555555555555ULL & mask, 0xaaaaaaaaaaaaaaaaULL & mask };
	for (int i = 0; i < 16; i++)
		v.push_back(rng() & mask);
	return (v);
}

/*
 * Link `trace(((T *)arg0)->m)' for every member and execute it on
 * structures with random backgrounds.
 */
template <typename S, size_t N>
void
check_members(const char *type, const Member<S> (&members)[N], bool user)
{
	std::mt19937_64 rng(0x5bd5bd);
	for (auto &m : members) {
		std::string src = std::string("BEGIN { trace(((") +
		    (user ? "userland " : "") + type + " *)arg0)->" + m.name +
		    "); }";
		dtrace_difo_t *d = linked_action(src);
		uint8_t want = expected_load(m, user);
		uint8_t got = member_load(d);
		CHECKF(got == want, "%s.%s: load opcode %u, expected %u", type,
		    m.name, got, want);
		for (uint64_t v : values(m.bits, rng)) {
			alignas(16) unsigned char buf[sizeof(S) + 16];
			for (auto &c : buf)
				c = (unsigned char)rng();
			S *s = (S *)buf;
			m.set(s, v);
			Eval e{ d };
			e.arg0 = (uint64_t)(uintptr_t)s;
			uint64_t r;
			CHECKF(e.run(&r), "%s.%s: %s", type, m.name,
			    e.error.c_str());
			CHECKF((int64_t)r == m.get(s),
			    "%s.%s = %#jx: DIF read %#jx, C++ reads %#jx", type,
			    m.name, (uintmax_t)v, (uintmax_t)r,
			    (uintmax_t)m.get(s));
		}
		fprintf(stderr, "%s.%s: %s ok\n", type, m.name,
		    user ? "user" : "kernel");
	}
}

/* tcp.d's shapes: a translator member read from a bit-field, used as the
 * index of an inline of eleven conditions. */
const char *tcp_prelude =
    "typedef struct tf_info { int32_t st; } tf_info_t;\n"
    "translator tf_info_t < struct tf_bftcp *p > {\n"
    "	st = p == NULL ? -1 : p->t_state;\n"
    "};\n"
    "inline string tf_state_string[int32_t state] =\n"
    "	state == 0 ? \"state-closed\" :\n"
    "	state == 1 ? \"state-listen\" :\n"
    "	state == 2 ? \"state-syn-sent\" :\n"
    "	state == 3 ? \"state-syn-received\" :\n"
    "	state == 4 ? \"state-established\" :\n"
    "	state == 5 ? \"state-close-wait\" :\n"
    "	state == 6 ? \"state-fin-wait-1\" :\n"
    "	state == 7 ? \"state-closing\" :\n"
    "	state == 8 ? \"state-last-ack\" :\n"
    "	state == 9 ? \"state-fin-wait-2\" :\n"
    "	state == 10 ? \"state-time-wait\" :\n"
    "	\"<unknown>\";\n";

const char *state_names[] = { "state-closed", "state-listen",
	"state-syn-sent", "state-syn-received", "state-established",
	"state-close-wait", "state-fin-wait-1", "state-closing",
	"state-last-ack", "state-fin-wait-2", "state-time-wait",
	"<unknown>", "<unknown>", "<unknown>", "<unknown>", "<unknown>" };

double
now()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec + ts.tv_nsec / 1e9);
}

/* Link time bound: the exponential walk did not finish in hours; the
 * linear one takes milliseconds. */
constexpr double LINK_BOUND = 10.0;

dtrace_difo_t *
linked_action_bounded(const std::string &src, double *secs)
{
	dtrace_prog_t *p = compile(src.c_str());
	double t0 = now();
	link_ok(p);
	*secs = now() - t0;
	CHECKF(*secs < LINK_BOUND, "link took %.1f s", *secs);
	dtrace_difo_t *d = first_action_difo(p);
	check_linked(d);
	return (d);
}

} // namespace

CASE("bitfield-members-kernel")
{
	check_members("struct tf_bf", bf_members, false);
}

CASE("bitfield-members-userland")
{
	check_members("struct tf_bf", bf_members, true);
}

CASE("bitfield-tcpcb-word")
{
	check_members("struct tf_bftcp", tcp_members, false);
}

CASE("bitfield-translator-state")
{
	/* args[3]->tcps_state: the translator's ternary over the field. */
	double secs;
	dtrace_difo_t *d = linked_action_bounded(std::string(tcp_prelude) +
	    "BEGIN { trace(xlate<tf_info_t>((struct tf_bftcp *)arg0).st); }",
	    &secs);
	alignas(16) unsigned char buf[sizeof(struct tf_bftcp)];
	std::mt19937_64 rng(42);
	for (unsigned st = 0; st < 16; st++) {
		for (auto &c : buf)
			c = (unsigned char)rng();
		auto *t = (struct tf_bftcp *)buf;
		t->t_state = st;
		Eval e{ d };
		e.arg0 = (uint64_t)(uintptr_t)t;
		uint64_t r;
		CHECKF(e.run(&r), "%s", e.error.c_str());
		CHECKF(r == st, "state %u read as %#jx", st, (uintmax_t)r);
	}
	Eval e{ d };
	uint64_t r;
	CHECKF(e.run(&r) && (int64_t)r == -1, "NULL tcpcb: %#jx",
	    (uintmax_t)r);
}

CASE("bitfield-state-string-bounded")
{
	/* tcp_state_string[args[3]->tcps_state]: links in bounded time
	 * and selects the right string. */
	double secs;
	dtrace_difo_t *d = linked_action_bounded(std::string(tcp_prelude) +
	    "BEGIN { trace(tf_state_string[xlate<tf_info_t>("
	    "(struct tf_bftcp *)arg0).st]); }", &secs);
	fprintf(stderr, "linked in %.3f s\n", secs);
	alignas(16) unsigned char buf[sizeof(struct tf_bftcp)];
	std::mt19937_64 rng(7);
	for (unsigned st = 0; st < 16; st++) {
		for (auto &c : buf)
			c = (unsigned char)rng();
		auto *t = (struct tf_bftcp *)buf;
		t->t_state = st;
		Eval e{ d };
		e.arg0 = (uint64_t)(uintptr_t)t;
		uint64_t r;
		CHECKF(e.run(&r), "%s", e.error.c_str());
		CHECKF(strcmp((const char *)(uintptr_t)r, state_names[st]) == 0,
		    "state %u: '%s'", st, (const char *)(uintptr_t)r);
	}
}

CASE("bitfield-state-string-twice-bounded")
{
	/* Two such lookups in one action (each a chain of conditions, the
	 * second after the first): still linear. */
	double secs;
	dtrace_difo_t *d = linked_action_bounded(std::string(tcp_prelude) +
	    "BEGIN { trace(strjoin(tf_state_string[xlate<tf_info_t>("
	    "(struct tf_bftcp *)arg0).st], tf_state_string[xlate<tf_info_t>("
	    "(struct tf_bftcp *)arg1).st])); }", &secs);
	fprintf(stderr, "linked in %.3f s (%u instructions)\n", secs,
	    d->dtdo_len);
}

CASE("bitfield-state-string-variable-bounded")
{
	/* A clause-local variable stored before the first lookup and loaded
	 * after it (a variable definition live across the conditions). */
	double secs;
	dtrace_difo_t *d = linked_action_bounded(std::string(tcp_prelude) +
	    "BEGIN { trace(strjoin(tf_state_string[xlate<tf_info_t>("
	    "(this->p = (struct tf_bftcp *)arg0)).st], "
	    "tf_state_string[xlate<tf_info_t>(this->p).st])); }", &secs);
	fprintf(stderr, "linked in %.3f s (%u instructions)\n", secs,
	    d->dtdo_len);
}

CASE("embedded-member-translator")
{
	/* tcps_lport = p->t_inpcb.inp_inc.inc_ie.ie_lport: a member of a
	 * structure embedded in a structure the pointer points to (the type
	 * checker looked for it in the type the embedded structure
	 * "references" and failed). */
	double secs;
	dtrace_difo_t *d = linked_action_bounded(
	    "typedef struct tf_info3 { int32_t lport; } tf_info3_t;\n"
	    "translator tf_info3_t < struct tf_bftcp *p > {\n"
	    "	lport = p == NULL ? -1 : p->t_inpcb.inp_inc.ie_lport;\n"
	    "};\n"
	    "BEGIN { trace(xlate<tf_info3_t>((struct tf_bftcp *)arg0).lport); }",
	    &secs);
	alignas(16) unsigned char buf[sizeof(struct tf_bftcp)];
	std::mt19937_64 rng(3);
	for (uint32_t port : { 0u, 1u, 80u, 0x8000u, 0xffffu }) {
		for (auto &c : buf)
			c = (unsigned char)rng();
		auto *t = (struct tf_bftcp *)buf;
		t->t_inpcb.inp_inc.ie_lport = (uint16_t)port;
		Eval e{ d };
		e.arg0 = (uint64_t)(uintptr_t)t;
		uint64_t r;
		CHECKF(e.run(&r), "%s", e.error.c_str());
		CHECKF(r == port, "port %u read as %#jx", port, (uintmax_t)r);
	}
}

CASE("stack-pushes-after-conditions-bounded")
{
	/* tcp.d's tcpsinfo_t assigned to a clause variable: subroutine calls
	 * whose arguments follow conditions, many in one DIFO.  The tuple
	 * stack walk enumerated every path. */
	std::string src = std::string(tcp_prelude) +
	    "typedef struct tf_info4 { int32_t st; string s0; "
	    "string s1; string s2; string s3; } tf_info4_t;\n"
	    "translator tf_info4_t < struct tf_bftcp *p > {\n"
	    "	st = p == NULL ? -1 : p->t_flags;\n";
	/* No bit-field or embedded member: the walk alone is exercised. */
	for (int i = 0; i < 4; i++)
		src += "	s" + std::to_string(i) + " = p == NULL ? \"<unknown>\" : "
		    "strjoin(lltostr(p->t_flags), "
		    "tf_state_string[p->t_flags & 0xf]);\n";
	src += "};\nBEGIN { this->t = xlate<tf_info4_t>("
	    "(struct tf_bftcp *)arg0); trace(this->t.st); }";
	double secs;
	dtrace_prog_t *p = compile(src.c_str());
	double t0 = now();
	link_ok(p);
	secs = now() - t0;
	CHECKF(secs < LINK_BOUND, "link took %.1f s", secs);
	for_each_difo(p, [](dtrace_stmtdesc_t *, dtrace_actdesc_t *,
	    dtrace_difo_t *d) { check_linked(d); });
	fprintf(stderr, "linked in %.3f s\n", secs);
}

CASE("bitfield-unholdable-refused")
{
	/* q (60 bits at bit 8 of a packed structure) spans nine bytes. */
	dtrace_prog_t *p = compile(
	    "BEGIN { trace(((struct tf_bfpacked *)arg0)->q); }");
	std::string msg;
	int r = link(p, &msg);
	CHECKF(r == E_HYPERTRACE_LINKING &&
	    msg.find("no aligned load of at most 8 bytes holds it") !=
	    std::string::npos, "%d: %s", r, msg.c_str());
}

CASE("bitfield-placeholder-shape")
{
	/* The compiler's extraction directly follows the member load, with
	 * zero counts (an identity until linked). */
	dtrace_prog_t *p = compile(
	    "BEGIN { trace(((struct tf_bftcp *)arg0)->t_state); }");
	dtrace_difo_t *d = first_action_difo(p);
	uint_t i = 0;
	while (i < d->dtdo_len && DIF_INSTR_OP(d->dtdo_buf[i]) != DIF_OP_ULOAD)
		i++;
	CHECK(i + 4 < d->dtdo_len);
	uint8_t rd = DIF_INSTR_RD(d->dtdo_buf[i]);
	uint8_t rt = DIF_INSTR_RD(d->dtdo_buf[i + 1]);
	CHECK(DIF_INSTR_OP(d->dtdo_buf[i + 1]) == DIF_OP_SETX);
	CHECK(d->dtdo_inttab[DIF_INSTR_INTEGER(d->dtdo_buf[i + 1])] == 0);
	CHECK(d->dtdo_buf[i + 2] ==
	    (dif_instr_t)DIF_INSTR_FMT(DIF_OP_SLL, rd, rt, rd));
	CHECK(DIF_INSTR_OP(d->dtdo_buf[i + 3]) == DIF_OP_SETX);
	CHECK(d->dtdo_inttab[DIF_INSTR_INTEGER(d->dtdo_buf[i + 3])] == 0);
	CHECK(d->dtdo_buf[i + 4] ==
	    (dif_instr_t)DIF_INSTR_FMT(DIF_OP_SRL, rd, rt, rd));

	/* A non-zero count is not the compiler's placeholder: refused. */
	d->dtdo_inttab[DIF_INSTR_INTEGER(d->dtdo_buf[i + 3])] = 5;
	std::string msg;
	int r = link(p, &msg);
	CHECKF(r == E_HYPERTRACE_LINKING &&
	    msg.find("is not followed by a field extraction") !=
	    std::string::npos, "%d: %s", r, msg.c_str());
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
