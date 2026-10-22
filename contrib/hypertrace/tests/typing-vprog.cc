/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The guest-side forwarding program (dtrace_vprog_from(), dt_program.c).
 *
 * A guest firing forwards its probe to the host with one hypercall; the
 * hypercall names only the probe, and the host runs every clause enabled on
 * its vprobe for each one.  So a probe must be forwarded by exactly one
 * statement holding one hypercall, whatever the number of clauses and
 * actions: the compiler makes one statement per action, and forwarding each
 * made a clause with N actions run every host action (and predicate) N
 * times per guest firing (before this change, `BEGIN { trace(1); trace(2);
 * trace(3); }' gave 3 forwarding statements; lib-typing-20261021/vp.log).
 * The single hypercall also has to carry every argument any clause of the
 * probe reads: each statement used to load only the arguments of the
 * actions seen before it was built.
 *
 * Oracles: the source program's own statements (probes, actions, the
 * arguments their DIFOs read) and the DIF the forwarding statement holds.
 */
#include "typing-unit.h"

namespace {

struct Fwd {
	std::string probe;
	int hypercalls = 0;
	uint_t frames = 0;
	std::set<uint_t> args;	/* stack arguments (arg5..arg9) loaded */
	std::vector<int> kinds;	/* action kinds, in order */
	bool predicate = false;
	bool vtime = false;
};

std::vector<Fwd>
forwarding(const char *src, dtrace_prog_t **srcp = nullptr)
{
	dtrace_prog_t *p = compile(src);
	link_ok(p);
	if (srcp != nullptr)
		*srcp = p;
	dtrace_prog_t *v = dtrace_vprog_from(handle(), p, PGP_KIND_HYPERCALLS);
	CHECKF(v != nullptr, "%s: %s", src,
	    dtrace_errmsg(handle(), dtrace_errno(handle())));
	std::vector<Fwd> out;
	for (dt_stmt_t *st = (dt_stmt_t *)dt_list_next(&v->dp_stmts); st;
	    st = (dt_stmt_t *)dt_list_next(st)) {
		Fwd f;
		dtrace_ecbdesc_t *e = st->ds_desc->dtsd_ecbdesc;
		f.probe = std::string(e->dted_probe.dtpd_provider) + ":" +
		    e->dted_probe.dtpd_name;
		f.predicate = e->dted_pred.dtpdd_difo != nullptr;
		for (dtrace_actdesc_t *a = st->ds_desc->dtsd_action; a;
		    a = a->dtad_next) {
			f.kinds.push_back((int)a->dtad_kind);
			dtrace_difo_t *d = a->dtad_difo;
			for (uint_t i = 0; d != nullptr && i < d->dtdo_len; i++) {
				dif_instr_t ins = d->dtdo_buf[i];
				uint8_t op = DIF_INSTR_OP(ins);
				if (op == DIF_OP_HYPERCALL) {
					f.hypercalls++;
					f.frames = DIF_INSTR_R1(ins);
				}
				if (op == DIF_OP_LDGS) {
					uint_t var = DIF_INSTR_VAR(ins);
					if (var >= DIF_VAR_ARG0 &&
					    var <= DIF_VAR_ARG9)
						f.args.insert(var - DIF_VAR_ARG0);
					if (var == DIF_VAR_VTIMESTAMP)
						f.vtime = true;
				}
			}
			if (a == st->ds_desc->dtsd_action_last)
				break;
		}
		out.push_back(f);
	}
	return (out);
}

} // namespace

CASE("one-hypercall-for-a-clause-of-several-actions")
{
	/* (arg0..arg4 travel in the hypercall's registers; the stack
	 * arguments arg5..arg9 are loaded by the forwarding DIFO.) */
	auto f = forwarding("BEGIN { trace(1); trace(arg6); "
	    "printf(\"%d\", arg7); }");
	CHECKF(f.size() == 1, "%zu forwarding statements", f.size());
	CHECK(f[0].hypercalls == 1 && !f[0].predicate);
	CHECK(f[0].kinds == std::vector<int>({ DTRACEACT_DIFEXPR }));
	CHECK(f[0].args == std::set<uint_t>({ 6, 7 }));
}

CASE("one-hypercall-for-the-clauses-of-a-probe")
{
	/* Two clauses on BEGIN (one with a predicate) and one on END: one
	 * forwarding statement per probe, without predicates (the host
	 * evaluates them, once per firing), loading every argument either
	 * clause reads -- including one read only by the later clause. */
	auto f = forwarding("BEGIN /arg5 == 1/ { trace(arg6); } "
	    "END { trace(arg8); } BEGIN { trace(arg9); trace(2); }");
	CHECK(f.size() == 2);
	std::map<std::string, Fwd> by;
	for (auto &x : f)
		by[x.probe] = x; /* (compiled with PROBESPEC_NAME: no provider) */
	CHECK(by.count(":BEGIN") && by.count(":END"));
	CHECK(by[":BEGIN"].hypercalls == 1 &&
	    by[":END"].hypercalls == 1);
	CHECK(!by[":BEGIN"].predicate && !by[":END"].predicate);
	CHECK(by[":BEGIN"].args == std::set<uint_t>({ 5, 6, 9 }));
	CHECK(by[":END"].args == std::set<uint_t>({ 8 }));
}

CASE("stack-frames-and-time-of-all-clauses")
{
	/* The hypercall carries the most frames any stack() of the probe
	 * asks for, and the guest's virtual time when any clause uses it. */
	auto f = forwarding("BEGIN { stack(5); } BEGIN { trace(1); } "
	    "BEGIN { stack(9); trace(vtimestamp); }");
	CHECK(f.size() == 1);
	CHECK(f[0].hypercalls == 1 && f[0].frames == 9 && f[0].vtime);
}

CASE("one-immediate-stack-capture-per-probe")
{
	/* A guest immstack() captures the firing's stack into the buffer the
	 * hypercall sends, and each host printimmstack() prints that buffer
	 * (dtrace.c): one capture, before the hypercall, serves every
	 * clause; the source actions become printimmstack(). */
	dtrace_prog_t *src;
	auto f = forwarding("BEGIN { immstack(3); trace(1); } "
	    "BEGIN { immstack(7); }", &src);
	CHECK(f.size() == 1);
	CHECK(f[0].kinds == std::vector<int>({ DTRACEACT_IMMSTACK,
	    DTRACEACT_DIFEXPR }));
	int printing = 0;
	for (dt_stmt_t *st = (dt_stmt_t *)dt_list_next(&src->dp_stmts); st;
	    st = (dt_stmt_t *)dt_list_next(st))
		for (dtrace_actdesc_t *a = st->ds_desc->dtsd_action; a;
		    a = a == st->ds_desc->dtsd_action_last ? nullptr :
		    a->dtad_next)
			printing += a->dtad_kind == DTRACEACT_PRINTIMMSTACK;
	CHECK(printing == 2);
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
