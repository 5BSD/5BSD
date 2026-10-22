/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Typing of args[] against a modelled probe set.
 *
 * The handle is opened with dtrace_vopen() and a vector that implements
 * the dtrace(4) probe ioctls (CONF, PROVIDER, PROBEMATCH, PROBES, PROBEARG)
 * over the table below; kernel modules (and so the CTF the native argument
 * types are resolved in) still come from the kldnext()/kldstat() inventory.
 * The expected type of args[i] is the probe's declared native type, looked
 * up independently with libctf in the module that declares it.
 */
#include "typing-unit.h"

#include <fnmatch.h>

namespace {

#define CMD(x) ((u_long)(x) & 0xffffffffUL)

struct ModelProbe {
	const char *prov, *mod, *func, *name;
	std::vector<const char *> args; /* native argument types */
};

std::vector<ModelProbe> &
probes()
{
	static std::vector<ModelProbe> p = {
		{ "sdt", "kernel", "fn", "withthread",
		    { "struct thread *", "int", "char *" } },
		/* The same probe name in another function declares its second
		 * argument as long: the wider type is kept. */
		{ "sdt", "kernel", "fn2", "withthread",
		    { "struct thread *", "long", "char *" } },
		/* A non-profile probe named "tick". */
		{ "sched", "kernel", "", "tick",
		    { "struct thread *", "struct proc *" } },
		{ "profile", "", "", "tick-1s", {} },
		{ "profile", "", "", "profile-97", {} },
		/* An argument type that no type file has. */
		{ "sdt", "kernel", "fn", "badtype", { "struct no_such_type *" } },
		/* Argument types from a module's own CTF. */
		{ "fbt", "typingfix", "tf_fn", "entry",
		    { "struct tf_pair *", "struct tf_small *" } },
		/* Unrelated types under one name. */
		{ "sdt", "kernel", "fa", "clash", { "struct thread *" } },
		{ "sdt", "kernel", "fb", "clash", { "struct proc *" } },
		/* The same type name from another module's CTF (10), and a
		 * module that has no type file (11). */
		{ "fbt", "typingfix2", "tf_fn2", "entry", { "struct tf_pair *" } },
		{ "sdt", "nosuchmod", "fn", "nomod", { "struct no_such_type *" } },
		/* A type only typingfix2 defines (12). */
		{ "fbt", "typingfix2", "tf_fn3", "entry", { "struct tf_fwd *" } },
	};
	return (p);
}

bool
glob(const char *pattern, const char *s)
{
	return (*pattern == '\0' || fnmatch(pattern, s, 0) == 0);
}

int
model_ioctl(void *, u_long cmd, void *arg)
{
	cmd = CMD(cmd);
	auto &P = probes();
	if (cmd == CMD(DTRACEIOC_CONF)) {
		dtrace_conf_t *c = (dtrace_conf_t *)arg;
		memset(c, 0, sizeof(*c));
		c->dtc_difversion = DIF_VERSION;
		c->dtc_difintregs = DIF_DIR_NREGS;
		c->dtc_diftupregs = DIF_DTR_NREGS;
		c->dtc_ctfmodel = CTF_MODEL_NATIVE;
		return (0);
	}
	if (cmd == CMD(DTRACEIOC_PROVIDER)) {
		dtrace_providerdesc_t *pvd = (dtrace_providerdesc_t *)arg;
		dtrace_attribute_t at = { DTRACE_STABILITY_EVOLVING,
			DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON };
		for (auto &p : P) {
			if (strcmp(pvd->dtvd_name, p.prov) != 0)
				continue;
			memset(&pvd->dtvd_priv, 0, sizeof(pvd->dtvd_priv));
			pvd->dtvd_attr.dtpa_provider = at;
			pvd->dtvd_attr.dtpa_mod = at;
			pvd->dtvd_attr.dtpa_func = at;
			pvd->dtvd_attr.dtpa_name = at;
			pvd->dtvd_attr.dtpa_args = at;
			return (0);
		}
		errno = ESRCH;
		return (-1);
	}
	if (cmd == CMD(DTRACEIOC_PROBEMATCH) || cmd == CMD(DTRACEIOC_PROBES)) {
		dtrace_probedesc_t *d = (dtrace_probedesc_t *)arg;
		bool match = cmd == CMD(DTRACEIOC_PROBEMATCH);
		size_t first = d->dtpd_id == DTRACE_IDNONE ? 0 : d->dtpd_id - 1;
		for (size_t i = first; d->dtpd_vmid == 0 && i < P.size(); i++) {
			auto &p = P[i];
			if (match && (!glob(d->dtpd_provider, p.prov) ||
			    !glob(d->dtpd_mod, p.mod) ||
			    !glob(d->dtpd_func, p.func) ||
			    !glob(d->dtpd_name, p.name)))
				continue;
			d->dtpd_id = (dtrace_id_t)i + 1;
			strlcpy(d->dtpd_provider, p.prov, sizeof(d->dtpd_provider));
			strlcpy(d->dtpd_mod, p.mod, sizeof(d->dtpd_mod));
			strlcpy(d->dtpd_func, p.func, sizeof(d->dtpd_func));
			strlcpy(d->dtpd_name, p.name, sizeof(d->dtpd_name));
			return (0);
		}
		errno = ESRCH;
		return (-1);
	}
	if (cmd == CMD(DTRACEIOC_PROBEARG)) {
		dtrace_argdesc_t *a = (dtrace_argdesc_t *)arg;
		if (a->dtargd_id == DTRACE_IDNONE || a->dtargd_id > P.size() ||
		    a->dtargd_ndx == DTRACE_ARGNONE) {
			errno = EINVAL;
			return (-1);
		}
		auto &p = P[a->dtargd_id - 1];
		if ((size_t)a->dtargd_ndx >= p.args.size()) {
			a->dtargd_ndx = DTRACE_ARGNONE;
			return (0);
		}
		strlcpy(a->dtargd_native, p.args[a->dtargd_ndx],
		    sizeof(a->dtargd_native));
		a->dtargd_xlate[0] = '\0';
		a->dtargd_mapping = a->dtargd_ndx;
		return (0);
	}
	errno = ENOTTY;
	return (-1);
}

int
model_status(void *, processorid_t)
{
	return (1); /* online (P_ONLINE) */
}

long
model_sysconf(void *, int name)
{
	if (name == _SC_NPROCESSORS_CONF || name == _SC_NPROCESSORS_ONLN)
		return (1);
	return (sysconf(name));
}

int
model_lookup(void *, GElf_Addr, GElf_Sym *, dtrace_syminfo_t *)
{
	return (-1);
}

const dtrace_vector_t vector = {
	model_ioctl,
	model_lookup,
	model_status,
	model_sysconf,
};

/* Compile, link and return the type inferred for the first LDGA. */
std::string
args_type(const char *src)
{
	dtrace_prog_t *p = compile(src, 0);
	std::vector<std::pair<dtrace_difo_t *, uint_t>> ldga;
	for_each_difo(p, [&](dtrace_stmtdesc_t *, dtrace_actdesc_t *,
			     dtrace_difo_t *d) {
		for (uint_t i = 0; i < d->dtdo_len; i++)
			if (DIF_INSTR_OP(d->dtdo_buf[i]) == DIF_OP_LDGA)
				ldga.push_back({ d, i });
	});
	CHECKF(!ldga.empty(), "no ldga in %s", src);
	link_ok(p);
	auto [d, i] = ldga.front();
	CHECK(d->dtdo_types != nullptr && d->dtdo_types[i] != nullptr);
	return (d->dtdo_types[i]);
}

/* The CTF name of a type as declared in a module (independent lookup). */
std::string
declared(const char *mod, const char *type)
{
	dtrace_typeinfo_t tip;
	CHECKF(dtrace_lookup_by_type(handle(), mod, type, &tip) == 0,
	    "no %s in %s", type, mod);
	return (ctf_name(tip.dtt_ctfp, tip.dtt_type));
}

} // namespace

CASE("args-sdt-thread-pointer")
{
	std::string t = args_type(
	    "sdt:kernel:fn:withthread { trace(args[0]->td_tid); }");
	CHECKF(t == declared("kernel", "struct thread *"), "%s", t.c_str());
}

CASE("args-sched-tick-is-not-profile")
{
	/* Regression: probes merely named "tick" were typed as profile
	 * probes (uint64_t), losing args[0]'s structure type. */
	std::string t = args_type("sched:kernel::tick { trace(args[0]->td_tid); "
	    "trace(args[1]->p_pid); }");
	CHECKF(t == declared("kernel", "struct thread *"), "%s", t.c_str());
}

CASE("args-module-types")
{
	std::string t = args_type(
	    "fbt:typingfix:tf_fn:entry { trace(args[0]->b); }");
	CHECKF(t == "struct tf_pair *", "%s", t.c_str());
}

CASE("args-scalar-argument")
{
	/* The D compiler narrows args[1] (int) with shifts, so its type is
	 * asked for. */
	std::string t = args_type("sdt:kernel:fn:withthread { trace(args[1]); }");
	CHECKF(t == declared("kernel", "int"), "%s", t.c_str());
}

/* dt_infer_type_arg() called directly. */
namespace {
struct ArgUnit : Unit {
	DFGNode *n;
	ArgUnit() : Unit()
	{
		n = node(DIF_INSTR_LDA(DIF_OP_LDGA, DIF_VAR_ARGS, 2, 3));
	}
	int
	run(const dtrace_probedesc_t &pd, uint8_t idx,
	    uint16_t var = DIF_VAR_ARGS)
	{
		argcheck_cookie c(n, var, idx, &ti);
		return (dt_infer_type_arg(dtp, &pd, &c));
	}
};

dtrace_probedesc_t
pdesc(dtrace_id_t id)
{
	auto &p = probes()[id - 1];
	dtrace_probedesc_t pd;
	memset(&pd, 0, sizeof(pd));
	pd.dtpd_id = id;
	strlcpy(pd.dtpd_provider, p.prov, sizeof(pd.dtpd_provider));
	strlcpy(pd.dtpd_mod, p.mod, sizeof(pd.dtpd_mod));
	strlcpy(pd.dtpd_func, p.func, sizeof(pd.dtpd_func));
	strlcpy(pd.dtpd_name, p.name, sizeof(pd.dtpd_name));
	return (pd);
}
} // namespace

CASE("infer-arg-other-variable")
{
	ArgUnit u;
	CHECK(u.run(pdesc(1), 0, DIF_VAR_REGS) == 1);
	CHECK(u.n->dType == -1);
}

CASE("infer-arg-profile")
{
	ArgUnit u;
	CHECK(u.run(pdesc(4), 0) == 0);
	CHECK(u.n->dType == DIF_TYPE_CTF && u.tname(u.n) == "uint64_t");
}

CASE("infer-arg-join")
{
	ArgUnit u;
	/* int, then long (wider: replaces), then int again (keeps long). */
	CHECK(u.run(pdesc(1), 1) == 0 && u.tname(u.n) == "int");
	CHECK(u.run(pdesc(2), 1) == 0 && u.tname(u.n) == "long");
	CHECK(u.run(pdesc(1), 1) == 0 && u.tname(u.n) == "long");
	/* The same type again. */
	CHECK(u.run(pdesc(2), 1) == 0 && u.tname(u.n) == "long");
}

CASE("infer-arg-unknown-type")
{
	ArgUnit u;
	std::string err = capture_stderr([&] { CHECK(u.run(pdesc(6), 0) == 1); });
	CHECK(err.find("could not find type struct no_such_type * in kernel") !=
	    std::string::npos);
}

CASE("infer-arg-join-across-modules")
{
	/* struct tf_pair * from typingfix, then from typingfix2 (another
	 * type file, an identical layout): the first is kept. */
	ArgUnit u;
	CHECK(u.run(pdesc(7), 0) == 0);
	Typefile *first = u.n->tf;
	CHECK(u.run(pdesc(10), 0) == 0);
	CHECK(u.n->tf == first && u.tname(u.n) == "struct tf_pair *");
}

CASE("infer-arg-unrelated-across-modules")
{
	/* struct tf_pair * (typingfix) and struct tf_fwd * (typingfix2):
	 * unrelated types from two type files cannot be joined. */
	ArgUnit u;
	CHECK(u.run(pdesc(7), 0) == 0);
	std::string err = capture_stderr([&] { CHECK(u.run(pdesc(12), 0) == 1); });
	CHECK(err.find("failed to infer type") != std::string::npos);
}

CASE("infer-arg-unknown-type-unknown-module")
{
	ArgUnit u;
	std::string err = capture_stderr([&] { CHECK(u.run(pdesc(11), 0) == 1); });
	CHECK(err.find("could not find type struct no_such_type * in ") !=
	    std::string::npos);
}

CASE("infer-arg-no-such-argument")
{
	/* The ioctl fails for an unknown probe id. */
	ArgUnit u;
	dtrace_probedesc_t pd = pdesc(1);
	pd.dtpd_id = 999;
	CHECK(u.run(pd, 0) == 1);
}

CASE("infer-arg-string-node")
{
	ArgUnit u;
	u.n->dType = DIF_TYPE_STRING;
	std::string err = capture_stderr([&] { CHECK(u.run(pdesc(1), 0) == 1); });
	CHECK(err.find("failed to infer type for type = struct thread *") !=
	    std::string::npos);
}

CASE("infer-arg-unrelated")
{
	ArgUnit u;
	CHECK(u.run(pdesc(8), 0) == 0);
	std::string err = capture_stderr([&] { CHECK(u.run(pdesc(9), 0) == 1); });
	CHECK(err.find("failed to infer type") != std::string::npos);
}

CASE("infer-arg-bottom-and-none-nodes")
{
	for (int t : { DIF_TYPE_BOTTOM, DIF_TYPE_NONE }) {
		ArgUnit u;
		u.n->dType = t;
		CHECK(u.run(pdesc(1), 0) == 0 && u.n->dType == DIF_TYPE_CTF);
	}
}

int
main(int argc, char **argv)
{
	int err;
	handle() = dtrace_vopen(DTRACE_VERSION, DTRACE_O_LP64, &err, &vector,
	    nullptr);
	if (handle() == nullptr) {
		fprintf(stderr, "dtrace_vopen: %s\n", dtrace_errmsg(nullptr, err));
		return (3);
	}
	return (run_all(argc, argv));
}
