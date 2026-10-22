/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Host round trip of linked programs: compile, serialize the unlinked
 * program (the guest's ELF), parse it, link it, serialize the linked program,
 * parse it against the original and verify it (dt_prog_verify()).
 *
 * dtrace_diftype_t's dtdt_ckind is a CTF kind (dt_node_diftype() stores the
 * kind of the resolved CTF type, CTF_K_UNKNOWN for D strings).  The linker
 * stored CTF type ids there (return types and variable types), so the
 * verifier, which compares them with the compiler's kinds, rejected
 * correctly linked programs such as
 *   dtrace:::BEGIN { x = 1; } dtrace:::END { trace(x); }
 * The oracle for every kind is the compiler's own dtrace_diftype_t.
 */
#include "typing-unit.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <set>

/* This machine's identity can be made unreadable (EIO), as if
 * gethostname() and kern.osrelease failed. */
static bool identity_fails;

extern "C" int
gethostname(char *name, size_t len)
{
	static int (*real)(char *, size_t);
	if (real == nullptr)
		real = (int (*)(char *, size_t))dlsym(RTLD_NEXT, "gethostname");
	if (identity_fails) {
		errno = EIO;
		return (-1);
	}
	return (real(name, len));
}

extern "C" int
sysctlbyname(const char *name, void *oldp, size_t *oldlenp, const void *newp,
    size_t newlen)
{
	static int (*real)(const char *, void *, size_t *, const void *,
	    size_t);
	if (real == nullptr)
		real = (int (*)(const char *, void *, size_t *, const void *,
		    size_t))dlsym(RTLD_NEXT, "sysctlbyname");
	if (identity_fails && strcmp(name, "kern.osrelease") == 0) {
		errno = EIO;
		return (-1);
	}
	return (real(name, oldp, oldlenp, newp, newlen));
}

namespace {

dtrace_prog_t *
elf_roundtrip(dtrace_prog_t *p, int guest, dtrace_prog_t *base,
    const char *name)
{
	std::string path = std::string(getenv("TMPDIR")) + "/" + name;
	int fd = open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600);
	CHECK(fd >= 0);
	char msg[HYPERTRACE_ERRMSGLEN] = { 0 };
	int r = dtrace_elf_create(handle(), p, ELFDATA2LSB, fd, path.c_str(),
	    msg);
	CHECKF(r == 0, "dtrace_elf_create: %d %s", r, msg);
	CHECK(lseek(fd, 0, SEEK_SET) == 0);
	int err = 0;
	dtrace_prog_t *q = dtrace_elf_parse(handle(), fd, path.c_str(), guest,
	    &err, msg, base);
	CHECKF(q != nullptr, "dtrace_elf_parse: %d %s", err, msg);
	close(fd);
	unlink(path.c_str());
	return (q);
}

std::vector<dtrace_difo_t *>
action_difos(dtrace_prog_t *p)
{
	std::vector<dtrace_difo_t *> v;
	for (dt_stmt_t *s = (dt_stmt_t *)dt_list_next(&p->dp_stmts);
	    s != nullptr; s = (dt_stmt_t *)dt_list_next(s)) {
		for (dtrace_actdesc_t *a = s->ds_desc->dtsd_action; a != nullptr;
		    a = a->dtad_next) {
			if (a->dtad_difo != nullptr)
				v.push_back(a->dtad_difo);
			if (a == s->ds_desc->dtsd_action_last)
				break;
		}
	}
	return (v);
}

/* Link the program's guest ELF, return it through the host ELF, verify. */
void
roundtrip_verifies(const char *src)
{
	dtrace_prog_t *a = compile(src, 0);
	dtrace_prog_t *b = elf_roundtrip(a, 1, nullptr, "guest.elf");
	std::string msg;
	int r = link(b, &msg);
	CHECKF(r == 0, "%s: link returned %d: %s", src, r, msg.c_str());
	dtrace_prog_t *c = elf_roundtrip(b, 0, a, "host.elf");

	/* Every CTF kind is the compiler's. */
	auto da = action_difos(a), dc = action_difos(c);
	if (getenv("ROUNDTRIP_DUMP") != nullptr) {
		auto db = action_difos(b);
		for (size_t i = 0; i < da.size(); i++) {
			auto pr = [](const char *w, const dtrace_diftype_t &t) {
				printf("  %s kind %u ckind %u flags %x size %u\n", w,
				    t.dtdt_kind, t.dtdt_ckind, t.dtdt_flags,
				    t.dtdt_size);
			};
			printf("%s action %zu\n", src, i);
			pr("a.rtype", da[i]->dtdo_rtype);
			pr("b.rtype", db[i]->dtdo_rtype);
			pr("c.rtype", dc[i]->dtdo_rtype);
			for (uint_t j = 0; j < da[i]->dtdo_varlen; j++) {
				pr("a.var", da[i]->dtdo_vartab[j].dtdv_type);
				pr("b.var", db[i]->dtdo_vartab[j].dtdv_type);
				pr("c.var", dc[i]->dtdo_vartab[j].dtdv_type);
			}
		}
		fflush(stdout);
	}
	CHECK(da.size() == dc.size());
	for (size_t i = 0; i < da.size(); i++) {
		const dtrace_diftype_t &ra = da[i]->dtdo_rtype;
		const dtrace_diftype_t &rc = dc[i]->dtdo_rtype;
		if (ra.dtdt_kind == DIF_TYPE_CTF && rc.dtdt_kind == DIF_TYPE_CTF)
			CHECKF(ra.dtdt_ckind == rc.dtdt_ckind,
			    "%s: action %zu return kind %u, compiler %u", src, i,
			    rc.dtdt_ckind, ra.dtdt_ckind);
		CHECK(da[i]->dtdo_varlen == dc[i]->dtdo_varlen);
		for (uint_t j = 0; j < da[i]->dtdo_varlen; j++) {
			const dtrace_diftype_t &va =
			    da[i]->dtdo_vartab[j].dtdv_type;
			const dtrace_diftype_t &vc =
			    dc[i]->dtdo_vartab[j].dtdv_type;
			CHECKF(va.dtdt_ckind == vc.dtdt_ckind,
			    "%s: action %zu variable %u kind %u, compiler %u",
			    src, i, j, vc.dtdt_ckind, va.dtdt_ckind);
		}
	}

	void *ctx = dt_verictx_init(handle());
	CHECKF(dt_prog_verify(ctx, a, c) == 0, "%s: verification failed", src);
	dt_verictx_teardown(ctx);
}

} // namespace

/* ---- TYPECAST annotations and the kernel ------------------------------
 *
 * The compiler annotates casts and constants whose D type is not the one
 * their value gives (`-1', `1u', `sizeof (int)', a folded cast) with
 * DIF_OP_TYPECAST for the HyperTrace linker, which turns each into a nop.
 * The kernel's DIF validator has no TYPECAST and refuses the program, and
 * consumers that do not link (lockstat, plockstat, bsdinstruments) exec the
 * compiled program directly: the DOF built for the kernel must hold none.
 * A program with only annotations gets nops in its DOF and keeps them (for
 * its ELF and a later link); one with USETX/ULOAD is linked by
 * dtrace_dof_create() (unlinked-program-linked-for-the-kernel).
 * Oracle: the DIF sections of the DOF itself, and dt_prog_verify().
 */
namespace {
const char *const ANNOTATED[] = {
	"dtrace:::BEGIN { trace((int)arg0 + -1); }",
	"dtrace:::BEGIN { trace((int)arg0 + 1u); }",
	"dtrace:::BEGIN { trace(sizeof (int) + (int)arg0); }",
	"dtrace:::BEGIN { trace((char)300 + (int)arg0); }",
	("dtrace:::BEGIN /arg0 + -1 > 1l/ { this->x = arg1 & 0xffffffff; "
	    "trace(this->x); }"),
};

int
count_typecasts(dtrace_prog_t *p)
{
	int n = 0;
	std::set<dtrace_difo_t *> seen; /* a predicate is shared */
	for_each_difo(p, [&](dtrace_stmtdesc_t *, dtrace_actdesc_t *,
	    dtrace_difo_t *d) {
		if (!seen.insert(d).second)
			return;
		for (uint_t i = 0; i < d->dtdo_len; i++)
			n += DIF_INSTR_OP(d->dtdo_buf[i]) == DIF_OP_TYPECAST;
	});
	return (n);
}

/* TYPECASTs and nops in the DIF sections of a DOF. */
void
scan_dof(const void *dofp, int *typecasts, int *nops, int *difos)
{
	const dof_hdr_t *dof = (const dof_hdr_t *)dofp;
	*typecasts = *nops = *difos = 0;
	for (uint_t s = 0; s < dof->dofh_secnum; s++) {
		const dof_sec_t *sec = (const dof_sec_t *)((const char *)dof +
		    dof->dofh_secoff + s * dof->dofh_secsize);
		if (sec->dofs_type != DOF_SECT_DIF)
			continue;
		(*difos)++;
		const dif_instr_t *ip = (const dif_instr_t *)((const char *)dof +
		    sec->dofs_offset);
		CHECK(sec->dofs_size % sizeof(dif_instr_t) == 0);
		for (uint64_t i = 0; i < sec->dofs_size / sizeof(dif_instr_t);
		    i++) {
				uint_t op = DIF_INSTR_OP(ip[i]);
			/* Every link-time instruction counts. */
			*typecasts += op == DIF_OP_TYPECAST ||
			    op == DIF_OP_USETX || op == DIF_OP_ULOAD ||
			    op == DIF_OP_UULOAD;
			*nops += ip[i] == DIF_INSTR_NOP;
		}
	}
}

/* The DOF dtrace_program_exec() hands the kernel, through an ioctl
 * vector (the same path, without a device). */
int exec_typecasts = -1, exec_nops = -1;

int
exec_ioctl(void *, u_long cmd, void *data)
{
	if ((cmd & 0xffffffff) == (DTRACEIOC_ENABLE & 0xffffffff)) {
		int difos;
		scan_dof(((dtrace_enable_io_t *)data)->dof, &exec_typecasts,
		    &exec_nops, &difos);
		errno = ENOSPC; /* nothing is enabled */
		return (-1);
	}
	if ((cmd & 0xffffffff) == (DTRACEIOC_CONF & 0xffffffff)) {
		dtrace_conf_t *c = (dtrace_conf_t *)data;
		memset(c, 0, sizeof(*c));
		c->dtc_difversion = DIF_VERSION;
		c->dtc_difintregs = DIF_DIR_NREGS;
		c->dtc_diftupregs = DIF_DTR_NREGS;
		c->dtc_ctfmodel = CTF_MODEL_NATIVE;
		return (0);
	}
	errno = ESRCH;
	return (-1);
}

int
exec_status(void *, processorid_t cpu)
{
	return (cpu == 0 ? 1 : -1);
}

long
exec_sysconf(void *, int name)
{
	return (sysconf(name));
}
} // namespace

CASE("kernel-dof-has-no-typecast")
{
	for (const char *src : ANNOTATED) {
		dtrace_prog_t *p = compile(src, 0);
		int before = count_typecasts(p);
		CHECKF(before > 0, "%s: no annotation to strip", src);
		for (uint_t flags : { (uint_t)DTRACE_D_STRIP, 0u }) {
			void *dof = dtrace_dof_create(handle(), p, flags);
			CHECK(dof != nullptr);
			int tc, nops, difos;
			scan_dof(dof, &tc, &nops, &difos);
			CHECKF(tc == 0, "%s: %d TYPECAST in the DOF", src, tc);
			CHECKF(nops >= before, "%s: %d nops for %d annotations",
			    src, nops, before);
			CHECK(difos > 0);
			dtrace_dof_destroy(handle(), dof);
		}
		/* The program keeps its annotations: it needs no linking
		 * (no USETX/ULOAD), so it is not linked. */
		CHECK(count_typecasts(p) == before);
	}
}

CASE("kernel-dof-from-program-exec-has-no-typecast")
{
	static const dtrace_vector_t vec = {
		.dtv_ioctl = exec_ioctl,
		.dtv_lookup_by_addr = nullptr,
		.dtv_status = exec_status,
		.dtv_sysconf = exec_sysconf,
	};
	int err;
	dtrace_hdl_t *h = dtrace_vopen(DTRACE_VERSION, DTRACE_O_LP64, &err,
	    &vec, nullptr);
	CHECKF(h != nullptr, "dtrace_vopen: %s", dtrace_errmsg(nullptr, err));
	for (const char *src : ANNOTATED) {
		dtrace_prog_t *p = dtrace_program_strcompile(h, src,
		    DTRACE_PROBESPEC_NAME, DTRACE_C_ZDEFS, 0, nullptr);
		CHECKF(p != nullptr, "%s: %s", src,
		    dtrace_errmsg(h, dtrace_errno(h)));
		int before = count_typecasts(p);
		CHECK(before > 0);
		dtrace_proginfo_t info;
		exec_typecasts = exec_nops = -1;
		CHECK(dtrace_program_exec(h, p, &info) == -1);
		CHECKF(exec_typecasts == 0, "%s: %d TYPECAST reached the "
		    "kernel", src, exec_typecasts);
		CHECK(exec_nops >= before);
	}
	dtrace_close(h);
}

CASE("annotated-constants-link-verify-roundtrip")
{
	for (const char *src : ANNOTATED) {
		/* The guest ELF carries the annotations to the host. */
		dtrace_prog_t *a = compile(src, 0);
		int before = count_typecasts(a);
		dtrace_prog_t *g = elf_roundtrip(a, 1, nullptr, "guest.elf");
		CHECK(count_typecasts(g) == before);
		/* Making the kernel's DOF changes nothing (only annotations:
		 * no linking needed). */
		void *dof = dtrace_dof_create(handle(), a, DTRACE_D_STRIP);
		CHECK(dof != nullptr);
		dtrace_dof_destroy(handle(), dof);
		CHECK(count_typecasts(a) == before);
		/* Linked, verified against the original, and none left. */
		roundtrip_verifies(src);
		dtrace_prog_t *l = compile(src, 0);
		link_ok(l);
		CHECK(count_typecasts(l) == 0);
	}
}

CASE("unlinked-program-linked-for-the-kernel")
{
	/*
	 * A kernel symbol (USETX) and a member load through a pointer
	 * (ULOAD) are resolved only by the HyperTrace linker; the kernel
	 * refuses both.  A program nobody linked gets the same DIF in its DOF
	 * (and through dtrace_program_exec()) as the one dtrace(1) links.
	 */
	static const char *const SRC[] = {
		"dtrace:::BEGIN { trace(((struct proc *)arg0)->p_pid + `hz); }",
		"dtrace:::BEGIN { trace(curthread->td_proc->p_pid); }",
		("dtrace:::BEGIN /curthread->td_tid != `maxproc/ "
		    "{ trace(curthread->td_tid + -1); }"),
	};
	auto linktime = [](dtrace_prog_t *p) {
		int n = 0;
		for_each_difo(p, [&](dtrace_stmtdesc_t *, dtrace_actdesc_t *,
		    dtrace_difo_t *d) {
			for (uint_t i = 0; i < d->dtdo_len; i++) {
				uint_t op = DIF_INSTR_OP(d->dtdo_buf[i]);
				n += op == DIF_OP_TYPECAST || op == DIF_OP_USETX ||
				    op == DIF_OP_ULOAD || op == DIF_OP_UULOAD;
			}
		});
		return (n);
	};
	auto difsections = [](const void *dofp) {
		const dof_hdr_t *dof = (const dof_hdr_t *)dofp;
		std::vector<std::string> v;
		for (uint_t s = 0; s < dof->dofh_secnum; s++) {
			const dof_sec_t *sec = (const dof_sec_t *)(
			    (const char *)dof + dof->dofh_secoff +
			    s * dof->dofh_secsize);
			if (sec->dofs_type == DOF_SECT_DIF ||
			    sec->dofs_type == DOF_SECT_INTTAB ||
			    sec->dofs_type == DOF_SECT_DIFOHDR)
				v.emplace_back((const char *)dof +
				    sec->dofs_offset, sec->dofs_size);
		}
		return (v);
	};
	for (const char *src : SRC) {
		dtrace_prog_t *a = compile(src, 0);
		CHECKF(linktime(a) > 0, "%s: nothing to link", src);
		bool uload = false, usetx = false;
		for_each_difo(a, [&](dtrace_stmtdesc_t *, dtrace_actdesc_t *,
		    dtrace_difo_t *d) {
			for (uint_t i = 0; i < d->dtdo_len; i++) {
				uint_t op = DIF_INSTR_OP(d->dtdo_buf[i]);
				uload |= op == DIF_OP_ULOAD || op == DIF_OP_UULOAD;
				usetx |= op == DIF_OP_USETX;
			}
		});
		CHECK(usetx || uload);
		/* What dtrace(1) does: link, verify, then exec. */
		dtrace_prog_t *b = compile(src, 0);
		link_ok(b);
		void *verictx = dt_verictx_init(handle());
		CHECK(dt_prog_verify(verictx, b, b) == 0);
		dt_verictx_teardown(verictx);
		void *dofb = dtrace_dof_create(handle(), b, DTRACE_D_STRIP);
		CHECK(dofb != nullptr);
		/* The unlinked program, straight to DOF. */
		void *dofa = dtrace_dof_create(handle(), a, DTRACE_D_STRIP);
		CHECK(dofa != nullptr);
		int tc, nops, difos;
		scan_dof(dofa, &tc, &nops, &difos);
		CHECK(tc == 0 && difos > 0);
		CHECK(linktime(a) == 0);
		CHECKF(difsections(dofa) == difsections(dofb),
		    "%s: DIF differs from the dtrace(1)-linked program", src);
		/* Linked once: a second DOF changes nothing. */
		void *dofa2 = dtrace_dof_create(handle(), a, DTRACE_D_STRIP);
		CHECK(difsections(dofa2) == difsections(dofa));
		dtrace_dof_destroy(handle(), dofa);
		dtrace_dof_destroy(handle(), dofa2);
		dtrace_dof_destroy(handle(), dofb);
	}
}

/* ---- Dynamic translators ----------------------------------------------
 *
 * With -x late=dynamic, a translated member becomes DIF_OP_XLATE (the
 * register's value translated) or DIF_OP_XLARG (a probe argument
 * translated), naming the member through the DIFO's translator table
 * (dtdo_xlmtab).  The type checker types the result as the member.
 */
namespace {
/* Each compile declares its own structure and provider (a handle keeps
 * declarations). */
const char *const XL_IMPORT = "trace(args[0]->a);";
const char *const XL_KERNEL =
    "trace(args[0]->a + ((struct proc *)arg1)->p_pid);";

dtrace_prog_t *
xl_compile(const char *body)
{
	static int seq;
	char src[512];
	seq++;
	/* (A provider name may not end with a digit.) */
	snprintf(src, sizeof(src), "struct yy%d { int a; int b; }; "
	    "provider xl%dp { probe bar(struct yy%d *x); }; "
	    "xl%dp:::bar { %s }", seq, seq, seq, seq, body);
	return (compile(src));
}

int
count_op(dtrace_prog_t *p, uint_t op)
{
	int n = 0;
	std::set<dtrace_difo_t *> seen;
	for_each_difo(p, [&](dtrace_stmtdesc_t *, dtrace_actdesc_t *,
	    dtrace_difo_t *d) {
		if (!seen.insert(d).second)
			return;
		for (uint_t i = 0; i < d->dtdo_len; i++)
			n += DIF_INSTR_OP(d->dtdo_buf[i]) == op;
	});
	return (n);
}

/* The type the type checker gave the last XLATE/XLARG. */
std::string
xl_type(dtrace_prog_t *p)
{
	std::string t = "?";
	for_each_difo(p, [&](dtrace_stmtdesc_t *, dtrace_actdesc_t *,
	    dtrace_difo_t *d) {
		for (uint_t i = 0; d->dtdo_types != nullptr && i < d->dtdo_len;
		    i++) {
			uint_t op = DIF_INSTR_OP(d->dtdo_buf[i]);
			if ((op == DIF_OP_XLATE || op == DIF_OP_XLARG) &&
			    d->dtdo_types[i] != nullptr)
				t = d->dtdo_types[i];
		}
	});
	return (t);
}
} // namespace

CASE("dynamic-translator-links-and-verifies")
{
	CHECK(dtrace_setopt(handle(), "late", "dynamic") == 0);
	for (const char *src : { XL_IMPORT, XL_KERNEL }) {
		dtrace_prog_t *p = xl_compile(src);
		CHECKF(count_op(p, DIF_OP_XLARG) + count_op(p, DIF_OP_XLATE) > 0,
		    "%s: no dynamic translator reference", src);
		link_ok(p);
		/* The member a is an int. */
		CHECKF(xl_type(p) == "int", "%s: %s", src, xl_type(p).c_str());
		/* As dtrace(1) verifies before it executes. */
		void *verictx = dt_verictx_init(handle());
		CHECK(dt_prog_verify(verictx, p, p) == 0);
		dt_verictx_teardown(verictx);
		CHECK(count_op(p, DIF_OP_USETX) == 0 &&
		    count_op(p, DIF_OP_ULOAD) == 0 &&
		    count_op(p, DIF_OP_TYPECAST) == 0);
		/* Its DOF carries the translator references (XLTAB). */
		void *dof = dtrace_dof_create(handle(), p, 0);
		CHECK(dof != nullptr);
		const dof_hdr_t *h = (const dof_hdr_t *)dof;
		int xltab = 0;
		for (uint_t s = 0; s < h->dofh_secnum; s++) {
			const dof_sec_t *sec = (const dof_sec_t *)(
			    (const char *)h + h->dofh_secoff + s * h->dofh_secsize);
			xltab += sec->dofs_type == DOF_SECT_XLTAB;
		}
		CHECK(xltab > 0);
		dtrace_dof_destroy(handle(), dof);
	}
	/* Unlinked, the kernel-member program is linked for its DOF (it was
	 * refused: "unhandled instruction: 79"). */
	dtrace_prog_t *q = xl_compile(XL_KERNEL);
	CHECK(count_op(q, DIF_OP_USETX) > 0);
	void *dof = dtrace_dof_create(handle(), q, 0);
	CHECKF(dof != nullptr, "%s", dtrace_errmsg(handle(),
	    dtrace_errno(handle())));
	CHECK(count_op(q, DIF_OP_USETX) == 0 && count_op(q, DIF_OP_XLARG) > 0);
	dtrace_dof_destroy(handle(), dof);
}

CASE("dynamic-translator-type-matches-static")
{
	/* The same expression translated statically has the same result
	 * type and record size as the dynamic one after linking.  (The
	 * static program is not linked: the type checker cannot type args[]
	 * of a probe the program itself declares; the linker keeps the
	 * compiler's type in any case.) */
	CHECK(dtrace_setopt(handle(), "late", "dynamic") == 0);
	dtrace_prog_t *dp = xl_compile(XL_KERNEL);
	link_ok(dp);
	dtrace_diftype_t d = first_action_difo(dp)->dtdo_rtype;
	CHECK(dtrace_setopt(handle(), "late", "static") == 0);
	dtrace_prog_t *sp = xl_compile(XL_KERNEL);
	CHECK(count_op(sp, DIF_OP_XLARG) == 0 && count_op(sp, DIF_OP_XLATE) == 0);
	dtrace_diftype_t st = first_action_difo(sp)->dtdo_rtype;
	CHECK(d.dtdt_kind == st.dtdt_kind && d.dtdt_size == st.dtdt_size &&
	    d.dtdt_ckind == st.dtdt_ckind);
}

CASE("dynamic-translator-through-the-elf")
{
	/* The guest ELF does not carry the translator table (dtdo_xlmtab:
	 * pointers to the compiler's translator members), so a program with
	 * dynamic translator references cannot be linked from its ELF: the
	 * host reports it as a program error rather than mistyping it. */
	CHECK(dtrace_setopt(handle(), "late", "dynamic") == 0);
	dtrace_prog_t *a = xl_compile(XL_IMPORT);
	dtrace_prog_t *b = elf_roundtrip(a, 1, nullptr, "guest.elf");
	CHECK(count_op(b, DIF_OP_XLARG) > 0);
	std::string msg;
	CHECK(link(b, &msg) != 0);
	CHECKF(msg.find("translator table") != std::string::npos, "%s",
	    msg.c_str());
}

CASE("dynamic-translator-table-checked")
{
	/* A reference past the translator table, or to a register nothing
	 * defined, is a program error. */
	CHECK(dtrace_setopt(handle(), "late", "dynamic") == 0);
	dtrace_prog_t *p = xl_compile(XL_IMPORT);
	dtrace_difo_t *d = first_action_difo(p);
	uint_t xlen = d->dtdo_xlmlen;
	d->dtdo_xlmlen = 0;
	std::string msg;
	CHECK(link(p, &msg) != 0);
	CHECKF(msg.find("is not in the 0-entry translator table") !=
	    std::string::npos, "%s", msg.c_str());
	d->dtdo_xlmlen = xlen;
}

CASE("roundtrip-integer-variable")
{
	roundtrip_verifies("dtrace:::BEGIN { x = 1; } dtrace:::END { trace(x); }");
}

CASE("roundtrip-typedef-variable")
{
	/* pid_t: the kind is that of the resolved type (an integer). */
	roundtrip_verifies(
	    "dtrace:::BEGIN { t = pid; } dtrace:::END { trace(t); }");
}

CASE("roundtrip-pointer-variable")
{
	roundtrip_verifies("dtrace:::BEGIN { p = curthread; } "
	    "dtrace:::END { trace(p->td_tid); }");
}

CASE("roundtrip-string-variable")
{
	roundtrip_verifies(
	    "dtrace:::BEGIN { s = execname; } dtrace:::END { trace(s); }");
}

CASE("roundtrip-integer-return")
{
	roundtrip_verifies("dtrace:::BEGIN { trace(timestamp); }");
}

CASE("roundtrip-kernel-type-returns")
{
	/* Kernel CTF type ids are far from the kind numbers. */
	roundtrip_verifies("dtrace:::BEGIN { trace(curthread->td_proc->p_pid); "
	    "trace(curthread->td_tid); }");
}

CASE("roundtrip-kernel-type-variable")
{
	roundtrip_verifies("dtrace:::BEGIN { self->t = curthread->td_tid; } "
	    "dtrace:::END { trace(self->t); }");
}

/*
 * A value returned by reference is described by the object: kernel and
 * userland structs alike (a userland one was given the pointer's 8 bytes),
 * and a userland D string stays a string by user reference.  The compiler's
 * return type is the oracle; the round trip verifies sizes and kinds.
 */
CASE("roundtrip-userland-struct-by-reference")
{
	roundtrip_verifies("struct ru { int a; long b; char c[20]; }; "
	    "dtrace:::BEGIN { trace(*(userland struct ru *)arg0); }");
}

CASE("roundtrip-kernel-struct-by-reference")
{
	roundtrip_verifies("struct rk { int a; long b; char c[20]; }; "
	    "dtrace:::BEGIN { trace(*(struct rk *)arg0); }");
}

CASE("roundtrip-userland-string-by-reference")
{
	roundtrip_verifies(
	    "dtrace:::BEGIN { trace(*(userland string *)arg0); }");
}

CASE("link-matches-compiler-return-types")
{
	/* Without the ELF round trip: the linked return type is the
	 * compiler's (kind, CTF kind, flags, size). */
	for (const char *src : {
	    "struct rs1 { int a; long b; char c[20]; }; "
	    "BEGIN { trace(*(userland struct rs1 *)arg0); }",
	    "BEGIN { trace(*(userland string *)arg0); }",
	    "struct rs2 { int a; long b; char c[20]; }; "
	    "BEGIN { trace(*(struct rs2 *)arg0); }" }) {
		dtrace_prog_t *p = compile(src, 0);
		dtrace_difo_t *d = first_action_difo(p);
		dtrace_diftype_t before = d->dtdo_rtype;
		link_ok(p);
		const dtrace_diftype_t &after = d->dtdo_rtype;
		CHECKF(before.dtdt_kind == after.dtdt_kind &&
		    before.dtdt_ckind == after.dtdt_ckind &&
		    before.dtdt_flags == after.dtdt_flags &&
		    before.dtdt_size == after.dtdt_size,
		    "%s: compiler %u/%u/%x/%u, linker %u/%u/%x/%u", src,
		    before.dtdt_kind, before.dtdt_ckind, before.dtdt_flags,
		    before.dtdt_size, after.dtdt_kind, after.dtdt_ckind,
		    after.dtdt_flags, after.dtdt_size);
	}
}

CASE("struct-copied-into-clause-variable")
{
	/* Regression: `this->s = *(struct s *)p' stores the struct's
	 * address into a by-reference struct variable; the type checker
	 * compared struct s with struct s * and rejected it. */
	roundtrip_verifies("struct rc { int a; long b; }; "
	    "dtrace:::BEGIN { this->s = *(struct rc *)arg0; trace(this->s.a); }");
	roundtrip_verifies("dtrace:::BEGIN { self->t = *curthread; "
	    "trace(self->t.td_tid); }");
	/* A kernel union held by reference. */
	roundtrip_verifies("dtrace:::BEGIN { self->v = *(union sigval *)arg0; "
	    "trace(self->v.sival_int); }");
}

CASE("member-address-and-pointer-in-one-variable")
{
	/*
	 * Regression (`t | sym'): the address of a member was kept as the
	 * structure pointer plus the member's name, so a variable given
	 * &curthread->td_tid in one clause and an lwpid_t pointer (or the
	 * address of another int member) in another was rejected
	 * ("subtyping not possible: struct thread * != int *").  C and the
	 * D compiler accept both: the values point at the same type.
	 */
	roundtrip_verifies("dtrace:::BEGIN { self->p = &curthread->td_tid; } "
	    "dtrace:::END { self->p = (lwpid_t *)arg0; trace(*self->p); }");
	roundtrip_verifies("dtrace:::BEGIN { self->q = &curthread->td_tid; } "
	    "dtrace:::END { self->q = &curthread->td_oncpu; trace(*self->q); }");
	roundtrip_verifies("dtrace:::BEGIN { self->r = (lwpid_t *)arg0; } "
	    "dtrace:::END { self->r = &curthread->td_tid; trace(*self->r); }");
}

CASE("target-filter-and-unreadable-identity")
{
	/*
	 * A parse that resolves targets keeps the statements for this
	 * machine and drops the others (dt_resolve()).  When this machine's
	 * identity cannot be read (DT_RESOLVE_ERROR), the parse fails with
	 * the reason: the statements used to be dropped silently.
	 */
	dtrace_resolver_setflags(3); /* hostname, then OS release */
	char host[MAXHOSTNAMELEN];
	CHECK(gethostname(host, sizeof(host)) == 0);
	/* Two clauses: BEGIN for this host, END for `target'. */
	auto parse = [&](const char *target, int *err, std::string *msg) {
		dtrace_prog_t *p = compile("BEGIN { trace(1); } END { trace(2); }",
		    0);
		dt_stmt_t *st = (dt_stmt_t *)dt_list_next(&p->dp_stmts);
		strlcpy(st->ds_desc->dtsd_ecbdesc->dted_probe.dtpd_target,
		    host, DTRACE_TARGETNAMELEN);
		st = (dt_stmt_t *)dt_list_next(st);
		strlcpy(st->ds_desc->dtsd_ecbdesc->dted_probe.dtpd_target,
		    target, DTRACE_TARGETNAMELEN);
		std::string path = std::string(getenv("TMPDIR")) + "/t.elf";
		int fd = open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600);
		char m[HYPERTRACE_ERRMSGLEN] = { 0 };
		CHECK(dtrace_elf_create(handle(), p, ELFDATA2LSB, fd,
		    path.c_str(), m) == 0);
		CHECK(lseek(fd, 0, SEEK_SET) == 0);
		dtrace_prog_t *q = dtrace_elf_parse(handle(), fd, path.c_str(),
		    1, err, m, nullptr);
		close(fd);
		unlink(path.c_str());
		*msg = m;
		return (q);
	};
	auto count = [](dtrace_prog_t *q) {
		int n = 0;
		for (dt_stmt_t *st = (dt_stmt_t *)dt_list_next(&q->dp_stmts);
		    st; st = (dt_stmt_t *)dt_list_next(st))
			n++;
		return (n);
	};
	int err;
	std::string msg;
	dtrace_prog_t *q = parse(host, &err, &msg);
	CHECKF(q != nullptr && count(q) == 2, "%s", msg.c_str());
	q = parse("no-such-host-for-typing", &err, &msg);
	CHECKF(q != nullptr && count(q) == 1, "%s", msg.c_str());
	identity_fails = true;
	q = parse("no-such-host-for-typing", &err, &msg);
	identity_fails = false;
	CHECKF(q == nullptr && err == E_HYPERTRACE_SYS &&
	    msg.find("identity is unavailable") != std::string::npos,
	    "%p %d %s", (void *)q, err, msg.c_str());
	dtrace_resolver_setflags(0);
}

CASE("print-type-reference-survives-the-elf")
{
	/*
	 * print() records the value's CTF type ("module`id", dtsd_strdata)
	 * for the consumer, which prints the value by type with it.  The host
	 * runs the program that comes back from the guest through an ELF
	 * file; the ELF dropped the reference, so the host printed print()'s
	 * value as untyped trace() data.  Oracle: the compiled statement.
	 */
	dtrace_prog_t *a = compile("dtrace:::BEGIN { print(*curthread); "
	    "print(curthread->td_tid); }", 0);
	dtrace_prog_t *b = elf_roundtrip(a, 1, nullptr, "print-guest.elf");
	dtrace_prog_t *c = elf_roundtrip(b, 0, a, "print-host.elf");
	dt_stmt_t *sa = (dt_stmt_t *)dt_list_next(&a->dp_stmts);
	dt_stmt_t *sc = (dt_stmt_t *)dt_list_next(&c->dp_stmts);
	int n = 0;
	for (; sa != nullptr && sc != nullptr; sa = (dt_stmt_t *)dt_list_next(sa),
	    sc = (dt_stmt_t *)dt_list_next(sc), n++) {
		const char *x = (const char *)sa->ds_desc->dtsd_strdata;
		const char *y = (const char *)sc->ds_desc->dtsd_strdata;
		CHECK(x != nullptr);
		CHECKF(y != nullptr && strcmp(x, y) == 0, "%s vs %s", x,
		    y ? y : "(null)");
	}
	CHECK(n == 2 && sa == nullptr && sc == nullptr);
	/* The DOF the host enables names the type for the print() record
	 * (dt_dof.c: the record's format string); before, it had none and
	 * the consumer printed the value as untyped trace() data. */
	sa = (dt_stmt_t *)dt_list_next(&a->dp_stmts);
	const char *want = (const char *)sa->ds_desc->dtsd_strdata;
	void *dof = dtrace_dof_create(handle(), c, 0);
	CHECK(dof != nullptr);
	size_t len = ((dof_hdr_t *)dof)->dofh_filesz;
	CHECK(memmem(dof, len, want, strlen(want) + 1) != nullptr);
	dtrace_dof_destroy(handle(), dof);
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
