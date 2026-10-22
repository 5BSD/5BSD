/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * DIF execution in host and guest probe context.  Each D program from the
 * corpus is enabled once on the host probe khx:mod:func:entry and once on
 * the same description in a guest VM's namespace; the guest firing goes
 * through hypertrace_probe() with arguments in a hypertrace_args_t and
 * guest memory reachable only through the vmm_* copy callbacks.  Expected
 * records are the D language results for the given inputs.
 */

/* Test memory: identical bytes in a host "kernel" arena, a host "user"
 * arena, and the guest's kernel and user windows. */
extern int dtrace_destructive_disallow;	/* dtrace.c tunable */
static char karena[1024] __aligned(64);
static char uarena[1024] __aligned(64);

static void
arena_fill(char *a)
{
	static const uint8_t in6_lo[16] = { [15] = 1 };

	memset(a, 0, 1024);
	strcpy(a + 0, "hello");
	strcpy(a + 32, "UPPERlower");
	strcpy(a + 64, "/usr/local/bin/tool");
	strcpy(a + 128, "a,b;c,d");
	strcpy(a + 192, "12345");
	strcpy(a + 224, "-42");
	strcpy(a + 256, "0x1f");
	for (int i = 0; i < 8; i++)
		a[288 + i] = (char)(0x11 + i);
	strcpy(a + 320, "the quick brown fox");
	strcpy(a + 384, "path//a/./b/../c");
	strcpy(a + 448, "{\"k\":{\"n\":42},\"s\":\"v\",\"a\":[7,8]}");
	a[512] = 10;
	a[515] = 1;
	memcpy(a + 528, in6_lo, 16);
	strcpy(a + 600, "guestproc");
	strcpy(a + 640, "arg-a");
	strcpy(a + 704, "jail9");
	memcpy(a + 960, "x\0y\0z\0", 6);
	memcpy(a + 736, "    ", 4);		/* strtoll limits (strsize 4) */
	memcpy(a + 744, "   -", 4);
	memcpy(a + 752, "1234", 4);
	strcpy(a + 760, "-9223372036854775808");
	memcpy(a + 784, "0x", 2);
	/* Paths of "." and ".." components longer than strsize 16, each
	 * cut at a different point of cleanpath()'s scan (round 4). */
	strcpy(a + 864, "/./././././././././");
	strcpy(a + 896, "//./././././././././");
	strcpy(a + 928, "/../../../../../../");
	strcpy(a + 976, "/../../../../../.././");
	/* Guest strings that run off the end of the kernel window. */
}

/* Guest kernel layout (offsets in the guest kernel window). */
#define GUEST_THREAD	0x1000	/* struct thread; td_frame -> GUEST_FRAME */
#define GUEST_FRAME	0x2c00	/* struct trapframe */
#define GUEST_PCSTACK	0x3800	/* raw kernel PCs */
#define GUEST_IMMSTACK	0x3c00	/* guest-formatted immstack strings */

static void
guest_layout(struct fvm *vm)
{
	struct trapframe tf;
	uint64_t frame = vm->gbase + GUEST_FRAME;
	uint64_t pcs[4] = { 0xffffffff80001000ULL, 0xffffffff80002000ULL,
	    0xffffffff80003000ULL, 0xffffffff80004000ULL };
	uint64_t w[2];

	KHX_CHECK(offsetof(struct thread, td_frame) + sizeof(frame) <
	    GUEST_FRAME - GUEST_THREAD);
	memcpy(vm->mem + GUEST_THREAD + offsetof(struct thread, td_frame),
	    &frame, sizeof(frame));
	memset(&tf, 0, sizeof(tf));
	tf.tf_rip = 0x401000;
	tf.tf_rbp = vm->ubase + 0x200;
	tf.tf_rsp = vm->ubase + 0x100;
	tf.tf_rax = 0xabcd;
	memcpy(vm->mem + GUEST_FRAME, &tf, sizeof(tf));
	memcpy(vm->mem + GUEST_PCSTACK, pcs, sizeof(pcs));
	for (int r = 0; r < 64; r++)
		vm->regs[r] = 0x5000 + r;
	/* The top of the guest address space: 256 bytes with no NUL, so a
	 * string there runs to UINTPTR_MAX. */
	vm->tbase = 0xffffffffffffff00ULL;
	memset(vm->tmem, 'T', sizeof(vm->tmem));
	memcpy(vm->mem + GUEST_IMMSTACK, "kern`f0\0kern`f1\0", 16);
	/* User frames: [saved fp, return pc] chains ending with fp 0. */
	w[0] = 0x404000;
	memcpy(vm->umem + 0x100, w, 8);
	w[0] = vm->ubase + 0x220;
	w[1] = 0x402000;
	memcpy(vm->umem + 0x200, w, 16);
	w[0] = 0;
	w[1] = 0x403000;
	memcpy(vm->umem + 0x220, w, 16);
}

enum { A_V, A_K, A_U, A_BAD, A_SCRATCH };
struct darg {
	int kind;
	uint64_t v;
};
#define V(x) { A_V, (uint64_t)(x) }
#define K(o) { A_K, (o) }
#define U(o) { A_U, (o) }
#define BAD(x) { A_BAD, (uint64_t)(x) }
/* All but x bytes of the probe's scratch space, as found by probing alloca
 * (scratch_probe()): an alloca() of this size leaves the rest of the clause
 * almost no scratch. */
#define SCR(x) { A_SCRATCH, (uint64_t)(x) }

enum { E_END, E_INT, E_STR, E_NZ, E_ANY, E_I32 };
struct dexp {
	int kind;
	uint64_t v;
	const char *s;
};
#define I(x) { E_INT, (uint64_t)(x), NULL }
#define S(x) { E_STR, 0, (x) }
#define NZ { E_NZ, 0, NULL }
#define ANY { E_ANY, 0, NULL }
/* ERROR's DIF offset is an int passed in a 64-bit register by
 * dtrace_probe_error(); only the low 32 bits are defined by the ABI. */
#define I32(x) { E_I32, (uint32_t)(x), NULL }

#define CTX_HOST 1
#define CTX_GUEST 2
#define CTX_BOTH 3

struct dcase {
	const char *prog;
	int ctx;
	void (*tweak)(hypertrace_args_t *);	/* adjust guest arguments */
	void (*check)(const struct recs *);	/* additional record checks */
	struct darg a[3];
	int nrec;		/* records expected (ERROR records included) */
	struct dexp e[24];	/* flattened values across records */
};

static struct fvm *dif_vm;
static dtrace_id_t dif_guest_id = 11;
static int dif_discover;
static const char *dif_craft_name;	/* current crafted case */
static size_t dif_case_index;

/* Rewrite every "ldgs from" in a DOF's DIF into "ldgs to". */
static int
dof_patch_var(dof_hdr_t *dof, uint_t from, uint_t to)
{
	int n = 0;

	for (uint32_t i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t *sec = (dof_sec_t *)((char *)dof + dof->dofh_secoff +
		    i * dof->dofh_secsize);
		dif_instr_t *ins;

		if (sec->dofs_type != DOF_SECT_DIF)
			continue;
		ins = (dif_instr_t *)((char *)dof + sec->dofs_offset);
		for (size_t j = 0; j < sec->dofs_size / sizeof(*ins); j++) {
			if (DIF_INSTR_OP(ins[j]) == DIF_OP_LDGS &&
			    DIF_INSTR_VAR(ins[j]) == from) {
				ins[j] = DIF_INSTR_LDV(DIF_OP_LDGS, to,
				    DIF_INSTR_RD(ins[j]));
				n++;
			}
		}
	}
	return (n);
}

static uint64_t dif_scratch_max[2];
extern dtrace_id_t dtrace_probeid_error;
/* Hand-assembled DIF: when set, dif_exec() replaces the action DIFO of the
 * loaded program with these instructions (preceded by NOPs to keep the
 * section length).  Any consumer may submit such DOF; the kernel's DIF
 * validator is the only gate, as for compiled programs. */
static const dif_instr_t *dif_craft;
static int dif_ncraft;
static int dif_minion;		/* add DTRACEOPT_MINION to the options */

static void
dof_craft(dof_hdr_t *dof)
{
	int done = 0;

	for (uint32_t i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t *sec = (dof_sec_t *)((char *)dof + dof->dofh_secoff +
		    i * dof->dofh_secsize);
		dif_instr_t *ins;
		size_t n;

		if (sec->dofs_type != DOF_SECT_DIF)
			continue;
		ins = (dif_instr_t *)((char *)dof + sec->dofs_offset);
		n = sec->dofs_size / sizeof(*ins);
		KHX_CHECK(n >= (size_t)dif_ncraft);
		for (size_t j = 0; j < n - dif_ncraft; j++)
			ins[j] = DIF_INSTR_NOP;
		memcpy(ins + n - dif_ncraft, dif_craft,
		    dif_ncraft * sizeof(*ins));
		done++;
	}
	KHX_EQ(done, 1);
}

static uint64_t
argval(const struct darg *a, int guest)
{
	switch (a->kind) {
	case A_SCRATCH:
		return (a->v);
	case A_K:
		return (guest ? dif_vm->gbase + a->v :
		    (uint64_t)(uintptr_t)(karena + a->v));
	case A_U:
		return (guest ? dif_vm->ubase + a->v :
		    (uint64_t)(uintptr_t)(uarena + a->v));
	default:
		return (a->v);
	}
}

static const struct opt dif_opts[] = {
	{ DTRACEOPT_BUFSIZE, 64 * 1024 },
	{ DTRACEOPT_DYNVARSIZE, 64 * 1024 },
	{ DTRACEOPT_STRSIZE, 256 },
	{ DTRACEOPT_STACKFRAMES, 4 },
	{ DTRACEOPT_USTACKFRAMES, 4 },
	{ DTRACEOPT_DESTRUCTIVE, 1 },
	{ DTRACEOPT_SPECSIZE, 4096 },
	{ DTRACEOPT_NSPEC, 2 },
};

static void
dif_print(const char *prog, int guest, const struct recs *rs)
{
	khx_host_log("  %s[%s]: %d records (case %zu)\n", prog,
	    guest ? "guest" : "host", rs->n, dif_case_index);
	for (int r = 0; r < rs->n; r++)
		for (int i = 0; i < rs->r[r].nrecs && i < 16; i++)
			khx_host_log("    rec%d.%d kind %d size %u val %#llx "
			    "str \"%s\"\n", r, i, rs->r[r].kind[i],
			    rs->r[r].size[i], (unsigned long long)rs->r[r].val[i],
			    rs->r[r].size[i] > 8 ? rs->r[r].str[i] : "");
}

static void
dif_check(const struct dcase *k, int guest, const struct recs *rs)
{
	int e = 0;

	if (rs->n != k->nrec || dif_discover)
		dif_print(k->prog, guest, rs);
	KHX_EQ(rs->n, k->nrec);
	for (int r = 0; r < rs->n; r++) {
		for (int i = 0; i < rs->r[r].nrecs && i < 16; i++, e++) {
			const struct dexp *x = &k->e[e];
			int ok = 1;

			switch (x->kind) {
			case E_END:
				ok = 0;
				break;
			case E_INT:
				ok = rs->r[r].val[i] == x->v;
				break;
			case E_STR:
				ok = rs->r[r].size[i] > 8 &&
				    strcmp(rs->r[r].str[i], x->s) == 0;
				break;
			case E_I32:
				ok = (uint32_t)rs->r[r].val[i] == x->v;
				break;
			case E_NZ:
				ok = rs->r[r].val[i] != 0 ||
				    rs->r[r].str[i][0] != '\0';
				break;
			}
			if (!ok) {
				if (dif_craft != NULL)
					khx_host_log("  (craft %s)\n",
					    dif_craft_name);
				khx_host_log("  %s[%s] record %d.%d mismatch: got "
				    "%#llx \"%s\"\n", k->prog, guest ? "guest" :
				    "host", r, i,
				    (unsigned long long)rs->r[r].val[i],
				    rs->r[r].size[i] > 8 ? rs->r[r].str[i] : "");
				KHX_CHECK(ok);
			}
		}
	}
	KHX_EQ(k->e[e].kind, E_END);
}

/*
 * Run one case and collect its records.  The program name may carry a
 * prefix selecting the string size: "z:" strsize 0, "s:" strsize 4 (the
 * historical "s_" program names also use 4).  fail_at > 0 makes that guest
 * memory access fail once (dif_vm->fault_hit reports whether it was hit).
 */
static void
dif_exec(const struct dcase *k, int guest, int fail_at, struct recs *rsp)
{
	struct cons c;
	struct recs rs;
	dof_hdr_t *dof;
	int matched;
	const char *prog = k->prog;
	int strsize = 256;
	int dynsize = 64 * 1024;
	int firings = 1;
	const char *gfunc = "func";

	if (strncmp(prog, "u:", 2) == 0) {
		/* Unanchored guest probe: no function name. */
		gfunc = "";
		prog += 2;
	} else if (strncmp(prog, "z:", 2) == 0) {
		strsize = 0;
		prog += 2;
	} else if (strncmp(prog, "m:", 2) == 0) {
		dynsize = 1024;
		firings = 300;
		prog += 2;
	} else if (strncmp(prog, "L:", 2) == 0) {
		strsize = 512;
		prog += 2;
	} else if (strncmp(prog, "s:", 2) == 0 || strncmp(prog, "s_", 2) == 0) {
		strsize = 4;
		if (prog[1] == ':')
			prog += 2;
	}
	KHX_EQ(cons_open(&c), 0);
	if (guest) {
		/* ECB teardown disables a virtual probe, after which the
		 * namespace is reclaimed; register it for this consumer. */
		dtrace_probedesc_t d = vdesc(dif_guest_id, "khx", "mod", gfunc,
		    "entry");

		KHX_EQ(vprobe_create(&c, dif_vm, &d, 1), 0);
	}
	dof = dof_load(prog);
	if (strcmp(prog, "r_craft") == 0 && dif_craft != NULL)
		dof_craft(dof);
	if (strcmp(prog, "d_hostid") == 0) {
		KHX_EQ(dof_patch_var(dof, DIF_VAR_EPID, DIF_VAR_HOSTID), 1);
		KHX_EQ(dof_patch_var(dof, DIF_VAR_ID, DIF_VAR_HHOSTID), 1);
	}
	if (guest) {
		/* Only the khx probe description moves into the guest; the
		 * dtrace:::ERROR clause stays on the host provider. */
		for (uint32_t i = 0; i < dof->dofh_secnum; i++) {
			dof_sec_t *sec = (dof_sec_t *)((char *)dof +
			    dof->dofh_secoff + i * dof->dofh_secsize);
			dof_probedesc_t *pd;
			dof_sec_t *strtab;

			if (sec->dofs_type != DOF_SECT_PROBEDESC)
				continue;
			pd = (dof_probedesc_t *)((char *)dof + sec->dofs_offset);
			strtab = (dof_sec_t *)((char *)dof + dof->dofh_secoff +
			    pd->dofp_strtab * dof->dofh_secsize);
			if (strcmp((char *)dof + strtab->dofs_offset +
			    pd->dofp_provider, "khx") == 0)
				pd->dofp_vmid = dif_vm->vmid;
		}
	}
	KHX_EQ(cons_enable_vm(&c, dof, 0, 0, &matched), 0);
	dof_free(dof);
	KHX_CHECK(matched >= 1);
	/* ERROR stays a host probe; an enabling may not span namespaces, so
	 * faults are captured by a separate host enabling. */
	KHX_EQ(cons_enable(&c, "err_capture", &matched), 0);
	KHX_EQ(matched, 1);
	{
		struct opt o[nitems(dif_opts) + 1];

		memcpy(o, dif_opts, sizeof(dif_opts));
		o[nitems(dif_opts)] = (struct opt){ DTRACEOPT_MINION, 1 };
		for (size_t i = 0; i < nitems(dif_opts); i++) {
			if (o[i].option == DTRACEOPT_STRSIZE)
				o[i].value = strsize;
			if (o[i].option == DTRACEOPT_DYNVARSIZE)
				o[i].value = dynsize;
		}
		KHX_EQ(cons_options(&c, o, nitems(dif_opts) + (dif_minion != 0)),
		    0);
	}
	KHX_EQ(cons_go(&c), 0);
	struct thread *prev = khx_set_curthread(root_td);
	if (guest) {
		hypertrace_args_t a = gargs(argval(&k->a[0], 1),
		    argval(&k->a[1], 1), argval(&k->a[2], 1));

		a.htr_args[5] = 0x55;
		a.htr_args[9] = 0x99;
		a.htr_execname = (char *)(uintptr_t)(dif_vm->gbase + 600);
		a.htr_execargs = (char *)(uintptr_t)(dif_vm->gbase + 640);
		a.htr_execargs_len = 6;
		a.htr_jailname = (char *)(uintptr_t)(dif_vm->gbase + 704);
		a.htr_jid = 9;
		a.htr_uid = 1001;
		a.htr_gid = 1002;
		a.htr_ppid = 98;
		a.htr_errno = 4;
		/* Raw guest kernel PCs live in guest memory. */
		a.htr_pcstack = (uintptr_t *)(uintptr_t)(dif_vm->gbase +
		    GUEST_PCSTACK);
		a.htr_pcstack_count = 4;
		a.htr_stackdepth = 3;
		a.htr_caller = 0xffffffff80000abcULL;
		a.htr_curthread = (void *)(uintptr_t)(dif_vm->gbase +
		    GUEST_THREAD);
		a.htr_walltimestamp = 1700000000000000000ULL;
		a.htr_timestamp = 123456789;
		a.htr_vtimestamp = 4242;
		a.htr_present = HYPERTRACE_ARGS_WALLTIME_VALID;
		__typeof__(hypertrace_guest_copyin) saved0 =
		    hypertrace_guest_copyin;
		__typeof__(hypertrace_guest_user_copyin) saved1 =
		    hypertrace_guest_user_copyin;
		__typeof__(hypertrace_guest_user_copyout) saved2 =
		    hypertrace_guest_user_copyout;
		__typeof__(hypertrace_getreg) saved3 = hypertrace_getreg;
		int saved_disallow = dtrace_destructive_disallow;

		if (k->tweak != NULL)
			k->tweak(&a);
		dif_vm->fail_at = fail_at;
		dif_vm->naccess = 0;
		dif_vm->fault_hit = 0;
		for (int f = 0; f < firings; f++) {
			if (firings > 1)
				a.htr_args[1] = f;
			KHX_EQ(hypertrace_probe(&dif_vm->hdl, dif_guest_id, &a),
			    0);
		}
		dif_vm->fail_at = 0;
		hypertrace_guest_copyin = saved0;
		hypertrace_guest_user_copyin = saved1;
		hypertrace_guest_user_copyout = saved2;
		hypertrace_getreg = saved3;
		dtrace_destructive_disallow = saved_disallow;
		/* Undo the tweak's changes to the VM. */
		dif_vm->getreg_error = dif_vm->copyin_error = 0;
		dif_vm->ucopyin_error = dif_vm->ucopyout_error = 0;
		dif_vm->zero_mapped = 0;
		dif_vm->utop_mapped = 0;
		khx_guest_map(0, 0, NULL, 0);
		arena_fill(dif_vm->mem);
		arena_fill(dif_vm->umem);
		guest_layout(dif_vm);
	} else {
		khx_probe_args[5] = 0x55;
		khx_probe_args[9] = 0x99;
		for (int f = 0; f < firings; f++)
			fire(p_entry, argval(&k->a[0], 0),
			    firings > 1 ? f : argval(&k->a[1], 0),
			    argval(&k->a[2], 0));
	}
	khx_set_curthread(prev);
	KHX_CHECK(snap_records(&c, 0, &rs) >= 0);
	cons_close(&c);
	*rsp = rs;
}

static void
dif_run(const struct dcase *k, int guest)
{
	struct recs rs;
	char name[64];

	snprintf(name, sizeof(name), "dif-%s-%s", k->prog,
	    guest ? "guest" : "host");
	khx_host_case(name);
	if (k->a[2].kind == A_SCRATCH) {
		/*
		 * The clause starts with this->scr = alloca(arg2): find the
		 * largest arg2 for which alloca() itself succeeds (a huge one
		 * faults NOSCRATCH at the alloca's DIF offset), so the rest of
		 * the clause runs with almost no scratch left.
		 */
		struct dcase t = *k;
		uint64_t lo = 0, hi = 1 << 20, off0;

		t.a[2].v = hi;
		dif_exec(&t, guest, 0, &rs);
		KHX_EQ(rs.n, 1);
		KHX_EQ(rs.r[0].probe, dtrace_probeid_error);
		off0 = rs.r[0].val[0];
		while (hi - lo > 1) {
			t.a[2].v = (lo + hi) / 2;
			dif_exec(&t, guest, 0, &rs);
			if (rs.n == 1 && rs.r[0].probe == dtrace_probeid_error &&
			    rs.r[0].val[0] == off0 &&
			    rs.r[0].val[1] == DTRACEFLT_NOSCRATCH)
				hi = t.a[2].v;
			else
				lo = t.a[2].v;
		}
		t.a[2].v = lo;
		dif_exec(&t, guest, 0, &rs);
		/* The clause's own NOSCRATCH is past the alloca. */
		if (rs.n == 1 && rs.r[0].probe == dtrace_probeid_error)
			KHX_CHECK(rs.r[0].val[0] != off0);
		dif_check(k, guest, &rs);
		if (k->check != NULL && rs.n > 0)
			k->check(&rs);
		return;
	}
	dif_exec(k, guest, 0, &rs);
	dif_check(k, guest, &rs);
	if (k->check != NULL && (rs.n > 0 || k->nrec == 0))
		k->check(&rs);
}

/*
 * Fault sweep: rerun a guest case with its 1st, 2nd, ... guest memory
 * access failing, until a run completes without reaching the injected
 * access.  Oracle: an injected fault never crashes, leaks or corrupts; the
 * firing yields either the case's normal records (the access was retried
 * or its failure is absorbed) or exactly one ERROR record reporting a bad
 * address (or, for a VMM routine reporting an error on a user access, the
 * guest-user fault), and the clean run afterwards still matches.
 */
static int dif_sweep_runs, dif_sweep_faults;

static void
dif_sweep(const struct dcase *k)
{
	struct recs rs;
	char name[64];

	snprintf(name, sizeof(name), "sweep-%s", k->prog);
	khx_host_case(name);
	/* Every access up to the 64th, then geometrically spaced ones (long
	 * strings repeat the same per-byte path). */
	for (int n = 1; n <= 1 << 16; n = n < 64 ? n + 1 : n + n / 4) {
		dif_exec(k, 1, n, &rs);
		dif_sweep_runs++;
		if (!dif_vm->fault_hit)
			return;
		dif_sweep_faults++;
		KHX_CHECK(rs.n <= k->nrec || rs.n == 1);
		for (int r = 0; r < rs.n; r++) {
			/* An ERROR record: DIF offset, fault, address. */
			if (rs.r[r].probe == dtrace_probeid_error)
				KHX_CHECK(rs.r[r].val[1] == DTRACEFLT_BADADDR ||
				    rs.r[r].val[1] == DTRACEFLT_BADSTACK);
		}
	}
	KHX_CHECK(!"fault sweep did not terminate");
}

static void tw_nowall(hypertrace_args_t *a) { a->htr_present = 0; }
/* "ab" at 0xffffffffffffff80: readable and terminated, but a string-size
 * window from it would wrap the address space. */
static void
tw_top_nul(hypertrace_args_t *a __unused)
{
	memset(dif_vm->tmem, 'T', sizeof(dif_vm->tmem));
	dif_vm->tmem[0x80] = 'a';
	dif_vm->tmem[0x81] = 'b';
	dif_vm->tmem[0x82] = '\0';
}
static void tw_execargs_empty(hypertrace_args_t *a) { a->htr_execargs_len = 0; }
static void tw_execargs_null(hypertrace_args_t *a) { a->htr_execargs = NULL; }
/* Round 4 tweaks. */
#define	GUEST_SCRATCH	0x900	/* free guest kernel bytes past the arena */
static void tw_kload_page(hypertrace_args_t *a __unused)
{
	/* 8 known bytes across the page boundary at guest offset 0x3000. */
	for (int i = 0; i < 9; i++)
		dif_vm->mem[0x2ffd + i] = (char)(0x21 + i);
	dif_vm->copyin_error = EOPNOTSUPP;
	khx_guest_map(0, dif_vm->gbase, dif_vm->mem, sizeof(dif_vm->mem));
}
static void tw_no_kcopy(hypertrace_args_t *a __unused)
{
	hypertrace_guest_copyin = NULL;
}
static void tw_no_getreg(hypertrace_args_t *a __unused)
{
	hypertrace_getreg = NULL;
}
static void tw_disallow(hypertrace_args_t *a __unused)
{
	dtrace_destructive_disallow = 1;
}
static void tw_execname_null(hypertrace_args_t *a) { a->htr_execname = NULL; }
static void tw_execname_long(hypertrace_args_t *a)
{
	strcpy(dif_vm->mem + GUEST_SCRATCH, "longname");
	a->htr_execname = (char *)(uintptr_t)(dif_vm->gbase + GUEST_SCRATCH);
}
static void tw_td_frame_top(hypertrace_args_t *a __unused)
{
	uint64_t f = 0xffffffffffffff80ULL;

	memcpy(dif_vm->mem + GUEST_THREAD + offsetof(struct thread, td_frame),
	    &f, sizeof(f));
}
static void tw_rsp_top(hypertrace_args_t *a)
{
	uint64_t rsp = 0xfffffffffffffffcULL;

	memcpy(dif_vm->mem + GUEST_FRAME + offsetof(struct trapframe, tf_rsp),
	    &rsp, sizeof(rsp));
	a->htr_entry = 1;
}
static void tw_pcstack_bad(hypertrace_args_t *a)
{
	/* More frames than an envelope can describe. */
	a->htr_pcstack_count = HYPERTRACE_STACK_MAX_FRAMES + 1;
}
static void tw_rip_zero(hypertrace_args_t *a __unused)
{
	uint64_t z = 0;

	memcpy(dif_vm->mem + GUEST_FRAME + offsetof(struct trapframe, tf_rip),
	    &z, sizeof(z));
}
/* Paths cut at strsize 4 at each point of cleanpath()'s scan. */
static void tw_paths(hypertrace_args_t *a __unused)
{
	static const char *const p[] = { "abcdef", "abc/", "ab/.", "a/.." };

	for (size_t i = 0; i < nitems(p); i++)
		memcpy(dif_vm->mem + GUEST_SCRATCH + 16 * i, p[i],
		    strlen(p[i]) + 1);
}
/* Guest argument area running past the top of the address space. */
static void tw_execargs_top(hypertrace_args_t *a)
{
	a->htr_execargs = (char *)(uintptr_t)0xfffffffffffffff8ULL;
	a->htr_execargs_len = 16;
}
static void
tw_utop(hypertrace_args_t *a __unused)
{
	dif_vm->utop_mapped = 1;
	memset(dif_vm->tmem, 'T', sizeof(dif_vm->tmem));
}
static void
tw_no_kernel_hook2(hypertrace_args_t *a __unused)
{
	hypertrace_guest_copyin = NULL;
}
static void
tw_execname_top(hypertrace_args_t *a)
{
	a->htr_execname = (char *)(uintptr_t)0xfffffffffffffff8ULL;
}
static void
tw_entry_rsp0(hypertrace_args_t *a)
{
	a->htr_entry = 1;
	memset(dif_vm->mem + GUEST_FRAME + offsetof(struct trapframe, tf_rsp),
	    0, sizeof(uint64_t));
}
/* A guest that maps its page zero: NULL is readable ("a,b") but DTrace
 * must still refuse NULL as a string or memory address. */
static void
tw_zero_page(hypertrace_args_t *a __unused)
{
	dif_vm->zero_mapped = 1;
	memset(dif_vm->zmem, 0, sizeof(dif_vm->zmem));
	strcpy(dif_vm->zmem, "a,b");
}
/* Text at the very end of the guest kernel window (the next byte faults). */
static void
win_end(const char *t)
{
	size_t n = strlen(t);

	memcpy(dif_vm->mem + sizeof(dif_vm->mem) - n, t, n);
}
static void tw_end_ws(hypertrace_args_t *a __unused) { win_end("   "); }
static void tw_end_sign(hypertrace_args_t *a __unused) { win_end("-"); }
static void tw_end_zero(hypertrace_args_t *a __unused) { win_end("0"); }
static void tw_end_0x(hypertrace_args_t *a __unused) { win_end("0x"); }
static void tw_end_digits(hypertrace_args_t *a __unused) { win_end("12"); }
static void tw_ucopy_eop(hypertrace_args_t *a __unused)
{
	dif_vm->ucopyin_error = EOPNOTSUPP;
}
static void tw_ucopy_efault(hypertrace_args_t *a __unused)
{
	dif_vm->ucopyin_error = EFAULT;
}
static void tw_ucopyout_eop(hypertrace_args_t *a __unused)
{
	dif_vm->ucopyout_error = EOPNOTSUPP;
}
static void tw_ucopyout_efault(hypertrace_args_t *a __unused)
{
	dif_vm->ucopyout_error = EFAULT;
}
/* No VMM copy routine: the guest kernel is read by translating guest
 * linear addresses to host pages instead. */
static void tw_kcopy_eop(hypertrace_args_t *a __unused)
{
	dif_vm->copyin_error = EOPNOTSUPP;
	khx_guest_map(0, dif_vm->gbase, dif_vm->mem, sizeof(dif_vm->mem));
}
static void tw_kcopy_eop_unmapped(hypertrace_args_t *a __unused)
{
	dif_vm->copyin_error = EOPNOTSUPP;
	khx_guest_map(0, 0, NULL, 0);
}
static void tw_no_user_hooks(hypertrace_args_t *a __unused)
{
	hypertrace_guest_user_copyin = NULL;
	hypertrace_guest_user_copyout = NULL;
}
static void tw_no_kernel_hook(hypertrace_args_t *a __unused)
{
	hypertrace_guest_copyin = NULL;
	khx_guest_map(0, 0, NULL, 0);
}
/* User frame chains: [saved fp, return pc] at fp. */
static void
uframe(uint64_t off, uint64_t fp, uint64_t pc)
{
	uint64_t w[2] = { fp, pc };

	memcpy(dif_vm->umem + off, w, sizeof(w));
}
static void
tw_pc_zero(hypertrace_args_t *a __unused)
{
	uframe(0x200, dif_vm->ubase + 0x220, 0);
}
static void tw_fp_self(hypertrace_args_t *a __unused)
{
	uframe(0x200, dif_vm->ubase + 0x200, 0x402000);
}
static void tw_fp_cycle(hypertrace_args_t *a __unused)
{
	uframe(0x200, dif_vm->ubase + 0x220, 0x402000);
	uframe(0x220, dif_vm->ubase + 0x200, 0x403000);
}
static void tw_fp_outside(hypertrace_args_t *a __unused)
{
	uframe(0x200, 0x7000000, 0x402000);
}
static void
set_frame_rbp(uint64_t rbp)
{
	memcpy(dif_vm->mem + GUEST_FRAME + offsetof(struct trapframe, tf_rbp),
	    &rbp, sizeof(rbp));
}
static void
set_frame_rsp(uint64_t rsp)
{
	memcpy(dif_vm->mem + GUEST_FRAME + offsetof(struct trapframe, tf_rsp),
	    &rsp, sizeof(rsp));
}
static void tw_fp_top(hypertrace_args_t *a __unused)
{
	set_frame_rbp(0xfffffffffffffff8ULL);
}
static void tw_fp_zero(hypertrace_args_t *a __unused)
{
	set_frame_rbp(0);
}
static void tw_entry_badsp(hypertrace_args_t *a)
{
	a->htr_entry = 1;
	set_frame_rsp(0x7000000);
}
static void tw_td_frame_null(hypertrace_args_t *a __unused)
{
	uint64_t z = 0;

	memcpy(dif_vm->mem + GUEST_THREAD + offsetof(struct thread, td_frame),
	    &z, sizeof(z));
}
static void tw_td_frame_bad(hypertrace_args_t *a __unused)
{
	uint64_t z = 0x1234;

	memcpy(dif_vm->mem + GUEST_THREAD + offsetof(struct thread, td_frame),
	    &z, sizeof(z));
}
static void tw_thread_top(hypertrace_args_t *a)
{
	a->htr_curthread = (void *)(uintptr_t)0xfffffffffffffff0ULL;
}
static void tw_bad_execname(hypertrace_args_t *a)
{
	a->htr_execname = (char *)(uintptr_t)0x1234;
	a->htr_jailname = (char *)(uintptr_t)0x1234;
}
static void tw_getreg_fails(hypertrace_args_t *a __unused)
{
	dif_vm->getreg_error = EINVAL;
}
static void
tw_imm(hypertrace_args_t *a)
{
	a->htr_immstack = (char *)(uintptr_t)(dif_vm->gbase + GUEST_IMMSTACK);
	a->htr_immstacksize = 16;
}
static void
tw_imm_misaligned(hypertrace_args_t *a)
{
	tw_imm(a);
	a->htr_immstack += 1;
}
static void
tw_imm_negative(hypertrace_args_t *a)
{
	tw_imm(a);
	a->htr_immstacksize = -1;
}
static void
tw_imm_huge(hypertrace_args_t *a)
{
	tw_imm(a);
	a->htr_immstacksize = 1 << 20;
}

/* printimmstack(): the guest's preformatted strings, copied verbatim. */
static void
ck_pimm(const struct recs *rs)
{
	KHX_CHECK(memcmp(rs->r[0].raw[0], "kern`f0\0kern`f1\0", 16) == 0);
}

/* Host stop()/raise() signal the current process (pid 4500). */
static void
ck_sigstop(const struct recs *rs __unused)
{
	pid_t pid;

	KHX_EQ(khx_psignal_last(&pid), SIGSTOP);
	KHX_EQ(pid, 4500);
}
static void
ck_sigkill(const struct recs *rs __unused)
{
	pid_t pid;

	KHX_EQ(khx_psignal_last(&pid), SIGKILL);
	KHX_EQ(pid, 4500);
}
/* User-address records are [pid, address]; a guest's pid is tagged with
 * its VM. */
static void
ck_uaddr_host(const struct recs *rs)
{
	KHX_EQ(rs->r[0].raw[0][0], 4500);
	KHX_EQ(rs->r[0].raw[0][1], 0x1234);
}
static void
ck_uaddr_guest(const struct recs *rs)
{
	KHX_EQ(rs->r[0].raw[0][0], HYPERTRACE_UADDR_ENCODE(dif_vm->vmid, 99));
	KHX_EQ(rs->r[0].raw[0][1], 0x1234);
}
static void
ck_jstack_host(const struct recs *rs)
{
	KHX_EQ(rs->r[0].raw[0][0], 4500);
}
static void tw_fewframes(hypertrace_args_t *a) { a->htr_pcstack_count = 2; }
static void tw_nopid(hypertrace_args_t *a) { a->htr_pid = 0; }
static void tw_entry(hypertrace_args_t *a) { a->htr_entry = 1; }
static void tw_badentry(hypertrace_args_t *a) { a->htr_entry = 2; }
static void tw_nothread(hypertrace_args_t *a) { a->htr_curthread = NULL; }

/* Guest ustack(): [tagged VM/pid, rip, then return PCs up the fp chain]. */
static void
ck_gustack(const struct recs *rs)
{
	const uint64_t *u = rs->r[0].raw[0];

	KHX_EQ(u[0], HYPERTRACE_USTACK_ENCODE(dif_vm->vmid, 99));
	KHX_EQ(u[1], 0x401000);
	KHX_EQ(u[2], 0x402000);
	KHX_EQ(u[3], 0x403000);
	KHX_EQ(u[4], 0);
}

/* A two-frame cycle is cut off by the requested depth. */
static void
ck_gustack_cycle(const struct recs *rs)
{
	const uint64_t *u = rs->r[0].raw[0];

	KHX_EQ(u[1], 0x401000);
	KHX_EQ(u[2], 0x402000);
	KHX_EQ(u[3], 0x403000);
	KHX_EQ(u[4], 0x402000);
}
/* A guest kernel thread (pid 0) has no user stack: all zero. */
static void
ck_gustack_nopid(const struct recs *rs)
{
	for (int i = 0; i < 5; i++)
		KHX_EQ(rs->r[0].raw[0][i], 0);
}

/* At an entry probe the return address comes from the stack pointer. */
static void
ck_gustack_entry(const struct recs *rs)
{
	const uint64_t *u = rs->r[0].raw[0];

	KHX_EQ(u[1], 0x401000);
	KHX_EQ(u[2], 0x404000);
	KHX_EQ(u[3], 0x402000);
	KHX_EQ(u[4], 0x403000);
}

/* Guest stack(): the VMM-supplied raw kernel PCs, copied from guest RAM. */
static void
ck_gstack(const struct recs *rs)
{
	const uint64_t *u = rs->r[0].raw[0];

	KHX_EQ(u[0], 0xffffffff80001000ULL);
	KHX_EQ(u[3], 0xffffffff80004000ULL);
}

/* printm(): [byte count, bytes] from the memref() pair. */
static void
ck_printm(const struct recs *rs)
{
	KHX_EQ(rs->r[0].raw[1][0], 8);
	KHX_EQ(rs->r[0].raw[1][1], 0x1817161514131211ULL);
}

extern uint64_t dtrace_node_id;
static void
ck_hostid_host(const struct recs *rs)
{
	KHX_EQ(rs->r[0].val[0], dtrace_node_id);
	KHX_EQ(rs->r[0].val[1], dtrace_node_id);
}
static void
ck_hostid_guest(const struct recs *rs)
{
	KHX_EQ(rs->r[0].val[0], dif_vm->vmid);
	KHX_EQ(rs->r[0].val[1], dtrace_node_id);
}

/* A 16-byte struct traced by value: bytes 11..18 then the zero bytes at
 * offset 296 of the arena. */
static void
ck_struct(const struct recs *rs)
{
	KHX_EQ(rs->r[0].size[0], 16);
	KHX_EQ(rs->r[0].raw[0][0], 0x1817161514131211ULL);
	KHX_EQ(rs->r[0].raw[0][1], 0);
}
static void
ck_arr(const struct recs *rs)
{
	KHX_EQ(rs->r[0].size[0], 8);
	KHX_CHECK(memcmp(rs->r[0].raw[0], "hello\0\0\0", 8) == 0);
}

static void
ck_illval_k800(const struct recs *rs)
{
	KHX_EQ(rs->r[0].val[2], (uintptr_t)(karena + 800));
}
static void
ck_odd_illval(const struct recs *rs)
{
	KHX_CHECK((rs->r[0].val[2] & 1) != 0 || (rs->r[0].val[2] & 3) == 2 ||
	    (rs->r[0].val[2] & 7) == 4);
}

static void
ck_kdb(const struct recs *rs __unused)
{
	KHX_CHECK(khx_kdb_count() >= 1);
}

/* A frame whose return address is 0 ends the user stack. */
static void
ck_ustack_pc0(const struct recs *rs)
{
	KHX_EQ(rs->r[0].raw[0][1], 0x401000);
	KHX_EQ(rs->r[0].raw[0][2], 0);
}

/* ustack(1) at an entry probe: only the tagged pid slot. */
static void
ck_ustack1(const struct recs *rs)
{
	KHX_EQ(rs->r[0].raw[0][0], HYPERTRACE_USTACK_ENCODE(dif_vm->vmid, 99));
	KHX_EQ(rs->r[0].size[0], 16);
}

/* The fault address of a refused destination is the destination. */
static void
ck_illval_u800(const struct recs *rs)
{
	KHX_EQ(rs->r[0].val[2], (uintptr_t)(uarena + 800));
}

static const struct dcase dcases[] = {
	{ "d_str", CTX_BOTH, NULL, NULL, { K(0) }, 1,
	    { I(5), S("hello"), I(1), I(1) } },
	{ "d_case", CTX_BOTH, NULL, NULL, { K(32) }, 1,
	    { S("UPPERLOWER"), S("upperlower") } },
	{ "d_path", CTX_BOTH, NULL, NULL, { K(64), K(384) }, 1,
	    { S("tool"), S("/usr/local/bin"), S("path/a/c") } },
	{ "d_search", CTX_BOTH, NULL, NULL, { K(128) }, 1,
	    { S("b;c,d"), S(",d"), S(";c,d"), I(1), I(5), I(5), I(1) } },
	{ "d_substr", CTX_BOTH, NULL, NULL, { K(320) }, 1,
	    { S("quick brown fox"), S("quick"), S("fox") } },
	{ "d_strtok", CTX_BOTH, NULL, NULL, { K(128) }, 1,
	    { S("a"), S("b"), S("c") } },
	{ "d_join", CTX_BOTH, NULL, NULL, { K(0), K(32) }, 1,
	    { S("helloUPPERlower") } },
	{ "d_lltostr", CTX_BOTH, NULL, NULL, { V(-123), V(255) }, 1,
	    { S("-123"), S("255"), S("0xff"), S("11111111") } },
	{ "d_strtoll", CTX_BOTH, NULL, NULL, { K(192), K(256), K(224) }, 1,
	    { I(12345), I(31), I(-42) } },
	{ "d_hton", CTX_BOTH, NULL, NULL, { V(0x0102030405060708ULL) }, 1,
	    { I(0x0807), I(0x08070605), I(0x0807060504030201ULL), I(0x0807),
	    I(0x08070605), I(0x0807060504030201ULL) } },
	{ "d_inet", CTX_BOTH, NULL, NULL, { K(512), K(528) }, 1,
	    { S("::1"), S("10.0.0.1"), S("::1") } },
	{ "d_json", CTX_BOTH, NULL, NULL, { K(448) }, 1,
	    { S("42"), S("v"), S("8") } },
	/* copyinstr(addr, n) copies n characters and terminates the copy. */
	{ "d_copyin", CTX_BOTH, NULL, NULL, { U(288), U(0) }, 1,
	    { I(0x1817161514131211ULL), S("hello"), S("hel") } },
	{ "d_copyinto", CTX_BOTH, NULL, NULL, { U(288) }, 1,
	    { I(0x1817161514131211ULL) } },
	{ "d_bcopy", CTX_BOTH, NULL, NULL, { K(288) }, 1,
	    { I(0x1817161514131211ULL) } },
	{ "d_kload", CTX_BOTH, NULL, NULL, { K(288) }, 1,
	    { I(0x11), I(0x1211), I(0x14131211), I(0x1817161514131211ULL),
	    I(0x18) } },
	{ "d_uload", CTX_BOTH, NULL, NULL, { U(288) }, 1,
	    { I(0x11), I(0x1211), I(0x14131211), I(0x1817161514131211ULL),
	    I(0x18) } },
	/* memstr() joins NUL-separated memory with the separator. */
	{ "d_memstr", CTX_BOTH, NULL, NULL, { K(960) }, 1, { S("x,y,z,") } },
	{ "d_rand", CTX_BOTH, NULL, NULL, { V(0) }, 1, { I(1), I(1) } },
	{ "d_arith", CTX_BOTH, NULL, NULL, { V(17), V(5) }, 1,
	    { I(22), I(12), I(85), I(3), I(2), I(1), I(21), I(20), I(68),
	    I(8), I(~17ULL), I(0), I(1), I(0), I(-5), I(-5) } },
	{ "d_assoc", CTX_HOST, NULL, NULL, { V(3), V(40) }, 1,
	    { I(3), I(40), I(41), I(0) } },
	/* Guest arguments carry the VM's provenance and a scalar variable
	 * cannot hold a tagged value: the first store is an illegal
	 * operation (see the record's decisions section). */
	{ "d_assoc", CTX_GUEST, NULL, NULL, { V(3), V(40) }, 1,
	    { I(4), I(DTRACEFLT_ILLOP), ANY } },
	{ "d_search_err", CTX_GUEST, NULL, NULL, { K(128) }, 1, { S("b;c,d") } },
	/* Variables.  Host: the firing thread is root_td (pid 4500, comm
	 * "dtrace", parent proc0, root credentials, outside any jail).
	 * Guest: values come from hypertrace_args_t and guest memory; the
	 * h-prefixed variables report the host side. */
	{ "d_vars", CTX_HOST, NULL, NULL, { V(0) }, 1,
	    { I(4500), ANY, S("dtrace"), I(0), I(0), I(0), I(0), I(0), I(0),
	    S(""), S("host") } },
	{ "d_vars", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { I(99), I(4321), S("guestproc"), I(1001), I(1002), I(4), I(1),
	    I(98), I(9), S("jail9"), S("difvm") } },
	/* The host stack depth is the harness's real call depth. */
	{ "d_vars2", CTX_HOST, NULL, NULL, { V(0) }, 1,
	    { S("khx"), S("mod"), S("func"), S("entry"), ANY, ANY, I(1),
	    I(1), NZ, ANY, I(1), I(1) } },
	{ "d_vars2", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { S("khx"), S("mod"), S("func"), S("entry"), ANY, I(11), I(1),
	    I(1), I(3), I(0xffffffff80000abcULL), I(1), I(1) } },
	{ "d_hvars", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { I(4500), ANY, S("dtrace"), I(0), I(0), I(0), I(0), I(0), I(0),
	    S(""), S("host") } },
	{ "d_hvars2", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { S("khx"), S("mod"), S("func"), S("entry"), ANY, ANY, I(1),
	    I(1), ANY, ANY, I(1), I(1) } },
	{ "d_uvars", CTX_HOST, NULL, NULL, { V(0) }, 1,
	    { ANY, ANY, I(0xa0a0), S("dtrace -x") } },
	/* Guest: depth 3 over the fp chain, caller from the first frame,
	 * register from the guest trapframe, args from guest memory. */
	{ "d_uvars", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { I(3), I(0x402000), I(0xabcd), S("arg-a") } },
	{ "d_stack", CTX_BOTH, NULL, NULL, { V(0) }, 1,
	    { ANY, ANY } },
	{ "d_hargs", CTX_HOST, NULL, NULL, { V(0) }, 1, { ANY, ANY } },
	{ "d_hargs", CTX_GUEST, NULL, NULL, { V(0) }, 1, { I(0x55), I(0x99) } },
	{ "d_hustack", CTX_GUEST, NULL, NULL, { V(0) }, 1, { ANY, ANY } },
	/* execargs joins the NUL-separated argument vector with spaces. */
	{ "d_hexecargs", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { S("dtrace -x") } },
	{ "d_wall", CTX_HOST, NULL, NULL, { V(0) }, 1, { NZ, NZ, ANY } },
	{ "d_wall", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { I(1700000000000000000ULL), I(123456789), I(4242) } },
	/* A guest that did not supply a valid wall clock gets ILLOP. */
	{ "d_wall", CTX_GUEST, tw_nowall, NULL, { V(0) }, 1,
	    { I(0), I(DTRACEFLT_ILLOP), ANY } },
	{ "d_ustack", CTX_GUEST, NULL, ck_gustack, { V(0) }, 1, { ANY } },
	{ "d_ustack", CTX_GUEST, tw_entry, ck_gustack_entry, { V(0) }, 1,
	    { ANY } },
	{ "d_ustack", CTX_HOST, NULL, NULL, { V(0) }, 1, { ANY } },
	{ "d_kstack", CTX_GUEST, NULL, ck_gstack, { V(0) }, 1, { ANY } },
	{ "d_kstack", CTX_HOST, NULL, NULL, { V(0) }, 1, { ANY } },
	/* Fewer VMM-supplied PCs than stack() records: BADSTACK. */
	{ "d_kstack", CTX_GUEST, tw_fewframes, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADSTACK), ANY } },
	/* User-stack variables need a guest process and a known frame. */
	{ "d_uvars", CTX_GUEST, tw_nopid, NULL, { V(0) }, 1,
	    { I(0), I(0), ANY, ANY } },
	{ "d_uvars", CTX_GUEST, tw_badentry, NULL, { V(0) }, 1,
	    { I(0), I(DTRACEFLT_ILLOP), ANY } },
	{ "d_uvars", CTX_GUEST, tw_nothread, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	/* Each string/memory subroutine on an unreadable address. */
	{ "f_strlen", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_toupper", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_tolower", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_basename", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_dirname", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_cleanpath", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_strchr", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_strrchr", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_strstr", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_strstr2", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_index", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_rindex", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_rindex2", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_substr", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_strtok", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_strtok2", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_strjoin", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_strjoin2", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_strtoll", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_json", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_json2", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_inet4", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_inet6", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_ntoa", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_ntoa6", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_memstr", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_copyin", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_copyinstr", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_copyinto", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_bcopy", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_strcmp", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_strcmp2", CTX_BOTH, NULL, NULL, { V(8), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "f_ptinfo", CTX_GUEST, NULL, NULL, { V(8) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	/* Empty needles, out-of-range starts and failed searches ("a,b;c,d"). */
	{ "e_search", CTX_BOTH, NULL, NULL, { K(128) }, 1,
	    { I(7), I(0), S("a,b;c,d"), I(-1U), I(-1U), I(-1U), I(1), I(5),
	    I(-1U), I(3), I(3), I(1), I(1), I(1) } },
	/* substr() index/length clamping ("the quick brown fox", 19 chars). */
	{ "e_substr", CTX_BOTH, NULL, NULL, { K(320) }, 1,
	    { S(""), S("the quick brown fox"), S("e quick brown fo"), S(""),
	    S(""), S("he quick brown fox"), S("fo") } },
	{ "e_strtok", CTX_BOTH, NULL, NULL, { K(128) }, 1,
	    { I(1), S("a,b;c,d"), I(1), I(1) } },
	/* basename/dirname per POSIX; cleanpath() follows the upstream
	 * algorithm, which only collapses "/.." after a component. */
	{ "e_path", CTX_BOTH, NULL, NULL, { V(0) }, 1,
	    { S("/"), S("/"), S("noslash"), S("."), S("b"), S("a"), ANY, S("/"),
	    S("."), S("."), ANY, S("/") } },
	{ "e_case", CTX_BOTH, NULL, NULL, { V(0) }, 1,
	    { S(""), S(""), S("A1-Z"), S("a1-z") } },
	{ "e_strtoll", CTX_BOTH, NULL, NULL, { V(0) }, 1,
	    { I(0), I(35), I(12), I(-16), I(0777), I(12),
	    I(0x7fffffffffffffffULL) } },
	/* Bases outside 2..36 are illegal operations. */
	{ "e_strtoll_base", CTX_BOTH, NULL, NULL, { V(1) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "e_strtoll_base", CTX_BOTH, NULL, NULL, { V(37) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "e_lltostr", CTX_BOTH, NULL, NULL, { V(0) }, 1,
	    { S("0"), S("0xffffffffffffffff"), S("0"),
	    S("-9223372036854775808"), S("73") } },
	{ "e_lltostr_base", CTX_BOTH, NULL, NULL, { V(1) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "e_lltostr_base", CTX_BOTH, NULL, NULL, { V(37) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "e_json", CTX_BOTH, NULL, NULL, { K(448) }, 1,
	    { I(1), I(1), I(1), S("{\"n\":42}"), S("[7,8]"), S("1"), S("true"),
	    S("a\\\"b") } },
	{ "e_join", CTX_BOTH, NULL, NULL, { K(0) }, 1, { S(""), S("hello") } },
	/* Only AF_INET and AF_INET6 are formatted. */
	{ "e_inet", CTX_BOTH, NULL, NULL, { K(512) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "e_memref", CTX_BOTH, NULL, ck_printm, { K(288) }, 1, { I(8), ANY } },
	/* Host: printm() validates the referenced bytes in the action (DIF
	 * offset -1).  Guest: memref() copies guest bytes eagerly and faults. */
	{ "e_memref", CTX_HOST, NULL, NULL, { V(8) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), ANY } },
	{ "e_memref", CTX_GUEST, NULL, NULL, { V(8) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	/* Destructive copyout()/copyoutstr() into the (guest) user window,
	 * read back through copyin. */
	{ "e_copyout", CTX_BOTH, NULL, NULL, { U(800), K(288) }, 1,
	    { I(0x1817161514131211ULL), S("dtrace!") } },
	{ "e_copyout_bad", CTX_BOTH, NULL, NULL, { V(8), K(288) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "e_copyout_bad", CTX_BOTH, NULL, NULL, { U(800), V(8) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	/* A guest kernel thread has no user address space to write. */
	{ "e_copyout_bad", CTX_GUEST, tw_nopid, NULL, { U(800), K(288) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0x400320) } },
	{ "e_copyoutstr_bad", CTX_BOTH, NULL, NULL, { V(8) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	/* pid 4500's parent is proc0; guest processes are not host progeny. */
	{ "e_progeny", CTX_HOST, NULL, NULL, { V(4500) }, 1, { I(0), I(1) } },
	{ "e_progeny", CTX_GUEST, NULL, NULL, { V(4500) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "e_speculate", CTX_BOTH, NULL, NULL, { V(0) }, 1, { I(1) } },
	/* Actions in guest context: process and kernel control, Java and
	 * symbol actions have no meaning for a guest and are illegal. */
	{ "a_stop", CTX_HOST, NULL, ck_sigstop, { V(0) }, 1, { I(1) } },
	{ "a_raise", CTX_HOST, NULL, ck_sigkill, { V(0) }, 1, { I(1) } },
	{ "a_chill", CTX_HOST, NULL, NULL, { V(0) }, 1, { I(1) } },
	{ "a_jstack", CTX_HOST, NULL, ck_jstack_host, { V(0) }, 1, { ANY } },
	{ "a_sym", CTX_HOST, NULL, NULL, { V(0x1234) }, 1, { I(0x1234) } },
	{ "a_mod", CTX_HOST, NULL, NULL, { V(0x1234) }, 1, { I(0x1234) } },
	{ "a_usym", CTX_HOST, NULL, ck_uaddr_host, { V(0x1234) }, 1, { ANY } },
	{ "a_umod", CTX_HOST, NULL, ck_uaddr_host, { V(0x1234) }, 1, { ANY } },
	{ "a_uaddr", CTX_HOST, NULL, ck_uaddr_host, { V(0x1234) }, 1, { ANY } },
	{ "a_uaddr", CTX_GUEST, NULL, ck_uaddr_guest, { V(0x1234) }, 1,
	    { ANY } },
	{ "a_immstack", CTX_HOST, NULL, NULL, { V(0) }, 1, { ANY } },
	{ "a_stop", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_ILLOP), ANY } },
	{ "a_raise", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_ILLOP), ANY } },
	{ "a_chill", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_ILLOP), ANY } },
	{ "a_panic", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_ILLOP), ANY } },
	{ "a_bkpt", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_ILLOP), ANY } },
	{ "a_jstack", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_ILLOP), ANY } },
	{ "a_sym", CTX_GUEST, NULL, NULL, { V(0x1234) }, 1,
	    { I32(-1), I(DTRACEFLT_ILLOP), ANY } },
	{ "a_mod", CTX_GUEST, NULL, NULL, { V(0x1234) }, 1,
	    { I32(-1), I(DTRACEFLT_ILLOP), ANY } },
	{ "a_usym", CTX_GUEST, NULL, NULL, { V(0x1234) }, 1,
	    { I32(-1), I(DTRACEFLT_ILLOP), ANY } },
	{ "a_umod", CTX_GUEST, NULL, NULL, { V(0x1234) }, 1,
	    { I32(-1), I(DTRACEFLT_ILLOP), ANY } },
	{ "a_immstack", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_ILLOP), ANY } },
	/* printimmstack() (immstack() rewritten by dtrace_vprog_from() for
	 * the host side) prints what the guest formatted. */
	{ "a_pimmstack", CTX_BOTH, NULL, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADSTACK), ANY } },
	{ "a_pimmstack", CTX_GUEST, tw_imm, ck_pimm, { V(0) }, 1, { ANY } },
	{ "a_pimmstack", CTX_GUEST, tw_imm_misaligned, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADALIGN), ANY } },
	{ "a_pimmstack", CTX_GUEST, tw_imm_negative, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADSTACK), ANY } },
	/* Larger than the record: dropped, not recorded. */
	{ "a_pimmstack", CTX_GUEST, tw_imm_huge, NULL, { V(0) }, 0, { } },
	/* Unsigned and signed division/remainder: (2^64 - 7) / 3, mod 3, and
	 * -7 % 3 == -1; tagged guest operands of one VM keep that VM. */
	{ "v_udiv", CTX_BOTH, NULL, NULL, { V(-7), V(3) }, 1,
	    { I(0x5555555555555553ULL), I(0), I(-1) } },
	{ "v_udiv0", CTX_BOTH, NULL, NULL, { V(7), V(0) }, 1,
	    { ANY, I(DTRACEFLT_DIVZERO), ANY } },
	{ "v_urem0", CTX_BOTH, NULL, NULL, { V(7), V(0) }, 1,
	    { ANY, I(DTRACEFLT_DIVZERO), ANY } },
	{ "v_srem0", CTX_BOTH, NULL, NULL, { V(7), V(0) }, 1,
	    { ANY, I(DTRACEFLT_DIVZERO), ANY } },
	/* Sign-extending kernel and user loads of bytes 11 12 13 14. */
	{ "v_sload", CTX_BOTH, NULL, NULL, { K(288), U(288) }, 1,
	    { I(0x1211), I(0x14131211), I(0x1211), I(0x14131211) } },
	/* Loads from DTrace scratch (alloca) after a copy of those bytes. */
	{ "v_rload", CTX_BOTH, NULL, NULL, { K(288) }, 1,
	    { I(0x11), I(0x1211), I(0x14131211), I(0x11), I(0x1211),
	    I(0x14131211), I(0x1817161514131211ULL) } },
	{ "v_store", CTX_BOTH, NULL, NULL, { V(0) }, 1,
	    { I(1), I(2), I(3), I(4) } },
	/* A guest-tagged scalar may not be stored into host scratch. */
	{ "v_store_tag", CTX_HOST, NULL, NULL, { V(9) }, 1, { I(9) } },
	{ "v_store_tag", CTX_GUEST, NULL, NULL, { V(9) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	/* Guest strings copied into global, thread-local and associative
	 * string variables are host-owned copies. */
	{ "v_gstr", CTX_BOTH, NULL, NULL, { K(0) }, 1, { S("hello") } },
	{ "v_tstr", CTX_BOTH, NULL, NULL, { K(0) }, 1, { S("hello") } },
	{ "v_taa", CTX_BOTH, NULL, NULL, { V(0) }, 1, { I(5), I(0) } },
	{ "v_taas", CTX_BOTH, NULL, NULL, { K(0) }, 1, { S("hello") } },
	{ "v_gaas", CTX_BOTH, NULL, NULL, { K(0) }, 1, { S("hello") } },
	/*
	 * Guest regs[] uses the D register ABI of regs_x86.d (R_GS = 0 ...
	 * R_SS = 18, then 19 + REG_*) and reads the VM register through the
	 * VMM; the test VM holds 0x5000 + vm_reg_name.  Expected names:
	 * GS FS ES DS RDI RSI RBP RSP RBX RDX RCX RAX RIP CS RFLAGS RSP.
	 */
	{ "d_gregs", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { I(0x5000 + 27), I(0x5000 + 26), I(0x5000 + 22), I(0x5000 + 25),
	    I(0x5000 + 5), I(0x5000 + 4), I(0x5000 + 6), I(0x5000 + 19),
	    I(0x5000 + 1), I(0x5000 + 3), I(0x5000 + 2), I(0x5000 + 0),
	    I(0x5000 + 20), I(0x5000 + 23), I(0x5000 + 21), I(0x5000 + 19) } },
	/* R_SS, then 19 + REG_{R8 R15 R10 RIP RAX RCX R11 R9 R12 R13 R14 RBX
	 * RBP RSI RDI} (regset.h values 7 0 5 21 14 13 4 6 3 2 1 11 10 9 8). */
	{ "d_gregs_x", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { I(0x5000 + 24), I(0x5000 + 7), I(0x5000 + 14), I(0x5000 + 9),
	    I(0x5000 + 20), I(0x5000 + 0), I(0x5000 + 2), I(0x5000 + 10),
	    I(0x5000 + 8), I(0x5000 + 11), I(0x5000 + 12), I(0x5000 + 13),
	    I(0x5000 + 1), I(0x5000 + 6), I(0x5000 + 4), I(0x5000 + 5) } },
	/* TRAPNO, ERR, FS/GS base have no VMM register; a VMM read error is
	 * also an illegal operation. */
	{ "d_greg12", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "d_greg13", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "d_greg46", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "d_greg45", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "d_greg11", CTX_GUEST, tw_getreg_fails, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	/* Host probes have no DTrace trap frame here (not via invop). */
	{ "d_greg11", CTX_HOST, NULL, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	/* hostid is the node id on the host and the VM's id for a guest;
	 * hhostid is always the host node id.  libdtrace cannot type hostid
	 * without kernel CTF, so the program loads epid and id and the test
	 * rewrites those variable references (ck/patch below). */
	{ "d_hostid", CTX_HOST, NULL, ck_hostid_host, { V(0) }, 1,
	    { ANY, ANY } },
	{ "d_hostid", CTX_GUEST, NULL, ck_hostid_guest, { V(0) }, 1,
	    { ANY, ANY } },
	/* A NULL guest pointer: refused before any guest access. */
	{ "f_strlen", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_toupper", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_tolower", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_basename", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_dirname", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_cleanpath", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strchr", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strrchr", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strstr", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strstr2", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_index", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_rindex", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_rindex2", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_substr", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strtok", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strtok2", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strjoin", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strjoin2", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strtoll", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_json", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_json2", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_inet4", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_inet6", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_ntoa", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_ntoa6", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_memstr", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_copyin", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_copyinstr", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_copyinto", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_bcopy", CTX_GUEST, NULL, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	/* A NULL string compares as the empty string (SCMP), whether the
	 * pointer is a host or a guest one, and whatever the guest maps at 0. */
	{ "f_strcmp", CTX_BOTH, NULL, NULL, { V(0), K(128) }, 1, { I(0) } },
	{ "f_strcmp2", CTX_BOTH, NULL, NULL, { V(0), K(128) }, 1, { I(0) } },
	/* Guest strings that run to the top of the address space (256 bytes
	 * of 'T' ending at UINTPTR_MAX, strsize 256): string subroutines
	 * refuse them rather than wrap; fixed-size reads succeed. */
	{ "f_strlen", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { I(256) } },
	{ "f_toupper", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_tolower", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_basename", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_dirname", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_cleanpath", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_strchr", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_strrchr", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_strstr", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_strstr2", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_index", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_rindex", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_rindex2", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_substr", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_strtok", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_strtok2", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_strjoin", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "f_strjoin2", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "f_strtoll", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_json", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_json2", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_inet4", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { S("84.84.84.84") } },
	{ "f_inet6", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { S("5454:5454:5454:5454:5454:5454:5454:5454") } },
	{ "f_ntoa", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { S("84.84.84.84") } },
	{ "f_ntoa6", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { S("5454:5454:5454:5454:5454:5454:5454:5454") } },
	{ "f_memstr", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { S("TTT") } },
	{ "f_copyin", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_copyinstr", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_copyinto", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "f_bcopy", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { I(0x5454545454545454ULL) } },
	{ "f_strcmp", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { I(0) } },
	{ "f_strcmp2", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { I(0) } },
	/* By-reference records from kernel and user memory (DIF_TF_BYREF and
	 * DIF_TF_BYUREF), in host and guest. */
	{ "k_struct", CTX_BOTH, NULL, ck_struct, { K(288) }, 1, { ANY } },
	{ "u_struct", CTX_BOTH, NULL, ck_struct, { U(288) }, 1, { ANY } },
	{ "u_arr", CTX_BOTH, NULL, ck_arr, { U(0) }, 1, { ANY } },
	{ "u_ustr", CTX_BOTH, NULL, NULL, { U(0) }, 1, { S("hello") } },
	/* The user copy happens in the action (DIF offset -1). */
	{ "u_struct", CTX_BOTH, NULL, NULL, { V(8) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), I(8) } },
	{ "u_ustr", CTX_BOTH, NULL, NULL, { V(8) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), I(8) } },
	/* Destinations must be host scratch: a guest-tagged destination is
	 * illegal, an untagged one outside scratch a bad address. */
	{ "g_bcopy_dst", CTX_HOST, NULL, ck_illval_u800, { U(800) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	{ "g_bcopy_dst", CTX_GUEST, NULL, NULL, { U(800) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "g_copyinto_dst", CTX_HOST, NULL, ck_illval_u800, { U(800), U(288) },
	    1, { ANY, I(DTRACEFLT_BADADDR), ANY } },
	{ "g_copyinto_dst", CTX_GUEST, NULL, NULL, { U(800), U(288) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	/* Sizes beyond scratch. */
	{ "g_copyin_big", CTX_BOTH, NULL, NULL, { U(288), V(-1) }, 1,
	    { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "g_copyinstr_big", CTX_BOTH, NULL, NULL, { U(0), V(-1) }, 1,
	    { S("hello") } },
	{ "g_alloca_big", CTX_BOTH, NULL, NULL, { V(1 << 20) }, 1,
	    { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "g_alloca_big", CTX_BOTH, NULL, NULL, { V(-1) }, 1,
	    { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	/* A constant address is untagged: in a guest clause it is refused
	 * rather than read as host memory. */
	{ "g_const", CTX_BOTH, NULL, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0x123) } },
	{ "g_memref_const", CTX_HOST, NULL, NULL, { V(0) }, 1, { I(8) } },
	{ "g_memref_const", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	/* A host memref() only describes memory; a guest one copies it. */
	{ "g_memref_big", CTX_HOST, NULL, NULL, { K(0), V(1 << 20) }, 1,
	    { I(1 << 20) } },
	{ "g_memref_big", CTX_GUEST, NULL, NULL, { K(0), V(1 << 20) }, 1,
	    { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "g_strjoin_big", CTX_BOTH, NULL, NULL, { K(320) }, 1,
	    { S("the quick brown foxthe quick brown foxthe quick brown fox") } },
	/*
	 * Guest helpers under VMM failures and odd frames.  EOPNOTSUPP from
	 * the VMM (or no VMM routine) is an illegal operation, any other
	 * failure a bad address at the word being read; self-referencing or
	 * cyclic frame chains are bad stacks; without a VMM kernel copy
	 * routine guest kernel memory is read by page translation.
	 */
	{ "d_uvars", CTX_GUEST, tw_ucopy_eop, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "d_uvars", CTX_GUEST, tw_ucopy_efault, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0x400208) } },
	{ "d_uvars", CTX_GUEST, tw_no_user_hooks, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "d_uvars", CTX_GUEST, tw_fp_self, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADSTACK), I(0x400200) } },
	{ "d_uvars", CTX_GUEST, tw_fp_cycle, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADSTACK), I(0x400200) } },
	{ "d_uvars", CTX_GUEST, tw_fp_outside, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0x7000008) } },
	{ "d_uvars", CTX_GUEST, tw_fp_top, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xfffffffffffffff8ULL) } },
	{ "d_uvars", CTX_GUEST, tw_fp_zero, NULL, { V(0) }, 1,
	    { I(1), I(0), I(0xabcd), S("arg-a") } },
	{ "d_uvars", CTX_GUEST, tw_entry_badsp, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0x7000000) } },
	{ "d_uvars", CTX_GUEST, tw_td_frame_null, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "d_uvars", CTX_GUEST, tw_td_frame_bad, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0x1234) } },
	{ "d_uvars", CTX_GUEST, tw_thread_top, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xfffffffffffffff0ULL) } },
	{ "d_ustack", CTX_GUEST, tw_ucopy_eop, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_ILLOP), ANY } },
	{ "d_ustack", CTX_GUEST, tw_fp_self, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADSTACK), I(0x400200) } },
	{ "d_ustack", CTX_GUEST, tw_fp_cycle, ck_gustack_cycle, { V(0) }, 1,
	    { ANY } },
	{ "d_ustack", CTX_GUEST, tw_fp_outside, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), I(0x7000008) } },
	{ "d_ustack", CTX_GUEST, tw_fp_top, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), I(0xfffffffffffffff8ULL) } },
	{ "d_ustack", CTX_GUEST, tw_nopid, ck_gustack_nopid, { V(0) }, 1,
	    { ANY } },
	{ "d_ustack", CTX_GUEST, tw_badentry, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_ILLOP), ANY } },
	{ "d_ustack", CTX_GUEST, tw_entry_badsp, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), I(0x7000000) } },
	{ "d_ustack", CTX_GUEST, tw_td_frame_null, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), I(0) } },
	{ "d_uload", CTX_GUEST, tw_ucopy_eop, NULL, { U(288) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "d_uload", CTX_GUEST, tw_ucopy_efault, NULL, { U(288) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0x400120) } },
	{ "d_uload", CTX_GUEST, tw_no_user_hooks, NULL, { U(288) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "d_uload", CTX_GUEST, tw_nopid, NULL, { U(288) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0x400120) } },
	{ "d_uload", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "d_uload", CTX_GUEST, NULL, NULL, { V(-4) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xfffffffffffffffcULL) } },
	{ "d_copyin", CTX_GUEST, tw_ucopy_eop, NULL, { U(288), U(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "d_copyin", CTX_GUEST, tw_nopid, NULL, { U(288), U(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0x400120) } },
	{ "d_copyin", CTX_GUEST, tw_no_user_hooks, NULL, { U(288), U(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "u_struct", CTX_GUEST, tw_ucopy_eop, NULL, { U(288) }, 1,
	    { I32(-1), I(DTRACEFLT_ILLOP), ANY } },
	{ "u_ustr", CTX_GUEST, tw_ucopy_efault, NULL, { U(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), I(0x400000) } },
	{ "e_copyout", CTX_GUEST, tw_ucopyout_eop, NULL, { U(800), K(288) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "e_copyout", CTX_GUEST, tw_ucopyout_efault, NULL, { U(800), K(288) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0x400320) } },
	{ "e_copyout", CTX_GUEST, tw_no_user_hooks, NULL, { U(800), K(288) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "e_copyout", CTX_GUEST, tw_kcopy_eop, NULL, { U(800), K(288) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "e_copyout_bad", CTX_GUEST, NULL, NULL, { V(-4), K(288) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xfffffffffffffffcULL) } },
	{ "e_copyout_bad", CTX_GUEST, NULL, NULL, { U(800), V(-4) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xfffffffffffffffcULL) } },
	{ "e_copyoutstr_bad", CTX_GUEST, NULL, NULL, { V(-4) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xfffffffffffffffcULL) } },
	{ "d_kload", CTX_GUEST, tw_kcopy_eop, NULL, { K(288) }, 1,
	    { I(0x11), I(0x1211), I(0x14131211), I(0x1817161514131211ULL), I(0x18) } },
	{ "d_kload", CTX_GUEST, tw_kcopy_eop_unmapped, NULL, { K(288) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffff800000100120ULL) } },
	{ "d_kload", CTX_GUEST, tw_no_kernel_hook, NULL, { K(288) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffff800000100120ULL) } },
	{ "d_str", CTX_GUEST, tw_kcopy_eop, NULL, { K(0) }, 1,
	    { I(5), S("hello"), I(1), I(1) } },
	{ "d_vars", CTX_GUEST, tw_bad_execname, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0x1234) } },
	{ "d_kstack", CTX_GUEST, tw_kcopy_eop_unmapped, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), I(0xffff800000103800ULL) } },
	/* Lock subroutines dereference host lock objects: never for a guest. */
	{ "l_mtx", CTX_GUEST, NULL, NULL, { K(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "l_rd", CTX_GUEST, NULL, NULL, { K(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "l_wr", CTX_GUEST, NULL, NULL, { K(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	/*
	 * strtoll() limits: with strsize 4, all-blank, a lone sign at the
	 * limit and digits up to the limit; INT64_MIN; and (guest) strings
	 * whose next byte is unmapped at each stage of parsing.
	 */
	{ "s_strtoll", CTX_BOTH, NULL, NULL, { K(736) }, 1, { I(0) } },
	{ "s_strtoll", CTX_BOTH, NULL, NULL, { K(744) }, 1, { I(0) } },
	{ "s_strtoll", CTX_BOTH, NULL, NULL, { K(752) }, 1, { I(1234) } },
	{ "s_strtoll16", CTX_BOTH, NULL, NULL, { K(784) }, 1, { I(0) } },
	{ "f_strtoll", CTX_BOTH, NULL, NULL, { K(760) }, 1,
	    { I(0x8000000000000000ULL) } },
	{ "f_strtoll", CTX_GUEST, tw_end_ws, NULL, { K(16384 - 3) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffff800000104000ULL) } },
	{ "f_strtoll", CTX_GUEST, tw_end_sign, NULL, { K(16384 - 1) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffff800000104000ULL) } },
	{ "f_strtoll", CTX_GUEST, tw_end_digits, NULL, { K(16384 - 2) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffff800000104000ULL) } },
	{ "e_strtoll_hex", CTX_GUEST, tw_end_zero, NULL, { K(16384 - 1) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffff800000104000ULL) } },
	{ "e_strtoll_hex", CTX_GUEST, tw_end_0x, NULL, { K(16384 - 2) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffff800000104000ULL) } },
	/* Scratch exhaustion: alloca() takes all but 8 bytes first. */
	{ "n_copyinstr", CTX_BOTH, NULL, NULL, { U(0), V(0), SCR(8) }, 1, { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "n_strtok", CTX_BOTH, NULL, NULL, { K(128), V(0), SCR(8) }, 1, { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "n_substr", CTX_BOTH, NULL, NULL, { K(0), V(0), SCR(8) }, 1, { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "n_json", CTX_BOTH, NULL, NULL, { K(448), V(0), SCR(8) }, 1, { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "n_toupper", CTX_BOTH, NULL, NULL, { K(0), V(0), SCR(8) }, 1, { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "n_lltostr", CTX_BOTH, NULL, NULL, { V(12345), V(0), SCR(8) }, 1, { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "n_basename", CTX_BOTH, NULL, NULL, { K(64), V(0), SCR(8) }, 1, { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "n_cleanpath", CTX_BOTH, NULL, NULL, { K(384), V(0), SCR(8) }, 1, { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "n_inet4", CTX_BOTH, NULL, NULL, { K(512), V(0), SCR(8) }, 1, { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "n_inet6", CTX_BOTH, NULL, NULL, { K(528), V(0), SCR(8) }, 1, { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "n_memref", CTX_BOTH, NULL, NULL, { K(288), V(0), SCR(8) }, 1, { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "n_strjoin", CTX_BOTH, NULL, NULL, { K(0), V(0), SCR(8) }, 1, { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "n_memstr", CTX_BOTH, NULL, NULL, { K(960), V(0), SCR(8) }, 1, { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "n_copyin", CTX_BOTH, NULL, NULL, { U(288), V(0), SCR(0) }, 1,
	    { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	/* Host process strings are not copied; a guest's are. */
	{ "n_execname", CTX_HOST, NULL, NULL, { K(0), V(0), SCR(8) }, 1, { S("dtrace") } },
	{ "n_execname", CTX_GUEST, NULL, NULL, { K(0), V(0), SCR(8) }, 1, { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	/* Host process strings are not copied; a guest's are. */
	{ "n_jailname", CTX_HOST, NULL, NULL, { K(0), V(0), SCR(8) }, 1, { S("") } },
	{ "n_jailname", CTX_GUEST, NULL, NULL, { K(0), V(0), SCR(8) }, 1, { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "n_execargs", CTX_BOTH, NULL, NULL, { K(0), V(0), SCR(8) }, 1, { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "n_ntoa6", CTX_BOTH, NULL, NULL, { K(528), V(0), SCR(8) }, 1, { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "n_ntoa", CTX_BOTH, NULL, NULL, { K(512), V(0), SCR(8) }, 1, { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	/* strsize 0: string-producing subroutines are illegal; copyinstr has
	 * no room; json cannot authorize a zero-length string region. */
	{ "z:zz_tok", CTX_BOTH, NULL, NULL, { K(128) }, 1, { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "z:zz_sub", CTX_BOTH, NULL, NULL, { K(128) }, 1, { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "z:zz_up", CTX_BOTH, NULL, NULL, { K(128) }, 1, { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "z:zz_base", CTX_BOTH, NULL, NULL, { K(128) }, 1, { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "z:zz_clean", CTX_BOTH, NULL, NULL, { K(128) }, 1, { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "z:zz_cpi", CTX_BOTH, NULL, NULL, { U(0) }, 1,
	    { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "z:zz_json", CTX_BOTH, NULL, NULL, { K(448) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	/* Empty haystack and/or needle, with positions out of range. */
	{ "e_search_empty", CTX_BOTH, NULL, NULL, { K(1023), K(0) }, 1,
	    { I(0), I(0), I(1), I(0), I(0), I(-1U), I(0), I(5) } },
	/* substr() with a negative length past the start, and with a length
	 * longer than the string size (strsize 256, then 4). */
	{ "e_substr2", CTX_BOTH, NULL, NULL, { K(320) }, 1,
	    { S(""), S("the quick brown fox") } },
	{ "s:e_substr2", CTX_BOTH, NULL, NULL, { K(320) }, 1,
	    { S(""), S("the") } },
	{ "e_inet_af", CTX_BOTH, NULL, NULL, { K(512), V(99) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	/* Guest page zero mapped: NULL is still refused. */
	{ "f_strlen", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_toupper", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_basename", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_cleanpath", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strchr", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strrchr", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strstr", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strstr2", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_index", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_rindex2", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_substr", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strtok", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strtok2", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strjoin2", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strtoll", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_json", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_json2", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_inet4", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_inet6", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_memstr", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_copyinto", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_bcopy", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strcmp", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1,
	    { I(0) } },
	{ "f_strcmp2", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1,
	    { I(0) } },
	{ "e_memref", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_ntoa6", CTX_GUEST, tw_zero_page, NULL, { V(0), K(128) }, 1, { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	/*
	 * Signed and unsigned comparisons at the extremes, where the
	 * subtraction behind DIF_OP_CMP overflows; the oracle is C's own
	 * comparison of the same int64_t/uint64_t values.
	 */
	{ "c_cmp", CTX_HOST, NULL, NULL, { V((int64_t)(INT64_MIN)), V((int64_t)(1000)) }, 1,
	    { I((int64_t)(INT64_MIN) < (int64_t)(1000)), I((int64_t)(INT64_MIN) <= (int64_t)(1000)), I((int64_t)(INT64_MIN) > (int64_t)(1000)), I((int64_t)(INT64_MIN) >= (int64_t)(1000)), I((int64_t)(INT64_MIN) == (int64_t)(1000)), I((int64_t)(INT64_MIN) != (int64_t)(1000)), I((uint64_t)(int64_t)(INT64_MIN) < (uint64_t)(int64_t)(1000)), I((uint64_t)(int64_t)(INT64_MIN) <= (uint64_t)(int64_t)(1000)), I((uint64_t)(int64_t)(INT64_MIN) > (uint64_t)(int64_t)(1000)), I((uint64_t)(int64_t)(INT64_MIN) >= (uint64_t)(int64_t)(1000)) } },
	{ "c_cmp", CTX_HOST, NULL, NULL, { V((int64_t)(1000)), V((int64_t)(INT64_MIN)) }, 1,
	    { I((int64_t)(1000) < (int64_t)(INT64_MIN)), I((int64_t)(1000) <= (int64_t)(INT64_MIN)), I((int64_t)(1000) > (int64_t)(INT64_MIN)), I((int64_t)(1000) >= (int64_t)(INT64_MIN)), I((int64_t)(1000) == (int64_t)(INT64_MIN)), I((int64_t)(1000) != (int64_t)(INT64_MIN)), I((uint64_t)(int64_t)(1000) < (uint64_t)(int64_t)(INT64_MIN)), I((uint64_t)(int64_t)(1000) <= (uint64_t)(int64_t)(INT64_MIN)), I((uint64_t)(int64_t)(1000) > (uint64_t)(int64_t)(INT64_MIN)), I((uint64_t)(int64_t)(1000) >= (uint64_t)(int64_t)(INT64_MIN)) } },
	{ "c_cmp", CTX_HOST, NULL, NULL, { V((int64_t)(INT64_MAX)), V((int64_t)(-1)) }, 1,
	    { I((int64_t)(INT64_MAX) < (int64_t)(-1)), I((int64_t)(INT64_MAX) <= (int64_t)(-1)), I((int64_t)(INT64_MAX) > (int64_t)(-1)), I((int64_t)(INT64_MAX) >= (int64_t)(-1)), I((int64_t)(INT64_MAX) == (int64_t)(-1)), I((int64_t)(INT64_MAX) != (int64_t)(-1)), I((uint64_t)(int64_t)(INT64_MAX) < (uint64_t)(int64_t)(-1)), I((uint64_t)(int64_t)(INT64_MAX) <= (uint64_t)(int64_t)(-1)), I((uint64_t)(int64_t)(INT64_MAX) > (uint64_t)(int64_t)(-1)), I((uint64_t)(int64_t)(INT64_MAX) >= (uint64_t)(int64_t)(-1)) } },
	{ "c_cmp", CTX_HOST, NULL, NULL, { V((int64_t)(-1)), V((int64_t)(INT64_MAX)) }, 1,
	    { I((int64_t)(-1) < (int64_t)(INT64_MAX)), I((int64_t)(-1) <= (int64_t)(INT64_MAX)), I((int64_t)(-1) > (int64_t)(INT64_MAX)), I((int64_t)(-1) >= (int64_t)(INT64_MAX)), I((int64_t)(-1) == (int64_t)(INT64_MAX)), I((int64_t)(-1) != (int64_t)(INT64_MAX)), I((uint64_t)(int64_t)(-1) < (uint64_t)(int64_t)(INT64_MAX)), I((uint64_t)(int64_t)(-1) <= (uint64_t)(int64_t)(INT64_MAX)), I((uint64_t)(int64_t)(-1) > (uint64_t)(int64_t)(INT64_MAX)), I((uint64_t)(int64_t)(-1) >= (uint64_t)(int64_t)(INT64_MAX)) } },
	{ "c_cmp", CTX_HOST, NULL, NULL, { V((int64_t)(INT64_MIN)), V((int64_t)(INT64_MAX)) }, 1,
	    { I((int64_t)(INT64_MIN) < (int64_t)(INT64_MAX)), I((int64_t)(INT64_MIN) <= (int64_t)(INT64_MAX)), I((int64_t)(INT64_MIN) > (int64_t)(INT64_MAX)), I((int64_t)(INT64_MIN) >= (int64_t)(INT64_MAX)), I((int64_t)(INT64_MIN) == (int64_t)(INT64_MAX)), I((int64_t)(INT64_MIN) != (int64_t)(INT64_MAX)), I((uint64_t)(int64_t)(INT64_MIN) < (uint64_t)(int64_t)(INT64_MAX)), I((uint64_t)(int64_t)(INT64_MIN) <= (uint64_t)(int64_t)(INT64_MAX)), I((uint64_t)(int64_t)(INT64_MIN) > (uint64_t)(int64_t)(INT64_MAX)), I((uint64_t)(int64_t)(INT64_MIN) >= (uint64_t)(int64_t)(INT64_MAX)) } },
	{ "c_cmp", CTX_HOST, NULL, NULL, { V((int64_t)(INT64_MAX)), V((int64_t)(INT64_MIN)) }, 1,
	    { I((int64_t)(INT64_MAX) < (int64_t)(INT64_MIN)), I((int64_t)(INT64_MAX) <= (int64_t)(INT64_MIN)), I((int64_t)(INT64_MAX) > (int64_t)(INT64_MIN)), I((int64_t)(INT64_MAX) >= (int64_t)(INT64_MIN)), I((int64_t)(INT64_MAX) == (int64_t)(INT64_MIN)), I((int64_t)(INT64_MAX) != (int64_t)(INT64_MIN)), I((uint64_t)(int64_t)(INT64_MAX) < (uint64_t)(int64_t)(INT64_MIN)), I((uint64_t)(int64_t)(INT64_MAX) <= (uint64_t)(int64_t)(INT64_MIN)), I((uint64_t)(int64_t)(INT64_MAX) > (uint64_t)(int64_t)(INT64_MIN)), I((uint64_t)(int64_t)(INT64_MAX) >= (uint64_t)(int64_t)(INT64_MIN)) } },
	{ "c_cmp", CTX_HOST, NULL, NULL, { V((int64_t)(0)), V((int64_t)(INT64_MIN)) }, 1,
	    { I((int64_t)(0) < (int64_t)(INT64_MIN)), I((int64_t)(0) <= (int64_t)(INT64_MIN)), I((int64_t)(0) > (int64_t)(INT64_MIN)), I((int64_t)(0) >= (int64_t)(INT64_MIN)), I((int64_t)(0) == (int64_t)(INT64_MIN)), I((int64_t)(0) != (int64_t)(INT64_MIN)), I((uint64_t)(int64_t)(0) < (uint64_t)(int64_t)(INT64_MIN)), I((uint64_t)(int64_t)(0) <= (uint64_t)(int64_t)(INT64_MIN)), I((uint64_t)(int64_t)(0) > (uint64_t)(int64_t)(INT64_MIN)), I((uint64_t)(int64_t)(0) >= (uint64_t)(int64_t)(INT64_MIN)) } },
	{ "c_cmp", CTX_HOST, NULL, NULL, { V((int64_t)(INT64_MIN)), V((int64_t)(0)) }, 1,
	    { I((int64_t)(INT64_MIN) < (int64_t)(0)), I((int64_t)(INT64_MIN) <= (int64_t)(0)), I((int64_t)(INT64_MIN) > (int64_t)(0)), I((int64_t)(INT64_MIN) >= (int64_t)(0)), I((int64_t)(INT64_MIN) == (int64_t)(0)), I((int64_t)(INT64_MIN) != (int64_t)(0)), I((uint64_t)(int64_t)(INT64_MIN) < (uint64_t)(int64_t)(0)), I((uint64_t)(int64_t)(INT64_MIN) <= (uint64_t)(int64_t)(0)), I((uint64_t)(int64_t)(INT64_MIN) > (uint64_t)(int64_t)(0)), I((uint64_t)(int64_t)(INT64_MIN) >= (uint64_t)(int64_t)(0)) } },
	{ "c_cmp", CTX_HOST, NULL, NULL, { V((int64_t)(INT64_MIN)), V((int64_t)(INT64_MIN)) }, 1,
	    { I((int64_t)(INT64_MIN) < (int64_t)(INT64_MIN)), I((int64_t)(INT64_MIN) <= (int64_t)(INT64_MIN)), I((int64_t)(INT64_MIN) > (int64_t)(INT64_MIN)), I((int64_t)(INT64_MIN) >= (int64_t)(INT64_MIN)), I((int64_t)(INT64_MIN) == (int64_t)(INT64_MIN)), I((int64_t)(INT64_MIN) != (int64_t)(INT64_MIN)), I((uint64_t)(int64_t)(INT64_MIN) < (uint64_t)(int64_t)(INT64_MIN)), I((uint64_t)(int64_t)(INT64_MIN) <= (uint64_t)(int64_t)(INT64_MIN)), I((uint64_t)(int64_t)(INT64_MIN) > (uint64_t)(int64_t)(INT64_MIN)), I((uint64_t)(int64_t)(INT64_MIN) >= (uint64_t)(int64_t)(INT64_MIN)) } },
	{ "c_cmp", CTX_HOST, NULL, NULL, { V((int64_t)(-5)), V((int64_t)(3)) }, 1,
	    { I((int64_t)(-5) < (int64_t)(3)), I((int64_t)(-5) <= (int64_t)(3)), I((int64_t)(-5) > (int64_t)(3)), I((int64_t)(-5) >= (int64_t)(3)), I((int64_t)(-5) == (int64_t)(3)), I((int64_t)(-5) != (int64_t)(3)), I((uint64_t)(int64_t)(-5) < (uint64_t)(int64_t)(3)), I((uint64_t)(int64_t)(-5) <= (uint64_t)(int64_t)(3)), I((uint64_t)(int64_t)(-5) > (uint64_t)(int64_t)(3)), I((uint64_t)(int64_t)(-5) >= (uint64_t)(int64_t)(3)) } },
	/* Unset thread-local scalars read as 0; NULL strings stored in global
	 * and clause-local string variables read back as NULL. */
	{ "w_ldts", CTX_BOTH, NULL, NULL, { V(0) }, 1, { I(0) } },
	{ "w_gnull", CTX_BOTH, NULL, NULL, { V(0), V(0) }, 1, { I(1) } },
	{ "w_lnull", CTX_BOTH, NULL, NULL, { V(0), V(0) }, 1, { I(1) } },
	/* Scalar stores of a guest-tagged value are refused (current design,
	 * decision pending); the host stores and reads back. */
	{ "w_stts", CTX_HOST, NULL, NULL, { V(7) }, 1, { I(7) } },
	{ "w_stls", CTX_HOST, NULL, NULL, { V(7) }, 1, { I(7) } },
	{ "w_stgaa", CTX_HOST, NULL, NULL, { V(7) }, 1, { I(7) } },
	{ "w_sttaa", CTX_HOST, NULL, NULL, { V(7) }, 1, { I(7) } },
	{ "w_stgs", CTX_HOST, NULL, NULL, { V(7) }, 1, { I(7) } },
	{ "w_stb", CTX_HOST, NULL, NULL, { V(7) }, 1, { I(1) } },
	{ "w_sth", CTX_HOST, NULL, NULL, { V(7) }, 1, { I(1) } },
	{ "w_stw", CTX_HOST, NULL, NULL, { V(7) }, 1, { I(1) } },
	{ "w_stts", CTX_GUEST, NULL, NULL, { V(7) }, 1, { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "w_stls", CTX_GUEST, NULL, NULL, { V(7) }, 1, { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "w_stgaa", CTX_GUEST, NULL, NULL, { V(7) }, 1, { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "w_sttaa", CTX_GUEST, NULL, NULL, { V(7) }, 1, { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "w_stgs", CTX_GUEST, NULL, NULL, { V(7) }, 1, { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "w_stb", CTX_GUEST, NULL, NULL, { V(7) }, 1, { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "w_sth", CTX_GUEST, NULL, NULL, { V(7) }, 1, { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "w_stw", CTX_GUEST, NULL, NULL, { V(7) }, 1, { ANY, I(DTRACEFLT_ILLOP), ANY } },
	/* Stores outside DTrace scratch: a bad address on the host, illegal
	 * through a guest pointer. */
	{ "w_stbg", CTX_HOST, NULL, ck_illval_k800, { K(800) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	{ "w_sthg", CTX_HOST, NULL, ck_illval_k800, { K(800) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	{ "w_stwg", CTX_HOST, NULL, ck_illval_k800, { K(800) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	{ "w_stxg", CTX_HOST, NULL, ck_illval_k800, { K(800) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	{ "w_stbg", CTX_GUEST, NULL, NULL, { K(800) }, 1, { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "w_sthg", CTX_GUEST, NULL, NULL, { K(800) }, 1, { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "w_stwg", CTX_GUEST, NULL, NULL, { K(800) }, 1, { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "w_stxg", CTX_GUEST, NULL, NULL, { K(800) }, 1, { ANY, I(DTRACEFLT_ILLOP), ANY } },
	/* Misaligned scratch stores (illval: the odd address). */
	{ "w_align2", CTX_BOTH, NULL, ck_odd_illval, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADALIGN), ANY } },
	{ "w_align4", CTX_BOTH, NULL, ck_odd_illval, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADALIGN), ANY } },
	{ "w_align8", CTX_BOTH, NULL, ck_odd_illval, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADALIGN), ANY } },
	/* Predicates, true and false; /pid == 1/ is cacheable (host only). */
	{ "w_pred", CTX_BOTH, NULL, NULL, { V(1) }, 1, { I(2) } },
	{ "w_pred", CTX_BOTH, NULL, NULL, { V(2) }, 0, { } },
	{ "w_predc", CTX_BOTH, NULL, NULL, { V(0) }, 0, { } },
	{ "w_predc", CTX_BOTH, NULL, NULL, { V(0) }, 0, { } },
	/* FreeBSD has no zones: zonename is NULL on the host; for a guest it
	 * is the guest's jail name. */
	{ "w_zone", CTX_HOST, NULL, NULL, { V(0) }, 1, { I(0) } },
	{ "w_zone", CTX_GUEST, NULL, NULL, { V(0) }, 1, { S("jail9") } },
	/* Struct copy into a clause-local (DIF_OP_COPYS). */
	{ "w_copys", CTX_BOTH, NULL, NULL, { K(288) }, 1, { I(0x14131211) } },
	{ "w_copys", CTX_BOTH, NULL, NULL, { V(8) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "w_gstrkey", CTX_BOTH, NULL, NULL, { K(0) }, 1, { I(1) } },
	/* Terminated strings whose string-size window would wrap. */
	{ "f_strlen", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff80ULL) } },
	{ "f_toupper", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { S("AB") } },
	{ "f_basename", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { S("ab") } },
	{ "f_cleanpath", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff80ULL) } },
	{ "f_strchr", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff80ULL) } },
	{ "f_strrchr", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff80ULL) } },
	{ "f_strstr", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	{ "f_index", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { I(-1U) } },
	{ "f_rindex", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { I(-1U) } },
	{ "f_substr", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { S("b") } },
	{ "f_strtok", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff80ULL) } },
	{ "f_strjoin", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff80ULL) } },
	{ "f_strtoll", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff80ULL) } },
	{ "f_json", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff80ULL) } },
	{ "f_memstr", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { S("ab,") } },
	{ "f_tracestr", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff80ULL) } },
	{ "f_strcmp", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff80ULL) } },
	{ "f_strstr2", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	{ "f_rindex2", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { I(-1U) } },
	{ "f_strtok2", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff80ULL) } },
	{ "f_strjoin2", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff80ULL) } },
	{ "f_json2", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	/* Strings that reach the last byte of the address space (strsize 512). */
	{ "L:f_strlen", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "L:f_strcmp", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	{ "L:f_strcmp2", CTX_GUEST, NULL, NULL, { V(0xffffffffffffff00ULL), V(0xffffffffffffff00ULL) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff00ULL) } },
	/* strsize 0: strtoll() scans nothing, in host and guest alike. */
	{ "z:f_strtoll", CTX_BOTH, NULL, NULL, { K(192) }, 1, { I(0) } },
	{ "z:d_vars", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), ANY } },
	/* Zero-length copies are no-ops for host and guest sources. */
	{ "p_bcopy0", CTX_BOTH, NULL, NULL, { K(288) }, 1, { I(1) } },
	/* Overlapping scratch copy to a higher address (memmove semantics). */
	{ "p_overlap", CTX_HOST, NULL, NULL, { V(0) }, 1, { I(0x08070605) } },
	{ "f_bcopy", CTX_HOST, NULL, NULL, { V(-4), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(-4) } },
	{ "e_copyout0", CTX_BOTH, NULL, NULL, { U(800), K(288) }, 1, { I(1) } },
	{ "f_copyinstr", CTX_GUEST, NULL, NULL, { V(-2), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(-2) } },
	{ "e_copyoutstr_bad", CTX_GUEST, NULL, NULL, { V(-2) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(-2) } },
	/* ucaller: at an entry probe the word at the stack pointer; frame
	 * pointer at the top of the address space or a NULL stack pointer
	 * fault; a kernel thread (pid 0), or no frame pointer: 0. */
	{ "d_ucaller", CTX_GUEST, tw_entry, NULL, { V(0) }, 1, { I(0x404000) } },
	{ "d_ucaller", CTX_GUEST, tw_fp_top, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xfffffffffffffff8ULL) } },
	{ "d_ucaller", CTX_GUEST, tw_entry_rsp0, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "d_ucaller", CTX_GUEST, tw_nopid, NULL, { V(0) }, 1, { I(0) } },
	{ "d_ucaller", CTX_GUEST, tw_badentry, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "d_ucaller", CTX_GUEST, tw_fp_zero, NULL, { V(0) }, 1, { I(0) } },
	{ "d_ustackdepth", CTX_GUEST, tw_entry_badsp, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0x7000000) } },
	/* Entry: rip, the return address at rsp, then two fp-chain frames. */
	{ "d_ustackdepth", CTX_GUEST, tw_entry, NULL, { V(0) }, 1, { I(4) } },
	{ "d_ustack1", CTX_GUEST, tw_entry, ck_ustack1, { V(0) }, 1, { ANY } },
	/* An untagged constant is not a guest address. */
	{ "g_constload", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0x123) } },
	{ "g_load16", CTX_GUEST, NULL, NULL, { V(-1) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(-1) } },
	{ "n_tstr", CTX_GUEST, NULL, NULL, { K(0), V(0), SCR(8) }, 1,
	    { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "j_arr0", CTX_BOTH, NULL, NULL, { K(448) }, 1, { S("7") } },
	/* printm() of a forged memref pair: on the host the bytes are loaded
	 * (here from the unmapped first page); a guest probe may print only
	 * its own scratch. */
	{ "pm_forge_c", CTX_HOST, NULL, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), ANY } },
	{ "pm_forge_c", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), ANY } },
	/* An empty argument vector is no string: tracing it faults. */
	{ "e_execargs", CTX_GUEST, tw_execargs_empty, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), I(0) } },
	{ "d_vars", CTX_GUEST, tw_execname_top, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	/* Valid guest strings (the fault sweep reaches every load).  A
	 * failed search returns NULL, and tracing NULL is a bad address. */
	{ "f_strlen", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { I(7) } },
	{ "f_toupper", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { S("A,B;C,D") } },
	{ "f_tolower", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { S("a,b;c,d") } },
	{ "f_basename", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { S("a,b;c,d") } },
	{ "f_dirname", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { S(".") } },
	{ "f_cleanpath", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { S("a,b;c,d") } },
	{ "f_strchr", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strrchr", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strstr", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_strstr2", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_index", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { I(-1U) } },
	{ "f_rindex", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { I(-1U) } },
	{ "f_rindex2", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { I(-1U) } },
	{ "f_substr", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { S(",b;c,d") } },
	{ "f_strtok", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { S("a") } },
	{ "f_strtok2", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { S("hello") } },
	{ "f_strjoin", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { S("a,b;c,dx") } },
	{ "f_strjoin2", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { S("helloa,b;c,d") } },
	{ "f_strtoll", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { I(0) } },
	{ "f_json", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_json2", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), I(0) } },
	{ "f_memstr", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { S("a,b") } },
	{ "f_strcmp", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { I(0) } },
	{ "f_strcmp2", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { I(0) } },
	{ "f_tracestr", CTX_GUEST, NULL, NULL, { K(128), K(0) }, 1,
	    { S("a,b;c,d") } },
	{ "e_copyin0", CTX_BOTH, NULL, NULL, { U(288) }, 1, { I(1) } },
	/* A string running to the top of guest user space: the per-byte
	 * offset would wrap. */
	{ "f_copyinstr", CTX_GUEST, tw_utop, NULL, { V(-2), K(128) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	{ "e_copyoutstr_bad", CTX_GUEST, tw_utop, NULL, { V(-1) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	{ "e_copyout_src", CTX_GUEST, NULL, NULL, { U(800), V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "e_copyout_src", CTX_GUEST, tw_zero_page, NULL, { U(800), V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "w_gstrkey_del", CTX_BOTH, NULL, NULL, { K(0) }, 1, { I(1) } },
	{ "d_uvars", CTX_GUEST, tw_no_kernel_hook2, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "d_ustack", CTX_GUEST, tw_pc_zero, ck_ustack_pc0, { V(0) }, 1, { ANY } },
	{ "d_vars", CTX_GUEST, tw_nopid, NULL, { V(0) }, 1,
	    { I(0), ANY, ANY, ANY, ANY, ANY, ANY, I(0), ANY, ANY, ANY } },
	{ "e_execargs", CTX_GUEST, tw_execargs_top, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	/* A struct-typed (by-reference) key at a guest NULL pointer. */
	{ "w_gstructkey", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	/* hcaller in an unanchored virtual probe: the host stack is walked
	 * without an interrupted PC (that belongs to the guest). */
	{ "u:d_hcaller", CTX_GUEST, NULL, NULL, { V(0) }, 1, { I(1) } },
	{ "e_execargs", CTX_GUEST, tw_execargs_null, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), I(0) } },
	{ "w_tstr_only", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	{ "w_gaas_only", CTX_GUEST, tw_top_nul, NULL, { V(0xffffffffffffff80ULL) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	/* Dynamic-variable exhaustion while storing strings (300 firings,
	 * a 1 KiB space): later stores are dropped, staged copies released. */
	{ "m:w_fill", CTX_BOTH, NULL, NULL, { K(0) }, 0, { } },
	/* breakpoint() on the host enters the debugger (kdb_enter). */
	{ "a_bkpt", CTX_HOST, NULL, ck_kdb, { V(0) }, 0, { } },
	/* Faults: the ERROR probe reports DIF offset, fault and address; the
	 * address is meaningful only for address faults. */
	{ "d_div0", CTX_BOTH, NULL, NULL, { V(1), V(0) }, 1,
	    { ANY, I(DTRACEFLT_DIVZERO), ANY } },
	{ "d_badload", CTX_HOST, NULL, NULL, { V(8) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "d_badload", CTX_GUEST, NULL, NULL, { V(8) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(8) } },
	{ "d_badstr", CTX_GUEST, NULL, NULL, { V(0x1000) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0x1000) } },
	{ "d_badcopyin", CTX_GUEST, NULL, NULL, { V(0x10) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0x10) } },
	/* ---- round 4: branch outcomes ---------------------------------- */
	/* A guest load across a page boundary on the page-walk path. */
	{ "d_kload", CTX_GUEST, tw_kload_page, NULL, { K(0x2ffd) }, 1,
	    { I(0x21), I(0x2221), I(0x24232221), I(0x2827262524232221ULL),
	    I(0x28) } },
	/* User loads/copies whose range wraps past the top. */
	{ "b_uload8", CTX_GUEST, NULL, NULL, { V(-4) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xfffffffffffffffcULL) } },
	{ "b_copyin8", CTX_GUEST, NULL, NULL, { V(-4) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xfffffffffffffffcULL) } },
	/* Sizes that are not a multiple of the 8-byte chunk. */
	{ "b_copyin5", CTX_GUEST, NULL, NULL, { U(800) }, 1, { ANY } },
	{ "b_copyout5", CTX_GUEST, NULL, NULL, { U(800), K(288) }, 1, { I(1) } },
	/* copyout() of a guest kernel source without the kernel copy hook. */
	{ "e_copyout", CTX_GUEST, tw_no_kcopy, NULL, { U(800), K(288) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	/* An untagged destination, and a NULL one. */
	{ "b_copyout_kdst", CTX_GUEST, NULL, NULL, { V(0), K(288) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0x1000) } },
	{ "e_copyout_bad", CTX_GUEST, NULL, NULL, { V(0), K(288) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	/* Untagged copyout() sources in a guest clause: a string literal
	 * (DTrace-owned, copied) and a toxic constant. */
	{ "b_copyout_lit", CTX_GUEST, NULL, NULL, { U(800) }, 1, { I(1) } },
	{ "b_copyout_tox", CTX_GUEST, NULL, NULL, { U(800) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0x10) } },
	{ "b_copyoutstr_t", CTX_GUEST, NULL, NULL, { U(800), K(0) }, 1,
	    { I(1) } },
	{ "b_copyoutstr_tox", CTX_GUEST, NULL, NULL, { U(800) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0x10) } },
	/* Destructive actions disallowed: nothing is copied. */
	{ "b_copyout_lit", CTX_GUEST, tw_disallow, NULL, { U(800) }, 1,
	    { I(1) } },
	{ "b_copyoutstr_t", CTX_GUEST, tw_disallow, NULL, { U(800), K(0) }, 1,
	    { I(1) } },
	/* Guest execname: absent, and longer than strsize. */
	{ "b_execname", CTX_GUEST, tw_execname_null, NULL, { V(0) }, 1,
	    { I32(-1), I(DTRACEFLT_BADADDR), I(0) } },
	{ "s:b_execname", CTX_GUEST, tw_execname_long, NULL, { V(0) }, 1,
	    { S("lon") } },
	/* td_frame at the top of the address space; a user stack pointer
	 * at the top (entry probe); a zero user PC in the trap frame. */
	{ "d_ucaller", CTX_GUEST, tw_td_frame_top, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffff80ULL) } },
	{ "d_ustackdepth", CTX_GUEST, tw_rsp_top, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0xfffffffffffffffcULL) } },
	{ "d_ucaller", CTX_GUEST, tw_rip_zero, NULL, { V(0) }, 1, { I(0) } },
	{ "d_ustackdepth", CTX_GUEST, tw_rip_zero, NULL, { V(0) }, 1, { I(0) } },
	{ "b_regs", CTX_GUEST, tw_no_getreg, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	/* json() literal values. */
	{ "b_json", CTX_BOTH, NULL, NULL, { V(0) }, 1,
	    { S("true"), S("false"), S("null"), S("5") } },
	/* strtoll(): leading blanks, "0X" prefix, and base-16 strings that
	 * have no prefix. */
	{ "b_strtoll", CTX_HOST, NULL, NULL, { V(0) }, 1,
	    { I(7), I(31), I(31), I(0), I(18) } },
	/* Guest copies longer than one 8-byte chunk. */
	{ "b_copyin16", CTX_GUEST, NULL, NULL, { U(800) }, 1, { ANY } },
	{ "b_copyout16", CTX_GUEST, NULL, NULL, { U(800), K(288) }, 1,
	    { I(1) } },
	/* A guest string longer than strsize stored in a global. */
	{ "s:b_gs_copy", CTX_GUEST, NULL, NULL, { K(0) }, 1, { I(1) } },
	/* Host string dynamic variables exhaust a small dynvar space. */
	{ "m:b_fill_host", CTX_HOST, NULL, NULL, { K(0) }, 0, { } },
	/* A join that exactly fills strsize (4 with the NUL) is discarded:
	 * dtrace_strjoin() returns NULL without a fault, so tracing it is a
	 * BADADDR at 0 (upstream leaves the result register unset). */
	{ "s:b_strjoin_fit", CTX_HOST, NULL, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	/* Lock subroutines are host-only: each is ILLOP in a guest clause. */
	{ "b_l_owner", CTX_GUEST, NULL, NULL, { K(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "b_l_adaptive", CTX_GUEST, NULL, NULL, { K(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "b_l_spin", CTX_GUEST, NULL, NULL, { K(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "b_l_iswriter", CTX_GUEST, NULL, NULL, { K(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "b_l_sxshared", CTX_GUEST, NULL, NULL, { K(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "b_l_sxexcl", CTX_GUEST, NULL, NULL, { K(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "b_l_sxisexcl", CTX_GUEST, NULL, NULL, { K(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	/* substr() with a negative index past the start and no length. */
	{ "b_substr_neg", CTX_HOST, NULL, NULL, { V(0) }, 1, { S("") } },
	/* Guest strings are bounded by strsize (4) without a NUL: strchr(),
	 * cleanpath() and strjoin() run to the bound. */
	{ "s:b_strchr", CTX_GUEST, NULL, NULL, { K(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	{ "s:b_cleanpath", CTX_GUEST, tw_paths, NULL, { K(GUEST_SCRATCH) }, 1,
	    { ANY } },
	{ "s:b_cleanpath", CTX_GUEST, tw_paths, NULL,
	    { K(GUEST_SCRATCH + 16) }, 1, { ANY } },
	{ "s:b_cleanpath", CTX_GUEST, tw_paths, NULL,
	    { K(GUEST_SCRATCH + 32) }, 1, { ANY } },
	{ "s:b_cleanpath", CTX_GUEST, tw_paths, NULL,
	    { K(GUEST_SCRATCH + 48) }, 1, { ANY } },
	{ "s:f_strjoin2", CTX_GUEST, NULL, NULL, { K(0), K(32) }, 1,
	    { ANY, I(DTRACEFLT_NOSCRATCH), I(0) } },
	/* memref() of untagged scratch in a guest clause. */
	{ "b_memref_scr", CTX_GUEST, NULL, NULL, { V(8) }, 1, { I(8) } },
	{ "b_memref_scr", CTX_GUEST, NULL, NULL, { V(4096) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "b_memref_above", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_ILLOP), ANY } },
	{ "b_memref_zero", CTX_GUEST, NULL, NULL, { K(0) }, 1, { I(0) } },
	/* A host memref() only refers to its bytes: any length is kept. */
	{ "g_memref_big", CTX_HOST, NULL, NULL, { K(0), V(-1) }, 1,
	    { I(0xffffffffffffffffULL) } },
	/* printm() of memref pairs outside scratch / short / oversized. */
	{ "b_pm_const", CTX_BOTH, NULL, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	{ "b_pm_above", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	/* On the host the pair need only lie inside the scratch region. */
	{ "b_pm_above", CTX_HOST, NULL, NULL, { V(0) }, 1, { ANY } },
	{ "b_pm_short", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	/* A pair longer than the printm() size is dropped. */
	{ "b_pm_big", CTX_BOTH, NULL, NULL, { V(0) }, 0, { } },
	{ "b_pm_far", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	{ "b_pm_tail", CTX_GUEST, NULL, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	/* A by-reference store of an unloadable guest string. */
	{ "b_gs_bad", CTX_GUEST, NULL, NULL, { V(-1) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	{ "b_ts_bad", CTX_GUEST, NULL, NULL, { V(-1) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), ANY } },
	{ "b_alloca_huge", CTX_BOTH, NULL, NULL, { V(-1) }, 1,
	    { ANY, I(DTRACEFLT_NOSCRATCH), ANY } },
	{ "b_stmt_str", CTX_BOTH, NULL, NULL, { V(0) }, 1, { I(1) } },
	/* json() of a bareword that is not true/false/null: NULL, so the
	 * trace is a BADADDR at 0. */
	{ "b_json_bare", CTX_HOST, NULL, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADADDR), I(0) } },
	/* ptinfo() of a mapped guest address (page walk succeeds). */
	{ "f_ptinfo", CTX_GUEST, tw_kcopy_eop, NULL, { K(0) }, 1, { ANY } },
	/* stack() of a guest whose envelope claims too many frames:
	 * BADSTACK. */
	{ "d_kstack", CTX_GUEST, tw_pcstack_bad, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADSTACK), I(0) } },
	/* Deallocating a by-reference thread-local by storing 0. */
	{ "b_zero_str", CTX_BOTH, NULL, NULL, { K(0) }, 1, { I(1) } },
	/* printimmstack() on the host: the slots are not guest-formatted. */
	{ "a_pimmstack_n", CTX_HOST, NULL, NULL, { V(0) }, 1,
	    { ANY, I(DTRACEFLT_BADSTACK), ANY } },
};

/*
 * The guest (minion) side: dtrace(1) sends a VM the forwarding program from
 * dtrace_vprog_from(), whose DIF ends in DIF_OP_HYPERCALL.  Running in a
 * bhyve guest kernel, that instruction packages the probe context into a
 * hypertrace_args_t and calls the host.  The oracle is the probe context
 * the test set up (thread, process, credentials, arguments).
 */
/* Forwarding statements (one hypercall each) in the last hc_fire()'s
 * program: libdtrace decides how many statements a clause becomes. */
static int hc_nstmts;

static int
hc_fire(const char *prog, uint64_t a0, uint64_t a1, int *ndrops)
{
	struct cons c;
	int matched;
	long before = khx_hypercall_count();

	cons_open(&c);
	KHX_EQ(cons_enable(&c, prog, &matched), 0);
	KHX_CHECK(matched >= 1);
	hc_nstmts = matched;
	KHX_EQ(cons_enable(&c, "err_capture", &matched), 0);
	KHX_EQ(cons_options(&c, dif_opts, nitems(dif_opts)), 0);
	KHX_EQ(cons_go(&c), 0);
	struct thread *prev = khx_set_curthread(root_td);
	khx_probe_args[5] = 0x55;
	fire(p_entry, a0, a1, 0);
	khx_set_curthread(prev);
	struct recs rs;
	KHX_CHECK(snap_records(&c, 0, &rs) >= 0);
	*ndrops = rs.n;
	/* Faults are ILLOP at the hypercall instruction. */
	for (int r = 0; r < rs.n; r++)
		KHX_EQ(rs.r[r].val[1], DTRACEFLT_ILLOP);
	cons_close(&c);
	return ((int)(khx_hypercall_count() - before));
}

/* Set the frame count of every DIF_OP_HYPERCALL in a DOF; returns how many
 * instructions were patched. */
static int
dof_patch_hypercall(dof_hdr_t *dof, uint_t frames)
{
	int n = 0;

	for (uint32_t i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t *sec = (dof_sec_t *)((char *)dof + dof->dofh_secoff +
		    i * dof->dofh_secsize);
		dif_instr_t *ins;

		if (sec->dofs_type != DOF_SECT_DIF)
			continue;
		ins = (dif_instr_t *)((char *)dof + sec->dofs_offset);
		for (size_t j = 0; j < sec->dofs_size / sizeof(*ins); j++) {
			if (DIF_INSTR_OP(ins[j]) != DIF_OP_HYPERCALL)
				continue;
			ins[j] = DIF_INSTR_FMT(DIF_OP_HYPERCALL, frames, 0, 0);
			n++;
		}
	}
	return (n);
}

static void
case_hypercall_dof(void)
{
	struct cons c;
	struct recs rs;
	dof_hdr_t *dof;
	int matched;
	long before;

	khx_host_case("hypercall-dof");
	khx_cpuid_bhyve_guest(1);
	/* More frames than a hypercall envelope carries: the DIF validator
	 * refuses the program, so the interpreter's own check is defensive. */
	dof = dof_load("h_stack");
	KHX_CHECK(dof_patch_hypercall(dof, HYPERTRACE_STACK_MAX_FRAMES + 1) >= 1);
	cons_open(&c);
	KHX_EQ(cons_enable_vm(&c, dof, 0, 0, &matched), EINVAL);
	dof_free(dof);
	cons_close(&c);
	/* The maximum itself is accepted. */
	dof = dof_load("h_stack");
	KHX_CHECK(dof_patch_hypercall(dof, HYPERTRACE_STACK_MAX_FRAMES) >= 1);
	cons_open(&c);
	KHX_EQ(cons_enable_vm(&c, dof, 0, 0, &matched), 0);
	dof_free(dof);
	cons_close(&c);

	/* A forwarding program on a virtual probe (a host-side VM namespace)
	 * does nothing: it forwards only from real providers. */
	cons_open(&c);
	{
		dtrace_probedesc_t d = vdesc(dif_guest_id, "khx", "mod", "func",
		    "entry");

		KHX_EQ(vprobe_create(&c, dif_vm, &d, 1), 0);
	}
	dof = dof_load("h_args");
	dof_set_vmid(dof, dif_vm->vmid);
	{
		/* ENABLE describes matched guest probes by their VM and
		 * virtual provider name. */
		dtrace_probedesc_t pds[8];
		dtrace_enable_io_t io;

		memset(&io, 0, sizeof(io));
		io.dof = dof;
		io.ps = pds;
		io.ps_bufsize = sizeof(pds);
		KHX_EQ(cons_ioctl(&c, DTRACEIOC_ENABLE, &io), 0);
		matched = io.n_matched;
		KHX_CHECK(io.n_desc >= 1);
		KHX_EQ(pds[0].dtpd_vmid, dif_vm->vmid);
		KHX_EQ(strcmp(pds[0].dtpd_provider, "khx"), 0);
		KHX_EQ(strcmp(pds[0].dtpd_name, "entry"), 0);
	}
	dof_free(dof);
	KHX_CHECK(matched >= 1);
	KHX_EQ(cons_enable(&c, "err_capture", &matched), 0);
	KHX_EQ(cons_options(&c, dif_opts, nitems(dif_opts)), 0);
	KHX_EQ(cons_go(&c), 0);
	before = khx_hypercall_count();
	hypertrace_args_t a = gargs(1, 2, 3);
	KHX_EQ(hypertrace_probe(&dif_vm->hdl, dif_guest_id, &a), 0);
	KHX_EQ(khx_hypercall_count(), before);
	KHX_CHECK(snap_records(&c, 0, &rs) >= 0);
	KHX_EQ(rs.n, 0);
	cons_close(&c);
	khx_cpuid_bhyve_guest(0);
}

/*
 * immstack(): kernel stack frames symbolized in probe context through the
 * ddb symbol tables (dtrace_db.c), with the immstack name cache.  The
 * kernel symbol table here is a private ELF table naming two functions of
 * this test (fire and case_immstack); a second, module-style table resolves
 * through the linker_file KPI.  Oracle: after the framework's own frame
 * (not in the table: "??"), the frames of this call path are fire (the
 * provider's call to dtrace_probe), imm_fire_opts, imm_fire, then
 * case_immstack.
 */
static void case_immstack(void);
struct khx_db_private {		/* layout of dtrace_db.c's private data */
	char *strtab;
	vm_offset_t relbase;
};
static char imm_strtab[] =
    "\0fire\0case_immstack\0localdup\0obj\0sect\0undef\0imm_fire"
    "\0imm_fire_opts";
static Elf_Sym imm_syms[9];
static int imm_fire(char names[][64], int max);
static int imm_fire_opts(int, int, char [][64], int, int *);
static struct khx_db_private imm_priv = { imm_strtab, 0 };
static struct linker_file imm_lf, imm_lf2, imm_lf3;
/* A kobj method cache with nothing cached, so every linker method call is
 * looked up (and dispatched by khx_kobj_bind). */
static struct kobj_method imm_nomethod;
static struct kobj_ops imm_ops;
static int imm_mod_lookups;

static int
imm_mod_search(linker_file_t lf, caddr_t value,
    c_linker_sym_t *symp, long *diffp)
{
	uintptr_t v = (uintptr_t)value, f = (uintptr_t)fire;

	imm_mod_lookups++;
	/* Round 4: a second file whose candidate is farther away, and a third
	 * that reports success without a symbol. */
	if (lf == &imm_lf2 && v >= f && v - f < 0x1000) {
		*symp = (c_linker_sym_t)&imm_lf2;
		*diffp = (long)(v - f) + 0x10;
		return (0);
	}
	if (lf == &imm_lf3) {
		*symp = NULL;
		*diffp = 0;
		return (0);
	}
	if (v >= f && v - f < 0x1000) {
		*symp = (c_linker_sym_t)&imm_lf;
		*diffp = (long)(v - f);
		return (0);
	}
	*symp = NULL;
	*diffp = (long)v;
	return (ENOENT);
}

static int
imm_mod_values(linker_file_t lf __unused, c_linker_sym_t sym,
    linker_symval_t *valp)
{
	if (sym != (c_linker_sym_t)&imm_lf)
		return (ENOENT);
	valp->name = "modfire";
	valp->value = (caddr_t)fire;
	valp->size = 0;
	return (0);
}

static void
imm_symtab(int with_fire, int with_module)
{
	static const struct {
		uint32_t name;
		uintptr_t addr;
		int type, bind, shndx;
	} t[] = {
		{ 1, 0, STT_FUNC, STB_GLOBAL, 1 },	/* fire */
		{ 6, 0, STT_FUNC, STB_GLOBAL, 1 },	/* case_immstack */
		{ 20, 0, STT_FUNC, STB_LOCAL, 1 },	/* local twin of 6 */
		{ 29, 0x1000, STT_OBJECT, STB_GLOBAL, 1 },
		{ 33, 0x2000, STT_SECTION, STB_LOCAL, 1 },
		{ 38, 0x3000, STT_FUNC, STB_GLOBAL, SHN_UNDEF },
		{ 0, 0x4000, STT_FUNC, STB_GLOBAL, 1 },	/* no name */
		{ 44, 0, STT_FUNC, STB_GLOBAL, 1 },	/* imm_fire */
		{ 53, 0, STT_FUNC, STB_GLOBAL, 1 },	/* imm_fire_opts */
	};

	memset(imm_syms, 0, sizeof(imm_syms));
	for (size_t i = 0; i < nitems(t); i++) {
		imm_syms[i].st_name = t[i].name;
		imm_syms[i].st_value = t[i].addr;
		imm_syms[i].st_info = ELF_ST_INFO(t[i].bind, t[i].type);
		imm_syms[i].st_shndx = t[i].shndx;
	}
	imm_syms[0].st_value = with_fire ? (uintptr_t)fire : 0x5000;
	imm_syms[1].st_value = (uintptr_t)case_immstack;
	imm_syms[2].st_value = (uintptr_t)case_immstack;
	imm_syms[7].st_value = (uintptr_t)imm_fire;
	imm_syms[8].st_value = (uintptr_t)imm_fire_opts;
	db_symtabs[0].name = "kernel";
	db_symtabs[0].start = (char *)imm_syms;
	db_symtabs[0].end = (char *)(imm_syms + nitems(imm_syms));
	db_symtabs[0].private = (char *)&imm_priv;
	db_nsymtab = 1;
	if (with_module) {
		db_symtabs[1].name = "modules";
		db_symtabs[1].start = db_symtabs[1].end = NULL;
		db_symtabs[1].private = NULL;
		db_nsymtab = 2;
		khx_kobj_bind(&linker_search_symbol_desc,
		    (kobjop_t)imm_mod_search);
		khx_kobj_bind(&linker_symbol_values_desc,
		    (kobjop_t)imm_mod_values);
		for (int i = 0; i < KOBJ_CACHE_SIZE; i++)
			imm_ops.cache[i] = &imm_nomethod;
		imm_lf.ops = &imm_ops;
		if (TAILQ_EMPTY(&linker_files))
			TAILQ_INSERT_TAIL(&linker_files, &imm_lf, link);
	}
}

/* Run immstack() once with the given string size and frame count (0:
 * defaults); return the frame names (strsize-byte slots: name, NUL, then
 * the 8-byte offset at the next aligned address) and any ERROR fault. */
static int
imm_fire_opts(int strsize, int frames, char names[][64], int max, int *fault)
{
	struct cons c;
	struct recs rs;
	struct opt o[nitems(dif_opts) + 2];
	int matched, n = 0, no = 0;

	memcpy(o, dif_opts, sizeof(dif_opts));
	no = nitems(dif_opts);
	if (strsize != 0)
		o[no++] = (struct opt){ DTRACEOPT_IMMSTACKSTRSIZE, strsize };
	if (frames != 0)
		o[no++] = (struct opt){ DTRACEOPT_IMMSTACKFRAMES, frames };
	if (strsize == 0)
		strsize = 64;
	cons_open(&c);
	KHX_EQ(cons_options(&c, o, no), 0);
	KHX_EQ(cons_enable(&c, "a_immstack", &matched), 0);
	KHX_EQ(cons_enable(&c, "err_capture", &matched), 0);
	KHX_EQ(cons_go(&c), 0);
	struct thread *prev = khx_set_curthread(root_td);
	fire(p_entry, 0, 0, 0);
	khx_set_curthread(prev);
	KHX_CHECK(snap_records(&c, 0, &rs) >= 0);
	KHX_EQ(rs.n, 1);
	*fault = -1;
	if (rs.r[0].kind[0] == DTRACEACT_DIFEXPR && rs.r[0].nrecs == 3) {
		*fault = (int)rs.r[0].val[1];		/* ERROR record */
	} else {
		for (size_t off = 0; off + strsize <= rs.bigsize && n < max;
		    off += strsize) {
			strlcpy(names[n], (char *)rs.big + off,
			    MIN(64, strsize));
			if (dif_discover)
				khx_host_log("  immstack[%d] %s (size %zu)\n",
				    n, names[n], rs.bigsize);
			n++;
		}
	}
	cons_close(&c);
	return (n);
}

static int
imm_fire(char names[][64], int max)
{
	int fault, n;

	n = imm_fire_opts(0, 0, names, max, &fault);
	KHX_EQ(fault, -1);
	return (n);
}

static void
imm_expect(char names[][64], int n, const char *first)
{
	KHX_CHECK(n >= 5);
	KHX_EQ(strcmp(names[0], "??"), 0);
	KHX_EQ(strcmp(names[1], first), 0);
	KHX_EQ(strcmp(names[2], "imm_fire_opts"), 0);
	KHX_EQ(strcmp(names[3], "imm_fire"), 0);
	KHX_EQ(strcmp(names[4], "case_immstack"), 0);
}

static void
case_immstack(void)
{
	char names[20][64];
	int n;

	khx_host_case("immstack-symbols");
	imm_symtab(1, 0);
	dtrace_immstack_caching_enabled = 1;
	n = imm_fire(names, 20);
	imm_expect(names, n, "fire");
	/* The names are now cached by PC: without any symbol table the same
	 * return addresses (in fire and imm_fire) are still named; the call
	 * site in case_immstack is a new PC and is not. */
	db_nsymtab = 0;
	n = imm_fire(names, 20);
	KHX_EQ(strcmp(names[1], "fire"), 0);
	KHX_EQ(strcmp(names[2], "imm_fire_opts"), 0);
	KHX_EQ(strcmp(names[3], "imm_fire"), 0);
	KHX_EQ(strcmp(names[4], "??"), 0);
	/* Caching disabled: looked up every time. */
	dtrace_immstack_caching_enabled = 0;
	imm_symtab(1, 0);
	n = imm_fire(names, 20);
	imm_expect(names, n, "fire");
	/* Without any symbol: "??" everywhere. */
	db_nsymtab = 0;
	n = imm_fire(names, 20);
	KHX_EQ(strcmp(names[1], "??"), 0);
	KHX_EQ(strcmp(names[4], "??"), 0);
	/* A module (linker file) symbol closer than any kernel symbol. */
	imm_symtab(0, 1);
	imm_mod_lookups = 0;
	n = imm_fire(names, 20);
	imm_expect(names, n, "modfire");
	KHX_CHECK(imm_mod_lookups > 0);

	/* String sizes: one that is not a multiple of 8 cannot hold the
	 * aligned offsets; 16 bytes truncate "case_immstack" and leave no room
	 * for its offset; 8 bytes leave no room at all (frames are skipped). */
	{
		int fault;

		imm_symtab(1, 0);
		dtrace_immstack_caching_enabled = 0;
		(void)imm_fire_opts(60, 0, names, 20, &fault);
		KHX_EQ(fault, DTRACEFLT_BADSTACK);
		(void)imm_fire_opts(16, 0, names, 20, &fault);
		KHX_EQ(fault, DTRACEFLT_BADSTACK);
		n = imm_fire_opts(8, 0, names, 20, &fault);
		KHX_EQ(fault, -1);
		/* An unanchored probe (no function): its first frame is the
		 * interrupted PC passed as arg0. */
		{
			static dtrace_id_t tick;
			struct cons c;
			struct recs rs;
			int matched;

			if (tick == 0)
				tick = dtrace_probe_lookup(0, khx_prov, "mod", "",
				    "tick");
			if (tick == 0)
				tick = dtrace_probe_create(khx_prov, "mod", "",
				    "tick", 0, NULL);
			KHX_CHECK(tick != 0);
			cons_open(&c);
			KHX_EQ(cons_enable(&c, "a_immstack_tick", &matched), 0);
			KHX_EQ(matched, 1);
			KHX_EQ(cons_options(&c, dif_opts, nitems(dif_opts)), 0);
			KHX_EQ(cons_go(&c), 0);
			struct thread *prev = khx_set_curthread(root_td);
			fire(tick, (uintptr_t)case_immstack + 3, 0, 0);
			khx_set_curthread(prev);
			KHX_CHECK(snap_records(&c, 0, &rs) >= 0);
			KHX_EQ(rs.n, 1);
			KHX_EQ(strcmp((char *)rs.big, "case_immstack"), 0);
			KHX_EQ(*(uint64_t *)(rs.big + 16), 3);
			cons_close(&c);
		}
		/* A provider-recorded caller replaces the skipped frame. */
		solaris_cpu[0].cpu_dtrace_caller = (uintptr_t)imm_fire + 5;
		n = imm_fire_opts(0, 0, names, 20, &fault);
		solaris_cpu[0].cpu_dtrace_caller = 0;
		KHX_EQ(strcmp(names[0], "imm_fire"), 0);
		KHX_EQ(strcmp(names[2], "fire"), 0);
		/* Two frames of 64 bytes: the framework frame and fire. */
		n = imm_fire_opts(0, 2, names, 20, &fault);
		KHX_EQ(fault, -1);
		KHX_EQ(n, 2);
		KHX_EQ(strcmp(names[1], "fire"), 0);
	}
	TAILQ_REMOVE(&linker_files, &imm_lf, link);
	db_nsymtab = 0;
	dtrace_immstack_caching_enabled = 1;
}

/*
 * Lock subroutines.  FreeBSD implements them through the lock's class
 * (lock_classes[] and lc_owner); the test installs classes whose owner
 * callbacks decode the lock word as the kernel's do (owner thread pointer,
 * or RW_LOCK_READ with a reader count).  mutex_* and the "read held"
 * subroutines take the lock's address, as do rw_write_held/iswriter and
 * sx_exclusive_held/isexclusive (D: rw_write_held(krwlock_t *)).  Guest
 * probes refuse all of them.
 */
#ifndef RW_LOCK_READ	/* FreeBSD <sys/rwlock.h>; shadowed by the SPL header */
#define	RW_LOCK_READ		0x01
#define	RW_READERS_SHIFT	5
#define	RW_READERS(x)		(((x) & ~(uintptr_t)0x1f) >> RW_READERS_SHIFT)
#endif
struct tlock {
	struct lock_object lo;
	volatile uintptr_t word;
};

static int
tl_owner(const struct lock_object *lo, struct thread **owner)
{
	const struct tlock *t = (const struct tlock *)(const void *)lo;

	if ((t->word & RW_LOCK_READ) != 0) {
		*owner = NULL;
		return (RW_READERS(t->word) != 0);
	}
	*owner = (struct thread *)(t->word & ~(uintptr_t)MTX_FLAGMASK);
	return (*owner != NULL);
}

static struct lock_class tl_sleep = { .lc_name = "tsleep",
	.lc_flags = LC_SLEEPLOCK, .lc_owner = tl_owner };
static struct lock_class tl_spin = { .lc_name = "tspin",
	.lc_flags = LC_SPINLOCK, .lc_owner = tl_owner };

static void
tl_init(struct tlock *t, int cls, uintptr_t word)
{
	memset(t, 0, sizeof(*t));
	t->lo.lo_name = "tlock";
	t->lo.lo_flags = LO_INITIALIZED | ((u_int)cls << LO_CLASSSHIFT);
	t->word = word;
}

static void
lk_fire(const char *prog, uintptr_t a0, uint64_t *v, int nv)
{
	struct cons c;
	struct recs rs;
	int matched;

	cons_open(&c);
	KHX_EQ(cons_enable(&c, prog, &matched), 0);
	KHX_EQ(cons_options(&c, dif_opts, nitems(dif_opts)), 0);
	KHX_EQ(cons_go(&c), 0);
	struct thread *prev = khx_set_curthread(root_td);
	fire(p_entry, a0, 0, 0);
	khx_set_curthread(prev);
	KHX_CHECK(snap_records(&c, 0, &rs) >= 0);
	KHX_EQ(rs.n, 1);
	KHX_EQ(rs.r[0].nrecs, nv);
	for (int i = 0; i < nv && i < rs.r[0].nrecs; i++)
		v[i] = rs.r[0].val[i];
	cons_close(&c);
}

static void
case_locks(void)
{
	static struct tlock m, sp, rw;
	uint64_t v[4];

	khx_host_case("lock-subroutines");
	lock_classes[10] = &tl_sleep;
	lock_classes[11] = &tl_spin;
	/* A sleep mutex owned by the current thread. */
	tl_init(&m, 10, (uintptr_t)root_td);
	lk_fire("l_mtx", (uintptr_t)&m, v, 4);
	KHX_EQ(v[0], 1);
	KHX_EQ(v[1], (uintptr_t)root_td);
	KHX_EQ(v[2], 1);
	KHX_EQ(v[3], 0);
	/* An unowned spin mutex. */
	tl_init(&sp, 11, 0);
	lk_fire("l_mtx", (uintptr_t)&sp, v, 4);
	KHX_EQ(v[0], 0);
	KHX_EQ(v[1], 0);
	KHX_EQ(v[2], 0);
	KHX_EQ(v[3], 1);
	/* An unowned sleep lock: no holder of either kind. */
	{
		static struct tlock u;

		tl_init(&u, 10, 0);
		lk_fire("l_rd", (uintptr_t)&u, v, 2);
		KHX_EQ(v[0], 0);
		KHX_EQ(v[1], 0);
		lk_fire("l_wr", (uintptr_t)&u, v, 4);
		KHX_EQ(v[0], 0);
		KHX_EQ(v[2], 0);
	}
	/* Read-held by two readers. */
	tl_init(&rw, 10, RW_LOCK_READ | (2UL << RW_READERS_SHIFT));
	lk_fire("l_rd", (uintptr_t)&rw, v, 2);
	KHX_EQ(v[0], 1);
	KHX_EQ(v[1], 1);
	lk_fire("l_wr", (uintptr_t)&rw, v, 4);
	KHX_EQ(v[0], 0);
	KHX_EQ(v[1], 0);
	KHX_EQ(v[2], 0);
	KHX_EQ(v[3], 0);
	/* Write-held by the current thread. */
	tl_init(&rw, 10, (uintptr_t)root_td);
	lk_fire("l_rd", (uintptr_t)&rw, v, 2);
	KHX_EQ(v[0], 0);
	KHX_EQ(v[1], 0);
	lk_fire("l_wr", (uintptr_t)&rw, v, 4);
	KHX_EQ(v[0], 1);
	KHX_EQ(v[1], 1);
	KHX_EQ(v[2], 1);
	KHX_EQ(v[3], 1);
	/* Write-held by another thread. */
	tl_init(&rw, 10, (uintptr_t)jail_td);
	lk_fire("l_wr", (uintptr_t)&rw, v, 4);
	KHX_EQ(v[0], 1);
	KHX_EQ(v[1], 0);
	lock_classes[10] = lock_classes[11] = NULL;
}

/*
 * dtrace_immstack.c (the arm64/riscv immstack slot formatter, portable C,
 * built here natively): one slot is the symbol name, NUL, then the offset
 * as a 64-bit word at the next 8-byte boundary.
 */
static void
case_immstack_format(void)
{
	char slot[64] __aligned(8);
	volatile uint16_t *flags = &cpu_core[curcpu].cpuc_dtrace_flags;

	khx_host_case("immstack-format");
	imm_symtab(1, 0);
	dtrace_immstack_caching_enabled = 0;
	/* Bad slots. */
	*flags = 0;
	KHX_EQ(dtrace_immstack_format(NULL, 64, 1), -1);
	KHX_CHECK((*flags & CPU_DTRACE_BADSTACK) != 0);
	*flags = 0;
	KHX_EQ(dtrace_immstack_format(slot, 8, 1), -1);
	*flags = 0;
	KHX_EQ(dtrace_immstack_format(slot + 1, 32, 1), -1);
	*flags = 0;
	KHX_EQ(dtrace_immstack_format(slot, 60, 1), -1);
	*flags = 0;
	/* A zero PC is an empty slot. */
	memset(slot, 'x', sizeof(slot));
	KHX_EQ(dtrace_immstack_format(slot, 64, 0), 0);
	KHX_EQ(slot[0], 0);
	/* A known PC: "fire" + offset 10. */
	KHX_EQ(dtrace_immstack_format(slot, 64, (uintptr_t)fire + 10), 0);
	KHX_EQ(strcmp(slot, "fire"), 0);
	KHX_EQ(*(uint64_t *)(slot + 8), 10);
	/* The nearest preceding symbol may be a data object ("obj" at
	 * 0x1000); section and undefined symbols never match. */
	KHX_EQ(dtrace_immstack_format(slot, 64, 0x1234), 0);
	KHX_EQ(strcmp(slot, "obj"), 0);
	KHX_EQ(*(uint64_t *)(slot + 8), 0x234);
	/* Below the first page, or 64 KiB or more past a symbol: "??". */
	KHX_EQ(dtrace_immstack_format(slot, 64, 0x900), 0);
	KHX_EQ(strcmp(slot, "??"), 0);
	KHX_EQ(*(uint64_t *)(slot + 8), 0);
	KHX_EQ(dtrace_immstack_format(slot, 64, 0x30000), 0);
	KHX_EQ(strcmp(slot, "??"), 0);
	/* A name longer than the slot is truncated to leave room for the
	 * offset word. */
	KHX_EQ(dtrace_immstack_format(slot, 16,
	    (uintptr_t)case_immstack + 4), 0);
	KHX_EQ(strcmp(slot, "case_im"), 0);
	KHX_EQ(*(uint64_t *)(slot + 8), 4);
	/* Cached: a second lookup needs no symbol table. */
	dtrace_immstack_caching_enabled = 1;
	KHX_EQ(dtrace_immstack_format(slot, 64, (uintptr_t)imm_fire + 6), 0);
	KHX_EQ(strcmp(slot, "imm_fire"), 0);
	db_nsymtab = 0;
	memset(slot, 0, sizeof(slot));
	KHX_EQ(dtrace_immstack_format(slot, 64, (uintptr_t)imm_fire + 6), 0);
	KHX_EQ(strcmp(slot, "imm_fire"), 0);
	KHX_EQ(*(uint64_t *)(slot + 16), 6);
	dtrace_immstack_caching_enabled = 0;

	/*
	 * ELF symbol-table ties (dtrace_db.c, from ddb's search): a global
	 * symbol replaces a local one at the same address; a PC exactly at a
	 * global function stops the search; a symbol at 0 is as far as any
	 * symbol can be from the last address (distance ~0), which the
	 * search still records but the lookup treats as no symbol ("??").
	 */
	{
		static char tstrtab[] =
		    "\0zero\0lcl\0glb\0exact\0nt\0l1\0l2\0ob\0lf";
		static Elf_Sym tsyms[9];
		static struct khx_db_private tpriv = { tstrtab, 0 };
		static char hstrtab[] = "\0hi";
		static Elf_Sym hsyms[1];
		static struct khx_db_private hpriv = { hstrtab, 0 };
		static const struct {
			uint32_t name;
			uintptr_t addr;
			int bind, type;
		} t[] = {
			{ 1, 0, STB_GLOBAL, STT_FUNC },			/* zero */
			{ 6, 0x10000000, STB_LOCAL, STT_FUNC },		/* lcl */
			{ 10, 0x10000000, STB_GLOBAL, STT_FUNC },	/* glb */
			{ 14, 0x20000000, STB_GLOBAL, STT_FUNC },	/* exact */
			{ 20, 0x40000000, STB_GLOBAL, STT_NOTYPE },	/* nt */
			{ 23, 0x50000000, STB_LOCAL, STT_FUNC },	/* l1 */
			{ 26, 0x50000000, STB_LOCAL, STT_FUNC },	/* l2 */
			{ 29, 0x60000000, STB_GLOBAL, STT_OBJECT },	/* ob */
			{ 32, 0x70000000, STB_LOCAL, STT_FUNC },	/* lf */
		};
		static const struct { uintptr_t pc; const char *name;
		    uint64_t off; } q[] = {
			{ 0x10000005, "glb", 5 },
			{ 0x20000000, "exact", 0 },
			{ 0x40000004, "nt", 4 },	/* untyped symbols count */
			{ 0x50000003, "l1", 3 },	/* first of two locals */
			{ 0x60000000, "ob", 0 },	/* exact data object */
			{ 0x70000000, "lf", 0 },	/* exact local function */
		};

		for (size_t i = 0; i < nitems(t); i++) {
			tsyms[i].st_name = t[i].name;
			tsyms[i].st_value = t[i].addr;
			tsyms[i].st_info = ELF_ST_INFO(t[i].bind, t[i].type);
			tsyms[i].st_shndx = 1;
		}
		/* A second table whose only symbol lies above every PC
		 * asked for: it never matches. */
		hsyms[0].st_name = 1;
		hsyms[0].st_value = 0x7f000000;
		hsyms[0].st_info = ELF_ST_INFO(STB_GLOBAL, STT_FUNC);
		hsyms[0].st_shndx = 1;
		db_symtabs[0].name = "kernel";
		db_symtabs[0].start = (char *)tsyms;
		db_symtabs[0].end = (char *)(tsyms + nitems(tsyms));
		db_symtabs[0].private = (char *)&tpriv;
		db_symtabs[1].name = "high";
		db_symtabs[1].start = (char *)hsyms;
		db_symtabs[1].end = (char *)(hsyms + nitems(hsyms));
		db_symtabs[1].private = (char *)&hpriv;
		db_nsymtab = 2;
		for (size_t i = 0; i < nitems(q); i++) {
			KHX_EQ(dtrace_immstack_format(slot, 64, q[i].pc), 0);
			KHX_EQ(strcmp(slot, q[i].name), 0);
			KHX_EQ(*(uint64_t *)(slot + 8), q[i].off);
		}
		/* Cached with offset 0, an exact hit is looked up again (the
		 * cache treats offset 0 as absent). */
		dtrace_immstack_caching_enabled = 1;
		KHX_EQ(dtrace_immstack_format(slot, 64, 0x20000000), 0);
		KHX_EQ(dtrace_immstack_format(slot, 64, 0x20000000), 0);
		KHX_EQ(strcmp(slot, "exact"), 0);
		dtrace_immstack_caching_enabled = 0;
		KHX_EQ(dtrace_immstack_format(slot, 64, ~(pc_t)0), 0);
		KHX_EQ(strcmp(slot, "??"), 0);
		db_nsymtab = 0;
	}
	/* A module (linker) symbol exactly at the PC ends the search over
	 * the linker files. */
	imm_symtab(0, 1);
	KHX_EQ(dtrace_immstack_format(slot, 64, (uintptr_t)fire), 0);
	KHX_EQ(strcmp(slot, "modfire"), 0);
	KHX_EQ(*(uint64_t *)(slot + 8), 0);
	/* More linker files: one without a symbol, one farther away; the
	 * nearest symbol (in the first file) wins. */
	imm_lf2.ops = imm_lf.ops;
	imm_lf3.ops = imm_lf.ops;
	TAILQ_INSERT_HEAD(&linker_files, &imm_lf3, link);
	TAILQ_INSERT_TAIL(&linker_files, &imm_lf2, link);
	KHX_EQ(dtrace_immstack_format(slot, 64, (uintptr_t)fire + 2), 0);
	KHX_EQ(strcmp(slot, "modfire"), 0);
	KHX_EQ(*(uint64_t *)(slot + 8), 2);
	TAILQ_REMOVE(&linker_files, &imm_lf2, link);
	TAILQ_REMOVE(&linker_files, &imm_lf3, link);
	TAILQ_REMOVE(&linker_files, &imm_lf, link);
	db_nsymtab = 0;
	*flags = 0;
}

/*
 * Hand-assembled DIF for opcodes the compiler does not emit (ALLOCS,
 * COPYS, the RLD* loads, LDTA, PUSHTR of a sized non-string) and for
 * register states it cannot produce (an untagged zero address in a guest
 * clause).  Oracles: the DIF ISA comments in sys/dtrace.h.
 */
#define	LD(v, d)	DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_ARG0 + (v), (d))
#define	FMT		DIF_INSTR_FMT

#define	CRAFT(name, ins, n, ctx, args, exp) \
	craft_run((name), (ins), (n), &(const struct dcase){ "r_craft", (ctx), \
	    NULL, NULL, args, 1, exp })
#define	A3(a, b, c)	{ a, b, c }
#define	E3(a, b, c)	{ a, b, c }
#define	E1(a)		{ a }

static void
craft_run(const char *name, const dif_instr_t *ins, int n,
    const struct dcase *kp)
{
	struct dcase k = *kp;
	int ctx = k.ctx;

	khx_host_case(name);
	dif_craft_name = name;
	dif_craft = ins;
	dif_ncraft = n;
	if (ctx & CTX_HOST)
		dif_run(&k, 0);
	if (ctx & CTX_GUEST)
		dif_run(&k, 1);
	dif_craft = NULL;
}

static void
case_crafted_dif(void)
{
	/* allocs/copys: copy arg0 bytes from arg1 into fresh scratch. */
	static const dif_instr_t copy[] = {
		LD(0, 1), FMT(DIF_OP_ALLOCS, 1, 0, 3), LD(1, 2),
		FMT(DIF_OP_COPYS, 2, 1, 3), DIF_INSTR_LOAD(DIF_OP_LDX, 3, 4),
		DIF_INSTR_RET(4) };
	/* copys into arg2 (outside scratch; a guest pointer in a guest). */
	static const dif_instr_t copy_out[] = {
		LD(0, 1), LD(1, 2), LD(2, 5), FMT(DIF_OP_COPYS, 2, 1, 5),
		DIF_INSTR_RET(5) };
	/* allocs only. */
	static const dif_instr_t alloc[] = {
		LD(0, 1), FMT(DIF_OP_ALLOCS, 1, 0, 3), DIF_INSTR_RET(3) };
	/* Restricted loads of every width from arg0. */
	static const dif_instr_t rld[] = {
		LD(0, 1), DIF_INSTR_LOAD(DIF_OP_RLDSB, 1, 2),
		DIF_INSTR_LOAD(DIF_OP_RLDSH, 1, 3),
		DIF_INSTR_LOAD(DIF_OP_RLDSW, 1, 4),
		DIF_INSTR_LOAD(DIF_OP_RLDUB, 1, 5),
		DIF_INSTR_LOAD(DIF_OP_RLDUH, 1, 6),
		DIF_INSTR_LOAD(DIF_OP_RLDUW, 1, 7),
		DIF_INSTR_LOAD(DIF_OP_RLDX, 1, 2),
		FMT(DIF_OP_ADD, 2, 7, 2), DIF_INSTR_RET(2) };
	static const uint_t lds[] = { DIF_OP_LDSB, DIF_OP_LDSH, DIF_OP_LDSW,
	    DIF_OP_LDUB, DIF_OP_LDUH, DIF_OP_LDUW, DIF_OP_LDX, DIF_OP_RLDSB,
	    DIF_OP_RLDSH, DIF_OP_RLDSW, DIF_OP_RLDUB, DIF_OP_RLDUH,
	    DIF_OP_RLDUW, DIF_OP_RLDX };
	/* Thread-local array load (no such variables exist) and a
	 * clause-local load of a reserved variable ID. */
	static const dif_instr_t ldta[] = {
		DIF_INSTR_LDA(DIF_OP_LDTA, 0, 0, 1), DIF_INSTR_RET(1) };
	static const dif_instr_t ldls[] = {
		DIF_INSTR_LDV(DIF_OP_LDLS, DIF_VAR_OTHER_MIN + 1, 1),
		DIF_INSTR_RET(1) };
	/* A by-reference tuple element of a given size (arg0). */
	static const dif_instr_t pushtr[] = {
		LD(0, 1), LD(1, 2), FMT(DIF_OP_PUSHTR, DIF_TYPE_CTF, 1, 2),
		DIF_INSTR_FLUSHTS, DIF_INSTR_RET(2) };
	/* args[arg0]: an argument index beyond the ten a probe carries. */
	static const dif_instr_t ldga[] = {
		LD(0, 1), DIF_INSTR_LDA(DIF_OP_LDGA, DIF_VAR_ARGS, 1, 2),
		DIF_INSTR_RET(2) };
	dif_instr_t one[2];

	CRAFT("craft-copys", copy, nitems(copy), CTX_BOTH,
	    A3(V(8), K(288), V(0)), E1(I(0x1817161514131211ULL)));
	CRAFT("craft-copys-bad-src", copy, nitems(copy), CTX_BOTH,
	    A3(V(8), V(8), V(0)), E3(ANY, I(DTRACEFLT_BADADDR), I(8)));
	CRAFT("craft-copys-out", copy_out, nitems(copy_out), CTX_HOST,
	    A3(V(8), K(288), K(800)), E3(ANY, I(DTRACEFLT_BADADDR), ANY));
	CRAFT("craft-copys-guestdst", copy_out, nitems(copy_out), CTX_GUEST,
	    A3(V(8), K(288), K(800)), E3(ANY, I(DTRACEFLT_ILLOP), ANY));
	CRAFT("craft-allocs-big", alloc, nitems(alloc), CTX_BOTH,
	    A3(V(1 << 20), V(0), V(0)), E3(ANY, I(DTRACEFLT_NOSCRATCH), ANY));
	CRAFT("craft-allocs-wrap", alloc, nitems(alloc), CTX_BOTH,
	    A3(V(-1), V(0), V(0)), E3(ANY, I(DTRACEFLT_NOSCRATCH), ANY));
	CRAFT("craft-rld", rld, nitems(rld), CTX_BOTH,
	    A3(K(288), V(0), V(0)), E1(I(0x1817161514131211ULL + 0x14131211ULL)));
	/* An untagged zero address in a guest clause: refused. */
	for (size_t i = 0; i < nitems(lds); i++) {
		one[0] = DIF_INSTR_LOAD(lds[i], 0, 1);
		one[1] = DIF_INSTR_RET(1);
		CRAFT("craft-load-untagged", one, 2, CTX_GUEST,
	    A3(V(0), V(0), V(0)), E3(ANY, I(DTRACEFLT_BADADDR), I(0)));
	}
	/* Guest: arguments past the hypercall envelope read as 0. */
	CRAFT("craft-ldga-guest", ldga, nitems(ldga), CTX_GUEST,
	    A3(V(12), V(0), V(0)), E1(I(0)));
	/* Host minion (guest-side forwarding state): arguments past the five
	 * stack slots of the envelope read as 0. */
	dif_minion = 1;
	CRAFT("craft-ldga-minion", ldga, nitems(ldga), CTX_HOST,
	    A3(V(12), V(0), V(0)), E1(I(0)));
	dif_minion = 0;
	CRAFT("craft-ldta", ldta, nitems(ldta), CTX_BOTH,
	    A3(V(0), V(0), V(0)), E3(ANY, I(DTRACEFLT_ILLOP), ANY));
	CRAFT("craft-ldls", ldls, nitems(ldls), CTX_BOTH,
	    A3(V(0), V(0), V(0)), E1(I(0)));
	CRAFT("craft-pushtr", pushtr, nitems(pushtr), CTX_BOTH,
	    A3(V(16), K(0), V(0)), E1(ANY));
	CRAFT("craft-pushtr-huge", pushtr, nitems(pushtr), CTX_BOTH,
	    A3(V(-1), K(0), V(0)), E3(ANY, I(DTRACEFLT_ILLOP), ANY));

	/*
	 * Round 4.  Host-side variables have IDs beyond the 8-bit LDGA array
	 * field; LDGS reaches them by ID (index 0).  Oracles: host args are
	 * the probe's own (hargs[0] == arg0); host regs[] without a host trap
	 * frame is BADADDR at 0; huregs[] and hzonename read a value.
	 */
	{
		static const struct { const char *name; uint_t v; int ctx; }
		    hv[] = {
			{ "craft-hargs", DIF_VAR_HARGS, CTX_HOST },
			{ "craft-hregs", DIF_VAR_HREGS, CTX_BOTH },
			{ "craft-huregs", DIF_VAR_HUREGS, CTX_BOTH },
			{ "craft-hzonename", DIF_VAR_HZONENAME, CTX_BOTH },
		};
		dif_instr_t hins[2];

		for (size_t i = 0; i < nitems(hv); i++) {
			hins[0] = DIF_INSTR_LDV(DIF_OP_LDGS, hv[i].v, 1);
			hins[1] = DIF_INSTR_RET(1);
			if (hv[i].v == DIF_VAR_HARGS)
				CRAFT(hv[i].name, hins, 2, hv[i].ctx,
				    A3(V(0x77), V(0), V(0)), E1(I(0x77)));
			else if (hv[i].v == DIF_VAR_HREGS)
				/* No host trap frame in probe context. */
				CRAFT(hv[i].name, hins, 2, hv[i].ctx,
				    A3(V(0), V(0), V(0)),
				    E3(ANY, I(DTRACEFLT_BADADDR), I(0)));
			else
				CRAFT(hv[i].name, hins, 2, hv[i].ctx,
				    A3(V(0), V(0), V(0)), E1(ANY));
		}
		/* hargs in a guest clause are the host probe's arguments. */
		hins[0] = DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_HARGS, 1);
		CRAFT("craft-hargs-guest", hins, 2, CTX_GUEST,
		    A3(V(0x77), V(0), V(0)), E1(ANY));
	}
	/* Restricted loads of a guest NULL: refused before the load. */
	for (size_t i = 7; i < nitems(lds); i++) {
		dif_instr_t rl[3] = { LD(0, 1), DIF_INSTR_LOAD(lds[i], 1, 2),
		    DIF_INSTR_RET(2) };

		CRAFT("craft-rld-null", rl, 3, CTX_GUEST,
		    A3(V(0), V(0), V(0)), E3(ANY, I(DTRACEFLT_BADADDR), I(0)));
	}
	/* A string compare whose second operand is a wrapping guest
	 * address. */
	{
		static const dif_instr_t scmp[] = { LD(0, 1), LD(1, 2),
		    DIF_INSTR_CMP(DIF_OP_SCMP, 1, 2), DIF_INSTR_RET(0) };

		CRAFT("craft-scmp-wrap", scmp, nitems(scmp), CTX_GUEST,
		    A3(K(0), V(-1), V(0)),
		    E3(ANY, I(DTRACEFLT_BADADDR), I(0xffffffffffffffffULL)));
	}
	/* COPYS from a guest NULL. */
	CRAFT("craft-copys-null-src", copy, nitems(copy), CTX_GUEST,
	    A3(V(8), V(0), V(0)), E3(ANY, I(DTRACEFLT_BADADDR), I(0)));

	/*
	 * A CTF-typed (not string-typed) tuple element skips PUSHTR's string
	 * check, so the string subroutines see a guest-tagged NULL pointer
	 * themselves and refuse it (canload_tagged: BADADDR at 0).
	 */
	{
		static const struct { const char *name; uint_t subr; int n; }
		    ss[] = {
			{ "craft-ctf-index", DIF_SUBR_INDEX, 2 },
			{ "craft-ctf-strstr", DIF_SUBR_STRSTR, 2 },
			{ "craft-ctf-index-sub", DIF_SUBR_INDEX, -2 },
			{ "craft-ctf-substr", DIF_SUBR_SUBSTR, 2 },
			{ "craft-ctf-json", DIF_SUBR_JSON, 2 },
			{ "craft-ctf-json-elem", DIF_SUBR_JSON, -2 },
			{ "craft-ctf-toupper", DIF_SUBR_TOUPPER, 1 },
			{ "craft-ctf-basename", DIF_SUBR_BASENAME, 1 },
		};
		dif_instr_t ins[8];

		for (size_t i = 0; i < nitems(ss); i++) {
			int k = 0;

			ins[k++] = DIF_INSTR_FLUSHTS;
			ins[k++] = LD(0, 1);		/* tagged 0 */
			ins[k++] = LD(1, 2);		/* a guest string */
			if (ss[i].n < 0) {
				/* the second string is the bad one */
				ins[k++] = FMT(DIF_OP_PUSHTR, DIF_TYPE_STRING,
				    0, 2);
				ins[k++] = FMT(DIF_OP_PUSHTR, DIF_TYPE_CTF, 0,
				    1);
			} else {
				ins[k++] = FMT(DIF_OP_PUSHTR, DIF_TYPE_CTF, 0,
				    1);
				if (ss[i].n == 2 && ss[i].subr == DIF_SUBR_SUBSTR)
					ins[k++] = FMT(DIF_OP_PUSHTV,
					    DIF_TYPE_CTF, 0, 0);
				else if (ss[i].n == 2)
					ins[k++] = FMT(DIF_OP_PUSHTR,
					    DIF_TYPE_STRING, 0, 2);
			}
			ins[k++] = DIF_INSTR_CALL(ss[i].subr, 3);
			ins[k++] = DIF_INSTR_RET(3);
			CRAFT(ss[i].name, ins, k, CTX_GUEST,
			    A3(V(0), K(288), V(0)),
			    E3(ANY, I(DTRACEFLT_BADADDR), I(0)));
		}
	}
}

/* Host probes reached through dtrace_invop() carry a trap frame: regs[]
 * reads it and arguments past the register set come from its stack. */
static void
case_trapframe(void)
{
	static struct trapframe tf;
	static uint64_t stack[8];
	struct cons c;
	struct recs rs;
	int matched;

	khx_host_case("trapframe");
	memset(&tf, 0, sizeof(tf));
	tf.tf_rax = 0xa1;
	tf.tf_r8 = 0xa8;
	for (int i = 0; i < 8; i++)
		stack[i] = 0x700 + i;
	tf.tf_rsp = (register_t)(uintptr_t)stack;
	cons_open(&c);
	KHX_EQ(cons_enable(&c, "d_hregs", &matched), 0);
	KHX_EQ(matched, 1);
	KHX_EQ(cons_enable(&c, "err_capture", &matched), 0);
	KHX_EQ(cons_options(&c, dif_opts, nitems(dif_opts)), 0);
	KHX_EQ(cons_go(&c), 0);
	struct thread *prev = khx_set_curthread(root_td);
	root_td->t_dtrace_trapframe = &tf;
	fire(p_entry, 1, 2, 3);
	root_td->t_dtrace_trapframe = NULL;
	khx_set_curthread(prev);
	KHX_CHECK(snap_records(&c, 0, &rs) >= 0);
	KHX_EQ(rs.n, 1);
	/* regs[R_EAX], regs[R_R8], uregs[R_EAX] (the thread's user frame),
	 * then args 7, 9 and 6:
	 * argument n > 5 is word n - 5 of the trapped stack. */
	KHX_EQ(rs.r[0].val[0], 0xa1);
	KHX_EQ(rs.r[0].val[1], 0xa8);
	KHX_EQ(rs.r[0].val[2], 0xa0a0);
	KHX_EQ(rs.r[0].val[3], 0x702);
	KHX_EQ(rs.r[0].val[4], 0x704);
	KHX_EQ(rs.r[0].val[5], 0x701);
	cons_close(&c);
}

static void
case_hypercall(void)
{
	const hypertrace_args_t *h;
	uintptr_t *pcs;
	int id, nrec;

	khx_host_case("hypercall");
	/* Not a bhyve guest: the forwarding instruction is illegal; each of
	 * the four forwarding statements reports one ERROR. */
	khx_cpuid_bhyve_guest(0);
	KHX_EQ(hc_fire("h_args", 7, 8, &nrec), 0);
	KHX_EQ(nrec, hc_nstmts);

	khx_cpuid_bhyve_guest(1);
	khx_hypercall_result(HYPERCALL_RET_SUCCESS);
	long base = khx_hypercall_count();
	KHX_EQ(hc_fire("h_args", 7, 8, &nrec), hc_nstmts);
	KHX_EQ(nrec, 0);			/* nothing is traced locally */
	for (long n = base; n < base + hc_nstmts; n++) {
		h = khx_hypercall_nth(n, &id, &pcs);
		KHX_CHECK(h != NULL);
		KHX_EQ(id, p_entry);
		KHX_EQ(h->htr_args[0], 7);
		KHX_EQ(h->htr_args[1], 8);
		KHX_EQ(h->htr_pid, root_td->td_proc->p_pid);
		KHX_EQ(h->htr_ppid, 0);		/* parent is proc0 */
		KHX_EQ(h->htr_tid, root_td->td_tid);
		KHX_CHECK(h->htr_execname != NULL &&
		    strcmp(h->htr_execname, "dtrace") == 0);
		KHX_EQ(h->htr_execargs_len, 10);
		KHX_EQ(h->htr_uid, root_td->td_ucred->cr_uid);
		KHX_EQ(h->htr_gid, root_td->td_ucred->cr_gid);
		KHX_EQ(h->htr_pcstack_count, 0);	/* no stack() */
		KHX_EQ(h->htr_present, 0);	/* no walltimestamp */
		KHX_EQ(h->htr_curcpu, 0);
	}

	/* stack(3) forwards three PCs; walltimestamp is forwarded valid. */
	base = khx_hypercall_count();
	KHX_EQ(hc_fire("h_stack", 1, 2, &nrec), hc_nstmts);
	int stacks = 0, walls = 0;
	for (long n = base; n < base + hc_nstmts; n++) {
		h = khx_hypercall_nth(n, &id, &pcs);
		KHX_CHECK(h != NULL);
		if (h->htr_pcstack_count != 0) {
			KHX_EQ(h->htr_pcstack_count, 3);
			KHX_CHECK(pcs[0] != 0 && pcs[2] != 0);
			stacks++;
		}
		if (h->htr_present & HYPERTRACE_ARGS_WALLTIME_VALID) {
			KHX_CHECK(h->htr_walltimestamp != 0);
			walls++;
		}
	}
	KHX_EQ(stacks, 1);
	KHX_EQ(walls, 1);

	/* A minion (guest-side) consumer forwards arguments past the cached
	 * five in the envelope's stack slots instead of tracing them. */
	{
		static struct trapframe tf;
		static uint64_t stack[8];
		static const struct opt mopts[] = {
			{ DTRACEOPT_BUFSIZE, 64 * 1024 },
			{ DTRACEOPT_MINION, 1 },
		};
		struct cons c;
		struct recs rs;
		int matched;

		for (int i = 0; i < 8; i++)
			stack[i] = 0x900 + i;
		memset(&tf, 0, sizeof(tf));
		tf.tf_rsp = (register_t)(uintptr_t)stack;
		cons_open(&c);
		KHX_EQ(cons_enable(&c, "h_args9", &matched), 0);
		KHX_EQ(cons_options(&c, mopts, nitems(mopts)), 0);
		KHX_EQ(cons_go(&c), 0);
		base = khx_hypercall_count();
		struct thread *prev = khx_set_curthread(root_td);
		root_td->t_dtrace_trapframe = &tf;
		fire(p_entry, 1, 2, 3);
		root_td->t_dtrace_trapframe = NULL;
		khx_set_curthread(prev);
		KHX_CHECK(khx_hypercall_count() > base);
		int seen = 0;
		for (long n = base; n < khx_hypercall_count(); n++) {
			h = khx_hypercall_nth(n, &id, &pcs);
			if (h->htr_args[7] == 0x902 || h->htr_args[9] == 0x904)
				seen++;
			KHX_EQ(h->htr_args[3], 0);	/* arg3: fire passed 0 */
		}
		KHX_CHECK(seen >= 1);
		KHX_CHECK(snap_records(&c, 0, &rs) >= 0);
		KHX_EQ(rs.n, 0);
		cons_close(&c);
	}

	/* A host that rejects the hypercall surfaces as an illegal operation. */
	khx_hypercall_result(HYPERCALL_RET_ERROR);
	KHX_EQ(hc_fire("h_args", 7, 8, &nrec), hc_nstmts);
	KHX_EQ(nrec, hc_nstmts);
	khx_hypercall_result(HYPERCALL_RET_SUCCESS);
	khx_cpuid_bhyve_guest(0);
}

/*
 * Find the scratch space a clause has (host and guest): the largest
 * alloca(N) that does not fault NOSCRATCH, by bisection over firings.
 */
static void
scratch_probe(void)
{
	for (int guest = 0; guest < 2; guest++) {
		uint64_t lo = 0, hi = 1 << 20;

		while (hi - lo > 1) {
			uint64_t mid = (lo + hi) / 2;
			struct dcase k = { "g_alloca_big", 0, NULL, NULL,
			    { V(0) }, 1, { ANY } };
			struct recs rs;

			k.a[0].v = mid;
			dif_exec(&k, guest, 0, &rs);
			KHX_EQ(rs.n, 1);
			if (rs.r[0].probe == dtrace_probeid_error)
				hi = mid;
			else
				lo = mid;
		}
		dif_scratch_max[guest] = lo & ~(uint64_t)7;
		KHX_CHECK(lo > 4096);
		khx_host_log("scratch: %s %ju bytes\n", guest ? "guest" :
		    "host", (uintmax_t)lo);
	}
}

static void
case_dif_corpus(void)
{
	arena_fill(karena);
	arena_fill(uarena);
	dif_vm = fvm_new("difvm");
	arena_fill(dif_vm->mem);
	arena_fill(dif_vm->umem);
	guest_layout(dif_vm);
	dif_discover = khx_host_env_flag("KHX_DISCOVER");
	scratch_probe();
	for (size_t i = 0; i < nitems(dcases); i++) {
		if (khx_host_env_flag("KHX_DIF_ONLY") &&
		    !khx_host_env_is("KHX_DIF_ONLY", dcases[i].prog))
			continue;
		dif_case_index = i;
		if (dcases[i].ctx & CTX_HOST)
			dif_run(&dcases[i], 0);
		if (dcases[i].ctx & CTX_GUEST)
			dif_run(&dcases[i], 1);
	}
	/* Transient guest faults at every access of every guest case. */
	if (!khx_host_env_flag("KHX_NO_SWEEP")) {
		for (size_t i = 0; i < nitems(dcases); i++) {
			if (khx_host_env_flag("KHX_DIF_ONLY") &&
			    !khx_host_env_is("KHX_DIF_ONLY", dcases[i].prog))
				continue;
			if (dcases[i].ctx & CTX_GUEST)
				dif_sweep(&dcases[i]);
		}
		khx_host_log("fault sweep: %d runs, %d injected faults\n",
		    dif_sweep_runs, dif_sweep_faults);
	}
	if (!khx_host_env_flag("KHX_DIF_ONLY")) {
		case_crafted_dif();
		case_locks();
		case_immstack();
		case_immstack_format();
		case_trapframe();
		case_hypercall();
		case_hypercall_dof();
	}
	fvm_free(dif_vm);
	dif_vm = NULL;
}
