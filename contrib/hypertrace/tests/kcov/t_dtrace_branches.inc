/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Round 4: branch outcomes of changed lines that the corpus does not reach
 * (coverage-kernel.py branch view).  Each case names the outcome it drives
 * and checks the documented result.
 */

/* Framework epoch KPIs with out-of-range VM IDs or a zero epoch. */
static void
case_br_epochs(void)
{
	khx_host_case("br-epochs");
	dtrace_hypertrace_config_lock();
	KHX_EQ(dtrace_hypertrace_epoch_suspend(HYPERTRACE_MAX_VMS, 1), EINVAL);
	KHX_EQ(dtrace_hypertrace_epoch_resume(HYPERTRACE_MAX_VMS, 1), EINVAL);
	KHX_EQ(dtrace_hypertrace_epoch_suspended(HYPERTRACE_MAX_VMS, 1), 0);
	KHX_EQ(dtrace_hypertrace_epoch_suspended(5, 0), 0);
	/* revoke() of a lifetime that is neither active nor suspended. */
	KHX_EQ(dtrace_hypertrace_epoch_revoke(0, 1), ESTALE);
	KHX_EQ(dtrace_hypertrace_epoch_revoke(HYPERTRACE_MAX_VMS, 1), ESTALE);
	KHX_EQ(dtrace_hypertrace_epoch_revoke(5, 0), ESTALE);
	dtrace_hypertrace_config_unlock();
}

/* dtrace_probe_arg(): no probe 0, and another provider's probe. */
static void
case_br_probe_arg(void)
{
	dtrace_provider_id_t other;
	dtrace_id_t id;

	khx_host_case("br-probe-arg");
	KHX_CHECK(dtrace_probe_arg(khx_prov, 0) == NULL);
	KHX_EQ(dtrace_register("khxarg", &khxp_attr, DTRACE_PRIV_KERNEL, NULL,
	    &lp_pops, NULL, &other), 0);
	id = dtrace_probe_create(other, "m", "f", "n", 0, (void *)0x5a);
	KHX_CHECK(id != 0);
	KHX_CHECK(dtrace_probe_arg(other, id) == (void *)0x5a);
	KHX_CHECK(dtrace_probe_arg(khx_prov, id) == NULL);
	KHX_EQ(dtrace_unregister(other), 0);
}

/* A predicate the framework can cache: the second firing of the same
 * thread skips it (no record either way). */
static void
case_br_predcache(void)
{
	struct cons c;
	struct recs rs;
	int matched;

	khx_host_case("br-predcache");
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable(&c, "b_pred", &matched), 0);
	KHX_EQ(cons_options(&c, dif_opts, nitems(dif_opts)), 0);
	KHX_EQ(cons_go(&c), 0);
	{
		struct thread *prev = khx_set_curthread(root_td);

		fire(p_entry, 0, 0, 0);
		fire(p_entry, 0, 0, 0);
		khx_set_curthread(prev);
	}
	KHX_CHECK(snap_records(&c, 0, &rs) >= 0);
	KHX_EQ(rs.n, 0);
	cons_close(&c);
}

/* caller in an unanchored host probe: the frame walk starts at the
 * interrupted PC (arg0). */
static void
case_br_host_unanchored_caller(void)
{
	static dtrace_id_t tick;
	struct cons c;
	struct recs rs;
	int matched;

	khx_host_case("br-unanchored-caller");
	if (tick == 0)
		tick = dtrace_probe_lookup(0, khx_prov, "mod", "", "tick");
	if (tick == 0)
		tick = dtrace_probe_create(khx_prov, "mod", "", "tick", 0,
		    NULL);
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable(&c, "b_hcaller_host", &matched), 0);
	KHX_EQ(matched, 1);
	KHX_EQ(cons_options(&c, dif_opts, nitems(dif_opts)), 0);
	KHX_EQ(cons_go(&c), 0);
	{
		struct thread *prev = khx_set_curthread(root_td);

		fire(tick, (uintptr_t)fire + 3, 0, 0);
		khx_set_curthread(prev);
	}
	KHX_CHECK(snap_records(&c, 0, &rs) >= 0);
	KHX_EQ(rs.n, 1);
	cons_close(&c);
}

/* hypertrace_probe() on a VM that never created a virtual probe. */
static void
case_br_probe_empty_vm(void)
{
	struct fvm *vm = fvm_new("br-empty");
	hypertrace_args_t a = gargs(1, 2, 3);

	khx_host_case("br-probe-empty-vm");
	KHX_EQ(hypertrace_probe(&vm->hdl, 3, &a), ESRCH);
	fvm_free(vm);
}

/*
 * Virtual-probe ioctls: VPROBE_CREATE without descriptions; PROBES
 * starting at a gap in the VM's ID space; a duplicate ID with framework
 * diagnostics off; DTrace ioctl logging on.
 */
static void
case_br_vprobe_ioctls(void)
{
	struct fvm *vm = fvm_new("br-vp");
	dtrace_probedesc_t d[2], q;
	dtrace_vprobe_io_t io;
	struct cons c;
	struct sysctl_oid *oid;
	int on = 1, off = 0;

	khx_host_case("br-vprobe-ioctls");
	KHX_EQ(cons_open(&c), 0);
	memset(&io, 0, sizeof(io));
	io.eprobes = d;
	io.neprobes = 0;
	io.vmid = vm->vmid;
	io.epoch = vm->epoch;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_VPROBE_CREATE, &io), EINVAL);
	d[0] = vdesc(1, "gbr", "m", "f", "a");
	d[1] = vdesc(7, "gbr", "m", "f", "b");
	KHX_EQ(vprobe_create(&c, vm, d, 2), 0);
	memset(&q, 0, sizeof(q));
	q.dtpd_vmid = vm->vmid;
	q.dtpd_id = 3;		/* IDs 3..6 are unused */
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_PROBES, &q), 0);
	KHX_EQ(q.dtpd_id, 7);
	dtrace_err_verbose = 0;
	d[0] = vdesc(7, "gbr", "m", "f", "dup");
	KHX_EQ(vprobe_create(&c, vm, d, 1), EEXIST);
	dtrace_err_verbose = 1;
	oid = khx_sysctl_find("dtrace", "verbose_ioctl");
	KHX_CHECK(oid != NULL);
	KHX_EQ(khx_sysctl_call(oid, root_td, NULL, NULL, &on, sizeof(on)), 0);
	{
		dtrace_conf_t conf;
		dtrace_enable_io_t eio;

		KHX_EQ(cons_ioctl(&c, DTRACEIOC_CONF, &conf), 0);
		d[0] = vdesc(9, "gbr", "m", "f", "verbose");
		KHX_EQ(vprobe_create(&c, vm, d, 1), 0);
		/* AUGMENT needs an active state. */
		memset(&eio, 0, sizeof(eio));
		eio.dof = dof_load("trace_arg0");
		KHX_EQ(cons_ioctl(&c, DTRACEIOC_AUGMENT, &eio), ESHUTDOWN);
		dof_free(eio.dof);
	}
	KHX_EQ(khx_sysctl_call(oid, root_td, NULL, NULL, &off, sizeof(off)), 0);
	cons_close(&c);
	fvm_free(vm);
}

/*
 * AUGMENT of an active consumer with an enabling whose ECB cannot be
 * created (jstack() string size beyond the 32-bit record argument): the
 * enabling is destroyed and the error returned.
 */
static void
case_br_augment_error(void)
{
	static const struct opt o[] = {
		{ DTRACEOPT_BUFSIZE, 64 * 1024 },
		{ DTRACEOPT_JSTACKSTRSIZE, 1L << 33 },
	};
	dtrace_enable_io_t eio;
	struct cons c;
	int matched;

	khx_host_case("br-augment-error");
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_options(&c, o, nitems(o)), 0);
	KHX_EQ(cons_enable(&c, "trace_arg0", &matched), 0);
	KHX_EQ(cons_go(&c), 0);
	memset(&eio, 0, sizeof(eio));
	eio.dof = dof_load("a_jstack");
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_AUGMENT, &eio), EINVAL);
	dof_free(eio.dof);
	cons_close(&c);
}

/* Record-size options of zero or out of range refuse the stack action
 * (at option or at enable time). */
static void
case_br_stack_options(void)
{
	static const struct {
		dtrace_optid_t opt;
		dtrace_optval_t val;
		const char *prog;
	} t[] = {
		{ DTRACEOPT_IMMSTACKFRAMES, 0, "a_immstack" },
		{ DTRACEOPT_IMMSTACKSTRSIZE, 0, "a_immstack" },
		{ DTRACEOPT_STACKFRAMES, 0, "b_stack0" },
		{ DTRACEOPT_USTACKFRAMES, 0, "b_ustack0" },
		{ DTRACEOPT_USTACKFRAMES, 1L << 40, "b_ustack0" },
		{ DTRACEOPT_JSTACKSTRSIZE, -1, "a_jstack" },
	};

	khx_host_case("br-stack-options");
	for (size_t i = 0; i < nitems(t); i++) {
		struct opt o[2] = { { DTRACEOPT_BUFSIZE, 64 * 1024 },
		    { t[i].opt, t[i].val } };
		struct cons c;
		int matched, e1, e2 = -1;

		KHX_EQ(cons_open(&c), 0);
		e1 = cons_options(&c, o, 2);
		if (e1 == 0)
			e2 = cons_enable(&c, t[i].prog, &matched);
		if (e1 == 0 && e2 == 0)
			e2 = cons_go(&c);
		KHX_CHECK(e1 == EINVAL || e2 == EINVAL);
		cons_close(&c);
	}
}

/* basename()/cleanpath() refuse a string size near INT_MAX. */
static void
case_br_huge_strsize(void)
{
	static const struct opt o[] = {
		{ DTRACEOPT_BUFSIZE, 64 * 1024 },
		{ DTRACEOPT_STRSIZE, 0x7ffffffc },
	};
	static const char *const progs[] = { "b_basename_huge",
	    "b_cleanpath_huge" };

	khx_host_case("br-huge-strsize");
	for (size_t i = 0; i < nitems(progs); i++) {
		struct cons c;
		struct recs rs;
		int matched;

		KHX_EQ(cons_open(&c), 0);
		KHX_EQ(cons_options(&c, o, nitems(o)), 0);
		KHX_EQ(cons_enable(&c, progs[i], &matched), 0);
		KHX_EQ(cons_enable(&c, "err_capture", &matched), 0);
		KHX_EQ(cons_go(&c), 0);
		{
			struct thread *prev = khx_set_curthread(root_td);

			fire(p_entry, 0, 0, 0);
			khx_set_curthread(prev);
		}
		KHX_CHECK(snap_records(&c, 0, &rs) >= 0);
		KHX_EQ(rs.n, 1);
		KHX_EQ(rs.r[0].val[1], DTRACEFLT_ILLOP);
		cons_close(&c);
	}
}

/* A global changes its type flags (scalar to by-reference string) in a
 * later enabling of the same consumer. */
static void
case_br_var_flags(void)
{
	struct cons c;
	int matched;

	khx_host_case("br-var-flags");
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable(&c, "b_vflag1", &matched), 0);
	KHX_EQ(cons_enable(&c, "b_vflag2", &matched), EINVAL);
	cons_close(&c);
}

/* GO while an ENABLE of the same consumer is copying its probe list
 * out: refused (the enabling is pending). */
static struct cons *br_go_cons;
static int br_go_error;

static int
br_go_hook(void *arg __unused, int out, const void *uaddr __unused,
    size_t len __unused)
{
	processorid_t cpu;

	if (!out || br_go_cons == NULL)
		return (0);
	br_go_error = cons_ioctl(br_go_cons, DTRACEIOC_GO, &cpu);
	br_go_cons = NULL;
	return (0);
}

static void
case_br_go_pending(void)
{
	dtrace_enable_io_t io;
	dtrace_probedesc_t ps[4];
	struct cons c;

	khx_host_case("br-go-pending");
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_options(&c, default_opts, nitems(default_opts)), 0);
	memset(&io, 0, sizeof(io));
	io.dof = dof_load("trace_arg0");
	io.ps = ps;
	io.ps_bufsize = sizeof(ps);
	br_go_cons = &c;
	br_go_error = -1;
	khx_set_copy_hook(br_go_hook, NULL);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_ENABLE, &io), 0);
	khx_set_copy_hook(NULL, NULL);
	KHX_EQ(br_go_error, EBUSY);
	dof_free(io.dof);
	cons_close(&c);
}

/* REPLICATE walks every retained enabling, skipping other consumers'. */
static void
case_br_replicate_states(void)
{
	dtrace_repldesc_t rd;
	struct cons a, b;
	int matched;

	khx_host_case("br-replicate-states");
	KHX_EQ(cons_open(&a), 0);
	KHX_EQ(cons_open(&b), 0);
	KHX_EQ(cons_enable(&a, "trace_arg0", &matched), 0);
	KHX_EQ(cons_enable(&b, "trace_arg0", &matched), 0);
	KHX_EQ(cons_enable(&b, "trace_arg0", &matched), 0);
	memset(&rd, 0, sizeof(rd));
	/* An exact description of the enabled probe (trace_arg0). */
	strlcpy(rd.dtrpd_match.dtpd_provider, "khx",
	    sizeof(rd.dtrpd_match.dtpd_provider));
	strlcpy(rd.dtrpd_match.dtpd_mod, "mod", sizeof(rd.dtrpd_match.dtpd_mod));
	strlcpy(rd.dtrpd_match.dtpd_func, "func",
	    sizeof(rd.dtrpd_match.dtpd_func));
	strlcpy(rd.dtrpd_match.dtpd_name, "entry",
	    sizeof(rd.dtrpd_match.dtpd_name));
	rd.dtrpd_create = rd.dtrpd_match;
	KHX_EQ(cons_ioctl(&b, DTRACEIOC_REPLICATE, &rd), 0);
	cons_close(&a);
	cons_close(&b);
}

/* immstack(n) with an explicit frame count, outside hypercall mode. */
static void
case_br_immstack_frames(void)
{
	struct cons c;
	int matched;

	khx_host_case("br-immstack-frames");
	khx_cpuid_bhyve_guest(0);
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_options(&c, dif_opts, nitems(dif_opts)), 0);
	KHX_EQ(cons_enable(&c, "b_immstack3", &matched), 0);
	KHX_EQ(cons_go(&c), 0);
	cons_close(&c);
}

/* The HYPERTRACE option with an aggregation buffer but no aggregations:
 * the buffer is kept for forwarded aggregations. */
static void
case_br_hypertrace_aggsize(void)
{
	static const struct opt o[] = {
		{ DTRACEOPT_BUFSIZE, 64 * 1024 },
		{ DTRACEOPT_AGGSIZE, 64 * 1024 },
		{ DTRACEOPT_HYPERTRACE, 1 },
	};
	struct cons c;
	int matched;

	khx_host_case("br-hypertrace-aggsize");
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_options(&c, o, nitems(o)), 0);
	KHX_EQ(cons_enable(&c, "trace_arg0", &matched), 0);
	KHX_EQ(cons_go(&c), 0);
	KHX_EQ(cons_stop(&c), 0);
	cons_close(&c);
}

/* PROBEMATCH descriptions with an empty provider and some empty
 * components (dtrace_probekey()'s null matchers; all empty matches any
 * probe). */
static void
case_br_probekey(void)
{
	static const char *const d[][3] = {
		{ "mod", "", "" }, { "", "func", "" }, { "", "", "" },
	};
	struct cons c;

	khx_host_case("br-probekey");
	KHX_EQ(cons_open(&c), 0);
	for (size_t i = 0; i < nitems(d); i++) {
		dtrace_probedesc_t pd;

		memset(&pd, 0, sizeof(pd));
		strlcpy(pd.dtpd_mod, d[i][0], sizeof(pd.dtpd_mod));
		strlcpy(pd.dtpd_func, d[i][1], sizeof(pd.dtpd_func));
		strlcpy(pd.dtpd_name, d[i][2], sizeof(pd.dtpd_name));
		KHX_EQ(cons_ioctl(&c, DTRACEIOC_PROBEMATCH, &pd), 0);
		KHX_CHECK(pd.dtpd_id != DTRACE_IDNONE);
	}
	cons_close(&c);
}

/* cleanpath() of host paths longer than strsize (16) made of "." and
 * ".." components: the scan stops at the bound wherever it falls; every
 * component collapses, and the cut final "/." or "/.." component leaves
 * nothing (the upstream algorithm drops it with its slash), so the result
 * is empty. */
static void
case_br_cleanpath_bound(void)
{
	static const size_t offs[] = { 864, 896, 928, 976 };

	khx_host_case("br-cleanpath-bound");
	for (size_t i = 0; i < nitems(offs); i++) {
		struct opt o[nitems(dif_opts)];
		struct cons c;
		struct recs rs;
		int matched;

		memcpy(o, dif_opts, sizeof(dif_opts));
		for (size_t j = 0; j < nitems(o); j++)
			if (o[j].option == DTRACEOPT_STRSIZE)
				o[j].value = 16;
		KHX_EQ(cons_open(&c), 0);
		KHX_EQ(cons_options(&c, o, nitems(o)), 0);
		KHX_EQ(cons_enable(&c, "b_cleanpath", &matched), 0);
		KHX_EQ(cons_go(&c), 0);
		{
			struct thread *prev = khx_set_curthread(root_td);

			fire(p_entry, (uintptr_t)(karena + offs[i]), 0, 0);
			khx_set_curthread(prev);
		}
		KHX_CHECK(snap_records(&c, 0, &rs) >= 0);
		KHX_EQ(rs.n, 1);
		KHX_EQ(rs.r[0].kind[0], DTRACEACT_DIFEXPR);
		KHX_EQ(rs.r[0].str[0][0], '\0');
		cons_close(&c);
	}
}

/* DIF_OP_HYPERCALL takes a frame count in r1 only: r2 and rd must be 0
 * (the validator refuses the enabling). */
static void
case_br_hypercall_validate(void)
{
	static const dif_instr_t bad_r2[] = {
	    DIF_INSTR_FMT(DIF_OP_HYPERCALL, 0, 1, 0), DIF_INSTR_RET(0) };
	static const dif_instr_t bad_rd[] = {
	    DIF_INSTR_FMT(DIF_OP_HYPERCALL, 0, 0, 1), DIF_INSTR_RET(0) };
	const dif_instr_t *progs[] = { bad_r2, bad_rd };

	khx_host_case("br-hypercall-validate");
	for (size_t i = 0; i < nitems(progs); i++) {
		struct cons c;
		dof_hdr_t *dof;
		int matched;

		KHX_EQ(cons_open(&c), 0);
		dof = dof_load("r_craft");
		dif_craft = progs[i];
		dif_ncraft = 2;
		dof_craft(dof);
		dif_craft = NULL;
		KHX_EQ(cons_enable_vm(&c, dof, 0, 0, &matched), EINVAL);
		dof_free(dof);
		cons_close(&c);
	}
}

/*
 * A forwarding (hypercall) clause fired by threads whose process has no
 * argument vector (jail_td), or that belong to proc0: the envelope's
 * execargs stay empty and the parent pid is 0.
 */
static void
case_br_hypercall_threads(void)
{
	struct thread *p0 = khx_thread_new("p0", 0);
	struct thread *who[2] = { jail_td, p0 };

	khx_host_case("br-hypercall-threads");
	khx_cpuid_bhyve_guest(1);
	khx_hypercall_result(HYPERCALL_RET_SUCCESS);
	for (size_t i = 0; i < nitems(who); i++) {
		struct cons c;
		struct recs rs;
		int matched, id;
		long before = khx_hypercall_count();
		uintptr_t *pcs;
		hypertrace_args_t *h;

		KHX_EQ(cons_open(&c), 0);
		KHX_EQ(cons_enable(&c, "h_args", &matched), 0);
		KHX_EQ(cons_options(&c, dif_opts, nitems(dif_opts)), 0);
		KHX_EQ(cons_go(&c), 0);
		{
			struct thread *prev = khx_set_curthread(who[i]);

			fire(p_entry, 7, 8, 0);
			khx_set_curthread(prev);
		}
		KHX_CHECK(snap_records(&c, 0, &rs) >= 0);
		KHX_CHECK(khx_hypercall_count() > before);
		h = khx_hypercall_nth(before, &id, &pcs);
		KHX_CHECK(h != NULL);
		if (h != NULL) {
			KHX_EQ(h->htr_execargs_len, 0);
			KHX_EQ(h->htr_pid, who[i]->td_proc->p_pid);
			if (i == 1)
				KHX_EQ(h->htr_ppid, 0);	/* proc0 has no parent */
		}
		cons_close(&c);
	}
	khx_cpuid_bhyve_guest(0);
}

/* immstack() of an unanchored probe in hypercall mode: the interrupted
 * PC is forwarded, nothing is recorded locally. */
static void
case_br_hypercall_immstack_tick(void)
{
	static dtrace_id_t tick;
	struct cons c;
	struct recs rs;
	int matched;

	khx_host_case("br-hypercall-immstack-tick");
	if (tick == 0)
		tick = dtrace_probe_lookup(0, khx_prov, "mod", "", "tick");
	KHX_CHECK(tick != 0);
	khx_cpuid_bhyve_guest(1);
	khx_hypercall_result(HYPERCALL_RET_SUCCESS);
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable(&c, "a_immstack_tick", &matched), 0);
	KHX_EQ(cons_options(&c, dif_opts, nitems(dif_opts)), 0);
	KHX_EQ(cons_go(&c), 0);
	{
		struct thread *prev = khx_set_curthread(root_td);

		fire(tick, (uintptr_t)fire + 3, 0, 0);
		khx_set_curthread(prev);
	}
	KHX_CHECK(snap_records(&c, 0, &rs) >= 0);
	KHX_EQ(rs.n, 0);
	cons_close(&c);
	khx_cpuid_bhyve_guest(0);
}

/*
 * vprog end to end: the guest-side forwarding program (dtrace_vprog_from())
 * makes one hypercall per probe firing, whatever the number of actions in
 * the clause, and the host evaluates the original clause once per
 * hypercall.  Every hypercall a guest firing produces is replayed into a
 * host consumer of the same clause on the VM's namespace; the host must
 * see each action's record exactly once per firing, in order, and a
 * predicate with a side effect must run once per firing.
 */
#define	E2E_MAXHC	8

/* Fire the guest probe `firings` times under the forwarding program and
 * collect the hypercalls made. */
static int
e2e_guest(const char *prog, int firings, hypertrace_args_t *hc, int *ids)
{
	struct cons g;
	int matched, n;
	long before;

	khx_cpuid_bhyve_guest(1);
	khx_hypercall_result(HYPERCALL_RET_SUCCESS);
	KHX_EQ(cons_open(&g), 0);
	KHX_EQ(cons_enable(&g, prog, &matched), 0);
	KHX_EQ(matched, 1);	/* one forwarding statement per probe */
	KHX_EQ(cons_options(&g, dif_opts, nitems(dif_opts)), 0);
	KHX_EQ(cons_go(&g), 0);
	before = khx_hypercall_count();
	for (int f = 0; f < firings; f++) {
		struct thread *prev = khx_set_curthread(root_td);

		fire(p_entry, 5, 6, 0);
		khx_set_curthread(prev);
	}
	n = (int)(khx_hypercall_count() - before);
	for (int i = 0; i < n && i < E2E_MAXHC; i++) {
		uintptr_t *pcs;
		hypertrace_args_t *h = khx_hypercall_nth(before + i, &ids[i],
		    &pcs);

		KHX_CHECK(h != NULL);
		if (h == NULL)
			continue;
		hc[i] = *h;
		/* Guest addresses are not replayed (no clause reads them). */
		hc[i].htr_pcstack = NULL;
		hc[i].htr_pcstack_count = 0;
	}
	cons_close(&g);
	khx_cpuid_bhyve_guest(0);
	return (n);
}

static void
case_vprog_e2e(void)
{
	static const struct { const char *guest, *host; int pred; } t[] = {
		{ "h_e2e", "h_e2e_host", 0 },
		{ "h_e2e_pred", "h_e2e_pred_host", 1 },
	};

	khx_host_case("vprog-e2e");
	for (size_t k = 0; k < nitems(t); k++) {
		struct fvm *vm = fvm_new("e2e");
		hypertrace_args_t hc[E2E_MAXHC];
		int ids[E2E_MAXHC], n, matched;
		struct cons h;
		struct recs rs;
		dof_hdr_t *dof;
		dtrace_probedesc_t d;
		int expect = 0;

		/* The guest probe's ID names the host-side virtual probe. */
		n = e2e_guest(t[k].guest, 1, hc, ids);
		KHX_EQ(n, 1);		/* one hypercall per firing */
		KHX_EQ(ids[0], (int)p_entry);
		KHX_EQ(cons_open(&h), 0);
		d = vdesc(p_entry, "khx", "mod", "func", "entry");
		KHX_EQ(vprobe_create(&h, vm, &d, 1), 0);
		dof = dof_load(t[k].host);
		dof_set_vmid(dof, vm->vmid);
		KHX_EQ(cons_enable_vm(&h, dof, 0, 0, &matched), 0);
		KHX_EQ(matched, 1);
		dof_free(dof);
		KHX_EQ(cons_options(&h, default_opts, nitems(default_opts)), 0);
		KHX_EQ(cons_go(&h), 0);
		for (int round = 1; round <= 2; round++) {
			/* Round 1: one firing; round 2: two firings. */
			if (round == 2)
				n = e2e_guest(t[k].guest, 2, hc, ids);
			KHX_EQ(n, round);
			for (int i = 0; i < n && i < E2E_MAXHC; i++)
				KHX_EQ(hypertrace_probe(&vm->hdl, ids[i],
				    &hc[i]), 0);
			KHX_CHECK(snap_records(&h, curcpu, &rs) >= 0);
			KHX_EQ(rs.n, round);	/* once per firing */
			for (int r = 0; r < rs.n; r++) {
				if (t[k].pred) {
					/* The predicate's counter advanced
					 * once per firing. */
					KHX_EQ(rs.r[r].nrecs, 1);
					KHX_EQ(rs.r[r].val[0], ++expect);
				} else {
					/* trace(1), trace(2), printf(3): each
					 * record once, in clause order. */
					KHX_EQ(rs.r[r].nrecs, 3);
					KHX_EQ(rs.r[r].val[0], 1);
					KHX_EQ(rs.r[r].val[1], 2);
					KHX_EQ(rs.r[r].val[2], 3);
				}
			}
		}
		cons_close(&h);
		fvm_free(vm);
	}
}

/* An enabling whose probe description is all empty (every component is
 * the empty string): it matches every probe that has a function name. */
static void
case_br_empty_desc(void)
{
	struct cons c;
	dof_hdr_t *dof;
	int matched = 0, n = 0;

	khx_host_case("br-empty-desc");
	dof = dof_load("trace_arg0");
	for (uint32_t i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t *sec = (dof_sec_t *)((char *)dof + dof->dofh_secoff +
		    i * dof->dofh_secsize);
		dof_probedesc_t *pd;

		if (sec->dofs_type != DOF_SECT_PROBEDESC)
			continue;
		pd = (dof_probedesc_t *)((char *)dof + sec->dofs_offset);
		/* Offset 0 of a DOF string table is the empty string. */
		pd->dofp_provider = pd->dofp_mod = pd->dofp_func =
		    pd->dofp_name = 0;
		n++;
	}
	KHX_EQ(n, 1);
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable_vm(&c, dof, 0, 0, &matched), 0);
	KHX_CHECK(matched >= 1);
	dof_free(dof);
	cons_close(&c);
}

/* An action description naming a string table that does not exist. */
static void
case_br_actdesc_strtab(void)
{
	struct cons c;
	dof_hdr_t *dof;
	int matched, n = 0;

	khx_host_case("br-actdesc-strtab");
	dof = dof_load("h_e2e_host");	/* has a printf() action */
	for (uint32_t i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t *sec = (dof_sec_t *)((char *)dof + dof->dofh_secoff +
		    i * dof->dofh_secsize);
		dof_actdesc_t *ad;

		if (sec->dofs_type != DOF_SECT_ACTDESC)
			continue;
		ad = (dof_actdesc_t *)((char *)dof + sec->dofs_offset);
		for (size_t j = 0; j < sec->dofs_size / sec->dofs_entsize;
		    j++, ad++) {
			if (ad->dofa_strtab != DOF_SECIDX_NONE) {
				ad->dofa_strtab = dof->dofh_secnum + 5;
				n++;
			}
		}
	}
	KHX_CHECK(n >= 1);
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable_vm(&c, dof, 0, 0, &matched), EINVAL);
	dof_free(dof);
	cons_close(&c);
}

/*
 * The HyperTrace provider table holds 4096 providers: 16 VMs of 256
 * providers each fill it, and a 4097th distinct provider is refused
 * (ENOSPC) even on a VM with room of its own.
 */
static void
case_br_provtab_full(void)
{
	enum { NVM = 17, NPROV = 256 };
	struct fvm *vm[NVM];
	static char names[NVM][16];
	dtrace_probedesc_t *d;
	struct cons c;

	khx_host_case("br-provtab-full");
	d = malloc(NPROV * sizeof(*d), M_TEMP, M_WAITOK | M_ZERO);
	KHX_EQ(cons_open(&c), 0);
	for (int v = 0; v < NVM; v++) {
		snprintf(names[v], sizeof(names[v]), "pt%d", v);
		vm[v] = fvm_new(names[v]);
	}
	for (int v = 0; v < NVM - 1; v++) {
		for (int p = 0; p < NPROV; p++) {
			char prov[DTRACE_PROVNAMELEN];

			snprintf(prov, sizeof(prov), "q%d_%d", v, p);
			d[p] = vdesc(p + 1, prov, "m", "f", "n");
		}
		KHX_EQ(vprobe_create(&c, vm[v], d, NPROV), 0);
	}
	d[0] = vdesc(1, "qfull", "m", "f", "n");
	KHX_EQ(vprobe_create(&c, vm[NVM - 1], d, 1), ENOSPC);
	cons_close(&c);
	for (int v = 0; v < NVM; v++)
		fvm_free(vm[v]);
	free(d, M_TEMP);
}

/* The late epoch re-check of a guest-origin ENABLE when the HyperTrace
 * hook disappears while the probe list copies out: ENOTSUP. */
static struct fvm *br_late_vm;
static void *br_late_saved;

static int
br_late_hook(void *arg __unused, int out, const void *uaddr __unused,
    size_t len __unused)
{
	if (!out || br_late_vm == NULL)
		return (0);
	br_late_saved = hypertrace_check_epoch;
	hypertrace_check_epoch = NULL;
	br_late_vm = NULL;
	return (0);
}

static void
case_br_late_epoch_hook(void)
{
	struct fvm *vm = fvm_new("br-late");
	dtrace_enable_io_t io;
	dtrace_probedesc_t ps[4];
	struct cons c;

	khx_host_case("br-late-epoch-hook");
	KHX_EQ(cons_open(&c), 0);
	memset(&io, 0, sizeof(io));
	io.dof = dof_load("trace_arg0");
	io.ps = ps;
	io.ps_bufsize = sizeof(ps);
	io.vmid = vm->vmid;
	io.epoch = vm->epoch;
	br_late_vm = vm;
	br_late_saved = NULL;
	khx_set_copy_hook(br_late_hook, NULL);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_ENABLE, &io), ENOTSUP);
	khx_set_copy_hook(NULL, NULL);
	KHX_CHECK(br_late_saved != NULL);
	hypertrace_check_epoch = br_late_saved;
	dof_free(io.dof);
	cons_close(&c);
	fvm_free(vm);
}

/*
 * VM ID reuse and probe epochs (hypertrace_priv_check_epoch()'s invariant):
 * a VM ID is handed out again only once its probe namespace is empty, so
 * every probe in a namespace carries the epoch of the VM's current lifetime.
 */
static void
case_ht_vmid_reuse(void)
{
	struct cons c;
	struct fvm *a, *b, *n;
	dtrace_probedesc_t d[2];
	uint16_t id2, ids[8];
	uint64_t ep2, eps[8];
	size_t base = ht_nprobes();
	int k;

	khx_host_case("ht-vmid-reuse");
	KHX_EQ(cons_open(&c), 0);
	a = fvm_new("reuse-a");
	d[0] = vdesc(1, "greuse", "m", "f", "a");
	d[1] = vdesc(2, "greuse", "m", "f", "b");
	KHX_EQ(vprobe_create(&c, a, d, 2), 0);
	KHX_EQ(ht_nprobes(), base + 2);

	/* 1. Destroying the VM while its probes remain: the ID is not
	 * reused (no allocation returns it), and the old lifetime can no
	 * longer register probes. */
	KHX_EQ(hypertrace_vm_release(a->vmid, a->epoch), 0);
	for (k = 0; k < 8; k++) {
		KHX_EQ(hypertrace_vm_alloc(&ids[k], &eps[k]), 0);
		KHX_CHECK(ids[k] != a->vmid);
	}
	d[0] = vdesc(3, "greuse", "m", "f", "c");
	KHX_EQ(vprobe_create(&c, a, d, 1), ESTALE);
	for (k = 0; k < 8; k++)
		KHX_EQ(hypertrace_vm_release(ids[k], eps[k]), 0);

	/* 2. Once the consumer that registered them closes, the namespace
	 * empties; a VM that gets the ID again starts with no probes (the
	 * same IDs register without EEXIST). */
	cons_close(&c);
	KHX_EQ(ht_nprobes(), base);
	n = NULL;
	for (k = 0; k < 8 && n == NULL; k++) {
		struct fvm *t = fvm_new("reuse-n");

		if (t->vmid == a->vmid)
			n = t;
		else
			ids[k] = t->vmid, eps[k] = t->epoch, free(t, M_TEMP);
	}
	for (int j = 0; j < k - (n != NULL); j++)
		KHX_EQ(hypertrace_vm_release(ids[j], eps[j]), 0);
	KHX_CHECK(n != NULL);	/* the lowest free ID comes back */
	if (n != NULL) {
		KHX_CHECK(n->epoch != a->epoch);
		KHX_EQ(cons_open(&c), 0);
		d[0] = vdesc(1, "greuse", "m", "f", "a");
		d[1] = vdesc(2, "greuse", "m", "f", "b");
		KHX_EQ(vprobe_create(&c, n, d, 2), 0);
		cons_close(&c);
		fvm_free(n);
	}
	free(a, M_TEMP);

	/* 3. A failed batch (a duplicate ID) rolls back completely: nothing
	 * is left in the namespace and the same IDs register afterwards. */
	b = fvm_new("reuse-b");
	KHX_EQ(cons_open(&c), 0);
	d[0] = vdesc(5, "greuse", "m", "f", "x");
	d[1] = vdesc(5, "greuse", "m", "f", "y");
	KHX_EQ(vprobe_create(&c, b, d, 2), EEXIST);
	KHX_EQ(ht_nprobes(), base);
	d[1] = vdesc(6, "greuse", "m", "f", "y");
	KHX_EQ(vprobe_create(&c, b, d, 2), 0);
	KHX_EQ(ht_nprobes(), base + 2);

	/* 4. Reinitialization with probes present (vm_reinit(): reserve the
	 * new identity first, then release the old one): the new identity
	 * has a different ID with an empty namespace; the old ID's probes
	 * stay tied to the retired lifetime, which can neither fire nor
	 * register, and the old ID is not reused while they exist. */
	KHX_EQ(hypertrace_vm_alloc(&id2, &ep2), 0);
	KHX_CHECK(id2 != b->vmid);
	KHX_EQ(hypertrace_vm_release(b->vmid, b->epoch), 0);
	{
		hypertrace_args_t ga = gargs(1, 2, 3);
		uint16_t oldid = b->vmid;

		/* The retired lifetime can no longer register probes. */
		d[0] = vdesc(7, "greuse", "m", "f", "z");
		KHX_EQ(vprobe_create(&c, b, d, 1), ESTALE);
		/* The VM now reports its new identity (vmm_getns() and
		 * vmm_getepoch() read the live VM): its namespace is empty,
		 * so the old IDs do not resolve, and new ones register. */
		b->vmid = id2;
		b->epoch = ep2;
		KHX_EQ(hypertrace_probe(&b->hdl, 6, &ga), ESRCH);
		d[0] = vdesc(5, "greuse", "m", "f", "x");
		KHX_EQ(vprobe_create(&c, b, d, 1), 0);
		KHX_EQ(hypertrace_probe(&b->hdl, 5, &ga), 0);
		b->vmid = oldid;
	}
	for (k = 0; k < 8; k++) {
		KHX_EQ(hypertrace_vm_alloc(&ids[k], &eps[k]), 0);
		KHX_CHECK(ids[k] != b->vmid);
	}
	for (k = 0; k < 8; k++)
		KHX_EQ(hypertrace_vm_release(ids[k], eps[k]), 0);
	cons_close(&c);
	KHX_EQ(ht_nprobes(), base);
	KHX_EQ(hypertrace_vm_release(id2, ep2), 0);
	free(b, M_TEMP);	/* its identity was released above */
}

/*
 * DOF from consumers that do not link (lockstat, plockstat: their exact
 * ENABLE DOF, captured by coverage-kernel.py) and a program of literal
 * casts compiled without linking, through dtrace_dof_slurp() and the DIF
 * validator.  libdtrace turns every DIF_OP_TYPECAST annotation into a NOP,
 * so no captured DOF carries one.  The kernel accepts a DOF exactly when it
 * carries none of the link-time opcodes (USETX, ULOAD, UULOAD, TYPECAST);
 * a DIF_OP_TYPECAST that reaches the kernel is refused.
 */
static int
dof_unlinked_ops(const dof_hdr_t *dof, int *typecasts)
{
	int n = 0;

	*typecasts = 0;
	for (uint32_t i = 0; i < dof->dofh_secnum; i++) {
		const dof_sec_t *sec = (const dof_sec_t *)((const char *)dof +
		    dof->dofh_secoff + i * dof->dofh_secsize);
		const dif_instr_t *ins;

		if (sec->dofs_type != DOF_SECT_DIF)
			continue;
		ins = (const dif_instr_t *)((const char *)dof +
		    sec->dofs_offset);
		for (size_t j = 0; j < sec->dofs_size / sizeof(*ins); j++) {
			uint_t op = DIF_INSTR_OP(ins[j]);

			if (op == DIF_OP_TYPECAST)
				(*typecasts)++;
			n += op == DIF_OP_USETX || op == DIF_OP_ULOAD ||
			    op == DIF_OP_UULOAD || op == DIF_OP_TYPECAST;
		}
	}
	return (n);
}

static int tool_dof_refused;	/* captured DOFs with link-time opcodes */

static void
case_tool_dofs(void)
{
	struct cons c;
	int matched, n;

	khx_host_case("tool-dofs");
	tool_dof_refused = 0;
	for (n = 0; n < 12; n++) {
		char name[32];
		dof_hdr_t *dof;
		int tc, unlinked, rv;

		snprintf(name, sizeof(name), "tool_%d", n);
		dof = dof_load(name);
		unlinked = dof_unlinked_ops(dof, &tc);
		KHX_EQ(tc, 0);		/* the libdtrace TYPECAST rewrite */
		KHX_EQ(cons_open(&c), 0);
		rv = cons_enable_vm(&c, dof, 0, 0, &matched);
		KHX_EQ(rv, unlinked == 0 ? 0 : EINVAL);
		if (unlinked != 0) {
			tool_dof_refused++;
			khx_host_log("  tool_%d: %d link-time opcodes, refused\n",
			    n, unlinked);
		}
		cons_close(&c);
		dof_free(dof);
	}
	/* -1, 1u, sizeof (int), a folded (char)300, and a runtime cast. */
	{
		struct recs rs;

		KHX_EQ(cons_open(&c), 0);
		KHX_EQ(cons_enable(&c, "b_casts", &matched), 0);
		KHX_EQ(matched, 1);
		KHX_EQ(cons_options(&c, dif_opts, nitems(dif_opts)), 0);
		KHX_EQ(cons_go(&c), 0);
		{
			struct thread *prev = khx_set_curthread(root_td);

			fire(p_entry, 0x100000005ULL, 0, 0);
			khx_set_curthread(prev);
		}
		KHX_CHECK(snap_records(&c, 0, &rs) >= 0);
		KHX_EQ(rs.n, 1);
		/* Records take the expression's size: int, unsigned, size_t,
		 * char, int. */
		KHX_EQ(rs.r[0].size[0], sizeof(int));
		KHX_EQ((uint32_t)rs.r[0].val[0], 0xffffffffU);	/* -1 */
		KHX_EQ(rs.r[0].val[1], 1);
		KHX_EQ(rs.r[0].val[2], sizeof(int));
		KHX_EQ(rs.r[0].size[3], 1);
		KHX_EQ(rs.r[0].val[3], (uint8_t)(char)300);	/* 44 */
		KHX_EQ(rs.r[0].val[4], 4);	/* (int)0x100000005 - 1 */
		cons_close(&c);
	}
	/* A crafted DIF_OP_TYPECAST is an invalid opcode for the kernel. */
	{
		static const dif_instr_t tc[] = {
		    DIF_INSTR_FMT(DIF_OP_TYPECAST, 0, 0, 0), DIF_INSTR_RET(0) };
		dof_hdr_t *dof = dof_load("r_craft");

		dif_craft = tc;
		dif_ncraft = nitems(tc);
		dof_craft(dof);
		dif_craft = NULL;
		KHX_EQ(cons_open(&c), 0);
		KHX_EQ(cons_enable_vm(&c, dof, 0, 0, &matched), EINVAL);
		cons_close(&c);
		dof_free(dof);
	}
}
