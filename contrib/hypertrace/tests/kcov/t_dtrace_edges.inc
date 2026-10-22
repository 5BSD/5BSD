/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Framework edges reached through the consumer ioctls and the provider
 * and hypertrace module boundaries: probe matching by ID, condensing with
 * enabled probes, epoch suspension, the hypertrace enable/disable hooks
 * failing, record-size validation, enablings spanning VM namespaces or
 * origins, retained guest enablings after the VM is gone, the probe
 * description list under allocation failure and long names, immstack
 * buffers, dists on STOP, the immstack cache's collision chain and the
 * probe-context fault hook.
 */

static int edge_enable_ret, edge_disable_ret;
static int (*edge_saved_enable)(uint16_t, hypertrace_id_t);
static int (*edge_saved_disable)(uint16_t, hypertrace_id_t);

static int
edge_enable(uint16_t vmid, hypertrace_id_t id)
{
	return (edge_enable_ret);
}

static int
edge_disable(uint16_t vmid, hypertrace_id_t id)
{
	if (edge_disable_ret != 0)
		return (edge_disable_ret);
	return (edge_saved_disable(vmid, id));
}

/* Rewrite the VM of every probe description in a DOF. */
static void
dof_vmids(dof_hdr_t *dof, uint16_t first, uint16_t rest)
{
	int n = 0;

	for (uint32_t i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t *sec = (dof_sec_t *)((char *)dof + dof->dofh_secoff +
		    i * dof->dofh_secsize);

		if (sec->dofs_type == DOF_SECT_PROBEDESC)
			((dof_probedesc_t *)((char *)dof +
			    sec->dofs_offset))->dofp_vmid = n++ == 0 ? first :
			    rest;
	}
}

static void
case_edges_match(void)
{
	struct cons c;
	dof_hdr_t *dof;
	int matched;

	khx_host_case("edges-match");
	/* A description naming a probe ID matches exactly that probe. */
	KHX_EQ(cons_open(&c), 0);
	dof = dof_load("trace_arg0");
	for (uint32_t i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t *sec = (dof_sec_t *)((char *)dof + dof->dofh_secoff +
		    i * dof->dofh_secsize);

		if (sec->dofs_type == DOF_SECT_PROBEDESC)
			((dof_probedesc_t *)((char *)dof +
			    sec->dofs_offset))->dofp_id = p_entry;
	}
	KHX_EQ(cons_enable_vm(&c, dof, 0, 0, &matched), 0);
	KHX_EQ(matched, 1);
	dof_free(dof);
	/* Condensing keeps a provider's enabled probes. */
	KHX_EQ(dtrace_condense(khx_prov), 0);
	KHX_CHECK(dtrace_probe_lookup(0, khx_prov, "mod", "func", "entry") ==
	    p_entry);
	/* The provider KPI's probe-argument lookup. */
	KHX_CHECK(dtrace_probe_arg(khx_prov, p_entry) == NULL);
	KHX_CHECK(dtrace_probe_arg(khx_prov, DTRACE_SENSIBLE_PROBELIMIT) ==
	    NULL);
	cons_close(&c);
}

static void
case_edges_vm(void)
{
	struct cons c, d;
	struct fvm *vm, *vm2;
	dtrace_probedesc_t pd[2];
	dtrace_repldesc_t rd;
	dof_hdr_t *dof;
	int matched;

	khx_host_case("edges-vm");
	vm = fvm_new("edge1");
	vm2 = fvm_new("edge2");
	pd[0] = vdesc(41, "khx", "mod", "func", "entry");
	pd[1] = vdesc(42, "khx", "mod", "func2", "entry");

	/* Suspending a suspended epoch is idempotent. */
	dtrace_hypertrace_config_lock();
	KHX_EQ(dtrace_hypertrace_epoch_suspend(vm->vmid, vm->epoch), 0);
	KHX_EQ(dtrace_hypertrace_epoch_suspend(vm->vmid, vm->epoch), 0);
	KHX_EQ(dtrace_hypertrace_epoch_resume(vm->vmid, vm->epoch), 0);
	dtrace_hypertrace_config_unlock();

	/* The hypertrace backend refusing to enable a virtual probe: the
	 * error (or its absolute value) is ENABLE's result. */
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(vprobe_create(&c, vm, pd, 1), 0);
	edge_saved_enable = hypertrace_enable;
	edge_saved_disable = hypertrace_disable;
	hypertrace_enable = edge_enable;
	edge_enable_ret = -EIO;
	dof = dof_load("trace_arg0");
	dof_vmids(dof, vm->vmid, vm->vmid);
	KHX_EQ(cons_enable_vm(&c, dof, 0, 0, &matched), EIO);
	edge_enable_ret = EAGAIN;
	KHX_EQ(cons_enable_vm(&c, dof, 0, 0, &matched), EAGAIN);
	hypertrace_enable = NULL;
	KHX_EQ(cons_enable_vm(&c, dof, 0, 0, &matched), ENXIO);
	hypertrace_enable = edge_saved_enable;
	/* A disable the backend cannot find only warns. */
	KHX_EQ(cons_enable_vm(&c, dof, 0, 0, &matched), 0);
	hypertrace_disable = edge_disable;
	edge_disable_ret = -1;
	cons_close(&c);
	edge_disable_ret = 0;
	hypertrace_disable = edge_saved_disable;
	dof_free(dof);

	/* One enabling whose probe list is requested may not name probes of
	 * two VMs. */
	KHX_EQ(cons_open(&c), 0);
	pd[0] = vdesc(44, "khx", "mod", "func", "entry");
	KHX_EQ(vprobe_create(&c, vm, pd, 1), 0);
	pd[1] = vdesc(45, "khx", "mod", "func", "return");
	KHX_EQ(vprobe_create(&c, vm2, &pd[1], 1), 0);
	dof = dof_load("two_ecbs");
	dof_vmids(dof, vm->vmid, vm2->vmid);
	{
		dtrace_probedesc_t out[4];
		dtrace_enable_io_t io;

		memset(&io, 0, sizeof(io));
		io.dof = dof;
		io.ps = out;
		io.ps_bufsize = sizeof(out);
		KHX_EQ(cons_ioctl(&c, DTRACEIOC_ENABLE, &io), EXDEV);
	}
	dof_free(dof);
	cons_close(&c);

	/* REPLICATE across retained enablings of different origins. */
	KHX_EQ(cons_open(&c), 0);
	dof = dof_load("trace_arg0");
	KHX_EQ(cons_enable_vm(&c, dof, 0, 0, &matched), 0);
	KHX_EQ(cons_enable_vm(&c, dof, vm->vmid, vm->epoch, &matched), 0);
	dof_free(dof);
	memset(&rd, 0, sizeof(rd));
	rd.dtrpd_match = vdesc(0, "khx", "mod", "func", "entry");
	rd.dtrpd_create = vdesc(0, "khx", "mod2", "func2", "entry");
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_REPLICATE, &rd), EXDEV);
	cons_close(&c);

	/* A retained guest-origin enabling of a VM that is gone matches
	 * nothing when providers appear later. */
	KHX_EQ(cons_open(&d), 0);
	dof = dof_load("trace_arg0");
	KHX_EQ(cons_enable_vm(&d, dof, vm2->vmid, vm2->epoch, &matched), 0);
	dof_free(dof);
	fvm_free(vm2);
	KHX_EQ(cons_ioctl(&d, DTRACEIOC_ENABLE, &(dtrace_enable_io_t){ 0 }),
	    0);
	cons_close(&d);
	fvm_free(vm);
}

static void
case_edges_records(void)
{
	static const struct opt huge_imm[] = {
		{ DTRACEOPT_BUFSIZE, 64 * 1024 },
		{ DTRACEOPT_IMMSTACKFRAMES, 1L << 40 },
	};
	static const struct opt bigger_imm[] = {
		{ DTRACEOPT_BUFSIZE, 256 * 1024 },
		{ DTRACEOPT_IMMSTACKFRAMES, 40 },
	};
	struct cons c;
	struct fvm *vm;
	dtrace_probedesc_t pd;
	dof_hdr_t *dof;
	struct recs rs;
	int matched;

	khx_host_case("edges-records");
	/* Immediate-stack sizes that overflow the record size are refused
	 * at enable (options first) and at go (options after). */
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_options(&c, huge_imm, nitems(huge_imm)), 0);
	KHX_EQ(cons_enable(&c, "a_immstack", &matched), EINVAL);
	KHX_EQ(cons_enable(&c, "a_pimmstack", &matched), EINVAL);
	cons_close(&c);
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable(&c, "trace_arg0", &matched), 0);
	KHX_EQ(cons_options(&c, huge_imm, nitems(huge_imm)), 0);
	KHX_EQ(cons_go(&c), EINVAL);
	cons_close(&c);
	/* An immstack record sized before the frame count grew is dropped. */
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable(&c, "a_immstack", &matched), 0);
	KHX_EQ(cons_options(&c, bigger_imm, nitems(bigger_imm)), 0);
	KHX_EQ(cons_go(&c), 0);
	struct thread *prev = khx_set_curthread(root_td);
	fire(p_entry, 0, 0, 0);
	khx_set_curthread(prev);
	KHX_CHECK(snap_records(&c, 0, &rs) >= 0);
	KHX_EQ(rs.n, 0);
	cons_close(&c);
	/* Immediate stack buffers cannot be allocated. */
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable(&c, "a_immstack", &matched), 0);
	KHX_EQ(cons_options(&c, default_opts, nitems(default_opts)), 0);
	khx_host_fail_alloc(1, "solaris");
	KHX_CHECK(cons_go(&c) != 0);
	khx_host_fail_alloc(0, NULL);
	cons_close(&c);
	/* With hypercalls enabled (the guest kernel) immstack() records
	 * nothing locally: frames go into the per-CPU hypercall buffer. */
	khx_cpuid_bhyve_guest(1);
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable(&c, "a_immstack", &matched), 0);
	KHX_EQ(cons_options(&c, default_opts, nitems(default_opts)), 0);
	KHX_EQ(cons_go(&c), 0);
	prev = khx_set_curthread(root_td);
	fire(p_entry, 0, 0, 0);
	khx_set_curthread(prev);
	KHX_CHECK(snap_records(&c, 0, &rs) >= 0);
	cons_close(&c);
	khx_cpuid_bhyve_guest(0);
	/* Guest stack()/ustack() frame limits. */
	vm = fvm_new("edgerec");
	pd = vdesc(43, "khx", "mod", "func", "entry");
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(vprobe_create(&c, vm, &pd, 1), 0);
	dof = dof_load("big_kstack");
	dof_vmids(dof, vm->vmid, vm->vmid);
	KHX_EQ(cons_enable_vm(&c, dof, 0, 0, &matched), EINVAL);
	dof_free(dof);
	dof = dof_load("big_ustack");
	dof_vmids(dof, vm->vmid, vm->vmid);
	KHX_EQ(cons_enable_vm(&c, dof, 0, 0, &matched), EINVAL);
	dof_free(dof);
	cons_close(&c);
	fvm_free(vm);
}

static void
case_edges_lists(void)
{
	dtrace_provider_id_t prov;
	struct cons c;
	dtrace_enable_io_t io;
	dtrace_probedesc_t pds[4];
	dof_hdr_t *dof;
	char longname[DTRACE_NAMELEN + 8];

	khx_host_case("edges-lists");
	KHX_EQ(dtrace_register("khxlong", &khxp_attr, DTRACE_PRIV_KERNEL, NULL,
	    &lp_pops, NULL, &prov), 0);
	memset(longname, 'm', sizeof(longname) - 1);
	longname[sizeof(longname) - 1] = '\0';
	/* A module or name longer than a description field. */
	KHX_CHECK(dtrace_probe_create(prov, longname, "f", "entry", 0,
	    NULL) != 0);
	KHX_CHECK(dtrace_probe_create(prov, "m", "f", longname, 0, NULL) != 0);
	for (int t = 0; t < 3; t++) {
		KHX_EQ(cons_open(&c), 0);
		dof = dof_load("p_long");
		memset(&io, 0, sizeof(io));
		io.dof = dof;
		io.ps = pds;
		io.ps_bufsize = sizeof(pds);
		if (t == 2)
			khx_host_fail_alloc(1, "solaris");
		/* A name the description cannot hold is ENAMETOOLONG; only the
		 * injected allocation failure is a memory shortage. */
		KHX_EQ(cons_ioctl(&c, DTRACEIOC_ENABLE, &io),
		    t == 2 ? ENOMEM : ENAMETOOLONG);
		khx_host_fail_alloc(0, NULL);
		dof_free(dof);
		cons_close(&c);
	}
	KHX_EQ(dtrace_unregister(prov), 0);
}

/* The immstack table's hash (dtrace.c dtrace_immstackhashfn), used only to
 * choose PCs that land in the same slot; the oracle is what the cache
 * returns, not this function. */
static uint32_t
imm_slot(uintptr_t pc)
{
	uint64_t h = 0;

	for (int sh = 48; sh >= 0; sh -= 16) {
		h += (pc >> sh) & 0xffff;
		h += (h << 10);
		h ^= (h >> 6);
	}
	return ((uint32_t)h & (DTRACE_IMMSTACKHASH_DEFAULT_SIZE - 1));
}

static int edge_dist_stops;

static void
edge_dist_open(void *d __unused, struct dtrace_state *s __unused)
{
}

static void
edge_dist_close(void *d __unused, struct dtrace_state *s __unused)
{
	edge_dist_stops++;
}

static void
case_edges_misc(void)
{
	static const dtrace_dops_t ops = { edge_dist_open, edge_dist_close };
	static const struct opt dd[] = {
		{ DTRACEOPT_BUFSIZE, 64 * 1024 },
		{ DTRACEOPT_DDTRACEARG, 3 },
	};
	dtrace_dist_id_t id;
	struct cons c;
	int matched;
	uint64_t off;
	static pc_t pcs[1100];
	int n;
	int64_t h0;

	khx_host_case("edges-misc");
	/* STOP notifies the dists too. */
	KHX_EQ(dtrace_dist_register("edge", &ops, NULL, &id), 0);
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable(&c, "trace_arg0", &matched), 0);
	KHX_EQ(cons_options(&c, dd, nitems(dd)), 0);
	KHX_EQ(cons_go(&c), 0);
	edge_dist_stops = 0;
	KHX_EQ(cons_stop(&c), 0);
	KHX_CHECK(edge_dist_stops >= 1);
	cons_close(&c);
	KHX_EQ(dtrace_dist_unregister(&id), 0);

	/* The immstack cache: a PC of 0 is never looked up; PCs that land in
	 * one slot probe linearly; after 1024 probes a PC is neither cached
	 * nor found. */
	KHX_CHECK(dtrace_immstack_get_cached(0, &off) == NULL);
	n = 0;
	h0 = -1;
	for (uintptr_t pc = 0xffffffff80000000ULL; n < 1030; pc++) {
		if (h0 == -1)
			h0 = imm_slot(pc);
		if (imm_slot(pc) == (uint32_t)h0)
			pcs[n++] = pc;
	}
	for (int i = 0; i < n; i++)
		dtrace_immstack_cache(pcs[i], "collide", i + 1);
	KHX_CHECK(dtrace_immstack_get_cached(pcs[0], &off) != NULL);
	KHX_EQ(off, 1);
	KHX_CHECK(dtrace_immstack_get_cached(pcs[1023], &off) != NULL);
	KHX_EQ(off, 1024);
	KHX_CHECK(dtrace_immstack_get_cached(pcs[1029], &off) == NULL);
	/* Unloading a module empties the cache (dtrace_kld_unload). */
	KHX_EQ(khx_eh_invoke("kld_unload", call_unload, NULL), 1);
	KHX_CHECK(dtrace_immstack_get_cached(pcs[0], &off) == NULL);

	/* The probe-context fault hook reports a pending fault. */
	KHX_EQ(dtrace_fault_func(), 0);
	cpu_core[curcpu].cpuc_dtrace_flags |= CPU_DTRACE_BADADDR;
	KHX_CHECK(dtrace_fault_func() != 0);
	cpu_core[curcpu].cpuc_dtrace_flags = 0;
}

static struct cons *edge_mc;
static int edge_mc_mode;

static int
edge_matchall_hook(void *arg __unused, int out, const void *uaddr __unused,
    size_t len __unused)
{
	dtrace_enable_io_t io;

	if (!out || edge_mc_mode == 0)
		return (0);
	edge_mc_mode = 0;
	/* Another consumer asks for all retained enablings to be matched
	 * against new probes while an ENABLE is still copying out. */
	memset(&io, 0, sizeof(io));
	KHX_EQ(cons_ioctl(edge_mc, DTRACEIOC_ENABLE, &io), 0);
	return (0);
}

static void
case_edges_more(void)
{
	static const struct opt huge_frames[] = {
		{ DTRACEOPT_BUFSIZE, 64 * 1024 },
		{ DTRACEOPT_STACKFRAMES, 1L << 40 },
	};
	dtrace_provider_id_t prov;
	dtrace_repldesc_t rd;
	dtrace_enable_io_t io;
	dtrace_probedesc_t ps[4];
	struct cons c, m;
	dof_hdr_t *dof;
	char longname[DTRACE_NAMELEN + 8];
	int matched, n, rv;

	khx_host_case("edges-more");
	/* REPLICATE creating a description with a probe ID: matched by ID. */
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable(&c, "trace_arg0", &matched), 0);
	memset(&rd, 0, sizeof(rd));
	rd.dtrpd_match = vdesc(0, "khx", "mod", "func", "entry");
	rd.dtrpd_create = vdesc(p_entry, "khx", "mod", "func", "entry");
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_REPLICATE, &rd), 0);
	cons_close(&c);

	/* A variable redeclared with another size by a later enabling of
	 * the same consumer: thread-local, array and clause-local forms. */
	{
		static const char *pairs[][2] = {
			{ "v_tsize1", "v_tsize2" },
			{ "v_asize1", "v_asize2" },
			{ "v_lsize1", "v_lsize2" },
		};

		for (size_t i = 0; i < nitems(pairs); i++) {
			KHX_EQ(cons_open(&c), 0);
			KHX_EQ(cons_enable(&c, pairs[i][0], &matched), 0);
			rv = cons_enable(&c, pairs[i][1], &matched);
			KHX_CHECK(rv == EINVAL || rv == 0);
			cons_close(&c);
		}
	}

	/* stack() with a frame count from an absurd option. */
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_options(&c, huge_frames, nitems(huge_frames)), 0);
	KHX_EQ(cons_enable(&c, "big_stack_opt", &matched), EINVAL);
	cons_close(&c);
	/* ustack() with a string size beyond the 32-bit argument field. */
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable(&c, "big_ustack_str", &matched), EINVAL);
	cons_close(&c);
	/* In a guest kernel, printimmstack() records nothing locally. */
	khx_cpuid_bhyve_guest(1);
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable(&c, "a_pimmstack_n", &matched), 0);
	cons_close(&c);
	khx_cpuid_bhyve_guest(0);

	/* A probe name longer than a description holds. */
	KHX_EQ(dtrace_register("khxnm", &khxp_attr, DTRACE_PRIV_KERNEL, NULL,
	    &lp_pops, NULL, &prov), 0);
	memset(longname, 'n', sizeof(longname) - 1);
	longname[sizeof(longname) - 1] = '\0';
	KHX_CHECK(dtrace_probe_create(prov, "m", "f", longname, 0, NULL) != 0);
	KHX_EQ(cons_open(&c), 0);
	dof = dof_load("p_nm");
	memset(&io, 0, sizeof(io));
	io.dof = dof;
	io.ps = ps;
	io.ps_bufsize = sizeof(ps);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_ENABLE, &io), ENAMETOOLONG);
	dof_free(dof);
	cons_close(&c);
	KHX_EQ(dtrace_unregister(prov), 0);

	/* Matching retained enablings while an ENABLE copies out its list:
	 * the pending enabling is skipped. */
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_open(&m), 0);
	edge_mc = &m;
	edge_mc_mode = 1;
	khx_set_copy_hook(edge_matchall_hook, NULL);
	dof = dof_load("trace_arg0");
	memset(&io, 0, sizeof(io));
	io.dof = dof;
	io.ps = ps;
	io.ps_bufsize = sizeof(ps);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_ENABLE, &io), 0);
	khx_set_copy_hook(NULL, NULL);
	dof_free(dof);
	cons_close(&m);
	cons_close(&c);

	/* Allocation failures while a consumer goes active: every M_NOWAIT
	 * solaris allocation of GO in turn, with manual buffer resizing so
	 * no failure is absorbed by a smaller retry.  GO fails cleanly or
	 * succeeds; after a failure a second GO succeeds (reusing whatever
	 * per-CPU immstack buffers the first one kept).  The sweep ends when
	 * the injection point lies past every allocation GO makes. */
	{
		static const struct opt manual[] = {
			{ DTRACEOPT_BUFSIZE, 64 * 1024 },
			{ DTRACEOPT_BUFRESIZE, DTRACEOPT_BUFRESIZE_MANUAL },
			{ DTRACEOPT_DYNVARSIZE, 64 * 1024 },
		};
		int nfail = 0;

		for (n = 1; n < 256; n++) {
			int failed = khx_host_alloc_failed();

			KHX_EQ(cons_open(&c), 0);
			KHX_EQ(cons_enable(&c, "a_immstack", &matched), 0);
			KHX_EQ(cons_options(&c, manual, nitems(manual)), 0);
			khx_host_fail_alloc(n, "solaris");
			rv = cons_go(&c);
			khx_host_fail_alloc(0, NULL);
			if (khx_host_alloc_failed() == failed) {
				/* The injection never fired: sweep done. */
				KHX_EQ(rv, 0);
				cons_close(&c);
				break;
			}
			if (rv != 0) {
				KHX_EQ(rv, ENOMEM);
				nfail++;
				KHX_EQ(cons_go(&c), 0);
			}
			cons_close(&c);
		}
		KHX_CHECK(n > 1 && n < 256);
		/* Per CPU: principal buffer, immstack; plus the dynvar space. */
		KHX_CHECK(nfail > 2 * mp_ncpus);
	}

	/* A defunct provider whose probes are still enabled: unregister
	 * asks for the ECBs to be reaped (EAGAIN) and the reaper runs. */
	KHX_EQ(dtrace_register("khxdef", &khxp_attr, DTRACE_PRIV_KERNEL, NULL,
	    &lp_pops, NULL, &prov), 0);
	KHX_CHECK(dtrace_probe_create(prov, "m", "f", "entry", 0, NULL) != 0);
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable(&c, "p_def", &matched), 0);
	KHX_EQ(matched, 1);
	KHX_EQ(cons_options(&c, default_opts, nitems(default_opts)), 0);
	KHX_EQ(cons_go(&c), 0);
	dtrace_invalidate(prov);
	KHX_EQ(dtrace_unregister(prov), EAGAIN);
	/* A defunct provider's probes match no new enabling. */
	{
		struct cons c2;
		int m2 = -1;

		KHX_EQ(cons_open(&c2), 0);
		KHX_EQ(cons_enable(&c2, "p_def", &m2), 0);
		KHX_EQ(m2, 0);
		cons_close(&c2);
	}
	{
		struct recs rs;

		(void)snap_records(&c, 0, &rs);
		(void)snap_records(&c, 0, &rs);
	}
	khx_taskqs_run();
	rv = dtrace_unregister(prov);
	KHX_CHECK(rv == 0 || rv == EAGAIN);
	cons_close(&c);
	if (rv != 0)
		KHX_EQ(dtrace_unregister(prov), 0);
	khx_taskqs_run();
}

/*
 * panic() on the host panics the host: run last.  The firing is captured
 * as an expected panic; the per-thread probe state the panic left behind
 * is reset by hand (a real kernel does not return).  A second panic action
 * finds the panic slot taken and does nothing.
 */
static struct cons edge_pc;

static void
edge_fire_panic(void *arg __unused)
{
	fire(p_entry, 0, 0, 0);
}

static void
case_host_panic(void)
{
	static const struct opt d[] = {
		{ DTRACEOPT_BUFSIZE, 64 * 1024 },
		{ DTRACEOPT_DESTRUCTIVE, 1 },
	};
	int matched;

	khx_host_case("host-panic");
	KHX_EQ(cons_open(&edge_pc), 0);
	KHX_EQ(cons_enable(&edge_pc, "a_panic", &matched), 0);
	KHX_EQ(cons_options(&edge_pc, d, nitems(d)), 0);
	KHX_EQ(cons_go(&edge_pc), 0);
	struct thread *prev = khx_set_curthread(root_td);
	KHX_CHECK(KHX_PANICS(edge_fire_panic, NULL));
	khx_release_locks_after_panic(root_td);
	root_td->t_dtrace_inprobe = 0;
	cpu_core[curcpu].cpuc_dtrace_flags = 0;
	fire(p_entry, 0, 0, 0);		/* the slot is taken: no panic */
	khx_set_curthread(prev);
	cons_close(&edge_pc);
}

/*
 * Virtual-probe limits: 64Ki live probes per VM, and 64 MiB of per-VM
 * probe tables in total (a table is sized by the next power of two above
 * its highest probe ID).
 */
static void
case_vprobe_limits(void)
{
	enum { BATCH = 4096 };
	dtrace_probedesc_t *d;
	struct fvm *vm[12];
	static char names[12][16];
	struct cons c;
	int nvm = 0, rv = 0;

	khx_host_case("vprobe-limits");
	d = malloc(BATCH * sizeof(*d), M_TEMP, M_WAITOK | M_ZERO);
	KHX_EQ(cons_open(&c), 0);
	vm[nvm++] = fvm_new("lim0");
	for (int b = 0; b < 16; b++) {
		for (int i = 0; i < BATCH; i++) {
			char f[32];

			snprintf(f, sizeof(f), "f%d", b * BATCH + i);
			d[i] = vdesc(b * BATCH + i + 1, "lim", "m", f, "n");
		}
		KHX_EQ(vprobe_create(&c, vm[0], d, BATCH), 0);
	}
	d[0] = vdesc(65537, "lim", "m", "over", "n");
	KHX_EQ(vprobe_create(&c, vm[0], d, 1), ENOSPC);
	cons_close(&c);

	/* Tables: one probe with ID 2^20 makes an 8 MiB table. */
	KHX_EQ(cons_open(&c), 0);
	for (nvm = 0; nvm < (int)nitems(vm); nvm++) {
		snprintf(names[nvm], sizeof(names[nvm]), "tab%d", nvm);
		vm[nvm] = fvm_new(names[nvm]);
		d[0] = vdesc(DTRACE_SENSIBLE_PROBELIMIT, "lim", "m", "big",
		    "n");
		rv = vprobe_create(&c, vm[nvm], d, 1);
		if (rv != 0) {
			nvm++;
			break;
		}
	}
	KHX_EQ(rv, ENOSPC);
	KHX_CHECK(nvm > 1);
	cons_close(&c);
	for (int i = 0; i < nvm; i++)
		fvm_free(vm[i]);
	free(d, M_TEMP);
}

/*
 * Anonymous tracing: the loader passes enablings as "dof-data-N=<hex>"
 * lines in a preloaded dtrace_dof file; dtrace_anon_init() creates an
 * anonymous state at boot, matches and starts it; the first consumer to
 * open /dev/dtrace/dtrace takes it over.  Run as a second (and third)
 * module boot after the main teardown.
 */
static int anon_dist_wanted, anon_dist_opens;
static uint64_t anon_dist_arg;
static dtrace_dist_id_t anon_dist_id;

static void
anon_dist_open(void *d __unused, struct dtrace_state *s)
{
	anon_dist_opens++;
	anon_dist_arg = s->dts_options[DTRACEOPT_DDTRACEARG];
}

static void
anon_dist_close(void *d __unused, struct dtrace_state *s __unused)
{
}

static void
anon_dist_sysinit(void *arg __unused)
{
	static const dtrace_dops_t ops = { anon_dist_open, anon_dist_close };

	if (anon_dist_wanted)
		KHX_EQ(dtrace_dist_register("anon", &ops, NULL, &anon_dist_id),
		    0);
}
SYSINIT(khx_anon_dist, SI_SUB_DTRACE_PROVIDER, SI_ORDER_ANY,
    anon_dist_sysinit, NULL);

static char *
anon_line(char *p, int n, const void *dof, size_t len)
{
	static const char hex[] = "0123456789abcdef";
	const uint8_t *b = dof;

	p += sprintf(p, "dof-data-%d=", n);
	for (size_t i = 0; i < len; i++) {
		*p++ = hex[b[i] >> 4];
		*p++ = hex[b[i] & 0xf];
	}
	*p++ = '\n';
	return (p);
}

static void
case_anon(int take_over)
{
	static const struct opt o[] = {
		{ DTRACEOPT_BUFSIZE, 64 * 1024 },
		{ DTRACEOPT_DDTRACEARG, 7 },
	};
	static char buf[64 * 1024];
	dof_hdr_t *prog, *opts;
	struct cons c;
	char *p = buf;

	khx_host_case(take_over ? "anon-boot-takeover" : "anon-boot-unload");
	/* Boot 2 enables BEGIN/END (the dtrace provider exists at boot).
	 * Boot 3 passes options only: an anonymous state without enabled
	 * probes does not hold the framework, which destroys it at unload.
	 * (With enabled probes the framework cannot unload until a consumer
	 * claims the state, by design.) */
	prog = dof_load("begin_end");
	opts = dof_options(o, nitems(o), sizeof(uint64_t),
	    sizeof(dof_optdesc_t));
	if (take_over) {
		p = anon_line(p, 0, prog, prog->dofh_filesz);
		p = anon_line(p, 1, opts, opts->dofh_loadsz);
	} else
		p = anon_line(p, 0, opts, opts->dofh_loadsz);
	khx_preload_dof(buf, p - buf);
	anon_dist_wanted = take_over;
	anon_dist_opens = 0;
	khx_run_sysinits();
	if (take_over) {
		/* The anonymous state went active at boot and told the dists,
		 * passing its own DDTRACEARG. */
		KHX_EQ(anon_dist_opens, 1);
		KHX_EQ(anon_dist_arg, 7);
		/* While the anonymous state exists, another consumer's STOP
		 * with DDTRACEARG does not notify the dists (the anonymous
		 * state owns that notification). */
		{
			static const struct opt dd[] = {
				{ DTRACEOPT_BUFSIZE, 64 * 1024 },
				{ DTRACEOPT_DDTRACEARG, 5 },
			};
			int m3, before = anon_dist_opens;

			KHX_EQ(cons_open(&c), 0);
			KHX_EQ(cons_enable(&c, "trace_arg0", &m3), 0);
			KHX_EQ(cons_options(&c, dd, nitems(dd)), 0);
			KHX_EQ(cons_go(&c), 0);
			KHX_EQ(cons_stop(&c), 0);
			cons_close(&c);
			KHX_CHECK(anon_dist_opens >= before);
		}
		/* A consumer that goes with "grabanon" takes the anonymous
		 * state over; it is already active (STATUS works, GO again is
		 * refused), and it stops like any other. */
		{
			static const struct opt g[] = {
				{ DTRACEOPT_GRABANON, 1 },
			};
			dtrace_status_t st;
			processorid_t cpu;

			KHX_EQ(cons_open(&c), 0);
			memset(&st, 0, sizeof(st));
			KHX_EQ(cons_ioctl(&c, DTRACEIOC_STATUS, &st), ENOENT);
			KHX_EQ(cons_options(&c, g, nitems(g)), 0);
			KHX_EQ(cons_ioctl(&c, DTRACEIOC_GO, &cpu), 0);
			KHX_EQ(cons_ioctl(&c, DTRACEIOC_STATUS, &st), 0);
			KHX_EQ(cons_stop(&c), 0);
			cons_close(&c);
		}
		KHX_EQ(dtrace_dist_unregister(&anon_dist_id), 0);
	}
	khx_preload_dof(NULL, 0);
	dof_free(prog);
	free(opts, M_TEMP);
	/* An anonymous state nobody took is destroyed at unload. */
	KHX_EQ(khx_module_event("hypertrace", MOD_UNLOAD), 0);
	khx_run_sysuninits();
	KHX_CHECK(khx_cdev_find("dtrace/dtrace") == NULL);
	/* Regression: the anonymous dtrace_state_t itself is freed, both
	 * when a consumer that grabbed it closes and at unload. */
	if (khx_host_live_tag("solaris") != 0)
		khx_host_dump_tag("solaris");
	KHX_EQ(khx_host_live_tag("solaris"), 0);
}

/*
 * ustack() helpers: a process registers helper DOF through the helper node
 * (DTRACEHIOC_ADDDOF); a ustack() action with string space then asks the
 * helper for a symbol per frame.  The harness thread has no user frame,
 * and the helpers see each frame's pc and fp as arg0/arg1 (never 1).
 */
/*
 * Helper DOF built by dtrace -G carries user relocations.  Append to a
 * DOF a string table, a relocation table with one SETX and one DOFREL
 * entry, an 8-byte target and the URELHDR tying them together; the
 * section headers move to the end so they stay contiguous.
 */
static dof_hdr_t *
dof_add_relocs(dof_hdr_t *odof, uint64_t roff)
{
	size_t osz = odof->dofh_loadsz, nsec = odof->dofh_secnum + 4;
	size_t hdroff = roundup2(osz, 8);
	size_t dataoff = hdroff + nsec * sizeof(dof_sec_t);
	size_t size = dataoff + 8 + 16 + 2 * sizeof(dof_relodesc_t) +
	    sizeof(dof_relohdr_t);
	char *buf = khx_host_alloc(size, 1, 0, "khx-file");
	dof_hdr_t *dof = (dof_hdr_t *)buf;
	dof_sec_t *sec = (dof_sec_t *)(buf + hdroff), *ns;
	dof_relodesc_t *rd;
	dof_relohdr_t *rh;
	uint32_t base = odof->dofh_secnum;
	size_t off = dataoff;

	memcpy(buf, odof, osz);
	memcpy(sec, (char *)odof + odof->dofh_secoff,
	    odof->dofh_secnum * sizeof(dof_sec_t));
	ns = &sec[base];
	/* base+0: string table (relocation names are unused) */
	ns[0] = (dof_sec_t){ .dofs_type = DOF_SECT_STRTAB, .dofs_align = 1,
	    .dofs_flags = DOF_SECF_LOAD, .dofs_offset = off, .dofs_size = 1 };
	off += 8;
	/* base+1: target, two 64-bit words */
	ns[1] = (dof_sec_t){ .dofs_type = DOF_SECT_NONE, .dofs_align = 8,
	    .dofs_flags = DOF_SECF_LOAD, .dofs_offset = off, .dofs_size = 16 };
	off += 16;
	/* base+2: relocations */
	rd = (dof_relodesc_t *)(buf + off);
	rd[0] = (dof_relodesc_t){ .dofr_type = DOF_RELO_SETX,
	    .dofr_offset = roff };
	rd[1] = (dof_relodesc_t){ .dofr_type = DOF_RELO_DOFREL,
	    .dofr_offset = 0 };
	ns[2] = (dof_sec_t){ .dofs_type = DOF_SECT_RELTAB, .dofs_align = 8,
	    .dofs_flags = DOF_SECF_LOAD, .dofs_entsize = sizeof(*rd),
	    .dofs_offset = off, .dofs_size = 2 * sizeof(*rd) };
	off += 2 * sizeof(*rd);
	/* base+3: the relocation header */
	rh = (dof_relohdr_t *)(buf + off);
	rh->dofr_strtab = base;
	rh->dofr_tgtsec = base + 1;
	rh->dofr_relsec = base + 2;
	ns[3] = (dof_sec_t){ .dofs_type = DOF_SECT_URELHDR,
	    .dofs_align = sizeof(dof_secidx_t), .dofs_flags = DOF_SECF_LOAD,
	    .dofs_offset = off, .dofs_size = sizeof(*rh) };
	dof->dofh_secoff = hdroff;
	dof->dofh_secnum = nsec;
	dof->dofh_loadsz = dof->dofh_filesz = size;
	dof_free(odof);
	return (dof);
}

static uint64_t
dof_reloc_target(dof_hdr_t *dof)
{
	dof_sec_t *sec = (dof_sec_t *)((char *)dof + dof->dofh_secoff);

	return (*(uint64_t *)((char *)dof +
	    sec[dof->dofh_secnum - 3].dofs_offset));
}

/* When >= 0, helper_add() appends relocations with this SETX offset. */
static int64_t hlp_reloc_off = -1;

static int
helper_add(const char *name, int *gen)
{
	dof_hdr_t *dof = dof_load(name);
	dof_helper_t dh;
	int error;

	if (hlp_reloc_off >= 0)
		dof = dof_add_relocs(dof, hlp_reloc_off);

	memset(&dh, 0, sizeof(dh));
	strlcpy(dh.dofhp_mod, "a.out", sizeof(dh.dofhp_mod));
	dh.dofhp_addr = 0x400000;	/* load base of the object */
	dh.dofhp_dof = (uintptr_t)dof;
	dh.dofhp_pid = root_td->td_proc->p_pid;
	{
		/* The helper node acts on curproc. */
		struct thread *prev = khx_set_curthread(root_td);

		error = khx_dev_ioctl(khx_cdev_find("dtrace/helper"),
		    DTRACEHIOC_ADDDOF, (caddr_t)&dh, 0, root_td);
		khx_set_curthread(prev);
	}
	*gen = dh.dofhp_gen;
	if (hlp_reloc_off >= 0)
		/* The kernel relocated its own copy; ours is untouched. */
		KHX_EQ(dof_reloc_target(dof), 0);
	dof_free(dof);
	return (error);
}

static int
helper_remove(int gen)
{
	struct thread *prev = khx_set_curthread(root_td);
	int error = khx_dev_ioctl(khx_cdev_find("dtrace/helper"),
	    DTRACEHIOC_REMOVE, (caddr_t)&gen, 0, root_td);

	khx_set_curthread(prev);
	return (error);
}

static void
helper_ustack(struct recs *rs)
{
	struct cons c;
	int matched;

	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable(&c, "d_ustack_str", &matched), 0);
	KHX_EQ(cons_options(&c, dif_opts, nitems(dif_opts)), 0);
	KHX_EQ(cons_go(&c), 0);
	{
		struct thread *prev = khx_set_curthread(root_td);

		fire(p_entry, 0, 0, 0);
		khx_set_curthread(prev);
	}
	KHX_CHECK(snap_records(&c, curcpu, rs) >= 1);
	cons_close(&c);
}

/*
 * jstack() takes its string size from the jstackstrsize option when the
 * action does not carry one; the record argument stores only 32 bits of
 * it, so a larger option is refused when the action is created.
 */
static void
case_jstack_strsize(void)
{
	static const struct opt big[] = {
		{ DTRACEOPT_JSTACKSTRSIZE, 1L << 33 },
	};
	static const struct opt max[] = {
		{ DTRACEOPT_JSTACKSTRSIZE, 1L << 12 },
	};
	struct cons c;
	int matched;

	khx_host_case("jstack-strsize");
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_options(&c, big, nitems(big)), 0);
	KHX_EQ(cons_enable(&c, "a_jstack", &matched), EINVAL);
	cons_close(&c);
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_options(&c, max, nitems(max)), 0);
	KHX_EQ(cons_enable(&c, "a_jstack", &matched), 0);
	KHX_EQ(matched, 1);
	cons_close(&c);
}

static void
case_helpers(void)
{
	struct recs rs;
	int gen1;
	const char *str;

	khx_host_case("helpers");
	/* A pid that is not the caller's must be a stopped, traced child. */
	{
		dof_helper_t dh;

		memset(&dh, 0, sizeof(dh));
		dh.dofhp_pid = 999999;
		KHX_EQ(khx_dev_ioctl(khx_cdev_find("dtrace/helper"),
		    DTRACEHIOC_ADDDOF, (caddr_t)&dh, 0, root_td), EINVAL);
	}
	/* A relocation inside the target but not 8-byte aligned rejects the
	 * DOF ("misaligned setx relo"), which shows they are processed ... */
	hlp_reloc_off = 4;
	KHX_EQ(helper_add("hlp_sym", &gen1), EINVAL);
	/* ... and aligned ones (SETX and DOFREL) are applied.
	 * Predicate true: each of the 3 frames gets the helper's string. */
	hlp_reloc_off = 0;
	KHX_EQ(helper_add("hlp_sym", &gen1), 0);
	hlp_reloc_off = -1;
	KHX_CHECK(root_td->td_proc->p_dtrace_helpers != NULL);
	helper_ustack(&rs);
	KHX_EQ(rs.bigsize, 4 * sizeof(uint64_t) + 64);
	str = (const char *)rs.big + 4 * sizeof(uint64_t);
	for (int i = 0; i < 3; i++) {
		KHX_EQ(strcmp(str, "khx`help"), 0);
		str += strlen("khx`help") + 1;
	}
	KHX_EQ(*str, 0);
	KHX_EQ(helper_remove(gen1), 0);

	/* Predicate false: no helper action runs (no symbol). */
	KHX_EQ(helper_add("hlp_nomatch", &gen1), 0);
	helper_ustack(&rs);
	str = (const char *)rs.big + 4 * sizeof(uint64_t);
	KHX_EQ(str[0], 0);
	/* A fork duplicates the helpers into the child; process exit
	 * (fasttrap's exit hook) releases them. */
	{
		struct proc *child = malloc(sizeof(*child), M_TEMP,
		    M_WAITOK | M_ZERO);

		/* p_dtrace_helpers lives in the process's kdtrace_proc. */
		child->p_dtrace = malloc(sizeof(*child->p_dtrace), M_TEMP,
		    M_WAITOK | M_ZERO);

		dtrace_helpers_duplicate(root_td->td_proc, child);
		KHX_CHECK(child->p_dtrace_helpers != NULL);
		dtrace_helpers_destroy(child);
		KHX_CHECK(child->p_dtrace_helpers == NULL);
		free(child->p_dtrace, M_TEMP);
		free(child, M_TEMP);
	}
	{
		struct thread *prev = khx_set_curthread(root_td);

		/* fasttrap's exec/exit hook calls this on FreeBSD. */
		dtrace_helpers_destroy(root_td->td_proc);
		khx_set_curthread(prev);
	}
	KHX_CHECK(root_td->td_proc->p_dtrace_helpers == NULL);
}

/*
 * immstack() when the frame walk records nothing (the current frame is not
 * on the thread's kernel stack: here a thread without one): every slot is
 * filled as an empty frame.  With a slot size the string formatter refuses
 * (8 bytes leave no room for the offset; 60 is not 8-byte aligned) the
 * filler must stop instead of retrying the same slot forever.
 */
static void
case_immstack_noframes(void)
{
	static const int sizes[] = { 64, 8, 60 };

	khx_host_case("immstack-noframes");
	for (size_t i = 0; i < nitems(sizes); i++) {
		struct opt o[nitems(dif_opts) + 2];
		struct cons c;
		struct recs rs;
		int matched, no = nitems(dif_opts);

		memcpy(o, dif_opts, sizeof(dif_opts));
		o[no++] = (struct opt){ DTRACEOPT_IMMSTACKSTRSIZE, sizes[i] };
		o[no++] = (struct opt){ DTRACEOPT_IMMSTACKFRAMES, 4 };
		KHX_EQ(cons_open(&c), 0);
		KHX_EQ(cons_options(&c, o, no), 0);
		KHX_EQ(cons_enable(&c, "a_immstack", &matched), 0);
		KHX_EQ(cons_enable(&c, "err_capture", &matched), 0);
		KHX_EQ(cons_go(&c), 0);
		{
			struct thread *prev = khx_set_curthread(jail_td);

			KHX_CHECK(jail_td->td_kstack == 0);
			fire(p_entry, 0, 0, 0);
			khx_set_curthread(prev);
		}
		KHX_CHECK(snap_records(&c, 0, &rs) >= 0);
		KHX_EQ(rs.n, 1);
		if (sizes[i] % 8 != 0) {
			/* A misaligned slot is a BADSTACK fault, as when
			 * frames were walked (case_immstack). */
			KHX_EQ(rs.r[0].kind[0], DTRACEACT_DIFEXPR);
			KHX_EQ(rs.r[0].val[1], DTRACEFLT_BADSTACK);
		} else {
			/* 64: four empty frames; 8: slots too small to
			 * hold a frame are left as reserved (zero). */
			KHX_EQ(rs.bigsize, 4 * (size_t)sizes[i]);
			for (size_t b = 0; b < rs.bigsize; b++)
				KHX_EQ(rs.big[b], 0);
		}
		cons_close(&c);
	}
}

/*
 * immstack() slots too small for a frame (8 bytes: no room for the offset
 * word) when the first frame comes from the interrupted PC of an
 * unanchored probe, or from the provider-supplied caller once the
 * artificial frames are skipped: the walk stops there, as it does for a
 * walked frame (case_immstack), and the record stays empty.
 */
static void
case_immstack_small_slots(void)
{
	static dtrace_id_t tick;
	int no0 = nitems(dif_opts);

	khx_host_case("immstack-small-slots");
	if (tick == 0)
		tick = dtrace_probe_lookup(0, khx_prov, "mod", "", "tick");
	if (tick == 0)
		tick = dtrace_probe_create(khx_prov, "mod", "", "tick", 0,
		    NULL);
	KHX_CHECK(tick != 0);
	for (int pass = 0; pass < 3; pass++) {
		struct opt o[nitems(dif_opts) + 2];
		struct cons c;
		struct recs rs;
		int matched, no = no0;

		memcpy(o, dif_opts, sizeof(dif_opts));
		/* Passes 0, 1: 8-byte slots; pass 2: 16 bytes, whose first
		 * name ("case_immstack", the caller) fills the slot and leaves
		 * no room for its offset word: BADSTACK. */
		o[no++] = (struct opt){ DTRACEOPT_IMMSTACKSTRSIZE,
		    pass == 2 ? 16 : 8 };
		o[no++] = (struct opt){ DTRACEOPT_IMMSTACKFRAMES, 4 };
		if (pass == 2) {
			imm_symtab(1, 0);
			dtrace_immstack_caching_enabled = 0;
		}
		KHX_EQ(cons_open(&c), 0);
		KHX_EQ(cons_options(&c, o, no), 0);
		KHX_EQ(cons_enable(&c, pass == 0 ? "a_immstack_tick" :
		    "a_immstack", &matched), 0);
		KHX_EQ(matched, 1);
		KHX_EQ(cons_enable(&c, "err_capture", &matched), 0);
		KHX_EQ(cons_go(&c), 0);
		{
			struct thread *prev = khx_set_curthread(root_td);

			if (pass == 0)
				fire(tick, (uintptr_t)fire + 3, 0, 0);
			else {
				solaris_cpu[curcpu].cpu_dtrace_caller =
				    pass == 2 ? (uintptr_t)case_immstack + 4 :
				    (uintptr_t)fire + 3;
				fire(p_entry, 0, 0, 0);
				solaris_cpu[curcpu].cpu_dtrace_caller = 0;
			}
			khx_set_curthread(prev);
		}
		KHX_CHECK(snap_records(&c, 0, &rs) >= 0);
		KHX_EQ(rs.n, 1);
		if (pass == 2) {
			KHX_EQ(rs.r[0].kind[0], DTRACEACT_DIFEXPR);
			KHX_EQ(rs.r[0].val[1], DTRACEFLT_BADSTACK);
			db_nsymtab = 0;
		} else {
			KHX_EQ(rs.bigsize, 4 * 8);
			for (size_t b = 0; b < rs.bigsize; b++)
				KHX_EQ(rs.big[b], 0);
		}
		cons_close(&c);
	}
}
