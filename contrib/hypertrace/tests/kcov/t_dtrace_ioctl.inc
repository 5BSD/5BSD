/* SPDX-License-Identifier: BSD-2-Clause */
/* dtrace_ioctl.c cases: every dtrace(4) command and its error contract. */

static int
cons_ready(struct cons *c, const char *prog, const struct opt *extra, int n)
{
	int matched = 0, error;

	KHX_EQ(cons_open(c), 0);
	error = cons_enable(c, prog, &matched);
	if (error != 0)
		return (error);
	KHX_EQ(cons_options(c, default_opts, nitems(default_opts)), 0);
	if (n > 0)
		KHX_EQ(cons_options(c, extra, n), 0);
	return (matched);
}

static void
case_ioctl_enable(void)
{
	struct cons c, c2;
	dtrace_enable_io_t io;
	dtrace_probedesc_t ps[4];
	dof_hdr_t *dof, bad;
	int matched;

	khx_host_case("ioctl-enable");
	KHX_EQ(cons_open(&c), 0);
	/* A NULL DOF re-evaluates retained enablings. */
	memset(&io, 0, sizeof(io));
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_ENABLE, &io), 0);
	/* Unreadable or malformed DOF. */
	io.dof = &bad;
	khx_host_user_fault_range(&bad, sizeof(bad));
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_ENABLE, &io), EINVAL);
	khx_host_user_fault_clear();
	memset(&bad, 0, sizeof(bad));
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_ENABLE, &io), EINVAL);
	/* An origin VM must name its live lifetime. */
	dof = dof_load("trace_arg0");
	KHX_EQ(cons_enable_vm(&c, dof, 3, 1, NULL), ESTALE);
	{
		void *saved = hypertrace_check_epoch;

		hypertrace_check_epoch = NULL;
		KHX_EQ(cons_enable_vm(&c, dof, 3, 1, NULL), ENOTSUP);
		hypertrace_check_epoch = saved;
	}
	/* Matched probes are reported when the caller supplies room. */
	memset(&io, 0, sizeof(io));
	io.dof = dof_load("glob_entry");
	io.ps = ps;
	io.ps_bufsize = sizeof(ps);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_ENABLE, &io), 0);
	KHX_EQ(io.n_matched, 2);
	KHX_EQ(io.n_desc, 2);
	KHX_CHECK(strcmp(ps[0].dtpd_name, "entry") == 0);
	KHX_CHECK(ps[0].dtpd_id == p_entry || ps[1].dtpd_id == p_entry);
	/* Too little room: E2BIG, and the enabling is rolled back. */
	io.ps_bufsize = sizeof(ps[0]);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_ENABLE, &io), E2BIG);
	KHX_EQ(io.n_matched, 0);
	io.ps_bufsize = -1;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_ENABLE, &io), E2BIG);
	/* The probe list cannot be written back: EFAULT, rolled back. */
	io.ps_bufsize = sizeof(ps);
	khx_host_user_fault_range(ps, sizeof(ps));
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_ENABLE, &io), EFAULT);
	khx_host_user_fault_clear();
	KHX_EQ(io.n_matched, 0);
	dof_free(io.dof);
	/* Options are validated with the enabling. */
	{
		struct opt badopt[] = { { DTRACEOPT_MAX, 1 } };
		dof_hdr_t *o = dof_options(badopt, 1, 8, sizeof(dof_optdesc_t));

		KHX_EQ(cons_enable_vm(&c, o, 0, 0, NULL), EINVAL);
		free(o, M_TEMP);
		o = dof_options(default_opts, 1, 4, sizeof(dof_optdesc_t));
		KHX_EQ(cons_enable_vm(&c, o, 0, 0, NULL), EINVAL);
		free(o, M_TEMP);
		o = dof_options(default_opts, 1, 8, 0);
		KHX_EQ(cons_enable_vm(&c, o, 0, 0, NULL), EINVAL);
		free(o, M_TEMP);
		o = dof_options(default_opts, 1, 8, 4);
		KHX_EQ(cons_enable_vm(&c, o, 0, 0, NULL), EINVAL);
		free(o, M_TEMP);
		badopt[0] = (struct opt){ DTRACEOPT_BUFSIZE, DTRACEOPT_UNSET };
		o = dof_options(badopt, 1, 8, sizeof(dof_optdesc_t));
		KHX_EQ(cons_enable_vm(&c, o, 0, 0, NULL), EINVAL);
		free(o, M_TEMP);
		o = dof_options(default_opts, 1, 8, sizeof(dof_optdesc_t));
		((dof_optdesc_t *)((dof_sec_t *)(o + 1) + 1))->dofo_strtab = 0;
		KHX_EQ(cons_enable_vm(&c, o, 0, 0, NULL), EINVAL);
		free(o, M_TEMP);
	}
	/* Nothing matched is not an error. */
	KHX_EQ(cons_enable(&c, "nomatch", &matched), 0);
	KHX_EQ(matched, 0);
	/* After GO, ENABLE is refused; AUGMENT is the only way to add. */
	KHX_EQ(cons_options(&c, default_opts, nitems(default_opts)), 0);
	KHX_EQ(cons_go(&c), 0);
	KHX_EQ(cons_enable_vm(&c, dof, 0, 0, NULL), EBUSY);
	memset(&io, 0, sizeof(io));
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_AUGMENT, &io), EINVAL);
	io.dof = &bad;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_AUGMENT, &io), EINVAL);
	io.dof = dof;
	io.vmid = 3;
	io.epoch = 1;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_AUGMENT, &io), ESTALE);
	io.vmid = 0;
	io.epoch = 0;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_AUGMENT, &io), 0);
	KHX_EQ(io.n_matched, 1);
	{
		struct recs rs;

		fire(p_entry, 5, 6, 7);
		/* Both the original and the augmented ECB fired. */
		KHX_EQ(snap_records(&c, 0, &rs), 2);
	}
	KHX_EQ(cons_stop(&c), 0);
	io.dof = dof;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_AUGMENT, &io), ESHUTDOWN);
	cons_close(&c);
	/* AUGMENT before GO is also refused. */
	KHX_EQ(cons_open(&c2), 0);
	memset(&io, 0, sizeof(io));
	io.dof = dof;
	KHX_EQ(cons_ioctl(&c2, DTRACEIOC_AUGMENT, &io), ESHUTDOWN);
	cons_close(&c2);
	dof_free(dof);
}

static void
case_ioctl_queries(void)
{
	struct cons c;
	dtrace_probedesc_t pd;
	dtrace_argdesc_t ad;
	dtrace_fmtdesc_t fd;
	dtrace_status_t st;
	dtrace_repldesc_t rd;
	char fmt[64];
	int matched;

	khx_host_case("ioctl-queries");
	matched = cons_ready(&c, "printf_fmt", NULL, 0);
	KHX_EQ(matched, 1);
	/* Before GO there is no status. */
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_STATUS, &st), ENOENT);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_DRAINABLE, NULL), EBUSY);
	/* Formats: IDs start at one; short buffers learn the length. */
	memset(&fd, 0, sizeof(fd));
	fd.dtfd_format = 0;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_FORMAT, &fd), EINVAL);
	fd.dtfd_format = 99;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_FORMAT, &fd), EINVAL);
	fd.dtfd_format = 1;
	fd.dtfd_length = 1;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_FORMAT, &fd), 0);
	{
		int need = fd.dtfd_length;

		fd.dtfd_string = fmt;
		fd.dtfd_length = sizeof(fmt);
		KHX_EQ(cons_ioctl(&c, DTRACEIOC_FORMAT, &fd), 0);
		/* The compiler canonicalizes conversions; the kernel returns
		 * exactly the stored string and its length. */
		KHX_EQ(need, (int)strlen(fmt) + 1);
		KHX_CHECK(strncmp(fmt, "v=%", 3) == 0);
		KHX_CHECK(strstr(fmt, " s=%s") != NULL);
	}
	khx_host_user_fault_range(fmt, 1);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_FORMAT, &fd), EINVAL);
	khx_host_user_fault_clear();
	/* Probe arguments. */
	memset(&ad, 0, sizeof(ad));
	ad.dtargd_id = DTRACE_IDNONE;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_PROBEARG, &ad), EINVAL);
	ad.dtargd_id = p_entry;
	ad.dtargd_ndx = DTRACE_ARGNONE;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_PROBEARG, &ad), EINVAL);
	ad.dtargd_ndx = 0;
	ad.dtargd_id = 1000000;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_PROBEARG, &ad), EINVAL);
	ad.dtargd_id = p_entry;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_PROBEARG, &ad), 0);
	KHX_CHECK(strcmp(ad.dtargd_native, "uint64_t") == 0);
	ad.dtargd_ndx = 5;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_PROBEARG, &ad), 0);
	KHX_EQ(ad.dtargd_ndx, DTRACE_ARGNONE);
	/* The dtrace provider has no argument descriptions. */
	ad.dtargd_id = 1;
	ad.dtargd_ndx = 0;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_PROBEARG, &ad), 0);
	KHX_EQ(ad.dtargd_ndx, DTRACE_ARGNONE);
	/* A hole in the probe table. */
	{
		dtrace_id_t gap = p_other + 1;

		ad.dtargd_id = gap;
		ad.dtargd_ndx = 0;
		(void)cons_ioctl(&c, DTRACEIOC_PROBEARG, &ad);
	}
	/* Probe queries that find nothing. */
	memset(&pd, 0, sizeof(pd));
	strlcpy(pd.dtpd_provider, "nope", sizeof(pd.dtpd_provider));
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_PROBEMATCH, &pd), ESRCH);
	memset(&pd, 0, sizeof(pd));
	pd.dtpd_id = 1000000;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_PROBES, &pd), ESRCH);
	/* Replication of enablings onto a newly provided probe. */
	memset(&rd, 0, sizeof(rd));
	strlcpy(rd.dtrpd_match.dtpd_provider, "khx",
	    sizeof(rd.dtrpd_match.dtpd_provider));
	strlcpy(rd.dtrpd_create.dtpd_provider, "khx",
	    sizeof(rd.dtrpd_create.dtpd_provider));
	strlcpy(rd.dtrpd_create.dtpd_name, "entry",
	    sizeof(rd.dtrpd_create.dtpd_name));
	/* Only exact descriptions of retained enablings are replicated. */
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_REPLICATE, &rd), ENOENT);
	strlcpy(rd.dtrpd_match.dtpd_mod, "mod", sizeof(rd.dtrpd_match.dtpd_mod));
	strlcpy(rd.dtrpd_match.dtpd_func, "func",
	    sizeof(rd.dtrpd_match.dtpd_func));
	strlcpy(rd.dtrpd_match.dtpd_name, "entry",
	    sizeof(rd.dtrpd_match.dtpd_name));
	strlcpy(rd.dtrpd_create.dtpd_mod, "mod2",
	    sizeof(rd.dtrpd_create.dtpd_mod));
	strlcpy(rd.dtrpd_create.dtpd_func, "func2",
	    sizeof(rd.dtrpd_create.dtpd_func));
	/* Unknown commands. */
	KHX_EQ(cons_ioctl(&c, _IO('x', 99), NULL), ENOTTY);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_FILTER, fmt), ENOTTY);
	/* GO; status and drainability while active. */
	KHX_EQ(cons_go(&c), 0);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_STATUS, &st), 0);
	KHX_EQ(st.dtst_exiting, 0);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_DRAINABLE, NULL), 0);
	KHX_EQ(cons_go(&c), EBUSY);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_REPLICATE, &rd), 0);
	KHX_EQ(cons_stop(&c), 0);
	KHX_EQ(cons_stop(&c), EINVAL);	/* not active any more */
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_STATUS, &st), 0);
	cons_close(&c);

	/* Speculation makes a consumer non-drainable. */
	matched = cons_ready(&c, "spec", NULL, 0);
	KHX_EQ(matched, 2);
	KHX_EQ(cons_go(&c), 0);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_DRAINABLE, NULL), EOPNOTSUPP);
	cons_close(&c);
}

static void
case_ioctl_buffers(void)
{
	struct cons c;
	dtrace_bufdesc_t d;
	struct recs rs;
	static const struct opt ring[] = {
		{ DTRACEOPT_BUFPOLICY, DTRACEOPT_BUFPOLICY_RING },
		{ DTRACEOPT_BUFSIZE, 4096 },
	};
	static const struct opt fill[] = {
		{ DTRACEOPT_BUFPOLICY, DTRACEOPT_BUFPOLICY_FILL },
		{ DTRACEOPT_BUFSIZE, 4096 },
	};

	khx_host_case("ioctl-buffers");
	/* Switch buffers: absent CPUs and faults. */
	KHX_EQ(cons_ready(&c, "trace_arg0", NULL, 0), 1);
	KHX_EQ(cons_snap(&c, DTRACEIOC_BUFSNAP, 0, &d), ENOENT);	/* no GO */
	KHX_EQ(cons_go(&c), 0);
	KHX_EQ(cons_snap(&c, DTRACEIOC_BUFSNAP, KHX_NCPU, &d), ENOENT);
	KHX_EQ(cons_snap(&c, DTRACEIOC_BUFSNAP, MAXCPU + 5, &d), ENOENT);
	fire(p_entry, 1, 0, 0);
	khx_host_user_fault_range(snapbuf, 1);
	KHX_EQ(cons_snap(&c, DTRACEIOC_BUFSNAP, 0, &d), EFAULT);
	khx_host_user_fault_clear();
	{
		dtrace_bufdesc_t *bad = NULL;

		khx_host_user_fault_range(&d, sizeof(d));
		bad = &d;
		KHX_EQ(cons_ioctl(&c, DTRACEIOC_BUFSNAP, &bad), EFAULT);
		khx_host_user_fault_clear();
	}
	/* Records on another CPU stay there. */
	khx_set_curcpu(2);
	fire(p_entry, 22, 0, 0);
	khx_set_curcpu(0);
	KHX_EQ(snap_records(&c, 2, &rs), 1);
	KHX_EQ(rs.r[0].val[0], 22);
	KHX_EQ(snap_records(&c, 0, &rs), 0);
	cons_close(&c);

	/* Ring buffers: snapshots only after STOP, wrap order preserved. */
	KHX_EQ(cons_ready(&c, "trace_arg0", ring, nitems(ring)), 1);
	KHX_EQ(cons_go(&c), 0);
	for (int i = 0; i < 1000; i++)
		fire(p_entry, i, 0, 0);
	KHX_EQ(cons_snap(&c, DTRACEIOC_BUFSNAP, 0, &d), EBUSY);
	KHX_EQ(cons_stop(&c), 0);
	KHX_EQ(cons_snap(&c, DTRACEIOC_BUFSNAP, 0, &d), 0);
	KHX_EQ(d.dtbd_size, 4096);
	KHX_CHECK(d.dtbd_oldest < d.dtbd_size);
	/* Consumed: a second snapshot reports nothing. */
	KHX_EQ(cons_snap(&c, DTRACEIOC_BUFSNAP, 0, &d), 0);
	KHX_EQ(d.dtbd_size, 0);
	cons_close(&c);

	/* Fill buffers stop accepting when full and count drops. */
	KHX_EQ(cons_ready(&c, "trace_arg0", fill, nitems(fill)), 1);
	KHX_EQ(cons_go(&c), 0);
	for (int i = 0; i < 1000; i++)
		fire(p_entry, i, 0, 0);
	KHX_EQ(cons_stop(&c), 0);
	khx_host_user_fault_range(snapbuf, 1);
	KHX_EQ(cons_snap(&c, DTRACEIOC_BUFSNAP, 0, &d), EFAULT);
	khx_host_user_fault_clear();
	/* A fill buffer keeps exactly the records that fit, in order:
	 * each is a 12-byte header plus an 8-byte value, 8-byte aligned. */
	KHX_EQ(cons_eprobe(&c, 1)->dtepd_size, 24);
	KHX_EQ(snap_records(&c, 0, &rs), 4096 / 24);
	KHX_EQ(rs.r[0].val[0], 0);
	KHX_EQ(rs.r[1].val[0], 1);
	cons_close(&c);
}

static void
case_ioctl_aggs(void)
{
	struct cons c;
	dtrace_bufdesc_t d;
	char buf[2048];
	dtrace_aggdesc_t *ad = (dtrace_aggdesc_t *)buf;
	dof_hdr_t hdr, *dofp;

	khx_host_case("ioctl-aggregations");
	KHX_EQ(cons_ready(&c, "agg_multi", NULL, 0), 1);
	KHX_EQ(cons_go(&c), 0);
	for (int i = 0; i < 10; i++)
		fire(p_entry, i * 3, i & 1, 0);
	KHX_EQ(cons_snap(&c, DTRACEIOC_AGGSNAP, 0, &d), 0);
	KHX_CHECK(d.dtbd_size > 0);
	/* Aggregation descriptions: unknown IDs, then each real one. */
	memset(buf, 0, sizeof(buf));
	ad->dtagd_id = 999;
	{
		dtrace_aggdesc_t *p = ad;

		KHX_EQ(cons_ioctl(&c, DTRACEIOC_AGGDESC, &p), EINVAL);
		for (int id = 1; id <= 4; id++) {
			memset(buf, 0, sizeof(buf));
			ad->dtagd_id = id;
			ad->dtagd_nrecs = 16;
			KHX_EQ(cons_ioctl(&c, DTRACEIOC_AGGDESC, &p), 0);
			KHX_CHECK(ad->dtagd_nrecs >= 1);
			KHX_CHECK(ad->dtagd_size > 0);
		}
		/* A short record budget truncates the copy. */
		memset(buf, 0, sizeof(buf));
		ad->dtagd_id = 4;
		ad->dtagd_nrecs = 1;
		KHX_EQ(cons_ioctl(&c, DTRACEIOC_AGGDESC, &p), 0);
		khx_host_user_fault_range(buf, sizeof(buf));
		KHX_EQ(cons_ioctl(&c, DTRACEIOC_AGGDESC, &p), EFAULT);
		khx_host_user_fault_clear();
	}
	/* The kernel's view of the program as DOF. */
	memset(&hdr, 0, sizeof(hdr));
	hdr.dofh_loadsz = sizeof(hdr);
	dofp = &hdr;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_DOFGET, &dofp), 0);
	KHX_EQ(memcmp(hdr.dofh_ident, DOF_MAG_STRING, DOF_MAG_STRLEN), 0);
	khx_host_user_fault_range(&hdr, sizeof(hdr));
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_DOFGET, &dofp), EFAULT);
	khx_host_user_fault_clear();
	/* EPROBE on an unknown EPID, and a faulting descriptor. */
	{
		dtrace_eprobedesc_t ep, *p = &ep;

		memset(&ep, 0, sizeof(ep));
		ep.dtepd_epid = 999;
		KHX_EQ(cons_ioctl(&c, DTRACEIOC_EPROBE, &p), EINVAL);
		khx_host_user_fault_range(&ep, sizeof(ep));
		KHX_EQ(cons_ioctl(&c, DTRACEIOC_EPROBE, &p), EFAULT);
		khx_host_user_fault_clear();
	}
	cons_close(&c);
}

static void
case_ioctl_misc(void)
{
	struct cons c;
	struct khx_file *fp;
	int gen = 0;

	khx_host_case("ioctl-misc");
	/* dtrace_ioctl() without consumer state is unreachable: every file
	 * that reaches it was opened by dtrace_open(), which installs the
	 * cdevpriv.  (The upstream code would read an uninitialized pointer
	 * there, since devfs_get_cdevpriv() leaves it unset on failure.) */
	(void)fp;
	/* The helper node: unknown commands, and removal of a generation. */
	KHX_EQ(khx_dev_ioctl(khx_cdev_find("dtrace/helper"), _IO('z', 9), NULL,
	    0, root_td), ENOTTY);
	gen = 12345;
	KHX_EQ(khx_dev_ioctl(khx_cdev_find("dtrace/helper"), DTRACEHIOC_REMOVE,
	    (caddr_t)&gen, 0, root_td), EINVAL);
	/* VPROBE_CREATE without the HyperTrace provider. */
	KHX_EQ(cons_open(&c), 0);
	{
		dtrace_probedesc_t d = vdesc(1, "p", "m", "f", "n");
		void *saved = hypertrace_create_probes;
		dtrace_vprobe_io_t io = { &d, 1, 1, 1 };

		hypertrace_create_probes = NULL;
		KHX_EQ(cons_ioctl(&c, DTRACEIOC_VPROBE_CREATE, &io), ENOTSUP);
		hypertrace_create_probes = saved;
	}
	/* Verbose ioctl logging. */
	{
		struct sysctl_oid *oid = khx_sysctl_find("dtrace", "verbose_ioctl");
		int one = 1, zero = 0;
		dtrace_conf_t conf;

		KHX_CHECK(oid != NULL);
		if (oid != NULL) {
			KHX_EQ(khx_sysctl_call(oid, root_td, NULL, NULL, &one,
			    sizeof(one)), 0);
			khx_printf_reset();
			KHX_EQ(cons_ioctl(&c, DTRACEIOC_CONF, &conf), 0);
			KHX_CHECK(khx_printf_seen("DTRACEIOC_CONF"));
			KHX_EQ(khx_sysctl_call(oid, root_td, NULL, NULL, &zero,
			    sizeof(zero)), 0);
		}
	}
	cons_close(&c);
}

/* Copies that fail at the second (or nth) user access. */
static void
case_ioctl_copy_faults(void)
{
	struct cons c;
	dtrace_bufdesc_t d;
	char buf[2048];
	dtrace_aggdesc_t *ad = (dtrace_aggdesc_t *)buf, *pad = ad;
	dtrace_eprobedesc_t ep, *pep = &ep;
	dof_hdr_t hdr, *dofp = &hdr;
	static const struct opt ring[] = {
		{ DTRACEOPT_BUFPOLICY, DTRACEOPT_BUFPOLICY_RING },
		{ DTRACEOPT_BUFSIZE, 4096 },
	};

	khx_host_case("ioctl-copy-faults");
	KHX_EQ(cons_ready(&c, "agg_args", NULL, 0), 1);
	KHX_EQ(cons_go(&c), 0);
	for (int i = 0; i < 20; i++)
		fire(p_entry, i * 7, i + 1, 0);
	/* Aggregations with an argument record: zero-size records are not
	 * described to the consumer. */
	for (int id = 1; id <= 3; id++) {
		memset(buf, 0, sizeof(buf));
		ad->dtagd_id = id;
		ad->dtagd_nrecs = 16;
		KHX_EQ(cons_ioctl(&c, DTRACEIOC_AGGDESC, &pad), 0);
		for (int r = 0; r < ad->dtagd_nrecs; r++)
			KHX_CHECK(ad->dtagd_rec[r].dtrd_size != 0);
	}
	memset(buf, 0, sizeof(buf));
	ad->dtagd_id = 1;
	ad->dtagd_nrecs = 16;
	khx_host_fail_copy(2);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_AGGDESC, &pad), EFAULT);
	/* EPROBE on an aggregating ECB lists no aggregation records; a short
	 * record budget truncates, and a failed copyout is reported. */
	memset(&ep, 0, sizeof(ep));
	ep.dtepd_epid = 1;
	ep.dtepd_nrecs = 0;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_EPROBE, &pep), 0);
	ep.dtepd_epid = 1;
	khx_host_fail_copy(2);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_EPROBE, &pep), EFAULT);
	/* Switched snapshot: descriptor copyout failure. */
	khx_host_fail_copy(3);
	KHX_EQ(cons_snap(&c, DTRACEIOC_BUFSNAP, 0, &d), EFAULT);
	/* DOFGET copyout failure. */
	memset(&hdr, 0, sizeof(hdr));
	hdr.dofh_loadsz = sizeof(hdr);
	khx_host_fail_copy(2);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_DOFGET, &dofp), EFAULT);
	cons_close(&c);

	/* Ring buffers: descriptor copyout failures for both the consumed
	 * and the live snapshot. */
	KHX_EQ(cons_ready(&c, "trace_arg0", ring, nitems(ring)), 1);
	KHX_EQ(cons_go(&c), 0);
	fire(p_entry, 1, 0, 0);
	KHX_EQ(cons_stop(&c), 0);
	khx_host_fail_copy(3);
	KHX_EQ(cons_snap(&c, DTRACEIOC_BUFSNAP, 0, &d), EFAULT);
	KHX_EQ(cons_snap(&c, DTRACEIOC_BUFSNAP, 0, &d), 0);
	khx_host_fail_copy(2);
	KHX_EQ(cons_snap(&c, DTRACEIOC_BUFSNAP, 0, &d), EFAULT);
	cons_close(&c);
}

/* An exit() action drains the consumer; status reports it. */
static void
case_ioctl_status(void)
{
	struct cons c;
	dtrace_status_t st;
	static const struct opt fill[] = {
		{ DTRACEOPT_BUFPOLICY, DTRACEOPT_BUFPOLICY_FILL },
		{ DTRACEOPT_BUFSIZE, 4096 },
	};

	khx_host_case("ioctl-status");
	KHX_EQ(cons_ready(&c, "exit_end", NULL, 0), 2);
	KHX_EQ(cons_go(&c), 0);
	fire(p_entry, 3, 0, 0);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_STATUS, &st), 0);
	KHX_EQ(st.dtst_exiting, 1);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_DRAINABLE, NULL), EBUSY);
	KHX_EQ(cons_stop(&c), 0);
	cons_close(&c);
	/* A full fill buffer is counted. */
	KHX_EQ(cons_ready(&c, "trace_arg0", fill, nitems(fill)), 1);
	KHX_EQ(cons_go(&c), 0);
	for (int i = 0; i < 400; i++)
		fire(p_entry, i, 0, 0);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_STATUS, &st), 0);
	KHX_EQ(st.dtst_filled, 1);
	cons_close(&c);
}

/* Malformed DOF that passes the header checks is rejected by slurp. */
static void
case_ioctl_bad_dof(void)
{
	struct cons c;
	dof_hdr_t *dof;
	dtrace_enable_io_t io;

	khx_host_case("ioctl-bad-dof");
	KHX_EQ(cons_open(&c), 0);
	dof = dof_load("trace_arg0");
	/* Point the ECB description at a nonexistent probe section. */
	for (uint32_t i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t *sec = (dof_sec_t *)((char *)dof + dof->dofh_secoff +
		    i * dof->dofh_secsize);

		if (sec->dofs_type == DOF_SECT_ECBDESC)
			((dof_ecbdesc_t *)((char *)dof +
			    sec->dofs_offset))->dofe_probes = 999;
	}
	KHX_EQ(cons_enable_vm(&c, dof, 0, 0, NULL), EINVAL);
	KHX_EQ(cons_options(&c, default_opts, nitems(default_opts)), 0);
	{
		dof_hdr_t *good = dof_load("trace_arg0");

		KHX_EQ(cons_enable_vm(&c, good, 0, 0, NULL), 0);
		dof_free(good);
	}
	KHX_EQ(cons_go(&c), 0);
	memset(&io, 0, sizeof(io));
	io.dof = dof;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_AUGMENT, &io), EINVAL);
	dof_free(dof);
	/* Glob syntax errors in probe matching. */
	{
		dtrace_probedesc_t pd;

		memset(&pd, 0, sizeof(pd));
		strlcpy(pd.dtpd_provider, "khx[", sizeof(pd.dtpd_provider));
		(void)cons_ioctl(&c, DTRACEIOC_PROBEMATCH, &pd);
	}
	/* VPROBE_CREATE with a count but no descriptions. */
	{
		dtrace_vprobe_io_t vio = { NULL, 1, 1, 1 };

		KHX_EQ(cons_ioctl(&c, DTRACEIOC_VPROBE_CREATE, &vio), EINVAL);
	}
	/*
	 * VM identifiers index the per-VM probe tables (HYPERTRACE_MAX_VMS
	 * entries) but arrive as 16-bit values from the caller: a probe query
	 * or a DOF probe description naming VM 1024 or above is invalid and
	 * must be refused before any table is indexed.
	 */
	{
		static const uint16_t bad[] = { HYPERTRACE_MAX_VMS, 0xffff };
		dtrace_probedesc_t pd;
		int matched;

		cons_close(&c);
		KHX_EQ(cons_open(&c), 0);

		for (size_t i = 0; i < nitems(bad); i++) {
			memset(&pd, 0, sizeof(pd));
			pd.dtpd_vmid = bad[i];
			KHX_EQ(cons_ioctl(&c, DTRACEIOC_PROBES, &pd), EINVAL);
			memset(&pd, 0, sizeof(pd));
			pd.dtpd_vmid = bad[i];
			strlcpy(pd.dtpd_name, "entry", sizeof(pd.dtpd_name));
			KHX_EQ(cons_ioctl(&c, DTRACEIOC_PROBEMATCH, &pd),
			    EINVAL);
			dof = dof_load("trace_arg0");
			dof_set_vmid(dof, bad[i]);
			KHX_EQ(cons_enable_vm(&c, dof, 0, 0, &matched), EINVAL);
			dof_free(dof);
		}
		/* The largest valid identifier is accepted (nothing there). */
		memset(&pd, 0, sizeof(pd));
		pd.dtpd_vmid = HYPERTRACE_MAX_VMS - 1;
		KHX_EQ(cons_ioctl(&c, DTRACEIOC_PROBES, &pd), ESRCH);
		dof = dof_load("trace_arg0");
		dof_set_vmid(dof, HYPERTRACE_MAX_VMS - 1);
		KHX_EQ(cons_enable_vm(&c, dof, 0, 0, &matched), 0);
		KHX_EQ(matched, 0);
		dof_free(dof);
	}
	cons_close(&c);
}

/* Guest-origin programs: the origin VM's lifetime gates enabling, the
 * late re-check after the probe-list copyout, and firing. */
static struct cons *reenter_cons;
static struct fvm *reenter_vm;
static int reenter_mode, reenter_error, reenter_repl;

static int
enable_copy_hook(void *arg __unused, int out, const void *uaddr __unused,
    size_t len __unused)
{
	dtrace_enable_io_t io;
	dtrace_repldesc_t rd;
	dof_hdr_t *dof;

	if (!out || reenter_mode == 0)
		return (0);
	switch (reenter_mode) {
	case 1:		/* concurrent ENABLE and REPLICATE on the same state */
		reenter_mode = 0;
		dof = dof_load("trace_arg0");
		memset(&io, 0, sizeof(io));
		io.dof = dof;
		reenter_error = cons_ioctl(reenter_cons, DTRACEIOC_ENABLE, &io);
		memset(&rd, 0, sizeof(rd));
		reenter_repl = cons_ioctl(reenter_cons, DTRACEIOC_REPLICATE, &rd);
		dof_free(dof);
		break;
	case 2:		/* the origin VM is retired while the list copies out */
		reenter_mode = 0;
		KHX_EQ(hypertrace_vm_release(reenter_vm->vmid,
		    reenter_vm->epoch), 0);
		break;
	case 3:
		reenter_mode = 0;
		{
			void *saved = hypertrace_check_epoch;

			hypertrace_check_epoch = NULL;
			reenter_vm->name = saved;	/* restored by caller */
		}
		break;
	}
	return (0);
}

static void
case_ioctl_guest_origin(void)
{
	struct cons c;
	struct fvm *vm;
	dtrace_enable_io_t io;
	dtrace_probedesc_t ps[4];
	dof_hdr_t *dof;
	struct recs rs;

	khx_host_case("ioctl-guest-origin");
	KHX_EQ(cons_open(&c), 0);
	vm = fvm_new("origin");
	dof = dof_load("trace_arg0");
	/* Concurrent requests during the copyout window are refused. */
	reenter_cons = &c;
	reenter_mode = 1;
	khx_set_copy_hook(enable_copy_hook, NULL);
	memset(&io, 0, sizeof(io));
	io.dof = dof;
	io.ps = ps;
	io.ps_bufsize = sizeof(ps);
	io.vmid = vm->vmid;
	io.epoch = vm->epoch;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_ENABLE, &io), 0);
	KHX_EQ(reenter_error, EBUSY);
	KHX_EQ(reenter_repl, EBUSY);
	KHX_EQ(io.n_matched, 1);
	/* The guest-origin ECB fires only while its origin lifetime is
	 * active. */
	KHX_EQ(cons_options(&c, default_opts, nitems(default_opts)), 0);
	KHX_EQ(cons_go(&c), 0);
	fire(p_entry, 77, 0, 0);
	dtrace_hypertrace_config_lock();
	KHX_EQ(dtrace_hypertrace_epoch_suspend(vm->vmid, vm->epoch), 0);
	dtrace_hypertrace_config_unlock();
	fire(p_entry, 78, 0, 0);		/* suppressed */
	dtrace_hypertrace_config_lock();
	KHX_EQ(dtrace_hypertrace_epoch_resume(vm->vmid, vm->epoch), 0);
	dtrace_hypertrace_config_unlock();
	fire(p_entry, 79, 0, 0);
	KHX_EQ(snap_records(&c, 0, &rs), 2);
	KHX_EQ(rs.r[0].val[0], 77);
	KHX_EQ(rs.r[1].val[0], 79);
	/* Guest-origin AUGMENT. */
	memset(&io, 0, sizeof(io));
	io.dof = dof;
	io.vmid = vm->vmid;
	io.epoch = vm->epoch;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_AUGMENT, &io), 0);
	{
		void *saved = hypertrace_check_epoch;

		hypertrace_check_epoch = NULL;
		KHX_EQ(cons_ioctl(&c, DTRACEIOC_AUGMENT, &io), ENOTSUP);
		hypertrace_check_epoch = saved;
	}
	cons_close(&c);

	/* Retirement during the probe-list copyout rolls the enabling back. */
	KHX_EQ(cons_open(&c), 0);
	reenter_vm = vm;
	reenter_mode = 2;
	memset(&io, 0, sizeof(io));
	io.dof = dof;
	io.ps = ps;
	io.ps_bufsize = sizeof(ps);
	io.vmid = vm->vmid;
	io.epoch = vm->epoch;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_ENABLE, &io), ESTALE);
	KHX_EQ(io.n_matched, 0);
	cons_close(&c);
	khx_set_copy_hook(NULL, NULL);
	free(vm, M_TEMP);
	dof_free(dof);
}

/*
 * The DDTrace "dist" KPI: in-kernel consumers registered with
 * dtrace_dist_register() are told when a consumer state with the
 * ddtracearg option goes active, and when any consumer closes.
 */
static int dist_opens, dist_closes;
static void *dist_last;
static dtrace_state_t *dist_state;

static void
dist_open(void *d, struct dtrace_state *s)
{
	dist_opens++;
	dist_last = d;
	dist_state = s;
}

static void
dist_close(void *d __unused, struct dtrace_state *s __unused)
{
	dist_closes++;
}

static void
dist_unregister_bogus(void *arg)
{
	(void)dtrace_dist_unregister((dtrace_dist_id_t *)arg);
}

static void
case_dist(void)
{
	static const dtrace_dops_t ops = { dist_open, dist_close };
	static const struct opt dd[] = {
		{ DTRACEOPT_BUFSIZE, 64 * 1024 },
		{ DTRACEOPT_DDTRACEARG, 7 },
	};
	dtrace_dist_id_t a, b, gone;
	char longname[100];
	struct cons c;
	int matched;
	long mism = khx_kmem_mismatches();

	khx_host_case("dist");
	KHX_EQ(dtrace_dist_register(NULL, &ops, NULL, &a), EINVAL);
	KHX_EQ(dtrace_dist_register("x", NULL, NULL, &a), EINVAL);
	KHX_EQ(dtrace_dist_register("x", &ops, NULL, NULL), EINVAL);
	KHX_EQ(dtrace_dist_register("", &ops, NULL, &a), EINVAL);
	KHX_EQ(dtrace_dist_register("first", &ops, &a, &a), 0);
	memset(longname, 'n', sizeof(longname) - 1);
	longname[sizeof(longname) - 1] = '\0';
	KHX_EQ(dtrace_dist_register(longname, &ops, &b, &b), 0);
	/* Names are truncated to DTRACE_KONNAMELEN - 1 characters. */
	KHX_EQ(strlen(((dtrace_dist_t *)b)->dtd_name), DTRACE_KONNAMELEN - 1);
	KHX_EQ(((dtrace_dist_t *)b)->dtd_arg, &b);

	/* With ddtracearg set, going active opens every dist for that state,
	 * and that state's stop or close closes every dist exactly once. */
	dist_opens = dist_closes = 0;
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable(&c, "trace_arg0", &matched), 0);
	KHX_EQ(cons_options(&c, dd, nitems(dd)), 0);
	KHX_EQ(cons_go(&c), 0);
	KHX_EQ(dist_opens, 2);
	KHX_CHECK(dist_state != NULL);
	KHX_EQ(dist_state->dts_options[DTRACEOPT_DDTRACEARG], 7);
	KHX_EQ(dist_state->dts_dists_open, 1);
	cons_close(&c);
	KHX_EQ(dist_closes, 2);
	/* Without the option nothing is opened, so nothing is closed: a
	 * consumer that never opened the dists owes them no close. */
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable(&c, "trace_arg0", &matched), 0);
	KHX_EQ(cons_options(&c, dd, 1), 0);
	KHX_EQ(cons_go(&c), 0);
	KHX_EQ(dist_opens, 2);
	cons_close(&c);
	KHX_EQ(dist_closes, 2);

	/* Unregister the second entry, then the head. */
	KHX_EQ(dtrace_dist_unregister(&b), 0);
	KHX_EQ(dtrace_dist_unregister(&a), 0);
	/* An identifier that is not registered is a caller bug: panic. */
	gone = (dtrace_dist_id_t)&gone;
	KHX_EQ(dtrace_dist_register("other", &ops, NULL, &a), 0);
	KHX_CHECK(KHX_PANICS(dist_unregister_bogus, &gone));
	khx_release_locks_after_panic(curthread);
	KHX_EQ(dtrace_dist_unregister(&a), 0);
	/* Names are freed with the size they were allocated with. */
	KHX_EQ(khx_kmem_mismatches(), mism);
}

/*
 * Dynamic-variable exhaustion, conflicting variable types across
 * enablings, and ENABLE's probe-description list for long probe names and
 * guest probes.
 */
static dtrace_provider_id_t long_prov;

static void
lp_provide(void *arg __unused, dtrace_probedesc_t *desc __unused)
{
}
static void
lp_enable(void *arg __unused, dtrace_id_t id __unused, void *parg __unused)
{
}
static void
lp_destroy(void *arg __unused, dtrace_id_t id __unused, void *parg __unused)
{
}
static dtrace_pops_t lp_pops = {
	.dtps_provide = lp_provide,
	.dtps_enable = lp_enable,
	.dtps_disable = lp_enable,
	.dtps_destroy = lp_destroy,
};

static void
case_dyn_and_lists(void)
{
	static const struct opt small[] = {
		{ DTRACEOPT_BUFSIZE, 64 * 1024 },
		{ DTRACEOPT_DYNVARSIZE, 1024 },
	};
	struct cons c;
	dtrace_status_t st;
	dtrace_enable_io_t io;
	dtrace_probedesc_t pds[4];
	dof_hdr_t *dof;
	char longfunc[DTRACE_FUNCNAMELEN + 8];
	int matched;

	khx_host_case("dyn-and-lists");
	/* A 1 KiB dynamic variable space holds a handful of a[] entries;
	 * further keys are dropped and counted. */
	for (int t = 0; t < 2; t++) {
		KHX_EQ(cons_open(&c), 0);
		KHX_EQ(cons_enable(&c, t == 0 ? "v_dyn" : "v_tdyn", &matched),
		    0);
		KHX_EQ(cons_options(&c, small, nitems(small)), 0);
		KHX_EQ(cons_go(&c), 0);
		struct thread *prev = khx_set_curthread(root_td);
		for (int i = 0; i < 200; i++)
			fire(p_entry, 1000 + i, i, 0);
		khx_set_curthread(prev);
		memset(&st, 0, sizeof(st));
		KHX_EQ(cons_ioctl(&c, DTRACEIOC_STATUS, &st), 0);
		if (t == 0)
			KHX_CHECK(st.dtst_dyndrops > 0);
		cons_close(&c);
	}

	/* A global's type is fixed by the first enabling in a consumer. */
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable(&c, "v_size1", &matched), 0);
	KHX_EQ(cons_enable(&c, "v_size2", &matched), EINVAL);
	cons_close(&c);

	/* Probe descriptions returned by ENABLE: a provider may create a
	 * function name longer than a description can hold. */
	KHX_EQ(dtrace_register("khxlong", &khxp_attr, DTRACE_PRIV_KERNEL, NULL,
	    &lp_pops, NULL, &long_prov), 0);
	memset(longfunc, 'f', sizeof(longfunc) - 1);
	longfunc[sizeof(longfunc) - 1] = '\0';
	KHX_CHECK(dtrace_probe_create(long_prov, "m", longfunc, "entry", 0,
	    NULL) != 0);
	KHX_EQ(cons_open(&c), 0);
	dof = dof_load("p_long");
	memset(&io, 0, sizeof(io));
	io.dof = dof;
	io.ps = pds;
	io.ps_bufsize = sizeof(pds);
	/* A name the description cannot hold is reported as such, never as
	 * a memory shortage and never truncated into another probe's name. */
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_ENABLE, &io), ENAMETOOLONG);
	KHX_EQ(io.n_matched, 0);
	dof_free(dof);
	cons_close(&c);
	KHX_EQ(dtrace_unregister(long_prov), 0);

	/* The same for a provider name (dtrace_register() does not bound
	 * it); the glob "*" matches it. */
	{
		char longprov[DTRACE_PROVNAMELEN + 6];

		memset(longprov, 'p', sizeof(longprov) - 1);
		longprov[sizeof(longprov) - 1] = '\0';
		KHX_EQ(dtrace_register(longprov, &khxp_attr,
		    DTRACE_PRIV_KERNEL, NULL, &lp_pops, NULL, &long_prov), 0);
		KHX_CHECK(dtrace_probe_create(long_prov, "zm", "zf", "zn", 0,
		    NULL) != 0);
		KHX_EQ(cons_open(&c), 0);
		dof = dof_load("p_longprov");
		memset(&io, 0, sizeof(io));
		io.dof = dof;
		io.ps = pds;
		io.ps_bufsize = sizeof(pds);
		KHX_EQ(cons_ioctl(&c, DTRACEIOC_ENABLE, &io), ENAMETOOLONG);
		KHX_EQ(io.n_matched, 0);
		/* Without a probe list the enabling stands. */
		KHX_EQ(cons_enable(&c, "p_longprov", &matched), 0);
		KHX_EQ(matched, 1);
		dof_free(dof);
		cons_close(&c);
		KHX_EQ(dtrace_unregister(long_prov), 0);
	}
}

/*
 * Module unload: kld_unload_try removes a module's probes (each provider's
 * destroy entry point runs) unless an enabling uses them; kld_unload
 * invalidates the immstack cache.
 */
static int mod_destroys;

static void
mod_destroy(void *arg __unused, dtrace_id_t id __unused, void *parg __unused)
{
	mod_destroys++;
}
static dtrace_pops_t mod_pops = {
	.dtps_provide = lp_provide,
	.dtps_enable = lp_enable,
	.dtps_disable = lp_enable,
	.dtps_destroy = mod_destroy,
};

struct unload_ctx {
	linker_file_t lf;
	int error;
};

static void
call_unload_try(void *func, void *arg, void *ctx)
{
	struct unload_ctx *u = ctx;

	((void (*)(void *, linker_file_t, int *))func)(arg, u->lf, &u->error);
}

static void
call_unload(void *func, void *arg, void *ctx __unused)
{
	((void (*)(void *, const char *, caddr_t, size_t))func)(arg, "x.ko",
	    NULL, 0);
}

static void
case_module_unload(void)
{
	static struct linker_file lf;
	dtrace_provider_id_t prov;
	struct unload_ctx u = { &lf, 0 };
	struct cons c;
	int matched;

	khx_host_case("module-unload");
	KHX_EQ(dtrace_register("khxmod", &khxp_attr, DTRACE_PRIV_KERNEL, NULL,
	    &mod_pops, NULL, &prov), 0);
	KHX_CHECK(dtrace_probe_create(prov, "khxmod", "f", "n", 0, NULL) != 0);
	KHX_CHECK(dtrace_probe_create(prov, "khxmod", "g", "n", 0, NULL) != 0);
	lf.filename = "khxmod.ko";
	/* A module whose probes are enabled stays. */
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable(&c, "m_probe", &matched), 0);
	KHX_EQ(matched, 1);
	mod_destroys = 0;
	KHX_EQ(khx_eh_invoke("kld_unload_try", call_unload_try, &u), 1);
	KHX_EQ(mod_destroys, 0);
	KHX_CHECK(dtrace_probe_lookup(0, prov, "khxmod", "f", "n") != 0);
	cons_close(&c);
	/* The linker's own count of enabled probes also blocks unload. */
	lf.nenabled = 1;
	KHX_EQ(khx_eh_invoke("kld_unload_try", call_unload_try, &u), 1);
	KHX_EQ(mod_destroys, 0);
	lf.nenabled = 0;
	/* An earlier error from another handler: nothing is done. */
	u.error = EBUSY;
	KHX_EQ(khx_eh_invoke("kld_unload_try", call_unload_try, &u), 1);
	KHX_EQ(mod_destroys, 0);
	u.error = 0;
	/* Otherwise both probes are destroyed and gone. */
	KHX_EQ(khx_eh_invoke("kld_unload_try", call_unload_try, &u), 1);
	KHX_EQ(mod_destroys, 2);
	KHX_EQ(dtrace_probe_lookup(0, prov, "khxmod", "f", "n"), 0);
	KHX_EQ(khx_eh_invoke("kld_unload", call_unload, NULL), 1);
	KHX_EQ(dtrace_unregister(prov), 0);
}

/*
 * Provider-side edges: argument values beyond the cached five supplied by
 * the provider's getargval entry point; firing an ID that has no probe;
 * dtrace_condense() of a provider; an unknown DIF variable; a thread of
 * proc0 (no parent, no arguments).
 */
static int dof_patch_var(dof_hdr_t *, uint_t, uint_t);

static uint64_t
ga_getargval(void *arg __unused, dtrace_id_t id __unused, void *parg __unused,
    int ndx, int aframes __unused)
{
	return (1000 + ndx);
}
static dtrace_pops_t ga_pops = {
	.dtps_provide = lp_provide,
	.dtps_enable = lp_enable,
	.dtps_disable = lp_enable,
	.dtps_destroy = lp_destroy,
	.dtps_getargval = ga_getargval,
};

static int
one_firing(const char *prog, dtrace_id_t id, struct thread *td,
    struct recs *rs, int patch_unknown)
{
	struct cons c;
	dof_hdr_t *dof;
	int matched;

	KHX_EQ(cons_open(&c), 0);
	dof = dof_load(prog);
	if (patch_unknown)
		KHX_EQ(dof_patch_var(dof, DIF_VAR_EPID, 0x01fe), 1);
	KHX_EQ(cons_enable_vm(&c, dof, 0, 0, &matched), 0);
	dof_free(dof);
	KHX_EQ(cons_enable(&c, "err_capture", &matched), 0);
	KHX_EQ(cons_options(&c, default_opts, nitems(default_opts)), 0);
	KHX_EQ(cons_go(&c), 0);
	struct thread *prev = khx_set_curthread(td);
	fire(id, 1, 2, 3);
	khx_set_curthread(prev);
	KHX_CHECK(snap_records(&c, 0, rs) >= 0);
	cons_close(&c);
	return (rs->n);
}

static void
case_provider_edges(void)
{
	dtrace_provider_id_t prov;
	dtrace_id_t id, id2;
	struct thread *p0td;
	struct recs rs;

	khx_host_case("provider-edges");
	KHX_EQ(dtrace_register("khxga", &khxp_attr, DTRACE_PRIV_KERNEL, NULL,
	    &ga_pops, NULL, &prov), 0);
	id = dtrace_probe_create(prov, "m", "f", "entry", 0, NULL);
	id2 = dtrace_probe_create(prov, "m", "g", "entry", 0, NULL);
	KHX_CHECK(id != 0 && id2 != 0);
	/* arg6 and arg9 come from the provider (1000 + index). */
	KHX_EQ(one_firing("ga_args", id, root_td, &rs, 0), 1);
	KHX_EQ(rs.r[0].val[0], 1006);
	KHX_EQ(rs.r[0].val[1], 1009);
	/* An ID with no probe (or a stale one) is ignored. */
	fire(DTRACE_SENSIBLE_PROBELIMIT, 0, 0, 0);
	/* Condensing removes the provider's probes that have no ECBs. */
	KHX_EQ(dtrace_condense(prov), 0);
	KHX_EQ(dtrace_probe_lookup(0, prov, "m", "f", "entry"), 0);
	KHX_EQ(dtrace_unregister(prov), 0);

	/* A DIF variable the framework does not know: illegal operation. */
	KHX_EQ(one_firing("w_unknownvar", p_entry, root_td, &rs, 1), 1);
	KHX_EQ(rs.r[0].val[1], DTRACEFLT_ILLOP);
	/* proc0: its ppid is its own pid (0) and it has no arguments. */
	p0td = khx_thread_new("kernel", 0);
	KHX_EQ(one_firing("w_vars_p0", p_entry, p0td, &rs, 0), 1);
	KHX_EQ(rs.r[0].val[0], 0);
	KHX_EQ(rs.r[0].val[1], 1);
	khx_thread_free(p0td);
}

/*
 * Virtual-probe namespace KPI edges and teardown of a VM's probe space
 * while another consumer, or the hypertrace map, still holds probes.
 */
static int vk_enabled_ret, vk_rm_ret;
static int (*vk_saved_is_enabled)(uint16_t, hypertrace_id_t);
static int (*vk_saved_rmprobe)(uint16_t, hypertrace_id_t);

static int
vk_is_enabled(uint16_t vmid, hypertrace_id_t id)
{
	return (vk_enabled_ret);
}
static int
vk_rmprobe(uint16_t vmid, hypertrace_id_t id)
{
	return (vk_rm_ret != 0 ? vk_rm_ret : vk_saved_rmprobe(vmid, id));
}

static void
vk_close(void *arg)
{
	cons_close(arg);
}

static void
case_vprobe_kpi(void)
{
	struct cons a, b;
	struct fvm *vm;
	dtrace_probedesc_t d;
	int err, matched;
	dof_hdr_t *dof;

	khx_host_case("vprobe-kpi");
	/* A host provider's probe never has a caller-chosen ID. */
	KHX_EQ(dtrace_vprobe_create(0, 5, (const char *)khx_prov, "m", "f", "n",
	    &err), DTRACE_IDNONE);

	/* Teardown of a VM probe space at consumer close skips probes that
	 * another consumer has enabled, or that the hypertrace map reports
	 * enabled, and warns about probes it cannot query.  (A failing
	 * hypertrace_rmprobe() is a fatal invariant violation: not tested.) */
	vm = fvm_new("vkvm");
	KHX_EQ(cons_open(&a), 0);
	/* Virtual probes need an ID within the sensible limit. */
	d = vdesc(DTRACE_SENSIBLE_PROBELIMIT + 1, "vk", "m", "f", "n");
	KHX_CHECK(vprobe_create(&a, vm, &d, 1) != 0);
	d = vdesc(31, "khx", "mod", "func", "entry");
	KHX_EQ(vprobe_create(&a, vm, &d, 1), 0);
	dof = dof_load("trace_arg0");
	for (uint32_t i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t *sec = (dof_sec_t *)((char *)dof + dof->dofh_secoff +
		    i * dof->dofh_secsize);
		if (sec->dofs_type == DOF_SECT_PROBEDESC)
			((dof_probedesc_t *)((char *)dof +
			    sec->dofs_offset))->dofp_vmid = vm->vmid;
	}
	KHX_EQ(cons_enable_vm(&a, dof, 0, 0, &matched), 0);
	dof_free(dof);
	KHX_EQ(cons_open(&b), 0);
	cons_close(&b);			/* a's probe keeps its ECB */
	vk_saved_is_enabled = hypertrace_is_enabled;
	vk_saved_rmprobe = hypertrace_rmprobe;
	cons_close(&a);
	/* Recreate and close with the map claiming the probe is enabled,
	 * then failing the query, then failing the removal. */
	KHX_EQ(cons_open(&a), 0);
	KHX_EQ(vprobe_create(&a, vm, &d, 1), 0);
	hypertrace_is_enabled = vk_is_enabled;
	vk_enabled_ret = 1;
	cons_close(&a);
	KHX_EQ(cons_open(&a), 0);
	vk_enabled_ret = -1;
	cons_close(&a);
	vk_enabled_ret = 0;
	hypertrace_is_enabled = vk_saved_is_enabled;
	hypertrace_rmprobe = vk_saved_rmprobe;
	KHX_EQ(cons_open(&a), 0);
	cons_close(&a);
	fvm_free(vm);
}
