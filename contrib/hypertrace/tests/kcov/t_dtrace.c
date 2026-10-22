/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Tests for the DTrace framework (dtrace.c with its included FreeBSD glue,
 * notably dtrace_ioctl.c) and the HyperTrace provider (hypertrace.c,
 * hypertrace_map.c), compiled unmodified as kernel translation units.
 *
 * The framework is driven through its real interfaces: SYSINITs, the
 * /dev/dtrace and /dev/dtrace/hypertrace cdevsw entry points with
 * per-open cdevpriv, the provider API (dtrace_register/dtrace_probe_create/
 * dtrace_probe), the HyperTrace hooks (hypertrace_probe and the vmm_*
 * callbacks a VMM installs), and DOF produced from D source by the
 * worktree's own libdtrace.  Record contents are checked against the
 * values each D action must store, located through DTRACEIOC_EPROBE.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <sys/hypertrace.h>
#include <machine/vmm.h>

#include "khx_kern.h"
#include "khx_dtrace.h"
#include <machine/bhyve_hypercall.h>
#include "dtrace_cddl.h"
#include <sys/linker.h>
#include <sys/elf.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <ddb/ddb.h>
#include <ddb/db_sym.h>
#include "linker_if.h"
extern int dtrace_err_verbose;

/* ---- consumers ---------------------------------------------------------- */
struct cons {
	struct khx_file *fp;
	struct thread *td;
	struct cdev *dev;
};

static struct thread *root_td;

static int
cons_open(struct cons *c)
{
	int error;

	c->dev = khx_cdev_find("dtrace/dtrace");
	c->td = root_td;
	c->fp = khx_file_new();
	khx_file_set_current(c->fp);
	error = khx_dev_open(c->dev, FREAD | FWRITE, c->td);
	khx_file_set_current(NULL);
	return (error);
}

static int
cons_ioctl(struct cons *c, u_long cmd, void *arg)
{
	int error;

	khx_file_set_current(c->fp);
	error = khx_dev_ioctl(c->dev, cmd, arg, 0, c->td);
	khx_file_set_current(NULL);
	return (error);
}

static void
cons_close(struct cons *c)
{
	khx_file_close(c->fp);
	c->fp = NULL;
}

/* ---- DOF corpus ------------------------------------------------------- */
static dof_hdr_t *
dof_load(const char *name)
{
	char file[128];
	size_t len;
	dof_hdr_t *dof;

	snprintf(file, sizeof(file), "%s.dof", name);
	dof = khx_host_read_file("KHX_DOF_DIR", file, &len);
	KHX_EQ(len, dof->dofh_filesz);
	return (dof);
}

static void
dof_free(dof_hdr_t *dof)
{
	khx_host_free(dof, "khx-file");
}

/* Retarget every probe description at a VM namespace. */
static void
dof_set_vmid(dof_hdr_t *dof, uint16_t vmid)
{
	for (uint32_t i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t *sec = (dof_sec_t *)((char *)dof + dof->dofh_secoff +
		    i * dof->dofh_secsize);

		if (sec->dofs_type == DOF_SECT_PROBEDESC)
			((dof_probedesc_t *)((char *)dof +
			    sec->dofs_offset))->dofp_vmid = vmid;
	}
}

static int
cons_enable_vm(struct cons *c, dof_hdr_t *dof, uint16_t vmid, uint64_t epoch,
    int *matched)
{
	dtrace_enable_io_t io;
	int error;

	memset(&io, 0, sizeof(io));
	io.dof = dof;
	io.vmid = vmid;
	io.epoch = epoch;
	error = cons_ioctl(c, DTRACEIOC_ENABLE, &io);
	if (matched != NULL)
		*matched = io.n_matched;
	return (error);
}

static int
cons_enable(struct cons *c, const char *name, int *matched)
{
	dof_hdr_t *dof = dof_load(name);
	int error = cons_enable_vm(c, dof, 0, 0, matched);

	dof_free(dof);
	return (error);
}

/* An options-only DOF, as libdtrace submits from dtrace_go(). */
struct opt {
	int option;
	uint64_t value;
};

static dof_hdr_t *
dof_options(const struct opt *opts, int n, uint32_t align, uint32_t entsize)
{
	size_t size = sizeof(dof_hdr_t) + sizeof(dof_sec_t) +
	    (size_t)n * sizeof(dof_optdesc_t);
	dof_hdr_t *dof = malloc(size, M_TEMP, M_WAITOK | M_ZERO);
	dof_sec_t *sec = (dof_sec_t *)(dof + 1);
	dof_optdesc_t *od = (dof_optdesc_t *)(sec + 1);

	dof->dofh_ident[DOF_ID_MAG0] = DOF_MAG_MAG0;
	dof->dofh_ident[DOF_ID_MAG1] = DOF_MAG_MAG1;
	dof->dofh_ident[DOF_ID_MAG2] = DOF_MAG_MAG2;
	dof->dofh_ident[DOF_ID_MAG3] = DOF_MAG_MAG3;
	dof->dofh_ident[DOF_ID_MODEL] = DOF_MODEL_NATIVE;
	dof->dofh_ident[DOF_ID_ENCODING] = DOF_ENCODE_NATIVE;
	dof->dofh_ident[DOF_ID_VERSION] = DOF_VERSION;
	dof->dofh_ident[DOF_ID_DIFVERS] = DIF_VERSION;
	dof->dofh_ident[DOF_ID_DIFIREG] = DIF_DIR_NREGS;
	dof->dofh_ident[DOF_ID_DIFTREG] = DIF_DTR_NREGS;
	dof->dofh_hdrsize = sizeof(dof_hdr_t);
	dof->dofh_secsize = sizeof(dof_sec_t);
	dof->dofh_secnum = 1;
	dof->dofh_secoff = sizeof(dof_hdr_t);
	dof->dofh_loadsz = dof->dofh_filesz = size;
	sec->dofs_type = DOF_SECT_OPTDESC;
	sec->dofs_align = align;
	sec->dofs_flags = DOF_SECF_LOAD;
	sec->dofs_entsize = entsize;
	sec->dofs_offset = sizeof(dof_hdr_t) + sizeof(dof_sec_t);
	sec->dofs_size = (size_t)n * sizeof(dof_optdesc_t);
	for (int i = 0; i < n; i++) {
		od[i].dofo_option = opts[i].option;
		od[i].dofo_strtab = DOF_SECIDX_NONE;
		od[i].dofo_value = opts[i].value;
	}
	return (dof);
}

static int
cons_options(struct cons *c, const struct opt *opts, int n)
{
	dof_hdr_t *dof = dof_options(opts, n, sizeof(uint64_t),
	    sizeof(dof_optdesc_t));
	int error = cons_enable_vm(c, dof, 0, 0, NULL);

	free(dof, M_TEMP);
	return (error);
}

static const struct opt default_opts[] = {
	{ DTRACEOPT_BUFSIZE, 64 * 1024 },
	{ DTRACEOPT_AGGSIZE, 64 * 1024 },
	{ DTRACEOPT_DYNVARSIZE, 64 * 1024 },
	{ DTRACEOPT_SPECSIZE, 16 * 1024 },
	{ DTRACEOPT_NSPEC, 2 },
	{ DTRACEOPT_STRSIZE, 256 },
};

static int
cons_go(struct cons *c)
{
	processorid_t cpu = -1;

	return (cons_ioctl(c, DTRACEIOC_GO, &cpu));
}

static int
cons_stop(struct cons *c)
{
	processorid_t cpu = -1;

	return (cons_ioctl(c, DTRACEIOC_STOP, &cpu));
}

static char snapbuf[256 * 1024];

static int
cons_snap(struct cons *c, u_long cmd, int cpu, dtrace_bufdesc_t *out)
{
	dtrace_bufdesc_t desc, *p = &desc;
	int error;

	memset(&desc, 0, sizeof(desc));
	desc.dtbd_cpu = cpu;
	desc.dtbd_data = snapbuf;
	desc.dtbd_size = sizeof(snapbuf);
	error = cons_ioctl(c, cmd, &p);
	if (out != NULL)
		*out = desc;
	return (error);
}

static dtrace_eprobedesc_t *
cons_eprobe(struct cons *c, dtrace_epid_t epid)
{
	static char buf[4096];
	dtrace_eprobedesc_t *ep = (dtrace_eprobedesc_t *)buf;

	memset(buf, 0, sizeof(buf));
	ep->dtepd_epid = epid;
	ep->dtepd_nrecs = (sizeof(buf) - sizeof(*ep)) /
	    sizeof(dtrace_recdesc_t);
	int error;

	/* The ioctl argument holds the descriptor's address. */
	if ((error = cons_ioctl(c, DTRACEIOC_EPROBE, &ep)) != 0) {
		khx_host_log("  EPROBE(%u) error %d\n", epid, error);
		return (NULL);
	}
	return (ep);
}

/*
 * Walk the records of a switched buffer.  For each record, cb receives the
 * header and the record descriptions from DTRACEIOC_EPROBE.
 */
typedef void (*rec_cb_t)(void *, const dtrace_rechdr_t *,
    const dtrace_eprobedesc_t *, const char *);

static int
cons_walk(struct cons *c, const char *data, size_t size, rec_cb_t cb,
    void *arg)
{
	size_t off = 0;
	int n = 0;

	while (off < size) {
		const dtrace_rechdr_t *h = (const dtrace_rechdr_t *)(data + off);
		dtrace_eprobedesc_t *ep;

		if (h->dtrh_epid == DTRACE_EPIDNONE) {
			off += sizeof(dtrace_epid_t);	/* padding */
			continue;
		}
		ep = cons_eprobe(c, h->dtrh_epid);
		if (ep == NULL)
			khx_host_log("  EPROBE failed for epid %u at offset %zu of %zu\n",
			    h->dtrh_epid, off, size);
		KHX_CHECK(ep != NULL);
		if (ep == NULL)
			return (n);
		cb(arg, h, ep, data + off);
		off += ep->dtepd_size;
		n++;
	}
	return (n);
}

/* ---- test provider -------------------------------------------------- */
static dtrace_provider_id_t khx_prov;
static dtrace_id_t p_entry, p_return, p_other;
static int prov_enables, prov_disables, prov_provides, prov_destroys;
static int prov_getargdesc;

static void
khxp_provide(void *arg __unused, dtrace_probedesc_t *desc __unused)
{
	prov_provides++;
	if (p_entry == 0) {
		p_entry = dtrace_probe_create(khx_prov, "mod", "func", "entry",
		    0, NULL);
		p_return = dtrace_probe_create(khx_prov, "mod", "func",
		    "return", 0, NULL);
		p_other = dtrace_probe_create(khx_prov, "mod2", "func2",
		    "entry", 0, NULL);
	}
}

static void
khxp_enable(void *arg __unused, dtrace_id_t id __unused, void *parg __unused)
{
	prov_enables++;
}

static void
khxp_disable(void *arg __unused, dtrace_id_t id __unused, void *parg __unused)
{
	prov_disables++;
}

static void
khxp_getargdesc(void *arg __unused, dtrace_id_t id __unused,
    void *parg __unused, dtrace_argdesc_t *desc)
{
	prov_getargdesc++;
	if (desc->dtargd_ndx < 2)
		strlcpy(desc->dtargd_native, "uint64_t",
		    sizeof(desc->dtargd_native));
	else
		desc->dtargd_ndx = DTRACE_ARGNONE;
}

static void
khxp_destroy(void *arg __unused, dtrace_id_t id __unused, void *parg __unused)
{
	prov_destroys++;
}

static dtrace_pops_t khxp_ops = {
	.dtps_provide = khxp_provide,
	.dtps_enable = khxp_enable,
	.dtps_disable = khxp_disable,
	.dtps_getargdesc = khxp_getargdesc,
	.dtps_destroy = khxp_destroy,
};

static dtrace_pattr_t khxp_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
};

static void
fire(dtrace_id_t id, uint64_t a0, uint64_t a1, uint64_t a2)
{
	khx_probe_args[0] = a0;
	khx_probe_args[1] = a1;
	khx_probe_args[2] = a2;
	dtrace_probe(id, a0, a1, a2, 0, 0);
}

/* ---- record collection --------------------------------------------- */
struct rec {
	dtrace_epid_t epid;
	dtrace_id_t probe;
	uint16_t vmid;
	int nrecs;
	dtrace_actkind_t kind[16];
	uint64_t val[16];
	uint32_t size[16];
	char str[16][64];
	uint64_t raw[16][8];	/* first 64 bytes of each record */
};
struct recs {
	int n;
	struct rec r[64];
	uint8_t big[4096];	/* full bytes of record 0's first action */
	size_t bigsize;
};

static void
collect(void *arg, const dtrace_rechdr_t *h, const dtrace_eprobedesc_t *ep,
    const char *base)
{
	struct recs *rs = arg;
	struct rec *r;

	if (rs->n >= (int)nitems(rs->r))
		return;
	r = &rs->r[rs->n++];
	memset(r, 0, sizeof(*r));
	r->epid = h->dtrh_epid;
	r->probe = ep->dtepd_probeid;
	r->vmid = ep->dtepd_vmid;
	r->nrecs = ep->dtepd_nrecs;
	r->nrecs = 0;
	for (int j = 0; j < ep->dtepd_nrecs && r->nrecs < 16; j++) {
		const dtrace_recdesc_t *rd = &ep->dtepd_rec[j];
		const char *p = base + rd->dtrd_offset;
		int i;

		/* Clause-local and other statement-only actions record nothing. */
		if (rd->dtrd_size == 0)
			continue;
		i = r->nrecs++;
		memcpy(r->raw[i], p, MIN(rd->dtrd_size, sizeof(r->raw[i])));
		if (rs->n == 1 && i == 0) {
			rs->bigsize = MIN(rd->dtrd_size, sizeof(rs->big));
			memcpy(rs->big, p, rs->bigsize);
		}
		r->kind[i] = rd->dtrd_action;
		r->size[i] = rd->dtrd_size;
		switch (rd->dtrd_size) {
		case 1: r->val[i] = *(const uint8_t *)p; break;
		case 2: r->val[i] = *(const uint16_t *)p; break;
		case 4: r->val[i] = *(const uint32_t *)p; break;
		case 8: r->val[i] = *(const uint64_t *)p; break;
		default:
			strlcpy(r->str[i], p, MIN(sizeof(r->str[i]),
			    rd->dtrd_size + 1));
		}
	}
}

static int
snap_records(struct cons *c, int cpu, struct recs *rs)
{
	dtrace_bufdesc_t d;
	int error;

	memset(rs, 0, sizeof(*rs));
	error = cons_snap(c, DTRACEIOC_BUFSNAP, cpu, &d);
	if (error != 0)
		return (-error);
	return (cons_walk(c, snapbuf, d.dtbd_size, collect, rs));
}

/* ---- cases ---------------------------------------------------------- */
static void
case_boot(void)
{
	struct cons c;
	dtrace_conf_t conf;
	dtrace_providerdesc_t pvd;
	dtrace_probedesc_t pd;
	int error;

	khx_host_case("boot");
	KHX_CHECK(khx_cdev_find("dtrace/dtrace") != NULL);
	KHX_CHECK(khx_cdev_find("dtrace/helper") != NULL);
	KHX_CHECK(khx_cdev_find("dtrace/hypertrace") != NULL);
	KHX_EQ(dtrace_register("khx", &khxp_attr, DTRACE_PRIV_KERNEL, NULL,
	    &khxp_ops, NULL, &khx_prov), 0);
	KHX_EQ(cons_open(&c), 0);
	KHX_CHECK(p_entry != 0);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_CONF, &conf), 0);
	KHX_EQ(conf.dtc_difversion, DIF_VERSION);
	KHX_EQ(conf.dtc_difintregs, DIF_DIR_NREGS);
	memset(&pvd, 0, sizeof(pvd));
	strlcpy(pvd.dtvd_name, "khx", sizeof(pvd.dtvd_name));
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_PROVIDER, &pvd), 0);
	KHX_EQ(pvd.dtvd_priv.dtpp_flags, DTRACE_PRIV_KERNEL);
	strlcpy(pvd.dtvd_name, "nosuch", sizeof(pvd.dtvd_name));
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_PROVIDER, &pvd), ESRCH);
	/* Probe enumeration visits every host probe in ID order. */
	memset(&pd, 0, sizeof(pd));
	pd.dtpd_id = DTRACE_IDNONE;
	error = cons_ioctl(&c, DTRACEIOC_PROBES, &pd);
	KHX_EQ(error, 0);
	KHX_CHECK(strcmp(pd.dtpd_provider, "dtrace") == 0);
	KHX_CHECK(strcmp(pd.dtpd_name, "BEGIN") == 0);
	memset(&pd, 0, sizeof(pd));
	strlcpy(pd.dtpd_provider, "khx", sizeof(pd.dtpd_provider));
	strlcpy(pd.dtpd_name, "return", sizeof(pd.dtpd_name));
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_PROBEMATCH, &pd), 0);
	KHX_EQ(pd.dtpd_id, p_return);
	KHX_CHECK(strcmp(pd.dtpd_func, "func") == 0);
	cons_close(&c);
}

static void
case_trace_record(void)
{
	struct cons c;
	struct recs rs;
	int matched;

	khx_host_case("trace-record");
	KHX_EQ(cons_open(&c), 0);
	KHX_EQ(cons_enable(&c, "trace_arg0", &matched), 0);
	KHX_EQ(matched, 1);
	KHX_EQ(cons_options(&c, default_opts, nitems(default_opts)), 0);
	KHX_EQ(cons_go(&c), 0);
	fire(p_entry, 0x1122334455667788ULL, 2, 3);
	fire(p_return, 9, 9, 9);	/* not enabled */
	fire(p_entry, 42, 0, 0);
	KHX_EQ(snap_records(&c, 0, &rs), 2);
	KHX_EQ(rs.r[0].probe, p_entry);
	KHX_EQ(rs.r[0].nrecs, 1);
	KHX_EQ(rs.r[0].kind[0], DTRACEACT_DIFEXPR);
	KHX_EQ(rs.r[0].size[0], 8);
	KHX_EQ(rs.r[0].val[0], 0x1122334455667788ULL);
	KHX_EQ(rs.r[1].val[0], 42);
	KHX_EQ(cons_stop(&c), 0);
	cons_close(&c);
}

#include "t_dtrace_ht.inc"
#include "t_dtrace_ht2.inc"
#include "t_dtrace_ioctl.inc"
#include "t_dtrace_dif.inc"
#include "t_dtrace_edges.inc"
#include "t_dtrace_branches.inc"

int
khx_test_main(void)
{
	khx_kern_boot();
	root_td = khx_thread_new("dtrace", 4500);
	{
		/* Firing from root_td: its kernel stack is this pthread's stack,
		 * so the real dtrace_getpcstack() walks real frames, and it has
		 * a user trapframe for uregs[]. */
		static struct trapframe tf;
		void *lo;
		size_t size;

		khx_host_stack_bounds(&lo, &size);
		root_td->td_kstack = (void *)lo;
		root_td->td_kstack_pages = size / PAGE_SIZE;
		tf.tf_rip = 0x400100;
		tf.tf_rsp = 0x7fff0000;
		tf.tf_rbp = 0;
		tf.tf_rax = 0xa0a0;
		root_td->td_frame = &tf;
		/* Its process has arguments, as an ordinary process does. */
		static struct {
			struct pargs pa;
			char space[32];
		} args;

		args.pa.ar_ref = 1;
		args.pa.ar_length = 10;
		memcpy(args.pa.ar_args, "dtrace\0-x\0", 10);
		root_td->td_proc->p_args = &args.pa;
	}
	jail_td = khx_thread_new("jailed", 4501);
	jail_td->td_ucred->cr_prison = &khx_jail;
	khx_run_sysinits();
	vmm_hooks(1);
	dtrace_err_verbose = 1;	/* DOF rejections are logged to the console */
	case_boot();
	case_trace_record();
	case_ht_identity();
	case_ht_gate();
	case_ht_handles();
	case_ht_vprobes();
	case_ht_fire();
	case_ht_map();
	case_ht_hooks();
	case_ht_probe_state();
	case_ht_module();
	case_ht_limits();
	case_ioctl_enable();
	case_ioctl_queries();
	case_ioctl_buffers();
	case_ioctl_aggs();
	case_ioctl_misc();
	case_ioctl_copy_faults();
	case_ioctl_status();
	case_ioctl_bad_dof();
	case_ioctl_guest_origin();
	case_dist();
	case_dyn_and_lists();
	case_module_unload();
	case_provider_edges();
	case_vprobe_kpi();
	case_edges_match();
	case_edges_vm();
	case_edges_records();
	case_edges_lists();
	case_edges_misc();
	case_edges_more();
	case_helpers();
	case_jstack_strsize();
	case_immstack_noframes();
	case_immstack_small_slots();
	case_br_epochs();
	case_br_probe_arg();
	case_br_predcache();
	case_br_host_unanchored_caller();
	case_br_probe_empty_vm();
	case_br_vprobe_ioctls();
	case_br_augment_error();
	case_br_stack_options();
	case_br_huge_strsize();
	case_br_var_flags();
	case_br_go_pending();
	case_br_replicate_states();
	case_br_hypertrace_aggsize();
	case_br_immstack_frames();
	case_br_probekey();
	case_br_cleanpath_bound();
	case_br_hypercall_validate();
	case_br_hypercall_threads();
	case_br_hypercall_immstack_tick();
	case_vprog_e2e();
	case_br_empty_desc();
	case_br_actdesc_strtab();
	case_br_provtab_full();
	case_br_late_epoch_hook();
	case_ht_vmid_reuse();
	case_tool_dofs();
	case_dif_corpus();
	case_vprobe_limits();
	case_host_panic();
	/* Teardown: providers first, then the SYSUNINITs (hypertrace node,
	 * then the framework).  Everything the framework allocated through
	 * kmem must be released. */
	khx_host_case("teardown");
	KHX_EQ(dtrace_unregister(khx_prov), 0);
	vmm_hooks(0);
	KHX_EQ(khx_module_event("hypertrace", MOD_UNLOAD), 0);
	khx_run_sysuninits();
	KHX_CHECK(khx_cdev_find("dtrace/dtrace") == NULL);
	KHX_CHECK(khx_cdev_find("dtrace/hypertrace") == NULL);
	if (khx_host_live_tag("solaris") != 0)
		khx_host_log("  live solaris allocations: %ld\n",
		    khx_host_live_tag("solaris"));
	KHX_EQ(khx_host_live_tag("solaris"), 0);
	if (!khx_host_env_flag("KHX_NO_ANON")) {
		case_anon(1);
		case_anon(0);
		KHX_EQ(khx_host_live_tag("solaris"), 0);
	}
	return (khx_host_finish("dtrace_hypertrace"));
}
