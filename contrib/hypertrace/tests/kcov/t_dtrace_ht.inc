/* SPDX-License-Identifier: BSD-2-Clause */
/* HyperTrace provider and control-plane cases for t_dtrace.c. */

/* ---- a fake VM as seen through the vmm_* callbacks ---------------------- */
struct fvm {
	struct vm_hdl hdl;		/* must be first: vmhdl points here */
	uint16_t vmid;
	uint64_t epoch;
	const char *name;
	lwpid_t tid;
	uint64_t regs[64];
	uint64_t gbase;			/* guest kernel window */
	char mem[16384];
	uint64_t ubase;			/* guest user window */
	char umem[4096];
	uint64_t tbase;			/* last 256 bytes of the address space */
	char tmem[256];
	int copyin_error;		/* forced vmm_guest_copyin result */
	int getreg_error;
	int ucopyin_error;		/* forced vmm_guest_user_copyin result */
	int ucopyout_error;		/* forced vmm_guest_user_copyout result */
	/* Transient fault injection: the fail_at-th guest memory access
	 * (kernel or user, read or write; counted from 1) fails with EFAULT,
	 * as if another vCPU had just unmapped the page. */
	int fail_at;
	int naccess;
	int fault_hit;
	/* Optionally map the guest's page zero (kernel reads of [0, 256)). */
	int zero_mapped;
	char zmem[256];
	int utop_mapped;	/* user reads/writes of the top 256 bytes */
};

static struct fvm *
fvm_of(const void *h)
{
	return ((struct fvm *)(uintptr_t)h);
}

static uint16_t f_getid(const void *h) { return (fvm_of(h)->vmid); }
static uint64_t f_getepoch(const void *h) { return (fvm_of(h)->epoch); }
static lwpid_t f_gettid(const void *h) { return (fvm_of(h)->tid); }
static const char *f_getname(const void *h) { return (fvm_of(h)->name); }

static int
f_getreg(const void *h, int reg, uint64_t *value)
{
	struct fvm *vm = fvm_of(h);

	if (vm->getreg_error != 0)
		return (vm->getreg_error);
	if (reg < 0 || reg >= 64)
		return (EINVAL);
	*value = vm->regs[reg];
	return (0);
}

static int
f_copyin(const void *h, uint64_t gla, void *dst, size_t len)
{
	struct fvm *vm = fvm_of(h);

	if (vm->copyin_error != 0)
		return (vm->copyin_error);
	if (vm->fail_at != 0 && ++vm->naccess == vm->fail_at) {
		vm->fault_hit = 1;
		return (EFAULT);
	}

	if (vm->zero_mapped && gla < sizeof(vm->zmem)) {
		if (len > sizeof(vm->zmem) - gla)
			return (EFAULT);
		memcpy(dst, vm->zmem + gla, len);
		return (0);
	}
	if (vm->tbase != 0 && gla >= vm->tbase) {
		if (len > sizeof(vm->tmem) - (gla - vm->tbase))
			return (EFAULT);
		memcpy(dst, vm->tmem + (gla - vm->tbase), len);
		return (0);
	}
	if (gla < vm->gbase || gla - vm->gbase > sizeof(vm->mem) ||
	    len > sizeof(vm->mem) - (gla - vm->gbase))
		return (EFAULT);
	memcpy(dst, vm->mem + (gla - vm->gbase), len);
	return (0);
}

static int
f_ucopyin(const void *h, uint64_t gla, void *dst, size_t len)
{
	struct fvm *vm = fvm_of(h);

	if (vm->ucopyin_error != 0)
		return (vm->ucopyin_error);
	if (vm->fail_at != 0 && ++vm->naccess == vm->fail_at) {
		vm->fault_hit = 1;
		return (EFAULT);
	}

	if (vm->utop_mapped && gla >= vm->tbase) {
		if (len > sizeof(vm->tmem) - (gla - vm->tbase))
			return (EFAULT);
		memcpy(dst, vm->tmem + (gla - vm->tbase), len);
		return (0);
	}
	if (gla < vm->ubase || gla - vm->ubase > sizeof(vm->umem) ||
	    len > sizeof(vm->umem) - (gla - vm->ubase))
		return (EFAULT);
	memcpy(dst, vm->umem + (gla - vm->ubase), len);
	return (0);
}

static int
f_ucopyout(const void *h, uint64_t gla, const void *src, size_t len)
{
	struct fvm *vm = fvm_of(h);

	if (vm->ucopyout_error != 0)
		return (vm->ucopyout_error);
	if (vm->fail_at != 0 && ++vm->naccess == vm->fail_at) {
		vm->fault_hit = 1;
		return (EFAULT);
	}

	if (vm->utop_mapped && gla >= vm->tbase) {
		if (len > sizeof(vm->tmem) - (gla - vm->tbase))
			return (EFAULT);
		memcpy(vm->tmem + (gla - vm->tbase), src, len);
		return (0);
	}
	if (gla < vm->ubase || gla - vm->ubase > sizeof(vm->umem) ||
	    len > sizeof(vm->umem) - (gla - vm->ubase))
		return (EFAULT);
	memcpy(vm->umem + (gla - vm->ubase), src, len);
	return (0);
}

/* The VMM installs these when it loads; they are hypertrace.c globals. */
static void
vmm_hooks(int on)
{
	vmm_getid = on ? f_getid : NULL;
	vmm_getepoch = on ? f_getepoch : NULL;
	vmm_gettid = on ? f_gettid : NULL;
	vmm_getname = on ? f_getname : NULL;
	vmm_getreg = on ? f_getreg : NULL;
	vmm_guest_copyin = on ? f_copyin : NULL;
	vmm_guest_user_copyin = on ? f_ucopyin : NULL;
	vmm_guest_user_copyout = on ? f_ucopyout : NULL;
}

static struct fvm *
fvm_new(const char *name)
{
	struct fvm *vm = malloc(sizeof(*vm), M_TEMP, M_WAITOK | M_ZERO);

	vm->name = name;
	vm->tid = 777;
	vm->gbase = 0xffff800000100000ULL;
	vm->ubase = 0x0000000000400000ULL;
	KHX_EQ(hypertrace_vm_alloc(&vm->vmid, &vm->epoch), 0);
	KHX_CHECK(vm->vmid != 0 && vm->epoch != 0);
	return (vm);
}

static void
fvm_free(struct fvm *vm)
{
	(void)hypertrace_vm_release(vm->vmid, vm->epoch);
	free(vm, M_TEMP);
}

/* ---- the HyperTrace control device -------------------------------------- */
static struct thread *jail_td;
static struct prison khx_jail;

static int
ht_ioctl(struct thread *td, u_long cmd, void *arg)
{
	return (khx_dev_ioctl(khx_cdev_find("dtrace/hypertrace"), cmd, arg, 0,
	    td));
}

static struct hypertrace_epoch_gate
gate(uint16_t vmid, uint64_t epoch, uint8_t token, uint8_t previous)
{
	struct hypertrace_epoch_gate g;

	memset(&g, 0, sizeof(g));
	g.vmid = vmid;
	g.epoch = epoch;
	memset(g.token, token, sizeof(g.token));
	memset(g.previous_token, previous, sizeof(g.previous_token));
	return (g);
}

static int
epoch_live(uint16_t vmid, uint64_t epoch)
{
	struct hypertrace_epoch_query q;

	memset(&q, 0, sizeof(q));
	q.vmid = vmid;
	q.epoch = epoch;
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_QUERY, &q), 0);
	return (q.live);
}

static void
case_ht_identity(void)
{
	struct hypertrace_epoch_query q;
	uint16_t id, ids[HYPERTRACE_MAX_VMS];
	uint64_t ep, eps[HYPERTRACE_MAX_VMS];
	int n = 0, error;

	khx_host_case("ht-identity");
	KHX_EQ(hypertrace_vm_alloc(NULL, &ep), EINVAL);
	KHX_EQ(hypertrace_vm_alloc(&id, NULL), EINVAL);
	/* Every usable VMID can be allocated exactly once. */
	while ((error = hypertrace_vm_alloc(&ids[n], &eps[n])) == 0) {
		KHX_EQ(khx_mbufid_epoch(ids[n]), eps[n]);
		n++;
	}
	KHX_EQ(error, ENOSPC);
	KHX_EQ(n, HYPERTRACE_MAX_VMS - 1);
	for (int i = 0; i < n; i++)
		KHX_CHECK(ids[i] == i + 1 && eps[i] != 0);
	/* Release requires the exact lifetime. */
	KHX_EQ(hypertrace_vm_release(0, eps[0]), ESTALE);
	KHX_EQ(hypertrace_vm_release(ids[0], 0), ESTALE);
	KHX_EQ(hypertrace_vm_release(HYPERTRACE_MAX_VMS, 1), ESTALE);
	KHX_EQ(hypertrace_vm_release(ids[0], eps[0] + 1), ESTALE);
	KHX_EQ(epoch_live(ids[0], eps[0]), 1);
	for (int i = 0; i < n; i++)
		KHX_EQ(hypertrace_vm_release(ids[i], eps[i]), 0);
	KHX_EQ(hypertrace_vm_release(ids[0], eps[0]), ESTALE);
	KHX_EQ(khx_mbufid_epoch(ids[0]), 0);
	KHX_EQ(epoch_live(ids[0], eps[0]), 0);
	/* A released VMID is reused with a fresh lifetime. */
	KHX_EQ(hypertrace_vm_alloc(&id, &ep), 0);
	KHX_EQ(id, 1);
	KHX_CHECK(ep != eps[0]);
	KHX_EQ(hypertrace_vm_release(id, ep), 0);

	/* Query validation. */
	memset(&q, 0, sizeof(q));
	q.vmid = 1;
	q.epoch = 1;
	q.live = 1;
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_QUERY, &q), EINVAL);
	q.live = 0;
	q.reserved2 = 1;
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_QUERY, &q), EINVAL);
	q.reserved2 = 0;
	for (int i = 0; i < 3; i++) {
		q.reserved[i] = 1;
		KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_QUERY, &q), EINVAL);
		q.reserved[i] = 0;
	}
	q.vmid = 0;
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_QUERY, &q), EINVAL);
	q.vmid = HYPERTRACE_MAX_VMS;
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_QUERY, &q), EINVAL);
	q.vmid = 1;
	q.epoch = 0;
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_QUERY, &q), EINVAL);
	/* Unknown commands, jailed callers and missing privilege. */
	KHX_EQ(ht_ioctl(root_td, _IOWR('H', 9, int), &q), ENOTTY);
	q.epoch = 1;
	KHX_EQ(ht_ioctl(jail_td, HYPERTRACE_IOC_EPOCH_QUERY, &q), EPERM);
	khx_priv_deny_all(1);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_QUERY, &q), EPERM);
	khx_priv_deny_all(0);
	KHX_EQ(khx_dev_open(khx_cdev_find("dtrace/hypertrace"), FREAD, root_td),
	    0);
}

static void
case_ht_gate(void)
{
	struct hypertrace_epoch_gate g;
	struct fvm *vm;

	khx_host_case("ht-gate");
	vm = fvm_new("gate");
	/* Validation for each gate command. */
	g = gate(vm->vmid, vm->epoch, 0, 0);
	g.suspended = 1;
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_GATE_QUERY, &g), EINVAL);
	g = gate(vm->vmid, vm->epoch, 0, 0);
	g.reserved2 = 1;
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_GATE_QUERY, &g), EINVAL);
	for (int i = 0; i < 3; i++) {
		g = gate(vm->vmid, vm->epoch, 0, 0);
		g.reserved[i] = 1;
		KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_GATE_QUERY, &g),
		    EINVAL);
	}
	g = gate(0, vm->epoch, 0, 0);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_GATE_QUERY, &g), EINVAL);
	g = gate(HYPERTRACE_MAX_VMS, vm->epoch, 0, 0);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_GATE_QUERY, &g), EINVAL);
	g = gate(vm->vmid, 0, 0, 0);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_GATE_QUERY, &g), EINVAL);
	/* A query carries no token; suspend/resume require one. */
	g = gate(vm->vmid, vm->epoch, 1, 0);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_GATE_QUERY, &g), EINVAL);
	g = gate(vm->vmid, vm->epoch, 0, 0);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_SUSPEND, &g), EINVAL);
	g = gate(vm->vmid, vm->epoch, 0, 0);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_RESUME, &g), EINVAL);
	/* Only SUSPEND may name a previous owner. */
	g = gate(vm->vmid, vm->epoch, 0, 2);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_GATE_QUERY, &g), EINVAL);
	g = gate(vm->vmid, vm->epoch, 1, 2);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_RESUME, &g), EINVAL);
	/* A stale lifetime is refused. */
	g = gate(vm->vmid, vm->epoch + 1, 0, 0);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_GATE_QUERY, &g), ESTALE);

	/* Initial state: active, no owner. */
	g = gate(vm->vmid, vm->epoch, 0, 0);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_GATE_QUERY, &g), 0);
	KHX_EQ(g.suspended, 0);
	KHX_EQ(g.token[0], 0);
	/* SUSPEND must name the observed owner (none yet). */
	g = gate(vm->vmid, vm->epoch, 0xa1, 0x77);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_SUSPEND, &g), ESTALE);
	g = gate(vm->vmid, vm->epoch, 0xa1, 0);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_SUSPEND, &g), 0);
	KHX_EQ(epoch_live(vm->vmid, vm->epoch), 1);	/* lifetime persists */
	g = gate(vm->vmid, vm->epoch, 0, 0);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_GATE_QUERY, &g), 0);
	KHX_EQ(g.suspended, 1);
	KHX_EQ(g.token[15], 0xa1);
	/* The owner may repeat its suspend; another ticket may not. */
	g = gate(vm->vmid, vm->epoch, 0xa1, 0);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_SUSPEND, &g), 0);
	g = gate(vm->vmid, vm->epoch, 0xb2, 0xa1);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_SUSPEND, &g), EBUSY);
	/* Only the owner resumes. */
	g = gate(vm->vmid, vm->epoch, 0xb2, 0);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_RESUME, &g), ESTALE);
	g = gate(vm->vmid, vm->epoch, 0xa1, 0);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_RESUME, &g), 0);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_RESUME, &g), 0);
	/* A completed ticket cannot suspend again. */
	g = gate(vm->vmid, vm->epoch, 0xa1, 0xa1);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_SUSPEND, &g), EBUSY);
	/* A new ticket must observe the last owner. */
	g = gate(vm->vmid, vm->epoch, 0xc3, 0);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_SUSPEND, &g), ESTALE);
	g = gate(vm->vmid, vm->epoch, 0xc3, 0xa1);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_SUSPEND, &g), 0);
	/* Release succeeds while suspended and clears the owner. */
	KHX_EQ(hypertrace_vm_release(vm->vmid, vm->epoch), 0);
	g = gate(vm->vmid, vm->epoch, 0, 0);
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_EPOCH_GATE_QUERY, &g), ESTALE);
	free(vm, M_TEMP);

	/* Framework-level epoch rules, directly. */
	dtrace_hypertrace_config_lock();
	KHX_EQ(dtrace_hypertrace_epoch_publish(0, 1), EINVAL);
	KHX_EQ(dtrace_hypertrace_epoch_publish(5, 0), EINVAL);
	KHX_EQ(dtrace_hypertrace_epoch_publish(HYPERTRACE_MAX_VMS, 1), EINVAL);
	KHX_EQ(dtrace_hypertrace_epoch_publish(5, 50), 0);
	KHX_EQ(dtrace_hypertrace_epoch_publish(5, 51), EBUSY);
	KHX_EQ(dtrace_hypertrace_epoch_suspend(0, 50), EINVAL);
	KHX_EQ(dtrace_hypertrace_epoch_suspend(5, 0), EINVAL);
	KHX_EQ(dtrace_hypertrace_epoch_suspend(5, 49), ESTALE);
	KHX_EQ(dtrace_hypertrace_epoch_suspend(5, 50), 0);
	KHX_EQ(dtrace_hypertrace_epoch_publish(5, 52), EBUSY);
	KHX_EQ(dtrace_hypertrace_epoch_resume(0, 50), EINVAL);
	KHX_EQ(dtrace_hypertrace_epoch_resume(5, 0), EINVAL);
	KHX_EQ(dtrace_hypertrace_epoch_resume(5, 49), ESTALE);
	KHX_EQ(dtrace_hypertrace_epoch_revoke(5, 49), ESTALE);
	KHX_EQ(dtrace_hypertrace_epoch_revoke(5, 50), 0);
	KHX_EQ(dtrace_hypertrace_epoch_suspended(5, 50), 0);
	KHX_EQ(dtrace_hypertrace_epoch_suspended(0, 50), 0);
	KHX_EQ(dtrace_hypertrace_epoch_revoke(5, 50), ESTALE);
	dtrace_hypertrace_config_unlock();
}

static void
case_ht_handles(void)
{
	struct cons a, b;
	dtrace_handle_lifetime_t ida, idb, q;

	khx_host_case("ht-handles");
	KHX_EQ(cons_open(&a), 0);
	KHX_EQ(cons_open(&b), 0);
	KHX_EQ(cons_ioctl(&a, DTRACEIOC_HANDLE_ID, &ida), 0);
	KHX_EQ(cons_ioctl(&b, DTRACEIOC_HANDLE_ID, &idb), 0);
	KHX_CHECK(ida.serial != 0 && idb.serial == ida.serial + 1);
	KHX_CHECK(memcmp(ida.generation, idb.generation,
	    sizeof(ida.generation)) == 0);
	KHX_CHECK((ida.generation[0] | ida.generation[1]) != 0);
	q = ida;
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_HANDLE_QUERY, &q), 0);
	KHX_EQ(q.retired, 0);
	KHX_EQ(cons_ioctl(&b, DTRACEIOC_HANDLE_QUERY, &q), 0);
	cons_close(&a);
	q = ida;
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_HANDLE_QUERY, &q), 0);
	KHX_EQ(q.retired, 1);
	q = idb;
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_HANDLE_QUERY, &q), 0);
	KHX_EQ(q.retired, 0);
	/* Malformed and foreign queries. */
	q = idb;
	q.retired = 1;
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_HANDLE_QUERY, &q), EINVAL);
	q = idb;
	q.reserved = 1;
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_HANDLE_QUERY, &q), EINVAL);
	q = idb;
	q.serial = 0;
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_HANDLE_QUERY, &q), EINVAL);
	q = idb;
	q.serial += 10;
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_HANDLE_QUERY, &q), ESTALE);
	q = idb;
	q.generation[1] ^= 1;
	KHX_EQ(ht_ioctl(root_td, HYPERTRACE_IOC_HANDLE_QUERY, &q), ESTALE);
	cons_close(&b);
}

/* ---- virtual probes ---------------------------------------------------- */
static dtrace_probedesc_t
vdesc(dtrace_id_t id, const char *prov, const char *mod, const char *func,
    const char *name)
{
	dtrace_probedesc_t d;

	memset(&d, 0, sizeof(d));
	d.dtpd_id = id;
	strlcpy(d.dtpd_provider, prov, sizeof(d.dtpd_provider));
	strlcpy(d.dtpd_mod, mod, sizeof(d.dtpd_mod));
	strlcpy(d.dtpd_func, func, sizeof(d.dtpd_func));
	strlcpy(d.dtpd_name, name, sizeof(d.dtpd_name));
	return (d);
}

static int
vprobe_create(struct cons *c, struct fvm *vm, dtrace_probedesc_t *d, size_t n)
{
	dtrace_vprobe_io_t io;

	memset(&io, 0, sizeof(io));
	io.eprobes = d;
	io.neprobes = n;
	io.vmid = vm->vmid;
	io.epoch = vm->epoch;
	return (cons_ioctl(c, DTRACEIOC_VPROBE_CREATE, &io));
}

static size_t
ht_nprobes(void)
{
	struct sysctl_oid *oid = khx_sysctl_find("hypertrace", "nprobes");
	uint64_t n = 0;
	size_t len = sizeof(n);

	KHX_CHECK(oid != NULL);
	KHX_EQ(khx_sysctl_call(oid, root_td, &n, &len, NULL, 0), 0);
	return ((size_t)n);
}

static void
case_ht_vprobes(void)
{
	struct cons c;
	struct fvm *vm;
	dtrace_probedesc_t d[4], bad;
	dtrace_vprobe_io_t io;
	size_t len;

	khx_host_case("ht-vprobes");
	KHX_EQ(cons_open(&c), 0);
	vm = fvm_new("vp");
	/* ioctl argument validation. */
	memset(&io, 0, sizeof(io));
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_VPROBE_CREATE, &io), EINVAL);
	d[0] = vdesc(1, "gfbt", "kernel", "vm_fault", "entry");
	io.eprobes = d;
	io.neprobes = 1;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_VPROBE_CREATE, &io), EINVAL);
	io.vmid = HYPERTRACE_MAX_VMS;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_VPROBE_CREATE, &io), EINVAL);
	io.vmid = vm->vmid;
	io.neprobes = 64U * 1024U * 1024U / sizeof(dtrace_probedesc_t) + 1;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_VPROBE_CREATE, &io), EINVAL);
	io.neprobes = 1;
	khx_host_user_fault_range(d, 1);
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_VPROBE_CREATE, &io), EFAULT);
	khx_host_user_fault_clear();
	/* Wrong lifetime is refused before anything is created. */
	io.epoch = vm->epoch + 1;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_VPROBE_CREATE, &io), ESTALE);
	KHX_EQ(ht_nprobes(), 0);
	/* Unterminated strings and bad IDs invalidate the whole batch. */
	bad = vdesc(2, "gfbt", "kernel", "f", "entry");
	memset(bad.dtpd_name, 'x', sizeof(bad.dtpd_name));
	d[1] = bad;
	KHX_EQ(vprobe_create(&c, vm, d, 2), EINVAL);
	KHX_EQ(ht_nprobes(), 0);
	bad = vdesc(0, "gfbt", "kernel", "f", "entry");
	d[1] = bad;
	KHX_EQ(vprobe_create(&c, vm, d, 2), EINVAL);
	bad = vdesc(DTRACE_SENSIBLE_PROBELIMIT + 1, "gfbt", "kernel", "f", "e");
	d[1] = bad;
	KHX_EQ(vprobe_create(&c, vm, d, 2), EINVAL);
	/* A valid batch. */
	d[0] = vdesc(1, "gfbt", "kernel", "vm_fault", "entry");
	d[1] = vdesc(2, "gfbt", "kernel", "vm_fault", "return");
	d[2] = vdesc(7, "gsdt", "proc", "exec", "success");
	KHX_EQ(vprobe_create(&c, vm, d, 3), 0);
	KHX_EQ(ht_nprobes(), 3);
	/* A duplicate in a later batch rolls back that batch only. */
	d[0] = vdesc(9, "gfbt", "kernel", "x", "entry");
	d[1] = vdesc(2, "gfbt", "kernel", "dup", "entry");
	KHX_EQ(vprobe_create(&c, vm, d, 2), EEXIST);
	KHX_EQ(ht_nprobes(), 3);
	/* Enumerate the VM namespace through the ordinary probe ioctls. */
	memset(&bad, 0, sizeof(bad));
	bad.dtpd_vmid = vm->vmid;
	bad.dtpd_id = 1;
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_PROBES, &bad), 0);
	KHX_EQ(bad.dtpd_id, 1);
	KHX_EQ(bad.dtpd_vmid, vm->vmid);
	KHX_CHECK(strcmp(bad.dtpd_provider, "gfbt") == 0);
	memset(&bad, 0, sizeof(bad));
	bad.dtpd_vmid = vm->vmid;
	bad.dtpd_id = 1;
	strlcpy(bad.dtpd_provider, "gsdt", sizeof(bad.dtpd_provider));
	KHX_EQ(cons_ioctl(&c, DTRACEIOC_PROBEMATCH, &bad), 0);
	KHX_EQ(bad.dtpd_id, 7);
	/* A jailed reader may not count virtual probes. */
	{
		struct sysctl_oid *oid = khx_sysctl_find("hypertrace",
		    "nprobes");
		uint64_t n;

		len = sizeof(n);
		KHX_EQ(khx_sysctl_call(oid, jail_td, &n, &len, NULL, 0), EPERM);
	}
	/* The VMM still owns the module and probes exist: unload refused. */
	KHX_EQ(khx_module_event("hypertrace", MOD_QUIESCE), EBUSY);
	KHX_EQ(khx_module_event("hypertrace", MOD_UNLOAD), EBUSY);
	/* Closing the registering consumer disables its probes; the VM's
	 * namespace is reclaimed once nothing enables them. */
	cons_close(&c);
	KHX_EQ(ht_nprobes(), 0);
	fvm_free(vm);
}

/* ---- guest firing ------------------------------------------------------ */
static hypertrace_args_t
gargs(uint64_t a0, uint64_t a1, uint64_t a2)
{
	hypertrace_args_t a;

	memset(&a, 0, sizeof(a));
	a.htr_args[0] = a0;
	a.htr_args[1] = a1;
	a.htr_args[2] = a2;
	a.htr_tid = 4321;
	a.htr_pid = 99;
	a.htr_curcpu = 1;
	return (a);
}

static void
case_ht_fire(void)
{
	struct cons c;
	struct fvm *vm, *other;
	struct recs rs;
	dtrace_probedesc_t d[2];
	hypertrace_args_t a;
	dof_hdr_t *dof;
	int matched;

	khx_host_case("ht-fire");
	KHX_EQ(cons_open(&c), 0);
	vm = fvm_new("guest0");
	other = fvm_new("guest1");
	d[0] = vdesc(3, "khx", "mod", "func", "entry");
	d[1] = vdesc(4, "khx", "mod", "func", "return");
	KHX_EQ(vprobe_create(&c, vm, d, 2), 0);
	/* Host program on the guest's probe namespace. */
	dof = dof_load("trace_arg0");
	dof_set_vmid(dof, vm->vmid);
	KHX_EQ(cons_enable_vm(&c, dof, 0, 0, &matched), 0);
	KHX_EQ(matched, 1);
	dof_free(dof);
	KHX_EQ(cons_options(&c, default_opts, nitems(default_opts)), 0);
	KHX_EQ(cons_go(&c), 0);
	a = gargs(0xabc, 2, 3);
	/* Invalid calls are refused before any lookup. */
	KHX_EQ(hypertrace_probe(NULL, 3, &a), EINVAL);
	KHX_EQ(hypertrace_probe(&vm->hdl, 3, NULL), EINVAL);
	KHX_EQ(hypertrace_probe(&vm->hdl, 0, &a), EINVAL);
	KHX_EQ(hypertrace_probe(&vm->hdl, DTRACE_SENSIBLE_PROBELIMIT + 1, &a),
	    EINVAL);
	/* No VMM hooks: the namespace cannot be resolved. */
	vmm_hooks(0);
	KHX_EQ(hypertrace_probe(&vm->hdl, 3, &a), EINVAL);
	vmm_hooks(1);
	/* Unknown probe and wrong VM. */
	KHX_EQ(hypertrace_probe(&vm->hdl, 5, &a), ESRCH);
	KHX_EQ(hypertrace_probe(&other->hdl, 3, &a), ESRCH);
	/* The probe fires and records the guest's argument. */
	KHX_EQ(hypertrace_probe(&vm->hdl, 3, &a), 0);
	KHX_EQ(curthread->t_hypertrace_vmhdl, NULL);
	KHX_CHECK(!khx_interrupts_disabled());
	/* A handle from a previous lifetime of the VMID is stale. */
	vm->epoch++;
	KHX_EQ(hypertrace_probe(&vm->hdl, 3, &a), ESTALE);
	vm->epoch--;
	vmm_getepoch = NULL;
	KHX_EQ(hypertrace_probe(&vm->hdl, 3, &a), ESTALE);
	vmm_getepoch = f_getepoch;
	KHX_EQ(snap_records(&c, 0, &rs), 1);
	KHX_EQ(rs.r[0].vmid, vm->vmid);
	KHX_EQ(rs.r[0].probe, 3);
	KHX_EQ(rs.r[0].val[0], 0xabc);
	KHX_EQ(cons_stop(&c), 0);
	cons_close(&c);
	fvm_free(other);
	fvm_free(vm);
}
