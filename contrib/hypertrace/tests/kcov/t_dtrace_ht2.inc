/* SPDX-License-Identifier: BSD-2-Clause */
/* hypertrace_map.c unit cases and hypertrace.c hook/module cases. */
#include "hypertrace.h"

static hypertrace_probe_t *
mkprobe(uint16_t vmid, dtrace_id_t id)
{
	hypertrace_probe_t *p = kmem_zalloc(sizeof(*p), KM_SLEEP);

	p->htpb_vmid = vmid;
	p->htpb_id = id;
	return (p);
}

/* The map is an exported, self-contained table: test it directly with an
 * independent model (expected occupancy per VM). */
static void
case_ht_map(void)
{
	hypertrace_map_t *m;
	hypertrace_probe_t *p1, *p2, *p3, *dup, *big[9];
	size_t count;
	long live;

	khx_host_case("ht-map");
	live = khx_host_live_tag("solaris");
	m = map_init();
	KHX_EQ(map_insert(NULL, NULL), EINVAL);
	KHX_EQ(map_insert(m, NULL), EINVAL);
	p1 = mkprobe(3, 1);
	KHX_EQ(map_insert(NULL, p1), EINVAL);
	p1->htpb_vmid = HYPERTRACE_MAX_VMS;
	KHX_EQ(map_insert(m, p1), EINVAL);
	p1->htpb_vmid = 3;
	p1->htpb_id = 0;
	KHX_EQ(map_insert(m, p1), EINVAL);
	p1->htpb_id = DTRACE_SENSIBLE_PROBELIMIT + 1;
	KHX_EQ(map_insert(m, p1), EINVAL);
	p1->htpb_id = 1;
	KHX_EQ(map_insert(m, p1), 0);
	/* Growth preserves existing entries. */
	p2 = mkprobe(3, 1000);
	KHX_EQ(map_insert(m, p2), 0);
	KHX_CHECK(map_get(m, 3, 1) == p1);
	KHX_CHECK(map_get(m, 3, 1000) == p2);
	p3 = mkprobe(4, 2);
	KHX_EQ(map_insert(m, p3), 0);
	dup = mkprobe(3, 1000);
	KHX_EQ(map_insert(m, dup), EEXIST);
	/* Lookups outside the table are misses, not faults. */
	KHX_CHECK(map_get(NULL, 3, 1) == NULL);
	KHX_CHECK(map_get(m, HYPERTRACE_MAX_VMS, 1) == NULL);
	KHX_CHECK(map_get(m, 3, 0) == NULL);
	KHX_CHECK(map_get(m, 3, 5000) == NULL);
	KHX_CHECK(map_get(m, 9, 1) == NULL);
	KHX_CHECK(map_get(m, 3, 2) == NULL);
	/* Counting: one VM, or every VM for the host ID. */
	KHX_EQ(map_count(NULL, 3, &count), EINVAL);
	KHX_EQ(map_count(m, 3, NULL), EINVAL);
	KHX_EQ(map_count(m, HYPERTRACE_MAX_VMS, &count), EINVAL);
	KHX_EQ(map_count(m, 3, &count), 0);
	KHX_EQ(count, 2);
	KHX_EQ(map_count(m, 0, &count), 0);
	KHX_EQ(count, 3);
	/* Removal checks identity: a different object at the slot stays. */
	map_rm(NULL, p1);
	map_rm(m, NULL);
	dup->htpb_vmid = HYPERTRACE_MAX_VMS;
	map_rm(m, dup);
	dup->htpb_vmid = 3;
	dup->htpb_id = 0;
	map_rm(m, dup);
	dup->htpb_id = 1000;
	map_rm(m, dup);
	KHX_CHECK(map_get(m, 3, 1000) == p2);
	dup->htpb_id = 100000;		/* beyond the table */
	map_rm(m, dup);
	dup->htpb_vmid = 50;		/* VM without a table */
	map_rm(m, dup);
	map_rm(m, p1);
	KHX_CHECK(map_get(m, 3, 1) == NULL);
	KHX_EQ(map_count(m, 3, &count), 0);
	KHX_EQ(count, 1);
	/* Removing the last probe frees the VM's table. */
	map_rm(m, p2);
	KHX_CHECK(map_get(m, 3, 1000) == NULL);
	KHX_EQ(map_count(m, 0, &count), 0);
	KHX_EQ(count, 1);
	kmem_free(p1, sizeof(*p1));
	kmem_free(p2, sizeof(*p2));
	kmem_free(dup, sizeof(*dup));
	/* Aggregate table storage is bounded: eight full-range VM tables fit,
	 * the ninth does not. */
	for (int i = 0; i < 9; i++) {
		big[i] = mkprobe((uint16_t)(10 + i), DTRACE_SENSIBLE_PROBELIMIT);
		KHX_EQ(map_insert(m, big[i]), i < 7 ? 0 : ENOSPC);
	}
	kmem_free(big[7], sizeof(*big[7]));
	kmem_free(big[8], sizeof(*big[8]));
	/* Teardown frees remaining probes and tables. */
	map_teardown(m);
	map_teardown(NULL);
	KHX_EQ(khx_host_live_tag("solaris"), live);
}

static void
case_ht_hooks(void)
{
	struct fvm *vm;
	uint64_t v;
	char buf[16];

	khx_host_case("ht-hooks");
	vm = fvm_new("hooks");
	vm->regs[5] = 0x55;
	KHX_EQ(hypertrace_gettid(&vm->hdl), 777);
	KHX_CHECK(strcmp(hypertrace_getname(&vm->hdl), "hooks") == 0);
	KHX_EQ(hypertrace_getns(&vm->hdl), vm->vmid);
	KHX_EQ(hypertrace_getreg(NULL, 5, &v), ENXIO);
	KHX_EQ(hypertrace_getreg(&vm->hdl, 5, NULL), ENXIO);
	KHX_EQ(hypertrace_getreg(&vm->hdl, 5, &v), 0);
	KHX_EQ(v, 0x55);
	KHX_EQ(hypertrace_guest_copyin(NULL, vm->gbase, buf, 1), EINVAL);
	KHX_EQ(hypertrace_guest_copyin(&vm->hdl, vm->gbase, NULL, 1), EINVAL);
	KHX_EQ(hypertrace_guest_copyin(&vm->hdl, vm->gbase, buf, 0), EINVAL);
	strlcpy(vm->mem, "guest", sizeof(vm->mem));
	KHX_EQ(hypertrace_guest_copyin(&vm->hdl, vm->gbase, buf, 6), 0);
	KHX_CHECK(strcmp(buf, "guest") == 0);
	KHX_EQ(hypertrace_guest_copyin(&vm->hdl, vm->gbase - 1, buf, 6), EFAULT);
	/* User-space accessors are word-sized only. */
	KHX_EQ(hypertrace_guest_user_copyin(NULL, vm->ubase, buf, 8), EINVAL);
	KHX_EQ(hypertrace_guest_user_copyin(&vm->hdl, vm->ubase, NULL, 8),
	    EINVAL);
	KHX_EQ(hypertrace_guest_user_copyin(&vm->hdl, vm->ubase, buf, 0), EINVAL);
	KHX_EQ(hypertrace_guest_user_copyin(&vm->hdl, vm->ubase, buf, 9), EINVAL);
	KHX_EQ(hypertrace_guest_user_copyout(NULL, vm->ubase, buf, 8), EINVAL);
	KHX_EQ(hypertrace_guest_user_copyout(&vm->hdl, vm->ubase, NULL, 8),
	    EINVAL);
	KHX_EQ(hypertrace_guest_user_copyout(&vm->hdl, vm->ubase, buf, 0),
	    EINVAL);
	KHX_EQ(hypertrace_guest_user_copyout(&vm->hdl, vm->ubase, buf, 9),
	    EINVAL);
	memcpy(buf, "12345678", 8);
	KHX_EQ(hypertrace_guest_user_copyout(&vm->hdl, vm->ubase + 8, buf, 8), 0);
	memset(buf, 0, sizeof(buf));
	KHX_EQ(hypertrace_guest_user_copyin(&vm->hdl, vm->ubase + 8, buf, 8), 0);
	KHX_CHECK(memcmp(buf, "12345678", 8) == 0);
	/* Without a VMM every accessor reports the absence. */
	vmm_hooks(0);
	KHX_EQ(hypertrace_gettid(&vm->hdl), 0);
	KHX_CHECK(hypertrace_getname(&vm->hdl) == NULL);
	KHX_EQ(hypertrace_getns(&vm->hdl), 0);
	KHX_EQ(hypertrace_getreg(&vm->hdl, 5, &v), ENXIO);
	KHX_EQ(hypertrace_guest_copyin(&vm->hdl, vm->gbase, buf, 1), EOPNOTSUPP);
	KHX_EQ(hypertrace_guest_user_copyin(&vm->hdl, vm->ubase, buf, 8),
	    EOPNOTSUPP);
	KHX_EQ(hypertrace_guest_user_copyout(&vm->hdl, vm->ubase, buf, 8),
	    EOPNOTSUPP);
	vmm_hooks(1);
	/* Probe state hooks on unknown probes. */
	KHX_EQ(hypertrace_is_enabled(vm->vmid, 77), -ESRCH);
	KHX_EQ(hypertrace_enable(vm->vmid, 77), ESRCH);
	KHX_EQ(hypertrace_disable(vm->vmid, 77), ESRCH);
	KHX_EQ(hypertrace_suspend(vm->vmid, 77), ESRCH);
	KHX_EQ(hypertrace_resume(vm->vmid, 77), ESRCH);
	KHX_EQ(hypertrace_rmprobe(vm->vmid, 77), ESRCH);
	/* Epoch check rules (callers hold the configuration locks). */
	dtrace_hypertrace_config_lock();
	KHX_EQ(hypertrace_check_epoch(0, vm->epoch), ESTALE);
	KHX_EQ(hypertrace_check_epoch(HYPERTRACE_MAX_VMS, 1), ESTALE);
	KHX_EQ(hypertrace_check_epoch(vm->vmid, 0), ESTALE);
	KHX_EQ(hypertrace_check_epoch(vm->vmid, vm->epoch + 1), ESTALE);
	KHX_EQ(hypertrace_check_epoch(vm->vmid, vm->epoch), 0);
	/* create_probes argument validation. */
	{
		dtrace_probedesc_t d = vdesc(1, "p", "m", "f", "n");

		KHX_EQ(hypertrace_create_probes(0, vm->epoch, &d, 1), EINVAL);
		KHX_EQ(hypertrace_create_probes(HYPERTRACE_MAX_VMS, 1, &d, 1),
		    EINVAL);
		KHX_EQ(hypertrace_create_probes(vm->vmid, vm->epoch, NULL, 1),
		    EINVAL);
		KHX_EQ(hypertrace_create_probes(vm->vmid, vm->epoch, &d, 0),
		    EINVAL);
		KHX_EQ(hypertrace_create_probes(vm->vmid, vm->epoch, &d,
		    DTRACE_SENSIBLE_PROBELIMIT + 1), EINVAL);
	}
	dtrace_hypertrace_config_unlock();
	fvm_free(vm);
}

/* Provider/probe lifecycle through the hooks dtrace.c calls. */
static void
case_ht_probe_state(void)
{
	struct cons c;
	struct fvm *vm;
	dtrace_probedesc_t d[3];

	khx_host_case("ht-probe-state");
	KHX_EQ(cons_open(&c), 0);
	vm = fvm_new("state");
	d[0] = vdesc(1, "pa", "m", "f", "entry");
	d[1] = vdesc(2, "pa", "m", "f", "return");
	d[2] = vdesc(3, "pb", "m", "g", "entry");
	KHX_EQ(vprobe_create(&c, vm, d, 3), 0);
	/* Probes are created enabled and running. */
	KHX_EQ(hypertrace_is_enabled(vm->vmid, 1), 1);
	KHX_EQ(hypertrace_suspend(vm->vmid, 1), 0);
	KHX_EQ(hypertrace_is_enabled(vm->vmid, 1), 1);
	{
		hypertrace_args_t a = gargs(1, 2, 3);

		/* Suspended: the probe exists but may not run. */
		KHX_EQ(hypertrace_probe(&vm->hdl, 1, &a), EACCES);
		KHX_EQ(hypertrace_resume(vm->vmid, 1), 0);
		KHX_EQ(hypertrace_probe(&vm->hdl, 1, &a), 0);
		KHX_EQ(hypertrace_disable(vm->vmid, 1), 0);
		KHX_EQ(hypertrace_probe(&vm->hdl, 1, &a), EACCES);
		KHX_EQ(hypertrace_enable(vm->vmid, 1), 0);
	}
	/* An enabled probe cannot be removed. */
	KHX_EQ(hypertrace_rmprobe(vm->vmid, 1), EAGAIN);
	/* A VM with probes from an old lifetime refuses a new consumer
	 * until those probes are gone; a suspended gate refuses too. */
	dtrace_hypertrace_config_lock();
	KHX_EQ(dtrace_hypertrace_epoch_suspend(vm->vmid, vm->epoch), 0);
	KHX_EQ(hypertrace_check_epoch(vm->vmid, vm->epoch), EBUSY);
	KHX_EQ(dtrace_hypertrace_epoch_resume(vm->vmid, vm->epoch), 0);
	dtrace_hypertrace_config_unlock();
	cons_close(&c);
	fvm_free(vm);
}

static void
case_ht_module(void)
{
	khx_host_case("ht-module");
	KHX_EQ(khx_module_event("hypertrace", MOD_SHUTDOWN), 0);
	KHX_EQ(khx_module_event("hypertrace", 99), EOPNOTSUPP);
	/* The VMM still holds the hooks. */
	KHX_EQ(khx_module_event("hypertrace", MOD_QUIESCE), EBUSY);
	KHX_EQ(khx_module_event("hypertrace", MOD_UNLOAD), EBUSY);
	vmm_hooks(0);
	KHX_EQ(khx_module_event("hypertrace", MOD_QUIESCE), 0);
	KHX_EQ(khx_module_event("hypertrace", MOD_UNLOAD), 0);
	KHX_CHECK(hypertrace_create_probes == NULL);
	KHX_CHECK(hypertrace_getns == NULL);
	/* Reload restores the hooks with an empty map and provider table. */
	KHX_EQ(khx_module_event("hypertrace", MOD_LOAD), 0);
	KHX_CHECK(hypertrace_create_probes != NULL);
	vmm_hooks(1);
}

static void
case_ht_limits(void)
{
	struct cons c;
	struct fvm *vm, *vms[16];
	dtrace_probedesc_t *d;
	char name[32];
	size_t n;
	int i, v;

	khx_host_case("ht-limits");
	KHX_EQ(cons_open(&c), 0);
	d = malloc(sizeof(*d) * 300, M_TEMP, M_WAITOK | M_ZERO);
	/* Each VM may use at most 256 distinct providers; the batch that
	 * exceeds the bound is rolled back completely. */
	vm = fvm_new("limits");
	for (i = 0; i < 257; i++) {
		snprintf(name, sizeof(name), "prov%d", i);
		d[i] = vdesc(i + 1, name, "m", "f", "n");
	}
	KHX_EQ(vprobe_create(&c, vm, d, 257), ENOSPC);
	KHX_EQ(ht_nprobes(), 0);
	KHX_EQ(vprobe_create(&c, vm, d, 256), 0);
	KHX_EQ(ht_nprobes(), 256);
	/* The same provider across probes is reference counted. */
	d[0] = vdesc(300, "prov0", "m", "g", "n");
	KHX_EQ(vprobe_create(&c, vm, d, 1), 0);
	cons_close(&c);
	KHX_EQ(ht_nprobes(), 0);
	fvm_free(vm);

	/* The global provider table holds 4096 names: sixteen VMs with 256
	 * providers each fill it, and a further name finds no slot. */
	KHX_EQ(cons_open(&c), 0);
	for (v = 0; v < 16; v++) {
		vms[v] = fvm_new("fill");
		for (i = 0; i < 256; i++) {
			snprintf(name, sizeof(name), "v%dp%d", v, i);
			d[i] = vdesc(i + 1, name, "m", "f", "n");
		}
		KHX_EQ(vprobe_create(&c, vms[v], d, 256), 0);
	}
	vm = fvm_new("overflow");
	d[0] = vdesc(1, "onemore", "m", "f", "n");
	KHX_EQ(vprobe_create(&c, vm, d, 1), ENOSPC);
	/* An existing name is still found when the table is full. */
	d[0] = vdesc(1, "v0p0", "m", "f", "n");
	KHX_EQ(vprobe_create(&c, vm, d, 1), 0);
	n = ht_nprobes();
	KHX_EQ(n, 16 * 256 + 1);
	cons_close(&c);
	for (v = 0; v < 16; v++)
		fvm_free(vms[v]);
	fvm_free(vm);
	KHX_EQ(ht_nprobes(), 0);

	/* Unterminated provider, module and function names. */
	KHX_EQ(cons_open(&c), 0);
	vm = fvm_new("strings");
	d[0] = vdesc(1, "p", "m", "f", "n");
	memset(d[0].dtpd_provider, 'p', sizeof(d[0].dtpd_provider));
	KHX_EQ(vprobe_create(&c, vm, d, 1), EINVAL);
	d[0] = vdesc(1, "p", "m", "f", "n");
	memset(d[0].dtpd_mod, 'm', sizeof(d[0].dtpd_mod));
	KHX_EQ(vprobe_create(&c, vm, d, 1), EINVAL);
	d[0] = vdesc(1, "p", "m", "f", "n");
	memset(d[0].dtpd_func, 'f', sizeof(d[0].dtpd_func));
	KHX_EQ(vprobe_create(&c, vm, d, 1), EINVAL);

	/* A VMID whose old lifetime still has probes is not reissued. */
	d[0] = vdesc(1, "p", "m", "f", "n");
	KHX_EQ(vprobe_create(&c, vm, d, 1), 0);
	{
		uint16_t old = vm->vmid, id;
		uint64_t ep;

		KHX_EQ(hypertrace_vm_release(vm->vmid, vm->epoch), 0);
		/* hypertrace_probe trusts the VMM's handle epoch; a destroyed
		 * VM has no handle.  Origin gating is checked separately. */
		{
			hypertrace_args_t a = gargs(1, 2, 3);

			KHX_EQ(hypertrace_probe(&vm->hdl, 1, &a), 0);
		}
		KHX_EQ(hypertrace_vm_alloc(&id, &ep), 0);
		KHX_CHECK(id != old);
		KHX_EQ(hypertrace_vm_release(id, ep), 0);
		/* Probes keep the module loaded even without a VMM. */
		vmm_hooks(0);
		KHX_EQ(khx_module_event("hypertrace", MOD_QUIESCE), EBUSY);
		KHX_EQ(khx_module_event("hypertrace", MOD_UNLOAD), EBUSY);
		vmm_hooks(1);
	}
	cons_close(&c);
	free(vm, M_TEMP);

	/* The lifetime token is never zero. */
	{
		uint16_t id;
		uint64_t ep;

		khx_random_zero_next(2);
		KHX_EQ(hypertrace_vm_alloc(&id, &ep), 0);
		KHX_CHECK(ep != 0);
		KHX_EQ(hypertrace_vm_release(id, ep), 0);
	}

	/* A VMM that reports an out-of-range VM ID is refused. */
	{
		struct fvm bogus;
		hypertrace_args_t a = gargs(1, 2, 3);

		memset(&bogus, 0, sizeof(bogus));
		bogus.vmid = HYPERTRACE_MAX_VMS;
		KHX_EQ(hypertrace_probe(&bogus.hdl, 1, &a), EINVAL);
	}

	/* The probe-count sysctl reports a short buffer. */
	{
		struct sysctl_oid *oid = khx_sysctl_find("hypertrace",
		    "nprobes");
		uint32_t small;
		size_t len = sizeof(small);

		KHX_EQ(khx_sysctl_call(oid, root_td, &small, &len, NULL, 0),
		    ENOMEM);
	}
	free(d, M_TEMP);
}
