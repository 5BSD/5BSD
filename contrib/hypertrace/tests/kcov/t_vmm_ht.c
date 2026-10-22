/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Tests for the amd64 VMM HyperTrace hooks, with sys/amd64/vmm/vmm.c,
 * sys/dev/vmm/vmm_vm.c, sys/amd64/vmm/x86.c and
 * sys/amd64/vmm/vmm_dev_machdep.c compiled unmodified as kernel
 * translation units (khx_vmm.c models the backend, guest memory and the
 * HyperTrace provider).
 *
 * Oracles are independent of the code under test:
 *  - the guest hypercall ABI of machine/bhyve_hypercall.h (call numbers,
 *    return codes, SysV argument registers for hypercall_dtrace_probe(id,
 *    args, tid)) and the hypertrace_args_t validity contract of
 *    sys/hypertrace.h;
 *  - the guest's own detector, bhyve_hypercalls_enabled(), run against the
 *    VMM's CPUID emulation;
 *  - an explicit guest page table with user/write bits (a CPL 3 access may
 *    only reach user pages, a write only writable pages, a failed copy
 *    never publishes partial data);
 *  - identity bookkeeping of the provider recorder (every allocated VM
 *    identity is released exactly once, a reset installs a fresh one).
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/module.h>
#include <sys/hypertrace.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include <machine/frame.h>
#include <machine/vmm.h>
#include <machine/vmm_dev.h>
#include <machine/bhyve_hypercall.h>
#include <dev/vmm/vmm_dev.h>
#include <dev/vmm/vmm_mem.h>
#include <sys/mman.h>
#include <dev/vmm/vmm_mem.h>
#include <dev/vmm/vmm_vm.h>

#include "x86.h"
#include "khx_kern.h"
#include "khx_vmm.h"

int vm_run(struct vcpu *vcpu);

/* ---- CPUID: the guest's detector against the VMM's emulation ------------ */
static struct vcpu *cpuid_vcpu;
static int cpuid_nesting;

void
khx_do_cpuid(u_int ax, u_int *p)
{
	uint64_t a = ax, b = 0, c = 0, d = 0;

	if (cpuid_vcpu == NULL || cpuid_nesting != 0) {
		khx_hw_do_cpuid(ax, p);
		return;
	}
	cpuid_nesting++;
	(void)x86_emulate_cpuid(cpuid_vcpu, &a, &b, &c, &d);
	cpuid_nesting--;
	p[0] = a;
	p[1] = b;
	p[2] = c;
	p[3] = d;
}

/* ---- guest layout -------------------------------------------------------- */
#define	GLA_KDATA	0x7000000ULL	/* supervisor page -> GPA page 0 */
#define	GLA_KDATA2	0x7001000ULL	/* supervisor page -> GPA page 1 */
#define	GLA_USER	0x400000ULL	/* user, writable  -> GPA page 2 */
#define	GLA_USER2	0x401000ULL	/* user, writable  -> GPA page 3 */
#define	GLA_URO		0x402000ULL	/* user, read-only -> GPA page 4 */
#define	GLA_HOLE	0x403000ULL	/* unmapped */

static void
guest_map(void)
{
	khx_gla_unmap_all();
	khx_gla_map(GLA_KDATA, KHX_GPA_BASE + 0 * PAGE_SIZE, 0, 1);
	khx_gla_map(GLA_KDATA2, KHX_GPA_BASE + 1 * PAGE_SIZE, 0, 1);
	khx_gla_map(GLA_USER, KHX_GPA_BASE + 2 * PAGE_SIZE, 1, 1);
	khx_gla_map(GLA_USER2, KHX_GPA_BASE + 3 * PAGE_SIZE, 1, 1);
	khx_gla_map(GLA_URO, KHX_GPA_BASE + 4 * PAGE_SIZE, 1, 0);
	memset(khx_gmem, 0, sizeof(khx_gmem));
	khx_gla_error = 0;
	khx_gpa_hold_fail = -1;
}

/* Guest memory at a guest linear address of the layout above. */
static void *
gmem(uint64_t gla)
{
	static const struct {
		uint64_t gla;
		int page;
	} map[] = {
		{ GLA_KDATA, 0 }, { GLA_KDATA2, 1 }, { GLA_USER, 2 },
		{ GLA_USER2, 3 }, { GLA_URO, 4 },
	};

	for (size_t i = 0; i < nitems(map); i++)
		if (trunc_page(gla) == map[i].gla)
			return (&khx_gmem[map[i].page * PAGE_SIZE +
			    (gla & PAGE_MASK)]);
	panic("gmem: unmapped %#jx", (uintmax_t)gla);
}

/* ---- VM fixture ---------------------------------------------------------- */
static struct vm *
vm_new(const char *name)
{
	struct vm *vm;

	KHX_EQ(vm_create(name, &vm), 0);
	return (vm);
}

static void
vm_gone(struct vm *vm)
{
	vm_destroy(vm);
}

static struct vm_guest_paging
paging(int cpl, enum vm_paging_mode mode)
{
	struct vm_guest_paging p;

	memset(&p, 0, sizeof(p));
	p.cpl = cpl;
	p.cpu_mode = CPU_MODE_64BIT;
	p.paging_mode = mode;
	return (p);
}

/* A frozen, active vCPU whose CS has the given privilege level. */
static struct vcpu *
vcpu_new(struct vm *vm, int id, int dpl)
{
	struct vcpu *vcpu = vm_alloc_vcpu(vm, id);
	struct khx_vcpu *kv;

	KHX_CHECK(vcpu != NULL);
	KHX_EQ(vm_activate_cpu(vcpu), 0);
	KHX_EQ(vcpu_set_state(vcpu, VCPU_FROZEN, true), 0);
	kv = khx_vmm_vcpu(vcpu);
	kv->desc_access[VM_REG_GUEST_CS] = (uint32_t)dpl << 5;
	kv->desc_base[VM_REG_GUEST_DS] = 0;
	return (vcpu);
}

/* Run one hypercall exit: the guest executed vmcall with RAX = hcid and the
 * SysV argument registers set; returns the guest's RAX afterwards. */
static uint64_t
hypercall(struct vcpu *vcpu, uint64_t hcid, uint64_t a0, uint64_t a1,
    uint64_t a2, int cpl)
{
	struct khx_vcpu *kv = khx_vmm_vcpu(vcpu);
	struct khx_exit ex[2];
	long holds = khx_gpa_holds, runs = khx_vmm_runs;

	memset(ex, 0, sizeof(ex));
	ex[0].exitcode = VM_EXITCODE_HYPERCALL;
	ex[0].paging = paging(cpl, PAGING_MODE_64);
	ex[1].exitcode = VM_EXITCODE_BOGUS;	/* back to userland */
	khx_vmm_script(ex, 2);
	kv->regs[VM_REG_GUEST_RAX] = hcid;
	kv->regs[VM_REG_GUEST_RDI] = a0;
	kv->regs[VM_REG_GUEST_RSI] = a1;
	kv->regs[VM_REG_GUEST_RDX] = a2;
	kv->regs[VM_REG_GUEST_RCX] = 0xc;
	kv->regs[VM_REG_GUEST_R8] = 0x8;
	kv->regs[VM_REG_GUEST_R9] = 0x9;
	KHX_EQ(vm_run(vcpu), 0);
	/* The hypercall exit resumed the guest, which then left for userland. */
	KHX_EQ(khx_vmm_runs, runs + 2);
	KHX_EQ(vcpu_get_state(vcpu, NULL), VCPU_FROZEN);
	/* Every guest page held for a copy was released. */
	KHX_EQ(khx_gpa_holds, holds);
	return (kv->regs[VM_REG_GUEST_RAX]);
}

static hypertrace_args_t *
guest_args(uint64_t gla)
{
	hypertrace_args_t *a = gmem(gla);

	memset(a, 0, sizeof(*a));
	for (int i = 0; i < HYPERTRACE_ARGS_MAX; i++)
		a->htr_args[i] = 0x100 + i;
	a->htr_curcpu = 77;		/* guest-chosen; the VMM overrides */
	a->htr_tid = 1234;
	return (a);
}

/* ---- module hooks -------------------------------------------------------- */
static int
hooks_installed(void)
{
	return ((vmm_getepoch != NULL) + (vmm_gettid != NULL) +
	    (vmm_getid != NULL) + (vmm_getname != NULL) +
	    (vmm_getreg != NULL) + (vmm_guest_copyin != NULL) +
	    (vmm_guest_user_copyin != NULL) + (vmm_guest_user_copyout != NULL));
}

static void
case_modinit(void)
{
	int unlocks;

	khx_host_case("modinit");
	/* The vmm module's MOD_LOAD (DECLARE_MODULE, run by the SYSINITs)
	 * installed the hooks; MOD_UNLOAD withdraws them. */
	KHX_EQ(hooks_installed(), 8);
	KHX_EQ(khx_module_event("vmm", MOD_UNLOAD), 0);
	KHX_EQ(hooks_installed(), 0);
	/* No VMX/SVM: nothing is published. */
	khx_vmm_hw_supported = 0;
	unlocks = khx_ht_config_unlocks;
	KHX_EQ(vmm_modinit(), ENXIO);
	KHX_EQ(hooks_installed(), 0);
	KHX_EQ(khx_ht_config_unlocks, unlocks);
	khx_vmm_hw_supported = 1;
	/* A backend that fails to initialize publishes no HyperTrace hook. */
	khx_vmm_modinit_error = EIO;
	KHX_EQ(vmm_modinit(), EIO);
	KHX_EQ(hooks_installed(), 0);
	KHX_EQ(khx_ht_config_unlocks, unlocks);
	khx_vmm_modinit_error = 0;
	/* Success installs all eight hooks inside one configuration lock. */
	KHX_EQ(vmm_modinit(), 0);
	KHX_EQ(hooks_installed(), 8);
	KHX_EQ(khx_ht_config_unlocks, unlocks + 1);
	KHX_EQ(khx_ht_hooks_at_unlock, 8);
	KHX_EQ(khx_ht_config_depth, 0);
	/* Cleanup withdraws them, also inside the lock. */
	KHX_EQ(vmm_modcleanup(), 0);
	KHX_EQ(hooks_installed(), 0);
	KHX_EQ(khx_ht_config_unlocks, unlocks + 2);
	KHX_EQ(khx_ht_hooks_at_unlock, 0);
	/* Without a dedicated IPI vector the common one is used and not
	 * freed. */
	khx_vmm_ipi = -1;
	KHX_EQ(vmm_modinit(), 0);
	KHX_EQ(vmm_modcleanup(), 0);
	khx_vmm_ipi = 250;
	KHX_EQ(khx_module_event("vmm", MOD_LOAD), 0);
	KHX_EQ(hooks_installed(), 8);
}

/* ---- VM identity lifecycle ---------------------------------------------- */
static void
destroy_cb(void *arg)
{
	vm_destroy(arg);
}

static void
case_identity(void)
{
	struct vm *vm, *vm2;
	long live = khx_ht_live;
	uint16_t id;
	uint64_t epoch;

	khx_host_case("identity");
	vm = vm_new("idvm");
	KHX_EQ(khx_ht_live, live + 1);
	id = vm_get_id(vm);
	epoch = vm_get_hypertrace_epoch(vm);
	KHX_CHECK(id != 0 && epoch != 0);
	KHX_CHECK(khx_ht_is_live(id, epoch));
	/* Two VMs never share an identity. */
	vm2 = vm_new("idvm2");
	KHX_CHECK(vm_get_id(vm2) != id);
	KHX_CHECK(vm_get_hypertrace_epoch(vm2) != epoch);
	vm_gone(vm2);
	KHX_EQ(khx_ht_live, live + 1);
	/* Destruction revokes the identity. */
	vm_gone(vm);
	KHX_CHECK(!khx_ht_is_live(id, epoch));
	KHX_EQ(khx_ht_live, live);

	/* Creation fails cleanly when no identity is available ... */
	khx_ht_alloc_error = ENOSPC;
	KHX_EQ(vm_create("noid", &vm), ENOSPC);
	khx_ht_alloc_error = 0;
	KHX_EQ(khx_ht_live, live);
	/* ... and releases the identity on every later failure. */
	khx_vmm_coordinator_error = ENOMEM;
	KHX_EQ(vm_create("nocoord", &vm), ENOMEM);
	khx_vmm_coordinator_error = 0;
	KHX_EQ(khx_ht_live, live);
	khx_vmm_vmspace_fail = 1;
	KHX_EQ(vm_create("nomem", &vm), ENOMEM);
	khx_vmm_vmspace_fail = 0;
	KHX_EQ(khx_ht_live, live);

	/* A VM whose identity cannot be revoked must not be torn down while
	 * HyperTrace may still deliver its probes: destruction panics. */
	vm = vm_new("stuck");
	khx_ht_release_error = EBUSY;
	khx_ht_release_fail_vmid = 0;
	KHX_CHECK(KHX_PANICS(destroy_cb, vm));
	khx_ht_release_error = 0;
	khx_release_locks_after_panic(curthread);
	vm_gone(vm);
	KHX_EQ(khx_ht_live, live);
}

static int
reinit(struct vm *vm)
{
	int error;

	/* vmmdev holds the memory-segment write lock across VM_REINIT. */
	vm_xlock_memsegs(vm);
	error = vm_reinit(vm);
	vm_unlock_memsegs(vm);
	return (error);
}

static void
case_reset(void)
{
	struct vm *vm;
	struct vcpu *vcpu;
	long live = khx_ht_live;
	uint16_t id, id2;
	uint64_t epoch, epoch2;

	khx_host_case("reset");
	vm = vm_new("resetvm");
	vcpu = vm_alloc_vcpu(vm, 0);
	id = vm_get_id(vm);
	epoch = vm_get_hypertrace_epoch(vm);

	/* A reset is a new VM lifetime: a fresh identity replaces the old. */
	KHX_EQ(vcpu_set_state(vcpu, VCPU_FROZEN, true), 0);
	KHX_EQ(reinit(vm), 0);
	id2 = vm_get_id(vm);
	epoch2 = vm_get_hypertrace_epoch(vm);
	KHX_CHECK(epoch2 != epoch);
	KHX_CHECK(!khx_ht_is_live(id, epoch));
	KHX_CHECK(khx_ht_is_live(id2, epoch2));
	KHX_EQ(khx_ht_live, live + 1);

	/* Every failure leaves the VM's identity unchanged and live, and the
	 * reserved replacement is released. */
	khx_ht_alloc_error = ENOSPC;
	KHX_EQ(reinit(vm), ENOSPC);
	khx_ht_alloc_error = 0;
	KHX_EQ(vcpu_set_state(vcpu, VCPU_IDLE, false), 0);
	KHX_EQ(reinit(vm), EBUSY);	/* a vCPU that is not frozen */
	KHX_EQ(vcpu_set_state(vcpu, VCPU_FROZEN, true), 0);
	khx_vmm_coordinator_reset_error = EAGAIN;
	KHX_EQ(reinit(vm), EAGAIN);
	khx_vmm_coordinator_reset_error = 0;
	khx_vmm_ppt_error = EIO;
	KHX_EQ(reinit(vm), EIO);
	khx_vmm_ppt_error = 0;
	khx_ht_release_error = EBUSY;
	khx_ht_release_fail_vmid = id2;
	KHX_EQ(reinit(vm), EBUSY);	/* old identity cannot be revoked */
	khx_ht_release_error = 0;
	khx_ht_release_fail_vmid = 0;
	KHX_EQ(vm_get_id(vm), id2);
	KHX_EQ(vm_get_hypertrace_epoch(vm), epoch2);
	KHX_CHECK(khx_ht_is_live(id2, epoch2));
	KHX_EQ(khx_ht_live, live + 1);
	/* A VM whose vCPUs are not all suspended cannot be reset. */
	KHX_EQ(vm_activate_cpu(vcpu), 0);
	KHX_EQ(reinit(vm), EBUSY);
	KHX_EQ(khx_ht_live, live + 1);

	vm_gone(vm);
	KHX_EQ(khx_ht_live, live);
}

/* ---- the DTrace probe hypercall ----------------------------------------- */
static void
case_hypercall_probe(void)
{
	struct vm *vm;
	struct vcpu *vcpu;
	hypertrace_args_t *a;
	uint64_t *pcs;
	long probes;

	khx_host_case("hypercall-probe");
	guest_map();
	vm = vm_new("probevm");
	vcpu = vcpu_new(vm, 1, 0);

	/* hypercall_dtrace_probe(id 42, &args, tid 900) from ring 0. */
	a = guest_args(GLA_KDATA + 0x100);
	pcs = gmem(GLA_KDATA + 0x800);
	pcs[0] = 0xffffffff80123456ULL;
	pcs[1] = 0xffffffff80654321ULL;
	a->htr_pcstack = (uintptr_t *)(uintptr_t)(GLA_KDATA + 0x800);
	a->htr_pcstack_count = 2;
	a->htr_present = HYPERTRACE_ARGS_WALLTIME_VALID;
	a->htr_entry = 1;
	probes = khx_ht_probes;
	KHX_EQ(hypercall(vcpu, HYPERCALL_DTRACE_PROBE, 42, GLA_KDATA + 0x100,
	    900, 0), HYPERCALL_RET_SUCCESS);
	KHX_EQ(khx_ht_probes, probes + 1);
	KHX_EQ(khx_ht_last.id, 42);
	/* The provider sees this VM's identity and name, the guest tid from
	 * the third argument and the probing vCPU, not the guest's claim. */
	KHX_EQ(khx_ht_last.vmid, vm_get_id(vm));
	KHX_EQ(khx_ht_last.epoch, vm_get_hypertrace_epoch(vm));
	KHX_EQ(khx_ht_last.tid, 900);
	KHX_EQ(strcmp(khx_ht_last.name, "probevm"), 0);
	KHX_EQ(khx_ht_last.vcpu, 1);
	KHX_EQ(khx_ht_last.args0, 0x100);
	KHX_EQ(khx_ht_last.args9, 0x109);
	/* Guest registers and memory are reachable through the handle while
	 * the probe runs. */
	KHX_EQ(khx_ht_last.rax, HYPERCALL_DTRACE_PROBE);
	KHX_EQ(khx_ht_last.getreg_bad, EINVAL);
	KHX_EQ(khx_ht_last.pcstack_count, 2);
	KHX_EQ(khx_ht_last.copyin_error, 0);
	KHX_EQ(khx_ht_last.pc0, 0xffffffff80123456ULL);

	/* The argument block may straddle two guest pages. */
	a = guest_args(GLA_KDATA + PAGE_SIZE - 40);
	(void)a;
	KHX_EQ(hypercall(vcpu, HYPERCALL_DTRACE_PROBE, 43,
	    GLA_KDATA + PAGE_SIZE - 40, 1, 0), HYPERCALL_RET_SUCCESS);
	KHX_EQ(khx_ht_last.id, 43);
	KHX_EQ(khx_ht_last.args9, 0x109);

	/* A provider error is reported to the guest. */
	guest_args(GLA_KDATA + 0x100);
	khx_ht_probe_error = ENOENT;
	KHX_EQ(hypercall(vcpu, HYPERCALL_DTRACE_PROBE, 42, GLA_KDATA + 0x100,
	    900, 0), HYPERCALL_RET_ERROR);
	khx_ht_probe_error = 0;

	/* Invalid probe identifiers and thread ids never reach the provider. */
	probes = khx_ht_probes;
	KHX_EQ(hypercall(vcpu, HYPERCALL_DTRACE_PROBE, 0, GLA_KDATA + 0x100,
	    900, 0), HYPERCALL_RET_ERROR);
	KHX_EQ(hypercall(vcpu, HYPERCALL_DTRACE_PROBE, (uint64_t)INT_MAX + 1,
	    GLA_KDATA + 0x100, 900, 0), HYPERCALL_RET_ERROR);
	KHX_EQ(hypercall(vcpu, HYPERCALL_DTRACE_PROBE, 42, GLA_KDATA + 0x100,
	    (uint64_t)INT_MAX + 1, 0), HYPERCALL_RET_ERROR);
	/* Argument blocks that cannot be copied in. */
	KHX_EQ(hypercall(vcpu, HYPERCALL_DTRACE_PROBE, 42, 0, 900, 0),
	    HYPERCALL_RET_ERROR);
	KHX_EQ(hypercall(vcpu, HYPERCALL_DTRACE_PROBE, 42, GLA_HOLE, 900, 0),
	    HYPERCALL_RET_ERROR);
	KHX_EQ(hypercall(vcpu, HYPERCALL_DTRACE_PROBE, 42, ~0ULL - 8, 900, 0),
	    HYPERCALL_RET_ERROR);
	khx_vmm_vcpu(vcpu)->desc_base[VM_REG_GUEST_DS] = ~0ULL;
	KHX_EQ(hypercall(vcpu, HYPERCALL_DTRACE_PROBE, 42, 0x10, 900, 0),
	    HYPERCALL_RET_ERROR);
	khx_vmm_vcpu(vcpu)->desc_base[VM_REG_GUEST_DS] = 0;
	khx_gla_error = EFAULT;
	KHX_EQ(hypercall(vcpu, HYPERCALL_DTRACE_PROBE, 42, GLA_KDATA + 0x100,
	    900, 0), HYPERCALL_RET_ERROR);
	khx_gla_error = 0;
	khx_gpa_hold_fail = 0;
	KHX_EQ(hypercall(vcpu, HYPERCALL_DTRACE_PROBE, 42, GLA_KDATA + 0x100,
	    900, 0), HYPERCALL_RET_ERROR);
	/* Straddling block whose second page cannot be held. */
	guest_args(GLA_KDATA + PAGE_SIZE - 40);
	khx_gpa_hold_fail = 1;
	KHX_EQ(hypercall(vcpu, HYPERCALL_DTRACE_PROBE, 42,
	    GLA_KDATA + PAGE_SIZE - 40, 900, 0), HYPERCALL_RET_ERROR);
	khx_gpa_hold_fail = -1;
	/* Argument blocks that violate the hypertrace_args_t contract. */
	a = guest_args(GLA_KDATA + 0x100);
	a->htr_entry = 2;
	KHX_EQ(hypercall(vcpu, HYPERCALL_DTRACE_PROBE, 42, GLA_KDATA + 0x100,
	    900, 0), HYPERCALL_RET_ERROR);
	a = guest_args(GLA_KDATA + 0x100);
	a->htr_pcstack_count = HYPERTRACE_STACK_MAX_FRAMES + 1;
	a->htr_pcstack = (uintptr_t *)(uintptr_t)(GLA_KDATA + 0x800);
	KHX_EQ(hypercall(vcpu, HYPERCALL_DTRACE_PROBE, 42, GLA_KDATA + 0x100,
	    900, 0), HYPERCALL_RET_ERROR);
	a = guest_args(GLA_KDATA + 0x100);
	a->htr_present = 0x80;
	KHX_EQ(hypercall(vcpu, HYPERCALL_DTRACE_PROBE, 42, GLA_KDATA + 0x100,
	    900, 0), HYPERCALL_RET_ERROR);
	KHX_EQ(khx_ht_probes, probes);

	/* The probe hypercall is for the guest kernel only. */
	khx_vmm_vcpu(vcpu)->desc_access[VM_REG_GUEST_CS] = 3 << 5;
	guest_args(GLA_KDATA + 0x100);
	KHX_EQ(hypercall(vcpu, HYPERCALL_DTRACE_PROBE, 42, GLA_KDATA + 0x100,
	    900, 3), HYPERCALL_RET_ERROR);
	KHX_EQ(khx_ht_probes, probes);
	vm_gone(vm);
}

/* ---- dispatch, rings and the other hypercalls --------------------------- */
static void
case_dispatch(void)
{
	struct vm *vm;
	struct vcpu *k, *u;
	struct sysctl_oid *oid;
	char buf[64];
	size_t len;

	khx_host_case("dispatch");
	guest_map();
	vm = vm_new("dispvm");
	k = vcpu_new(vm, 0, 0);
	u = vcpu_new(vm, 1, 3);

	KHX_EQ(hypercall(k, HYPERCALL_PROTOTYPE, 0, 0, 0, 0),
	    HYPERCALL_RET_SUCCESS);
	/* Vacant call numbers are not implemented; out-of-range ones are
	 * errors. */
	KHX_EQ((int64_t)hypercall(k, 1, 0, 0, 0, 0), HYPERCALL_RET_NOT_IMPL);
	KHX_EQ((int64_t)hypercall(k, 3, 0, 0, 0, 0), HYPERCALL_RET_NOT_IMPL);
	KHX_EQ(hypercall(k, HYPERCALL_INDEX_MAX, 0, 0, 0, 0),
	    HYPERCALL_RET_ERROR);
	KHX_EQ(hypercall(k, ~0ULL, 0, 0, 0, 0), HYPERCALL_RET_ERROR);
	/*
	 * HYPERCALL_TEST reads one int and logs it on the host console.  Like
	 * every other hypercall it is reserved to guest ring 0 (its guest stub
	 * is kernel code, sys/amd64/amd64/bhyve_hypercall.S), so guest
	 * userland cannot use it to write to the host console, and the log
	 * line is rate-limited to one per second.
	 */
	*(int *)gmem(GLA_USER + 0x10) = 42;
	khx_printf_reset();
	KHX_EQ(hypercall(u, HYPERCALL_TEST, GLA_USER + 0x10, 0, 0, 3),
	    HYPERCALL_RET_ERROR);
	KHX_CHECK(!khx_printf_seen("got int"));
	ticks += 10 * hz;
	KHX_EQ(hypercall(k, HYPERCALL_TEST, GLA_USER + 0x10, 0, 0, 0),
	    HYPERCALL_RET_SUCCESS);
	KHX_CHECK(khx_printf_seen("got int: 42"));
	/* Within the same second: still answered, not logged again. */
	khx_printf_reset();
	*(int *)gmem(GLA_USER + 0x10) = 43;
	for (int i = 0; i < 100; i++)
		KHX_EQ(hypercall(k, HYPERCALL_TEST, GLA_USER + 0x10, 0, 0, 0),
		    HYPERCALL_RET_SUCCESS);
	KHX_CHECK(!khx_printf_seen("got int"));
	/* A second later it is logged again. */
	ticks += hz;
	KHX_EQ(hypercall(k, HYPERCALL_TEST, GLA_USER + 0x10, 0, 0, 0),
	    HYPERCALL_RET_SUCCESS);
	KHX_CHECK(khx_printf_seen("got int: 43"));
	KHX_EQ(hypercall(k, HYPERCALL_TEST, GLA_HOLE, 0, 0, 0),
	    HYPERCALL_RET_ERROR);
	KHX_EQ(hypercall(u, HYPERCALL_PROTOTYPE, 0, 0, 0, 3),
	    HYPERCALL_RET_ERROR);

	/* Hypercalls can be disabled globally. */
	hypercalls_enabled = 0;
	KHX_EQ(hypercall(k, HYPERCALL_PROTOTYPE, 0, 0, 0, 0),
	    HYPERCALL_RET_ERROR);
	hypercalls_enabled = 1;
	/* An unknown hypervisor mode dispatches nothing. */
	hypervisor_mode = VMM_MAX_MODES;
	KHX_EQ(hypercall(k, HYPERCALL_PROTOTYPE, 0, 0, 0, 0),
	    HYPERCALL_RET_ERROR);
	hypervisor_mode = -1;
	KHX_EQ(hypercall(k, HYPERCALL_PROTOTYPE, 0, 0, 0, 0),
	    HYPERCALL_RET_ERROR);

	/* hw.vmm.hv_mode names the mode and only accepts "bhyve". */
	oid = khx_sysctl_find("vmm", "hv_mode");
	KHX_CHECK(oid != NULL);
	len = sizeof(buf);
	KHX_EQ(khx_sysctl_call(oid, curthread, buf, &len, NULL, 0), 0);
	KHX_EQ(strcmp(buf, "undefined"), 0);
	hypervisor_mode = BHYVE_MODE;
	len = sizeof(buf);
	KHX_EQ(khx_sysctl_call(oid, curthread, buf, &len, NULL, 0), 0);
	KHX_EQ(strcmp(buf, "bhyve"), 0);
	len = sizeof(buf);
	KHX_EQ(khx_sysctl_call(oid, curthread, buf, &len, "bhyve", 6), 0);
	KHX_EQ(hypervisor_mode, BHYVE_MODE);
	/* An unknown mode name (only reachable as the loader tunable) is
	 * rejected and changes nothing; "bhyve" selects BHYVE_MODE. */
	hypervisor_mode = -1;
	len = sizeof(buf);
	KHX_EQ(khx_sysctl_call(oid, curthread, buf, &len, "kvm", 4), EINVAL);
	KHX_EQ(hypervisor_mode, -1);
	len = sizeof(buf);
	KHX_EQ(khx_sysctl_call(oid, curthread, buf, &len, "", 1), EINVAL);
	KHX_EQ(hypervisor_mode, -1);
	len = sizeof(buf);
	KHX_EQ(khx_sysctl_call(oid, curthread, buf, &len, "bhyve", 6), 0);
	KHX_EQ(hypervisor_mode, BHYVE_MODE);
	/* A reader whose buffer is too small gets the handler's error and no
	 * change. */
	len = 2;
	KHX_EQ(khx_sysctl_call(oid, curthread, buf, &len, "bhyve", 6), ENOMEM);
	KHX_EQ(hypervisor_mode, BHYVE_MODE);
	KHX_CHECK(khx_sysctl_find("vmm", "hypercalls_enabled") != NULL);
	vm_gone(vm);
}

/* ---- backend contract: register and descriptor access cannot fail ------ */
struct assert_run {
	struct vcpu *vcpu;
	uint64_t hcid, a1;
};

static void
assert_run_cb(void *arg)
{
	struct assert_run *r = arg;

	(void)hypercall(r->vcpu, r->hcid, 42, r->a1, 900, 0);
}

static void
case_backend_asserts(void)
{
	static const struct {
		uint64_t hcid;
		int getreg_only, setreg, getdesc_only, cs_dpl;
	} cases[] = {
		/* RAX unreadable at the exit. */
		{ HYPERCALL_PROTOTYPE, VM_REG_GUEST_RAX + 1, 0, 0, 0 },
		/* An argument register unreadable. */
		{ HYPERCALL_PROTOTYPE, VM_REG_GUEST_R9 + 1, 0, 0, 0 },
		/* The result cannot be stored: dispatched, rejected by range,
		 * rejected by ring. */
		{ HYPERCALL_PROTOTYPE, 0, 1, 0, 0 },
		{ HYPERCALL_INDEX_MAX, 0, 1, 0, 0 },
		{ HYPERCALL_DTRACE_PROBE, 0, 1, 0, 3 },
		/* CS, then DS (probe and test calls) unreadable. */
		{ HYPERCALL_PROTOTYPE, 0, 0, VM_REG_GUEST_CS + 1, 0 },
		{ HYPERCALL_DTRACE_PROBE, 0, 0, VM_REG_GUEST_DS + 1, 0 },
		{ HYPERCALL_TEST, 0, 0, VM_REG_GUEST_DS + 1, 0 },
	};
	struct vm *vm;
	struct assert_run r;
	struct khx_vcpu *kv;

	khx_host_case("backend-asserts");
	guest_map();
	vm = vm_new("assertvm");
	r.vcpu = vcpu_new(vm, 0, 0);
	r.a1 = GLA_KDATA + 0x100;
	kv = khx_vmm_vcpu(r.vcpu);
	for (size_t i = 0; i < nitems(cases); i++) {
		guest_args(GLA_KDATA + 0x100);
		r.hcid = cases[i].hcid;
		kv->desc_access[VM_REG_GUEST_CS] = (uint32_t)cases[i].cs_dpl << 5;
		kv->getreg_error = cases[i].getreg_only != 0 ? EIO : 0;
		kv->getreg_only = cases[i].getreg_only;
		kv->setreg_error = cases[i].setreg ? EIO : 0;
		kv->getdesc_error = cases[i].getdesc_only != 0 ? EIO : 0;
		kv->getdesc_only = cases[i].getdesc_only;
		/* INVARIANTS: a failing backend accessor is a VMM bug. */
		KHX_CHECK(KHX_PANICS(assert_run_cb, &r));
		khx_release_locks_after_panic(curthread);
		kv->getreg_error = kv->setreg_error = kv->getdesc_error = 0;
		/* The panic left the vCPU frozen after the guest exit. */
		KHX_EQ(vcpu_get_state(r.vcpu, NULL), VCPU_FROZEN);
	}
	vm_gone(vm);
}

/* ---- VMM accessors the provider uses ------------------------------------ */
static void
case_accessors(void)
{
	struct vm *vm;
	struct vcpu *vcpu;
	struct vm_guest_paging p0, flat;
	struct vm_hdl h, bad;
	uint8_t buf[sizeof(struct trapframe) + 8];
	uint64_t v;

	khx_host_case("accessors");
	guest_map();
	vm = vm_new("accvm");
	vcpu = vcpu_new(vm, 2, 0);
	p0 = paging(0, PAGING_MODE_64);
	flat = paging(0, PAGING_MODE_FLAT);
	memset(&h, 0, sizeof(h));
	h.vcpu = vcpu;
	h.paging = &p0;
	h.tid = 31;
	KHX_EQ(vmm_gettid(&h), 31);
	KHX_EQ(vmm_getid(&h), vm_get_id(vm));
	KHX_EQ(vmm_getepoch(&h), vm_get_hypertrace_epoch(vm));
	KHX_EQ(strcmp(vmm_getname(&h), "accvm"), 0);

	/* Registers. */
	khx_vmm_vcpu(vcpu)->regs[VM_REG_GUEST_RBP] = 0xbeef;
	KHX_EQ(vmm_getreg(&h, VM_REG_GUEST_RBP, &v), 0);
	KHX_EQ(v, 0xbeef);
	KHX_EQ(vmm_getreg(NULL, VM_REG_GUEST_RBP, &v), EINVAL);
	bad = h;
	bad.vcpu = NULL;
	KHX_EQ(vmm_getreg(&bad, VM_REG_GUEST_RBP, &v), EINVAL);
	KHX_EQ(vmm_getreg(&h, VM_REG_GUEST_RBP, NULL), EINVAL);
	KHX_EQ(vmm_getreg(&h, -1, &v), EINVAL);
	KHX_EQ(vmm_getreg(&h, VM_REG_LAST, &v), EINVAL);
	khx_vmm_vcpu(vcpu)->getreg_error = EIO;
	KHX_EQ(vmm_getreg(&h, VM_REG_GUEST_RBP, &v), EIO);
	khx_vmm_vcpu(vcpu)->getreg_error = 0;

	/* Kernel copyin: argument validation. */
	KHX_EQ(vmm_guest_copyin(NULL, GLA_KDATA, buf, 8), EINVAL);
	KHX_EQ(vmm_guest_copyin(&bad, GLA_KDATA, buf, 8), EINVAL);
	bad = h;
	bad.paging = NULL;
	KHX_EQ(vmm_guest_copyin(&bad, GLA_KDATA, buf, 8), EINVAL);
	KHX_EQ(vmm_guest_copyin(&h, GLA_KDATA, NULL, 8), EINVAL);
	KHX_EQ(vmm_guest_copyin(&h, 0, buf, 8), EINVAL);
	KHX_EQ(vmm_guest_copyin(&h, GLA_KDATA, buf, 0), EINVAL);
	KHX_EQ(vmm_guest_copyin(&h, GLA_KDATA, buf,
	    sizeof(struct trapframe) + 1), EINVAL);
	KHX_EQ(vmm_guest_copyin(&h, ~0ULL - 2, buf, 8), EINVAL);
	/* A trapframe-sized read across two supervisor pages. */
	for (size_t i = 0; i < sizeof(struct trapframe); i++)
		*(uint8_t *)gmem(GLA_KDATA + PAGE_SIZE - 16 + i) = (uint8_t)i;
	memset(buf, 0xee, sizeof(buf));
	KHX_EQ(vmm_guest_copyin(&h, GLA_KDATA + PAGE_SIZE - 16, buf,
	    sizeof(struct trapframe)), 0);
	for (size_t i = 0; i < sizeof(struct trapframe); i++)
		KHX_EQ(buf[i], (uint8_t)i);
	KHX_EQ(buf[sizeof(struct trapframe)], 0xee);
	KHX_EQ(khx_gpa_holds, 0);
	KHX_EQ(khx_last_gla_cpl, 0);
	KHX_EQ(khx_last_gla_prot, VM_PROT_READ);
	/* Failures never publish a partial copy. */
	memset(buf, 0xee, sizeof(buf));
	KHX_EQ(vmm_guest_copyin(&h, GLA_KDATA2 + PAGE_SIZE - 4, buf, 8),
	    EFAULT);			/* second page unmapped */
	KHX_EQ(buf[0], 0xee);
	khx_gpa_hold_fail = 1;
	KHX_EQ(vmm_guest_copyin(&h, GLA_KDATA + PAGE_SIZE - 4, buf, 8),
	    EFAULT);			/* second page cannot be held */
	khx_gpa_hold_fail = -1;
	KHX_EQ(buf[0], 0xee);
	KHX_EQ(khx_gpa_holds, 0);
	khx_gla_error = EINVAL;
	KHX_EQ(vmm_guest_copyin(&h, GLA_KDATA, buf, 8), EFAULT);
	khx_gla_error = 0;

	/* User copyin reads with the guest's user privilege. */
	*(uint64_t *)gmem(GLA_USER + 8) = 0x1122334455667788ULL;
	KHX_EQ(vmm_guest_user_copyin(&h, GLA_USER + 8, &v, 8), 0);
	KHX_EQ(v, 0x1122334455667788ULL);
	KHX_EQ(khx_last_gla_cpl, 3);
	KHX_EQ(p0.cpl, 0);		/* the caller's paging is not modified */
	KHX_EQ(vmm_guest_user_copyin(&h, GLA_KDATA, &v, 8), EFAULT);
	KHX_EQ(vmm_guest_user_copyin(&h, GLA_USER, &v, 9), EINVAL);
	KHX_EQ(vmm_guest_user_copyin(&h, GLA_USER, &v, 0), EINVAL);
	KHX_EQ(vmm_guest_user_copyin(&h, GLA_USER, NULL, 8), EINVAL);
	KHX_EQ(vmm_guest_user_copyin(NULL, GLA_USER, &v, 8), EINVAL);
	bad = h;
	bad.paging = NULL;
	KHX_EQ(vmm_guest_user_copyin(&bad, GLA_USER, &v, 8), EINVAL);
	bad = h;
	bad.vcpu = NULL;
	KHX_EQ(vmm_guest_user_copyin(&bad, GLA_USER, &v, 8), EINVAL);
	h.paging = &flat;
	KHX_EQ(vmm_guest_user_copyin(&h, GLA_USER, &v, 8), EOPNOTSUPP);

	/* User copyout writes only pages the guest user could write. */
	KHX_EQ(vmm_guest_user_copyout(&h, GLA_USER, &v, 8), EOPNOTSUPP);
	h.paging = &p0;
	v = 0xa1a2a3a4a5a6a7a8ULL;
	KHX_EQ(vmm_guest_user_copyout(&h, GLA_USER + PAGE_SIZE - 3, &v, 8), 0);
	KHX_EQ(memcmp(gmem(GLA_USER + PAGE_SIZE - 3), &v, 3), 0);
	KHX_EQ(memcmp(gmem(GLA_USER2), (char *)&v + 3, 5), 0);
	KHX_EQ(khx_last_gla_cpl, 3);
	KHX_EQ(khx_last_gla_prot, VM_PROT_WRITE);
	KHX_EQ(khx_gpa_holds, 0);
	KHX_EQ(vmm_guest_user_copyout(&h, GLA_URO, &v, 8), EFAULT);
	KHX_EQ(vmm_guest_user_copyout(&h, GLA_KDATA, &v, 8), EFAULT);
	KHX_EQ(*(uint64_t *)gmem(GLA_KDATA), 0);
	khx_gpa_hold_fail = 0;
	KHX_EQ(vmm_guest_user_copyout(&h, GLA_USER, &v, 8), EFAULT);
	khx_gpa_hold_fail = -1;
	khx_gla_error = EINVAL;
	KHX_EQ(vmm_guest_user_copyout(&h, GLA_USER, &v, 8), EFAULT);
	khx_gla_error = 0;
	KHX_EQ(vmm_guest_user_copyout(&h, GLA_USER, &v, 9), EINVAL);
	KHX_EQ(vmm_guest_user_copyout(&h, GLA_USER, &v, 0), EINVAL);
	KHX_EQ(vmm_guest_user_copyout(&h, 0, &v, 8), EINVAL);
	KHX_EQ(vmm_guest_user_copyout(&h, ~0ULL - 2, &v, 8), EINVAL);
	KHX_EQ(vmm_guest_user_copyout(&h, GLA_USER, NULL, 8), EINVAL);
	KHX_EQ(vmm_guest_user_copyout(NULL, GLA_USER, &v, 8), EINVAL);
	bad = h;
	bad.paging = NULL;
	KHX_EQ(vmm_guest_user_copyout(&bad, GLA_USER, &v, 8), EINVAL);
	bad = h;
	bad.vcpu = NULL;
	KHX_EQ(vmm_guest_user_copyout(&bad, GLA_USER, &v, 8), EINVAL);
	vm_gone(vm);
}

/* ---- CPUID advertisement ------------------------------------------------- */
static void
case_cpuid(void)
{
	struct vm *vm;
	struct vcpu *vcpu;

	khx_host_case("cpuid");
	vm = vm_new("cpuidvm");
	vcpu = vcpu_new(vm, 0, 0);
	cpuid_vcpu = vcpu;
	/* The guest's detector finds HyperTrace in the bhyve block ... */
	khx_vmm_pvclock = 0;
	KHX_EQ(bhyve_hypercalls_enabled(), 1);
	/* ... and in the secondary block when KVM owns the primary one. */
	khx_vmm_pvclock = 1;
	KHX_EQ(bhyve_hypercalls_enabled(), 1);
	/* Disabled hypercalls are advertised as such in both layouts. */
	hypercalls_enabled = 0;
	KHX_EQ(bhyve_hypercalls_enabled(), 0);
	khx_vmm_pvclock = 0;
	KHX_EQ(bhyve_hypercalls_enabled(), 0);
	hypercalls_enabled = 1;
	cpuid_vcpu = NULL;
	vm_gone(vm);
}

/* ---- identity ioctls ----------------------------------------------------- */
static void
case_ioctls(void)
{
	struct vm *vm;
	struct hypertrace_vm_identity id;
	struct hypertrace_vm_attestation at;
	uint16_t vmid;
	int found = 0;

	khx_host_case("ioctls");
	vm = vm_new("ioctlvm");
	memset(&id, 0xff, sizeof(id));
	KHX_EQ(vmmdev_machdep_ioctl(vm, NULL, VM_GET_IDENTITY, (caddr_t)&id, 0,
	    curthread), 0);
	KHX_EQ(id.vmid, vm_get_id(vm));
	KHX_EQ(id.epoch, vm_get_hypertrace_epoch(vm));
	for (int i = 0; i < 3; i++)
		KHX_EQ(id.reserved[i], 0);
	memset(&at, 0xff, sizeof(at));
	KHX_EQ(vmmdev_machdep_ioctl(vm, NULL, VM_GET_ATTESTATION, (caddr_t)&at,
	    0, curthread), 0);
	KHX_EQ(at.vmid, vm_get_id(vm));
	KHX_EQ(at.epoch, vm_get_hypertrace_epoch(vm));
	KHX_EQ(strcmp(at.name, "ioctlvm"), 0);
	KHX_EQ(at.name[sizeof(at.name) - 1], 0);
	KHX_EQ(at.reserved[0], 0);
	vmid = 0;
	KHX_EQ(vmmdev_machdep_ioctl(vm, NULL, VM_GET_IDENTIFIER, (caddr_t)&vmid,
	    0, curthread), 0);
	KHX_EQ(vmid, vm_get_id(vm));
	/* VM_REINIT replaces the identity under the memory-segment write
	 * lock, so the readers hold it shared. */
	for (size_t i = 0; i < vmmdev_machdep_ioctl_count; i++) {
		const struct vmmdev_ioctl *e = &vmmdev_machdep_ioctls[i];

		if (e->cmd == VM_GET_IDENTITY || e->cmd == VM_GET_ATTESTATION ||
		    e->cmd == VM_GET_IDENTIFIER) {
			KHX_EQ(e->flags, VMMDEV_IOCTL_SLOCK_MEMSEGS);
			found++;
		}
	}
	KHX_EQ(found, 3);
	vm_gone(vm);
}

/* ---- /dev/vmmctl and /dev/vmm/NAME: identity-checked destruction -------- */
static struct thread *td0;

static int
ctl(u_long cmd, void *data)
{
	return (khx_dev_ioctl(khx_cdev_find("vmmctl"), cmd, data, FWRITE,
	    td0));
}

static int
vm_create_dev(const char *name)
{
	struct vmmctl_vm_create c;

	memset(&c, 0, sizeof(c));
	strlcpy(c.name, name, sizeof(c.name));
	return (ctl(VMMCTL_VM_CREATE, &c));
}

static int
vm_identity(const char *name, struct hypertrace_vm_identity *id)
{
	char path[64];
	struct cdev *cdev;

	snprintf(path, sizeof(path), "vmm/%s", name);
	cdev = khx_cdev_find(path);
	if (cdev == NULL)
		return (ENOENT);
	return (khx_dev_ioctl(cdev, VM_GET_IDENTITY, (caddr_t)id, 0, td0));
}

static int
destroy_identity(const char *name, uint16_t vmid, uint64_t epoch)
{
	struct vmmctl_vm_destroy_identity d;

	memset(&d, 0, sizeof(d));
	strlcpy(d.name, name, sizeof(d.name));
	d.vmid = vmid;
	d.epoch = epoch;
	return (ctl(VMMCTL_VM_DESTROY_IDENTITY, &d));
}

/*
 * VM_REINIT racing identity-checked destruction.  Thread B issues
 * VM_REINIT; once it has passed the cdev lookup (its authorization hook),
 * it waits until destruction has marked the cdev unavailable (destroy_dev
 * is entered), then continues into the memory-segment lock and the reset.
 */
static volatile int reinit_race_error = -1;
static struct cdev *reinit_race_cdev;
static struct thread *reinit_td;
static void *reinit_passed, *reinit_marked;

static void
reinit_race_authorized(void)
{
	khx_host_sem_post(reinit_passed);
	khx_host_sem_wait(reinit_marked);
}

static void
reinit_race_destroying(void *arg __unused, struct cdev *cdev)
{
	if (cdev == reinit_race_cdev)
		khx_host_sem_post(reinit_marked);
}

static void
reinit_race_main(void *arg __unused)
{
	khx_pthread_attach(1, reinit_td);
	reinit_race_error = khx_dev_ioctl(reinit_race_cdev, VM_REINIT, NULL,
	    FWRITE, reinit_td);
}

static void
case_vmmctl(void)
{
	struct hypertrace_vm_identity id, id2;
	struct vmmctl_vm_destroy_identity d;
	struct vmmctl_vm_destroy legacy;
	long live = khx_ht_live;

	khx_host_case("vmmctl");
	td0 = curthread;
	khx_vmm_file_open();
	KHX_EQ(khx_dev_open(khx_cdev_find("vmmctl"), FREAD | FWRITE, td0), 0);
	KHX_EQ(vm_create_dev("dvm"), 0);
	KHX_EQ(khx_ht_live, live + 1);
	memset(&id, 0, sizeof(id));
	KHX_EQ(vm_identity("dvm", &id), 0);
	KHX_CHECK(khx_ht_is_live(id.vmid, id.epoch));

	/* Malformed requests are rejected before any lookup. */
	KHX_EQ(destroy_identity("dvm", 0, id.epoch), EINVAL);
	KHX_EQ(destroy_identity("dvm", id.vmid, 0), EINVAL);
	memset(&d, 'x', sizeof(d));
	d.vmid = id.vmid;
	d.epoch = id.epoch;
	memset(d.reserved, 0, sizeof(d.reserved));
	KHX_EQ(ctl(VMMCTL_VM_DESTROY_IDENTITY, &d), EINVAL);	/* no NUL */
	memset(&d, 0, sizeof(d));
	strlcpy(d.name, "dvm", sizeof(d.name));
	d.vmid = id.vmid;
	d.epoch = id.epoch;
	d.reserved[2] = 1;
	KHX_EQ(ctl(VMMCTL_VM_DESTROY_IDENTITY, &d), EINVAL);
	KHX_EQ(destroy_identity("nosuch", id.vmid, id.epoch), EINVAL);
	/* A request naming another incarnation is stale and harmless. */
	KHX_EQ(destroy_identity("dvm", id.vmid, id.epoch + 1), ESTALE);
	KHX_EQ(destroy_identity("dvm", id.vmid + 1, id.epoch), ESTALE);
	KHX_EQ(vm_identity("dvm", &id2), 0);
	KHX_EQ(id2.epoch, id.epoch);
	/* After VM_REINIT the old identity no longer destroys the VM. */
	KHX_EQ(khx_dev_ioctl(khx_cdev_find("vmm/dvm"), VM_REINIT, NULL, FWRITE,
	    td0), 0);
	KHX_EQ(vm_identity("dvm", &id2), 0);
	KHX_CHECK(id2.epoch != id.epoch);
	KHX_CHECK(!khx_ht_is_live(id.vmid, id.epoch));
	KHX_EQ(destroy_identity("dvm", id.vmid, id.epoch), ESTALE);
	/* The current identity destroys it and revokes the identity. */
	KHX_EQ(destroy_identity("dvm", id2.vmid, id2.epoch), 0);
	KHX_CHECK(khx_cdev_find("vmm/dvm") == NULL);
	KHX_CHECK(!khx_ht_is_live(id2.vmid, id2.epoch));
	KHX_EQ(khx_ht_live, live);

	/* A reset already inside the cdev when destruction marks it
	 * unavailable must not install a new incarnation. */
	KHX_EQ(vm_create_dev("rvm"), 0);
	KHX_EQ(vm_identity("rvm", &id), 0);
	reinit_race_cdev = khx_cdev_find("vmm/rvm");
	reinit_td = khx_thread_new("bhyve-reset", 0);
	reinit_passed = khx_host_sem_new(0);
	reinit_marked = khx_host_sem_new(0);
	khx_vmm_reinit_hook = reinit_race_authorized;
	khx_set_destroy_dev_hook(reinit_race_destroying, NULL);
	{
		void *h = khx_host_thread_start(reinit_race_main, NULL);
		long allocs = khx_ht_live;

		khx_host_sem_wait(reinit_passed);
		KHX_EQ(destroy_identity("rvm", id.vmid, id.epoch), 0);
		khx_host_thread_join(h);
		KHX_EQ(khx_ht_live, allocs - 1);
	}
	khx_set_destroy_dev_hook(NULL, NULL);
	khx_vmm_reinit_hook = NULL;
	khx_thread_free(reinit_td);
	KHX_EQ(reinit_race_error, ENXIO);
	KHX_CHECK(!khx_ht_is_live(id.vmid, id.epoch));
	KHX_EQ(khx_ht_live, live);

	/* The legacy name-only destroy still works. */
	KHX_EQ(vm_create_dev("lvm"), 0);
	memset(&legacy, 0, sizeof(legacy));
	strlcpy(legacy.name, "lvm", sizeof(legacy.name));
	KHX_EQ(ctl(VMMCTL_VM_DESTROY, &legacy), 0);
	KHX_EQ(khx_ht_live, live);
	khx_vmm_file_close();
}


/* ---- VM_FREE_MEMSEG ------------------------------------------------------ */
static int
vmdev_ioctl(const char *vm, u_long cmd, void *data)
{
	char path[64];
	struct cdev *cdev;

	snprintf(path, sizeof(path), "vmm/%s", vm);
	cdev = khx_cdev_find(path);
	if (cdev == NULL)
		return (ENOENT);
	return (khx_dev_ioctl(cdev, cmd, (caddr_t)data, FWRITE, td0));
}

static int
alloc_seg(const char *vm, int segid, size_t len, const char *name)
{
	struct vm_memseg m;

	memset(&m, 0, sizeof(m));
	m.segid = segid;
	m.len = len;
	if (name != NULL)
		strlcpy(m.name, name, sizeof(m.name));
	return (vmdev_ioctl(vm, VM_ALLOC_MEMSEG, &m));
}

static int
free_seg_r(const char *vm, int segid, int slot, int reserved)
{
	struct vm_free_memseg f;

	memset(&f, 0, sizeof(f));
	f.segid = segid;
	f.reserved[slot] = reserved;
	return (vmdev_ioctl(vm, VM_FREE_MEMSEG, &f));
}

static int
free_seg(const char *vm, int segid, int reserved)
{
	struct vm_free_memseg f;

	memset(&f, 0, sizeof(f));
	f.segid = segid;
	f.reserved[1] = reserved;
	return (vmdev_ioctl(vm, VM_FREE_MEMSEG, &f));
}

static int
map_seg(const char *vm, int segid, vm_paddr_t gpa, size_t len)
{
	struct vm_memmap mm;

	memset(&mm, 0, sizeof(mm));
	mm.gpa = gpa;
	mm.segid = segid;
	mm.len = len;
	mm.prot = VM_PROT_READ | VM_PROT_WRITE;
	return (vmdev_ioctl(vm, VM_MMAP_MEMSEG, &mm));
}

static int vmmdfr_runs;

/* vmmdev_destroy() waiting for freed devmem cdevs: the "taskqueue" that
 * destroys them runs while it sleeps. */
static int
vmmdfr_hook(void *arg __unused, const void *wchan __unused, const char *wmesg,
    int timo __unused, int catch_signals __unused)
{
	if (wmesg != NULL && strcmp(wmesg, "vmmdfr") == 0) {
		vmmdfr_runs++;
		khx_destroy_dev_sched_run();
	}
	return (0);
}

static void
case_free_memseg(void)
{
	struct vmmctl_vm_destroy dd;
	struct vm_object *obj;
	vm_ooffset_t off;
	long objs = khx_vmm_objects;

	khx_host_case("free-memseg");
	td0 = curthread;
	khx_vmm_file_open();
	KHX_EQ(khx_dev_open(khx_cdev_find("vmmctl"), FREAD | FWRITE, td0), 0);
	KHX_EQ(vm_create_dev("fma"), 0);
	KHX_EQ(alloc_seg("fma", VM_SYSMEM, 4 * PAGE_SIZE, NULL), 0);
	KHX_EQ(alloc_seg("fma", VM_BOOTROM, PAGE_SIZE, "bootrom"), 0);
	KHX_EQ(alloc_seg("fma", VM_FRAMEBUFFER, 2 * PAGE_SIZE, "fb"), 0);
	KHX_EQ(khx_vmm_objects, objs + 3);
	KHX_CHECK(khx_cdev_find("vmm.io/fma.bootrom") != NULL);

	/* Refusals: nonzero reserved, out of range, unallocated, system
	 * memory, and a segment that is still mapped. */
	KHX_EQ(free_seg("fma", VM_BOOTROM, 1), EINVAL);
	KHX_EQ(free_seg_r("fma", VM_BOOTROM, 0, 1), EINVAL);
	KHX_EQ(free_seg_r("fma", VM_BOOTROM, 2, 1), EINVAL);
	KHX_EQ(free_seg("fma", -1, 0), EINVAL);
	KHX_EQ(free_seg("fma", VM_MAX_MEMSEGS, 0), EINVAL);
	KHX_EQ(free_seg("fma", VM_PCIROM, 0), ENOENT);
	KHX_EQ(free_seg("fma", VM_SYSMEM, 0), EINVAL);
	KHX_EQ(map_seg("fma", VM_SYSMEM, 0, 4 * PAGE_SIZE), 0);
	KHX_EQ(map_seg("fma", VM_FRAMEBUFFER, 0x100000, 2 * PAGE_SIZE), 0);
	KHX_EQ(free_seg("fma", VM_FRAMEBUFFER, 0), EBUSY);
	KHX_EQ(khx_vmm_objects, objs + 3);

	/* Success: the segment and its object go at once; the devmem node
	 * is destroyed asynchronously, and until then an mmap of it fails. */
	off = 0;
	KHX_EQ(khx_dev_mmap_single(khx_cdev_find("vmm.io/fma.bootrom"), &off,
	    PAGE_SIZE, &obj, PROT_READ), 0);	/* still live: works */
	khx_vm_object_release(obj);
	KHX_EQ(free_seg("fma", VM_BOOTROM, 0), 0);
	KHX_EQ(khx_vmm_objects, objs + 2);
	KHX_EQ(khx_destroy_dev_sched_pending(), 1);
	KHX_CHECK(khx_cdev_find("vmm.io/fma.bootrom") != NULL);
	off = 0;
	KHX_EQ(khx_dev_mmap_single(khx_cdev_find("vmm.io/fma.bootrom"), &off,
	    PAGE_SIZE, &obj, PROT_READ), ENXIO);
	KHX_EQ(free_seg("fma", VM_BOOTROM, 0), ENOENT);	/* already freed */
	khx_destroy_dev_sched_run();
	KHX_CHECK(khx_cdev_find("vmm.io/fma.bootrom") == NULL);
	/* The ID can be allocated again, with a new node. */
	KHX_EQ(alloc_seg("fma", VM_BOOTROM, PAGE_SIZE, "bootrom"), 0);
	KHX_CHECK(khx_cdev_find("vmm.io/fma.bootrom") != NULL);

	/* Two frees pending at once (one of them not at the head of the
	 * VM's devmem list): each node goes in its own callback. */
	KHX_EQ(alloc_seg("fma", VM_PCIROM, PAGE_SIZE, "pcirom"), 0);
	/* The VM's devmem list is pcirom, bootrom, fb (newest first): free
	 * the tail (two steps along the list) once it is unmapped, then the
	 * middle, then the head. */
	{
		struct vm_munmap mu = { .gpa = 0x100000, .len = 2 * PAGE_SIZE };

		KHX_EQ(vmdev_ioctl("fma", VM_MUNMAP_MEMSEG, &mu), 0);
	}
	KHX_EQ(free_seg("fma", VM_FRAMEBUFFER, 0), 0);
	KHX_EQ(free_seg("fma", VM_BOOTROM, 0), 0);
	KHX_EQ(free_seg("fma", VM_PCIROM, 0), 0);
	KHX_EQ(khx_destroy_dev_sched_pending(), 3);
	khx_destroy_dev_sched_run();
	KHX_CHECK(khx_cdev_find("vmm.io/fma.bootrom") == NULL);
	KHX_CHECK(khx_cdev_find("vmm.io/fma.pcirom") == NULL);
	KHX_CHECK(khx_cdev_find("vmm.io/fma.fb") == NULL);

	/* Destroying VM A while VM B holds devmem segments does not wait for
	 * B's nodes. */
	KHX_EQ(vm_create_dev("fmb"), 0);
	KHX_EQ(alloc_seg("fmb", VM_BOOTROM, PAGE_SIZE, "rom"), 0);
	vmmdfr_runs = 0;
	memset(&dd, 0, sizeof(dd));
	strlcpy(dd.name, "fma", sizeof(dd.name));
	khx_host_set_sleep_hook(vmmdfr_hook, NULL);
	KHX_EQ(ctl(VMMCTL_VM_DESTROY, &dd), 0);
	khx_host_set_sleep_hook(NULL, NULL);
	KHX_EQ(vmmdfr_runs, 0);
	KHX_CHECK(khx_cdev_find("vmm/fma") == NULL);
	KHX_CHECK(khx_cdev_find("vmm.io/fmb.rom") != NULL);

	/* Destroying a VM with a free still pending waits for it. */
	KHX_EQ(free_seg("fmb", VM_BOOTROM, 0), 0);
	KHX_EQ(khx_destroy_dev_sched_pending(), 1);
	strlcpy(dd.name, "fmb", sizeof(dd.name));
	khx_host_set_sleep_hook(vmmdfr_hook, NULL);
	KHX_EQ(ctl(VMMCTL_VM_DESTROY, &dd), 0);
	khx_host_set_sleep_hook(NULL, NULL);
	KHX_EQ(vmmdfr_runs, 1);
	KHX_EQ(khx_destroy_dev_sched_pending(), 0);
	KHX_CHECK(khx_cdev_find("vmm.io/fmb.rom") == NULL);
	KHX_CHECK(khx_cdev_find("vmm/fmb") == NULL);
	KHX_EQ(khx_vmm_objects, objs);	/* nothing leaked */
	khx_vmm_file_close();
}

/* ---- VM_GET_RUN_WITNESS -------------------------------------------------- */
static void
case_run_witness(void)
{
	struct vm_run_witness w;
	struct hypertrace_vm_identity id;
	struct vmmctl_vm_destroy dd;
	struct vm *vm;
	struct vcpu *vcpu;
	uint64_t entries;
	uint32_t running;

	khx_host_case("run-witness");
	td0 = curthread;
	khx_vmm_file_open();
	KHX_EQ(khx_dev_open(khx_cdev_find("vmmctl"), FREAD | FWRITE, td0), 0);
	/* Through the device: a new VM has never entered the guest, and the
	 * witness names the same incarnation as VM_GET_IDENTITY. */
	KHX_EQ(vm_create_dev("rw"), 0);
	memset(&w, 0xff, sizeof(w));
	KHX_EQ(vmdev_ioctl("rw", VM_GET_RUN_WITNESS, &w), 0);
	KHX_EQ(vm_identity("rw", &id), 0);
	KHX_EQ(w.vmid, id.vmid);
	KHX_EQ(w.epoch, id.epoch);
	KHX_EQ(w.guest_entries, 0);
	KHX_EQ(w.running_vcpus, 0);
	KHX_EQ(w.reserved0, 0);
	for (size_t i = 0; i < nitems(w.reserved); i++)
		KHX_EQ(w.reserved[i], 0);
	memset(&dd, 0, sizeof(dd));
	strlcpy(dd.name, "rw", sizeof(dd.name));
	KHX_EQ(ctl(VMMCTL_VM_DESTROY, &dd), 0);

	/* The counter: every guest entry counts (a hypercall exit resumes
	 * the guest once more); a reset starts a new incarnation at zero. */
	guest_map();
	vm = vm_new("rwvm");
	vcpu = vcpu_new(vm, 1, 0);
	vm_get_run_witness(vm, &entries, &running);
	KHX_EQ(entries, 0);
	KHX_EQ(running, 0);
	/* An unknown probe (ID 0): the hypercall fails in the guest, but the
	 * guest was entered, and resumed once more, all the same. */
	guest_args(GLA_KDATA + 0x100);
	KHX_EQ(hypercall(vcpu, HYPERCALL_DTRACE_PROBE, 0, GLA_KDATA + 0x100,
	    900, 0), HYPERCALL_RET_ERROR);
	vm_get_run_witness(vm, &entries, &running);
	KHX_EQ(entries, 2);
	KHX_EQ(running, 0);	/* the vCPU is frozen again */
	KHX_EQ(hypercall(vcpu, HYPERCALL_DTRACE_PROBE, 0, GLA_KDATA + 0x100,
	    900, 0), HYPERCALL_RET_ERROR);
	vm_get_run_witness(vm, &entries, &running);
	KHX_EQ(entries, 4);	/* monotonic */
	/* A vCPU in the running state is counted. */
	KHX_EQ(vcpu_set_state(vcpu, VCPU_RUNNING, false), 0);
	vm_get_run_witness(vm, &entries, &running);
	KHX_EQ(running, 1);
	KHX_EQ(vcpu_set_state(vcpu, VCPU_FROZEN, false), 0);
	/* A reset starts a new incarnation that has never run. */
	/* VM_REINIT needs every active vCPU suspended (vm_suspend() and the
	 * run loop's acknowledgement): stand in for that acknowledgement. */
	CPU_COPY(&vm->active_cpus, &vm->suspended_cpus);
	KHX_EQ(reinit(vm), 0);
	vm_get_run_witness(vm, &entries, &running);
	KHX_EQ(entries, 0);
	vm_gone(vm);
	khx_vmm_file_close();
}

/* ---- VMMCTL_VM_LIFETIME_QUERY -------------------------------------------- */
static int lq_query_error;

static void
lq_destroying(void *arg __unused, struct cdev *cdev)
{
	struct vmmctl_vm_lifetime_query q;

	if (lq_query_error != -1 || strcmp(cdev->si_name, "vmm/lq") != 0)
		return;
	memset(&q, 0, sizeof(q));
	strlcpy(q.name, "lq", sizeof(q.name));
	lq_query_error = ctl(VMMCTL_VM_LIFETIME_QUERY, &q);
}
static void
case_lifetime_query(void)
{
	struct vmmctl_vm_lifetime_query q;
	struct hypertrace_vm_identity id;
	struct vmmctl_vm_destroy dd;
	struct thread *other;

	khx_host_case("lifetime-query");
	td0 = curthread;
	khx_vmm_file_open();
	KHX_EQ(khx_dev_open(khx_cdev_find("vmmctl"), FREAD | FWRITE, td0), 0);
	KHX_EQ(vm_create_dev("lq"), 0);
	KHX_EQ(vm_identity("lq", &id), 0);
	memset(&q, 0, sizeof(q));
	strlcpy(q.name, "lq", sizeof(q.name));
	KHX_EQ(ctl(VMMCTL_VM_LIFETIME_QUERY, &q), 0);
	KHX_EQ(q.vmid, id.vmid);
	KHX_EQ(q.epoch, id.epoch);
	/* After VM_REINIT the query follows the new incarnation. */
	KHX_EQ(vmdev_ioctl("lq", VM_REINIT, NULL), 0);
	KHX_EQ(vm_identity("lq", &id), 0);
	KHX_EQ(ctl(VMMCTL_VM_LIFETIME_QUERY, &q), 0);
	KHX_EQ(q.vmid, id.vmid);
	KHX_EQ(q.epoch, id.epoch);
	/* Malformed: no NUL in the name, nonzero reserved. */
	memset(&q, 'x', sizeof(q));
	memset(q.reserved, 0, sizeof(q.reserved));
	KHX_EQ(ctl(VMMCTL_VM_LIFETIME_QUERY, &q), EINVAL);
	memset(&q, 0, sizeof(q));
	strlcpy(q.name, "lq", sizeof(q.name));
	q.reserved[0] = 1;
	KHX_EQ(ctl(VMMCTL_VM_LIFETIME_QUERY, &q), EINVAL);
	/* Unknown name. */
	memset(&q, 0, sizeof(q));
	strlcpy(q.name, "nosuch", sizeof(q.name));
	KHX_EQ(ctl(VMMCTL_VM_LIFETIME_QUERY, &q), ENOENT);
	/* Another user without PRIV_VMM_DESTROY. */
	other = khx_thread_new("lq-other", 4601);
	other->td_ucred->cr_uid = 1001;
	strlcpy(q.name, "lq", sizeof(q.name));
	khx_vmm_priv_error = EPERM;
	KHX_EQ(khx_dev_ioctl(khx_cdev_find("vmmctl"), VMMCTL_VM_LIFETIME_QUERY,
	    (caddr_t)&q, FWRITE, other), EPERM);
	/* ...but with the privilege the query succeeds. */
	khx_vmm_priv_error = 0;
	KHX_EQ(khx_dev_ioctl(khx_cdev_find("vmmctl"), VMMCTL_VM_LIFETIME_QUERY,
	    (caddr_t)&q, FWRITE, other), 0);
	KHX_EQ(q.vmid, id.vmid);
	/* The same uid in another jail is another user too. */
	{
		/* Only the pointer is compared (jail identity). */
		static char other_pr[64] __aligned(16);

		other->td_ucred->cr_uid = td0->td_ucred->cr_uid;
		other->td_ucred->cr_prison = (struct prison *)(void *)other_pr;
		khx_vmm_priv_error = EPERM;
		KHX_EQ(khx_dev_ioctl(khx_cdev_find("vmmctl"),
		    VMMCTL_VM_LIFETIME_QUERY, (caddr_t)&q, FWRITE, other),
		    EPERM);
		khx_vmm_priv_error = 0;
	}
	/* While the VM's node is being destroyed it is not found. */
	lq_query_error = -1;
	khx_set_destroy_dev_hook(lq_destroying, NULL);
	/* A destroyed VM is gone. */
	memset(&dd, 0, sizeof(dd));
	strlcpy(dd.name, "lq", sizeof(dd.name));
	KHX_EQ(ctl(VMMCTL_VM_DESTROY, &dd), 0);
	khx_set_destroy_dev_hook(NULL, NULL);
	KHX_EQ(lq_query_error, ENOENT);
	memset(&q, 0, sizeof(q));
	strlcpy(q.name, "lq", sizeof(q.name));
	KHX_EQ(ctl(VMMCTL_VM_LIFETIME_QUERY, &q), ENOENT);
	khx_vmm_file_close();
}

int
khx_test_main(void)
{
	khx_kern_boot();
	khx_run_sysinits();
	case_modinit();
	case_identity();
	case_reset();
	case_hypercall_probe();
	case_dispatch();
	case_backend_asserts();
	case_accessors();
	case_cpuid();
	case_ioctls();
	case_vmmctl();
	case_free_memseg();
	case_run_witness();
	case_lifetime_query();
	khx_host_case("teardown");
	KHX_EQ(khx_ht_live, 0);
	KHX_EQ(khx_module_event("vmm", MOD_UNLOAD), 0);
	KHX_EQ(hooks_installed(), 0);
	return (khx_host_finish("vmm_hypertrace"));
}
