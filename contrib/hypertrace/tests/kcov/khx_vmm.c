/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Shim for the amd64 VMM HyperTrace suite.  vmm.c, vmm_vm.c, x86.c and
 * vmm_dev_machdep.c are compiled unmodified; this file provides:
 *
 *  - a VMX-like backend (vmm_ops_intel) with a per-vCPU register file and
 *    segment descriptors, selected by vmm.c's own ifunc resolvers;
 *  - guest memory: an 8-page guest-physical window and an explicit
 *    guest-linear page table with user/write permissions (vm_gla2gpa*,
 *    vm_gpa_hold/release), replacing the real page-table walker in
 *    vmm_instruction_emul.c and the vm_map-backed vmm_mem.c;
 *  - the HyperTrace provider entry points the VMM calls (identity
 *    allocation/release, hypertrace_probe, the configuration lock and the
 *    vmm_* hook slots that hypertrace.c owns), as recorders with fault
 *    injection.  The probe recorder calls the installed vmm_* hooks with the
 *    handle while it is live, exactly as the provider does;
 *  - inert device-model constructors (vioapic/vhpet/...: non-NULL tokens);
 *  - an audited list of panic stubs for symbols the measured paths never
 *    reach (khx_vmm_stubs below).  Not production code.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/hypertrace.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>

#include <sys/bus.h>
#include <x86/apicvar.h>
#include <machine/vmm.h>
#include <machine/vmm_instruction_emul.h>
#include <dev/vmm/vmm_mem.h>
#include <dev/vmm/vmm_vm.h>
#include <dev/vmm/vmm_startup_handshake.h>
#include <dev/vmm/vmm_event_coordinator.h>
#include <machine/specialreg.h>
#include <machine/fpu.h>

#include "khx_kern.h"
#include "khx_vmm.h"

/* ---- kernel globals the VMM reads --------------------------------------- */
struct mtx Giant;
u_int amd_feature, amd_feature2, cpu_exthigh, cpu_high = 0xd, cpu_id;
int pti;
int smp_tsc = 1;
uint64_t tsc_freq = 2000000000ULL;
int tsc_is_invariant = 1;

void (*vmm_suspend_p)(void);
void (*vmm_resume_p)(void);
struct sysctl_oid sysctl___hw;

/* hypertrace.c owns these hook slots. */
uint64_t (*vmm_getepoch)(const void *);
lwpid_t (*vmm_gettid)(const void *);
uint16_t (*vmm_getid)(const void *);
const char *(*vmm_getname)(const void *);
int (*vmm_getreg)(const void *, int, uint64_t *);
int (*vmm_guest_copyin)(const void *, uint64_t, void *, size_t);
int (*vmm_guest_user_copyin)(const void *, uint64_t, void *, size_t);
int (*vmm_guest_user_copyout)(const void *, uint64_t, const void *, size_t);

/* ---- spin mutexes: the harness mutex plus a critical section ------------ */
#undef _mtx_init
void _mtx_init(volatile uintptr_t *c, const char *name, const char *type,
    int opts);

void
khx_vmm_mtx_init(volatile uintptr_t *c, const char *name, const char *type,
    int opts)
{
	_mtx_init(c, name, type, opts & ~MTX_SPIN);
}

void
__mtx_lock_spin_flags(volatile uintptr_t *c, int opts, const char *file,
    int line)
{
	curthread->td_critnest++;
	__mtx_lock_flags(c, opts, file, line);
}

void
__mtx_unlock_spin_flags(volatile uintptr_t *c, int opts, const char *file,
    int line)
{
	__mtx_unlock_flags(c, opts, file, line);
	curthread->td_critnest--;
}

/* ---- scheduler binding: the bound thread runs on that CPU -------------- */
static struct mtx khx_thread_mtx;

void
thread_lock_flags_(struct thread *td, int opts, const char *file, int line)
{
	if (!lock_initialized(&khx_thread_mtx.lock_object))
		_mtx_init(&khx_thread_mtx.mtx_lock, "thread lock", NULL, 0);
	td->td_lock = &khx_thread_mtx;
	__mtx_lock_spin_flags(&khx_thread_mtx.mtx_lock, opts, file, line);
}

int khx_vmm_sched_binds;

void
sched_bind(struct thread *td __unused, int cpu)
{
	khx_vmm_sched_binds++;
	khx_set_curcpu(cpu);
}

void
sched_unbind(struct thread *td __unused)
{
}

/* ---- backend (vmm_ops_intel) -------------------------------------------- */
int khx_vmm_hw_supported = 1;
int khx_vmm_modinit_error;
int khx_vmm_coordinator_error;
int khx_vmm_vmspace_fail;
int khx_vmm_pvclock;
int khx_vmm_ipi = 250;

long khx_vmm_runs;

bool
vmm_is_intel(void)
{
	return (true);
}

bool
vmm_is_svm(void)
{
	return (false);
}

bool
vmm_is_hw_supported(void)
{
	return (khx_vmm_hw_supported != 0);
}

void
vmm_host_state_init(void)
{
}

int
lapic_ipi_alloc(inthand_t *ipifunc __unused,
    void (*fred_ipifunc)(struct trapframe *) __unused)
{
	return (khx_vmm_ipi);
}

void
lapic_ipi_free(int vector __unused)
{
}

void
iommu_cleanup(void)
{
}

static int
kb_modinit(int ipinum __unused)
{
	return (khx_vmm_modinit_error);
}

static int
kb_modcleanup(void)
{
	return (0);
}

static void
kb_modsuspend(void)
{
}

static int kb_vm_token;

static void *
kb_init(struct vm *vm __unused, struct pmap *pmap __unused)
{
	return (&kb_vm_token);
}

static void
kb_cleanup(void *vmi __unused)
{
}

static void *
kb_vcpu_init(void *vmi __unused, struct vcpu *vcpu, int vcpuid)
{
	struct khx_vcpu *kv = malloc(sizeof(*kv), M_TEMP, M_WAITOK | M_ZERO);

	kv->vcpuid = vcpuid;
	kv->vcpu = vcpu;
	return (kv);
}

static void
kb_vcpu_cleanup(void *vcpui)
{
	free(vcpui, M_TEMP);
}

static int
kb_vcpu_event_cleanup(void *vcpui __unused)
{
	return (0);
}

long khx_vmm_getreg_calls;

static int
kb_getreg(void *vcpui, int num, uint64_t *retval)
{
	struct khx_vcpu *kv = vcpui;

	khx_vmm_getreg_calls++;
	if (kv->getreg_error != 0 &&
	    (kv->getreg_only == 0 || kv->getreg_only == num + 1))
		return (kv->getreg_error);
	if (num < 0 || num >= KHX_VMM_NREGS)
		return (EINVAL);
	*retval = kv->regs[num];
	return (0);
}

static int
kb_setreg(void *vcpui, int num, uint64_t val)
{
	struct khx_vcpu *kv = vcpui;

	if (kv->setreg_error != 0)
		return (kv->setreg_error);
	if (num < 0 || num >= KHX_VMM_NREGS)
		return (EINVAL);
	kv->regs[num] = val;
	return (0);
}

/* No optional capability (RDPID, INVPCID, nested VMX) is enabled. */
static int
kb_getcap(void *vcpui __unused, int num __unused, int *retval)
{
	*retval = 0;
	return (ENOENT);
}

static int
kb_getdesc(void *vcpui, int num, struct seg_desc *desc)
{
	struct khx_vcpu *kv = vcpui;

	if (kv->getdesc_error != 0 &&
	    (kv->getdesc_only == 0 || kv->getdesc_only == num + 1))
		return (kv->getdesc_error);
	memset(desc, 0, sizeof(*desc));
	desc->base = kv->desc_base[num];
	desc->access = kv->desc_access[num];
	return (0);
}

static struct vmspace *
kb_vmspace_alloc(vm_offset_t min __unused, vm_offset_t max __unused)
{
	struct vmspace *vmspace;

	if (khx_vmm_vmspace_fail)
		return (NULL);
	vmspace = malloc(sizeof(*vmspace), M_DEVBUF, M_WAITOK | M_ZERO);
	PMAP_LOCK_INIT(vmspace_pmap(vmspace));
	return (vmspace);
}

static void
kb_vmspace_free(struct vmspace *vmspace)
{
	PMAP_LOCK_DESTROY(vmspace_pmap(vmspace));
	free(vmspace, M_DEVBUF);
}

static int kb_vlapic_token;

static struct vlapic *
kb_vlapic_init(void *vcpui __unused)
{
	return ((struct vlapic *)&kb_vlapic_token);
}

static void
kb_vlapic_cleanup(struct vlapic *vlapic __unused)
{
}

/* Each guest entry returns the next scripted exit. */
struct khx_exit khx_vmm_exits[8];
int khx_vmm_nexits;
static int khx_vmm_exit_pos;

void
khx_vmm_script(const struct khx_exit *exits, int n)
{
	memcpy(khx_vmm_exits, exits, n * sizeof(*exits));
	khx_vmm_nexits = n;
	khx_vmm_exit_pos = 0;
}

static int
kb_run(void *vcpui, register_t rip, struct pmap *pmap __unused,
    struct vm_eventinfo *info __unused,
    struct vmm_startup_entry_owner *owner __unused)
{
	struct khx_vcpu *kv = vcpui;
	struct vm_exit *vme = vm_exitinfo(kv->vcpu);
	const struct khx_exit *e;

	khx_vmm_runs++;
	if (khx_vmm_exit_pos >= khx_vmm_nexits)
		panic("khx_vmm: guest entry beyond the exit script");
	e = &khx_vmm_exits[khx_vmm_exit_pos++];
	if (vcpu_get_state(kv->vcpu, NULL) != VCPU_RUNNING)
		panic("khx_vmm: guest entered while not VCPU_RUNNING");
	memset(vme, 0, sizeof(*vme));
	vme->rip = rip;
	/* vmcall/vmmcall; an internal exit carries no instruction. */
	vme->inst_length = e->exitcode == VM_EXITCODE_VMM_INTERNAL ? 0 : 3;
	vme->exitcode = e->exitcode;
	vme->u.hypercall.paging = e->paging;
	return (e->error);
}

/*
 * The backend's frozen-vCPU handler (vmmops_handle_internal_exit) replaces
 * a VM_EXITCODE_VMM_INTERNAL exit with khx_vmm_internal, as svm.c does for
 * an L2 exit it resolved.
 */
struct vm_exit khx_vmm_internal;
int khx_vmm_internal_error;
long khx_vmm_internal_calls;

static int
kb_handle_internal_exit(void *vcpui)
{
	struct khx_vcpu *kv = vcpui;
	struct vm_exit *vme = vm_exitinfo(kv->vcpu);

	khx_vmm_internal_calls++;
	if (vcpu_get_state(kv->vcpu, NULL) != VCPU_FROZEN)
		panic("khx_vmm: internal exit while not VCPU_FROZEN");
	if (khx_vmm_internal_error != 0)
		return (khx_vmm_internal_error);
	*vme = khx_vmm_internal;
	return (0);
}

/* vm_handle_paging(): A/D emulation is EPT-only; vm_fault() is scripted. */
int khx_vm_fault_rv;
long khx_vm_faults;
vm_map_t khx_vm_fault_map;
vm_offset_t khx_vm_fault_va;
int khx_vm_fault_type;

int
pmap_emulate_accessed_dirty(pmap_t pmap __unused, vm_offset_t va __unused,
    int ftype __unused)
{
	return (-1);
}

int
vm_fault(vm_map_t map, vm_offset_t vaddr, vm_prot_t fault_type,
    int fault_flags, vm_page_t *m_hold)
{
	if (fault_flags != VM_FAULT_NORMAL || m_hold != NULL)
		panic("khx_vmm: unexpected vm_fault flags");
	khx_vm_faults++;
	khx_vm_fault_map = map;
	khx_vm_fault_va = vaddr;
	khx_vm_fault_type = fault_type;
	return (khx_vm_fault_rv);
}

/* ---- privileged-instruction model (khx_vmm_cpu.h) ----------------------- */
static u_long khx_cr0 = CR0_TS;

void
khx_clts(void)
{
	khx_cr0 &= ~CR0_TS;
}

u_long
khx_rcr0(void)
{
	return (khx_cr0);
}

void
khx_load_cr0(u_long v)
{
	khx_cr0 = v;
}

u_long
khx_rcr4(void)
{
	return (0);		/* no XSAVE: XCR0 is never touched */
}

u_long
khx_rxcr(u_int reg __unused)
{
	panic("khx_vmm: rxcr without CR4.XSAVE");
}

void
khx_load_xcr(u_int reg __unused, u_long v __unused)
{
	panic("khx_vmm: load_xcr without CR4.XSAVE");
}

void
set_pcb_flags(struct pcb *pcb __unused, const u_int flags __unused)
{
}

void
fpuexit(struct thread *td __unused)
{
}

void
fpurestore(void *addr __unused)
{
}

void
fpusave(void *addr __unused)
{
}

void
vpvclock_commit(struct vcpu *vcpu __unused)
{
}

int
vmm_event_coordinator_startup_execution_status(
    struct vmm_event_coordinator *c __unused,
    struct vmm_startup_handshake_status *status)
{
	memset(status, 0, sizeof(*status));
	status->mode.owner = VMM_STARTUP_OWNER_USERSPACE;
	return (0);
}

const struct vmm_ops vmm_ops_intel = {
	.modinit = kb_modinit,
	.modcleanup = kb_modcleanup,
	.modsuspend = kb_modsuspend,
	.modresume = kb_modsuspend,
	.init = kb_init,
	.run = kb_run,
	.handle_internal_exit = kb_handle_internal_exit,
	.cleanup = kb_cleanup,
	.vcpu_init = kb_vcpu_init,
	.vcpu_event_cleanup_check = kb_vcpu_event_cleanup,
	.vcpu_event_cleanup = kb_vcpu_event_cleanup,
	.vcpu_cleanup = kb_vcpu_cleanup,
	.getreg = kb_getreg,
	.setreg = kb_setreg,
	.getdesc = kb_getdesc,
	.getcap = kb_getcap,
	.vmspace_alloc = kb_vmspace_alloc,
	.vmspace_free = kb_vmspace_free,
	.vlapic_init = kb_vlapic_init,
	.vlapic_cleanup = kb_vlapic_cleanup,
};
const struct vmm_ops vmm_ops_amd;

struct khx_vcpu *
khx_vmm_vcpu(struct vcpu *vcpu)
{
	return (vcpu->cookie);
}

/* ---- vmm_mem.c subset --------------------------------------------------- */
int
vm_mem_init(struct vm_mem *mem, vm_offset_t lo, vm_offset_t hi)
{
	mem->mem_vmspace = vmmops_vmspace_alloc(lo, hi);
	if (mem->mem_vmspace == NULL)
		return (ENOMEM);
	sx_init(&mem->mem_segs_lock, "vm_mem_segs");
	return (0);
}

struct vmspace *
vm_vmspace(struct vm *vm)
{
	return (vm->mem.mem_vmspace);
}

void
vm_xlock_memsegs(struct vm *vm)
{
	sx_xlock(&vm->mem.mem_segs_lock);
}

void
vm_slock_memsegs(struct vm *vm)
{
	sx_slock(&vm->mem.mem_segs_lock);
}

void
vm_unlock_memsegs(struct vm *vm)
{
	sx_unlock(&vm->mem.mem_segs_lock);
}

void
vm_assert_memseg_xlocked(struct vm *vm)
{
	sx_assert(&vm->mem.mem_segs_lock, SA_XLOCKED);
}

/* Memory segments and guest mappings (vmm_mem.c's bookkeeping; the
 * segment's VM object is an opaque token with a reference count). */
struct khx_vmobj {
	int refs;
};
long khx_vmm_objects;		/* live segment objects */

int
vm_alloc_memseg(struct vm *vm, int ident, size_t len, bool sysmem,
    struct domainset *ds __unused)
{
	struct vm_mem_seg *seg;
	struct khx_vmobj *o;

	vm_assert_memseg_xlocked(vm);
	if (ident < 0 || ident >= VM_MAX_MEMSEGS)
		return (EINVAL);
	if (len == 0 || (len & PAGE_MASK))
		return (EINVAL);
	seg = &vm->mem.mem_segs[ident];
	if (seg->object != NULL)
		return (seg->len == len && seg->sysmem == sysmem ? EEXIST :
		    EINVAL);
	o = malloc(sizeof(*o), M_TEMP, M_WAITOK | M_ZERO);
	o->refs = 1;
	khx_vmm_objects++;
	seg->len = len;
	seg->sysmem = sysmem;
	seg->object = (vm_object_t)(void *)o;
	return (0);
}

int
vm_get_memseg(struct vm *vm, int ident, size_t *len, bool *sysmem,
    vm_object_t *objptr)
{
	struct vm_mem_seg *seg;

	if (ident < 0 || ident >= VM_MAX_MEMSEGS)
		return (EINVAL);
	seg = &vm->mem.mem_segs[ident];
	if (len)
		*len = seg->len;
	if (sysmem)
		*sysmem = seg->sysmem;
	if (objptr)
		*objptr = seg->object;
	return (0);
}

static void
khx_vmobj_release(vm_object_t obj)
{
	struct khx_vmobj *o = (void *)obj;

	if (--o->refs == 0) {
		free(o, M_TEMP);
		khx_vmm_objects--;
	}
}

void
vm_free_memseg(struct vm *vm, int ident)
{
	struct vm_mem_seg *seg;

	KASSERT(ident >= 0 && ident < VM_MAX_MEMSEGS,
	    ("%s: invalid memseg ident %d", __func__, ident));
	seg = &vm->mem.mem_segs[ident];
	if (seg->object != NULL) {
		khx_vmobj_release(seg->object);
		memset(seg, 0, sizeof(*seg));
	}
}

void
vm_object_reference(vm_object_t obj)
{
	((struct khx_vmobj *)(void *)obj)->refs++;
}

void
khx_vm_object_release(vm_object_t obj)
{
	khx_vmobj_release(obj);
}

int
vm_mmap_memseg(struct vm *vm, vm_paddr_t gpa, int segid, vm_ooffset_t first,
    size_t len, int prot, int flags)
{
	struct vm_mem_seg *seg;
	struct vm_mem_map *m = NULL;

	if (prot == 0 || (prot & ~VM_PROT_ALL) != 0 || flags != 0)
		return (EINVAL);
	if (segid < 0 || segid >= VM_MAX_MEMSEGS)
		return (EINVAL);
	seg = &vm->mem.mem_segs[segid];
	if (seg->object == NULL || first + len < first || gpa + len < gpa ||
	    first + len > seg->len || len == 0 ||
	    ((gpa | first | len) & PAGE_MASK) != 0)
		return (EINVAL);
	for (int i = 0; i < VM_MAX_MEMMAPS; i++) {
		if (vm->mem.mem_maps[i].len == 0) {
			m = &vm->mem.mem_maps[i];
			break;
		}
	}
	if (m == NULL)
		return (ENOSPC);
	m->gpa = gpa;
	m->len = len;
	m->segoff = first;
	m->segid = segid;
	m->prot = prot;
	m->flags = flags;
	return (0);
}

int
vm_munmap_memseg(struct vm *vm, vm_paddr_t gpa, size_t len)
{
	for (int i = 0; i < VM_MAX_MEMMAPS; i++) {
		struct vm_mem_map *m = &vm->mem.mem_maps[i];

		if (m->len != 0 && m->gpa == gpa && m->len == len) {
			memset(m, 0, sizeof(*m));
			return (0);
		}
	}
	return (EINVAL);
}

int
vm_mmap_getnext(struct vm *vm, vm_paddr_t *gpa, int *segid,
    vm_ooffset_t *segoff, size_t *len, int *prot, int *flags)
{
	struct vm_mem_map *mm, *mmnext = NULL;

	for (int i = 0; i < VM_MAX_MEMMAPS; i++) {
		mm = &vm->mem.mem_maps[i];
		if (mm->len == 0 || mm->gpa < *gpa)
			continue;
		if (mmnext == NULL || mm->gpa < mmnext->gpa)
			mmnext = mm;
	}
	if (mmnext == NULL)
		return (ENOENT);
	*gpa = mmnext->gpa;
	if (segid)
		*segid = mmnext->segid;
	if (segoff)
		*segoff = mmnext->segoff;
	if (len)
		*len = mmnext->len;
	if (prot)
		*prot = mmnext->prot;
	if (flags)
		*flags = mmnext->flags;
	return (0);
}

void
vm_mem_cleanup(struct vm *vm)
{
	vm_assert_memseg_xlocked(vm);
	/* Device-memory mappings go on reset; system memory stays. */
	for (int i = 0; i < VM_MAX_MEMMAPS; i++) {
		struct vm_mem_map *m = &vm->mem.mem_maps[i];

		if (m->len != 0 && !vm->mem.mem_segs[m->segid].sysmem)
			memset(m, 0, sizeof(*m));
	}
}

void
vm_mem_destroy(struct vm *vm)
{
	vm_assert_memseg_xlocked(vm);
	memset(vm->mem.mem_maps, 0, sizeof(vm->mem.mem_maps));
	for (int i = 0; i < VM_MAX_MEMSEGS; i++)
		vm_free_memseg(vm, i);
	vmmops_vmspace_free(vm->mem.mem_vmspace);
	sx_xunlock(&vm->mem.mem_segs_lock);
	sx_destroy(&vm->mem.mem_segs_lock);
}

int khx_vmm_ppt_error;

int
ppt_unassign_all(struct vm *vm __unused)
{
	return (khx_vmm_ppt_error);
}

/* ---- guest memory model ------------------------------------------------- */
char khx_gmem[KHX_GPA_PAGES * 4096] __aligned(4096);
int khx_gla_error;
int khx_gpa_hold_fail = -1;
long khx_gpa_holds;
int khx_last_gla_cpl = -1;
int khx_last_gla_prot;

static struct {
	uint64_t gla, gpa;
	int user, write, used;
} khx_pt[32];

void
khx_gla_map(uint64_t gla, uint64_t gpa, int user, int write)
{
	for (int i = 0; i < 32; i++) {
		if (!khx_pt[i].used) {
			khx_pt[i].gla = trunc_page(gla);
			khx_pt[i].gpa = trunc_page(gpa);
			khx_pt[i].user = user;
			khx_pt[i].write = write;
			khx_pt[i].used = 1;
			return;
		}
	}
	panic("khx_gla_map: table full");
}

void
khx_gla_unmap_all(void)
{
	memset(khx_pt, 0, sizeof(khx_pt));
}

static int
khx_translate(struct vm_guest_paging *paging, uint64_t gla, int prot,
    uint64_t *gpa, int *fault)
{
	khx_last_gla_cpl = paging->cpl;
	khx_last_gla_prot = prot;
	if (khx_gla_error != 0)
		return (khx_gla_error);
	*fault = 1;
	for (int i = 0; i < 32; i++) {
		if (!khx_pt[i].used || khx_pt[i].gla != trunc_page(gla))
			continue;
		if (paging->cpl == 3 && !khx_pt[i].user)
			return (0);
		if ((prot & VM_PROT_WRITE) != 0 && !khx_pt[i].write)
			return (0);
		*gpa = khx_pt[i].gpa + (gla & PAGE_MASK);
		*fault = 0;
		return (0);
	}
	return (0);
}

/* Resident-copy dependency; the real walker has its own production-TU suite. */
int
dtrace_guest_copy(struct vm_guest_paging *paging, uint64_t gla, void *buf,
    size_t len, int prot)
{
	uint64_t gpa[2];
	size_t chunks[2], done = 0;
	int n = 0, fault;
	while (done < len) {
		if (khx_translate(paging, gla + done, prot, &gpa[n], &fault) != 0 ||
		    fault || khx_gpa_hold_fail == 0)
			return (EFAULT);
		if (khx_gpa_hold_fail > 0)
			khx_gpa_hold_fail--;
		chunks[n] = MIN(len - done, PAGE_SIZE - ((gla + done) & PAGE_MASK));
		if (gpa[n] < KHX_GPA_BASE ||
		    gpa[n] - KHX_GPA_BASE + chunks[n] > sizeof(khx_gmem))
			return (EFAULT);
		done += chunks[n++];
	}
	for (done = 0, n = 0; done < len; done += chunks[n++]) {
		if (prot == VM_PROT_WRITE)
			memcpy(khx_gmem + (gpa[n] - KHX_GPA_BASE), (char *)buf + done, chunks[n]);
		else
			memcpy((char *)buf + done, khx_gmem + (gpa[n] - KHX_GPA_BASE), chunks[n]);
	}
	return (0);
}

int
vm_gla2gpa(struct vcpu *vcpu __unused, struct vm_guest_paging *paging,
    uint64_t gla, int prot, uint64_t *gpa, int *fault)
{
	return (khx_translate(paging, gla, prot, gpa, fault));
}

int
vm_gla2gpa_nofault(struct vcpu *vcpu __unused, struct vm_guest_paging *paging,
    uint64_t gla, int prot, uint64_t *gpa, int *fault)
{
	return (khx_translate(paging, gla, prot, gpa, fault));
}

void *
vm_gpa_hold(struct vcpu *vcpu __unused, vm_paddr_t gpa, size_t len,
    int reqprot __unused, void **cookie)
{
	if (khx_gpa_hold_fail == 0)
		return (NULL);
	if (khx_gpa_hold_fail > 0)
		khx_gpa_hold_fail--;
	/* A hold never spans a page, as in vmm_mem.c. */
	if (gpa < KHX_GPA_BASE || gpa - KHX_GPA_BASE >= sizeof(khx_gmem) ||
	    (gpa & PAGE_MASK) + len > PAGE_SIZE)
		return (NULL);
	khx_gpa_holds++;
	*cookie = &khx_gmem[gpa - KHX_GPA_BASE];
	return (&khx_gmem[gpa - KHX_GPA_BASE]);
}

void
vm_gpa_release(void *cookie)
{
	if (cookie == NULL)
		panic("vm_gpa_release(NULL)");
	khx_gpa_holds--;
}

/* ---- HyperTrace provider entry points ----------------------------------- */
int khx_ht_alloc_error;
int khx_ht_alloc_fail_after = -1;
int khx_ht_release_error;
int khx_ht_probe_error;
long khx_ht_live;
long khx_ht_probes;
struct khx_ht_probe_record khx_ht_last;
int khx_ht_config_depth;
int khx_ht_config_unlocks;
int khx_ht_hooks_at_unlock;

static uint16_t khx_ht_next = 1;
static uint64_t khx_ht_epoch = 0x1000;
static struct {
	uint16_t vmid;
	uint64_t epoch;
} khx_ht_ids[64];

int
khx_ht_is_live(uint16_t vmid, uint64_t epoch)
{
	for (int i = 0; i < 64; i++)
		if (khx_ht_ids[i].vmid == vmid && khx_ht_ids[i].epoch == epoch &&
		    vmid != 0)
			return (1);
	return (0);
}

int
hypertrace_vm_alloc(uint16_t *vmid, uint64_t *epoch)
{
	if (khx_ht_alloc_fail_after == 0 || khx_ht_alloc_error != 0)
		return (khx_ht_alloc_error != 0 ? khx_ht_alloc_error : ENOSPC);
	if (khx_ht_alloc_fail_after > 0)
		khx_ht_alloc_fail_after--;
	for (int i = 0; i < 64; i++) {
		if (khx_ht_ids[i].vmid == 0) {
			khx_ht_ids[i].vmid = khx_ht_next++;
			khx_ht_ids[i].epoch = ++khx_ht_epoch;
			*vmid = khx_ht_ids[i].vmid;
			*epoch = khx_ht_ids[i].epoch;
			khx_ht_live++;
			return (0);
		}
	}
	return (ENOSPC);
}

uint16_t khx_ht_release_fail_vmid;

int
hypertrace_vm_release(uint16_t vmid, uint64_t epoch)
{
	if (khx_ht_release_error != 0 &&
	    (khx_ht_release_fail_vmid == 0 || khx_ht_release_fail_vmid == vmid))
		return (khx_ht_release_error);
	for (int i = 0; i < 64; i++) {
		if (khx_ht_ids[i].vmid == vmid && khx_ht_ids[i].epoch == epoch &&
		    vmid != 0) {
			khx_ht_ids[i].vmid = 0;
			khx_ht_ids[i].epoch = 0;
			khx_ht_live--;
			return (0);
		}
	}
	return (ESRCH);
}

static struct mtx khx_ht_config_mtx;

void
dtrace_hypertrace_config_lock(void)
{
	if (!mtx_initialized(&khx_ht_config_mtx))
		mtx_init(&khx_ht_config_mtx, "dtrace hypertrace config", NULL,
		    MTX_DEF);
	mtx_lock(&khx_ht_config_mtx);
	khx_ht_config_depth++;
}

void
dtrace_hypertrace_config_unlock(void)
{
	khx_ht_hooks_at_unlock = (vmm_getepoch != NULL) + (vmm_gettid != NULL) +
	    (vmm_getid != NULL) + (vmm_getname != NULL) + (vmm_getreg != NULL) +
	    (vmm_guest_copyin != NULL) + (vmm_guest_user_copyin != NULL) +
	    (vmm_guest_user_copyout != NULL);
	khx_ht_config_unlocks++;
	khx_ht_config_depth--;
	mtx_unlock(&khx_ht_config_mtx);
}

/* The provider reads guest state through the VMM hooks only while the
 * hypercall's handle is live, i.e. inside this call. */
int
hypertrace_probe(const void *vmhdl, hypertrace_id_t id,
    hypertrace_args_t *args)
{
	struct khx_ht_probe_record *r = &khx_ht_last;
	const char *name;
	uint64_t v;
	long reads;
	int reg;

	KHX_CHECK(PMAP_LOCKED((pmap_t)((const struct vm_hdl *)vmhdl)->paging->pmap));
	memset(r, 0, sizeof(*r));
	khx_ht_probes++;
	r->id = id;
	r->vmid = vmm_getid(vmhdl);
	r->epoch = vmm_getepoch(vmhdl);
	r->tid = vmm_gettid(vmhdl);
	name = vmm_getname(vmhdl);
	strlcpy(r->name, name != NULL ? name : "", sizeof(r->name));
	if (vmm_getreg(vmhdl, VM_REG_GUEST_RAX, &r->rax) != 0)
		r->rax = ~0ULL;
	r->getreg_bad = vmm_getreg(vmhdl, -1, &v);
	/* What the probe can read of the guest's registers, and at what cost
	 * to the backend. */
	_Static_assert(VM_REG_LAST <= nitems(r->regs), "probe record");
	reads = khx_vmm_getreg_calls;
	for (reg = 0; reg < VM_REG_LAST; reg++) {
		if (vmm_getreg(vmhdl, reg, &r->regs[reg]) == 0)
			r->regs_ok |= (uint64_t)1 << reg;
	}
	r->getreg_backend = khx_vmm_getreg_calls - reads;
	r->vcpu = args->htr_curcpu;
	r->args0 = args->htr_args[0];
	r->args9 = args->htr_args[9];
	r->pcstack_count = args->htr_pcstack_count;
	if (args->htr_pcstack_count != 0)
		r->copyin_error = vmm_guest_copyin(vmhdl,
		    (uint64_t)(uintptr_t)args->htr_pcstack, &r->pc0,
		    sizeof(r->pc0));
	return (khx_ht_probe_error);
}

/* ---- event coordinator (opaque owner) ----------------------------------- */
static int khx_coordinator_token;

int
vmm_event_coordinator_create(uint16_t maxcpus __unused,
    struct vmm_event_coordinator **out)
{
	if (khx_vmm_coordinator_error != 0)
		return (khx_vmm_coordinator_error);
	*out = (struct vmm_event_coordinator *)&khx_coordinator_token;
	return (0);
}

int
vmm_event_coordinator_cancel(struct vmm_event_coordinator *c __unused)
{
	return (0);
}

int
vmm_event_coordinator_drain_publishers(struct vmm_event_coordinator *c
    __unused, const char *w __unused, int t __unused)
{
	return (0);
}

int
vmm_event_coordinator_drain(struct vmm_event_coordinator *c __unused,
    const char *w __unused, int t __unused)
{
	return (0);
}

int
vmm_event_coordinator_destroy(struct vmm_event_coordinator *c __unused)
{
	return (0);
}

int khx_vmm_coordinator_reset_error;

int
vmm_event_coordinator_reset(struct vmm_event_coordinator *c __unused)
{
	return (khx_vmm_coordinator_reset_error);
}

/* ---- device models: inert constructors and destructors ------------------ */
static int khx_dev_token;
#define	KHX_DEVMODEL(type, prefix)					\
	type *prefix##_init(struct vm *vm __unused)			\
	{ return ((type *)&khx_dev_token); }				\
	void prefix##_cleanup(type *p __unused) { }
KHX_DEVMODEL(struct vioapic, vioapic)
KHX_DEVMODEL(struct vhpet, vhpet)
KHX_DEVMODEL(struct vatpic, vatpic)
KHX_DEVMODEL(struct vatpit, vatpit)
KHX_DEVMODEL(struct vpmtmr, vpmtmr)
KHX_DEVMODEL(struct vrtc, vrtc)
KHX_DEVMODEL(struct vpvclock, vpvclock)

void
vrtc_reset(struct vrtc *vrtc __unused)
{
}

bool
vpvclock_capable(void)
{
	return (khx_vmm_pvclock != 0);
}

uint32_t
vpvclock_kvm_features(void)
{
	return (0x1234);
}

void
vlapic_set_x2apic_state(struct vcpu *vcpu __unused,
    enum x2apic_state state __unused)
{
}

struct savefpu *
fpu_save_area_alloc(void)
{
	return (malloc(1024, M_TEMP, M_WAITOK | M_ZERO));
}

void
fpu_save_area_free(struct savefpu *fsa)
{
	free(fsa, M_TEMP);
}

void
fpu_save_area_reset(struct savefpu *fsa __unused)
{
}

void *
vmm_stat_alloc(void)
{
	return (malloc(64, M_TEMP, M_WAITOK | M_ZERO));
}

void
vmm_stat_init(void *vp __unused)
{
}

void
vmm_stat_free(void *vp)
{
	free(vp, M_TEMP);
}

void
sdt_probe(uint32_t id __unused, uintptr_t a0 __unused, uintptr_t a1 __unused,
    uintptr_t a2 __unused, uintptr_t a3 __unused, uintptr_t a4 __unused)
{
}

/* Unreached symbols are audited panic stubs in khx_vmm_stubs.c. */

/* ---- vmm_dev.c environment: credentials, privilege, MAC, devfs ---------- */
#include <sys/conf.h>
#include <machine/stdarg.h>
#include <sys/jail.h>
#include <sys/priv.h>
#include <sys/resourcevar.h>
#include <sys/ucred.h>
#include <security/mac/mac_framework.h>

int khx_vmm_priv_error;		/* priv_check*() result */
long khx_vmm_vm_count;		/* chgvmmcnt() accounting */

struct ucred *
crhold(struct ucred *cr)
{
	cr->cr_ref++;
	return (cr);
}

void
crfree(struct ucred *cr)
{
	if (cr->cr_ref == 0)
		panic("crfree: unreferenced credential");
	cr->cr_ref--;
}

int
cr_cansee(struct ucred *u1 __unused, struct ucred *u2 __unused)
{
	return (0);
}

int
priv_check(struct thread *td __unused, int priv __unused)
{
	return (khx_vmm_priv_error);
}

int
priv_check_cred(struct ucred *cred __unused, int priv __unused)
{
	return (khx_vmm_priv_error);
}

int
chgvmmcnt(struct uidinfo *uip __unused, int diff, rlim_t max)
{
	if (diff > 0 && max != 0 && khx_vmm_vm_count + diff > max)
		return (0);
	khx_vmm_vm_count += diff;
	return (1);
}

int
getenv_int(const char *name __unused, int *data __unused)
{
	return (0);
}

int
exterr_set(int eerror, int category __unused, const char *mmsg __unused,
    uint64ptr_t pp1 __unused, uint64ptr_t pp2 __unused, int line __unused)
{
	return (eerror);
}

unsigned
prison_add_allow(const char *prefix __unused, const char *name __unused,
    const char *prefix_descr __unused, const char *descr __unused)
{
	return (0x1000);
}

#define	KHX_MAC_OK(name, ...)						\
	int name(__VA_ARGS__) { return (0); }
KHX_MAC_OK(mac_vmm_check_create, struct ucred *c __unused,
    const char *n __unused)
KHX_MAC_OK(mac_vmm_check_destroy, struct ucred *c __unused,
    const char *n __unused)
KHX_MAC_OK(mac_vmm_check_memseg_access, struct ucred *c __unused,
    const char *n __unused, const char *seg __unused, vm_ooffset_t off __unused,
    int prot __unused)
KHX_MAC_OK(mac_vmm_check_alloc_memseg, struct ucred *c __unused,
    const char *n __unused)
/* Runs where vmmdev_ioctl() authorizes VM_REINIT: after the cdev lookup,
 * before the memory-segment lock (models a reset already in flight). */
void (*khx_vmm_reinit_hook)(void);

int
mac_vmm_check_reinit(struct ucred *c __unused, const char *n __unused)
{
	if (khx_vmm_reinit_hook != NULL)
		khx_vmm_reinit_hook();
	return (0);
}

int
make_dev_p(int flags, struct cdev **cdev, struct cdevsw *devsw,
    struct ucred *cr, uid_t uid, gid_t gid, int mode, const char *fmt, ...)
{
	struct make_dev_args args;
	char name[SPECNAMELEN + 1];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(name, sizeof(name), fmt, ap);
	va_end(ap);
	make_dev_args_init(&args);
	args.mda_flags = flags;
	args.mda_devsw = devsw;
	args.mda_cr = cr;
	args.mda_uid = uid;
	args.mda_gid = gid;
	args.mda_mode = mode;
	return (make_dev_s(&args, cdev, "%s", name));
}

/* One open file at a time carries cdevpriv (devfs_set/get_cdevpriv). */
static struct {
	void *priv;
	d_priv_dtor_t *dtor;
	int open;
} khx_vmm_file;

int
devfs_set_cdevpriv(void *priv, d_priv_dtor_t *dtor)
{
	if (!khx_vmm_file.open)
		panic("devfs_set_cdevpriv without an open file");
	if (khx_vmm_file.priv != NULL)
		return (EBUSY);
	khx_vmm_file.priv = priv;
	khx_vmm_file.dtor = dtor;
	return (0);
}

int
devfs_get_cdevpriv(void **datap)
{
	if (!khx_vmm_file.open || khx_vmm_file.priv == NULL)
		return (EBADF);
	*datap = khx_vmm_file.priv;
	return (0);
}

void
khx_vmm_file_open(void)
{
	memset(&khx_vmm_file, 0, sizeof(khx_vmm_file));
	khx_vmm_file.open = 1;
}

/* Last close: devfs runs the cdevpriv destructor. */
void
khx_vmm_file_close(void)
{
	if (khx_vmm_file.dtor != NULL)
		khx_vmm_file.dtor(khx_vmm_file.priv);
	memset(&khx_vmm_file, 0, sizeof(khx_vmm_file));
}

void
vmm_stat_register(void *arg __unused)
{
	/* Statistics keep index -1: increments are discarded. */
}

/* WITNESS_WARN(): the harness checks lock state itself. */
int
witness_warn(int flags __unused, struct lock_object *lock __unused,
    const char *fmt __unused, ...)
{
	return (0);
}

/*
 * eventratecheck(9) (ppsratecheck), as in sys/kern/kern_time.c: at most
 * maxeps events per second of `ticks'.  The harness advances `ticks'
 * explicitly, so tests control the second boundary.
 */
int
eventratecheck(struct timeval *lasttime, int *cureps, int maxeps)
{
	int now;

	now = ticks;
	if (lasttime->tv_sec == 0 || (u_int)(now - lasttime->tv_sec) >= hz) {
		lasttime->tv_sec = now;
		*cureps = 1;
		return (maxeps != 0);
	} else {
		(*cureps)++;
		return (maxeps < 0 || *cureps <= maxeps);
	}
}

/*
 * The checkpoint event coordinator (vmm_event_coordinator.c) is outside this
 * suite: it needs sleepqueues and the event-ingress module.  vCPU allocation
 * consults its topology gate, so model the gate's answer; a test may set it
 * to exercise the refusal arm.
 */
int khx_vmm_topology_admit_error;

int
vmm_event_coordinator_checkpoint_topology_admit(
    struct vmm_event_coordinator *coordinator)
{
	(void)coordinator;
	return (khx_vmm_topology_admit_error);
}
