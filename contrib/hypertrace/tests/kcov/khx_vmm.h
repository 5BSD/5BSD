/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Harness API for the amd64 VMM HyperTrace suite (khx_vmm.c).  The VMM's
 * own sources (vmm.c, vmm_vm.c, x86.c, vmm_dev_machdep.c) are compiled
 * unmodified; this models the pieces around them: the VMX/SVM backend
 * (vmm_ops), guest physical memory and linear-address translation, and the
 * HyperTrace provider entry points the VMM calls.  Not production code.
 */
#ifndef KHX_VMM_H
#define KHX_VMM_H

#include <sys/types.h>
#include <sys/param.h>

struct vcpu;
struct vm_hdl;
struct hypertrace_args;

/* ---- backend register file (per vCPU cookie) ---------------------------- */
#define KHX_VMM_NREGS 64
struct khx_vcpu {
	uint64_t regs[KHX_VMM_NREGS];
	uint64_t desc_base[KHX_VMM_NREGS];
	uint32_t desc_access[KHX_VMM_NREGS];
	int getreg_error;		/* forced vmmops_getreg result ... */
	int getreg_only;		/* ... only for register n - 1 (0: all) */
	int setreg_error;		/* forced vmmops_setreg result */
	int getdesc_error;		/* forced vmmops_getdesc result ... */
	int getdesc_only;		/* ... only for segment n - 1 (0: all) */
	int vcpuid;
	struct vcpu *vcpu;
};
struct khx_vcpu *khx_vmm_vcpu(struct vcpu *vcpu);

/* ---- guest memory: GPA window and GLA page table ------------------------ */
#define KHX_GPA_BASE	0x100000UL
#define KHX_GPA_PAGES	8
extern char khx_gmem[KHX_GPA_PAGES * 4096];
/* Map one guest linear page to a guest physical page.  user: CPL 3 may
 * access it; write: writable. */
void khx_gla_map(uint64_t gla, uint64_t gpa, int user, int write);
void khx_gla_unmap_all(void);
extern int khx_gla_error;	/* forced vm_gla2gpa*() error */
extern int khx_gpa_hold_fail;	/* vm_gpa_hold() fails after this many */
extern long khx_gpa_holds;	/* outstanding holds */
extern int khx_last_gla_cpl;	/* cpl of the last translation request */
extern int khx_last_gla_prot;

/* ---- HyperTrace provider entry points ----------------------------------- */
extern int khx_ht_alloc_error;		/* hypertrace_vm_alloc failure */
extern int khx_ht_alloc_fail_after;	/* ... after this many successes */
extern int khx_ht_release_error;	/* hypertrace_vm_release failure */
extern uint16_t khx_ht_release_fail_vmid; /* ... only for this VM (0: any) */
extern int khx_ht_probe_error;		/* hypertrace_probe result */
extern long khx_ht_live;		/* allocated, unreleased identities */
extern long khx_ht_probes;
struct khx_ht_probe_record {
	int id;
	uint16_t vmid;			/* vmm_getid(handle) */
	uint64_t epoch;			/* vmm_getepoch(handle) */
	lwpid_t tid;			/* vmm_gettid(handle) */
	char name[64];			/* vmm_getname(handle) */
	uint64_t rax;			/* vmm_getreg(handle, RAX) */
	int getreg_bad;			/* vmm_getreg(handle, -1) */
	u_int vcpu;			/* htr_curcpu */
	uintptr_t args0, args9;
	uint64_t pcstack_count;
	int copyin_error;		/* vmm_guest_copyin of htr_pcstack */
	uint64_t pc0;
};
extern struct khx_ht_probe_record khx_ht_last;
int khx_ht_is_live(uint16_t vmid, uint64_t epoch);

/* dtrace_hypertrace_config_lock: depth and hook snapshot at unlock. */
extern int khx_ht_config_depth;
extern int khx_ht_config_unlocks;
extern int khx_ht_hooks_at_unlock;	/* number of non-NULL vmm_* hooks */

/* ---- misc backend knobs -------------------------------------------------- */
extern int khx_vmm_hw_supported;
extern int khx_vmm_modinit_error;
extern int khx_vmm_coordinator_error;	/* vmm_event_coordinator_create */
extern int khx_vmm_coordinator_reset_error;
extern int khx_vmm_ppt_error;		/* ppt_unassign_all */
extern int khx_vmm_vmspace_fail;	/* vmspace_alloc returns NULL */
extern int khx_vmm_pvclock;		/* vpvclock_capable() */
extern int khx_vmm_ipi;			/* lapic_ipi_alloc() result */
extern long khx_vmm_runs;

/* Guest entries (vmmops_run) return these exits in order. */
#include <machine/vmm.h>
struct khx_exit {
	int exitcode;
	int error;			/* vmmops_run return value */
	struct vm_guest_paging paging;
};
void khx_vmm_script(const struct khx_exit *exits, int n);

/* vmm_dev.c environment. */
extern int khx_vmm_priv_error;
extern long khx_vmm_vm_count;
void khx_vmm_file_open(void);
extern void (*khx_vmm_reinit_hook)(void);
void khx_vmm_file_close(void);
/* Memory-segment model: live segment objects; drop one test reference. */
extern long khx_vmm_objects;
struct vm_object;
void khx_vm_object_release(struct vm_object *obj);

#endif
