/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * Copyright (C) 2015 Mihai Carabas <mihai.carabas@gmail.com>
 * All rights reserved.
 */

#ifndef	_DEV_VMM_DEV_H_
#define	_DEV_VMM_DEV_H_

#include <sys/param.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ioccom.h>

#include <machine/vmm_dev.h>

#include <dev/vmm/vmm_param.h>
#include <dev/vmm/vmm_startup_request.h>
#include <dev/vmm/vmm_startup_run_request.h>

#ifdef _KERNEL
#include <dev/vmm/vmm_event_coordinator.h>

struct thread;
struct vm;
struct vcpu;

int	vmm_modinit(void);
int	vmm_modcleanup(void);

int	vmmdev_machdep_ioctl(struct vm *vm, struct vcpu *vcpu, u_long cmd,
	    caddr_t data, int fflag, struct thread *td);
#ifdef __amd64__
int	vmmdev_machdep_startup_classify(struct vcpu *, bool *);
int	vmmdev_startup_run_enter(struct vm *, struct vcpu *, uint64_t);
#endif
void	vmmdev_ppt_get_bdf(u_long cmd, caddr_t data, int *bus, int *slot,
	    int *func);
int	vmmdev_snapshot_session_begin(struct vm *,
	    vmm_event_deferred_apply_t *, void *, uint64_t *);
int	vmmdev_snapshot_session_finish(struct vm *, uint64_t, bool);
int	vmmdev_snapshot_session_abort_current(struct vm *);
/*
 * VM_SNAPSHOT_REQ changes VM state on RESTORE and participates in the
 * descriptor-owned checkpoint event fence on both SAVE and RESTORE.  The
 * machine-dependent ioctl dispatcher uses this to prevent a second open VM
 * descriptor from injecting records into another descriptor's transaction.
 */
int	vmmdev_snapshot_session_require(struct vm *);

/*
 * Entry in an ioctl handler table.  A number of generic ioctls are defined,
 * plus a table of machine-dependent ioctls.  The flags indicate the
 * required preconditions for a given ioctl.
 *
 * Some ioctls encode a vcpuid as the first member of their ioctl structure.
 * These ioctls must specify one of the following flags:
 * - ALLOC_VCPU: create the vCPU if it does not already exist
 * - LOCK_ONE_VCPU: create the vCPU if it does not already exist
 *   and lock the vCPU for the duration of the ioctl
 * - MAYBE_ALLOC_VCPU: if the vcpuid is -1, do nothing, otherwise
 *   create the vCPU if it does not already exist
 */
struct vmmdev_ioctl {
	unsigned long	cmd;
#define	VMMDEV_IOCTL_SLOCK_MEMSEGS	0x01
#define	VMMDEV_IOCTL_XLOCK_MEMSEGS	0x02
#define	VMMDEV_IOCTL_LOCK_ONE_VCPU	0x04
#define	VMMDEV_IOCTL_LOCK_ALL_VCPUS	0x08
#define	VMMDEV_IOCTL_ALLOC_VCPU		0x10
#define	VMMDEV_IOCTL_MAYBE_ALLOC_VCPU	0x20
#define	VMMDEV_IOCTL_PPT		0x40
	int		flags;
};

#define	VMMDEV_IOCTL(_cmd, _flags)	{ .cmd = (_cmd), .flags = (_flags) }

extern const struct vmmdev_ioctl vmmdev_machdep_ioctls[];
extern const size_t vmmdev_machdep_ioctl_count;

/*
 * Upper limit on vm_maxcpu.  Limited by use of uint16_t types for CPU counts as
 * well as range of vpid values for VT-x on amd64 and by the capacity of
 * cpuset_t masks.  The call to new_unrhdr() in vpid_init() in vmx.c requires
 * 'vm_maxcpu + 1 <= 0xffff', hence the '- 1' below.
 */
#define	VM_MAXCPU	MIN(0xffff - 1, CPU_SETSIZE)

/* Maximum number of vCPUs in a single VM. */
extern u_int vm_maxcpu;

#endif /* _KERNEL */

#define VMMCTL_CREATE_DESTROY_ON_CLOSE 0x1
#define VMMCTL_FLAGS_MASK	       (VMMCTL_CREATE_DESTROY_ON_CLOSE)

struct vmmctl_vm_create {
	char name[VM_MAX_NAMELEN + 1];
	uint32_t flags;
	int reserved[15];
};

struct vmmctl_vm_destroy {
	char name[VM_MAX_NAMELEN + 1];
	int reserved[16];
};

#define	VMMCTL_VM_CREATE	_IOWR('V', 0, struct vmmctl_vm_create)
#define	VMMCTL_VM_DESTROY	_IOWR('V', 1, struct vmmctl_vm_destroy)

/*
 * Versioned startup-controller management.  The command number is outside
 * every existing machine vmm_dev.h namespace and the payload is fixed-width.
 * Keep this private command aligned with its amd64-only dispatcher and
 * libvmmapi wrappers; it is not a machine-independent VMM contract.
 */
#ifdef __amd64__
#define	VM_STARTUP_REQUEST	\
	_IOWR('v', VMM_STARTUP_REQUEST_IOCNUM, struct vmm_startup_request)
#define	VM_RUN_GENERATION	\
	_IOW('v', VMM_STARTUP_RUN_REQUEST_IOCNUM, \
	    struct vmm_startup_run_request)
#endif

#endif /* _DEV_VMM_DEV_H_ */
