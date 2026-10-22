/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * Copyright (C) 2015 Mihai Carabas <mihai.carabas@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "opt_bhyve_snapshot.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/libkern.h>
#include <sys/ioccom.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/proc.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>

#include <machine/machdep.h>
#include <machine/vmparam.h>
#include <machine/vmm.h>

#ifdef BHYVE_SNAPSHOT
#include <sys/fcntl.h>

#include <machine/vmm_snapshot.h>
#endif

#include <dev/vmm/vmm_dev.h>
#include <dev/vmm/vmm_mem.h>
#include <dev/vmm/vmm_vm.h>

#include "io/vgic.h"

const struct vmmdev_ioctl vmmdev_machdep_ioctls[] = {
	VMMDEV_IOCTL(VM_GET_IDENTIFIER, VMMDEV_IOCTL_SLOCK_MEMSEGS),
	VMMDEV_IOCTL(VM_GET_IDENTITY, VMMDEV_IOCTL_SLOCK_MEMSEGS),
	VMMDEV_IOCTL(VM_GET_ATTESTATION, VMMDEV_IOCTL_SLOCK_MEMSEGS),
	VMMDEV_IOCTL(VM_GET_ARM64_CPU_FEATURES,
	    VMMDEV_IOCTL_LOCK_ONE_VCPU),
	VMMDEV_IOCTL(VM_RUN, VMMDEV_IOCTL_LOCK_ONE_VCPU),
	VMMDEV_IOCTL(VM_INJECT_EXCEPTION, VMMDEV_IOCTL_LOCK_ONE_VCPU),
	VMMDEV_IOCTL(VM_GLA2GPA_NOFAULT, VMMDEV_IOCTL_LOCK_ONE_VCPU),

	VMMDEV_IOCTL(VM_ATTACH_VGIC,
	    VMMDEV_IOCTL_XLOCK_MEMSEGS | VMMDEV_IOCTL_LOCK_ALL_VCPUS),

	VMMDEV_IOCTL(VM_GET_VGIC_VERSION, 0),
	VMMDEV_IOCTL(VM_RAISE_MSI, 0),
	VMMDEV_IOCTL(VM_ASSERT_IRQ, 0),
	VMMDEV_IOCTL(VM_DEASSERT_IRQ, 0),
#ifdef BHYVE_SNAPSHOT
	VMMDEV_IOCTL(VM_SNAPSHOT_REQ, VMMDEV_IOCTL_LOCK_ALL_VCPUS),
	VMMDEV_IOCTL(VM_SNAPSHOT_SESSION, VMMDEV_IOCTL_LOCK_ALL_VCPUS),
	VMMDEV_IOCTL(VM_RESTORE_TIME, VMMDEV_IOCTL_LOCK_ALL_VCPUS),
#endif
};
const size_t vmmdev_machdep_ioctl_count = nitems(vmmdev_machdep_ioctls);

int
vmmdev_machdep_ioctl(struct vm *vm, struct vcpu *vcpu, u_long cmd, caddr_t data,
    int fflag, struct thread *td)
{
	int error;

	error = 0;
	switch (cmd) {
	case VM_GET_IDENTIFIER:
		*(uint16_t *)data = vm_get_id(vm);
		break;
	case VM_GET_ARM64_CPU_FEATURES:
		error = vmm_get_arm64_cpu_features((void *)data);
		break;
	case VM_GET_IDENTITY: {
		struct hypertrace_vm_identity *identity = (void *)data;
		memset(identity, 0, sizeof(*identity));
		identity->vmid = vm_get_id(vm);
		identity->epoch = vm_get_hypertrace_epoch(vm);
		break;
	}
	case VM_GET_ATTESTATION: {
		struct hypertrace_vm_attestation *attestation = (void *)data;
		memset(attestation, 0, sizeof(*attestation));
		attestation->vmid = vm_get_id(vm);
		attestation->epoch = vm_get_hypertrace_epoch(vm);
		strlcpy(attestation->name, vm_name(vm),
		    sizeof(attestation->name));
		break;
	}
	case VM_RUN: {
		struct vm_exit *vme;
		struct vm_run *vmrun;

		vmrun = (struct vm_run *)data;
		vme = vm_exitinfo(vcpu);

		error = vm_run(vcpu);
		if (error != 0)
			break;

		error = copyout(vme, vmrun->vm_exit, sizeof(*vme));
		if (error != 0)
			break;
		break;
	}
	case VM_INJECT_EXCEPTION: {
		struct vm_exception *vmexc;

		vmexc = (struct vm_exception *)data;
		error = vm_inject_exception(vcpu, vmexc->esr, vmexc->far);
		break;
	}
	case VM_GLA2GPA_NOFAULT: {
		struct vm_gla2gpa *gg;

		gg = (struct vm_gla2gpa *)data;
		error = vm_gla2gpa_nofault(vcpu, &gg->paging, gg->gla,
		    gg->prot, &gg->gpa, &gg->fault);
		KASSERT(error == 0 || error == EFAULT,
		    ("%s: vm_gla2gpa unknown error %d", __func__, error));
		break;
	}
	case VM_GET_VGIC_VERSION: {
		struct vm_vgic_version *vgv;

		vgv = (struct vm_vgic_version *)data;
		/* TODO: Query the vgic driver for this */
		vgv->version = 3;
		vgv->flags = 0;
		error = 0;
		break;
	}
	case VM_ATTACH_VGIC: {
		struct vm_vgic_descr *vgic;

		vgic = (struct vm_vgic_descr *)data;
		error = vm_attach_vgic(vm, vgic);
		break;
	}
	case VM_RAISE_MSI: {
		struct vm_msi *vmsi;

		vmsi = (struct vm_msi *)data;
		error = vm_raise_msi(vm, vmsi->msg, vmsi->addr, vmsi->bus,
		    vmsi->slot, vmsi->func);
		break;
	}
	case VM_ASSERT_IRQ: {
		struct vm_irq *vi;

		vi = (struct vm_irq *)data;
		error = vm_assert_irq(vm, vi->irq);
		break;
	}
	case VM_DEASSERT_IRQ: {
		struct vm_irq *vi;

		vi = (struct vm_irq *)data;
		error = vm_deassert_irq(vm, vi->irq);
		break;
	}
#ifdef BHYVE_SNAPSHOT
	case VM_SNAPSHOT_REQ: {
		struct vm_snapshot_meta *snapshot_meta;

		if ((fflag & FWRITE) == 0) {
			error = EBADF;
			break;
		}
		error = vmmdev_snapshot_session_require(vm);
		if (error != 0)
			break;
		snapshot_meta = (struct vm_snapshot_meta *)data;
		error = vm_snapshot_req(vm, snapshot_meta);
		if (error == 0 && snapshot_meta->op == VM_SNAPSHOT_RESTORE &&
		    snapshot_meta->dev_req == STRUCT_VM)
			error = vmmdev_snapshot_restore_time_mark(vm);
		break;
	}
	case VM_SNAPSHOT_SESSION: {
		struct vm_snapshot_session *session;

		session = (struct vm_snapshot_session *)data;
		if ((fflag & FWRITE) == 0) {
			error = EBADF;
			break;
		}
		if (session->version != VM_SNAPSHOT_SESSION_VERSION ||
		    session->flags != 0 || session->reserved[0] != 0 ||
		    session->reserved[1] != 0) {
			error = EINVAL;
			break;
		}
		switch (session->op) {
		case VM_SNAPSHOT_SESSION_BEGIN:
			error = vmmdev_snapshot_session_begin(vm,
			    vm_event_checkpoint_deferred_apply, vm,
			    &session->session_id);
			break;
		case VM_SNAPSHOT_SESSION_COMMIT:
			error = vmmdev_snapshot_session_finish(vm,
			    session->session_id, false);
			break;
		case VM_SNAPSHOT_SESSION_ABORT:
			error = vmmdev_snapshot_session_finish(vm,
			    session->session_id, true);
			break;
		case VM_SNAPSHOT_SESSION_ABORT_CURRENT:
			if (session->session_id != 0) {
				error = EINVAL;
				break;
			}
			error = vmmdev_snapshot_session_abort_current(vm);
			break;
		default:
			error = EINVAL;
			break;
		}
		break;
	}
	case VM_RESTORE_TIME:
		if ((fflag & FWRITE) == 0) {
			error = EBADF;
			break;
		}
		error = vmmdev_snapshot_restore_time_consume(vm);
		if (error == 0)
			error = vm_restore_time(vm);
		break;
#endif
	default:
		error = ENOTTY;
		break;
	}

	return (error);
}

void
vmmdev_ppt_get_bdf(u_long cmd __unused, caddr_t data __unused, int *bus,
    int *slot, int *func)
{

	*bus = -1;
	*slot = -1;
	*func = -1;
}
