/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Userspace harness shadow of <dev/vmm/vmm_vm.h>: only the declarations
 * the interrupt/timer device models consume.
 */
#ifndef _KMOCK_DEV_VMM_VM_H_
#define	_KMOCK_DEV_VMM_VM_H_

#include <sys/types.h>
#include <sys/_cpuset.h>

#include <machine/vmm.h>

typedef void (*vm_rendezvous_func_t)(struct vcpu *vcpu, void *arg);

int vm_smp_rendezvous(struct vcpu *vcpu, cpuset_t dest,
    vm_rendezvous_func_t func, void *arg);
cpuset_t vm_active_cpus(struct vm *vm);
struct vm *vcpu_vm(struct vcpu *vcpu);

#endif /* !_KMOCK_DEV_VMM_VM_H_ */
