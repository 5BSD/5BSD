/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Userspace harness shadow of <dev/vmm/vmm_ktr.h>: tracing is a no-op.
 */
#ifndef _KMOCK_DEV_VMM_KTR_H_
#define	_KMOCK_DEV_VMM_KTR_H_

#define	VM_CTR0(vm, format)			do { (void)(vm); } while (0)
#define	VM_CTR1(vm, format, p1)			do { (void)(vm); } while (0)
#define	VM_CTR2(vm, format, p1, p2)		do { (void)(vm); } while (0)
#define	VM_CTR3(vm, format, p1, p2, p3)		do { (void)(vm); } while (0)
#define	VM_CTR4(vm, format, p1, p2, p3, p4)	do { (void)(vm); } while (0)

#define	VCPU_CTR0(vm, vcpuid, format)		do { (void)(vm); } while (0)
#define	VCPU_CTR1(vm, vcpuid, format, p1)	do { (void)(vm); } while (0)
#define	VCPU_CTR2(vm, vcpuid, format, p1, p2)	do { (void)(vm); } while (0)
#define	VCPU_CTR3(vm, vcpuid, format, p1, p2, p3) do { (void)(vm); } while (0)
#define	VCPU_CTR4(vm, vcpuid, format, p1, p2, p3, p4) \
						do { (void)(vm); } while (0)

#endif /* !_KMOCK_DEV_VMM_KTR_H_ */
