/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Userspace harness shadow of <machine/vmm.h>: only the declarations the
 * interrupt/timer device models consume.  The test programs provide the
 * definitions.
 */
#ifndef _KMOCK_MACHINE_VMM_H_
#define	_KMOCK_MACHINE_VMM_H_

#include <sys/types.h>

struct vm;
struct vm_exit;
struct vcpu;
struct vlapic;
struct vioapic;
struct vatpit;
struct vm_snapshot_meta;

/* Mirrors the kernel enum shapes; only referenced in prototypes here. */
enum x2apic_state {
	X2APIC_DISABLED,
	X2APIC_ENABLED,
	X2APIC_STATE_LAST
};

enum vm_intr_trigger {
	EDGE_TRIGGER,
	LEVEL_TRIGGER
};

struct vlapic *vm_lapic(struct vcpu *vcpu);
struct vioapic *vm_ioapic(struct vm *vm);
struct vatpit *vm_atpit(struct vm *vm);
struct vrtc;
struct vrtc *vm_rtc(struct vm *vm);

#endif /* !_KMOCK_MACHINE_VMM_H_ */
