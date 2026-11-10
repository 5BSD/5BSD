/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#define VM_MAX_NAMELEN 63
#define VMMCTL_VM_CREATE 1
#define VMMCTL_VM_DESTROY 2
#define VMMCTL_VM_DESTROY_IDENTITY 3
#define VMMCTL_VM_LIFETIME_QUERY 4
#define nitems(x) (sizeof(x)/sizeof((x)[0]))
#define PRIV_VMM_DESTROY 1
#define VM_SUSPEND_DESTROY 1
#define KASSERT(x, msg) assert(x)
#include "abi.inc"
struct ucred { int cr_uid, cr_prison; };
struct thread { struct ucred *td_ucred; };
struct vm { uint16_t id; uint64_t epoch; };
struct cdev { int unused; };
struct vmmdev_softc { struct cdev *cdev; struct vm *vm; struct ucred *ucred; };
static struct vm machine;
static struct cdev device;
static struct ucred creator = {1, 2}, stranger = {3, 2};
static struct vmmdev_softc softc = { &device, &machine, &creator };
static int vmmdev_mtx, global_lock, mem_lock, destroyed, suspended, reset_calls;
static int preflight_error, mac_error, privilege_error, pending_reset_error;
static bool reset_before_lock, reset_after_check, missing;
static void sx_xlock(int *lock) { (void)lock; assert(!global_lock); global_lock = 1; }
static void sx_xunlock(int *lock) { (void)lock; assert(global_lock); global_lock = 0; }
static int mac_vmm_check_destroy(struct ucred *cred, const char *name) { return mac_error; }
static int priv_check_cred(struct ucred *cred, int priv) { return privilege_error; }
static struct vmmdev_softc *vmmdev_lookup(const char *name, struct ucred *cred) {
	assert(global_lock && strcmp(name, "source") == 0); return missing ? NULL : &softc;
}
static int vm_reinit(struct vm *vm) { assert(mem_lock); vm->epoch++; reset_calls++; return 0; }
static int queued_reset(struct vmmdev_softc *sc, struct cdev *cdev) {
	int error;
#include "reset.inc"
	return error;
}
static void vm_slock_memsegs(struct vm *vm) {
	assert(global_lock && !mem_lock);
	if (reset_before_lock) { vm->epoch++; reset_before_lock = false; }
	mem_lock = 1;
}
static void vm_unlock_memsegs(struct vm *vm) {
	assert(mem_lock); mem_lock = 0;
	if (reset_after_check) {
		reset_after_check = false; mem_lock = 1;
		pending_reset_error = queued_reset(&softc, &device); mem_lock = 0;
	}
}
static uint16_t vm_get_id(struct vm *vm) { assert(mem_lock); return vm->id; }
static uint64_t vm_get_hypertrace_epoch(struct vm *vm) { assert(mem_lock); return vm->epoch; }
static int vm_suspend(struct vm *vm, int how) { assert(!softc.cdev); suspended++; return 0; }
static int vm_destroy_preflight(struct vm *vm) { return preflight_error; }
static void destroy_dev(struct cdev *cdev) { assert(cdev == &device && !softc.cdev); }
static void vmmdev_destroy(struct vmmdev_softc *sc) { destroyed++; }
static int vmmdev_create(const char *name, uint32_t flags, struct ucred *cred) { return 0; }
#include "destroy.inc"
#include "ioctl.inc"
int main(void) {
	struct thread td = { &creator };
	struct vmmctl_vm_destroy_identity request = { .epoch = 9, .vmid = 7, .name = "source" };
	machine.id = 7; machine.epoch = 9;
	struct vmmctl_vm_lifetime_query query = { .name = "source" };
	memset(query.name, 'x', sizeof(query.name));
	assert(vmmctl_ioctl(NULL, VMMCTL_VM_LIFETIME_QUERY, (void *)&query, 0, &td) == EINVAL);
	strcpy(query.name, "source"); query.reserved[0] = 1;
	assert(vmmctl_ioctl(NULL, VMMCTL_VM_LIFETIME_QUERY, (void *)&query, 0, &td) == EINVAL);
	query.reserved[0] = 0; missing = true;
	assert(vmmctl_ioctl(NULL, VMMCTL_VM_LIFETIME_QUERY, (void *)&query, 0, &td) == ENOENT);
	missing = false; td.td_ucred = &stranger; privilege_error = EPERM;
	assert(vmmctl_ioctl(NULL, VMMCTL_VM_LIFETIME_QUERY, (void *)&query, 0, &td) == EPERM);
	assert(query.vmid == 0 && query.epoch == 0);
	privilege_error = 0;
	assert(vmmctl_ioctl(NULL, VMMCTL_VM_LIFETIME_QUERY, (void *)&query, 0, &td) == 0);
	assert(query.vmid == 7 && query.epoch == 9 && !global_lock && !mem_lock);
	td.td_ucred = &creator;
	request.vmid = 0;
	assert(vmmctl_ioctl(NULL, VMMCTL_VM_DESTROY_IDENTITY, (void *)&request, 0, &td) == EINVAL);
	request.vmid = 7; request.reserved[1] = 1;
	assert(vmmctl_ioctl(NULL, VMMCTL_VM_DESTROY_IDENTITY, (void *)&request, 0, &td) == EINVAL);
	request.reserved[1] = 0; request.epoch = 0;
	assert(vmmctl_ioctl(NULL, VMMCTL_VM_DESTROY_IDENTITY, (void *)&request, 0, &td) == EINVAL);
	request.epoch = 9; memset(request.name, 'x', sizeof(request.name));
	assert(vmmctl_ioctl(NULL, VMMCTL_VM_DESTROY_IDENTITY, (void *)&request, 0, &td) == EINVAL);
	strcpy(request.name, "source"); mac_error = EACCES;
	assert(vmmctl_ioctl(NULL, VMMCTL_VM_DESTROY_IDENTITY, (void *)&request, 0, &td) == EACCES);
	mac_error = 0; td.td_ucred = &stranger; privilege_error = EPERM;
	assert(vmmctl_ioctl(NULL, VMMCTL_VM_DESTROY_IDENTITY, (void *)&request, 0, &td) == EPERM);
	td.td_ucred = &creator; missing = true;
	assert(vmmctl_ioctl(NULL, VMMCTL_VM_DESTROY_IDENTITY, (void *)&request, 0, &td) == EINVAL);
	missing = false; machine.id++;
	assert(vmmctl_ioctl(NULL, VMMCTL_VM_DESTROY_IDENTITY, (void *)&request, 0, &td) == ESTALE);
	machine.id--; reset_before_lock = true;
	assert(vmmctl_ioctl(NULL, VMMCTL_VM_DESTROY_IDENTITY, (void *)&request, 0, &td) == ESTALE);
	assert(!destroyed && !suspended && !global_lock && !mem_lock && softc.cdev == &device);
	machine.epoch = 9; preflight_error = EBUSY;
	assert(vmmctl_ioctl(NULL, VMMCTL_VM_DESTROY_IDENTITY, (void *)&request, 0, &td) == EBUSY);
	assert(!destroyed && suspended == 1 && softc.cdev == &device);
	preflight_error = 0; reset_after_check = true;
	assert(vmmctl_ioctl(NULL, VMMCTL_VM_DESTROY_IDENTITY, (void *)&request, 0, &td) == 0);
	assert(destroyed == 1 && suspended == 2 && pending_reset_error == ENXIO && reset_calls == 0);
	assert(!global_lock && !mem_lock && !softc.cdev);
	softc.cdev = &device; machine.epoch = 100;
	assert(vmmdev_lookup_and_destroy("source", &creator) == 0 && destroyed == 2);
	puts("PASS: identity destruction, reset ordering, permission checks, preflight retry and legacy destroy");
}
