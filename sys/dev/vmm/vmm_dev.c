/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * Copyright (C) 2015 Mihai Carabas <mihai.carabas@gmail.com>
 * All rights reserved.
 */

#include <sys/param.h>
#include <sys/conf.h>
#define	EXTERR_CATEGORY	EXTERR_CAT_VMM
#include <sys/exterrvar.h>
#include <sys/fcntl.h>
#include <sys/ioccom.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/module.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/resourcevar.h>
#include <sys/smp.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>
#include <sys/uio.h>

#include <machine/vmm.h>

#include <vm/vm.h>
#include <vm/vm_object.h>

#ifdef MAC
#include <security/mac/mac_framework.h>
#endif

#include <dev/vmm/vmm_dev.h>
#include <dev/vmm/vmm_dirty_log_collector.h>
#include <dev/vmm/vmm_dirty_log_machdep.h>
#include <dev/vmm/vmm_dirty_log_request.h>
#include <dev/vmm/vmm_event_checkpoint.h>
#include <dev/vmm/vmm_event_wait.h>
#include <dev/vmm/vmm_mem.h>
#include <dev/vmm/vmm_stat.h>
#include <dev/vmm/vmm_vm.h>

#ifdef __amd64__
#ifdef COMPAT_FREEBSD12
struct vm_memseg_12 {
	int		segid;
	size_t		len;
	char		name[64];
};
_Static_assert(sizeof(struct vm_memseg_12) == 80, "COMPAT_FREEBSD12 ABI");

#define	VM_ALLOC_MEMSEG_12	\
	_IOW('v', IOCNUM_ALLOC_MEMSEG, struct vm_memseg_12)
#define	VM_GET_MEMSEG_12	\
	_IOWR('v', IOCNUM_GET_MEMSEG, struct vm_memseg_12)
#endif /* COMPAT_FREEBSD12 */
#ifdef COMPAT_FREEBSD14
struct vm_memseg_14 {
	int		segid;
	size_t		len;
	char		name[VM_MAX_SUFFIXLEN + 1];
};
_Static_assert(sizeof(struct vm_memseg_14) == (VM_MAX_SUFFIXLEN + 1 + 16),
    "COMPAT_FREEBSD14 ABI");

#define	VM_ALLOC_MEMSEG_14	\
	_IOW('v', IOCNUM_ALLOC_MEMSEG, struct vm_memseg_14)
#define	VM_GET_MEMSEG_14	\
	_IOWR('v', IOCNUM_GET_MEMSEG, struct vm_memseg_14)
#endif /* COMPAT_FREEBSD14 */
#endif /* __amd64__ */

struct devmem_softc {
	int	segid;
	char	*name;
	struct cdev *cdev;
	struct vmmdev_softc *sc;
	SLIST_ENTRY(devmem_softc) link;
};

struct vmmdev_softc {
	struct vm	*vm;		/* vm instance cookie */
	struct cdev	*cdev;
	struct ucred	*ucred;
	SLIST_ENTRY(vmmdev_softc) link;
	LIST_ENTRY(vmmdev_softc) priv_link;
	SLIST_HEAD(, devmem_softc) devmem;
	int		flags;
};

struct vmmctl_priv {
	LIST_HEAD(, vmmdev_softc) softcs;
};

static bool vmm_initialized = false;

static SLIST_HEAD(, vmmdev_softc) head;

static unsigned int pr_allow_vmm_flag, pr_allow_vmm_ppt_flag;
static struct sx vmmdev_mtx;
SX_SYSINIT(vmmdev_mtx, &vmmdev_mtx, "vmm device mutex");

static MALLOC_DEFINE(M_VMMDEV, "vmmdev", "vmmdev");

struct vmmdev_fdpriv {
	struct vm *vm;
	struct sx lock;
#ifdef __amd64__
	struct vmm_startup_controller_ticket startup_controller;
#endif
	struct vmm_event_checkpoint checkpoint;
	struct vmm_event_checkpoint_entry *entries;
	uint32_t *instances;
	vmm_event_deferred_apply_t *apply;
	void *apply_arg;
	uint64_t session_id;
#ifdef __amd64__
	uint64_t startup_controller_id;
#endif
	size_t count;
	uint16_t maxcpus;
	bool active;
#ifdef __amd64__
	bool startup_active;
#endif
};

static struct mtx vmmdev_snapshot_session_id_lock;
MTX_SYSINIT(vmmdev_snapshot_session_id_lock,
    &vmmdev_snapshot_session_id_lock, "vmm snapshot session id", MTX_DEF);
static uint64_t vmmdev_snapshot_session_next_id = 1;

#ifdef __amd64__
static struct mtx vmmdev_startup_controller_id_lock;
MTX_SYSINIT(vmmdev_startup_controller_id_lock,
    &vmmdev_startup_controller_id_lock, "vmm startup controller id", MTX_DEF);
static uint64_t vmmdev_startup_controller_next_id = 1;
#endif

SYSCTL_DECL(_hw_vmm);

u_int vm_maxcpu;
SYSCTL_UINT(_hw_vmm, OID_AUTO, maxcpu, CTLFLAG_RDTUN | CTLFLAG_NOFETCH,
    &vm_maxcpu, 0, "Maximum number of vCPUs");

u_int vm_maxvmms;
SYSCTL_UINT(_hw_vmm, OID_AUTO, maxvmms, CTLFLAG_RWTUN,
    &vm_maxvmms, 0, "Maximum number of VMM instances per user");

static void devmem_destroy(void *arg);
static int devmem_create_cdev(struct vmmdev_softc *sc, int id, char *devmem);
static void vmmdev_destroy(struct vmmdev_softc *sc);

static int
vmm_jail_priv_check(struct ucred *ucred)
{
	if (jailed(ucred) &&
	    (ucred->cr_prison->pr_allow & pr_allow_vmm_flag) == 0)
		return (EPERM);

	return (0);
}

static int
vcpu_lock_one(struct vcpu *vcpu)
{
	return (vcpu_set_state(vcpu, VCPU_FROZEN, true));
}

static void
vcpu_unlock_one(struct vcpu *vcpu)
{
	enum vcpu_state state;

	state = vcpu_get_state(vcpu, NULL);
	if (state != VCPU_FROZEN) {
		panic("vcpu %s(%d) has invalid state %d",
		    vm_name(vcpu_vm(vcpu)), vcpu_vcpuid(vcpu), state);
	}

	vcpu_set_state(vcpu, VCPU_IDLE, false);
}

static int
vcpu_lock_all(struct vmmdev_softc *sc)
{
	int error;

	/*
	 * Serialize vcpu_lock_all() callers.  Individual vCPUs are not locked
	 * in a consistent order so we need to serialize to avoid deadlocks.
	 */
	vm_lock_vcpus(sc->vm);
	error = vcpu_set_state_all(sc->vm, VCPU_FROZEN);
	if (error != 0)
		vm_unlock_vcpus(sc->vm);
	return (error);
}

static void
vcpu_unlock_all(struct vmmdev_softc *sc)
{
	struct vcpu *vcpu;
	uint16_t i, maxcpus;

	maxcpus = vm_get_maxcpus(sc->vm);
	for (i = 0; i < maxcpus; i++) {
		vcpu = vm_vcpu(sc->vm, i);
		if (vcpu == NULL)
			continue;
		vcpu_unlock_one(vcpu);
	}
	vm_unlock_vcpus(sc->vm);
}

static int
vmmdev_dirty_log_abort(struct vm *vm,
    const struct vmm_dirty_log_ticket *ticket, int original_error)
{
	int error;

	error = vm_mem_dirty_log_abort(vm, ticket);
	if (error == 0)
		return (original_error);
	/* A transaction which cannot be rolled back must not remain reusable. */
	(void)vm_mem_dirty_log_invalidate(vm);
	return (EPROTO);
}

static int
vmmdev_dirty_log_request(struct vm *vm,
    struct vmm_dirty_log_request *request)
{
	struct vmm_dirty_log_leaf probe;
	struct vmm_dirty_log_request input;
	struct vmm_dirty_log_result *result;
	struct vmm_dirty_log_range range;
	struct vmm_dirty_log_ticket ticket;
	enum vmm_dirty_log_collect_mode mode;
	uint8_t *bitmap, *publication, *staging;
	void *user_output;
	size_t bitmap_bytes, output_bytes;
	int error;

	if (vm == NULL || request == NULL)
		return (EINVAL);
	input = *request;
	if ((error = vmm_dirty_log_request_validate(&input)) != 0)
		return (error);
	range = (struct vmm_dirty_log_range) {
		.gpa = input.gpa,
		.length = input.length,
	};
	switch (input.operation) {
	case VMM_DIRTY_LOG_REQUEST_ENABLE:
		/* Fail at enable time when this architecture cannot track CPU writes. */
		error = vmm_dirty_log_machdep_collector.query(vm, range.gpa,
		    &probe);
		if (error != 0)
			return (error);
		return (vm_mem_dirty_log_enable(vm, &range));
	case VMM_DIRTY_LOG_REQUEST_DISABLE:
		return (vm_mem_dirty_log_invalidate(vm));
	case VMM_DIRTY_LOG_REQUEST_OBSERVE:
		mode = VMM_DIRTY_LOG_COLLECT_OBSERVE;
		break;
	case VMM_DIRTY_LOG_REQUEST_CLEAR:
		mode = VMM_DIRTY_LOG_COLLECT_CLEAR;
		break;
	default:
		return (EINVAL);
	}

	error = vmm_dirty_log_request_output_bytes(&input, &bitmap_bytes,
	    &output_bytes);
	if (error != 0)
		return (error);
	user_output = (void *)(uintptr_t)input.output_address;
	/* Do not sleep with every vCPU frozen and the memory map xlocked. */
	staging = malloc(bitmap_bytes, M_VMMDEV, M_NOWAIT | M_ZERO);
	publication = malloc(output_bytes, M_VMMDEV, M_NOWAIT | M_ZERO);
	if (staging == NULL || publication == NULL) {
		error = ENOMEM;
		goto done;
	}
	result = (struct vmm_dirty_log_result *)publication;
	bitmap = publication + sizeof(*result);
	error = vm_mem_dirty_log_begin(vm, &range, mode, &ticket);
	if (error != 0)
		goto done;
	error = vmm_dirty_log_result_encode(&input, ticket.identity,
	    ticket.map_generation, ticket.dirty_generation, result);
	if (error != 0) {
		error = vmmdev_dirty_log_abort(vm, &ticket, error);
		goto done;
	}
	error = vm_mem_dirty_log_collect(vm, &ticket,
	    &vmm_dirty_log_machdep_collector, vm, staging,
	    bitmap_bytes, bitmap, bitmap_bytes);
	if (error != 0) {
		error = vmmdev_dirty_log_abort(vm, &ticket, error);
		goto done;
	}
	/* Publish one self-describing result before changing hardware state. */
	error = copyout(publication, user_output, output_bytes);
	if (error != 0) {
		error = vmmdev_dirty_log_abort(vm, &ticket, error);
		goto done;
	}
	if (mode == VMM_DIRTY_LOG_COLLECT_CLEAR) {
		error = vm_mem_dirty_log_clear(vm, &ticket,
		    &vmm_dirty_log_machdep_collector, vm);
		if (error != 0) {
			/* A partially-cleared hardware generation is not retryable. */
			(void)vm_mem_dirty_log_invalidate(vm);
			goto done;
		}
	}
	error = vm_mem_dirty_log_finish(vm, &ticket);
done:
	free(publication, M_VMMDEV);
	free(staging, M_VMMDEV);
	return (error);
}

static struct vmmdev_softc *
vmmdev_lookup(const char *name, struct ucred *cred)
{
	struct vmmdev_softc *sc;

	sx_assert(&vmmdev_mtx, SA_XLOCKED);

	SLIST_FOREACH(sc, &head, link) {
		if (strcmp(name, vm_name(sc->vm)) == 0)
			break;
	}

	if (sc == NULL)
		return (NULL);

	if (cr_cansee(cred, sc->ucred))
		return (NULL);

	return (sc);
}

static struct vmmdev_softc *
vmmdev_lookup2(struct cdev *cdev)
{
	return (cdev->si_drv1);
}

#ifdef MAC
static int
vmmdev_prot_from_nprot(int nprot)
{
	int prot;

	prot = 0;
	if ((nprot & PROT_READ) != 0)
		prot |= VM_PROT_READ;
	if ((nprot & PROT_WRITE) != 0)
		prot |= VM_PROT_WRITE;
	if ((nprot & PROT_EXEC) != 0)
		prot |= VM_PROT_EXECUTE;
	return (prot);
}
#endif

static int
vmmdev_rw(struct cdev *cdev, struct uio *uio, int flags)
{
	int error, off, c, prot;
	vm_paddr_t gpa, maxaddr;
	void *hpa, *cookie;
	struct vmmdev_softc *sc;

	sc = vmmdev_lookup2(cdev);
	if (sc == NULL)
		return (ENXIO);

	prot = (uio->uio_rw == UIO_WRITE ? VM_PROT_WRITE : VM_PROT_READ);
#ifdef MAC
	error = mac_vmm_check_mem_access(curthread->td_ucred, vm_name(sc->vm),
	    uio->uio_offset, uio->uio_resid, prot);
	if (error != 0)
		return (error);
#endif
	/*
	 * Get a read lock on the guest memory map.
	 */
	vm_slock_memsegs(sc->vm);

	error = 0;
	maxaddr = vmm_sysmem_maxaddr(sc->vm);
	while (uio->uio_resid > 0 && error == 0) {
		gpa = uio->uio_offset;
		off = gpa & PAGE_MASK;
		c = min(uio->uio_resid, PAGE_SIZE - off);

		/*
		 * The VM has a hole in its physical memory map. If we want to
		 * use 'dd' to inspect memory beyond the hole we need to
		 * provide bogus data for memory that lies in the hole.
		 *
		 * Since this device does not support lseek(2), dd(1) will
		 * read(2) blocks of data to simulate the lseek(2).
		 */
		hpa = vm_gpa_hold_global(sc->vm, gpa, c, prot, &cookie);
		if (hpa == NULL) {
			if (uio->uio_rw == UIO_READ && gpa < maxaddr)
				error = uiomove(__DECONST(void *, zero_region),
				    c, uio);
			else
				error = EFAULT;
		} else {
			error = uiomove(hpa, c, uio);
			vm_gpa_release(cookie);
		}
	}
	vm_unlock_memsegs(sc->vm);
	return (error);
}

CTASSERT(sizeof(((struct vm_memseg *)0)->name) >= VM_MAX_SUFFIXLEN + 1);

static int
get_memseg(struct vmmdev_softc *sc, struct vm_memseg *mseg, size_t len)
{
	struct devmem_softc *dsc;
	int error;
	bool sysmem;

	error = vm_get_memseg(sc->vm, mseg->segid, &mseg->len, &sysmem, NULL);
	if (error || mseg->len == 0)
		return (error);

	if (!sysmem) {
		SLIST_FOREACH(dsc, &sc->devmem, link) {
			if (dsc->segid == mseg->segid)
				break;
		}
		KASSERT(dsc != NULL, ("%s: devmem segment %d not found",
		    __func__, mseg->segid));
		error = copystr(dsc->name, mseg->name, len, NULL);
	} else {
		bzero(mseg->name, len);
	}

	return (error);
}

static int
alloc_memseg(struct vmmdev_softc *sc, struct vm_memseg *mseg, size_t len,
    struct domainset *domainset)
{
	char *name;
	int error;
	bool sysmem;

	error = 0;
	name = NULL;
	sysmem = true;

	/*
	 * The allocation is lengthened by 1 to hold a terminating NUL.  It'll
	 * by stripped off when devfs processes the full string.
	 */
	if (VM_MEMSEG_NAME(mseg)) {
		sysmem = false;
		name = malloc(len, M_VMMDEV, M_WAITOK);
		error = copystr(mseg->name, name, len, NULL);
		if (error)
			goto done;
	}
	error = vm_alloc_memseg(sc->vm, mseg->segid, mseg->len, sysmem, domainset);
	if (error)
		goto done;

	if (VM_MEMSEG_NAME(mseg)) {
		error = devmem_create_cdev(sc, mseg->segid, name);
		if (error)
			vm_free_memseg(sc->vm, mseg->segid);
		else
			name = NULL;	/* freed when 'cdev' is destroyed */
	}
done:
	free(name, M_VMMDEV);
	return (error);
}

#if defined(__amd64__) && \
    (defined(COMPAT_FREEBSD14) || defined(COMPAT_FREEBSD12))
/*
 * Translate pre-15.0 memory segment identifiers into their 15.0 counterparts.
 */
static void
adjust_segid(struct vm_memseg *mseg)
{
	if (mseg->segid != VM_SYSMEM) {
		mseg->segid += (VM_BOOTROM - 1);
	}
}
#endif

static int
vm_get_register_set(struct vcpu *vcpu, unsigned int count, int *regnum,
    uint64_t *regval)
{
	int error, i;

	error = 0;
	for (i = 0; i < count; i++) {
		error = vm_get_register(vcpu, regnum[i], &regval[i]);
		if (error)
			break;
	}
	return (error);
}

static int
vm_set_register_set(struct vcpu *vcpu, unsigned int count, int *regnum,
    uint64_t *regval)
{
	int error, i;

	error = 0;
	for (i = 0; i < count; i++) {
		error = vm_set_register(vcpu, regnum[i], regval[i]);
		if (error)
			break;
	}
	return (error);
}

static int
vmmdev_snapshot_session_id_allocate(uint64_t *session_id)
{

	mtx_lock(&vmmdev_snapshot_session_id_lock);
	if (vmmdev_snapshot_session_next_id == UINT64_MAX) {
		mtx_unlock(&vmmdev_snapshot_session_id_lock);
		return (EOVERFLOW);
	}
	*session_id = vmmdev_snapshot_session_next_id++;
	mtx_unlock(&vmmdev_snapshot_session_id_lock);
	return (0);
}

#ifdef __amd64__
/*
 * The private startup ABI is intentionally build-staged before its consumer.
 * Do not permit it to select kernel ownership until the machine-dependent
 * LAPIC path applies INIT and SIPI, including the frozen-target finalizer,
 * without returning either operation to userspace.
 */
static bool
vmmdev_startup_kernel_actions_ready(void)
{
	return (vmmops_startup_kernel_actions_ready());
}

static int
vmmdev_startup_controller_id_allocate(uint64_t *controller_id)
{

	if (controller_id == NULL || *controller_id != 0)
		return (EINVAL);
	mtx_lock(&vmmdev_startup_controller_id_lock);
	if (vmmdev_startup_controller_next_id == UINT64_MAX) {
		mtx_unlock(&vmmdev_startup_controller_id_lock);
		return (EOVERFLOW);
	}
	*controller_id = vmmdev_startup_controller_next_id++;
	mtx_unlock(&vmmdev_startup_controller_id_lock);
	return (0);
}

static int
vmmdev_startup_status_encode(struct vmmdev_fdpriv *priv,
    struct vmm_startup_request *request)
{
	struct vmm_startup_handshake_status status;
	int error;

	memset(&status, 0, sizeof(status));
	error = vm_startup_status(priv->vm, &priv->startup_controller,
	    &status);
	if (error == 0)
		error = vmm_startup_request_encode_status(request,
		    priv->maxcpus, &status, request);
	explicit_bzero(&status, sizeof(status));
	return (error);
}

static int
vmmdev_startup_request(struct vm *vm, struct vmm_startup_request *request)
{
	struct vmm_event_wait_ticket wait_ticket;
	struct vmmdev_fdpriv *priv;
	uint64_t generation;
	bool claimed;
	int error, release_error;

	if (vm == NULL || request == NULL)
		return (EINVAL);
	error = devfs_get_cdevpriv((void **)&priv);
	if (error != 0)
		return (error);
	if (priv->vm != vm)
		return (EXDEV);
	error = vmm_startup_request_validate(request, priv->maxcpus);
	if (error != 0)
		return (error);

	switch (request->operation) {
	case VMM_STARTUP_REQUEST_CONFIGURE:
		if (!vmmdev_startup_kernel_actions_ready())
			return (EOPNOTSUPP);
		claimed = false;
		generation = 0;
		sx_xlock(&priv->lock);
		if (priv->startup_active) {
			error = EBUSY;
			goto configure_out;
		}
		if (priv->startup_controller_id == 0) {
			error = vmmdev_startup_controller_id_allocate(
			    &priv->startup_controller_id);
			if (error != 0)
				goto configure_out;
		}
		memset(&priv->startup_controller, 0,
		    sizeof(priv->startup_controller));
		error = vm_startup_controller_claim(vm,
		    &priv->startup_controller, priv->startup_controller_id);
		if (error != 0)
			goto configure_out;
		claimed = true;
		error = vm_startup_configure_kernel(vm,
		    &priv->startup_controller, request->expected_vcpus,
		    &generation);
		if (error == 0) {
			priv->startup_active = true;
			error = vmmdev_startup_status_encode(priv, request);
		}
		if (error != 0 && claimed) {
			release_error = vm_startup_controller_release(vm,
			    &priv->startup_controller);
			if (release_error == 0) {
				priv->startup_active = false;
			} else {
				/* Preserve the exact ticket for final-close retry. */
				priv->startup_active = true;
				error = release_error;
			}
		}
configure_out:
		sx_xunlock(&priv->lock);
		return (error);
	case VMM_STARTUP_REQUEST_WAIT_READY:
	case VMM_STARTUP_REQUEST_COMMIT:
	case VMM_STARTUP_REQUEST_STATUS:
		sx_xlock(&priv->lock);
		if (!priv->startup_active) {
			sx_xunlock(&priv->lock);
			return (ENOENT);
		}
		/*
		 * A device method holds the open file description alive, so final
		 * close cannot run its cdevpriv destructor while this operation uses
		 * the immutable embedded ticket.  Drop the sx before any wait.
		 */
		sx_xunlock(&priv->lock);
		break;
	default:
		return (EINVAL);
	}

	if (request->operation == VMM_STARTUP_REQUEST_WAIT_READY) {
		memset(&wait_ticket, 0, sizeof(wait_ticket));
		error = vm_startup_wait_ready(vm, &priv->startup_controller,
		    request->generation, &wait_ticket, "vmstart", 0);
		explicit_bzero(&wait_ticket, sizeof(wait_ticket));
	} else if (request->operation == VMM_STARTUP_REQUEST_COMMIT) {
		error = vm_startup_commit(vm, &priv->startup_controller,
		    request->generation);
	} else {
		error = 0;
	}
	if (error == 0)
		error = vmmdev_startup_status_encode(priv, request);
	return (error);
}

int
vmmdev_startup_run_enter(struct vm *vm, struct vcpu *vcpu,
    uint64_t generation)
{
	struct vmm_event_wait_ticket wait_ticket;
	struct vmmdev_fdpriv *priv;
	bool bootstrap_processor;
	int error;

	if (vm == NULL || vcpu == NULL || generation == 0)
		return (EINVAL);
	if (!vmmdev_startup_kernel_actions_ready())
		return (EOPNOTSUPP);
	error = devfs_get_cdevpriv((void **)&priv);
	if (error != 0)
		return (error);
	if (priv->vm != vm)
		return (EXDEV);

	error = vmmdev_machdep_startup_classify(vcpu, &bootstrap_processor);
	if (error != 0)
		return (error);
	sx_slock(&priv->lock);
	if (!priv->startup_active) {
		sx_sunlock(&priv->lock);
		return (ENOENT);
	}
	error = vm_startup_enter(vm, &priv->startup_controller,
	    vcpu_vcpuid(vcpu), generation, bootstrap_processor);
	sx_sunlock(&priv->lock);
	if (error != 0)
		return (error);

	memset(&wait_ticket, 0, sizeof(wait_ticket));
	error = vm_startup_wait_committed(vm, &priv->startup_controller,
	    generation, &wait_ticket, "vmcommit", 0);
	explicit_bzero(&wait_ticket, sizeof(wait_ticket));
	return (error);
}
#endif

static void
vmmdev_snapshot_session_clear(struct vmmdev_fdpriv *priv)
{

	if (priv->count != 0) {
		explicit_bzero(priv->entries,
		    priv->count * sizeof(*priv->entries));
		explicit_bzero(priv->instances,
		    priv->count * sizeof(*priv->instances));
	}
	explicit_bzero(&priv->checkpoint, sizeof(priv->checkpoint));
	priv->apply = NULL;
	priv->apply_arg = NULL;
	priv->session_id = 0;
	priv->count = 0;
	priv->active = false;
}

static void
vmmdev_snapshot_session_notify(struct vmmdev_fdpriv *priv)
{
	struct vcpu *vcpu;
	size_t i;

	/*
	 * The deferred apply callback runs while the coordinator retains every
	 * selected ingress spin lock.  Notify only after the coordinator returns
	 * and releases those locks: a running vCPU can hold its run-state spin
	 * lock while entering an event publisher, so reversing that order here
	 * would deadlock close-time cleanup.  A spurious notification for a
	 * member without deferred work is harmless and keeps this MI adapter
	 * independent of architecture-specific deferred-mask values.
	 */
	for (i = 0; i < priv->count; i++) {
		vcpu = vm_vcpu(priv->vm, priv->instances[i]);
		if (vcpu == NULL)
			panic("%s: missing checkpoint vCPU %u", __func__,
			    priv->instances[i]);
		vcpu_notify_event(vcpu);
	}
}

static void
vmmdev_fdpriv_dtor(void *arg)
{
	struct vmmdev_fdpriv *priv;
	int cancel_error, error;

	priv = arg;
	sx_xlock(&priv->lock);
	if (priv->active && priv->count != 0) {
		error = vmm_event_coordinator_checkpoint_abort(
		    vm_event_coordinator(priv->vm), &priv->checkpoint,
		    priv->apply, priv->apply_arg);
		if (error != 0)
			panic("%s: checkpoint session abort failed: %d",
			    __func__, error);
		vmmdev_snapshot_session_notify(priv);
	}
	vmmdev_snapshot_session_clear(priv);
#ifdef __amd64__
	if (priv->startup_active) {
		error = vm_startup_controller_release(priv->vm,
		    &priv->startup_controller);
		if (error != 0) {
			/*
			 * Do not free the only credential while leaving admission
			 * live.  An exact release has no expected failure, but a
			 * defensive close must still force the whole event domain
			 * closed before discarding cdevpriv storage.
			 */
			cancel_error = vmm_event_coordinator_cancel(
			    vm_event_coordinator(priv->vm));
			printf("%s: startup release failed: %d; "
			    "fail-closed cancellation: %d\n", __func__, error,
			    cancel_error);
		}
		priv->startup_active = false;
	}
	explicit_bzero(&priv->startup_controller,
	    sizeof(priv->startup_controller));
#endif
	sx_xunlock(&priv->lock);
	sx_destroy(&priv->lock);
	if (priv->entries != NULL)
		explicit_bzero(priv->entries,
		    (size_t)priv->maxcpus * sizeof(*priv->entries));
	if (priv->instances != NULL)
		explicit_bzero(priv->instances,
		    (size_t)priv->maxcpus * sizeof(*priv->instances));
	free(priv->entries, M_VMMDEV);
	free(priv->instances, M_VMMDEV);
	explicit_bzero(priv, sizeof(*priv));
	free(priv, M_VMMDEV);
}

int
vmmdev_snapshot_session_begin(struct vm *vm,
    vmm_event_deferred_apply_t *apply, void *apply_arg,
    uint64_t *session_id)
{
	struct vmm_event_wait_ticket ticket;
	struct vmmdev_fdpriv *priv;
	struct vcpu *vcpu;
	size_t count;
	uint16_t i;
	bool begun;
	int abort_error, error;

	if (vm == NULL || session_id == NULL || *session_id != 0 ||
	    !sx_xlocked(&vm->vcpus_init_lock))
		return (EINVAL);
	error = devfs_get_cdevpriv((void **)&priv);
	if (error != 0)
		return (error);
	if (priv->vm != vm)
		return (EXDEV);

	sx_xlock(&priv->lock);
	if (priv->active) {
		error = EBUSY;
		goto out;
	}
	if (priv->entries == NULL) {
		priv->entries = mallocarray(priv->maxcpus,
		    sizeof(*priv->entries), M_VMMDEV, M_NOWAIT | M_ZERO);
		priv->instances = mallocarray(priv->maxcpus,
		    sizeof(*priv->instances), M_VMMDEV, M_NOWAIT | M_ZERO);
		if (priv->entries == NULL || priv->instances == NULL) {
			free(priv->entries, M_VMMDEV);
			free(priv->instances, M_VMMDEV);
			priv->entries = NULL;
			priv->instances = NULL;
			error = ENOMEM;
			goto out;
		}
	}
	begun = false;
	count = 0;
	for (i = 0; i < priv->maxcpus; i++) {
		vcpu = vm_vcpu(vm, i);
		if (vcpu == NULL)
			continue;
		if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN) {
			error = EBUSY;
			priv->count = count;
			goto failed;
		}
		if (count >= priv->maxcpus)
			panic("%s: vCPU session capacity exceeded", __func__);
		priv->instances[count++] = i;
	}
	if (count == 0) {
		error = EINVAL;
		priv->count = 0;
		goto failed;
	}

	priv->apply = apply;
	priv->apply_arg = apply_arg;
	priv->count = count;
	error = vmm_event_coordinator_checkpoint_begin(
	    vm_event_coordinator(vm), &priv->checkpoint, priv->entries,
	    priv->instances, count);
	if (error != 0)
		goto failed;
	begun = true;
	memset(&ticket, 0, sizeof(ticket));
	error = vmm_event_coordinator_checkpoint_wait_ready(
	    vm_event_coordinator(vm), &priv->checkpoint, &ticket,
	    "vmsess", 0);
	if (error != 0)
		goto failed;
	error = vmmdev_snapshot_session_id_allocate(&priv->session_id);
	if (error != 0)
		goto failed;
	priv->active = true;
	*session_id = priv->session_id;
	goto out;

failed:
	if (begun) {
		abort_error = vmm_event_coordinator_checkpoint_abort(
		    vm_event_coordinator(vm), &priv->checkpoint, priv->apply,
		    priv->apply_arg);
		if (abort_error != 0)
			panic("%s: failed begin rollback: %d", __func__,
			    abort_error);
		vmmdev_snapshot_session_notify(priv);
	}
	vmmdev_snapshot_session_clear(priv);
out:
	sx_xunlock(&priv->lock);
	return (error);
}

static int
vmmdev_snapshot_session_finish_locked(struct vmmdev_fdpriv *priv,
    bool aborting)
{
	int error;

	sx_assert(&priv->lock, SA_XLOCKED);
	if (!priv->active || priv->count == 0)
		return (EPROTO);
	if (aborting)
		error = vmm_event_coordinator_checkpoint_abort(
		    vm_event_coordinator(priv->vm), &priv->checkpoint,
		    priv->apply, priv->apply_arg);
	else
		error = vmm_event_coordinator_checkpoint_finish(
		    vm_event_coordinator(priv->vm), &priv->checkpoint,
		    priv->apply, priv->apply_arg);
	if (error == 0) {
		vmmdev_snapshot_session_notify(priv);
		vmmdev_snapshot_session_clear(priv);
	}
	return (error);
}

int
vmmdev_snapshot_session_finish(struct vm *vm, uint64_t session_id,
    bool aborting)
{
	struct vmmdev_fdpriv *priv;
	int error;

	if (vm == NULL || session_id == 0 ||
	    !sx_xlocked(&vm->vcpus_init_lock))
		return (EINVAL);
	error = devfs_get_cdevpriv((void **)&priv);
	if (error != 0)
		return (error);
	if (priv->vm != vm)
		return (EXDEV);

	sx_xlock(&priv->lock);
	if (!priv->active || priv->session_id != session_id) {
		error = ESTALE;
		goto out;
	}
	error = vmmdev_snapshot_session_finish_locked(priv, aborting);
out:
	sx_xunlock(&priv->lock);
	return (error);
}

int
vmmdev_snapshot_session_abort_current(struct vm *vm)
{
	struct vmmdev_fdpriv *priv;
	int error;

	if (vm == NULL || !sx_xlocked(&vm->vcpus_init_lock))
		return (EINVAL);
	error = devfs_get_cdevpriv((void **)&priv);
	if (error != 0)
		return (error);
	if (priv->vm != vm)
		return (EXDEV);

	/* Recover only this open file description's currently active session. */
	sx_xlock(&priv->lock);
	if (!priv->active)
		error = ESTALE;
	else
		error = vmmdev_snapshot_session_finish_locked(priv, true);
	sx_xunlock(&priv->lock);
	return (error);
}

static int
vmmdev_open(struct cdev *dev, int flags, int fmt, struct thread *td)
{
	struct vmmdev_fdpriv *priv;
	struct vmmdev_softc *sc;
	int error;

	/*
	 * A jail without vmm access shouldn't be able to access vmm device
	 * files at all, but check here just to be thorough.
	 */
	error = vmm_jail_priv_check(td->td_ucred);
	if (error != 0)
		return (error);
	sc = vmmdev_lookup2(dev);
	if (sc == NULL)
		return (ENXIO);
	priv = malloc(sizeof(*priv), M_VMMDEV, M_WAITOK | M_ZERO);
	priv->maxcpus = vm_get_maxcpus(sc->vm);
	if (priv->maxcpus == 0) {
		free(priv, M_VMMDEV);
		return (EINVAL);
	}
	priv->vm = sc->vm;
	sx_init(&priv->lock, "vmm snapshot session");
	error = devfs_set_cdevpriv(priv, vmmdev_fdpriv_dtor);
	if (error != 0) {
		sx_destroy(&priv->lock);
		free(priv, M_VMMDEV);
		return (error);
	}

	return (0);
}

static const struct vmmdev_ioctl vmmdev_ioctls[] = {
#ifdef __amd64__
	VMMDEV_IOCTL(VM_STARTUP_REQUEST, 0),
#endif
	VMMDEV_IOCTL(VM_GET_REGISTER, VMMDEV_IOCTL_LOCK_ONE_VCPU),
	VMMDEV_IOCTL(VM_SET_REGISTER, VMMDEV_IOCTL_LOCK_ONE_VCPU),
	VMMDEV_IOCTL(VM_GET_REGISTER_SET, VMMDEV_IOCTL_LOCK_ONE_VCPU),
	VMMDEV_IOCTL(VM_SET_REGISTER_SET, VMMDEV_IOCTL_LOCK_ONE_VCPU),
	VMMDEV_IOCTL(VM_GET_CAPABILITY, VMMDEV_IOCTL_LOCK_ONE_VCPU),
	VMMDEV_IOCTL(VM_SET_CAPABILITY, VMMDEV_IOCTL_LOCK_ONE_VCPU),
#ifdef __amd64__
	VMMDEV_IOCTL(VM_GET_CPUID, VMMDEV_IOCTL_LOCK_ONE_VCPU),
	VMMDEV_IOCTL(VM_GET_CPU_COMPAT, VMMDEV_IOCTL_LOCK_ONE_VCPU),
#endif
	VMMDEV_IOCTL(VM_ACTIVATE_CPU, VMMDEV_IOCTL_LOCK_ONE_VCPU),
	VMMDEV_IOCTL(VM_INJECT_EXCEPTION, VMMDEV_IOCTL_LOCK_ONE_VCPU),
	VMMDEV_IOCTL(VM_STATS, VMMDEV_IOCTL_LOCK_ONE_VCPU),
	VMMDEV_IOCTL(VM_STAT_DESC, 0),

#ifdef __amd64__
#ifdef COMPAT_FREEBSD12
	VMMDEV_IOCTL(VM_ALLOC_MEMSEG_12,
	    VMMDEV_IOCTL_XLOCK_MEMSEGS | VMMDEV_IOCTL_LOCK_ALL_VCPUS),
#endif
#ifdef COMPAT_FREEBSD14
	VMMDEV_IOCTL(VM_ALLOC_MEMSEG_14,
	    VMMDEV_IOCTL_XLOCK_MEMSEGS | VMMDEV_IOCTL_LOCK_ALL_VCPUS),
#endif
#endif /* __amd64__ */
	VMMDEV_IOCTL(VM_ALLOC_MEMSEG,
	    VMMDEV_IOCTL_XLOCK_MEMSEGS | VMMDEV_IOCTL_LOCK_ALL_VCPUS),
	VMMDEV_IOCTL(VM_MMAP_MEMSEG,
	    VMMDEV_IOCTL_XLOCK_MEMSEGS | VMMDEV_IOCTL_LOCK_ALL_VCPUS),
	VMMDEV_IOCTL(VM_MUNMAP_MEMSEG,
	    VMMDEV_IOCTL_XLOCK_MEMSEGS | VMMDEV_IOCTL_LOCK_ALL_VCPUS),
	VMMDEV_IOCTL(VM_REINIT,
	    VMMDEV_IOCTL_XLOCK_MEMSEGS | VMMDEV_IOCTL_LOCK_ALL_VCPUS),
	VMMDEV_IOCTL(VM_DIRTY_LOG_REQUEST,
	    VMMDEV_IOCTL_XLOCK_MEMSEGS | VMMDEV_IOCTL_LOCK_ALL_VCPUS),

#ifdef __amd64__
#if defined(COMPAT_FREEBSD12)
	VMMDEV_IOCTL(VM_GET_MEMSEG_12, VMMDEV_IOCTL_SLOCK_MEMSEGS),
#endif
#ifdef COMPAT_FREEBSD14
	VMMDEV_IOCTL(VM_GET_MEMSEG_14, VMMDEV_IOCTL_SLOCK_MEMSEGS),
#endif
#endif /* __amd64__ */
	VMMDEV_IOCTL(VM_GET_MEMSEG, VMMDEV_IOCTL_SLOCK_MEMSEGS),
	VMMDEV_IOCTL(VM_MMAP_GETNEXT, VMMDEV_IOCTL_SLOCK_MEMSEGS),

	VMMDEV_IOCTL(VM_SUSPEND_CPU, VMMDEV_IOCTL_MAYBE_ALLOC_VCPU),
	VMMDEV_IOCTL(VM_RESUME_CPU, VMMDEV_IOCTL_MAYBE_ALLOC_VCPU),

	VMMDEV_IOCTL(VM_SUSPEND, 0),
	VMMDEV_IOCTL(VM_GET_CPUS, 0),
	VMMDEV_IOCTL(VM_GET_TOPOLOGY, 0),
	VMMDEV_IOCTL(VM_SET_TOPOLOGY, 0),
};

static int
vmmdev_ioctl(struct cdev *cdev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	struct vmmdev_softc *sc;
	struct vcpu *vcpu;
	const struct vmmdev_ioctl *ioctl;
	struct vm_memseg *mseg;
	int error, vcpuid;

	sc = vmmdev_lookup2(cdev);
	if (sc == NULL)
		return (ENXIO);

	ioctl = NULL;
	for (size_t i = 0; i < nitems(vmmdev_ioctls); i++) {
		if (vmmdev_ioctls[i].cmd == cmd) {
			ioctl = &vmmdev_ioctls[i];
			break;
		}
	}
	if (ioctl == NULL) {
		for (size_t i = 0; i < vmmdev_machdep_ioctl_count; i++) {
			if (vmmdev_machdep_ioctls[i].cmd == cmd) {
				ioctl = &vmmdev_machdep_ioctls[i];
				break;
			}
		}
	}
	if (ioctl == NULL)
		return (ENOTTY);

	if ((ioctl->flags & VMMDEV_IOCTL_PPT) != 0) {
		if (jailed(td->td_ucred) && (td->td_ucred->cr_prison->pr_allow &
		    pr_allow_vmm_ppt_flag) == 0)
			return (EPERM);
		error = priv_check(td, PRIV_VMM_PPTDEV);
		if (error != 0)
			return (error);
#ifdef MAC
		{
			int ppt_bus, ppt_slot, ppt_func;

			WITNESS_WARN(WARN_SLEEPOK | WARN_GIANTOK, NULL,
			    "mac_vmm_check_passthrough");
			vmmdev_ppt_get_bdf(cmd, data, &ppt_bus, &ppt_slot,
			    &ppt_func);
			error = mac_vmm_check_passthrough(td->td_ucred,
			    vm_name(sc->vm), ppt_bus, ppt_slot, ppt_func);
			if (error != 0)
				return (error);
		}
#endif
	}

#ifdef MAC
	WITNESS_WARN(WARN_SLEEPOK | WARN_GIANTOK, NULL,
	    "mac_vmm_check_alloc_memseg/reinit");
	switch (cmd) {
	case VM_ALLOC_MEMSEG:
#ifdef __amd64__
#ifdef COMPAT_FREEBSD12
	case VM_ALLOC_MEMSEG_12:
#endif
#ifdef COMPAT_FREEBSD14
	case VM_ALLOC_MEMSEG_14:
#endif
#endif
		error = mac_vmm_check_alloc_memseg(td->td_ucred,
		    vm_name(sc->vm));
		if (error != 0)
			return (error);
		break;
	case VM_REINIT:
		error = mac_vmm_check_reinit(td->td_ucred,
		    vm_name(sc->vm));
		if (error != 0)
			return (error);
		break;
	}
#endif

	if ((ioctl->flags & VMMDEV_IOCTL_XLOCK_MEMSEGS) != 0)
		vm_xlock_memsegs(sc->vm);
	else if ((ioctl->flags & VMMDEV_IOCTL_SLOCK_MEMSEGS) != 0)
		vm_slock_memsegs(sc->vm);

	vcpu = NULL;
	vcpuid = -1;
	if ((ioctl->flags & (VMMDEV_IOCTL_LOCK_ONE_VCPU |
	    VMMDEV_IOCTL_ALLOC_VCPU | VMMDEV_IOCTL_MAYBE_ALLOC_VCPU)) != 0) {
		vcpuid = *(int *)data;
		if (vcpuid == -1) {
			if ((ioctl->flags &
			    VMMDEV_IOCTL_MAYBE_ALLOC_VCPU) == 0) {
				error = EINVAL;
				goto lockfail;
			}
		} else {
			vcpu = vm_alloc_vcpu(sc->vm, vcpuid);
			if (vcpu == NULL) {
				error = EINVAL;
				goto lockfail;
			}
			if ((ioctl->flags & VMMDEV_IOCTL_LOCK_ONE_VCPU) != 0) {
				error = vcpu_lock_one(vcpu);
				if (error)
					goto lockfail;
			}
		}
	}
	if ((ioctl->flags & VMMDEV_IOCTL_LOCK_ALL_VCPUS) != 0) {
		error = vcpu_lock_all(sc);
		if (error)
			goto lockfail;
	}

	switch (cmd) {
#ifdef __amd64__
	case VM_STARTUP_REQUEST:
		error = vmmdev_startup_request(sc->vm,
		    (struct vmm_startup_request *)data);
		break;
#endif
	case VM_SUSPEND: {
		struct vm_suspend *vmsuspend;

		vmsuspend = (struct vm_suspend *)data;
		error = vm_suspend(sc->vm, vmsuspend->how);
		break;
	}
	case VM_REINIT:
		error = vm_reinit(sc->vm);
		break;
	case VM_DIRTY_LOG_REQUEST:
		error = vmmdev_dirty_log_request(sc->vm,
		    (struct vmm_dirty_log_request *)data);
		break;
	case VM_STAT_DESC: {
		struct vm_stat_desc *statdesc;

		statdesc = (struct vm_stat_desc *)data;
		error = vmm_stat_desc_copy(statdesc->index, statdesc->desc,
		    sizeof(statdesc->desc));
		break;
	}
	case VM_STATS: {
		struct vm_stats *vmstats;

		vmstats = (struct vm_stats *)data;
		getmicrotime(&vmstats->tv);
		error = vmm_stat_copy(vcpu, vmstats->index,
		    nitems(vmstats->statbuf), &vmstats->num_entries,
		    vmstats->statbuf);
		break;
	}
	case VM_MMAP_GETNEXT: {
		struct vm_memmap *mm;

		mm = (struct vm_memmap *)data;
		error = vm_mmap_getnext(sc->vm, &mm->gpa, &mm->segid,
		    &mm->segoff, &mm->len, &mm->prot, &mm->flags);
		break;
	}
	case VM_MMAP_MEMSEG: {
		struct vm_memmap *mm;

		mm = (struct vm_memmap *)data;
		error = vm_mmap_memseg(sc->vm, mm->gpa, mm->segid, mm->segoff,
		    mm->len, mm->prot, mm->flags);
		break;
	}
	case VM_MUNMAP_MEMSEG: {
		struct vm_munmap *mu;

		mu = (struct vm_munmap *)data;
		error = vm_munmap_memseg(sc->vm, mu->gpa, mu->len);
		break;
	}
#ifdef __amd64__
#ifdef COMPAT_FREEBSD12
	case VM_ALLOC_MEMSEG_12:
		mseg = (struct vm_memseg *)data;

		adjust_segid(mseg);
		error = alloc_memseg(sc, mseg,
		    sizeof(((struct vm_memseg_12 *)0)->name), NULL);
		break;
	case VM_GET_MEMSEG_12:
		mseg = (struct vm_memseg *)data;

		adjust_segid(mseg);
		error = get_memseg(sc, mseg,
		    sizeof(((struct vm_memseg_12 *)0)->name));
		break;
#endif /* COMPAT_FREEBSD12 */
#ifdef COMPAT_FREEBSD14
	case VM_ALLOC_MEMSEG_14:
		mseg = (struct vm_memseg *)data;

		adjust_segid(mseg);
		error = alloc_memseg(sc, mseg,
		    sizeof(((struct vm_memseg_14 *)0)->name), NULL);
		break;
	case VM_GET_MEMSEG_14:
		mseg = (struct vm_memseg *)data;

		adjust_segid(mseg);
		error = get_memseg(sc, mseg,
		    sizeof(((struct vm_memseg_14 *)0)->name));
		break;
#endif /* COMPAT_FREEBSD14 */
#endif /* __amd64__ */
	case VM_ALLOC_MEMSEG: {
		domainset_t *mask;
		struct domainset *domainset, domain;

		domainset = NULL;
		mseg = (struct vm_memseg *)data;
		if (mseg->ds_policy != DOMAINSET_POLICY_INVALID && mseg->ds_mask != NULL) {
			if (mseg->ds_mask_size < sizeof(domainset_t) ||
			    mseg->ds_mask_size > DOMAINSET_MAXSIZE / NBBY) {
				error = ERANGE;
				break;
			}
			memset(&domain, 0, sizeof(domain));
			mask = malloc(mseg->ds_mask_size, M_VMMDEV, M_WAITOK);
			error = copyin(mseg->ds_mask, mask, mseg->ds_mask_size);
			if (error) {
				free(mask, M_VMMDEV);
				break;
			}
			error = domainset_populate(&domain, mask, mseg->ds_policy,
			    mseg->ds_mask_size);
			free(mask, M_VMMDEV);
			if (error)
				break;
			domainset = domainset_create(&domain);
			if (domainset == NULL) {
				error = EINVAL;
				break;
			}
		}
		error = alloc_memseg(sc, mseg, sizeof(mseg->name), domainset);
		break;
	}
	case VM_GET_MEMSEG:
		error = get_memseg(sc, (struct vm_memseg *)data,
		    sizeof(((struct vm_memseg *)0)->name));
		break;
	case VM_GET_REGISTER: {
		struct vm_register *vmreg;

		vmreg = (struct vm_register *)data;
		error = vm_get_register(vcpu, vmreg->regnum, &vmreg->regval);
		break;
	}
	case VM_SET_REGISTER: {
		struct vm_register *vmreg;

		vmreg = (struct vm_register *)data;
		error = vm_set_register(vcpu, vmreg->regnum, vmreg->regval);
		break;
	}
	case VM_GET_REGISTER_SET: {
		struct vm_register_set *vmregset;
		uint64_t *regvals;
		int *regnums;

		vmregset = (struct vm_register_set *)data;
		if (vmregset->count > VM_REG_LAST) {
			error = EINVAL;
			break;
		}
		regvals = mallocarray(vmregset->count, sizeof(regvals[0]),
		    M_VMMDEV, M_WAITOK);
		regnums = mallocarray(vmregset->count, sizeof(regnums[0]),
		    M_VMMDEV, M_WAITOK);
		error = copyin(vmregset->regnums, regnums, sizeof(regnums[0]) *
		    vmregset->count);
		if (error == 0)
			error = vm_get_register_set(vcpu,
			    vmregset->count, regnums, regvals);
		if (error == 0)
			error = copyout(regvals, vmregset->regvals,
			    sizeof(regvals[0]) * vmregset->count);
		free(regvals, M_VMMDEV);
		free(regnums, M_VMMDEV);
		break;
	}
	case VM_SET_REGISTER_SET: {
		struct vm_register_set *vmregset;
		uint64_t *regvals;
		int *regnums;

		vmregset = (struct vm_register_set *)data;
		if (vmregset->count > VM_REG_LAST) {
			error = EINVAL;
			break;
		}
		regvals = mallocarray(vmregset->count, sizeof(regvals[0]),
		    M_VMMDEV, M_WAITOK);
		regnums = mallocarray(vmregset->count, sizeof(regnums[0]),
		    M_VMMDEV, M_WAITOK);
		error = copyin(vmregset->regnums, regnums, sizeof(regnums[0]) *
		    vmregset->count);
		if (error == 0)
			error = copyin(vmregset->regvals, regvals,
			    sizeof(regvals[0]) * vmregset->count);
		if (error == 0)
			error = vm_set_register_set(vcpu,
			    vmregset->count, regnums, regvals);
		free(regvals, M_VMMDEV);
		free(regnums, M_VMMDEV);
		break;
	}
	case VM_GET_CAPABILITY: {
		struct vm_capability *vmcap;

		vmcap = (struct vm_capability *)data;
		error = vm_get_capability(vcpu, vmcap->captype, &vmcap->capval);
		break;
	}
#ifdef __amd64__
	case VM_GET_CPUID: {
		struct vm_cpuid *vmcpuid;

		vmcpuid = (struct vm_cpuid *)data;
		error = vm_get_cpuid(vcpu, vmcpuid->flags, &vmcpuid->eax,
		    &vmcpuid->ebx, &vmcpuid->ecx, &vmcpuid->edx);
		break;
	}
	case VM_GET_CPU_COMPAT: {
		struct vm_cpu_compat_query *query;

		query = (struct vm_cpu_compat_query *)data;
		if (query->reserved != 0) {
			error = EINVAL;
			break;
		}
		error = vm_get_cpu_compat(vcpu, &query->compat);
		break;
	}
#endif
	case VM_SET_CAPABILITY: {
		struct vm_capability *vmcap;

		vmcap = (struct vm_capability *)data;
		error = vm_set_capability(vcpu, vmcap->captype, vmcap->capval);
		break;
	}
	case VM_ACTIVATE_CPU:
		error = vm_activate_cpu(vcpu);
		break;
	case VM_GET_CPUS: {
		struct vm_cpuset *vm_cpuset;
		cpuset_t *cpuset;
		int size;

		error = 0;
		vm_cpuset = (struct vm_cpuset *)data;
		size = vm_cpuset->cpusetsize;
		if (size < 1 || size > CPU_MAXSIZE / NBBY) {
			error = ERANGE;
			break;
		}
		cpuset = malloc(max(size, sizeof(cpuset_t)), M_TEMP,
		    M_WAITOK | M_ZERO);
		if (vm_cpuset->which == VM_ACTIVE_CPUS)
			*cpuset = vm_active_cpus(sc->vm);
		else if (vm_cpuset->which == VM_SUSPENDED_CPUS)
			*cpuset = vm_suspended_cpus(sc->vm);
		else if (vm_cpuset->which == VM_DEBUG_CPUS)
			*cpuset = vm_debug_cpus(sc->vm);
		else
			error = EINVAL;
		if (error == 0 && size < howmany(CPU_FLS(cpuset), NBBY))
			error = ERANGE;
		if (error == 0)
			error = copyout(cpuset, vm_cpuset->cpus, size);
		free(cpuset, M_TEMP);
		break;
	}
	case VM_SUSPEND_CPU:
		error = vm_suspend_cpu(sc->vm, vcpu);
		break;
	case VM_RESUME_CPU:
		error = vm_resume_cpu(sc->vm, vcpu);
		break;
	case VM_SET_TOPOLOGY: {
		struct vm_cpu_topology *topology;

		topology = (struct vm_cpu_topology *)data;
		error = vm_set_topology(sc->vm, topology->sockets,
		    topology->cores, topology->threads, topology->maxcpus);
		break;
	}
	case VM_GET_TOPOLOGY: {
		struct vm_cpu_topology *topology;

		topology = (struct vm_cpu_topology *)data;
		vm_get_topology(sc->vm, &topology->sockets, &topology->cores,
		    &topology->threads, &topology->maxcpus);
		error = 0;
		break;
	}
	default:
		error = vmmdev_machdep_ioctl(sc->vm, vcpu, cmd, data, fflag,
		    td);
		break;
	}

	if ((ioctl->flags &
	    (VMMDEV_IOCTL_XLOCK_MEMSEGS | VMMDEV_IOCTL_SLOCK_MEMSEGS)) != 0)
		vm_unlock_memsegs(sc->vm);
	if ((ioctl->flags & VMMDEV_IOCTL_LOCK_ALL_VCPUS) != 0)
		vcpu_unlock_all(sc);
	else if ((ioctl->flags & VMMDEV_IOCTL_LOCK_ONE_VCPU) != 0)
		vcpu_unlock_one(vcpu);

	/*
	 * Make sure that no handler returns a kernel-internal
	 * error value to userspace.
	 */
	KASSERT(error == ERESTART || error >= 0,
	    ("vmmdev_ioctl: invalid error return %d", error));
	return (error);

lockfail:
	if ((ioctl->flags &
	    (VMMDEV_IOCTL_XLOCK_MEMSEGS | VMMDEV_IOCTL_SLOCK_MEMSEGS)) != 0)
		vm_unlock_memsegs(sc->vm);
	return (error);
}

static int
vmmdev_mmap_single(struct cdev *cdev, vm_ooffset_t *offset, vm_size_t mapsize,
    struct vm_object **objp, int nprot)
{
	struct vmmdev_softc *sc;
	vm_paddr_t gpa;
	size_t len;
	vm_ooffset_t segoff, first, last;
	int error, found, segid;
	bool sysmem;

	first = *offset;
	last = first + mapsize;
	if ((nprot & PROT_EXEC) || first < 0 || first >= last)
		return (EINVAL);

	sc = vmmdev_lookup2(cdev);
	if (sc == NULL) {
		/* virtual machine is in the process of being created */
		return (EINVAL);
	}

#ifdef MAC
	error = mac_vmm_check_mem_access(curthread->td_ucred, vm_name(sc->vm),
	    first, mapsize, vmmdev_prot_from_nprot(nprot));
	if (error != 0)
		return (error);
#endif

	/*
	 * Get a read lock on the guest memory map.
	 */
	vm_slock_memsegs(sc->vm);

	gpa = 0;
	found = 0;
	while (!found) {
		error = vm_mmap_getnext(sc->vm, &gpa, &segid, &segoff, &len,
		    NULL, NULL);
		if (error)
			break;

		if (first >= gpa && last <= gpa + len)
			found = 1;
		else
			gpa += len;
	}

	if (found) {
		error = vm_get_memseg(sc->vm, segid, &len, &sysmem, objp);
		KASSERT(error == 0 && *objp != NULL,
		    ("%s: invalid memory segment %d", __func__, segid));
		if (sysmem) {
			vm_object_reference(*objp);
			*offset = segoff + (first - gpa);
		} else {
			error = EINVAL;
		}
	}
	vm_unlock_memsegs(sc->vm);
	return (error);
}

static void
vmmdev_destroy(struct vmmdev_softc *sc)
{
	struct devmem_softc *dsc;
	int error;

	if (sc->cdev != NULL)
		panic("%s: cdev not free", __func__);
	if (sc->ucred == NULL)
		panic("%s: missing ucred", __func__);

	/*
	 * Destroy all cdevs:
	 *
	 * - any new operations on the 'cdev' will return an error (ENXIO).
	 *
	 * - the 'devmem' cdevs are destroyed before the virtual machine 'cdev'
	 */
	SLIST_FOREACH(dsc, &sc->devmem, link) {
		if (dsc->cdev == NULL)
			panic("%s: devmem cdev already destroyed", __func__);
		devmem_destroy(dsc);
	}

	vm_disable_vcpu_creation(sc->vm);
	error = vcpu_lock_all(sc);
	if (error != 0)
		panic("%s: error %d freezing vcpus", __func__, error);
	vm_unlock_vcpus(sc->vm);

	while ((dsc = SLIST_FIRST(&sc->devmem)) != NULL) {
		if (dsc->cdev != NULL)
			panic("%s: devmem not free", __func__);
		SLIST_REMOVE_HEAD(&sc->devmem, link);
		free(dsc->name, M_VMMDEV);
		free(dsc, M_VMMDEV);
	}

	vm_destroy(sc->vm);

	chgvmmcnt(sc->ucred->cr_ruidinfo, -1, 0);
	crfree(sc->ucred);

	sx_xlock(&vmmdev_mtx);
	SLIST_REMOVE(&head, sc, vmmdev_softc, link);
	if ((sc->flags & VMMCTL_CREATE_DESTROY_ON_CLOSE) != 0)
		LIST_REMOVE(sc, priv_link);
	sx_xunlock(&vmmdev_mtx);
	wakeup(sc);
	free(sc, M_VMMDEV);
}

static int
vmmdev_lookup_and_destroy(const char *name, struct ucred *cred)
{
	struct cdev *cdev;
	struct vmmdev_softc *sc;
	bool can_destroy;
	int error;

#ifdef MAC
	error = mac_vmm_check_destroy(cred, name);
	if (error != 0)
		return (error);
#endif

	sx_xlock(&vmmdev_mtx);
	sc = vmmdev_lookup(name, cred);
	if (sc == NULL || sc->cdev == NULL) {
		sx_xunlock(&vmmdev_mtx);
		return (EINVAL);
	}

	/*
	 * Only the creator of a VM or a privileged user can destroy it.
	 */
	can_destroy = (cred->cr_uid == sc->ucred->cr_uid &&
	    cred->cr_prison == sc->ucred->cr_prison);
	if (!can_destroy &&
	    (error = priv_check_cred(cred, PRIV_VMM_DESTROY)) != 0) {
		sx_xunlock(&vmmdev_mtx);
		return (error);
	}

	/*
	 * Setting 'sc->cdev' to NULL is used to indicate that the VM
	 * is scheduled for destruction.
	 */
	cdev = sc->cdev;
	sc->cdev = NULL;
	sx_xunlock(&vmmdev_mtx);

	(void)vm_suspend(sc->vm, VM_SUSPEND_DESTROY);
	destroy_dev(cdev);
	vmmdev_destroy(sc);

	return (0);
}

static int
sysctl_vmm_destroy(SYSCTL_HANDLER_ARGS)
{
	char *buf;
	int error, buflen;

	error = vmm_jail_priv_check(req->td->td_ucred);
	if (error)
		return (error);

	buflen = VM_MAX_NAMELEN + 1;
	buf = malloc(buflen, M_VMMDEV, M_WAITOK | M_ZERO);
	error = sysctl_handle_string(oidp, buf, buflen, req);
	if (error == 0 && req->newptr != NULL)
		error = vmmdev_lookup_and_destroy(buf, req->td->td_ucred);
	free(buf, M_VMMDEV);
	return (error);
}
SYSCTL_PROC(_hw_vmm, OID_AUTO, destroy,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_PRISON | CTLFLAG_MPSAFE,
    NULL, 0, sysctl_vmm_destroy, "A",
    "Destroy a vmm(4) instance (legacy interface)");

static struct cdevsw vmmdevsw = {
	.d_name		= "vmmdev",
	.d_version	= D_VERSION,
	.d_open		= vmmdev_open,
	.d_ioctl	= vmmdev_ioctl,
	.d_mmap_single	= vmmdev_mmap_single,
	.d_read		= vmmdev_rw,
	.d_write	= vmmdev_rw,
};

static struct vmmdev_softc *
vmmdev_alloc(struct vm *vm, struct ucred *cred)
{
	struct vmmdev_softc *sc;

	sc = malloc(sizeof(*sc), M_VMMDEV, M_WAITOK | M_ZERO);
	SLIST_INIT(&sc->devmem);
	sc->vm = vm;
	sc->ucred = crhold(cred);
	return (sc);
}

static int
vmmdev_create(const char *name, uint32_t flags, struct ucred *cred)
{
	struct make_dev_args mda;
	struct cdev *cdev;
	struct vmmdev_softc *sc;
	struct vmmctl_priv *priv;
	struct vm *vm;
	int error;

	if (name == NULL || strlen(name) > VM_MAX_NAMELEN)
		return (EINVAL);

	if ((flags & ~VMMCTL_FLAGS_MASK) != 0)
		return (EINVAL);
	error = devfs_get_cdevpriv((void **)&priv);
	if (error)
		return (error);

#ifdef MAC
	if ((error = mac_vmm_check_create(cred, name)) != 0)
		return (error);
	/*
	 * Auto-destroy runs from cdevpriv teardown, which cannot fail.
	 * Authorize that future destruction up front while this request can
	 * still be denied cleanly.
	 */
	if ((flags & VMMCTL_CREATE_DESTROY_ON_CLOSE) != 0 &&
	    (error = mac_vmm_check_destroy(cred, name)) != 0)
		return (error);
#endif

	sx_xlock(&vmmdev_mtx);
	sc = vmmdev_lookup(name, cred);
	if (sc != NULL) {
		sx_xunlock(&vmmdev_mtx);
		return (EEXIST);
	}

	/*
	 * Unprivileged users can only create VMs that will be automatically
	 * destroyed when the creating descriptor is closed.
	 */
	if ((flags & VMMCTL_CREATE_DESTROY_ON_CLOSE) == 0 &&
	    (error = priv_check_cred(cred, PRIV_VMM_CREATE)) != 0) {
		sx_xunlock(&vmmdev_mtx);
		return (EXTERROR(error,
		    "An unprivileged user must run VMs in monitor mode"));
	}

	if ((error = vmm_jail_priv_check(cred)) != 0) {
		sx_xunlock(&vmmdev_mtx);
		return (EXTERROR(error,
		    "VMs cannot be created in the current jail"));
	}

	if (!chgvmmcnt(cred->cr_ruidinfo, 1, vm_maxvmms)) {
		sx_xunlock(&vmmdev_mtx);
		return (ENOMEM);
	}

	error = vm_create(name, &vm);
	if (error != 0) {
		sx_xunlock(&vmmdev_mtx);
		(void)chgvmmcnt(cred->cr_ruidinfo, -1, 0);
		return (error);
	}
	sc = vmmdev_alloc(vm, cred);
	SLIST_INSERT_HEAD(&head, sc, link);
	sc->flags = flags;
	if ((flags & VMMCTL_CREATE_DESTROY_ON_CLOSE) != 0)
		LIST_INSERT_HEAD(&priv->softcs, sc, priv_link);

	make_dev_args_init(&mda);
	mda.mda_devsw = &vmmdevsw;
	mda.mda_cr = sc->ucred;
	mda.mda_uid = cred->cr_uid;
	mda.mda_gid = GID_VMM;
	mda.mda_mode = 0600;
	mda.mda_si_drv1 = sc;
	mda.mda_flags = MAKEDEV_CHECKNAME | MAKEDEV_WAITOK;
	error = make_dev_s(&mda, &cdev, "vmm/%s", name);
	if (error != 0) {
		sx_xunlock(&vmmdev_mtx);
		vmmdev_destroy(sc);
		return (error);
	}
	sc->cdev = cdev;
	sx_xunlock(&vmmdev_mtx);
	return (0);
}

static int
sysctl_vmm_create(SYSCTL_HANDLER_ARGS)
{
	char *buf;
	int error, buflen;

	if (!vmm_initialized)
		return (ENXIO);

	error = vmm_jail_priv_check(req->td->td_ucred);
	if (error != 0)
		return (error);

	buflen = VM_MAX_NAMELEN + 1;
	buf = malloc(buflen, M_VMMDEV, M_WAITOK | M_ZERO);
	error = sysctl_handle_string(oidp, buf, buflen, req);
	if (error == 0 && req->newptr != NULL)
		error = vmmdev_create(buf, 0, req->td->td_ucred);
	free(buf, M_VMMDEV);
	return (error);
}
SYSCTL_PROC(_hw_vmm, OID_AUTO, create,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_PRISON | CTLFLAG_MPSAFE,
    NULL, 0, sysctl_vmm_create, "A",
    "Create a vmm(4) instance (legacy interface)");

static void
vmmctl_dtor(void *arg)
{
	struct cdev *sc_cdev;
	struct vmmdev_softc *sc;
	struct vmmctl_priv *priv = arg;

	/*
	 * Scan the softc list for any VMs associated with
	 * the current descriptor and destroy them.
	 */
	sx_xlock(&vmmdev_mtx);
	while (!LIST_EMPTY(&priv->softcs)) {
		sc = LIST_FIRST(&priv->softcs);
		sc_cdev = sc->cdev;
		if (sc_cdev != NULL) {
			sc->cdev = NULL;
		} else {
			/*
			 * Another thread has already
			 * started the removal process.
			 * Sleep until 'vmmdev_destroy' notifies us
			 * that the removal has finished.
			 */
			sx_sleep(sc, &vmmdev_mtx, 0, "vmmctl_dtor", 0);
			continue;
		}
		/*
		 * Temporarily drop the lock to allow vmmdev_destroy to run.
		 */
		sx_xunlock(&vmmdev_mtx);
		(void)vm_suspend(sc->vm, VM_SUSPEND_DESTROY);
		destroy_dev(sc_cdev);
		/* vmmdev_destroy will unlink the 'priv_link' entry. */
		vmmdev_destroy(sc);
		sx_xlock(&vmmdev_mtx);
	}
	sx_xunlock(&vmmdev_mtx);

	free(priv, M_VMMDEV);
}

static int
vmmctl_open(struct cdev *cdev, int flags, int fmt, struct thread *td)
{
	int error;
	struct vmmctl_priv *priv;

	error = vmm_jail_priv_check(td->td_ucred);
	if (error != 0)
		return (error);

	if ((flags & FWRITE) == 0)
		return (EPERM);

	priv = malloc(sizeof(*priv), M_VMMDEV, M_WAITOK | M_ZERO);
	LIST_INIT(&priv->softcs);
	error = devfs_set_cdevpriv(priv, vmmctl_dtor);
	if (error != 0) {
		free(priv, M_VMMDEV);
		return (error);
	}

	return (0);
}

static int
vmmctl_ioctl(struct cdev *cdev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	int error;

	switch (cmd) {
	case VMMCTL_VM_CREATE: {
		struct vmmctl_vm_create *vmc;

		vmc = (struct vmmctl_vm_create *)data;
		vmc->name[VM_MAX_NAMELEN] = '\0';
		for (size_t i = 0; i < nitems(vmc->reserved); i++) {
			if (vmc->reserved[i] != 0) {
				error = EINVAL;
				return (error);
			}
		}

		error = vmmdev_create(vmc->name, vmc->flags, td->td_ucred);
		break;
	}
	case VMMCTL_VM_DESTROY: {
		struct vmmctl_vm_destroy *vmd;

		vmd = (struct vmmctl_vm_destroy *)data;
		vmd->name[VM_MAX_NAMELEN] = '\0';
		for (size_t i = 0; i < nitems(vmd->reserved); i++) {
			if (vmd->reserved[i] != 0) {
				error = EINVAL;
				return (error);
			}
		}

		error = vmmdev_lookup_and_destroy(vmd->name, td->td_ucred);
		break;
	}
	default:
		error = ENOTTY;
		break;
	}

	return (error);
}

static struct cdev *vmmctl_cdev;
static struct cdevsw vmmctlsw = {
	.d_name		= "vmmctl",
	.d_version	= D_VERSION,
	.d_open		= vmmctl_open,
	.d_ioctl	= vmmctl_ioctl,
};

static int
vmmdev_init(void)
{
	int error;

	sx_xlock(&vmmdev_mtx);
	error = make_dev_p(MAKEDEV_CHECKNAME, &vmmctl_cdev, &vmmctlsw, NULL,
	    UID_ROOT, GID_VMM, 0660, "vmmctl");
	if (error == 0) {
		pr_allow_vmm_flag = prison_add_allow(NULL, "vmm", NULL,
		    "Allow use of vmm in a jail");
		pr_allow_vmm_ppt_flag = prison_add_allow(NULL, "vmm_ppt", NULL,
		    "Allow use of vmm with ppt devices in a jail");
	}
	sx_xunlock(&vmmdev_mtx);

	return (error);
}

static int
vmmdev_cleanup(void)
{
	sx_xlock(&vmmdev_mtx);
	if (!SLIST_EMPTY(&head)) {
		sx_xunlock(&vmmdev_mtx);
		return (EBUSY);
	}
	if (vmmctl_cdev != NULL) {
		destroy_dev(vmmctl_cdev);
		vmmctl_cdev = NULL;
	}
	sx_xunlock(&vmmdev_mtx);

	return (0);
}

static int
vmm_handler(module_t mod, int what, void *arg)
{
	int error, maxcpu;

	switch (what) {
	case MOD_LOAD:
		error = vmmdev_init();
		if (error != 0)
			break;

		maxcpu = mp_ncpus;
		TUNABLE_INT_FETCH("hw.vmm.maxcpu", &maxcpu);
		if (maxcpu > VM_MAXCPU) {
			printf("vmm: vm_maxcpu clamped to %u\n", VM_MAXCPU);
			maxcpu = VM_MAXCPU;
		}
		if (maxcpu <= 0)
			maxcpu = 1;
		vm_maxcpu = (u_int)maxcpu;
		vm_maxvmms = 4 * mp_ncpus;
		error = vmm_modinit();
		if (error == 0)
			vmm_initialized = true;
		else {
			int error1 __diagused;

			error1 = vmmdev_cleanup();
			KASSERT(error1 == 0,
			    ("%s: vmmdev_cleanup failed: %d", __func__, error1));
		}
		break;
	case MOD_UNLOAD:
		error = vmmdev_cleanup();
		if (error == 0 && vmm_initialized) {
			error = vmm_modcleanup();
			if (error) {
				/*
				 * Something bad happened - prevent new
				 * VMs from being created
				 */
				vmm_initialized = false;
			}
		}
		break;
	default:
		error = 0;
		break;
	}
	return (error);
}

static moduledata_t vmm_kmod = {
	"vmm",
	vmm_handler,
	NULL
};

/*
 * vmm initialization has the following dependencies:
 *
 * - Initialization requires smp_rendezvous() and therefore must happen
 *   after SMP is fully functional (after SI_SUB_SMP).
 * - vmm device initialization requires an initialized devfs.
 */
DECLARE_MODULE(vmm, vmm_kmod, MAX(SI_SUB_SMP, SI_SUB_DEVFS) + 1, SI_ORDER_ANY);
MODULE_VERSION(vmm, 1);

static int
devmem_mmap_single(struct cdev *cdev, vm_ooffset_t *offset, vm_size_t len,
    struct vm_object **objp, int nprot)
{
	struct devmem_softc *dsc;
	vm_ooffset_t first, last;
	size_t seglen;
	int error;
	bool sysmem;

	dsc = cdev->si_drv1;
	if (dsc == NULL) {
		/* 'cdev' has been created but is not ready for use */
		return (ENXIO);
	}

	first = *offset;
	last = *offset + len;
	if ((nprot & PROT_EXEC) || first < 0 || first >= last)
		return (EINVAL);

#ifdef MAC
	error = mac_vmm_check_memseg_access(curthread->td_ucred,
	    vm_name(dsc->sc->vm), dsc->name, first,
	    vmmdev_prot_from_nprot(nprot));
	if (error != 0)
		return (error);
#endif

	vm_slock_memsegs(dsc->sc->vm);

	error = vm_get_memseg(dsc->sc->vm, dsc->segid, &seglen, &sysmem, objp);
	KASSERT(error == 0 && !sysmem && *objp != NULL,
	    ("%s: invalid devmem segment %d", __func__, dsc->segid));

	if (seglen >= last)
		vm_object_reference(*objp);
	else
		error = EINVAL;

	vm_unlock_memsegs(dsc->sc->vm);
	return (error);
}

static struct cdevsw devmemsw = {
	.d_name		= "devmem",
	.d_version	= D_VERSION,
	.d_mmap_single	= devmem_mmap_single,
};

static int
devmem_create_cdev(struct vmmdev_softc *sc, int segid, char *devname)
{
	struct make_dev_args mda;
	struct devmem_softc *dsc;
	int error;

	sx_xlock(&vmmdev_mtx);

	dsc = malloc(sizeof(struct devmem_softc), M_VMMDEV, M_WAITOK | M_ZERO);
	dsc->segid = segid;
	dsc->name = devname;
	dsc->sc = sc;
	SLIST_INSERT_HEAD(&sc->devmem, dsc, link);

	make_dev_args_init(&mda);
	mda.mda_devsw = &devmemsw;
	mda.mda_cr = sc->ucred;
	mda.mda_uid = sc->ucred->cr_uid;
	mda.mda_gid = GID_VMM;
	mda.mda_mode = 0600;
	mda.mda_si_drv1 = dsc;
	mda.mda_flags = MAKEDEV_CHECKNAME | MAKEDEV_WAITOK;
	error = make_dev_s(&mda, &dsc->cdev, "vmm.io/%s.%s", vm_name(sc->vm),
	    devname);
	if (error != 0) {
		SLIST_REMOVE(&sc->devmem, dsc, devmem_softc, link);
		free(dsc->name, M_VMMDEV);
		free(dsc, M_VMMDEV);
	}

	sx_xunlock(&vmmdev_mtx);

	return (error);
}

static void
devmem_destroy(void *arg)
{
	struct devmem_softc *dsc = arg;

	destroy_dev(dsc->cdev);
	dsc->cdev = NULL;
	dsc->sc = NULL;
}
