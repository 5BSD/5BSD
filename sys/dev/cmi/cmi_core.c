/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cmi — message-passing capability framework.
 * Module lifecycle, character device, service registry, instance creation.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sdt.h>
#include <sys/capsicum.h>
#include <sys/conf.h>
#include <sys/counter.h>
#include <sys/event.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/refcount.h>
#include <sys/sx.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>
#include <sys/uio.h>
#include <vm/uma.h>

#include "cmi_internal.h"

MALLOC_DEFINE(M_CMI, "cmi", "cmi capability message interface");

/* DTrace probes. */
SDT_PROVIDER_DEFINE(cmi);
SDT_PROBE_DEFINE3(cmi, , , connect,
    "const char *", "uint64_t", "pid_t");
SDT_PROBE_DEFINE3(cmi, , , send,
    "const char *", "uint64_t", "uint32_t");
SDT_PROBE_DEFINE3(cmi, , , recv,
    "const char *", "uint64_t", "uint32_t");
SDT_PROBE_DEFINE2(cmi, , , dispatch,
    "const char *", "uint64_t");
SDT_PROBE_DEFINE3(cmi, , , reply,
    "const char *", "uint64_t", "size_t");
SDT_PROBE_DEFINE3(cmi, , , notify,
    "const char *", "uint64_t", "size_t");
SDT_PROBE_DEFINE3(cmi, , , call,
    "const char *", "uint64_t", "uint32_t");
SDT_PROBE_DEFINE3(cmi, , , revoke,
    "const char *", "uint64_t", "int");
SDT_PROBE_DEFINE2(cmi, , , close,
    "const char *", "uint64_t");

struct sx cmi_registry_lock;
struct cmi_service_list cmi_services =
    LIST_HEAD_INITIALIZER(cmi_services);
uma_zone_t cmi_instance_zone;
uma_zone_t cmi_msg_zone;


static struct cdev *cmi_cdev;

SYSCTL_NODE(_kern, OID_AUTO, cmi, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "cmi capability message interface");

counter_u64_t cmi_stat_services;
SYSCTL_COUNTER_U64(_kern_cmi, OID_AUTO, services, CTLFLAG_RD,
    &cmi_stat_services, "Number of registered services");

counter_u64_t cmi_stat_instances;
SYSCTL_COUNTER_U64(_kern_cmi, OID_AUTO, instances, CTLFLAG_RD,
    &cmi_stat_instances, "Number of active instances");

/* ----------------------------------------------------------------
 * Service registry
 * ---------------------------------------------------------------- */

struct cmi_service *
cmi_service_lookup(const char *name)
{
	struct cmi_service *svc;

	sx_assert(&cmi_registry_lock, SA_LOCKED);
	LIST_FOREACH(svc, &cmi_services, csvc_link) {
		if (strncmp(svc->csvc_name, name, CMI_MAXNAME) == 0)
			return (svc);
	}
	return (NULL);
}

/* ----------------------------------------------------------------
 * Message lifecycle
 * ---------------------------------------------------------------- */

void
cmi_msg_free(struct cmi_msg *msg)
{
	int i;

	for (i = 0; i < msg->cm_nfds; i++) {
		if (msg->cm_fds[i] != NULL)
			fdrop(msg->cm_fds[i], curthread);
		filecaps_free(&msg->cm_fcaps[i]);
	}
	if (msg->cm_cred != NULL)
		crfree(msg->cm_cred);
	uma_zfree(cmi_msg_zone, msg);
}

/* ----------------------------------------------------------------
 * Instance init / free — shared by all creation paths.
 * ---------------------------------------------------------------- */

/*
 * Allocate and initialize an instance.  Does NOT reserve a slot,
 * install an fd, or link into the service list — callers do that.
 */
struct cmi_instance *
cmi_instance_init(struct cmi_service *svc, uint64_t badge)
{
	struct cmi_instance *s;

	s = uma_zalloc(cmi_instance_zone, M_WAITOK | M_ZERO);
	mtx_init(&s->ci_mtx, "cmi instance", NULL, MTX_DEF);
	STAILQ_INIT(&s->ci_txq);
	STAILQ_INIT(&s->ci_rxq);
	knlist_init_mtx(&s->ci_rknotes, &s->ci_mtx);
	knlist_init_mtx(&s->ci_wknotes, &s->ci_mtx);
	s->ci_rxqlimit = svc->csvc_queue_depth;
	s->ci_service = svc;
	s->ci_badge = badge;
	s->ci_id = ((uint64_t)arc4random() << 32) | arc4random();
	refcount_init(&s->ci_refcnt, 1);
	TASK_INIT(&s->ci_task, 0, cmi_dispatch_task, s);
	counter_u64_add(cmi_stat_instances, 1);
	return (s);
}

/*
 * Free an instance that was never linked into the service list.
 * Used on error paths before the instance is visible.
 */
void
cmi_instance_free(struct cmi_instance *s)
{

	knlist_destroy(&s->ci_rknotes);
	knlist_destroy(&s->ci_wknotes);
	mtx_destroy(&s->ci_mtx);
	uma_zfree(cmi_instance_zone, s);
	counter_u64_add(cmi_stat_instances, -1);
}

/*
 * Reserve an instance slot (increment ninstances + refcnt under xlock).
 * Returns 0 on success, EAGAIN if the limit or destroying.
 */
int
cmi_service_reserve(struct cmi_service *svc)
{

	sx_xlock(&cmi_registry_lock);
	if (svc->csvc_ninstances >= svc->csvc_instance_limit ||
	    (svc->csvc_flags & CMI_SVCF_DESTROYING)) {
		sx_xunlock(&cmi_registry_lock);
		return (EAGAIN);
	}
	svc->csvc_ninstances++;
	refcount_acquire(&svc->csvc_refcnt);
	sx_xunlock(&cmi_registry_lock);
	return (0);
}

void
cmi_service_unreserve(struct cmi_service *svc)
{

	sx_xlock(&cmi_registry_lock);
	svc->csvc_ninstances--;
	sx_xunlock(&cmi_registry_lock);
	refcount_release(&svc->csvc_refcnt);
}

/*
 * Link an instance into the service's instance list.
 * Rechecks DESTROYING under xlock to close the race with
 * cmi_service_destroy — a destroy that started after our
 * reserve will see this instance on the list.
 * Returns ECONNABORTED if the service is being torn down.
 */
int
cmi_instance_link(struct cmi_service *svc, struct cmi_instance *s)
{

	sx_xlock(&cmi_registry_lock);
	if (svc->csvc_flags & CMI_SVCF_DESTROYING) {
		sx_xunlock(&cmi_registry_lock);
		return (ECONNABORTED);
	}
	LIST_INSERT_HEAD(&svc->csvc_instances, s, ci_svc_link);
	s->ci_flags |= CMI_SF_LINKED;
	sx_xunlock(&cmi_registry_lock);
	return (0);
}

/* ----------------------------------------------------------------
 * Instance creation — CMI_CONNECT and cmi_mint_fp
 * ---------------------------------------------------------------- */

int
cmi_instance_create(struct cmi_service *svc, struct thread *td,
    uint64_t badge, int *fdp)
{
	struct cmi_instance *s;
	struct file *fp;
	int error, fd;

	error = cmi_service_reserve(svc);
	if (error != 0)
		return (error);

	s = cmi_instance_init(svc, badge);

	error = falloc_noinstall(td, &fp);
	if (error != 0) {
		cmi_instance_free(s);
		cmi_service_unreserve(svc);
		return (error);
	}

	finit(fp, FREAD | FWRITE, DTYPE_CMI, s,
	    (svc->csvc_svc_flags & CMI_SVC_NOXFER) ?
	    &cmi_instance_noxfer_ops : &cmi_instance_ops);

	/* Run co_init before the fd is visible to userspace. */
	if (svc->csvc_ops->co_init != NULL) {
		error = svc->csvc_ops->co_init(s, svc->csvc_arg);
		if (error != 0) {
			/*
			 * co_init failed.  Mark FINALIZED so close
			 * (triggered by fdrop) does NOT fire co_revoke.
			 * co_init's error path owns cleanup.
			 */
			mtx_lock(&s->ci_mtx);
			s->ci_flags |= CMI_SF_FINALIZED;
			mtx_unlock(&s->ci_mtx);
			fdrop(fp, td);
			cmi_service_unreserve(svc);
			return (error);
		}
	}

	/*
	 * Link before finstall.  Once finstall publishes the fd,
	 * another thread can close() it immediately.  If close sees
	 * !LINKED it skips the unlink and service-ref release,
	 * leaking the reservation.  Linking first ensures close
	 * always cleans up correctly.
	 *
	 * cmi_instance_link rechecks DESTROYING under xlock so a
	 * racing service_destroy cannot miss this instance.
	 */
	error = cmi_instance_link(svc, s);
	if (error != 0) {
		/* Service tearing down — let close fire co_revoke. */
		fdrop(fp, td);
		cmi_service_unreserve(svc);
		return (error);
	}

	/*
	 * Install the fd.  From this point close handles all cleanup
	 * (unlink + svc refcount release) — do NOT unreserve here.
	 */
	error = finstall(td, fp, &fd, 0, NULL);
	fdrop(fp, td);
	if (error != 0)
		return (error);

	SDT_PROBE3(cmi, , , connect,
	    svc->csvc_name, s->ci_badge, td->td_proc->p_pid);

	*fdp = fd;
	return (0);
}

/* ----------------------------------------------------------------
 * Character device — /dev/cmi
 * ---------------------------------------------------------------- */

static d_open_t		cmi_open;
static d_ioctl_t	cmi_cdev_ioctl;

static struct cdevsw cmi_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	cmi_open,
	.d_ioctl =	cmi_cdev_ioctl,
	.d_name =	"cmi",
};

static int
cmi_open(struct cdev *dev __unused, int oflags __unused,
    int devtype __unused, struct thread *td __unused)
{

	return (0);
}

static int
cmi_ioctl_connect(struct cmi_connect_args *args, struct thread *td)
{
	struct cmi_service *svc;
	uint64_t badge;
	int error;

	if (args->flags != 0 || (args->_reserved[0] | args->_reserved[1] |
	    args->_reserved[2] | args->_reserved[3]) != 0)
		return (EINVAL);
	args->name[CMI_MAXNAME - 1] = '\0';
	if (args->name[0] == '\0')
		return (EINVAL);

	sx_slock(&cmi_registry_lock);
	svc = cmi_service_lookup(args->name);
	if (svc == NULL || (svc->csvc_flags & CMI_SVCF_DESTROYING)) {
		sx_sunlock(&cmi_registry_lock);
		return (ENOENT);
	}
	/* Hold a refcount so svc stays alive across co_connect. */
	refcount_acquire(&svc->csvc_refcnt);
	sx_sunlock(&cmi_registry_lock);

	badge = 0;
	if (svc->csvc_ops->co_connect != NULL) {
		error = svc->csvc_ops->co_connect(td->td_ucred,
		    svc->csvc_arg, &badge);
		if (error != 0) {
			refcount_release(&svc->csvc_refcnt);
			return (error);
		}
	}

	error = cmi_instance_create(svc, td, badge, &args->fd);
	/*
	 * instance_create acquires its own refcount on success.
	 * Drop the one we took for the co_connect window.
	 */
	refcount_release(&svc->csvc_refcnt);
	return (error);
}

static int
cmi_cdev_ioctl(struct cdev *dev __unused, u_long cmd, caddr_t data,
    int fflag __unused, struct thread *td)
{

	switch (cmd) {
	case CMI_CONNECT:
		return (cmi_ioctl_connect(
		    (struct cmi_connect_args *)data, td));
	default:
		return (ENOTTY);
	}
}

/* ----------------------------------------------------------------
 * Module lifecycle
 * ---------------------------------------------------------------- */

int
cmi_init(void)
{

	sx_init(&cmi_registry_lock, "cmi registry");
	cmi_instance_zone = uma_zcreate("cmi_instance",
	    sizeof(struct cmi_instance), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);
	cmi_msg_zone = uma_zcreate("cmi_msg",
	    sizeof(struct cmi_msg) + CMI_MSG_PAYLOAD_SIZE,
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, 0);
	cmi_stat_services = counter_u64_alloc(M_WAITOK);
	cmi_stat_instances = counter_u64_alloc(M_WAITOK);
	return (0);
}

void
cmi_uninit(void)
{

	counter_u64_free(cmi_stat_instances);
	counter_u64_free(cmi_stat_services);
	uma_zdestroy(cmi_msg_zone);
	uma_zdestroy(cmi_instance_zone);
	sx_destroy(&cmi_registry_lock);
}

static int
cmi_modevent(module_t mod __unused, int type, void *unused __unused)
{
	struct make_dev_args mda;
	int error;

	switch (type) {
	case MOD_LOAD:
		cmi_init();
		make_dev_args_init(&mda);
		mda.mda_flags = MAKEDEV_WAITOK | MAKEDEV_CHECKNAME;
		mda.mda_devsw = &cmi_cdevsw;
		mda.mda_uid = UID_ROOT;
		mda.mda_gid = GID_WHEEL;
		mda.mda_mode = 0600;
		error = make_dev_s(&mda, &cmi_cdev, "cmi");
		if (error != 0) {
			printf("cmi: failed to create /dev/cmi: %d\n",
			    error);
			cmi_uninit();
			return (error);
		}
		if (bootverbose)
			printf("cmi: loaded\n");
		return (0);

	case MOD_UNLOAD:
		sx_slock(&cmi_registry_lock);
		if (!LIST_EMPTY(&cmi_services)) {
			sx_sunlock(&cmi_registry_lock);
			return (EBUSY);
		}
		sx_sunlock(&cmi_registry_lock);
		destroy_dev(cmi_cdev);
		cmi_uninit();
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t cmi_mod = {
	"cmi",
	cmi_modevent,
	NULL,
};

DECLARE_MODULE(cmi, cmi_mod, SI_SUB_PSEUDO, SI_ORDER_FIRST);
MODULE_VERSION(cmi, 1);
