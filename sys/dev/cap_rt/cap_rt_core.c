/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cap_rt — message-passing capability framework.
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
#include <sys/imgact.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
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
#include <sys/ucred.h>
#include <sys/uio.h>
#include <sys/vnode.h>
#include <vm/uma.h>

#include <security/mac/mac_policy.h>

#include "cap_rt_internal.h"
#include "cap_rt_label.h"

MALLOC_DEFINE(M_CAP_RT, "cap_rt", "cap_rt capability message interface");

/* DTrace probes. */
SDT_PROVIDER_DEFINE(cap_rt);
SDT_PROBE_DEFINE3(cap_rt, , , connect,
    "const char *", "uint64_t", "pid_t");
SDT_PROBE_DEFINE5(cap_rt, , , connect__done,
    "const char *", "uint64_t", "pid_t", "int", "sbintime_t");
SDT_PROBE_DEFINE3(cap_rt, , , send,
    "const char *", "uint64_t", "uint32_t");
SDT_PROBE_DEFINE6(cap_rt, , , send__done,
    "const char *", "uint64_t", "uint32_t", "uint32_t", "int",
    "sbintime_t");
SDT_PROBE_DEFINE3(cap_rt, , , recv,
    "const char *", "uint64_t", "uint32_t");
SDT_PROBE_DEFINE6(cap_rt, , , recv__done,
    "const char *", "uint64_t", "uint32_t", "uint32_t", "int",
    "sbintime_t");
SDT_PROBE_DEFINE2(cap_rt, , , dispatch,
    "const char *", "uint64_t");
SDT_PROBE_DEFINE4(cap_rt, , , dispatch__done,
    "const char *", "uint64_t", "int", "sbintime_t");
SDT_PROBE_DEFINE3(cap_rt, , , reply,
    "const char *", "uint64_t", "size_t");
SDT_PROBE_DEFINE5(cap_rt, , , reply__done,
    "const char *", "uint64_t", "size_t", "int", "sbintime_t");
SDT_PROBE_DEFINE3(cap_rt, , , notify,
    "const char *", "uint64_t", "size_t");
SDT_PROBE_DEFINE5(cap_rt, , , notify__done,
    "const char *", "uint64_t", "size_t", "int", "sbintime_t");
SDT_PROBE_DEFINE3(cap_rt, , , call,
    "const char *", "uint64_t", "uint32_t");
SDT_PROBE_DEFINE6(cap_rt, , , call__done,
    "const char *", "uint64_t", "uint32_t", "uint32_t", "int",
    "sbintime_t");
SDT_PROBE_DEFINE3(cap_rt, , , revoke,
    "const char *", "uint64_t", "int");
SDT_PROBE_DEFINE4(cap_rt, , , revoke__done,
    "const char *", "uint64_t", "int", "sbintime_t");
SDT_PROBE_DEFINE2(cap_rt, , , close,
    "const char *", "uint64_t");
SDT_PROBE_DEFINE5(cap_rt, , , queue__pressure,
    "const char *", "uint64_t", "const char *", "int", "int");

struct sx cap_rt_registry_lock;
struct cap_rt_service_list cap_rt_services =
    LIST_HEAD_INITIALIZER(cap_rt_services);
uma_zone_t cap_rt_instance_zone;
uma_zone_t cap_rt_msg_zone;


static struct cdev *cap_rt_cdev;

SYSCTL_NODE(_kern, OID_AUTO, cap_rt, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "cap_rt capability message interface");

counter_u64_t cap_rt_stat_services;
SYSCTL_COUNTER_U64(_kern_cap_rt, OID_AUTO, services, CTLFLAG_RD,
    &cap_rt_stat_services, "Number of registered services");

counter_u64_t cap_rt_stat_instances;
SYSCTL_COUNTER_U64(_kern_cap_rt, OID_AUTO, instances, CTLFLAG_RD,
    &cap_rt_stat_instances, "Number of active instances");

/* ----------------------------------------------------------------
 * Process nonce — MACF credential label
 *
 * Attaches a cryptographic nonce to every credential.  The nonce
 * identifies the program image: inherited across fork, rotated on
 * exec.  Services read it via cap_rt_proc_nonce().
 *
 * The exec transition hook runs with the process lock held.  To avoid
 * taking the MAC framework's sleepable dynamic-policy lock on that path,
 * this policy must be registered as a static boot-time policy rather than
 * a late-loadable/unloadable one.
 * ---------------------------------------------------------------- */

struct cap_rt_label {
	uint64_t	cl_nonce;
};

static int cap_rt_label_slot;

#define	SLOT(l)		((struct cap_rt_label *)mac_label_get((l), cap_rt_label_slot))
#define	SLOT_SET(l, v)	mac_label_set((l), cap_rt_label_slot, (uintptr_t)(v))

static void
cap_rt_label_gen_nonce(struct cap_rt_label *cl)
{

	do {
		arc4random_buf(&cl->cl_nonce, sizeof(cl->cl_nonce));
	} while (cl->cl_nonce == 0);
}

static void
cap_rt_cred_init_label(struct label *label)
{
	struct cap_rt_label *cl;

	cl = malloc(sizeof(*cl), M_CAP_RT, M_WAITOK | M_ZERO);
	SLOT_SET(label, cl);
}

static void
cap_rt_cred_create_init(struct ucred *cred)
{
	struct cap_rt_label *cl;

	cl = SLOT(cred->cr_label);
	if (cl != NULL)
		cap_rt_label_gen_nonce(cl);
}

static void
cap_rt_cred_copy_label(struct label *src, struct label *dest)
{
	struct cap_rt_label *scl, *dcl;

	scl = SLOT(src);
	dcl = SLOT(dest);
	if (scl != NULL && dcl != NULL)
		*dcl = *scl;
}

static void
cap_rt_cred_destroy_label(struct label *label)
{
	struct cap_rt_label *cl;

	cl = SLOT(label);
	if (cl != NULL) {
		free(cl, M_CAP_RT);
		SLOT_SET(label, NULL);
	}
}

static int
cap_rt_execve_will_transition(struct ucred *old, struct vnode *vp,
    struct label *vplabel, struct label *interpvplabel,
    struct image_params *imgp, struct label *execlabel)
{

	return (1);
}

static void
cap_rt_execve_transition(struct ucred *old, struct ucred *new,
    struct vnode *vp, struct label *vplabel,
    struct label *interpvplabel, struct image_params *imgp,
    struct label *execlabel)
{
	struct cap_rt_label *cl;

	cl = SLOT(new->cr_label);
	if (cl != NULL)
		cap_rt_label_gen_nonce(cl);
}

uint64_t
cap_rt_proc_nonce(struct ucred *cred)
{
	struct cap_rt_label *cl, *newcl;

	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	cl = SLOT(cred->cr_label);
	if (cl == NULL) {
		/*
		 * Backfill missing labels for credentials that predate
		 * policy registration.  Use M_NOWAIT because this accessor
		 * is used from no-sleep contexts such as MAC hooks.
		 */
		newcl = malloc(sizeof(*newcl), M_CAP_RT, M_NOWAIT | M_ZERO);
		if (newcl == NULL)
			return (0);
		cap_rt_label_gen_nonce(newcl);

		mtx_lock(&cred->cr_mtx);
		cl = SLOT(cred->cr_label);
		if (cl == NULL) {
			SLOT_SET(cred->cr_label, newcl);
			cl = newcl;
			newcl = NULL;
		}
		mtx_unlock(&cred->cr_mtx);

		if (newcl != NULL)
			free(newcl, M_CAP_RT);
	}
	return (cl->cl_nonce);
}

static struct mac_policy_ops cap_rt_label_mac_ops = {
	.mpo_cred_init_label = cap_rt_cred_init_label,
	.mpo_cred_create_init = cap_rt_cred_create_init,
	.mpo_cred_copy_label = cap_rt_cred_copy_label,
	.mpo_cred_destroy_label = cap_rt_cred_destroy_label,
	.mpo_vnode_execve_will_transition = cap_rt_execve_will_transition,
	.mpo_vnode_execve_transition = cap_rt_execve_transition,
};

MAC_POLICY_SET(&cap_rt_label_mac_ops, mac_cap_rt, "CAP_RT credential nonce",
    MPC_LOADTIME_FLAG_NOTLATE, &cap_rt_label_slot);

/* ----------------------------------------------------------------
 * Service registry
 * ---------------------------------------------------------------- */

struct cap_rt_service *
cap_rt_service_lookup(const char *name)
{
	struct cap_rt_service *svc;

	sx_assert(&cap_rt_registry_lock, SA_LOCKED);
	LIST_FOREACH(svc, &cap_rt_services, csvc_link) {
		if (strncmp(svc->csvc_name, name, CAP_RT_MAXNAME) == 0)
			return (svc);
	}
	return (NULL);
}

/* ----------------------------------------------------------------
 * Message lifecycle
 * ---------------------------------------------------------------- */

void
cap_rt_msg_free(struct cap_rt_msg *msg)
{
	int i;

	for (i = 0; i < msg->cm_nfds; i++) {
		if (msg->cm_fds[i] != NULL)
			fdrop(msg->cm_fds[i], curthread);
		filecaps_free(&msg->cm_fcaps[i]);
	}
	if (msg->cm_cred != NULL)
		crfree(msg->cm_cred);
	uma_zfree(cap_rt_msg_zone, msg);
}

/* ----------------------------------------------------------------
 * Instance init / free — shared by all creation paths.
 * ---------------------------------------------------------------- */

/*
 * Allocate and initialize an instance.  Does NOT reserve a slot,
 * install an fd, or link into the service list — callers do that.
 */
struct cap_rt_instance *
cap_rt_instance_init(struct cap_rt_service *svc, uint64_t badge)
{
	struct cap_rt_instance *s;

	s = uma_zalloc(cap_rt_instance_zone, M_WAITOK | M_ZERO);
	mtx_init(&s->ci_mtx, "cap_rt instance", NULL, MTX_DEF);
	STAILQ_INIT(&s->ci_txq);
	STAILQ_INIT(&s->ci_rxq);
	knlist_init_mtx(&s->ci_rknotes, &s->ci_mtx);
	knlist_init_mtx(&s->ci_wknotes, &s->ci_mtx);
	s->ci_rxqlimit = svc->csvc_queue_depth;
	s->ci_service = svc;
	s->ci_badge = badge;
	refcount_init(&s->ci_refcnt, 1);
	TASK_INIT(&s->ci_task, 0, cap_rt_dispatch_task, s);
	counter_u64_add(cap_rt_stat_instances, 1);
	return (s);
}

/*
 * Free an instance that was never linked into the service list.
 * Used on error paths before the instance is visible.
 */
void
cap_rt_instance_free(struct cap_rt_instance *s)
{

	knlist_destroy(&s->ci_rknotes);
	knlist_destroy(&s->ci_wknotes);
	mtx_destroy(&s->ci_mtx);
	uma_zfree(cap_rt_instance_zone, s);
	counter_u64_add(cap_rt_stat_instances, -1);
}

/*
 * Reserve an instance slot (increment ninstances + refcnt under xlock).
 * Returns 0 on success, EAGAIN if the limit or destroying.
 */
int
cap_rt_service_reserve(struct cap_rt_service *svc)
{

	sx_xlock(&cap_rt_registry_lock);
	if (svc->csvc_ninstances >= svc->csvc_instance_limit ||
	    (svc->csvc_flags & CAP_RT_SVCF_DESTROYING)) {
		sx_xunlock(&cap_rt_registry_lock);
		return (EAGAIN);
	}
	svc->csvc_ninstances++;
	refcount_acquire(&svc->csvc_refcnt);
	sx_xunlock(&cap_rt_registry_lock);
	return (0);
}

void
cap_rt_service_unreserve(struct cap_rt_service *svc)
{

	sx_xlock(&cap_rt_registry_lock);
	svc->csvc_ninstances--;
	sx_xunlock(&cap_rt_registry_lock);
	refcount_release(&svc->csvc_refcnt);
}

/*
 * Link an instance into the service's instance list.
 * Rechecks DESTROYING under xlock to close the race with
 * cap_rt_service_destroy — a destroy that started after our
 * reserve will see this instance on the list.
 * Returns ECONNABORTED if the service is being torn down.
 */
int
cap_rt_instance_link(struct cap_rt_service *svc, struct cap_rt_instance *s)
{

	sx_xlock(&cap_rt_registry_lock);
	if (svc->csvc_flags & CAP_RT_SVCF_DESTROYING) {
		sx_xunlock(&cap_rt_registry_lock);
		return (ECONNABORTED);
	}
	LIST_INSERT_HEAD(&svc->csvc_instances, s, ci_svc_link);
	s->ci_flags |= CAP_RT_SF_LINKED;
	sx_xunlock(&cap_rt_registry_lock);
	return (0);
}

/* ----------------------------------------------------------------
 * Instance creation — CAP_RT_CONNECT and cap_rt_mint_fp
 * ---------------------------------------------------------------- */

int
cap_rt_instance_create(struct cap_rt_service *svc, struct thread *td,
    uint64_t badge, int *fdp)
{
	struct cap_rt_instance *s;
	struct file *fp;
	int error, fd;

	error = cap_rt_service_reserve(svc);
	if (error != 0)
		return (error);

	s = cap_rt_instance_init(svc, badge);

	error = falloc_noinstall(td, &fp);
	if (error != 0) {
		cap_rt_instance_free(s);
		cap_rt_service_unreserve(svc);
		return (error);
	}

	finit(fp, FREAD | FWRITE, DTYPE_CAP_RT, s,
	    (svc->csvc_svc_flags & CAP_RT_SVC_NOXFER) ?
	    &cap_rt_instance_noxfer_ops : &cap_rt_instance_ops);

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
			s->ci_flags |= CAP_RT_SF_FINALIZED;
			mtx_unlock(&s->ci_mtx);
			fdrop(fp, td);
			cap_rt_service_unreserve(svc);
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
	 * cap_rt_instance_link rechecks DESTROYING under xlock so a
	 * racing service_destroy cannot miss this instance.
	 */
	error = cap_rt_instance_link(svc, s);
	if (error != 0) {
		/* Service tearing down — let close fire co_revoke. */
		fdrop(fp, td);
		cap_rt_service_unreserve(svc);
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

	SDT_PROBE3(cap_rt, , , connect,
	    svc->csvc_name, s->ci_badge, td->td_proc->p_pid);

	*fdp = fd;
	return (0);
}

/* ----------------------------------------------------------------
 * Character device — /dev/cap_rt
 * ---------------------------------------------------------------- */

static d_ioctl_t	cap_rt_cdev_ioctl;

static struct cdevsw cap_rt_cdevsw = {
	.d_version =	D_VERSION,
	.d_ioctl =	cap_rt_cdev_ioctl,
	.d_name =	"cap_rt",
};

static int
cap_rt_ioctl_connect(struct cap_rt_connect_args *args, struct thread *td)
{
	const char *svc_name __unused;
	struct cap_rt_service *svc;
	sbintime_t start __unused;
	uint64_t badge = 0;
	int error;

	start = getsbinuptime();
	svc_name = "<invalid>";
	if (args->flags != 0 || (args->_reserved[0] | args->_reserved[1] |
	    args->_reserved[2] | args->_reserved[3]) != 0) {
		error = EINVAL;
		goto out;
	}
	args->name[CAP_RT_MAXNAME - 1] = '\0';
	svc_name = args->name;
	if (args->name[0] == '\0') {
		error = EINVAL;
		goto out;
	}

	sx_slock(&cap_rt_registry_lock);
	svc = cap_rt_service_lookup(args->name);
	if (svc == NULL || (svc->csvc_flags & CAP_RT_SVCF_DESTROYING)) {
		sx_sunlock(&cap_rt_registry_lock);
		error = ENOENT;
		goto out;
	}
	/* Hold a refcount so svc stays alive across co_connect. */
	refcount_acquire(&svc->csvc_refcnt);
	sx_sunlock(&cap_rt_registry_lock);

	if (svc->csvc_ops->co_connect != NULL) {
		error = svc->csvc_ops->co_connect(td->td_ucred,
		    svc->csvc_arg, &badge);
		if (error != 0) {
			refcount_release(&svc->csvc_refcnt);
			goto out;
		}
	}

	error = cap_rt_instance_create(svc, td, badge, &args->fd);
	/*
	 * instance_create acquires its own refcount on success.
	 * Drop the one we took for the co_connect window.
	 */
	refcount_release(&svc->csvc_refcnt);
out:
	SDT_PROBE5(cap_rt, , , connect__done, svc_name, badge,
	    td->td_proc->p_pid, error, getsbinuptime() - start);
	return (error);
}

static int
cap_rt_cdev_ioctl(struct cdev *dev __unused, u_long cmd, caddr_t data,
    int fflag __unused, struct thread *td)
{

	switch (cmd) {
	case CAP_RT_CONNECT:
		return (cap_rt_ioctl_connect(
		    (struct cap_rt_connect_args *)data, td));
	default:
		return (ENOTTY);
	}
}

/* ----------------------------------------------------------------
 * Module lifecycle
 * ---------------------------------------------------------------- */

int
cap_rt_init(void)
{

	sx_init(&cap_rt_registry_lock, "cap_rt registry");
	cap_rt_instance_zone = uma_zcreate("cap_rt_instance",
	    sizeof(struct cap_rt_instance), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);
	cap_rt_msg_zone = uma_zcreate("cap_rt_msg",
	    sizeof(struct cap_rt_msg) + CAP_RT_MSG_PAYLOAD_SIZE,
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, 0);
	cap_rt_stat_services = counter_u64_alloc(M_WAITOK);
	cap_rt_stat_instances = counter_u64_alloc(M_WAITOK);
	return (0);
}

void
cap_rt_uninit(void)
{

	counter_u64_free(cap_rt_stat_instances);
	counter_u64_free(cap_rt_stat_services);
	uma_zdestroy(cap_rt_msg_zone);
	uma_zdestroy(cap_rt_instance_zone);
	sx_destroy(&cap_rt_registry_lock);
}

static int
cap_rt_modevent(module_t mod __unused, int type, void *unused __unused)
{
	struct make_dev_args mda;
	int error;

	switch (type) {
	case MOD_LOAD:
		cap_rt_init();
		make_dev_args_init(&mda);
		mda.mda_flags = MAKEDEV_WAITOK | MAKEDEV_CHECKNAME;
		mda.mda_devsw = &cap_rt_cdevsw;
		mda.mda_uid = UID_ROOT;
		mda.mda_gid = GID_WHEEL;
		mda.mda_mode = 0666;
		error = make_dev_s(&mda, &cap_rt_cdev, "cap_rt");
		if (error != 0) {
			printf("cap_rt: failed to create /dev/cap_rt: %d\n",
			    error);
			cap_rt_uninit();
			return (error);
		}
		if (bootverbose)
			printf("cap_rt: loaded\n");
		return (0);

	case MOD_UNLOAD:
		sx_slock(&cap_rt_registry_lock);
		if (!LIST_EMPTY(&cap_rt_services)) {
			sx_sunlock(&cap_rt_registry_lock);
			return (EBUSY);
		}
		sx_sunlock(&cap_rt_registry_lock);
		destroy_dev(cap_rt_cdev);
		cap_rt_uninit();
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t cap_rt_mod = {
	"cap_rt",
	cap_rt_modevent,
	NULL,
};

DECLARE_MODULE(cap_rt, cap_rt_mod, SI_SUB_PSEUDO, SI_ORDER_FIRST);
MODULE_VERSION(cap_rt, 1);
