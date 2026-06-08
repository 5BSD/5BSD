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
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/refcount.h>
#include <sys/sbuf.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>
#include <sys/ucred.h>
#include <sys/uio.h>
#include <vm/uma.h>

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
SDT_PROBE_DEFINE3(cap_rt, , , forward,
    "const char *", "uint64_t", "size_t");
SDT_PROBE_DEFINE5(cap_rt, , , forward__done,
    "const char *", "uint64_t", "size_t", "int", "sbintime_t");
SDT_PROBE_DEFINE3(cap_rt, , , revoke,
    "const char *", "uint64_t", "int");
SDT_PROBE_DEFINE4(cap_rt, , , revoke__done,
    "const char *", "uint64_t", "int", "sbintime_t");
SDT_PROBE_DEFINE2(cap_rt, , , close,
    "const char *", "uint64_t");
SDT_PROBE_DEFINE6(cap_rt, , , fd__install,
    "const char *", "uint64_t", "int", "pid_t", "struct ucred *",
    "uint64_t");
SDT_PROBE_DEFINE6(cap_rt, , , fd__close,
    "const char *", "uint64_t", "int", "pid_t", "struct ucred *",
    "uint64_t");
SDT_PROBE_DEFINE6(cap_rt, , , control,
    "const char *", "uint64_t", "u_long", "pid_t", "struct ucred *",
    "uint64_t");
SDT_PROBE_DEFINE6(cap_rt, , , fd__receive,
    "const char *", "uint64_t", "int", "pid_t", "struct ucred *",
    "uint64_t");
SDT_PROBE_DEFINE6(cap_rt, , , ioctl__deny,
    "const char *", "uint64_t", "u_long", "pid_t", "struct ucred *",
    "uint64_t");
SDT_PROBE_DEFINE6(cap_rt, , , error,
    "const char *", "uint64_t", "u_long", "pid_t", "uint64_t", "int");
SDT_PROBE_DEFINE6(cap_rt, , , instance__create,
    "const char *", "uint64_t", "pid_t", "struct ucred *", "uint64_t",
    "uint32_t");
SDT_PROBE_DEFINE6(cap_rt, , , instance__finalize,
    "const char *", "uint64_t", "int", "pid_t", "struct ucred *",
    "uint64_t");
SDT_PROBE_DEFINE6(cap_rt, , , instance__lastclose,
    "const char *", "uint64_t", "int", "pid_t", "struct ucred *",
    "uint64_t");
SDT_PROBE_DEFINE6(cap_rt, , , rights__change,
    "const char *", "uint64_t", "u_long", "pid_t", "struct ucred *",
    "uint64_t");
SDT_PROBE_DEFINE6(cap_rt, , , state,
    "const char *", "uint64_t", "int", "int", "pid_t", "uint64_t");
SDT_PROBE_DEFINE6(cap_rt, , , fd__mint,
    "const char *", "uint64_t", "pid_t", "struct ucred *", "uint64_t",
    "uint32_t");
SDT_PROBE_DEFINE5(cap_rt, , , service__create,
    "const char *", "uint32_t", "uint32_t", "uint32_t", "uint32_t");
SDT_PROBE_DEFINE2(cap_rt, , , service__destroy,
    "const char *", "uint32_t");
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

static int
cap_rt_sysctl_service_names(SYSCTL_HANDLER_ARGS)
{
	struct cap_rt_service *svc;
	struct sbuf sb;
	int error;

	error = sysctl_wire_old_buffer(req, 0);
	if (error != 0)
		return (error);
	sbuf_new_for_sysctl(&sb, NULL, 128, req);
	sbuf_clear_flags(&sb, SBUF_INCLUDENUL);
	sx_slock(&cap_rt_registry_lock);
	LIST_FOREACH(svc, &cap_rt_services, csvc_link)
		(void)sbuf_printf(&sb, "%s\n", svc->csvc_name);
	sx_sunlock(&cap_rt_registry_lock);
	error = sbuf_finish(&sb);
	sbuf_delete(&sb);
	return (error);
}

SYSCTL_PROC(_kern_cap_rt, OID_AUTO, service_names,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    cap_rt_sysctl_service_names, "A",
    "Newline-separated list of registered cap_rt service names");

static int
cap_rt_sysctl_service_details(SYSCTL_HANDLER_ARGS)
{
	struct cap_rt_service *svc;
	struct sbuf sb;
	int error;

	error = sysctl_wire_old_buffer(req, 0);
	if (error != 0)
		return (error);
	sbuf_new_for_sysctl(&sb, NULL, 256, req);
	sbuf_clear_flags(&sb, SBUF_INCLUDENUL);
	sx_slock(&cap_rt_registry_lock);
	LIST_FOREACH(svc, &cap_rt_services, csvc_link) {
		(void)sbuf_printf(&sb,
		    "%s flags=0x%x svc_flags=0x%x queue_depth=%u "
		    "tx_limit=%u instance_limit=%d instances=%d "
		    "destroying=%d\n",
		    svc->csvc_name, svc->csvc_flags, svc->csvc_svc_flags,
		    svc->csvc_queue_depth, svc->csvc_tx_limit,
		    svc->csvc_instance_limit, svc->csvc_ninstances,
		    (svc->csvc_flags & CAP_RT_SVCF_DESTROYING) != 0);
	}
	sx_sunlock(&cap_rt_registry_lock);
	error = sbuf_finish(&sb);
	sbuf_delete(&sb);
	return (error);
}

SYSCTL_PROC(_kern_cap_rt, OID_AUTO, service_details,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    cap_rt_sysctl_service_details, "A",
    "Registered cap_rt services with flags, limits, and instance counts");

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
		SDT_PROBE5(cap_rt, , , queue__pressure,
		    svc->csvc_name, (uint64_t)0, "instance-limit",
		    svc->csvc_ninstances, svc->csvc_instance_limit);
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
		SDT_PROBE5(cap_rt, , , queue__pressure,
		    svc->csvc_name, (uint64_t)0, "instance-link-race",
		    svc->csvc_ninstances, svc->csvc_instance_limit);
		sx_xunlock(&cap_rt_registry_lock);
		return (ECONNABORTED);
	}
	LIST_INSERT_HEAD(&svc->csvc_instances, s, ci_svc_link);
	s->ci_flags |= CAP_RT_SF_LINKED;
	sx_xunlock(&cap_rt_registry_lock);
	return (0);
}

/*
 * Shared instance setup: reserve slot, allocate instance, create a
 * struct file, run co_init, and link into the service list.  On
 * success the caller owns one reference on the returned fp.
 */
static int
cap_rt_instance_setup(struct cap_rt_service *svc, struct thread *td,
    uint64_t badge, struct file **fpp)
{
	struct cap_rt_instance *s;
	struct file *fp;
	int error;

	error = cap_rt_service_reserve(svc);
	if (error != 0)
		return (error);

	s = cap_rt_instance_init(svc, badge);
	SDT_PROBE6(cap_rt, , , instance__create, svc->csvc_name, badge,
	    td->td_proc->p_pid, td->td_ucred,
	    cap_rt_proc_nonce(td->td_ucred), svc->csvc_svc_flags);

	error = falloc_noinstall(td, &fp);
	if (error != 0) {
		cap_rt_instance_free(s);
		cap_rt_service_unreserve(svc);
		return (error);
	}

	finit(fp, FREAD | FWRITE, DTYPE_CAP_RT, s, &cap_rt_instance_ops);

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
	 * Link before the fd is visible.  cap_rt_instance_link rechecks
	 * DESTROYING under xlock so a racing service_destroy cannot miss
	 * this instance.
	 */
	error = cap_rt_instance_link(svc, s);
	if (error != 0) {
		fdrop(fp, td);
		cap_rt_service_unreserve(svc);
		return (error);
	}

	*fpp = fp;
	return (0);
}

int
cap_rt_instance_create(struct cap_rt_service *svc, struct thread *td,
    uint64_t badge, int *fdp)
{
	struct file *fp;
	int error, fd;

	error = cap_rt_instance_setup(svc, td, badge, &fp);
	if (error != 0)
		return (error);

	/*
	 * Install the fd.  From this point close handles all cleanup
	 * (unlink + svc refcount release) — do NOT unreserve here.
	 */
	error = finstall(td, fp, &fd, 0, NULL);
	fdrop(fp, td);
	if (error != 0)
		return (error);

	SDT_PROBE3(cap_rt, , , connect,
	    svc->csvc_name, badge, td->td_proc->p_pid);
	SDT_PROBE6(cap_rt, , , fd__install, svc->csvc_name, badge, fd,
	    td->td_proc->p_pid, td->td_ucred,
	    cap_rt_proc_nonce(td->td_ucred));

	*fdp = fd;
	return (0);
}

/*
 * Mint an instance and return a struct file * without installing an fd.
 * Safe to call from handler (taskqueue) context.  The caller holds one
 * reference on the returned fp and must fdrop() after passing it as an
 * attached descriptor in cap_rt_reply() or cap_rt_notify().
 */
int
cap_rt_mint_fp(struct cap_rt_service *svc, uint64_t badge,
    struct file **fpp)
{
	int error;

	error = cap_rt_instance_setup(svc, curthread, badge, fpp);
	if (error == 0) {
		SDT_PROBE6(cap_rt, , , fd__mint, svc->csvc_name, badge,
		    curthread->td_proc->p_pid, curthread->td_ucred,
		    cap_rt_proc_nonce(curthread->td_ucred),
		    svc->csvc_svc_flags);
	}
	return (error);
}

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
			SDT_PROBE6(cap_rt, , , error, svc->csvc_name,
			    badge, (u_long)CAP_RT_CONNECT, td->td_proc->p_pid,
			    cap_rt_proc_nonce(td->td_ucred), error);
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
