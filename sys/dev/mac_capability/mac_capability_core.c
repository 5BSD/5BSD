/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * mac_capability — message-passing capability framework.
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

#include "mac_capability_internal.h"
#include "mac_capability_label.h"

MALLOC_DEFINE(M_MAC_CAPABILITY, "mac_capability", "mac_capability capability message interface");

/* DTrace probes. */
SDT_PROVIDER_DEFINE(mac_capability);
SDT_PROBE_DEFINE3(mac_capability, , , connect,
    "const char *", "uint64_t", "pid_t");
SDT_PROBE_DEFINE5(mac_capability, , , connect__done,
    "const char *", "uint64_t", "pid_t", "int", "sbintime_t");
SDT_PROBE_DEFINE3(mac_capability, , , send,
    "const char *", "uint64_t", "uint32_t");
SDT_PROBE_DEFINE6(mac_capability, , , send__done,
    "const char *", "uint64_t", "uint32_t", "uint32_t", "int",
    "sbintime_t");
SDT_PROBE_DEFINE3(mac_capability, , , recv,
    "const char *", "uint64_t", "uint32_t");
SDT_PROBE_DEFINE6(mac_capability, , , recv__done,
    "const char *", "uint64_t", "uint32_t", "uint32_t", "int",
    "sbintime_t");
SDT_PROBE_DEFINE2(mac_capability, , , dispatch,
    "const char *", "uint64_t");
SDT_PROBE_DEFINE4(mac_capability, , , dispatch__done,
    "const char *", "uint64_t", "int", "sbintime_t");
SDT_PROBE_DEFINE3(mac_capability, , , reply,
    "const char *", "uint64_t", "size_t");
SDT_PROBE_DEFINE5(mac_capability, , , reply__done,
    "const char *", "uint64_t", "size_t", "int", "sbintime_t");
SDT_PROBE_DEFINE3(mac_capability, , , notify,
    "const char *", "uint64_t", "size_t");
SDT_PROBE_DEFINE5(mac_capability, , , notify__done,
    "const char *", "uint64_t", "size_t", "int", "sbintime_t");
SDT_PROBE_DEFINE3(mac_capability, , , call,
    "const char *", "uint64_t", "uint32_t");
SDT_PROBE_DEFINE6(mac_capability, , , call__done,
    "const char *", "uint64_t", "uint32_t", "uint32_t", "int",
    "sbintime_t");
SDT_PROBE_DEFINE3(mac_capability, , , forward,
    "const char *", "uint64_t", "size_t");
SDT_PROBE_DEFINE5(mac_capability, , , forward__done,
    "const char *", "uint64_t", "size_t", "int", "sbintime_t");
SDT_PROBE_DEFINE3(mac_capability, , , revoke,
    "const char *", "uint64_t", "int");
SDT_PROBE_DEFINE4(mac_capability, , , revoke__done,
    "const char *", "uint64_t", "int", "sbintime_t");
SDT_PROBE_DEFINE2(mac_capability, , , close,
    "const char *", "uint64_t");
SDT_PROBE_DEFINE6(mac_capability, , , fd__install,
    "const char *", "uint64_t", "int", "pid_t", "struct ucred *",
    "uint64_t");
SDT_PROBE_DEFINE6(mac_capability, , , fd__close,
    "const char *", "uint64_t", "int", "pid_t", "struct ucred *",
    "uint64_t");
SDT_PROBE_DEFINE6(mac_capability, , , control,
    "const char *", "uint64_t", "u_long", "pid_t", "struct ucred *",
    "uint64_t");
SDT_PROBE_DEFINE6(mac_capability, , , fd__receive,
    "const char *", "uint64_t", "int", "pid_t", "struct ucred *",
    "uint64_t");
SDT_PROBE_DEFINE6(mac_capability, , , ioctl__deny,
    "const char *", "uint64_t", "u_long", "pid_t", "struct ucred *",
    "uint64_t");
SDT_PROBE_DEFINE6(mac_capability, , , error,
    "const char *", "uint64_t", "u_long", "pid_t", "uint64_t", "int");
SDT_PROBE_DEFINE6(mac_capability, , , instance__create,
    "const char *", "uint64_t", "pid_t", "struct ucred *", "uint64_t",
    "uint32_t");
SDT_PROBE_DEFINE6(mac_capability, , , instance__finalize,
    "const char *", "uint64_t", "int", "pid_t", "struct ucred *",
    "uint64_t");
SDT_PROBE_DEFINE6(mac_capability, , , instance__lastclose,
    "const char *", "uint64_t", "int", "pid_t", "struct ucred *",
    "uint64_t");
SDT_PROBE_DEFINE6(mac_capability, , , rights__change,
    "const char *", "uint64_t", "u_long", "pid_t", "struct ucred *",
    "uint64_t");
SDT_PROBE_DEFINE6(mac_capability, , , state,
    "const char *", "uint64_t", "int", "int", "pid_t", "uint64_t");
SDT_PROBE_DEFINE6(mac_capability, , , fd__mint,
    "const char *", "uint64_t", "pid_t", "struct ucred *", "uint64_t",
    "uint32_t");
SDT_PROBE_DEFINE5(mac_capability, , , service__create,
    "const char *", "uint32_t", "uint32_t", "uint32_t", "uint32_t");
SDT_PROBE_DEFINE2(mac_capability, , , service__destroy,
    "const char *", "uint32_t");
SDT_PROBE_DEFINE5(mac_capability, , , queue__pressure,
    "const char *", "uint64_t", "const char *", "int", "int");

struct sx mac_capability_registry_lock;
struct mac_capability_service_list mac_capability_services =
    LIST_HEAD_INITIALIZER(mac_capability_services);
uma_zone_t mac_capability_instance_zone;
uma_zone_t mac_capability_msg_zone;


static struct cdev *mac_capability_cdev;

SYSCTL_NODE(_kern, OID_AUTO, mac_capability, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "mac_capability capability message interface");

counter_u64_t mac_capability_stat_services;
SYSCTL_COUNTER_U64(_kern_mac_capability, OID_AUTO, services, CTLFLAG_RD,
    &mac_capability_stat_services, "Number of registered services");

counter_u64_t mac_capability_stat_instances;
SYSCTL_COUNTER_U64(_kern_mac_capability, OID_AUTO, instances, CTLFLAG_RD,
    &mac_capability_stat_instances, "Number of active instances");

static int
mac_capability_sysctl_service_names(SYSCTL_HANDLER_ARGS)
{
	struct mac_capability_service *svc;
	struct sbuf sb;
	int error;

	error = sysctl_wire_old_buffer(req, 0);
	if (error != 0)
		return (error);
	sbuf_new_for_sysctl(&sb, NULL, 128, req);
	sbuf_clear_flags(&sb, SBUF_INCLUDENUL);
	sx_slock(&mac_capability_registry_lock);
	LIST_FOREACH(svc, &mac_capability_services, csvc_link)
		(void)sbuf_printf(&sb, "%s\n", svc->csvc_name);
	sx_sunlock(&mac_capability_registry_lock);
	error = sbuf_finish(&sb);
	sbuf_delete(&sb);
	return (error);
}

SYSCTL_PROC(_kern_mac_capability, OID_AUTO, service_names,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    mac_capability_sysctl_service_names, "A",
    "Newline-separated list of registered mac_capability service names");

static int
mac_capability_sysctl_service_details(SYSCTL_HANDLER_ARGS)
{
	struct mac_capability_service *svc;
	struct sbuf sb;
	int error;

	error = sysctl_wire_old_buffer(req, 0);
	if (error != 0)
		return (error);
	sbuf_new_for_sysctl(&sb, NULL, 256, req);
	sbuf_clear_flags(&sb, SBUF_INCLUDENUL);
	sx_slock(&mac_capability_registry_lock);
	LIST_FOREACH(svc, &mac_capability_services, csvc_link) {
		(void)sbuf_printf(&sb,
		    "%s flags=0x%x svc_flags=0x%x queue_depth=%u "
		    "tx_limit=%u instance_limit=%d instances=%d "
		    "destroying=%d\n",
		    svc->csvc_name, svc->csvc_flags, svc->csvc_svc_flags,
		    svc->csvc_queue_depth, svc->csvc_tx_limit,
		    svc->csvc_instance_limit, svc->csvc_ninstances,
		    (svc->csvc_flags & MAC_CAPABILITY_SVCF_DESTROYING) != 0);
	}
	sx_sunlock(&mac_capability_registry_lock);
	error = sbuf_finish(&sb);
	sbuf_delete(&sb);
	return (error);
}

SYSCTL_PROC(_kern_mac_capability, OID_AUTO, service_details,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    mac_capability_sysctl_service_details, "A",
    "Registered mac_capability services with flags, limits, and instance counts");

struct mac_capability_service *
mac_capability_service_lookup(const char *name)
{
	struct mac_capability_service *svc;

	sx_assert(&mac_capability_registry_lock, SA_LOCKED);
	LIST_FOREACH(svc, &mac_capability_services, csvc_link) {
		if (strncmp(svc->csvc_name, name, MAC_CAPABILITY_MAXNAME) == 0)
			return (svc);
	}
	return (NULL);
}

void
mac_capability_msg_free(struct mac_capability_msg *msg)
{
	int i;

	for (i = 0; i < msg->cm_nfds; i++) {
		if (msg->cm_fds[i] != NULL)
			fdrop(msg->cm_fds[i], curthread);
		filecaps_free(&msg->cm_fcaps[i]);
	}
	if (msg->cm_cred != NULL)
		crfree(msg->cm_cred);
	uma_zfree(mac_capability_msg_zone, msg);
}

/*
 * Allocate and initialize an instance.  Does NOT reserve a slot,
 * install an fd, or link into the service list — callers do that.
 */
struct mac_capability_instance *
mac_capability_instance_init(struct mac_capability_service *svc, uint64_t badge)
{
	struct mac_capability_instance *s;

	s = uma_zalloc(mac_capability_instance_zone, M_WAITOK | M_ZERO);
	mtx_init(&s->ci_mtx, "mac_capability instance", NULL, MTX_DEF);
	STAILQ_INIT(&s->ci_txq);
	STAILQ_INIT(&s->ci_rxq);
	knlist_init_mtx(&s->ci_rknotes, &s->ci_mtx);
	knlist_init_mtx(&s->ci_wknotes, &s->ci_mtx);
	s->ci_rxqlimit = svc->csvc_queue_depth;
	s->ci_service = svc;
	s->ci_badge = badge;
	refcount_init(&s->ci_refcnt, 1);
	TASK_INIT(&s->ci_task, 0, mac_capability_dispatch_task, s);
	counter_u64_add(mac_capability_stat_instances, 1);
	return (s);
}

/*
 * Free an instance that was never linked into the service list.
 * Used on error paths before the instance is visible.
 */
void
mac_capability_instance_free(struct mac_capability_instance *s)
{

	knlist_destroy(&s->ci_rknotes);
	knlist_destroy(&s->ci_wknotes);
	mtx_destroy(&s->ci_mtx);
	uma_zfree(mac_capability_instance_zone, s);
	counter_u64_add(mac_capability_stat_instances, -1);
}

/*
 * Reserve an instance slot (increment ninstances + refcnt under xlock).
 * Returns 0 on success, EAGAIN if the limit or destroying.
 */
int
mac_capability_service_reserve(struct mac_capability_service *svc)
{

	sx_xlock(&mac_capability_registry_lock);
	if (svc->csvc_ninstances >= svc->csvc_instance_limit ||
	    (svc->csvc_flags & MAC_CAPABILITY_SVCF_DESTROYING)) {
		SDT_PROBE5(mac_capability, , , queue__pressure,
		    svc->csvc_name, (uint64_t)0, "instance-limit",
		    svc->csvc_ninstances, svc->csvc_instance_limit);
		sx_xunlock(&mac_capability_registry_lock);
		return (EAGAIN);
	}
	svc->csvc_ninstances++;
	refcount_acquire(&svc->csvc_refcnt);
	sx_xunlock(&mac_capability_registry_lock);
	return (0);
}

void
mac_capability_service_unreserve(struct mac_capability_service *svc)
{

	sx_xlock(&mac_capability_registry_lock);
	svc->csvc_ninstances--;
	sx_xunlock(&mac_capability_registry_lock);
	refcount_release(&svc->csvc_refcnt);
}

/*
 * Link an instance into the service's instance list.
 * Rechecks DESTROYING under xlock to close the race with
 * mac_capability_service_destroy — a destroy that started after our
 * reserve will see this instance on the list.
 * Returns ECONNABORTED if the service is being torn down.
 */
int
mac_capability_instance_link(struct mac_capability_service *svc, struct mac_capability_instance *s)
{

	sx_xlock(&mac_capability_registry_lock);
	if (svc->csvc_flags & MAC_CAPABILITY_SVCF_DESTROYING) {
		SDT_PROBE5(mac_capability, , , queue__pressure,
		    svc->csvc_name, (uint64_t)0, "instance-link-race",
		    svc->csvc_ninstances, svc->csvc_instance_limit);
		sx_xunlock(&mac_capability_registry_lock);
		return (ECONNABORTED);
	}
	LIST_INSERT_HEAD(&svc->csvc_instances, s, ci_svc_link);
	s->ci_flags |= MAC_CAPABILITY_SF_LINKED;
	sx_xunlock(&mac_capability_registry_lock);
	return (0);
}

/*
 * Shared instance setup: reserve slot, allocate instance, create a
 * struct file, run co_init, and link into the service list.  On
 * success the caller owns one reference on the returned fp.
 */
static int
mac_capability_instance_setup(struct mac_capability_service *svc, struct thread *td,
    uint64_t badge, struct file **fpp)
{
	struct mac_capability_instance *s;
	struct file *fp;
	int error;

	error = mac_capability_service_reserve(svc);
	if (error != 0)
		return (error);

	s = mac_capability_instance_init(svc, badge);
	SDT_PROBE6(mac_capability, , , instance__create, svc->csvc_name, badge,
	    td->td_proc->p_pid, td->td_ucred,
	    mac_capability_proc_nonce(td->td_ucred), svc->csvc_svc_flags);

	error = falloc_noinstall(td, &fp);
	if (error != 0) {
		mac_capability_instance_free(s);
		mac_capability_service_unreserve(svc);
		return (error);
	}

	finit(fp, FREAD | FWRITE, DTYPE_MAC_CAPABILITY, s, &mac_capability_instance_ops);

	if (svc->csvc_ops->co_init != NULL) {
		error = svc->csvc_ops->co_init(s, svc->csvc_arg);
		if (error != 0) {
			/*
			 * co_init failed.  Mark FINALIZED so close
			 * (triggered by fdrop) does NOT fire co_revoke.
			 * co_init's error path owns cleanup.
			 */
			mtx_lock(&s->ci_mtx);
			s->ci_flags |= MAC_CAPABILITY_SF_FINALIZED;
			mtx_unlock(&s->ci_mtx);
			fdrop(fp, td);
			mac_capability_service_unreserve(svc);
			return (error);
		}
	}

	/*
	 * Link before the fd is visible.  mac_capability_instance_link rechecks
	 * DESTROYING under xlock so a racing service_destroy cannot miss
	 * this instance.
	 */
	error = mac_capability_instance_link(svc, s);
	if (error != 0) {
		fdrop(fp, td);
		mac_capability_service_unreserve(svc);
		return (error);
	}

	*fpp = fp;
	return (0);
}

int
mac_capability_instance_create(struct mac_capability_service *svc, struct thread *td,
    uint64_t badge, int *fdp)
{
	struct file *fp;
	int error, fd;

	error = mac_capability_instance_setup(svc, td, badge, &fp);
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

	SDT_PROBE3(mac_capability, , , connect,
	    svc->csvc_name, badge, td->td_proc->p_pid);
	SDT_PROBE6(mac_capability, , , fd__install, svc->csvc_name, badge, fd,
	    td->td_proc->p_pid, td->td_ucred,
	    mac_capability_proc_nonce(td->td_ucred));

	*fdp = fd;
	return (0);
}

/*
 * Mint an instance and return a struct file * without installing an fd.
 * Safe to call from handler (taskqueue) context.  The caller holds one
 * reference on the returned fp and must fdrop() after passing it as an
 * attached descriptor in mac_capability_reply() or mac_capability_notify().
 */
int
mac_capability_mint_fp(struct mac_capability_service *svc, uint64_t badge,
    struct file **fpp)
{
	int error;

	error = mac_capability_instance_setup(svc, curthread, badge, fpp);
	if (error == 0) {
		SDT_PROBE6(mac_capability, , , fd__mint, svc->csvc_name, badge,
		    curthread->td_proc->p_pid, curthread->td_ucred,
		    mac_capability_proc_nonce(curthread->td_ucred),
		    svc->csvc_svc_flags);
	}
	return (error);
}

static d_ioctl_t	mac_capability_cdev_ioctl;

static struct cdevsw mac_capability_cdevsw = {
	.d_version =	D_VERSION,
	.d_ioctl =	mac_capability_cdev_ioctl,
	.d_name =	"mac_capability",
};

static int
mac_capability_ioctl_connect(struct mac_capability_connect_args *args, struct thread *td)
{
	const char *svc_name __unused;
	struct mac_capability_service *svc;
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
	args->name[MAC_CAPABILITY_MAXNAME - 1] = '\0';
	svc_name = args->name;
	if (args->name[0] == '\0') {
		error = EINVAL;
		goto out;
	}

	sx_slock(&mac_capability_registry_lock);
	svc = mac_capability_service_lookup(args->name);
	if (svc == NULL || (svc->csvc_flags & MAC_CAPABILITY_SVCF_DESTROYING)) {
		sx_sunlock(&mac_capability_registry_lock);
		error = ENOENT;
		goto out;
	}
	/* Hold a refcount so svc stays alive across co_connect. */
	refcount_acquire(&svc->csvc_refcnt);
	sx_sunlock(&mac_capability_registry_lock);

	if (svc->csvc_ops->co_connect != NULL) {
		error = svc->csvc_ops->co_connect(td->td_ucred,
		    svc->csvc_arg, &badge);
		if (error != 0) {
			SDT_PROBE6(mac_capability, , , error, svc->csvc_name,
			    badge, (u_long)MAC_CAPABILITY_CONNECT, td->td_proc->p_pid,
			    mac_capability_proc_nonce(td->td_ucred), error);
			refcount_release(&svc->csvc_refcnt);
			goto out;
		}
	}

	error = mac_capability_instance_create(svc, td, badge, &args->fd);
	/*
	 * instance_create acquires its own refcount on success.
	 * Drop the one we took for the co_connect window.
	 */
	refcount_release(&svc->csvc_refcnt);
out:
	SDT_PROBE5(mac_capability, , , connect__done, svc_name, badge,
	    td->td_proc->p_pid, error, getsbinuptime() - start);
	return (error);
}

static int
mac_capability_cdev_ioctl(struct cdev *dev __unused, u_long cmd, caddr_t data,
    int fflag __unused, struct thread *td)
{

	switch (cmd) {
	case MAC_CAPABILITY_CONNECT:
		return (mac_capability_ioctl_connect(
		    (struct mac_capability_connect_args *)data, td));
	default:
		return (ENOTTY);
	}
}

int
mac_capability_init(void)
{

	sx_init(&mac_capability_registry_lock, "mac_capability registry");
	mac_capability_instance_zone = uma_zcreate("mac_capability_instance",
	    sizeof(struct mac_capability_instance), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);
	mac_capability_msg_zone = uma_zcreate("mac_capability_msg",
	    sizeof(struct mac_capability_msg) + MAC_CAPABILITY_MSG_PAYLOAD_SIZE,
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, 0);
	mac_capability_stat_services = counter_u64_alloc(M_WAITOK);
	mac_capability_stat_instances = counter_u64_alloc(M_WAITOK);
	return (0);
}

void
mac_capability_uninit(void)
{

	counter_u64_free(mac_capability_stat_instances);
	counter_u64_free(mac_capability_stat_services);
	uma_zdestroy(mac_capability_msg_zone);
	uma_zdestroy(mac_capability_instance_zone);
	sx_destroy(&mac_capability_registry_lock);
}

static int
mac_capability_modevent(module_t mod __unused, int type, void *unused __unused)
{
	struct make_dev_args mda;
	int error;

	switch (type) {
	case MOD_LOAD:
		mac_capability_init();
		make_dev_args_init(&mda);
		mda.mda_flags = MAKEDEV_WAITOK | MAKEDEV_CHECKNAME;
		mda.mda_devsw = &mac_capability_cdevsw;
		mda.mda_uid = UID_ROOT;
		mda.mda_gid = GID_WHEEL;
		mda.mda_mode = 0600;
		error = make_dev_s(&mda, &mac_capability_cdev, "mac_capability");
		if (error != 0) {
			printf("mac_capability: failed to create /dev/mac_capability: %d\n",
			    error);
			mac_capability_uninit();
			return (error);
		}
		if (bootverbose)
			printf("mac_capability: loaded\n");
		return (0);

	case MOD_UNLOAD:
		sx_slock(&mac_capability_registry_lock);
		if (!LIST_EMPTY(&mac_capability_services)) {
			sx_sunlock(&mac_capability_registry_lock);
			return (EBUSY);
		}
		sx_sunlock(&mac_capability_registry_lock);
		destroy_dev(mac_capability_cdev);
		mac_capability_uninit();
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t mac_capability_mod = {
	"mac_capability",
	mac_capability_modevent,
	NULL,
};

DECLARE_MODULE(mac_capability, mac_capability_mod, SI_SUB_PSEUDO, SI_ORDER_FIRST);
MODULE_VERSION(mac_capability, 1);
