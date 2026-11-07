/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue: /dev/dq, tunables, tracing and module glue.
 *
 * One open is one queue.  The node is 0600 root:wheel and every open runs
 * priv_check(PRIV_DRIVER), exactly as /dev/oes does (D85): in stage 1a
 * the device permission is the authority; the plane delivery through a
 * provider endpoint is stage 4.  Like OES the device exists only when
 * compiled in or loaded at boot, and never unloads while a queue exists.
 */

#include "opt_dq.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/sdt.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/taskqueue.h>
#include <sys/uio.h>

#include <security/mac/mac_framework.h>
#include <security/mac/mac_policy.h>	/* MAC_VERSION */

#include <dev/dq/dq.h>
#include <dev/dq/dq_var.h>

MALLOC_DEFINE(M_DQ, "dq", "DescriptorQueue");

SDT_PROVIDER_DEFINE(dq);
SDT_PROBE_DEFINE1(dq, , , queue__open, "struct dq_queue *");
SDT_PROBE_DEFINE1(dq, , , queue__close, "struct dq_queue *");
SDT_PROBE_DEFINE2(dq, , , mint, "struct dq_queue *", "struct dq_object *");
SDT_PROBE_DEFINE3(dq, , , revoke, "struct dq_queue *", "struct dq_object *",
    "int");
SDT_PROBE_DEFINE2(dq, , , object__close, "struct dq_queue *",
    "struct dq_object *");
SDT_PROBE_DEFINE2(dq, , , event__post, "struct dq_queue *",
    "struct dq_event_k *");
SDT_PROBE_DEFINE2(dq, , , event__deliver, "struct dq_queue *",
    "struct dq_event_k *");
SDT_PROBE_DEFINE4(dq, , , event__reply, "struct dq_queue *",
    "struct dq_event_k *", "int", "size_t");
SDT_PROBE_DEFINE2(dq, , , event__drop, "struct dq_queue *", "int");
SDT_PROBE_DEFINE2(dq, , , event__interrupt, "struct dq_queue *",
    "struct dq_event_k *");
SDT_PROBE_DEFINE2(dq, , , event__deadline, "struct dq_queue *",
    "struct dq_event_k *");
SDT_PROBE_DEFINE2(dq, , , reply__late, "struct dq_queue *", "uint64_t");

/*
 * Tunables (design 8.6).  Bounded setters: a controller can lower its own
 * queue's depth below kern.dq.queue_depth but never raise it above.
 */
SYSCTL_NODE(_kern, OID_AUTO, dq, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "DescriptorQueue");

u_int dq_max_io = 131072;
u_int dq_queue_depth = 1024;
u_int dq_max_inflight_per_object = 64;
u_int dq_max_inflight_per_requester = 256;
u_int dq_max_objects = 65536;
int dq_default_deadline_ms = 30000;
u_int dq_max_inflight_bytes = 64 * 1024 * 1024;
struct taskqueue *dq_taskq;

/* A zero would make every read empty, every post a drop or an endless wait. */
static int
dq_sysctl_uint_min(SYSCTL_HANDLER_ARGS)
{
	u_int value;
	int error;

	value = *(u_int *)arg1;
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (value < (u_int)arg2)
		return (EINVAL);
	*(u_int *)arg1 = value;
	return (0);
}

static int
dq_sysctl_deadline(SYSCTL_HANDLER_ARGS)
{
	int value, error;

	value = dq_default_deadline_ms;
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (value < 0)
		return (EINVAL);
	dq_default_deadline_ms = value;
	return (0);
}

SYSCTL_PROC(_kern_dq, OID_AUTO, max_io,
    CTLTYPE_UINT | CTLFLAG_RWTUN | CTLFLAG_MPSAFE, &dq_max_io, PAGE_SIZE,
    dq_sysctl_uint_min, "IU",
    "Largest I/O in one event; larger transfers are chunked in order");
SYSCTL_PROC(_kern_dq, OID_AUTO, queue_depth,
    CTLTYPE_UINT | CTLFLAG_RWTUN | CTLFLAG_MPSAFE, &dq_queue_depth, 1,
    dq_sysctl_uint_min, "IU",
    "Events a queue holds before dropping with EIO and a sequence gap");
SYSCTL_PROC(_kern_dq, OID_AUTO, max_inflight_per_object,
    CTLTYPE_UINT | CTLFLAG_RWTUN | CTLFLAG_MPSAFE,
    &dq_max_inflight_per_object, 1, dq_sysctl_uint_min, "IU",
    "Unanswered events per object before requesters wait for a slot");
SYSCTL_PROC(_kern_dq, OID_AUTO, max_inflight_per_requester,
    CTLTYPE_UINT | CTLFLAG_RWTUN | CTLFLAG_MPSAFE,
    &dq_max_inflight_per_requester, 1, dq_sysctl_uint_min, "IU",
    "Unanswered events per requester before it waits for a slot");
SYSCTL_PROC(_kern_dq, OID_AUTO, max_objects,
    CTLTYPE_UINT | CTLFLAG_RWTUN | CTLFLAG_MPSAFE, &dq_max_objects, 1,
    dq_sysctl_uint_min, "IU", "Live objects per queue");
SYSCTL_PROC(_kern_dq, OID_AUTO, default_deadline_ms,
    CTLTYPE_INT | CTLFLAG_RWTUN | CTLFLAG_MPSAFE, NULL, 0,
    dq_sysctl_deadline, "I",
    "Deadline for an unanswered event when the policy says default; 0 = none");
SYSCTL_PROC(_kern_dq, OID_AUTO, max_inflight_bytes,
    CTLTYPE_UINT | CTLFLAG_RWTUN | CTLFLAG_MPSAFE, &dq_max_inflight_bytes,
    PAGE_SIZE, dq_sysctl_uint_min, "IU",
    "Bytes of READ_ASYNC/WRITE_ASYNC page I/O a queue may have pending; "
    "past it writeback answers VM_PAGER_AGAIN");
u_int dq_nqueues;
SYSCTL_UINT(_kern_dq, OID_AUTO, queues, CTLFLAG_RD, &dq_nqueues, 0,
    "Open queues");

struct mtx dq_mtx;
struct dq_queue_list dq_queues = LIST_HEAD_INITIALIZER(dq_queues);
uint64_t dq_next_gid;

static struct cdev *dq_cdev;
static bool dq_active;

static bool
dq_thread_is_ilp32(struct thread *td)
{

	return (td != NULL && td->td_proc != NULL &&
	    (td->td_proc->p_sysent->sv_flags & SV_ILP32) != 0);
}

static void
dq_cdevpriv_dtor(void *data)
{

	dq_queue_close(data);
}

static int
dq_open(struct cdev *dev __unused, int oflags __unused, int devtype __unused,
    struct thread *td)
{
	struct dq_queue *q;
	int error;

	if (dq_thread_is_ilp32(td))
		return (EOPNOTSUPP);
	error = priv_check(td, PRIV_DRIVER);
	if (error != 0)
		return (error);
	if (!dq_active)
		return (ENXIO);
	/*
	 * td_fpop is the struct file being opened (devfs_vnops.c
	 * devfs_open); the queue keeps it as the identity the EDEADLK rule
	 * compares against, never as a reference.
	 */
	if (td->td_fpop == NULL)
		return (ENOENT);
	q = dq_queue_create(td, td->td_fpop);
	error = devfs_set_cdevpriv(q, dq_cdevpriv_dtor);
	if (error != 0)
		dq_queue_close(q);
	return (error);
}

static int
dq_read(struct cdev *dev __unused, struct uio *uio, int ioflag)
{
	struct dq_queue *q;
	int error;

	error = devfs_get_cdevpriv((void **)&q);
	if (error != 0)
		return (error);
	return (dq_queue_read(q, uio, ioflag));
}

static int
dq_ioctl(struct cdev *dev __unused, u_long cmd, caddr_t data, int fflag __unused,
    struct thread *td)
{
	struct dq_queue *q;
	struct dq_stats *st;
	int error;

	error = devfs_get_cdevpriv((void **)&q);
	if (error != 0)
		return (error);
	switch (cmd) {
	case DQ_IOC_MINT:
		return (dq_queue_mint(q, (struct dq_mint_args *)data, td));
	case DQ_IOC_MINT_OBSERVER:
		return (dq_queue_mint_observer(q,
		    (struct dq_observer_args *)data, td));
	case DQ_IOC_REPLY:
		return (dq_queue_reply(q, (const struct dq_reply *)data, td));
	case DQ_IOC_REVOKE: {
		struct dq_object_args *oa = (struct dq_object_args *)data;

		if (oa->doa_version != DQ_API_VERSION || oa->doa_pad0 != 0)
			return (EINVAL);
		return (dq_queue_revoke(q, oa->doa_object));
	}
	case DQ_IOC_SETIDENT:
		return (dq_queue_setident(q, (struct dq_setident_args *)data));
	case DQ_IOC_SETPOLICY:
		return (dq_queue_setpolicy(q, (struct dq_setpolicy_args *)data));
	case DQ_IOC_GET_STATS:
		st = (struct dq_stats *)data;
		dq_queue_stats(q, st);
		return (0);
	case DQ_IOC_GET_STATS2:
		dq_queue_stats2(q, (struct dq_stats2 *)data);
		return (0);
	case DQ_IOC_SET_QUEUE_DEPTH:
		return (dq_queue_set_depth(q, *(uint32_t *)data));
	case DQ_IOC_PUSH:
		return (dq_queue_push(q, (const struct dq_push_args *)data));
	case DQ_IOC_PUSH_V1: {
		/* The stage 1b-i layout: no range, so no INVALIDATE. */
		const struct dq_push_args_v1 *v1 =
		    (const struct dq_push_args_v1 *)data;
		struct dq_push_args pa;

		if (v1->dp_op != DQ_PUSH_NOTIFY_VNODE)
			return (EINVAL);
		bzero(&pa, sizeof(pa));
		pa.dp_version = v1->dp_version;
		pa.dp_op = v1->dp_op;
		pa.dp_object = v1->dp_object;
		pa.dp_note = v1->dp_note;
		pa.dp_pad0 = v1->dp_pad0;
		return (dq_queue_push(q, &pa));
	}
	case FIONBIO:
	case FIOASYNC:
		return (0);
	default:
		return (ENOTTY);
	}
}

static int
dq_poll(struct cdev *dev __unused, int events, struct thread *td)
{
	struct dq_queue *q;
	int error;

	error = devfs_get_cdevpriv((void **)&q);
	if (error != 0)
		return (POLLERR);
	return (dq_queue_poll(q, events, td));
}

static int
dq_kqfilter(struct cdev *dev __unused, struct knote *kn)
{
	struct dq_queue *q;
	int error;

	error = devfs_get_cdevpriv((void **)&q);
	if (error != 0)
		return (error);
	return (dq_queue_kqfilter(q, kn));
}

static struct cdevsw dq_cdevsw = {
	.d_version = D_VERSION,
	.d_open = dq_open,
	.d_read = dq_read,
	.d_ioctl = dq_ioctl,
	.d_poll = dq_poll,
	.d_kqfilter = dq_kqfilter,
	.d_name = "dq",
};

static int
dq_init(void)
{

	int error;

	/*
	 * The pager type (D102): a dynamic type gets no pgo_init, so it is
	 * registered here, before any queue can mint.  Without one there is
	 * no object to serve pages from and no device.
	 */
	error = dq_pager_register();
	if (error != 0) {
		printf("dq: no dynamic pager type available\n");
		return (error);
	}
	/* Async page completions (B1): never under a dq lock. */
	/*
	 * The name is the witness class of the queue's own mutex: it must not
	 * be "dq", which is dq_mtx's (WITNESS keys locks by name).
	 */
	dq_taskq = taskqueue_create("dq_taskq", M_WAITOK,
	    taskqueue_thread_enqueue, &dq_taskq);
	taskqueue_start_threads(&dq_taskq, 2, PVM, "dq taskq");
	mtx_init(&dq_mtx, "dq", NULL, MTX_DEF);
	dq_file_init();		/* the lock-owner hash key */
	dq_cdev = make_dev(&dq_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600, "dq");
	if (dq_cdev == NULL) {
		mtx_destroy(&dq_mtx);
		return (ENXIO);
	}
	dq_active = true;
	return (0);
}

/*
 * The dq.observe service needs the capability framework, which initialises
 * at SI_SUB_PSEUDO, SI_ORDER_FIRST; the device itself comes up with the
 * drivers, while `cold` still holds, so a late kldload is refused as OES
 * refuses it.  A failed registration leaves the device without observation
 * rather than without existence, and says so.
 */
static void
dq_observe_sysinit(void *arg __unused)
{
	int error;

	if (!dq_active)
		return;
	error = dq_observe_init();
	if (error != 0)
		printf("dq: dq.observe service not registered: %d\n", error);
}
SYSINIT(dq_observe, SI_SUB_PSEUDO, SI_ORDER_ANY, dq_observe_sysinit, NULL);

static int
dq_modevent(module_t mod __unused, int type, void *data __unused)
{

	switch (type) {
	case MOD_LOAD:
		if (!cold) {
			printf("dq: cannot be loaded after boot\n");
			return (EBUSY);
		}
		return (dq_init());
	case MOD_UNLOAD:
		/* Queues hold objects and observers; none may be orphaned. */
		return (EBUSY);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t dq_mod = {
	"dq",
	dq_modevent,
	NULL
};

DECLARE_MODULE(dq, dq_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(dq, 1);
MODULE_DEPEND(dq, mac_capability, 1, 1, 1);
MODULE_DEPEND(dq, kernel_mac_support, MAC_VERSION, MAC_VERSION, MAC_VERSION);
