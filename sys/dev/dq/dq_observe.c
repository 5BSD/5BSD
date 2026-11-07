/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue: the dq.observe mac_capability service (D90).
 *
 * Observation is a capability, not a uid-keyed sysctl (D21): a holder of
 * an instance lists queues and objects and subscribes to a queue's
 * observer stream.  Stage 1a admits a credential that may open the
 * device itself (priv_check(PRIV_DRIVER), the same rule as /dev/dq, D85);
 * the capsule/bundle admission under system.dq.observe arrives with the
 * provider in stage 4.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/ucred.h>

#include <dev/mac_capability/mac_capability.h>
#include <dev/mac_capability/mac_capability_label.h>

#include <dev/dq/dq.h>
#include <dev/dq/dq_var.h>
#include <dev/dq/dq_observe_proto.h>

static struct mac_capability_service *dq_observe_svc;

static int
dq_observe_connect(struct ucred *cred, void *arg __unused, uint64_t *badge_out)
{
	int error;

	error = priv_check_cred(cred, PRIV_DRIVER);
	if (error != 0)
		return (error);
	*badge_out = 0;
	return (0);
}

/* Look a queue up by its kernel-wide id and hold it. */
static struct dq_queue *
dq_observe_queue(uint64_t id)
{
	struct dq_queue *q;

	mtx_lock(&dq_mtx);
	LIST_FOREACH(q, &dq_queues, q_all) {
		if (q->q_gid == id) {
			dq_queue_hold(q);
			break;
		}
	}
	mtx_unlock(&dq_mtx);
	return (q);
}

static int
dq_observe_list_queues(const struct dqo_request *req, void *reply,
    size_t *replylenp)
{
	struct dqo_reply_hdr *hdr;
	struct dqo_queue_info *qi;
	struct dq_queue *q;
	size_t room, n;
	uint64_t index;

	if (*replylenp < sizeof(*hdr))
		return (EINVAL);
	hdr = reply;
	qi = (struct dqo_queue_info *)(hdr + 1);
	room = (*replylenp - sizeof(*hdr)) / sizeof(*qi);
	n = 0;
	index = 0;
	mtx_lock(&dq_mtx);
	LIST_FOREACH(q, &dq_queues, q_all) {
		if (index++ < req->dr_first || n >= room)
			continue;
		DQ_LOCK(q);
		bzero(&qi[n], sizeof(qi[n]));
		qi[n].qi_id = q->q_gid;
		qi[n].qi_pid = q->q_pid;
		qi[n].qi_uid = q->q_cred->cr_ruid;
		qi[n].qi_nonce = mac_capability_proc_nonce(q->q_cred);
		qi[n].qi_objects = q->q_nobjects;
		qi[n].qi_pending = q->q_count;
		qi[n].qi_inflight = q->q_stats.ds2_inflight;
		qi[n].qi_posted = q->q_stats.ds2_events_posted;
		qi[n].qi_dropped = q->q_stats.ds2_events_dropped;
		qi[n].qi_observers = q->q_nobservers;
		if ((q->q_flags & DQ_Q_CLOSING) != 0)
			qi[n].qi_flags |= DQO_QF_CLOSING;
		DQ_UNLOCK(q);
		n++;
	}
	hdr->dh_total = dq_nqueues;
	mtx_unlock(&dq_mtx);
	hdr->dh_version = DQ_OBSERVE_VERSION;
	hdr->dh_count = n;
	*replylenp = sizeof(*hdr) + n * sizeof(*qi);
	return (0);
}

static int
dq_observe_list_objects(const struct dqo_request *req, void *reply,
    size_t *replylenp)
{
	struct dqo_reply_hdr *hdr;
	struct dqo_object_info *oi;
	struct dq_queue *q;
	struct dq_object *o;
	size_t room, n;
	uint64_t index;

	if (*replylenp < sizeof(*hdr))
		return (EINVAL);
	q = dq_observe_queue(req->dr_queue);
	if (q == NULL)
		return (ESRCH);
	hdr = reply;
	oi = (struct dqo_object_info *)(hdr + 1);
	room = (*replylenp - sizeof(*hdr)) / sizeof(*oi);
	n = 0;
	index = 0;
	DQ_LOCK(q);
	RB_FOREACH(o, dq_object_tree, &q->q_objects) {
		if (index++ < req->dr_first || n >= room)
			continue;
		DQO_LOCK(o);
		bzero(&oi[n], sizeof(oi[n]));
		oi[n].oi_id = o->o_id;
		oi[n].oi_kind = o->o_kind;
		oi[n].oi_state = o->o_state;
		oi[n].oi_dev = o->o_ident.di_dev;
		oi[n].oi_ino = o->o_ident.di_ino;
		oi[n].oi_size = o->o_ident.di_size;
		oi[n].oi_mode = o->o_ident.di_mode;
		oi[n].oi_inflight = o->o_inflight;
		strlcpy(oi[n].oi_path, o->o_ident.di_path, sizeof(oi[n].oi_path));
		DQO_UNLOCK(o);
		n++;
	}
	hdr->dh_total = q->q_nobjects;
	DQ_UNLOCK(q);
	dq_queue_rele(q);
	hdr->dh_version = DQ_OBSERVE_VERSION;
	hdr->dh_count = n;
	*replylenp = sizeof(*hdr) + n * sizeof(*oi);
	return (0);
}

/*
 * A metadata-only observer of one queue.  co_call runs in the caller's
 * thread, so the descriptor is installed here with the same rights and
 * locked state as DQ_IOC_MINT_OBSERVER gives (the framework's reply
 * descriptors would be installed with full rights and unlimited transfer).
 */
static int
dq_observe_subscribe(const struct dqo_request *req, struct thread *td,
    void *reply, size_t *replylenp)
{
	struct dqo_subscribe_reply *rep;
	struct dq_queue *q;
	struct dq_observer *ob;
	int error, fd;

	if (*replylenp < sizeof(*rep))
		return (EINVAL);
	q = dq_observe_queue(req->dr_queue);
	if (q == NULL)
		return (ESRCH);
	ob = dq_observer_create(q, 0);
	dq_queue_rele(q);
	if (ob == NULL)
		return (ENXIO);
	error = dq_observer_install(td, ob, &fd);
	if (error != 0)
		return (error);
	rep = reply;
	bzero(rep, sizeof(*rep));
	rep->sr_hdr.dh_version = DQ_OBSERVE_VERSION;
	rep->sr_hdr.dh_count = 1;
	rep->sr_hdr.dh_total = 1;
	rep->sr_fd = fd;
	*replylenp = sizeof(*rep);
	return (0);
}

static int
dq_observe_call(struct mac_capability_instance *s __unused, const void *req,
    size_t reqlen, struct file **fds __unused, struct filecaps *fcaps __unused,
    int nfds, void *reply, size_t *replylenp, struct file **reply_fds __unused,
    int *reply_nfdsp __unused, void *arg __unused)
{
	const struct dqo_request *r;

	if (reqlen < sizeof(*r) || nfds != 0)
		return (EINVAL);
	r = req;
	if (r->dr_version != DQ_OBSERVE_VERSION)
		return (EINVAL);
	switch (r->dr_op) {
	case DQO_OP_LIST_QUEUES:
		return (dq_observe_list_queues(r, reply, replylenp));
	case DQO_OP_LIST_OBJECTS:
		return (dq_observe_list_objects(r, reply, replylenp));
	case DQO_OP_SUBSCRIBE:
		return (dq_observe_subscribe(r, curthread, reply, replylenp));
	default:
		return (EINVAL);
	}
}

static const struct mac_capability_ops dq_observe_ops = {
	.co_connect = dq_observe_connect,
	.co_call = dq_observe_call,
};

int
dq_observe_init(void)
{
	struct mac_capability_service_params params;

	memset(&params, 0, sizeof(params));
	params.name = DQ_OBSERVE_SERVICE;
	params.ops = &dq_observe_ops;
	params.flags = MAC_CAPABILITY_SVC_MINTABLE;
	return (mac_capability_service_create(&params, &dq_observe_svc));
}

void
dq_observe_uninit(void)
{

	if (dq_observe_svc != NULL) {
		mac_capability_service_destroy(dq_observe_svc);
		dq_observe_svc = NULL;
	}
}
