/*-
 * Copyright (c) 2015 iXsystems Inc.
 * Copyright (c) 2017-2018 Jakub Klama <jceel@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * VirtIO filesystem passthrough using 9p protocol.
 */

/*
 * Release-ledger anchor for pci_vt9p_notify()/pci_vt9p_send().
 * VIRTIO_ACTIVATION_ASSERTION: request-and-reply
 */

#include <sys/param.h>
#include <sys/linker_set.h>
#include <sys/uio.h>
#include <sys/capsicum.h>
#include <sys/endian.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <pthread_np.h>

#include <lib9p.h>
#include <backend/fs.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "pci_emul.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif
#include "virtio.h"

#define	VT9P_MAX_IOV	128
#define VT9P_RINGSZ	256
#define	VT9P_MAXTAGSZ	256
/*
 * Protocol/resource limit, not a host-page calculation.  Keeping the
 * historical amd64 limit explicit makes negotiation and saved state stable
 * on hosts with a different page size.
 */
#define	VT9P_MAX_MSIZE	(512U * 1024U)
#define	VT9P_CONFIGSPACESZ	(VT9P_MAXTAGSZ + sizeof(uint16_t))
#define	VIRTIO_9P_F_MOUNT_TAG	(1ULL << 0)
#ifndef VT9P_QUIESCE_TIMEOUT_SECONDS
#define	VT9P_QUIESCE_TIMEOUT_SECONDS	30
#endif

static int pci_vt9p_debug;
#define DPRINTF(params) if (pci_vt9p_debug) printf params
#define WPRINTF(params) printf params

/*
 * Per-device softc
 */
struct pci_vt9p_softc {
	struct virtio_softc      vsc_vs;
	struct virtio_consts     vsc_consts;
	struct vqueue_info       vsc_vq;
	pthread_mutex_t          vsc_mtx;
	pthread_cond_t           vsc_reset_cv;
	uint64_t                 vsc_features;
	char *                   vsc_rootpath;
	dev_t                    vsc_rootdev;
	ino_t                    vsc_rootino;
	bool                     vsc_readonly;
	struct pci_vt9p_config * vsc_config;
	struct l9p_backend *     vsc_fs_backend;
	struct l9p_server *      vsc_server;
	struct l9p_connection *  vsc_conn;
	uint64_t                 vsc_generation;
	uint64_t                 vsc_qreset_generation;
	size_t                   vsc_active_requests;
	struct vqueue_info *     vsc_qreset_vq;
	bool                     vsc_resetting;
	bool                     vsc_queue_reset;
	bool                     vsc_qreset_pending;
};

struct pci_vt9p_request {
	struct pci_vt9p_softc *	vsr_sc;
	struct iovec		vsr_iov[VT9P_MAX_IOV];
	size_t			vsr_niov;
	size_t			vsr_respidx;
	size_t			vsr_iolen;
	struct vi_req		vsr_req;
	uint64_t		vsr_generation;
	bool			vsr_active;
};

struct pci_vt9p_config {
	uint16_t tag_len;
	char tag[0];
} __attribute__((packed));

static int pci_vt9p_send(struct l9p_request *, const struct iovec *,
    const size_t, const size_t, void *);
static void pci_vt9p_drop(struct l9p_request *, const struct iovec *, size_t,
    void *);
static int pci_vt9p_get_buffer(struct l9p_request *, struct iovec *, size_t *,
    void *);
static void pci_vt9p_reset(void *);
static int pci_vt9p_qenable(void *, struct vqueue_info *);
static int pci_vt9p_qreset(void *, struct vqueue_info *, uint64_t);
static void pci_vt9p_notify(void *, struct vqueue_info *);
static int pci_vt9p_cfgread(void *, int, int, uint32_t *);
static int pci_vt9p_neg_features(void *, uint64_t);
static int pci_vt9p_suspend_device(void *);
static int pci_vt9p_resume_device(void *);
static void pci_vt9p_set_tag(struct pci_vt9p_softc *, const char *);
#ifdef BHYVE_SNAPSHOT
static int pci_vt9p_pause(void *);
static int pci_vt9p_resume(void *);
static int pci_vt9p_snapshot(void *, struct vm_snapshot_meta *);
static int pci_vt9p_snapshot_validate(struct vm_snapshot_meta *);
#endif

static void
pci_vt9p_configure_connection(struct l9p_connection *conn)
{

	conn->lc_msize = VT9P_MAX_MSIZE;
	conn->lc_lt.lt_get_response_buffer = pci_vt9p_get_buffer;
	conn->lc_lt.lt_send_response = pci_vt9p_send;
	conn->lc_lt.lt_drop_response = pci_vt9p_drop;
}

static void
pci_vt9p_set_tag(struct pci_vt9p_softc *sc, const char *tag)
{
	uint16_t tag_len;

	tag_len = (uint16_t)strlen(tag);
	sc->vsc_config->tag_len = vi_pci_is_modern(&sc->vsc_vs) ?
	    htole16(tag_len) : tag_len;
	memcpy(sc->vsc_config->tag, tag, tag_len);
}

static struct virtio_consts vt9p_vi_consts = {
	.vc_name =	"vt9p",
	.vc_nvq =	1,
	.vc_cfgsize =	VT9P_CONFIGSPACESZ,
	.vc_reset =	pci_vt9p_reset,
	.vc_qnotify =	pci_vt9p_notify,
	.vc_cfgread =	pci_vt9p_cfgread,
	.vc_apply_features = pci_vt9p_neg_features,
	.vc_qenable =	pci_vt9p_qenable,
	.vc_qreset =	pci_vt9p_qreset,
	.vc_suspend =	pci_vt9p_suspend_device,
	.vc_resume_device = pci_vt9p_resume_device,
	.vc_hv_caps =	VIRTIO_9P_F_MOUNT_TAG | VIRTIO_F_RING_RESET |
	    VIRTIO_F_SUSPEND,
#ifdef BHYVE_SNAPSHOT
	.vc_pause =	pci_vt9p_pause,
	.vc_resume =	pci_vt9p_resume,
	.vc_snapshot =	pci_vt9p_snapshot,
#endif
};

static int
pci_vt9p_reconnect(struct pci_vt9p_softc *sc)
{
	struct l9p_connection *conn, *newconn;

	/*
	 * A reconnect may have dropped vsc_mtx while draining lib9p just as
	 * another vCPU starts a full device reset.  The full reset must not
	 * publish status zero until that drain has finished: otherwise the
	 * driver can configure and kick a new queue while the stale callback is
	 * still replacing vsc_conn.  Serialize reset generations here instead
	 * of treating an in-progress reset as a completed one.
	 */
	while (sc->vsc_resetting)
		pthread_cond_wait(&sc->vsc_reset_cv, &sc->vsc_mtx);
	sc->vsc_resetting = true;
	conn = sc->vsc_conn;
	sc->vsc_conn = NULL;

	/*
	 * Closing drains worker requests, whose callbacks acquire vsc_mtx.
	 * The VirtIO layer calls reset with that mutex held, so drop it while
	 * draining.  vsc_resetting prevents a concurrent notify or reset from
	 * using the connection until its replacement is installed.
	 */
	pthread_mutex_unlock(&sc->vsc_mtx);
	if (conn != NULL) {
		l9p_connection_close(conn);
		l9p_connection_free(conn);
	}
	newconn = NULL;
	if (l9p_connection_init(sc->vsc_server, &newconn) == 0)
		pci_vt9p_configure_connection(newconn);
	pthread_mutex_lock(&sc->vsc_mtx);
	sc->vsc_conn = newconn;
	sc->vsc_qreset_pending = false;
	sc->vsc_qreset_vq = NULL;
	sc->vsc_queue_reset = false;
	sc->vsc_resetting = false;
	/*
	 * Every kick observed while the old connection was draining belongs to
	 * the queue incarnation invalidated by the reset.  Never replay it
	 * against the replacement connection; the driver must kick the newly
	 * enabled queue.
	 */
	pthread_cond_broadcast(&sc->vsc_reset_cv);
	if (newconn == NULL) {
		WPRINTF(("vt9p: cannot reinitialize 9P connection\n"));
		return (EIO);
	}
	return (0);
}

static void
pci_vt9p_reset(void *vsc)
{
	struct pci_vt9p_softc *sc;
	int error;

	sc = vsc;
	DPRINTF(("vt9p: device reset requested !\n"));
	sc->vsc_generation++;
	sc->vsc_queue_reset = false;
	vi_reset_dev(&sc->vsc_vs);
	sc->vsc_features = 0;
	error = pci_vt9p_reconnect(sc);
	if (error != 0)
		vi_set_needs_reset(&sc->vsc_vs);
}

static int
pci_vt9p_qenable(void *vsc, struct vqueue_info *vq)
{
	struct pci_vt9p_softc *sc;

	sc = vsc;
	if (vq->vq_num != 0 || vq != &sc->vsc_vq ||
	    sc->vsc_qreset_pending)
		return (EINVAL);
	sc->vsc_queue_reset = false;
	return (0);
}

static int
pci_vt9p_qreset(void *vsc, struct vqueue_info *vq, uint64_t generation)
{
	struct pci_vt9p_softc *sc;

	sc = vsc;
	if (vq->vq_num != 0 || vq != &sc->vsc_vq ||
	    sc->vsc_qreset_pending)
		return (EINVAL);

	/*
	 * Do not close the lib9p connection: queue reset must preserve the
	 * mounted session and its fid namespace.  Advancing the generation
	 * prevents accepted requests from publishing into the old used ring.
	 * Their lib9p callbacks release guest buffers asynchronously and the
	 * last callback completes the transport reset.
	 */
	sc->vsc_generation++;
	sc->vsc_queue_reset = true;
	if (sc->vsc_active_requests == 0)
		return (0);
	sc->vsc_qreset_vq = vq;
	sc->vsc_qreset_generation = generation;
	sc->vsc_qreset_pending = true;
	return (EINPROGRESS);
}

static int
pci_vt9p_neg_features(void *vsc, uint64_t negotiated_features)
{
	struct pci_vt9p_softc *sc = vsc;

	sc->vsc_features = negotiated_features;
	return (0);
}

static int
pci_vt9p_suspend_device(void *vsc)
{
	struct pci_vt9p_softc *sc;
	struct timespec deadline;
	int error;

	sc = vsc;
	assert(pthread_mutex_isowned_np(&sc->vsc_mtx));

	/*
	 * The common VirtIO layer has already fenced the queue, so the active
	 * count can only decrease.  Preserve the lib9p connection and its fid
	 * namespace across guest suspend, but do not acknowledge SUSPEND until
	 * every request accepted before the fence has completed.  Reset and
	 * queue-reset paths use the same condition variable and may temporarily
	 * drop vsc_mtx while draining callbacks.
	 */
	if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0)
		return (errno);
	deadline.tv_sec += VT9P_QUIESCE_TIMEOUT_SECONDS;
	while (sc->vsc_active_requests != 0 || sc->vsc_resetting ||
	    sc->vsc_qreset_pending) {
		error = pthread_cond_timedwait(&sc->vsc_reset_cv, &sc->vsc_mtx,
		    &deadline);
		if (error != 0)
			return (error);
	}
	return (sc->vsc_conn == NULL ? EIO : 0);
}

static int
pci_vt9p_resume_device(void *vsc)
{
	struct pci_vt9p_softc *sc;

	sc = vsc;
	assert(pthread_mutex_isowned_np(&sc->vsc_mtx));
	return (sc->vsc_conn == NULL ? EIO : 0);
}

static int
pci_vt9p_cfgread(void *vsc, int offset, int size, uint32_t *retval)
{
	struct pci_vt9p_softc *sc = vsc;

	return (vi_config_read_le(sc->vsc_config, VT9P_CONFIGSPACESZ,
	    offset, size, retval));
}

static int
pci_vt9p_get_buffer(struct l9p_request *req, struct iovec *iov, size_t *niov,
    void *arg __unused)
{
	struct pci_vt9p_request *preq = req->lr_aux;
	size_t n = preq->vsr_niov - preq->vsr_respidx;

	memcpy(iov, preq->vsr_iov + preq->vsr_respidx,
	    n * sizeof(struct iovec));
	*niov = n;
	return (0);
}

static bool
pci_vt9p_finish_request_locked(struct pci_vt9p_softc *sc,
    struct pci_vt9p_request *preq, struct vqueue_info **reset_vq,
    uint64_t *generation)
{

	if (preq->vsr_active) {
		preq->vsr_active = false;
		assert(sc->vsc_active_requests > 0);
		sc->vsc_active_requests--;
		pthread_cond_broadcast(&sc->vsc_reset_cv);
	}
	if (!sc->vsc_qreset_pending || sc->vsc_active_requests != 0)
		return (false);
	*reset_vq = sc->vsc_qreset_vq;
	*generation = sc->vsc_qreset_generation;
	sc->vsc_qreset_pending = false;
	sc->vsc_qreset_vq = NULL;
	pthread_cond_broadcast(&sc->vsc_reset_cv);
	return (true);
}

static int
pci_vt9p_send(struct l9p_request *req, const struct iovec *iov __unused,
    const size_t niov __unused, const size_t iolen, void *arg __unused)
{
	struct pci_vt9p_request *preq = req->lr_aux;
	struct pci_vt9p_softc *sc = preq->vsr_sc;
	struct vqueue_info *reset_vq;
	uint64_t generation;
	bool reset_complete;

	preq->vsr_iolen = iolen;
	reset_vq = NULL;
	generation = 0;

	pthread_mutex_lock(&sc->vsc_mtx);
	if (preq->vsr_generation == sc->vsc_generation) {
		vq_relchain_req(&sc->vsc_vq, &preq->vsr_req,
		    preq->vsr_iolen);
		vq_endchains(&sc->vsc_vq, 1);
	} else
		vq_discard_req(&sc->vsc_vq, &preq->vsr_req);
	reset_complete = pci_vt9p_finish_request_locked(sc, preq, &reset_vq,
	    &generation);
	pthread_mutex_unlock(&sc->vsc_mtx);
	free(preq);
	if (reset_complete)
		vi_pci_modern_queue_reset_complete(reset_vq, generation, 0);
	return (0);
}

static void
pci_vt9p_drop(struct l9p_request *req, const struct iovec *iov __unused,
    size_t niov __unused, void *arg __unused)
{
	struct pci_vt9p_request *preq = req->lr_aux;
	struct pci_vt9p_softc *sc = preq->vsr_sc;
	struct vqueue_info *reset_vq;
	uint64_t generation;
	bool reset_complete;

	reset_vq = NULL;
	generation = 0;
	pthread_mutex_lock(&sc->vsc_mtx);
	if (preq->vsr_generation == sc->vsc_generation) {
		vq_relchain_req(&sc->vsc_vq, &preq->vsr_req, 0);
		vq_endchains(&sc->vsc_vq, 1);
	} else
		vq_discard_req(&sc->vsc_vq, &preq->vsr_req);
	reset_complete = pci_vt9p_finish_request_locked(sc, preq, &reset_vq,
	    &generation);
	pthread_mutex_unlock(&sc->vsc_mtx);
	free(preq);
	if (reset_complete)
		vi_pci_modern_queue_reset_complete(reset_vq, generation, 0);
}

static void
pci_vt9p_notify(void *vsc, struct vqueue_info *vq)
{
	struct iovec iov[VT9P_MAX_IOV];
	struct pci_vt9p_softc *sc;
	struct pci_vt9p_request *preq;
	struct vi_req req;
	uint16_t budget;
	int n;

	sc = vsc;
	if (sc->vsc_resetting || sc->vsc_queue_reset ||
	    sc->vsc_conn == NULL)
		return;

	budget = vq->vq_qsize;
	while (budget-- != 0 && vq_has_descs(vq)) {
		n = vq_getchain(vq, iov, VT9P_MAX_IOV, &req);
		if (n <= 0)
			break;
		if (n > VT9P_MAX_IOV || !req.ordered || req.readable == 0 ||
		    req.writable == 0 || req.readable + req.writable != n) {
			DPRINTF(("vt9p: invalid descriptor chain\n"));
			vq_relchain_req(vq, &req, 0);
			continue;
		}
		preq = calloc(1, sizeof(*preq));
		if (preq == NULL) {
			WPRINTF(("vt9p: cannot allocate request\n"));
			vq_relchain_req(vq, &req, 0);
			continue;
		}
		preq->vsr_sc = sc;
		preq->vsr_req = req;
		memcpy(preq->vsr_iov, iov, n * sizeof(iov[0]));
		preq->vsr_niov = n;
		preq->vsr_respidx = req.readable;
		preq->vsr_generation = sc->vsc_generation;
		preq->vsr_active = true;
		sc->vsc_active_requests++;

		for (int i = 0; i < n; i++) {
			DPRINTF(("vt9p: vt9p_notify(): desc%d base=%p, "
			    "len=%zu\r\n", i, iov[i].iov_base,
			    iov[i].iov_len));
		}

		if (l9p_connection_recv(sc->vsc_conn, preq->vsr_iov,
		    preq->vsr_respidx, preq) != 0) {
			assert(preq->vsr_active);
			preq->vsr_active = false;
			assert(sc->vsc_active_requests > 0);
			sc->vsc_active_requests--;
			pthread_cond_broadcast(&sc->vsc_reset_cv);
			vq_relchain_req(vq, &preq->vsr_req, 0);
			free(preq);
		}
	}
	vq_endchains(vq, !vq_has_descs(vq));
}

#ifdef BHYVE_SNAPSHOT
#define	VT9P_SNAPSHOT_MAGIC		0x32503956U	/* "V9P2" on disk */
#define	VT9P_SNAPSHOT_VERSION		2U
#define	VT9P_SNAPSHOT_STRING_MAX	(1024U * 1024U)

static bool
pci_vt9p_has_fids(struct pci_vt9p_softc *sc)
{
	struct ht_iter iter;

	if (sc->vsc_conn == NULL ||
	    sc->vsc_conn->lc_files.ht_entries == NULL)
		return (false);
	ht_iter(&sc->vsc_conn->lc_files, &iter);
	return (ht_next(&iter) != NULL);
}

static int
pci_vt9p_pause(void *vsc)
{
	struct pci_vt9p_softc *sc;

	sc = vsc;
	pthread_mutex_lock(&sc->vsc_mtx);
	/*
	 * lib9p fids contain backend-private host descriptors and credentials.
	 * They are not portable state.  Refuse the checkpoint rather than
	 * silently restoring a broken mount or serializing host pointers.
	 * VIRTIO_ACTIVATION_ASSERTION: active-fid-checkpoint-rejected
	 */
	if (sc->vsc_conn == NULL || sc->vsc_resetting ||
	    sc->vsc_qreset_pending ||
	    sc->vsc_active_requests != 0 || pci_vt9p_has_fids(sc)) {
		pthread_mutex_unlock(&sc->vsc_mtx);
		return (EBUSY);
	}
	return (0);
}

static int
pci_vt9p_resume(void *vsc)
{
	struct pci_vt9p_softc *sc;

	sc = vsc;
	pthread_mutex_unlock(&sc->vsc_mtx);
	return (0);
}

static int
pci_vt9p_snapshot(void *vsc, struct vm_snapshot_meta *meta)
{
	struct pci_vt9p_softc *sc;
	uint64_t features, restore_generation, rootdev, rootino;
	uint32_t magic, max_io_size, msize, version;
	uint16_t current_tag_len, saved_tag_len;
	uint8_t connection_version, readonly;
	char saved_tag[VT9P_MAXTAGSZ];
	int error;

	sc = vsc;
	if (sc->vsc_conn == NULL || sc->vsc_resetting ||
	    sc->vsc_qreset_pending || sc->vsc_active_requests != 0 ||
	    pci_vt9p_has_fids(sc))
		return (EBUSY);
	restore_generation = 0;
	if (vm_snapshot_is_loading(meta)) {
		if (sc->vsc_generation == UINT64_MAX)
			return (EOVERFLOW);
		restore_generation = sc->vsc_generation + 1;
	}
	magic = VT9P_SNAPSHOT_MAGIC;
	version = VT9P_SNAPSHOT_VERSION;
	features = sc->vsc_features;
	rootdev = (uint64_t)sc->vsc_rootdev;
	rootino = (uint64_t)sc->vsc_rootino;
	readonly = sc->vsc_readonly;
	connection_version = sc->vsc_conn->lc_version;
	msize = sc->vsc_conn->lc_msize;
	max_io_size = sc->vsc_conn->lc_max_io_size;
	current_tag_len = vi_pci_is_modern(&sc->vsc_vs) ?
	    le16toh(sc->vsc_config->tag_len) : sc->vsc_config->tag_len;
	saved_tag_len = current_tag_len;
	/*
	 * The device-private mirror is established only by feature negotiation.
	 * Do not emit a self-inconsistent image which import will correctly
	 * reject against the common negotiated-feature state.
	 */
	if (meta->op == VM_SNAPSHOT_SAVE &&
	    features != sc->vsc_vs.vs_negotiated_caps) {
		error = EINVAL;
		goto done;
	}

	SNAPSHOT_LE32_OR_LEAVE(magic, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(version, meta, error, done);
	if (magic != VT9P_SNAPSHOT_MAGIC ||
	    version != VT9P_SNAPSHOT_VERSION) {
		error = ENOTSUP;
		goto done;
	}
	SNAPSHOT_LE64_OR_LEAVE(features, meta, error, done);
	SNAPSHOT_LE64_OR_LEAVE(rootdev, meta, error, done);
	SNAPSHOT_LE64_OR_LEAVE(rootino, meta, error, done);
	SNAPSHOT_U8_OR_LEAVE(readonly, meta, error, done);
	SNAPSHOT_U8_OR_LEAVE(connection_version, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(msize, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(max_io_size, meta, error, done);
	SNAPSHOT_LE16_OR_LEAVE(saved_tag_len, meta, error, done);
	if (readonly > 1 || connection_version > L9P_2000L ||
	    msize == 0 || msize > VT9P_MAX_MSIZE ||
	    (connection_version == L9P_INVALID_VERSION ?
	    max_io_size != 0 :
	    (msize <= 24 || max_io_size != msize - 24)) ||
	    saved_tag_len > VT9P_MAXTAGSZ) {
		error = EINVAL;
		goto done;
	}
	if (meta->op == VM_SNAPSHOT_SAVE) {
		SNAPSHOT_BUF_OR_LEAVE(sc->vsc_config->tag, saved_tag_len,
		    meta, error, done);
	} else {
		SNAPSHOT_BUF_OR_LEAVE(saved_tag, saved_tag_len, meta, error,
		    done);
		if (saved_tag_len != current_tag_len ||
		    memcmp(saved_tag, sc->vsc_config->tag,
		    saved_tag_len) != 0) {
			error = EINVAL;
			goto done;
		}
	}
	error = vm_snapshot_identity_string(sc->vsc_rootpath,
	    VT9P_SNAPSHOT_STRING_MAX, meta);
	if (error != 0)
		goto done;
	if (vm_snapshot_is_loading(meta) &&
	    (features != sc->vsc_vs.vs_negotiated_caps ||
	    rootdev != (uint64_t)sc->vsc_rootdev ||
	    rootino != (uint64_t)sc->vsc_rootino ||
	    readonly != sc->vsc_readonly)) {
		error = EINVAL;
		goto done;
	}
	if (meta->op == VM_SNAPSHOT_RESTORE) {
		sc->vsc_features = features;
		sc->vsc_generation = restore_generation;
		sc->vsc_conn->lc_version = connection_version;
		sc->vsc_conn->lc_msize = msize;
		sc->vsc_conn->lc_max_io_size = max_io_size;
	}
	error = 0;
done:
	return (error);
}

/*
 * Preflight parses an untrusted restore record before the common restore
 * transaction is allowed to publish anything.  Serialize that parse with
 * lib9p completion/reset state, but do not take the commit-time pause path:
 * validation must be side-effect free with respect to the export backend.
 */
static int
pci_vt9p_snapshot_validate(struct vm_snapshot_meta *meta)
{
	struct pci_devinst *pi;
	struct pci_vt9p_softc *sc;
	int error;

	if (meta == NULL || meta->op != VM_SNAPSHOT_VALIDATE ||
	    meta->dev_data == NULL)
		return (EINVAL);
	pi = meta->dev_data;
	sc = pi->pi_arg;
	if (sc == NULL)
		return (EINVAL);

	pthread_mutex_lock(&sc->vsc_mtx);
	error = vi_pci_snapshot(meta);
	pthread_mutex_unlock(&sc->vsc_mtx);
	return (error);
}
#endif

static int
pci_vt9p_legacy_config(nvlist_t *nvl, const char *opts)
{
	char *sharename = NULL, *tofree, *token, *tokens;

	if (opts == NULL)
		return (0);

	tokens = tofree = strdup(opts);
	if (tokens == NULL)
		return (-1);
	while ((token = strsep(&tokens, ",")) != NULL) {
		if (strncmp(token, "transport=", sizeof("transport=") - 1) == 0) {
			set_config_value_node(nvl, "transport",
			    token + sizeof("transport=") - 1);
			continue;
		}
		if (strncmp(token, "packed=", sizeof("packed=") - 1) == 0) {
			set_config_value_node(nvl, "packed",
			    token + sizeof("packed=") - 1);
			continue;
		}
		if (strchr(token, '=') != NULL) {
			if (sharename != NULL) {
				EPRINTLN(
				    "virtio-9p: more than one share name given");
				free(tofree);
				return (-1);
			}

			sharename = strsep(&token, "=");
			set_config_value_node(nvl, "sharename", sharename);
			set_config_value_node(nvl, "path", token);
		} else
			set_config_bool_node(nvl, token, true);
	}
	free(tofree);
	return (0);
}

static int
pci_vt9p_confine_rootfd(int rootfd)
{
	int flags;

	/*
	 * lib9p resolves fid names relative to this descriptor.  Make the
	 * FreeBSD namei confinement sticky on the descriptor so that every
	 * later *at(2) operation inherits O_RESOLVE_BENEATH, including calls
	 * made by lib9p that do not carry the flag explicitly.  Capsicum
	 * limits the operations available through rootfd; this independently
	 * prevents an intermediate symlink or ".." lookup from escaping the
	 * exported subtree.
	 */
	flags = fcntl(rootfd, F_GETFD);
	if (flags < 0)
		return (-1);
	if (fcntl(rootfd, F_SETFD, flags | FD_RESOLVE_BENEATH) < 0)
		return (-1);
	return (0);
}

static void
pci_vt9p_root_cap_rights(cap_rights_t *rights, bool readonly)
{

	cap_rights_init(rights, CAP_LOOKUP, CAP_ACL_CHECK, CAP_ACL_GET,
	    CAP_READ, CAP_SEEK, CAP_FSTAT, CAP_PREAD, CAP_EXTATTR_GET,
	    CAP_EXTATTR_LIST, CAP_FSTATFS, CAP_FPATHCONF);
	if (!readonly) {
		cap_rights_set(rights, CAP_ACL_DELETE, CAP_ACL_SET, CAP_WRITE,
		    CAP_CREATE, CAP_FCHMODAT, CAP_FCHOWNAT, CAP_FTRUNCATE,
		    CAP_LINKAT_SOURCE, CAP_LINKAT_TARGET, CAP_MKDIRAT,
		    CAP_MKNODAT, CAP_PWRITE, CAP_RENAMEAT_SOURCE,
		    CAP_RENAMEAT_TARGET, CAP_SYMLINKAT, CAP_UNLINKAT,
		    CAP_EXTATTR_DELETE, CAP_EXTATTR_SET, CAP_FUTIMES,
		    CAP_FSYNC);
	}
}

static int
pci_vt9p_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct pci_vt9p_softc *sc;
	const char *value;
	const char *sharename;
	struct stat rootstat;
	pthread_condattr_t cond_attr;
	pthread_mutexattr_t mtx_attr;
	int rootfd;
	bool cond_attr_initialized;
	bool intr_initialized, mtx_attr_initialized, mtx_initialized;
	bool reset_cv_initialized;
	bool packed, ro;
	cap_rights_t rootcap;

	sc = NULL;
	intr_initialized = false;
	cond_attr_initialized = false;
	mtx_attr_initialized = false;
	mtx_initialized = false;
	reset_cv_initialized = false;
	ro = get_config_bool_node_default(nvl, "ro", false);
	sharename = get_config_value_node(nvl, "sharename");
	if (sharename == NULL) {
		EPRINTLN("virtio-9p: share name required");
		return (-1);
	}
	if (strlen(sharename) > VT9P_MAXTAGSZ) {
		EPRINTLN("virtio-9p: share name too long");
		return (-1);
	}
	value = get_config_value_node(nvl, "path");
	if (value == NULL) {
		EPRINTLN("virtio-9p: path required");
		return (-1);
	}
	rootfd = open(value, O_RDONLY | O_DIRECTORY);
	if (rootfd < 0) {
		EPRINTLN("virtio-9p: failed to open '%s': %s", value,
		    strerror(errno));
		return (-1);
	}
	if (fstat(rootfd, &rootstat) != 0)
		goto fail;
	if (pci_vt9p_confine_rootfd(rootfd) != 0) {
		EPRINTLN("virtio-9p: failed to confine '%s': %s", value,
		    strerror(errno));
		goto fail;
	}

	sc = calloc(1, sizeof(*sc));
	if (sc == NULL)
		goto fail;
	sc->vsc_rootpath = strdup(value);
	if (sc->vsc_rootpath == NULL)
		goto fail;
	sc->vsc_rootdev = rootstat.st_dev;
	sc->vsc_rootino = rootstat.st_ino;
	sc->vsc_readonly = ro;
	sc->vsc_config = calloc(1, sizeof(struct pci_vt9p_config) +
	    VT9P_MAXTAGSZ);
	if (sc->vsc_config == NULL)
		goto fail;
	if (pthread_mutexattr_init(&mtx_attr) != 0)
		goto fail;
	mtx_attr_initialized = true;
	if (pthread_mutexattr_settype(&mtx_attr,
	    PTHREAD_MUTEX_RECURSIVE) != 0)
		goto fail;
	if (pthread_mutex_init(&sc->vsc_mtx, &mtx_attr) != 0)
		goto fail;
	mtx_initialized = true;
	if (pthread_condattr_init(&cond_attr) != 0)
		goto fail;
	cond_attr_initialized = true;
	if (pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC) != 0 ||
	    pthread_cond_init(&sc->vsc_reset_cv, &cond_attr) != 0)
		goto fail;
	reset_cv_initialized = true;
	pthread_condattr_destroy(&cond_attr);
	cond_attr_initialized = false;
	pthread_mutexattr_destroy(&mtx_attr);
	mtx_attr_initialized = false;

	pci_vt9p_root_cap_rights(&rootcap, ro);

	if (cap_rights_limit(rootfd, &rootcap) != 0)
		goto fail;

	memcpy(&sc->vsc_consts, &vt9p_vi_consts, sizeof(sc->vsc_consts));
	vi_softc_linkup(&sc->vsc_vs, &sc->vsc_consts, sc, pi, &sc->vsc_vq);
	sc->vsc_vs.vs_mtx = &sc->vsc_mtx;
	sc->vsc_vq.vq_qsize = VT9P_RINGSZ;
	if (vi_pci_select_transport(&sc->vsc_vs, nvl,
	    VIRTIO_PCI_LEGACY_DEFAULT) != 0)
		goto fail;
	packed = get_config_bool_node_default(nvl, "packed", false);
	if (packed && !vi_pci_is_modern(&sc->vsc_vs)) {
		EPRINTLN("virtio-9p packed queues require transport=modern");
		goto fail;
	}
	if (packed)
		sc->vsc_consts.vc_hv_caps |= VIRTIO_F_RING_PACKED;
	pci_vt9p_set_tag(sc, sharename);

	if (vi_pci_is_modern(&sc->vsc_vs))
		vi_pci_modern_set_identity(&sc->vsc_vs, VIRTIO_ID_9P);
	else {
		pci_set_cfgdata16(pi, PCIR_DEVICE,
		    VIRTIO_PCI_TRANSITIONAL_9P);
		pci_set_cfgdata16(pi, PCIR_VENDOR, VIRTIO_VENDOR);
		pci_set_cfgdata16(pi, PCIR_SUBDEV_0, VIRTIO_ID_9P);
		pci_set_cfgdata16(pi, PCIR_SUBVEND_0, VIRTIO_VENDOR);
	}
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_STORAGE);

	if (vi_intr_init(&sc->vsc_vs, 1, fbsdrun_virtio_msix()))
		goto fail;
	intr_initialized = true;
	if (vi_pci_is_modern(&sc->vsc_vs)) {
		if (vi_pci_modern_init(&sc->vsc_vs, 2) != 0)
			goto fail;
	} else
		vi_set_io_bar(&sc->vsc_vs, 0);

	if (l9p_backend_fs_init(&sc->vsc_fs_backend, rootfd, ro) != 0) {
		errno = ENXIO;
		goto fail;
	}
	if (l9p_server_init(&sc->vsc_server, sc->vsc_fs_backend) != 0) {
		errno = ENXIO;
		goto fail;
	}

	if (l9p_connection_init(sc->vsc_server, &sc->vsc_conn) != 0) {
		errno = EIO;
		goto fail;
	}

	pci_vt9p_configure_connection(sc->vsc_conn);

	return (0);

fail:
	if (cond_attr_initialized)
		pthread_condattr_destroy(&cond_attr);
	if (mtx_attr_initialized)
		pthread_mutexattr_destroy(&mtx_attr);
	if (rootfd >= 0)
		close(rootfd);
	if (sc != NULL) {
		free(sc->vsc_vs.vs_modern);
		if (intr_initialized)
			pthread_mutex_destroy(&sc->vsc_vs.vs_isr_mtx);
		if (reset_cv_initialized)
			pthread_cond_destroy(&sc->vsc_reset_cv);
		if (mtx_initialized)
			pthread_mutex_destroy(&sc->vsc_mtx);
		free(sc->vsc_config);
		free(sc->vsc_rootpath);
		free(sc);
	}
	return (-1);
}

static const struct pci_devemu pci_de_v9p = {
	.pe_emu =	"virtio-9p",
	.pe_legacy_config = pci_vt9p_legacy_config,
	.pe_init =	pci_vt9p_init,
	.pe_cfgwrite =	vi_pci_modern_cfgwrite,
	.pe_cfgread =	vi_pci_modern_cfgread,
	.pe_barwrite =	vi_pci_write,
	.pe_barread =	vi_pci_read,
#ifdef BHYVE_SNAPSHOT
	.pe_snapshot =	vi_pci_snapshot,
	.pe_snapshot_validate = pci_vt9p_snapshot_validate,
	.pe_snapshot_compat = vi_pci_snapshot_compat,
	.pe_pause =	vi_pci_pause,
	.pe_resume =	vi_pci_resume,
#endif
};
PCI_EMUL_SET(pci_de_v9p);
