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

#include <sys/param.h>
#include <sys/linker_set.h>
#include <sys/uio.h>
#include <sys/capsicum.h>
#include <sys/endian.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <lib9p.h>
#include <backend/fs.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "pci_emul.h"
#include "virtio.h"

#define	VT9P_MAX_IOV	128
#define VT9P_RINGSZ	256
#define	VT9P_MAXTAGSZ	256
#define	VT9P_CONFIGSPACESZ	(VT9P_MAXTAGSZ + sizeof(uint16_t))
#define	VIRTIO_9P_F_MOUNT_TAG	(1ULL << 0)

static int pci_vt9p_debug;
#define DPRINTF(params) if (pci_vt9p_debug) printf params
#define WPRINTF(params) printf params

/*
 * Per-device softc
 */
struct pci_vt9p_softc {
	struct virtio_softc      vsc_vs;
	struct vqueue_info       vsc_vq;
	pthread_mutex_t          vsc_mtx;
	pthread_cond_t           vsc_reset_cv;
	uint64_t                 vsc_cfg;
	uint64_t                 vsc_features;
	char *                   vsc_rootpath;
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
	bool                     vsc_notify_pending;
};

struct pci_vt9p_request {
	struct pci_vt9p_softc *	vsr_sc;
	struct iovec		vsr_iov[VT9P_MAX_IOV];
	size_t			vsr_niov;
	size_t			vsr_respidx;
	size_t			vsr_iolen;
	uint16_t		vsr_idx;
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
static void pci_vt9p_set_tag(struct pci_vt9p_softc *, const char *);

static void
pci_vt9p_configure_connection(struct l9p_connection *conn)
{

	conn->lc_msize = L9P_MAX_IOV * PAGE_SIZE;
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
	.vc_hv_caps =	VIRTIO_9P_F_MOUNT_TAG | VIRTIO_F_RING_RESET,
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
	sc->vsc_notify_pending = false;
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
	sc->vsc_notify_pending = false;
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
	sc->vsc_notify_pending = false;
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
pci_vt9p_cfgread(void *vsc, int offset, int size, uint32_t *retval)
{
	struct pci_vt9p_softc *sc = vsc;
	void *ptr;

	if (offset < 0 || (size != 1 && size != 2 && size != 4) ||
	    (size_t)offset > VT9P_CONFIGSPACESZ ||
	    (size_t)size > VT9P_CONFIGSPACESZ - (size_t)offset)
		return (EINVAL);
	*retval = 0;
	ptr = (uint8_t *)sc->vsc_config + offset;
	memcpy(retval, ptr, size);
	return (0);
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
	}
	if (!sc->vsc_qreset_pending || sc->vsc_active_requests != 0)
		return (false);
	*reset_vq = sc->vsc_qreset_vq;
	*generation = sc->vsc_qreset_generation;
	sc->vsc_qreset_pending = false;
	sc->vsc_qreset_vq = NULL;
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
		vq_relchain(&sc->vsc_vq, preq->vsr_idx, preq->vsr_iolen);
		vq_endchains(&sc->vsc_vq, 1);
	}
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
		vq_relchain(&sc->vsc_vq, preq->vsr_idx, 0);
		vq_endchains(&sc->vsc_vq, 1);
	}
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
	int n;

	sc = vsc;
	if (sc->vsc_resetting || sc->vsc_queue_reset ||
	    sc->vsc_conn == NULL) {
		sc->vsc_notify_pending = true;
		return;
	}

	while (vq_has_descs(vq)) {
		n = vq_getchain(vq, iov, VT9P_MAX_IOV, &req);
		if (n <= 0)
			break;
		if (n > VT9P_MAX_IOV || !req.ordered || req.readable == 0 ||
		    req.writable == 0 || req.readable + req.writable != n) {
			DPRINTF(("vt9p: invalid descriptor chain\n"));
			vq_relchain(vq, req.idx, 0);
			continue;
		}
		preq = calloc(1, sizeof(*preq));
		if (preq == NULL) {
			WPRINTF(("vt9p: cannot allocate request\n"));
			vq_relchain(vq, req.idx, 0);
			continue;
		}
		preq->vsr_sc = sc;
		preq->vsr_idx = req.idx;
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
			vq_relchain(vq, preq->vsr_idx, 0);
			free(preq);
		}
	}
	vq_endchains(vq, 1);
}

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
pci_vt9p_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct pci_vt9p_softc *sc;
	const char *value;
	const char *sharename;
	pthread_mutexattr_t mtx_attr;
	int rootfd;
	bool intr_initialized, mtx_attr_initialized, mtx_initialized;
	bool reset_cv_initialized;
	bool ro;
	cap_rights_t rootcap;

	sc = NULL;
	intr_initialized = false;
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

	sc = calloc(1, sizeof(*sc));
	if (sc == NULL)
		goto fail;
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
	if (pthread_cond_init(&sc->vsc_reset_cv, NULL) != 0)
		goto fail;
	reset_cv_initialized = true;
	pthread_mutexattr_destroy(&mtx_attr);
	mtx_attr_initialized = false;

	cap_rights_init(&rootcap,
	    CAP_LOOKUP, CAP_ACL_CHECK, CAP_ACL_DELETE, CAP_ACL_GET,
	    CAP_ACL_SET, CAP_READ, CAP_WRITE, CAP_SEEK, CAP_FSTAT,
	    CAP_CREATE, CAP_FCHMODAT, CAP_FCHOWNAT, CAP_FTRUNCATE,
	    CAP_LINKAT_SOURCE, CAP_LINKAT_TARGET, CAP_MKDIRAT, CAP_MKNODAT,
	    CAP_PREAD, CAP_PWRITE, CAP_RENAMEAT_SOURCE, CAP_RENAMEAT_TARGET,
	    CAP_SEEK, CAP_SYMLINKAT, CAP_UNLINKAT, CAP_EXTATTR_DELETE,
	    CAP_EXTATTR_GET, CAP_EXTATTR_LIST, CAP_EXTATTR_SET,
	    CAP_FUTIMES, CAP_FSTATFS, CAP_FSYNC, CAP_FPATHCONF);

	if (cap_rights_limit(rootfd, &rootcap) != 0)
		goto fail;

	vi_softc_linkup(&sc->vsc_vs, &vt9p_vi_consts, sc, pi, &sc->vsc_vq);
	sc->vsc_vs.vs_mtx = &sc->vsc_mtx;
	sc->vsc_vq.vq_qsize = VT9P_RINGSZ;
	if (vi_pci_select_transport(&sc->vsc_vs, nvl,
	    VIRTIO_PCI_LEGACY_DEFAULT) != 0)
		goto fail;
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
};
PCI_EMUL_SET(pci_de_v9p);
