/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2016 Jakub Klama <jceel@FreeBSD.org>.
 * Copyright (c) 2018 Marcelo Araujo <araujo@FreeBSD.org>.
 * Copyright (c) 2026 Hans Rosenfeld
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

#include <sys/param.h>
#include <sys/linker_set.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/sbuf.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <pthread_np.h>

#include <cam/scsi/scsi_all.h>
#include <cam/scsi/scsi_message.h>
#include <cam/ctl/ctl.h>
#include <cam/ctl/ctl_io.h>
#include <cam/ctl/ctl_backend.h>
#include <cam/ctl/ctl_ioctl.h>
#include <cam/ctl/ctl_util.h>
#include <cam/ctl/ctl_scsi_all.h>
#include <camlib.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "pci_emul.h"
#include "virtio.h"
#include "iov.h"

#define VTSCSI_RINGSZ		64
#define	VTSCSI_DEFAULT_REQUESTQ	1
#define	VTSCSI_MAX_REQUESTQ	8
#define	VTSCSI_TOTAL_THR	16
#define	VTSCSI_MIN_THR_PER_Q	2
#define	VTSCSI_MAXQ		(VTSCSI_MAX_REQUESTQ + 2)
#define	VTSCSI_MAXSEG		64

#define	VTSCSI_IN_HEADER_LEN(_sc)	\
	(sizeof(struct pci_vtscsi_req_cmd_rd) + _sc->vss_config.cdb_size)

#define	VTSCSI_OUT_HEADER_LEN(_sc) 	\
	(sizeof(struct pci_vtscsi_req_cmd_wr) + _sc->vss_config.sense_size)

#define	VTSCSI_MAX_IN_HEADER_LEN		\
	(sizeof(struct pci_vtscsi_req_cmd_rd) + CTL_MAX_CDBLEN)
#define	VTSCSI_MAX_OUT_HEADER_LEN	\
	(sizeof(struct pci_vtscsi_req_cmd_wr) + SSD_FULL_SIZE)
#define	VTSCSI_MAX_SECTORS	\
	((UINT32_MAX - VTSCSI_MAX_OUT_HEADER_LEN) / 512)

#define	VIRTIO_SCSI_MAX_CHANNEL	0
#define	VIRTIO_SCSI_MAX_TARGET	0
#define	VIRTIO_SCSI_MAX_LUN	16383

#define	VIRTIO_SCSI_F_INOUT	(1 << 0)
#define	VIRTIO_SCSI_F_HOTPLUG	(1 << 1)
#define	VIRTIO_SCSI_F_CHANGE	(1 << 2)

static int pci_vtscsi_debug = 0;
#define	WPRINTF(msg, params...) PRINTLN("virtio-scsi: " msg, ##params)
#define	DPRINTF(msg, params...) if (pci_vtscsi_debug) WPRINTF(msg, ##params)

struct pci_vtscsi_config {
	uint32_t num_queues;
	uint32_t seg_max;
	uint32_t max_sectors;
	uint32_t cmd_per_lun;
	uint32_t event_info_size;
	uint32_t sense_size;
	uint32_t cdb_size;
	uint16_t max_channel;
	uint16_t max_target;
	uint32_t max_lun;
} __attribute__((packed));

/*
 * I/O request state and I/O request queues
 *
 * In addition to the control queue and notification queues, each virtio-scsi
 * device instance has at least one I/O request queue, the state of which is
 * is kept in an array of struct pci_vtscsi_queue in the device softc.
 *
 * Currently there is only one I/O request queue, but it's trivial to support
 * more than one.
 *
 * Each pci_vtscsi_queue has VTSCSI_RINGSZ pci_vtscsi_request structures pre-
 * allocated on vsq_free_requests. For each I/O request coming in on the I/O
 * virtqueue, the request queue handler will take a pci_vtscsi_request off
 * vsq_free_requests, fills in the data from the I/O virtqueue, puts it on
 * vsq_requests, and signals vsq_cv.
 *
 * A fixed device-wide worker budget is divided across the configured request
 * queues.  Workers wait on vsq_cv, repeatedly take a pci_vtscsi_request off
 * vsq_requests, construct a ctl_io for it, and hand it off to the CTL ioctl
 * interface, which processes it synchronously. After completion of the
 * request, the pci_vtscsi_request is re-initialized and put back onto
 * vsq_free_requests.
 *
 * The worker threads exit when vsq_cv is signalled after vsw_exiting was set.
 *
 * There are three mutexes to coordinate the accesses to an I/O request queue:
 * - vsq_rmtx protects vsq_requests and must be held when waiting on vsq_cv
 * - vsq_fmtx protects vsq_free_requests
 * - vsq_qmtx must be held when operating on the underlying virtqueue, vsq_vq
 */
STAILQ_HEAD(pci_vtscsi_req_queue, pci_vtscsi_request);

struct pci_vtscsi_queue {
	struct pci_vtscsi_softc *         vsq_sc;
	struct vqueue_info *              vsq_vq;
	pthread_mutex_t                   vsq_rmtx;
	pthread_mutex_t                   vsq_fmtx;
	pthread_mutex_t                   vsq_qmtx;
	pthread_cond_t                    vsq_cv;
	bool                              vsq_rmtx_initialized;
	bool                              vsq_fmtx_initialized;
	bool                              vsq_qmtx_initialized;
	bool                              vsq_cv_initialized;
	struct pci_vtscsi_req_queue       vsq_requests;
	struct pci_vtscsi_req_queue       vsq_free_requests;
	struct pci_vtscsi_worker *        vsq_workers;
	int                               vsq_nworkers;
	unsigned int                      vsq_active;
	bool                              vsq_quiescing;
};

struct pci_vtscsi_worker {
	struct pci_vtscsi_queue *     vsw_queue;
	pthread_t                     vsw_thread;
	bool                          vsw_exiting;
};

struct pci_vtscsi_request {
	struct pci_vtscsi_queue * vsr_queue;
	struct iovec              vsr_iov[VTSCSI_MAXSEG + SPLIT_IOV_ADDL_IOV];
	struct iovec *            vsr_iov_in;
	struct iovec *            vsr_iov_out;
	struct iovec *            vsr_data_iov_in;
	struct iovec *            vsr_data_iov_out;
	struct pci_vtscsi_req_cmd_rd * vsr_cmd_rd;
	struct pci_vtscsi_req_cmd_wr * vsr_cmd_wr;
	union ctl_io *            vsr_ctl_io;
	size_t                    vsr_niov_in;
	size_t                    vsr_niov_out;
	size_t                    vsr_data_niov_in;
	size_t                    vsr_data_niov_out;
	uint32_t                  vsr_idx;
	STAILQ_ENTRY(pci_vtscsi_request) vsr_link;
};

/*
 * Per-device softc
 */
struct pci_vtscsi_softc {
	struct virtio_softc      vss_vs;
	struct vqueue_info       vss_vq[VTSCSI_MAXQ];
	struct pci_vtscsi_queue  vss_queues[VTSCSI_MAX_REQUESTQ];
	pthread_mutex_t          vss_mtx;
	int                      vss_iid;
	int                      vss_ctl_fd;
	bool                     vss_mtx_initialized;
	uint16_t                 vss_nrequestq;
	uint32_t                 vss_features;
	struct pci_vtscsi_config vss_config;
	struct virtio_consts     vss_consts;
};

#define	VIRTIO_SCSI_T_TMF			0
#define	VIRTIO_SCSI_T_TMF_ABORT_TASK		0
#define	VIRTIO_SCSI_T_TMF_ABORT_TASK_SET	1
#define	VIRTIO_SCSI_T_TMF_CLEAR_ACA		2
#define	VIRTIO_SCSI_T_TMF_CLEAR_TASK_SET	3
#define	VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET	4
#define	VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET	5
#define	VIRTIO_SCSI_T_TMF_QUERY_TASK		6
#define	VIRTIO_SCSI_T_TMF_QUERY_TASK_SET 	7

/* command-specific response values */
#define	VIRTIO_SCSI_S_FUNCTION_COMPLETE		0
#define	VIRTIO_SCSI_S_FUNCTION_SUCCEEDED	10
#define	VIRTIO_SCSI_S_FUNCTION_REJECTED		11

struct pci_vtscsi_ctrl_tmf {
	const uint32_t type;
	const uint32_t subtype;
	const uint8_t lun[8];
	const uint64_t id;
	uint8_t response;
} __attribute__((packed));

#define	VIRTIO_SCSI_T_AN_QUERY			1
#define	VIRTIO_SCSI_EVT_ASYNC_OPERATIONAL_CHANGE 2
#define	VIRTIO_SCSI_EVT_ASYNC_POWER_MGMT	4
#define	VIRTIO_SCSI_EVT_ASYNC_EXTERNAL_REQUEST	8
#define	VIRTIO_SCSI_EVT_ASYNC_MEDIA_CHANGE	16
#define	VIRTIO_SCSI_EVT_ASYNC_MULTI_HOST	32
#define	VIRTIO_SCSI_EVT_ASYNC_DEVICE_BUSY	64

struct pci_vtscsi_ctrl_an {
	const uint32_t type;
	const uint8_t lun[8];
	const uint32_t event_requested;
	uint32_t event_actual;
	uint8_t response;
} __attribute__((packed));

/* command-specific response values */
#define	VIRTIO_SCSI_S_OK 			0
#define	VIRTIO_SCSI_S_OVERRUN			1
#define	VIRTIO_SCSI_S_ABORTED			2
#define	VIRTIO_SCSI_S_BAD_TARGET		3
#define	VIRTIO_SCSI_S_RESET			4
#define	VIRTIO_SCSI_S_BUSY			5
#define	VIRTIO_SCSI_S_TRANSPORT_FAILURE		6
#define	VIRTIO_SCSI_S_TARGET_FAILURE		7
#define	VIRTIO_SCSI_S_NEXUS_FAILURE		8
#define	VIRTIO_SCSI_S_FAILURE			9
#define	VIRTIO_SCSI_S_INCORRECT_LUN		12

/* task_attr */
#define	VIRTIO_SCSI_S_SIMPLE			0
#define	VIRTIO_SCSI_S_ORDERED			1
#define	VIRTIO_SCSI_S_HEAD			2
#define	VIRTIO_SCSI_S_ACA			3

struct pci_vtscsi_event {
	uint32_t event;
	uint8_t lun[8];
	uint32_t reason;
} __attribute__((packed));

struct pci_vtscsi_req_cmd_rd {
	const uint8_t lun[8];
	const uint64_t id;
	const uint8_t task_attr;
	const uint8_t prio;
	const uint8_t crn;
	const uint8_t cdb[];
} __attribute__((packed));

struct pci_vtscsi_req_cmd_wr {
	uint32_t sense_len;
	uint32_t residual;
	uint16_t status_qualifier;
	uint8_t status;
	uint8_t response;
	uint8_t sense[];
} __attribute__((packed));

static void *pci_vtscsi_proc(void *);
static void pci_vtscsi_reset(void *);
static int pci_vtscsi_qenable(void *, struct vqueue_info *);
static int pci_vtscsi_qreset(void *, struct vqueue_info *, uint64_t);
static void pci_vtscsi_neg_features(void *, uint64_t);
static int pci_vtscsi_cfgread(void *, int, int, uint32_t *);
static int pci_vtscsi_cfgwrite(void *, int, int, uint32_t);

static inline bool pci_vtscsi_check_lun(const uint8_t *);
static inline int pci_vtscsi_get_lun(const uint8_t *);

static size_t pci_vtscsi_control_handle(struct pci_vtscsi_softc *, void *,
    size_t, size_t);
static void pci_vtscsi_tmf_handle(struct pci_vtscsi_softc *,
    struct pci_vtscsi_ctrl_tmf *);
static uint8_t pci_vtscsi_tmf_response(uint8_t);
static bool pci_vtscsi_tmf_affects_commands(uint32_t);
static void pci_vtscsi_tmf_pause(struct pci_vtscsi_softc *);
static void pci_vtscsi_tmf_complete(struct pci_vtscsi_softc *, uint32_t,
    const uint8_t *, uint64_t);
static void pci_vtscsi_an_handle(struct pci_vtscsi_softc *,
    struct pci_vtscsi_ctrl_an *);

static struct pci_vtscsi_request *pci_vtscsi_alloc_request(
    struct pci_vtscsi_softc *);
static void pci_vtscsi_free_request(struct pci_vtscsi_request *);
static struct pci_vtscsi_request *pci_vtscsi_get_request(
    struct pci_vtscsi_req_queue *);
static void pci_vtscsi_put_request(struct pci_vtscsi_req_queue *,
    struct pci_vtscsi_request *);
static bool pci_vtscsi_queue_request(struct pci_vtscsi_softc *,
    struct vqueue_info *);
static void pci_vtscsi_recycle_request(struct pci_vtscsi_queue *,
    struct pci_vtscsi_request *);
static void pci_vtscsi_quiesce_queue(struct pci_vtscsi_queue *, bool);
static void pci_vtscsi_resume_queue(struct pci_vtscsi_queue *);
static void pci_vtscsi_return_request(struct pci_vtscsi_queue *,
    struct pci_vtscsi_request *, uint32_t);
static uint32_t pci_vtscsi_request_handle(struct pci_vtscsi_softc *,
    struct pci_vtscsi_request *);

static void pci_vtscsi_controlq_notify(void *, struct vqueue_info *);
static void pci_vtscsi_eventq_notify(void *, struct vqueue_info *);
static void pci_vtscsi_requestq_notify(void *, struct vqueue_info *);
static int  pci_vtscsi_init_queue(struct pci_vtscsi_softc *,
    struct pci_vtscsi_queue *, int);
static void pci_vtscsi_destroy_queue(struct pci_vtscsi_queue *);
static int pci_vtscsi_init(struct pci_devinst *, nvlist_t *);

static struct virtio_consts vtscsi_vi_consts = {
	.vc_name =	"vtscsi",
	.vc_nvq =	VTSCSI_DEFAULT_REQUESTQ + 2,
	.vc_cfgsize =	sizeof(struct pci_vtscsi_config),
	.vc_reset =	pci_vtscsi_reset,
	.vc_cfgread =	pci_vtscsi_cfgread,
	.vc_cfgwrite =	pci_vtscsi_cfgwrite,
	.vc_apply_features = pci_vtscsi_neg_features,
	.vc_qenable =	pci_vtscsi_qenable,
	.vc_qreset =	pci_vtscsi_qreset,
	.vc_hv_caps =	VIRTIO_RING_F_INDIRECT_DESC | VIRTIO_F_RING_RESET,
};

/*
 * Modern VirtIO fields are little-endian.  The legacy PCI interface retains
 * guest-native byte order, which is host-native for bhyve's virtual machine.
 */
static uint32_t
pci_vtscsi_decode32(const struct pci_vtscsi_softc *sc, uint32_t value)
{

	return (vi_pci_is_modern(&sc->vss_vs) ? le32toh(value) : value);
}

static uint64_t
pci_vtscsi_decode64(const struct pci_vtscsi_softc *sc, uint64_t value)
{

	return (vi_pci_is_modern(&sc->vss_vs) ? le64toh(value) : value);
}

static uint32_t
pci_vtscsi_encode32(const struct pci_vtscsi_softc *sc, uint32_t value)
{

	return (vi_pci_is_modern(&sc->vss_vs) ? htole32(value) : value);
}

static uint16_t
pci_vtscsi_encode16(const struct pci_vtscsi_softc *sc, uint16_t value)
{

	return (vi_pci_is_modern(&sc->vss_vs) ? htole16(value) : value);
}

static void *
pci_vtscsi_proc(void *arg)
{
	struct pci_vtscsi_worker *worker = (struct pci_vtscsi_worker *)arg;
	struct pci_vtscsi_queue *q = worker->vsw_queue;
	struct pci_vtscsi_softc *sc = q->vsq_sc;
	uint32_t iolen;

	for (;;) {
		struct pci_vtscsi_request *req;

		pthread_mutex_lock(&q->vsq_rmtx);

		while ((STAILQ_EMPTY(&q->vsq_requests) || q->vsq_quiescing) &&
		    !worker->vsw_exiting)
			pthread_cond_wait(&q->vsq_cv, &q->vsq_rmtx);

		if (worker->vsw_exiting) {
			pthread_mutex_unlock(&q->vsq_rmtx);
			return (NULL);
		}

		req = pci_vtscsi_get_request(&q->vsq_requests);
		if (req != NULL)
			q->vsq_active++;
		pthread_mutex_unlock(&q->vsq_rmtx);
		if (req == NULL)
			continue;

		DPRINTF("I/O request lun %d, data_niov_in %zu, data_niov_out "
		    "%zu", pci_vtscsi_get_lun(req->vsr_cmd_rd->lun),
		    req->vsr_data_niov_in, req->vsr_data_niov_out);

		iolen = pci_vtscsi_request_handle(sc, req);

		pci_vtscsi_return_request(q, req, iolen);

		pthread_mutex_lock(&q->vsq_rmtx);
		q->vsq_active--;
		if (q->vsq_active == 0)
			pthread_cond_broadcast(&q->vsq_cv);
		pthread_mutex_unlock(&q->vsq_rmtx);
	}
}

static void
pci_vtscsi_reset(void *vsc)
{
	struct pci_vtscsi_softc *sc;

	sc = vsc;

	DPRINTF("device reset requested");
	for (int i = 0; i < sc->vss_nrequestq; i++)
		pci_vtscsi_quiesce_queue(&sc->vss_queues[i], true);
	vi_reset_dev(&sc->vss_vs);
	for (int i = 0; i < sc->vss_nrequestq; i++)
		pci_vtscsi_resume_queue(&sc->vss_queues[i]);
	sc->vss_features = 0;

	/* initialize config structure */
	sc->vss_config = (struct pci_vtscsi_config){
		.num_queues = sc->vss_nrequestq,
		/* Leave room for the request and the response. */
		.seg_max = VTSCSI_MAXSEG - 2,
		/*
		 * ext_data_len and the used-ring length are 32-bit values.
		 * Advertise the largest whole-sector transfer which always
		 * leaves room for the maximum response header.
		 */
		.max_sectors = VTSCSI_MAX_SECTORS,
		/*
		 * The worker pool bounds device-wide synchronous CTL calls.
		 * Permit one LUN to use that concurrency instead of causing
		 * multiqueue guests to serialize every command at queue depth 1.
		 */
		.cmd_per_lun = VTSCSI_TOTAL_THR,
		.event_info_size = sizeof(struct pci_vtscsi_event),
		.sense_size = 96,
		.cdb_size = 32,
		.max_channel = VIRTIO_SCSI_MAX_CHANNEL,
		.max_target = VIRTIO_SCSI_MAX_TARGET,
		.max_lun = VIRTIO_SCSI_MAX_LUN
	};
}

static int
pci_vtscsi_qenable(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtscsi_softc *sc;

	sc = vsc;
	if (vq->vq_num >= sc->vss_nrequestq + 2 ||
	    vq != &sc->vss_vq[vq->vq_num])
		return (EINVAL);
	if (vq->vq_num >= 2)
		pci_vtscsi_resume_queue(&sc->vss_queues[vq->vq_num - 2]);
	return (0);
}

static int
pci_vtscsi_qreset(void *vsc, struct vqueue_info *vq,
    uint64_t generation __unused)
{
	struct pci_vtscsi_softc *sc;

	sc = vsc;
	if (vq->vq_num >= sc->vss_nrequestq + 2 ||
	    vq != &sc->vss_vq[vq->vq_num])
		return (EINVAL);

	/*
	 * Control and event commands execute synchronously under vss_mtx.
	 * A request queue has independent workers: quiescing waits for active
	 * CTL calls to publish their results and recycles requests which have
	 * left the available ring but have not started.  Leave it quiesced
	 * until the replacement queue is enabled.
	 */
	if (vq->vq_num >= 2)
		pci_vtscsi_quiesce_queue(&sc->vss_queues[vq->vq_num - 2],
		    false);
	return (0);
}

static void
pci_vtscsi_neg_features(void *vsc, uint64_t negotiated_features)
{
	struct pci_vtscsi_softc *sc = vsc;

	sc->vss_features = negotiated_features;
}

static int
pci_vtscsi_cfgread(void *vsc, int offset, int size, uint32_t *retval)
{
	struct pci_vtscsi_softc *sc = vsc;
	struct pci_vtscsi_config wire;
	void *ptr;

	*retval = 0;
	if (offset < 0 || (size != 1 && size != 2 && size != 4) ||
	    (size_t)offset > sizeof(sc->vss_config) ||
	    (size_t)size > sizeof(sc->vss_config) - (size_t)offset)
		return (EINVAL);
	wire = sc->vss_config;
	wire.num_queues = pci_vtscsi_encode32(sc, wire.num_queues);
	wire.seg_max = pci_vtscsi_encode32(sc, wire.seg_max);
	wire.max_sectors = pci_vtscsi_encode32(sc, wire.max_sectors);
	wire.cmd_per_lun = pci_vtscsi_encode32(sc, wire.cmd_per_lun);
	wire.event_info_size =
	    pci_vtscsi_encode32(sc, wire.event_info_size);
	wire.sense_size = pci_vtscsi_encode32(sc, wire.sense_size);
	wire.cdb_size = pci_vtscsi_encode32(sc, wire.cdb_size);
	wire.max_channel = pci_vtscsi_encode16(sc, wire.max_channel);
	wire.max_target = pci_vtscsi_encode16(sc, wire.max_target);
	wire.max_lun = pci_vtscsi_encode32(sc, wire.max_lun);
	ptr = (uint8_t *)&wire + offset;
	memcpy(retval, ptr, size);
	return (0);
}

static int
pci_vtscsi_cfgwrite(void *vsc, int offset, int size, uint32_t val)
{
	struct pci_vtscsi_softc *sc = vsc;

	/* Device-specific setup is complete once the driver becomes active. */
	if (size != sizeof(uint32_t) ||
	    (sc->vss_vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0)
		return (1);
	val = pci_vtscsi_decode32(sc, val);

	switch (offset) {
	case offsetof(struct pci_vtscsi_config, sense_size):
		if (val > SSD_FULL_SIZE)
			return (1);
		sc->vss_config.sense_size = val;
		return (0);
	case offsetof(struct pci_vtscsi_config, cdb_size):
		if (val == 0 || val > CTL_MAX_CDBLEN)
			return (1);
		sc->vss_config.cdb_size = val;
		return (0);
	default:
		return (1);
	}
}

/*
 * LUN address parsing
 *
 * The LUN address consists of 8 bytes. While the spec describes this as 0x01,
 * followed by the target byte, followed by a "single-level LUN structure",
 * this is actually the same as a hierarchical LUN address as defined by SAM-5,
 * consisting of four levels of addressing, where in each level the two MSB of
 * byte 0 select the address mode used in the remaining bits and bytes.
 *
 *
 * Only the first two levels are actually used by virtio-scsi:
 *
 * Level 1: 0x01, 0xTT: Peripheral Device Addressing: Bus 1, Target 0-255
 * Level 2: 0xLL, 0xLL: Peripheral Device Addressing: Bus MBZ, LUN 0-255
 *                  or: Flat Space Addressing: LUN (0-16383)
 * Level 3 and 4: not used, MBZ
 *
 * Currently, we only support Target 0.
 *
 * Alternatively, the first level may contain an extended LUN address to select
 * the REPORT_LUNS well-known logical unit:
 *
 * Level 1: 0xC1, 0x01: Extended LUN Adressing, Well-Known LUN 1 (REPORT_LUNS)
 * Level 2, 3, and 4: not used, MBZ
 *
 * The virtio spec says that we SHOULD implement the REPORT_LUNS well-known
 * logical unit  but we currently don't.
 *
 * According to the virtio spec, these are the only LUNS address formats to be
 * used with virtio-scsi.
 */

/*
 * Check that the given LUN address conforms to the virtio spec, does not
 * address an unknown target, and especially does not address the REPORT_LUNS
 * well-known logical unit.
 */
static inline bool
pci_vtscsi_check_lun(const uint8_t *lun)
{
	if (lun[0] == 0xC1)
		return (false);

	if (lun[0] != 0x01)
		return (false);

	if (lun[1] != 0x00)
		return (false);

	if (lun[2] != 0x00 && (lun[2] & 0xc0) != 0x40)
		return (false);

	if (lun[4] != 0 || lun[5] != 0 || lun[6] != 0 || lun[7] != 0)
		return (false);

	return (true);
}

/*
 * Get the LUN id from a LUN address.
 *
 * Every code path using this function must have called pci_vtscsi_check_lun()
 * before to make sure the LUN address is valid.
 */
static inline int
pci_vtscsi_get_lun(const uint8_t *lun)
{
	assert(lun[0] == 0x01);
	assert(lun[1] == 0x00);
	assert(lun[2] == 0x00 || (lun[2] & 0xc0) == 0x40);

	return (((lun[2] << 8) | lun[3]) & 0x3fff);
}

static size_t
pci_vtscsi_control_handle(struct pci_vtscsi_softc *sc, void *buf,
    size_t insize, size_t outsize)
{
	struct pci_vtscsi_ctrl_tmf *tmf;
	struct pci_vtscsi_ctrl_an *an;
	uint32_t type;

	if (insize < sizeof(type)) {
		WPRINTF("ignoring truncated control request");
		return (0);
	}

	memcpy(&type, buf, sizeof(type));
	type = pci_vtscsi_decode32(sc, type);

	if (type == VIRTIO_SCSI_T_TMF) {
		if (insize != offsetof(struct pci_vtscsi_ctrl_tmf, response) ||
		    outsize < sizeof(tmf->response)) {
			WPRINTF("ignoring tmf request with sizes %zu/%zu", insize,
			    outsize);
			goto failure;
		}
		tmf = (struct pci_vtscsi_ctrl_tmf *)buf;
		pci_vtscsi_tmf_handle(sc, tmf);
		memmove(buf, &tmf->response, sizeof(tmf->response));
		return (sizeof(tmf->response));
	} else if (type == VIRTIO_SCSI_T_AN_QUERY) {
		if (insize != offsetof(struct pci_vtscsi_ctrl_an, event_actual) ||
		    outsize < sizeof(an->event_actual) + sizeof(an->response)) {
			WPRINTF("ignoring AN request with sizes %zu/%zu", insize,
			    outsize);
			goto failure;
		}
		an = (struct pci_vtscsi_ctrl_an *)buf;
		pci_vtscsi_an_handle(sc, an);
		memmove(buf, &an->event_actual,
		    sizeof(an->event_actual) + sizeof(an->response));
		return (sizeof(an->event_actual) + sizeof(an->response));
	}

	WPRINTF("ignoring unknown control request type %u", type);
failure:
	if (outsize == 0)
		return (0);
	*(uint8_t *)buf = VIRTIO_SCSI_S_FAILURE;
	return (1);
}

static void
pci_vtscsi_tmf_handle(struct pci_vtscsi_softc *sc,
    struct pci_vtscsi_ctrl_tmf *tmf)
{
	union ctl_io *io;
	uint32_t subtype;
	uint8_t response;
	uint64_t id;
	bool paused;
	int err;

	if (pci_vtscsi_check_lun(tmf->lun) == false) {
		DPRINTF("TMF request to invalid LUN %.2hhx%.2hhx-%.2hhx%.2hhx-"
		    "%.2hhx%.2hhx-%.2hhx%.2hhx", tmf->lun[0], tmf->lun[1],
		    tmf->lun[2], tmf->lun[3], tmf->lun[4], tmf->lun[5],
		    tmf->lun[6], tmf->lun[7]);

		tmf->response = VIRTIO_SCSI_S_BAD_TARGET;
		return;
	}

	io = ctl_scsi_alloc_io(sc->vss_iid);
	if (io == NULL) {
		WPRINTF("failed to allocate ctl_io: err=%d (%s)",
		    errno, strerror(errno));

		tmf->response = VIRTIO_SCSI_S_FAILURE;
		return;
	}

	ctl_scsi_zero_io(io);
	subtype = pci_vtscsi_decode32(sc, tmf->subtype);
	id = pci_vtscsi_decode64(sc, tmf->id);

	io->io_hdr.io_type = CTL_IO_TASK;
	io->io_hdr.nexus.initid = sc->vss_iid;
	io->io_hdr.nexus.targ_lun = pci_vtscsi_get_lun(tmf->lun);
	io->taskio.tag_type = CTL_TAG_SIMPLE;
	io->taskio.tag_num = id;
	io->io_hdr.flags |= CTL_FLAG_USER_TAG;

	switch (subtype) {
	case VIRTIO_SCSI_T_TMF_ABORT_TASK:
		io->taskio.task_action = CTL_TASK_ABORT_TASK;
		break;

	case VIRTIO_SCSI_T_TMF_ABORT_TASK_SET:
		io->taskio.task_action = CTL_TASK_ABORT_TASK_SET;
		break;

	case VIRTIO_SCSI_T_TMF_CLEAR_ACA:
		io->taskio.task_action = CTL_TASK_CLEAR_ACA;
		break;

	case VIRTIO_SCSI_T_TMF_CLEAR_TASK_SET:
		io->taskio.task_action = CTL_TASK_CLEAR_TASK_SET;
		break;

	case VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET:
		io->taskio.task_action = CTL_TASK_I_T_NEXUS_RESET;
		break;

	case VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET:
		io->taskio.task_action = CTL_TASK_LUN_RESET;
		break;

	case VIRTIO_SCSI_T_TMF_QUERY_TASK:
		io->taskio.task_action = CTL_TASK_QUERY_TASK;
		break;

	case VIRTIO_SCSI_T_TMF_QUERY_TASK_SET:
		io->taskio.task_action = CTL_TASK_QUERY_TASK_SET;
		break;
	default:
		tmf->response = VIRTIO_SCSI_S_FUNCTION_REJECTED;
		ctl_scsi_free_io(io);
		return;
	}
	paused = pci_vtscsi_tmf_affects_commands(subtype);
	if (paused)
		pci_vtscsi_tmf_pause(sc);

	if (pci_vtscsi_debug) {
		struct sbuf *sb = sbuf_new_auto();
		ctl_io_sbuf(io, sb);
		sbuf_finish(sb);
		DPRINTF("%s", sbuf_data(sb));
		sbuf_delete(sb);
	}

	err = ioctl(sc->vss_ctl_fd, CTL_IO, io);
	if (err != 0) {
		WPRINTF("CTL_IO: err=%d (%s)", errno, strerror(errno));
		response = VIRTIO_SCSI_S_FAILURE;
	} else
		response = pci_vtscsi_tmf_response(io->taskio.task_status);
	if (paused) {
		if (response == VIRTIO_SCSI_S_FUNCTION_COMPLETE ||
		    response == VIRTIO_SCSI_S_FUNCTION_SUCCEEDED)
			pci_vtscsi_tmf_complete(sc, subtype, tmf->lun, id);
		for (int i = 0; i < sc->vss_nrequestq; i++)
			pci_vtscsi_resume_queue(&sc->vss_queues[i]);
	}
	tmf->response = response;
	ctl_scsi_free_io(io);
}

static uint8_t
pci_vtscsi_tmf_response(uint8_t status)
{

	switch (status) {
	case CTL_TASK_FUNCTION_COMPLETE:
		return (VIRTIO_SCSI_S_FUNCTION_COMPLETE);
	case CTL_TASK_FUNCTION_SUCCEEDED:
		return (VIRTIO_SCSI_S_FUNCTION_SUCCEEDED);
	case CTL_TASK_FUNCTION_REJECTED:
	case CTL_TASK_FUNCTION_NOT_SUPPORTED:
		return (VIRTIO_SCSI_S_FUNCTION_REJECTED);
	case CTL_TASK_LUN_DOES_NOT_EXIST:
		return (VIRTIO_SCSI_S_BAD_TARGET);
	default:
		return (VIRTIO_SCSI_S_FAILURE);
	}
}

static bool
pci_vtscsi_tmf_affects_commands(uint32_t subtype)
{

	return (subtype == VIRTIO_SCSI_T_TMF_ABORT_TASK ||
	    subtype == VIRTIO_SCSI_T_TMF_ABORT_TASK_SET ||
	    subtype == VIRTIO_SCSI_T_TMF_CLEAR_TASK_SET ||
	    subtype == VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET ||
	    subtype == VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET);
}

static void
pci_vtscsi_tmf_pause(struct pci_vtscsi_softc *sc)
{
	struct pci_vtscsi_queue *q;

	for (int i = 0; i < sc->vss_nrequestq; i++) {
		q = &sc->vss_queues[i];
		if (q->vsq_sc == NULL)
			continue;
		pthread_mutex_lock(&q->vsq_rmtx);
		q->vsq_quiescing = true;
		pthread_mutex_unlock(&q->vsq_rmtx);
	}
}

static bool
pci_vtscsi_tmf_matches(struct pci_vtscsi_softc *sc,
    struct pci_vtscsi_request *req, uint32_t subtype, const uint8_t *lun,
    uint64_t id)
{

	if (subtype == VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET)
		return (true);
	if (memcmp(req->vsr_cmd_rd->lun, lun, sizeof(req->vsr_cmd_rd->lun)) != 0)
		return (false);
	if (subtype == VIRTIO_SCSI_T_TMF_ABORT_TASK)
		return (pci_vtscsi_decode64(sc, req->vsr_cmd_rd->id) == id);
	return (true);
}

/*
 * CTL has completed the active commands affected by the TMF.  Wait until the
 * worker threads have published those completions, then complete commands
 * which bhyve had consumed from the available ring but had not submitted to
 * CTL.  The controlq response is published only after this function returns.
 */
static void
pci_vtscsi_tmf_complete(struct pci_vtscsi_softc *sc, uint32_t subtype,
    const uint8_t *lun, uint64_t id)
{
	struct pci_vtscsi_req_queue keep;
	struct pci_vtscsi_request *req;
	struct pci_vtscsi_queue *q;
	uint8_t response;

	response = subtype == VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET ||
	    subtype == VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET ?
	    VIRTIO_SCSI_S_RESET : VIRTIO_SCSI_S_ABORTED;
	for (int i = 0; i < sc->vss_nrequestq; i++) {
		q = &sc->vss_queues[i];
		if (q->vsq_sc == NULL)
			continue;
		STAILQ_INIT(&keep);
		pthread_mutex_lock(&q->vsq_rmtx);
		while (q->vsq_active != 0)
			pthread_cond_wait(&q->vsq_cv, &q->vsq_rmtx);
		while ((req = pci_vtscsi_get_request(&q->vsq_requests)) != NULL) {
			if (!pci_vtscsi_tmf_matches(sc, req, subtype, lun, id)) {
				pci_vtscsi_put_request(&keep, req);
				continue;
			}
			req->vsr_cmd_wr->response = response;
			pci_vtscsi_return_request(q, req, 0);
		}
		STAILQ_CONCAT(&q->vsq_requests, &keep);
		pthread_mutex_unlock(&q->vsq_rmtx);
	}
}

static void
pci_vtscsi_an_handle(struct pci_vtscsi_softc *sc __unused,
    struct pci_vtscsi_ctrl_an *an __unused)
{
}

static struct pci_vtscsi_request *
pci_vtscsi_alloc_request(struct pci_vtscsi_softc *sc)
{
	struct pci_vtscsi_request *req;

	req = calloc(1, sizeof(struct pci_vtscsi_request));
	if (req == NULL)
		goto fail;

	req->vsr_cmd_rd = calloc(1, VTSCSI_MAX_IN_HEADER_LEN);
	if (req->vsr_cmd_rd == NULL)
		goto fail;
	req->vsr_cmd_wr = calloc(1, VTSCSI_MAX_OUT_HEADER_LEN);
	if (req->vsr_cmd_wr == NULL)
		goto fail;

	req->vsr_ctl_io = ctl_scsi_alloc_io(sc->vss_iid);
	if (req->vsr_ctl_io == NULL)
		goto fail;
	ctl_scsi_zero_io(req->vsr_ctl_io);

	return (req);

fail:
	EPRINTLN("failed to allocate request: %s", strerror(errno));

	if (req != NULL)
		pci_vtscsi_free_request(req);

	return (NULL);
}

static void
pci_vtscsi_free_request(struct pci_vtscsi_request *req)
{
	if (req->vsr_ctl_io != NULL)
		ctl_scsi_free_io(req->vsr_ctl_io);
	if (req->vsr_cmd_rd != NULL)
		free(req->vsr_cmd_rd);
	if (req->vsr_cmd_wr != NULL)
		free(req->vsr_cmd_wr);

	free(req);
}

static struct pci_vtscsi_request *
pci_vtscsi_get_request(struct pci_vtscsi_req_queue *req_queue)
{
	struct pci_vtscsi_request *req;

	if (STAILQ_EMPTY(req_queue))
		return (NULL);

	req = STAILQ_FIRST(req_queue);
	STAILQ_REMOVE_HEAD(req_queue, vsr_link);

	return (req);
}

static void
pci_vtscsi_put_request(struct pci_vtscsi_req_queue *req_queue,
    struct pci_vtscsi_request *req)
{
	STAILQ_INSERT_TAIL(req_queue, req, vsr_link);
}

static bool
pci_vtscsi_queue_request(struct pci_vtscsi_softc *sc, struct vqueue_info *vq)
{
	struct pci_vtscsi_queue *q = &sc->vss_queues[vq->vq_num - 2];
	struct pci_vtscsi_request *req;
	struct vi_req vireq;
	size_t off;
	int n;

	pthread_mutex_lock(&q->vsq_fmtx);
	req = pci_vtscsi_get_request(&q->vsq_free_requests);
	pthread_mutex_unlock(&q->vsq_fmtx);
	if (req == NULL) {
		WPRINTF("request queue has no free request objects");
		return (false);
	}

	n = vq_getchain(vq, req->vsr_iov, VTSCSI_MAXSEG, &vireq);
	if (n <= 0) {
		pci_vtscsi_recycle_request(q, req);
		return (false);
	}
	if (n > VTSCSI_MAXSEG || !vireq.ordered || vireq.readable < 1 ||
	    vireq.writable < 1 || vireq.readable + vireq.writable != n) {
		WPRINTF("ignoring invalid request descriptor chain");
		req->vsr_idx = vireq.idx;
		req->vsr_queue = q;
		pci_vtscsi_return_request(q, req, 0);
		return (true);
	}

	req->vsr_idx = vireq.idx;
	req->vsr_queue = q;
	req->vsr_iov_in = &req->vsr_iov[0];
	req->vsr_niov_in = vireq.readable;
	req->vsr_iov_out = &req->vsr_iov[vireq.readable];
	req->vsr_niov_out = vireq.writable;

	/*
	 * Make sure we got at least enough space for the VirtIO-SCSI
	 * command headers. If not, return this request immediately.
	 */
	if (check_iov_len(req->vsr_iov_out, req->vsr_niov_out,
	    VTSCSI_OUT_HEADER_LEN(q->vsq_sc)) == false) {
		WPRINTF("ignoring request with insufficient output");
		req->vsr_cmd_wr->response = VIRTIO_SCSI_S_FAILURE;
		pci_vtscsi_return_request(q, req, 0);
		return (true);
	}

	if (check_iov_len(req->vsr_iov_in, req->vsr_niov_in,
	    VTSCSI_IN_HEADER_LEN(q->vsq_sc)) == false) {
		WPRINTF("ignoring request with incomplete header");
		req->vsr_cmd_wr->response = VIRTIO_SCSI_S_FAILURE;
		pci_vtscsi_return_request(q, req, 0);
		return (true);
	}

	/*
	 * We have to split the iovec array into a header and data portion each
	 * for input and output.
	 *
	 * We need to start with the output section (at the end of iov) in case
	 * the iovec covering the final part of the output header needs to be
	 * split, in which case split_iov() will move all reamaining iovecs up
	 * by one to make room for a new iovec covering the first part of the
	 * output data portion.
	 */
	(void)split_iov(req->vsr_iov_out, &req->vsr_niov_out,
	    VTSCSI_OUT_HEADER_LEN(q->vsq_sc), &req->vsr_data_niov_out);

	/*
	 * Similarly, to not overwrite the first iovec of the output section,
	 * the 2nd call to split_iov() to split the input section must actually
	 * cover the entire iovec array (both input and the already split output
	 * sections).
	 */
	req->vsr_niov_in += req->vsr_niov_out + req->vsr_data_niov_out;

	(void)split_iov(req->vsr_iov_in, &req->vsr_niov_in,
	    VTSCSI_IN_HEADER_LEN(q->vsq_sc), &req->vsr_data_niov_in);

	/*
	 * And of course we now have to adjust data_niov_in accordingly.
	 */
	req->vsr_data_niov_in -= req->vsr_niov_out + req->vsr_data_niov_out;

	/*
	 * Either split may have moved later entries to make room.  Recompute
	 * every section pointer from the final layout instead of retaining a
	 * pointer returned before the second split.
	 */
	req->vsr_data_iov_in = req->vsr_data_niov_in == 0 ? NULL :
	    &req->vsr_iov[req->vsr_niov_in];
	req->vsr_iov_out = &req->vsr_iov[req->vsr_niov_in +
	    req->vsr_data_niov_in];
	req->vsr_data_iov_out = req->vsr_data_niov_out == 0 ? NULL :
	    &req->vsr_iov_out[req->vsr_niov_out];

	/* Copy the split request header into its fixed-size staging buffer. */
	off = 0;
	for (size_t i = 0; i < req->vsr_niov_in; i++) {
		memcpy((uint8_t *)req->vsr_cmd_rd + off,
		    req->vsr_iov_in[i].iov_base, req->vsr_iov_in[i].iov_len);
		off += req->vsr_iov_in[i].iov_len;
	}

	/* Make sure this request addresses a valid LUN. */
	if (pci_vtscsi_check_lun(req->vsr_cmd_rd->lun) == false) {
		DPRINTF("I/O request to invalid LUN "
		    "%.2hhx%.2hhx-%.2hhx%.2hhx-%.2hhx%.2hhx-%.2hhx%.2hhx",
		    req->vsr_cmd_rd->lun[0], req->vsr_cmd_rd->lun[1],
		    req->vsr_cmd_rd->lun[2], req->vsr_cmd_rd->lun[3],
		    req->vsr_cmd_rd->lun[4], req->vsr_cmd_rd->lun[5],
		    req->vsr_cmd_rd->lun[6], req->vsr_cmd_rd->lun[7]);
		req->vsr_cmd_wr->response = VIRTIO_SCSI_S_BAD_TARGET;
		pci_vtscsi_return_request(q, req, 0);
		return (true);
	}

	pthread_mutex_lock(&q->vsq_rmtx);
	pci_vtscsi_put_request(&q->vsq_requests, req);
	pthread_cond_signal(&q->vsq_cv);
	pthread_mutex_unlock(&q->vsq_rmtx);

	DPRINTF("request <idx=%d> enqueued", vireq.idx);
	return (true);
}

static void
pci_vtscsi_recycle_request(struct pci_vtscsi_queue *q,
    struct pci_vtscsi_request *req)
{
	void *cmd_rd = req->vsr_cmd_rd;
	void *cmd_wr = req->vsr_cmd_wr;
	void *ctl_io = req->vsr_ctl_io;

	ctl_scsi_zero_io(req->vsr_ctl_io);
	memset(cmd_rd, 0, VTSCSI_MAX_IN_HEADER_LEN);
	memset(cmd_wr, 0, VTSCSI_MAX_OUT_HEADER_LEN);
	memset(req, 0, sizeof(*req));
	req->vsr_cmd_rd = cmd_rd;
	req->vsr_cmd_wr = cmd_wr;
	req->vsr_ctl_io = ctl_io;

	pthread_mutex_lock(&q->vsq_fmtx);
	pci_vtscsi_put_request(&q->vsq_free_requests, req);
	pthread_mutex_unlock(&q->vsq_fmtx);
}

/*
 * A reset must not complete while a worker can still publish a used-ring
 * entry.  Stop workers from taking more requests and wait for requests
 * already submitted to CTL to complete.  A full device reset completes
 * requests which were consumed from the available ring but not yet submitted
 * with VIRTIO_SCSI_S_RESET, as required by VirtIO 1.4 section 5.6.6.1.1.
 * A selective queue reset instead discards them because the old queue
 * incarnation must not receive further used entries or notifications.
 */
static void
pci_vtscsi_quiesce_queue(struct pci_vtscsi_queue *q, bool complete)
{
	struct pci_vtscsi_request *req;

	/* The initial device reset runs before request queues are initialized. */
	if (q->vsq_sc == NULL)
		return;

	pthread_mutex_lock(&q->vsq_rmtx);
	q->vsq_quiescing = true;
	while (q->vsq_active != 0)
		pthread_cond_wait(&q->vsq_cv, &q->vsq_rmtx);
	while ((req = pci_vtscsi_get_request(&q->vsq_requests)) != NULL) {
		if (complete) {
			req->vsr_cmd_wr->response = VIRTIO_SCSI_S_RESET;
			pci_vtscsi_return_request(q, req, 0);
		} else
			pci_vtscsi_recycle_request(q, req);
	}
	pthread_mutex_unlock(&q->vsq_rmtx);
}

static void
pci_vtscsi_resume_queue(struct pci_vtscsi_queue *q)
{

	if (q->vsq_sc == NULL)
		return;

	pthread_mutex_lock(&q->vsq_rmtx);
	q->vsq_quiescing = false;
	pthread_cond_broadcast(&q->vsq_cv);
	pthread_mutex_unlock(&q->vsq_rmtx);
}

static void
pci_vtscsi_return_request(struct pci_vtscsi_queue *q,
    struct pci_vtscsi_request *req, uint32_t iolen)
{
	int idx = req->vsr_idx;

	DPRINTF("request <idx=%d> completed, response %d", idx,
	    req->vsr_cmd_wr->response);

	iolen += buf_to_iov(req->vsr_cmd_wr, VTSCSI_OUT_HEADER_LEN(q->vsq_sc),
	    req->vsr_iov_out, req->vsr_niov_out);
	pci_vtscsi_recycle_request(q, req);

	pthread_mutex_lock(&q->vsq_qmtx);
	vq_relchain(q->vsq_vq, idx, iolen);
	vq_endchains(q->vsq_vq, 0);
	pthread_mutex_unlock(&q->vsq_qmtx);
}

/*
 * CTL_IO returning from ioctl(2) only means that the command reached CTL.
 * Translate CTL's command and frontend transport status separately.  A SCSI
 * error is a completed command: its SCSI status and sense data are returned
 * with VIRTIO_SCSI_S_OK.  Other CTL failures must not be presented to the
 * guest as a completed SCSI command.
 */
static uint8_t
pci_vtscsi_request_response(const union ctl_io *io, uint32_t data_len)
{
	ctl_io_status status;

	if (io->io_hdr.port_status != 0)
		return (VIRTIO_SCSI_S_TRANSPORT_FAILURE);

	status = io->io_hdr.status & CTL_STATUS_MASK;
	switch (status) {
	case CTL_SUCCESS:
	case CTL_SCSI_ERROR:
		if (io->scsiio.ext_data_filled > data_len)
			return (VIRTIO_SCSI_S_OVERRUN);
		return (VIRTIO_SCSI_S_OK);
	case CTL_SEL_TIMEOUT:
		return (VIRTIO_SCSI_S_TRANSPORT_FAILURE);
	case CTL_CMD_ABORTED:
		return (VIRTIO_SCSI_S_ABORTED);
	case CTL_STATUS_NONE:
	case CTL_CMD_TIMEOUT:
	case CTL_ERROR:
	case CTL_NVME_ERROR:
	default:
		return (VIRTIO_SCSI_S_FAILURE);
	}
}

static uint32_t
pci_vtscsi_request_handle(struct pci_vtscsi_softc *sc,
    struct pci_vtscsi_request *req)
{
	union ctl_io *io = req->vsr_ctl_io;
	void *ext_data_ptr = NULL;
	size_t data_len;
	uint32_t ext_data_len = 0, ext_sg_entries = 0;
	uint32_t nxferred;
	int err;

	if (req->vsr_data_niov_in != 0 && req->vsr_data_niov_out != 0 &&
	    (sc->vss_features & VIRTIO_SCSI_F_INOUT) == 0) {
		req->vsr_cmd_wr->response = VIRTIO_SCSI_S_FAILURE;
		return (0);
	}

	if (req->vsr_data_niov_in > 0) {
		ext_data_ptr = (void *)req->vsr_data_iov_in;
		ext_sg_entries = req->vsr_data_niov_in;
		data_len = count_iov(req->vsr_data_iov_in,
		    req->vsr_data_niov_in);
		if (data_len > UINT32_MAX - VTSCSI_OUT_HEADER_LEN(sc)) {
			req->vsr_cmd_wr->response = VIRTIO_SCSI_S_FAILURE;
			return (0);
		}
		ext_data_len = data_len;
	} else if (req->vsr_data_niov_out > 0) {
		ext_data_ptr = (void *)req->vsr_data_iov_out;
		ext_sg_entries = req->vsr_data_niov_out;
		data_len = count_iov(req->vsr_data_iov_out,
		    req->vsr_data_niov_out);
		if (data_len > UINT32_MAX - VTSCSI_OUT_HEADER_LEN(sc)) {
			req->vsr_cmd_wr->response = VIRTIO_SCSI_S_FAILURE;
			return (0);
		}
		ext_data_len = data_len;
	}

	io->io_hdr.nexus.initid = sc->vss_iid;
	io->io_hdr.nexus.targ_lun = pci_vtscsi_get_lun(req->vsr_cmd_rd->lun);
	io->io_hdr.io_type = CTL_IO_SCSI;
	if (req->vsr_data_niov_in > 0)
		io->io_hdr.flags |= CTL_FLAG_DATA_OUT;
	else if (req->vsr_data_niov_out > 0)
		io->io_hdr.flags |= CTL_FLAG_DATA_IN;

	io->scsiio.sense_len = sc->vss_config.sense_size;
	io->scsiio.tag_num =
	    pci_vtscsi_decode64(sc, req->vsr_cmd_rd->id);
	io->io_hdr.flags |= CTL_FLAG_USER_TAG;
	switch (req->vsr_cmd_rd->task_attr) {
	case VIRTIO_SCSI_S_ORDERED:
		io->scsiio.tag_type = CTL_TAG_ORDERED;
		break;
	case VIRTIO_SCSI_S_HEAD:
		io->scsiio.tag_type = CTL_TAG_HEAD_OF_QUEUE;
		break;
	case VIRTIO_SCSI_S_ACA:
		io->scsiio.tag_type = CTL_TAG_ACA;
		break;
	case VIRTIO_SCSI_S_SIMPLE:
	default:
		io->scsiio.tag_type = CTL_TAG_SIMPLE;
		break;
	}
	io->scsiio.ext_sg_entries = ext_sg_entries;
	io->scsiio.ext_data_ptr = ext_data_ptr;
	io->scsiio.ext_data_len = ext_data_len;
	io->scsiio.ext_data_filled = 0;
	io->scsiio.cdb_len = sc->vss_config.cdb_size;
	memcpy(io->scsiio.cdb, req->vsr_cmd_rd->cdb, sc->vss_config.cdb_size);
	DPRINTF("submit opcode=0x%02x flags=0x%x readable=%zu writable=%zu "
	    "data_len=%u sg=%u", io->scsiio.cdb[0], io->io_hdr.flags,
	    req->vsr_data_niov_in, req->vsr_data_niov_out, ext_data_len,
	    ext_sg_entries);
	if (pci_vtscsi_debug && ext_sg_entries != 0) {
		const struct iovec *first = ext_data_ptr;

		if (first->iov_len >= 4) {
			const uint8_t *data = first->iov_base;

			DPRINTF("pre-io data bytes=%02x%02x%02x%02x len=%zu",
			    data[0], data[1], data[2], data[3], first->iov_len);
		}
	}

	if (pci_vtscsi_debug) {
		struct sbuf *sb = sbuf_new_auto();
		ctl_io_sbuf(io, sb);
		sbuf_finish(sb);
		DPRINTF("%s", sbuf_data(sb));
		sbuf_delete(sb);
	}

	err = ioctl(sc->vss_ctl_fd, CTL_IO, io);
	if (pci_vtscsi_debug && ext_sg_entries != 0 &&
	    (io->io_hdr.flags & CTL_FLAG_DATA_MASK) == CTL_FLAG_DATA_IN) {
		const struct iovec *first = ext_data_ptr;

		if (first->iov_len >= 4) {
			const uint8_t *data = first->iov_base;

			DPRINTF("post-io data bytes=%02x%02x%02x%02x len=%zu",
			    data[0], data[1], data[2], data[3], first->iov_len);
		}
	}
	DPRINTF("complete opcode=0x%02x ioctl=%d ctl_status=0x%x "
	    "port_status=%u scsi_status=0x%x filled=%u/%u",
	    io->scsiio.cdb[0], err, io->io_hdr.status,
	    io->io_hdr.port_status, io->scsiio.scsi_status,
	    io->scsiio.ext_data_filled, ext_data_len);
	if (err != 0) {
		WPRINTF("CTL_IO: err=%d (%s)", errno, strerror(errno));
		req->vsr_cmd_wr->response = VIRTIO_SCSI_S_FAILURE;
	} else {
		req->vsr_cmd_wr->response =
		    pci_vtscsi_request_response(io, ext_data_len);
		if (io->scsiio.ext_data_filled > ext_data_len) {
			req->vsr_cmd_wr->residual =
			    pci_vtscsi_encode32(sc, 0);
		} else {
			req->vsr_cmd_wr->residual = pci_vtscsi_encode32(sc,
			    ext_data_len - io->scsiio.ext_data_filled);
		}
		req->vsr_cmd_wr->status = io->scsiio.scsi_status;
		if ((io->io_hdr.status & CTL_STATUS_MASK) == CTL_SCSI_ERROR) {
			req->vsr_cmd_wr->sense_len = pci_vtscsi_encode32(sc,
			    MIN(io->scsiio.sense_len,
			    sc->vss_config.sense_size));
			memcpy(&req->vsr_cmd_wr->sense, &io->scsiio.sense_data,
			    MIN(io->scsiio.sense_len,
			    sc->vss_config.sense_size));
		}
	}

	/*
	 * The used-ring length counts bytes written by the device.  DATA OUT is
	 * readable by the device, so only its response header is counted by the
	 * caller.  DATA IN is writable by the device and must also include the
	 * transferred payload.
	 */
	if ((io->io_hdr.flags & CTL_FLAG_DATA_MASK) == CTL_FLAG_DATA_IN)
		nxferred = MIN(io->scsiio.ext_data_filled, ext_data_len);
	else
		nxferred = 0;
	return (nxferred);
}

static void
pci_vtscsi_controlq_notify(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtscsi_softc *sc;
	struct iovec iov[VTSCSI_MAXSEG];
	struct vi_req req;
	union {
		struct pci_vtscsi_ctrl_tmf tmf;
		struct pci_vtscsi_ctrl_an an;
	} buf;
	size_t insize, outsize, off, written;
	int n;

	sc = vsc;

	while (vq_has_descs(vq)) {
		n = vq_getchain(vq, iov, VTSCSI_MAXSEG, &req);
		if (n <= 0)
			break;
		if (n > VTSCSI_MAXSEG || !req.ordered || req.readable < 1 ||
		    req.writable < 1 || req.readable + req.writable != n) {
			WPRINTF("ignoring invalid control descriptor chain");
			vq_relchain(vq, req.idx, 0);
			continue;
		}

		insize = count_iov(iov, req.readable);
		outsize = count_iov(&iov[req.readable], req.writable);
		if (insize > sizeof(buf)) {
			WPRINTF("ignoring oversized control request");
			vq_relchain(vq, req.idx, 0);
			continue;
		}
		memset(&buf, 0, sizeof(buf));
		off = 0;
		for (int i = 0; i < req.readable; i++) {
			memcpy((uint8_t *)&buf + off, iov[i].iov_base,
			    iov[i].iov_len);
			off += iov[i].iov_len;
		}
		written = pci_vtscsi_control_handle(sc, &buf, insize,
		    outsize);
		written = buf_to_iov(&buf, written, &iov[req.readable],
		    req.writable);

		/*
		 * Release this chain and handle more
		 */
		vq_relchain(vq, req.idx, written);
	}
	vq_endchains(vq, 1);	/* Generate interrupt if appropriate. */
}

static void
pci_vtscsi_eventq_notify(void *vsc __unused, struct vqueue_info *vq)
{
	vq_kick_disable(vq);
}

static void
pci_vtscsi_requestq_notify(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtscsi_softc *sc;

	sc = vsc;
	if (vq->vq_num < 2 || vq->vq_num >= sc->vss_nrequestq + 2 ||
	    vq != &sc->vss_vq[vq->vq_num])
		return;
	while (vq_has_descs(vq)) {
		if (!pci_vtscsi_queue_request(sc, vq))
			break;
	}
}

static int
pci_vtscsi_init_queue(struct pci_vtscsi_softc *sc,
    struct pci_vtscsi_queue *queue, int num)
{
	char tname[MAXCOMLEN + 1];
	int error, i, nworkers;

	if (sc->vss_nrequestq < 1 ||
	    sc->vss_nrequestq > VTSCSI_MAX_REQUESTQ ||
	    num < 0 || num >= sc->vss_nrequestq)
		return (-1);

	queue->vsq_sc = sc;
	queue->vsq_vq = &sc->vss_vq[num + 2];
	STAILQ_INIT(&queue->vsq_requests);
	STAILQ_INIT(&queue->vsq_free_requests);

	error = pthread_mutex_init(&queue->vsq_rmtx, NULL);
	if (error != 0)
		goto fail;
	queue->vsq_rmtx_initialized = true;
	error = pthread_mutex_init(&queue->vsq_fmtx, NULL);
	if (error != 0)
		goto fail;
	queue->vsq_fmtx_initialized = true;
	error = pthread_mutex_init(&queue->vsq_qmtx, NULL);
	if (error != 0)
		goto fail;
	queue->vsq_qmtx_initialized = true;
	error = pthread_cond_init(&queue->vsq_cv, NULL);
	if (error != 0)
		goto fail;
	queue->vsq_cv_initialized = true;

	for (i = 0; i < VTSCSI_RINGSZ; i++) {
		struct pci_vtscsi_request *req;

		req = pci_vtscsi_alloc_request(sc);
		if (req == NULL)
			goto fail;

		pci_vtscsi_put_request(&queue->vsq_free_requests, req);
	}

	nworkers = MAX(VTSCSI_MIN_THR_PER_Q,
	    VTSCSI_TOTAL_THR / sc->vss_nrequestq);
	queue->vsq_workers = calloc(nworkers,
	    sizeof(struct pci_vtscsi_worker));
	if (queue->vsq_workers == NULL)
		goto fail;

	for (i = 0; i < nworkers; i++) {
		queue->vsq_workers[i].vsw_queue = queue;

		error = pthread_create(&queue->vsq_workers[i].vsw_thread, NULL,
		    &pci_vtscsi_proc, &queue->vsq_workers[i]);
		if (error != 0) {
			WPRINTF("failed to create request worker: %s",
			    strerror(error));
			goto fail;
		}
		queue->vsq_nworkers++;

		snprintf(tname, sizeof(tname), "vtscsi:%d-%d", num, i);
		pthread_set_name_np(queue->vsq_workers[i].vsw_thread, tname);
	}

	return (0);

fail:
	pci_vtscsi_destroy_queue(queue);

	return (-1);

}

static void
pci_vtscsi_destroy_queue(struct pci_vtscsi_queue *queue)
{
	if (queue->vsq_sc == NULL)
		return;

	if (queue->vsq_nworkers != 0) {
		pthread_mutex_lock(&queue->vsq_rmtx);
		for (int i = 0; i < queue->vsq_nworkers; i++)
			queue->vsq_workers[i].vsw_exiting = true;
		pthread_cond_broadcast(&queue->vsq_cv);
		pthread_mutex_unlock(&queue->vsq_rmtx);

		for (int i = 0; i < queue->vsq_nworkers; i++)
			pthread_join(queue->vsq_workers[i].vsw_thread, NULL);
	}
	free(queue->vsq_workers);
	queue->vsq_workers = NULL;
	queue->vsq_nworkers = 0;

	for (int i = VTSCSI_RINGSZ; i > 0; i--) {
		struct pci_vtscsi_request *req;

		if (STAILQ_EMPTY(&queue->vsq_free_requests))
			break;

		req = pci_vtscsi_get_request(&queue->vsq_free_requests);
		pci_vtscsi_free_request(req);
	}

	if (queue->vsq_cv_initialized) {
		pthread_cond_destroy(&queue->vsq_cv);
		queue->vsq_cv_initialized = false;
	}
	if (queue->vsq_qmtx_initialized) {
		pthread_mutex_destroy(&queue->vsq_qmtx);
		queue->vsq_qmtx_initialized = false;
	}
	if (queue->vsq_fmtx_initialized) {
		pthread_mutex_destroy(&queue->vsq_fmtx);
		queue->vsq_fmtx_initialized = false;
	}
	if (queue->vsq_rmtx_initialized) {
		pthread_mutex_destroy(&queue->vsq_rmtx);
		queue->vsq_rmtx_initialized = false;
	}
	queue->vsq_sc = NULL;
}

static int
pci_vtscsi_legacy_config(nvlist_t *nvl, const char *opts)
{
	char *cp, *devname;

	if (opts == NULL)
		return (0);

	cp = strchr(opts, ',');
	if (cp == NULL) {
		set_config_value_node(nvl, "dev", opts);
		return (0);
	}
	devname = strndup(opts, cp - opts);
	set_config_value_node(nvl, "dev", devname);
	free(devname);
	return (pci_parse_legacy_config(nvl, cp + 1));
}

static int
pci_vtscsi_parse_queues(const char *value, uint16_t *nrequestq,
    const char **errstr)
{
	long parsed;

	*errstr = NULL;
	if (value == NULL) {
		*nrequestq = VTSCSI_DEFAULT_REQUESTQ;
		return (0);
	}
	parsed = strtonum(value, 1, VTSCSI_MAX_REQUESTQ, errstr);
	if (*errstr != NULL)
		return (EINVAL);
	*nrequestq = (uint16_t)parsed;
	return (0);
}

static int
pci_vtscsi_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct pci_vtscsi_softc *sc;
	bool intr_initialized;
	const char *devname, *errstr, *value;
	uint16_t nrequestq;
	int err;
	int i;

	value = getenv("BHYVE_VTSCSI_DEBUG");
	if (value != NULL) {
		pci_vtscsi_debug = atoi(value);
		if (pci_vtscsi_debug < 1)
			pci_vtscsi_debug = 1;
	}

	value = get_config_value_node(nvl, "queues");
	if (pci_vtscsi_parse_queues(value, &nrequestq, &errstr) != 0) {
		EPRINTLN("virtio-scsi queues is %s: %s", errstr, value);
		return (-1);
	}

	sc = calloc(1, sizeof(struct pci_vtscsi_softc));
	if (sc == NULL)
		return (-1);
	intr_initialized = false;
	sc->vss_ctl_fd = -1;
	sc->vss_nrequestq = nrequestq;
	sc->vss_consts = vtscsi_vi_consts;
	sc->vss_consts.vc_nvq = sc->vss_nrequestq + 2;

	value = get_config_value_node(nvl, "iid");
	if (value != NULL)
		sc->vss_iid = strtoul(value, NULL, 10);

	value = get_config_value_node(nvl, "bootindex");
	if (value != NULL) {
		if (pci_emul_add_boot_device(pi, atoi(value))) {
			EPRINTLN("Invalid bootindex %d", atoi(value));
			goto fail;
		}
	}

	devname = get_config_value_node(nvl, "dev");
	if (devname == NULL)
		devname = "/dev/cam/ctl";
	sc->vss_ctl_fd = open(devname, O_RDWR);
	if (sc->vss_ctl_fd < 0) {
		WPRINTF("cannot open %s: %s", devname, strerror(errno));
		goto fail;
	}

	if (pthread_mutex_init(&sc->vss_mtx, NULL) != 0)
		goto fail;
	sc->vss_mtx_initialized = true;

	vi_softc_linkup(&sc->vss_vs, &sc->vss_consts, sc, pi, sc->vss_vq);
	sc->vss_vs.vs_mtx = &sc->vss_mtx;

	/* controlq */
	sc->vss_vq[0].vq_qsize = VTSCSI_RINGSZ;
	sc->vss_vq[0].vq_notify = pci_vtscsi_controlq_notify;

	/* eventq */
	sc->vss_vq[1].vq_qsize = VTSCSI_RINGSZ;
	sc->vss_vq[1].vq_notify = pci_vtscsi_eventq_notify;

	/* request queues */
	for (i = 2; i < sc->vss_nrequestq + 2; i++) {
		sc->vss_vq[i].vq_qsize = VTSCSI_RINGSZ;
		sc->vss_vq[i].vq_notify = pci_vtscsi_requestq_notify;
	}
	if (vi_pci_select_transport(&sc->vss_vs, nvl,
	    VIRTIO_PCI_LEGACY_DEFAULT) != 0)
		goto fail;
	if (sc->vss_nrequestq > 1 && !vi_pci_is_modern(&sc->vss_vs)) {
		EPRINTLN("virtio-scsi queues requires transport=modern");
		goto fail;
	}

	/* initialize config space */
	if (vi_pci_is_modern(&sc->vss_vs))
		vi_pci_modern_set_identity(&sc->vss_vs, VIRTIO_ID_SCSI);
	else {
		pci_set_cfgdata16(pi, PCIR_DEVICE,
		    VIRTIO_PCI_TRANSITIONAL_SCSI);
		pci_set_cfgdata16(pi, PCIR_VENDOR, VIRTIO_VENDOR);
		pci_set_cfgdata16(pi, PCIR_SUBDEV_0, VIRTIO_ID_SCSI);
		pci_set_cfgdata16(pi, PCIR_SUBVEND_0, VIRTIO_VENDOR);
	}
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_STORAGE);

	if (vi_intr_init(&sc->vss_vs, 1, fbsdrun_virtio_msix()))
		goto fail;
	intr_initialized = true;
	if (vi_pci_is_modern(&sc->vss_vs)) {
		if (vi_pci_modern_init(&sc->vss_vs, 2) != 0)
			goto fail;
	} else
		vi_set_io_bar(&sc->vss_vs, 0);

	/*
	 * Establish the default configuration only after vi_intr_init() has
	 * initialized the ISR mutex used by vi_reset_dev().  The request workers
	 * need these sizes, so reset before allocating any of their requests.
	 */
	pthread_mutex_lock(&sc->vss_mtx);
	pci_vtscsi_reset(sc);
	pthread_mutex_unlock(&sc->vss_mtx);

	/* Start workers only after every fallible PCI transport operation. */
	for (i = 2; i < sc->vss_nrequestq + 2; i++) {
		err = pci_vtscsi_init_queue(sc, &sc->vss_queues[i - 2], i - 2);
		if (err != 0)
			goto fail;
	}

	return (0);

fail:
	for (i = 2; i < sc->vss_nrequestq + 2; i++)
		pci_vtscsi_destroy_queue(&sc->vss_queues[i - 2]);

	if (sc->vss_ctl_fd >= 0)
		close(sc->vss_ctl_fd);
	free(sc->vss_vs.vs_modern);
	if (intr_initialized)
		pthread_mutex_destroy(&sc->vss_vs.vs_isr_mtx);
	if (sc->vss_mtx_initialized)
		pthread_mutex_destroy(&sc->vss_mtx);

	free(sc);
	return (-1);
}


static const struct pci_devemu pci_de_vscsi = {
	.pe_emu =	"virtio-scsi",
	.pe_init =	pci_vtscsi_init,
	.pe_legacy_config = pci_vtscsi_legacy_config,
	.pe_cfgwrite =	vi_pci_modern_cfgwrite,
	.pe_cfgread =	vi_pci_modern_cfgread,
	.pe_barwrite =	vi_pci_write,
	.pe_barread =	vi_pci_read
};
PCI_EMUL_SET(pci_de_vscsi);
