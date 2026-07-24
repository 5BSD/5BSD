/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Fault-injection tests for bhyve's VirtIO SCSI device.
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_1_4_spec.h"
#include "virtio_1_4_wire.h"
#include "pci_virtio_scsi.c"
#include "iov.c"

/* Test-side command and response values come from VirtIO 1.4. */
#undef VIRTIO_SCSI_T_TMF
#define	VIRTIO_SCSI_T_TMF		VIRTIO14_SCSI_T_TMF
#undef VIRTIO_SCSI_T_TMF_ABORT_TASK
#define	VIRTIO_SCSI_T_TMF_ABORT_TASK	VIRTIO14_SCSI_T_TMF_ABORT_TASK
#undef VIRTIO_SCSI_T_AN_QUERY
#define	VIRTIO_SCSI_T_AN_QUERY		VIRTIO14_SCSI_T_AN_QUERY
#undef VIRTIO_SCSI_S_FUNCTION_COMPLETE
#define	VIRTIO_SCSI_S_FUNCTION_COMPLETE \
	VIRTIO14_SCSI_S_FUNCTION_COMPLETE
#undef VIRTIO_SCSI_S_FUNCTION_SUCCEEDED
#define	VIRTIO_SCSI_S_FUNCTION_SUCCEEDED \
	VIRTIO14_SCSI_S_FUNCTION_SUCCEEDED
#undef VIRTIO_SCSI_S_FUNCTION_REJECTED
#define	VIRTIO_SCSI_S_FUNCTION_REJECTED \
	VIRTIO14_SCSI_S_FUNCTION_REJECTED
#undef VIRTIO_SCSI_S_OK
#define	VIRTIO_SCSI_S_OK		VIRTIO14_SCSI_S_OK
#undef VIRTIO_SCSI_S_OVERRUN
#define	VIRTIO_SCSI_S_OVERRUN		VIRTIO14_SCSI_S_OVERRUN
#undef VIRTIO_SCSI_S_ABORTED
#define	VIRTIO_SCSI_S_ABORTED		VIRTIO14_SCSI_S_ABORTED
#undef VIRTIO_SCSI_S_BAD_TARGET
#define	VIRTIO_SCSI_S_BAD_TARGET	VIRTIO14_SCSI_S_BAD_TARGET
#undef VIRTIO_SCSI_S_RESET
#define	VIRTIO_SCSI_S_RESET		VIRTIO14_SCSI_S_RESET
#undef VIRTIO_SCSI_S_TRANSPORT_FAILURE
#define	VIRTIO_SCSI_S_TRANSPORT_FAILURE \
	VIRTIO14_SCSI_S_TRANSPORT_FAILURE
#undef VIRTIO_SCSI_S_FAILURE
#define	VIRTIO_SCSI_S_FAILURE		VIRTIO14_SCSI_S_FAILURE
#undef VIRTIO_CONFIG_STATUS_DRIVER_OK
#define	VIRTIO_CONFIG_STATUS_DRIVER_OK	VIRTIO14_STATUS_DRIVER_OK
#undef VIRTIO_F_RING_RESET
#define	VIRTIO_F_RING_RESET		VIRTIO14_F_RING_RESET

#define MOCK_MAX_IOV 70

struct mock_chain {
	int n;
	struct vi_req req;
	struct iovec iov[MOCK_MAX_IOV];
};

static struct mock_chain g_chain;
static int g_chain_ready;
static int g_rel_calls;
static uint16_t g_rel_idx;
static uint32_t g_rel_len;
static int g_end_calls;
static int g_ctl_allocs;
static int g_ctl_frees;
static union ctl_io g_ctl_io;
static int g_mutex_init_calls;
static int g_mutex_init_fail_at;
static int g_cond_init_calls;
static int g_cond_init_fail_at;

int __real_pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);
int __real_pthread_cond_init(pthread_cond_t *, const pthread_condattr_t *);
int __wrap_pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);
int __wrap_pthread_cond_init(pthread_cond_t *, const pthread_condattr_t *);

int
__wrap_pthread_mutex_init(pthread_mutex_t *mutex,
    const pthread_mutexattr_t *attr)
{

	g_mutex_init_calls++;
	if (g_mutex_init_fail_at != 0 &&
	    g_mutex_init_calls == g_mutex_init_fail_at)
		return (EAGAIN);
	return (__real_pthread_mutex_init(mutex, attr));
}

int
__wrap_pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr)
{

	g_cond_init_calls++;
	if (g_cond_init_fail_at != 0 &&
	    g_cond_init_calls == g_cond_init_fail_at)
		return (EAGAIN);
	return (__real_pthread_cond_init(cond, attr));
}

static void
reset_mocks(void)
{

	memset(&g_chain, 0, sizeof(g_chain));
	memset(&g_ctl_io, 0, sizeof(g_ctl_io));
	g_chain_ready = 0;
	g_rel_calls = 0;
	g_rel_idx = 0;
	g_rel_len = UINT32_MAX;
	g_end_calls = 0;
	g_ctl_allocs = 0;
	g_ctl_frees = 0;
	g_mutex_init_calls = 0;
	g_mutex_init_fail_at = 0;
	g_cond_init_calls = 0;
	g_cond_init_fail_at = 0;
}

static void
set_chain(int n, int readable, int writable, bool ordered)
{

	g_chain.n = n;
	g_chain.req.idx = 7;
	g_chain.req.readable = readable;
	g_chain.req.writable = writable;
	g_chain.req.ordered = ordered;
	g_chain_ready = 1;
}

int
vq_has_descs(struct vqueue_info *vq __unused)
{

	return (g_chain_ready);
}

int
vq_getchain(struct vqueue_info *vq __unused, struct iovec *iov, int niov,
    struct vi_req *req)
{
	int copied;

	if (!g_chain_ready)
		return (0);
	g_chain_ready = 0;
	*req = g_chain.req;
	if (g_chain.n > 0) {
		copied = MIN(g_chain.n, niov);
		memcpy(iov, g_chain.iov, copied * sizeof(iov[0]));
	}
	return (g_chain.n);
}

void
vq_relchain(struct vqueue_info *vq __unused, uint16_t idx, uint32_t len)
{

	g_rel_calls++;
	g_rel_idx = idx;
	g_rel_len = len;
}

void
vq_endchains(struct vqueue_info *vq __unused, int used_all __unused)
{

	g_end_calls++;
}

void
vi_reset_dev(struct virtio_softc *vs __unused)
{
}

bool
vi_pci_is_modern(const struct virtio_softc *vs)
{

	return (vs->vs_transport == VIRTIO_PCI_TRANSPORT_MODERN);
}

union ctl_io *
ctl_scsi_alloc_io(uint32_t initid __unused)
{

	g_ctl_allocs++;
	memset(&g_ctl_io, 0, sizeof(g_ctl_io));
	return (&g_ctl_io);
}

void
ctl_scsi_free_io(union ctl_io *io __unused)
{

	g_ctl_frees++;
}

void
ctl_scsi_zero_io(union ctl_io *io)
{

	memset(io, 0, sizeof(*io));
}

void
ctl_io_sbuf(union ctl_io *io __unused, struct sbuf *sb __unused)
{
}

static void
setup_queue(struct pci_vtscsi_softc *sc, struct pci_vtscsi_request *req,
    uint8_t *cmd_rd, uint8_t *cmd_wr, union ctl_io *io)
{
	struct pci_vtscsi_queue *q;

	memset(sc, 0, sizeof(*sc));
	memset(req, 0, sizeof(*req));
	memset(cmd_rd, 0, VTSCSI_MAX_IN_HEADER_LEN);
	memset(cmd_wr, 0, VTSCSI_MAX_OUT_HEADER_LEN);
	memset(io, 0, sizeof(*io));
	sc->vss_config.cdb_size = VIRTIO14_SCSI_DEFAULT_CDB_SIZE;
	sc->vss_config.sense_size = VIRTIO14_SCSI_DEFAULT_SENSE_SIZE;
	sc->vss_vq[2].vq_num = 2;
	q = &sc->vss_queues[0];
	q->vsq_sc = sc;
	q->vsq_vq = &sc->vss_vq[2];
	pthread_mutex_init(&q->vsq_rmtx, NULL);
	pthread_mutex_init(&q->vsq_fmtx, NULL);
	pthread_mutex_init(&q->vsq_qmtx, NULL);
	pthread_cond_init(&q->vsq_cv, NULL);
	STAILQ_INIT(&q->vsq_requests);
	STAILQ_INIT(&q->vsq_free_requests);
	req->vsr_cmd_rd = (struct pci_vtscsi_req_cmd_rd *)cmd_rd;
	req->vsr_cmd_wr = (struct pci_vtscsi_req_cmd_wr *)cmd_wr;
	req->vsr_ctl_io = io;
	pci_vtscsi_put_request(&q->vsq_free_requests, req);
}

static void
teardown_queue(struct pci_vtscsi_softc *sc)
{
	struct pci_vtscsi_queue *q = &sc->vss_queues[0];

	pthread_cond_destroy(&q->vsq_cv);
	pthread_mutex_destroy(&q->vsq_qmtx);
	pthread_mutex_destroy(&q->vsq_fmtx);
	pthread_mutex_destroy(&q->vsq_rmtx);
}

ATF_TC_WITHOUT_HEAD(control_handler_validation);
ATF_TC_BODY(control_handler_validation, tc)
{
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_ctrl_tmf tmf = {
		.type = htole32(VIRTIO_SCSI_T_TMF),
		.subtype = htole32(UINT32_MAX),
		.lun = { VIRTIO14_SCSI_LUN_ADDRESS_METHOD, 0x00, 0x00,
		    0x00 },
	};
	struct pci_vtscsi_ctrl_an an = {
		.type = htole32(VIRTIO_SCSI_T_AN_QUERY),
	};
	uint32_t unknown;
	size_t written;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	written = pci_vtscsi_control_handle(&sc, &tmf,
	    VIRTIO14_SCSI_TMF_RESPONSE_OFF, VIRTIO14_SCSI_TMF_RESPONSE_SIZE);
	ATF_CHECK(written == 1);
	ATF_CHECK(*(uint8_t *)&tmf == VIRTIO_SCSI_S_FUNCTION_REJECTED);
	ATF_CHECK(g_ctl_allocs == 1 && g_ctl_frees == 1);

	reset_mocks();
	written = pci_vtscsi_control_handle(&sc, &an,
	    VIRTIO14_SCSI_AN_EVENT_ACTUAL_OFF,
	    VIRTIO14_SCSI_AN_EVENT_ACTUAL_SIZE +
	    VIRTIO14_SCSI_AN_RESPONSE_SIZE);
	ATF_CHECK(written == VIRTIO14_SCSI_AN_EVENT_ACTUAL_SIZE +
	    VIRTIO14_SCSI_AN_RESPONSE_SIZE);
	for (size_t i = 0; i < written; i++)
		ATF_CHECK(((uint8_t *)&an)[i] == 0);

	unknown = htole32(UINT32_MAX);
	written = pci_vtscsi_control_handle(&sc, &unknown, sizeof(unknown), 1);
	ATF_CHECK(written == 1);
	ATF_CHECK(*(uint8_t *)&unknown == VIRTIO_SCSI_S_FAILURE);

	unknown = htole32(VIRTIO_SCSI_T_TMF);
	written = pci_vtscsi_control_handle(&sc, &unknown, sizeof(unknown), 0);
	ATF_CHECK(written == 0);
}

ATF_TC_WITHOUT_HEAD(control_queue_validation);
ATF_TC_BODY(control_queue_validation, tc)
{
	struct pci_vtscsi_softc sc;
	uint8_t input[VIRTIO14_SCSI_AN_REQUEST_SIZE];
	uint8_t before[VIRTIO14_SCSI_AN_REQUEST_SIZE];
	uint8_t output[VIRTIO14_SCSI_AN_EVENT_ACTUAL_SIZE +
	    VIRTIO14_SCSI_AN_RESPONSE_SIZE];

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	memset(input, 0, sizeof(input));
	virtio14_store_le32(input, VIRTIO14_SCSI_T_AN_QUERY);
	memset(output, 0xa5, sizeof(output));
	memcpy(before, input, sizeof(before));
	set_chain(2, 1, 1, true);
	g_chain.iov[0] = (struct iovec){
		.iov_base = input,
		.iov_len = VIRTIO14_SCSI_AN_EVENT_ACTUAL_OFF,
	};
	g_chain.iov[1] = (struct iovec){
		.iov_base = output,
		.iov_len = sizeof(output),
	};
	pci_vtscsi_controlq_notify(&sc, &sc.vss_vq[0]);
	ATF_CHECK(memcmp(before, input, sizeof(input)) == 0);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == sizeof(output));
	for (size_t i = 0; i < sizeof(output); i++)
		ATF_CHECK(output[i] == 0);

	reset_mocks();
	set_chain(2, 2, 0, true);
	pci_vtscsi_controlq_notify(&sc, &sc.vss_vq[0]);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 0);

	reset_mocks();
	set_chain(VTSCSI_MAXSEG + 1, 1, VTSCSI_MAXSEG, true);
	pci_vtscsi_controlq_notify(&sc, &sc.vss_vq[0]);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 0);

	reset_mocks();
	set_chain(-1, 0, 0, true);
	pci_vtscsi_controlq_notify(&sc, &sc.vss_vq[0]);
	ATF_CHECK(g_rel_calls == 0);
}

ATF_TC_WITHOUT_HEAD(tmf_response_mapping);
ATF_TC_BODY(tmf_response_mapping, tc)
{

	ATF_CHECK(pci_vtscsi_tmf_response(CTL_TASK_FUNCTION_COMPLETE) ==
	    VIRTIO_SCSI_S_FUNCTION_COMPLETE);
	ATF_CHECK(pci_vtscsi_tmf_response(CTL_TASK_FUNCTION_SUCCEEDED) ==
	    VIRTIO_SCSI_S_FUNCTION_SUCCEEDED);
	ATF_CHECK(pci_vtscsi_tmf_response(CTL_TASK_FUNCTION_REJECTED) ==
	    VIRTIO_SCSI_S_FUNCTION_REJECTED);
	ATF_CHECK(pci_vtscsi_tmf_response(CTL_TASK_FUNCTION_NOT_SUPPORTED) ==
	    VIRTIO_SCSI_S_FUNCTION_REJECTED);
	ATF_CHECK(pci_vtscsi_tmf_response(CTL_TASK_LUN_DOES_NOT_EXIST) ==
	    VIRTIO_SCSI_S_BAD_TARGET);
	ATF_CHECK(pci_vtscsi_tmf_response(UINT8_MAX) ==
	    VIRTIO_SCSI_S_FAILURE);
}

ATF_TC_WITHOUT_HEAD(config_writes);
ATF_TC_BODY(config_writes, tc)
{
	struct pci_vtscsi_softc sc;
	uint32_t old_num_queues;
	uint32_t value;

	memset(&sc, 0, sizeof(sc));
	sc.vss_config.num_queues = 1;
	sc.vss_config.sense_size = VIRTIO14_SCSI_DEFAULT_SENSE_SIZE;
	sc.vss_config.cdb_size = VIRTIO14_SCSI_DEFAULT_CDB_SIZE;
	old_num_queues = sc.vss_config.num_queues;

	ATF_CHECK(pci_vtscsi_cfgwrite(&sc,
	    VIRTIO14_SCSI_CONFIG_SENSE_SIZE_OFF, 4, 64) == 0);
	ATF_CHECK(sc.vss_config.sense_size == 64);
	ATF_CHECK(pci_vtscsi_cfgwrite(&sc,
	    VIRTIO14_SCSI_CONFIG_CDB_SIZE_OFF, 4, 16) == 0);
	ATF_CHECK(sc.vss_config.cdb_size == 16);
	ATF_CHECK(pci_vtscsi_cfgwrite(&sc,
	    VIRTIO14_SCSI_CONFIG_NUM_QUEUES_OFF, 4, 2) == 1);
	ATF_CHECK(sc.vss_config.num_queues == old_num_queues);
	ATF_CHECK(pci_vtscsi_cfgwrite(&sc,
	    VIRTIO14_SCSI_CONFIG_SENSE_SIZE_OFF, 4,
	    SSD_FULL_SIZE + 1) == 1);
	ATF_CHECK(pci_vtscsi_cfgwrite(&sc,
	    VIRTIO14_SCSI_CONFIG_CDB_SIZE_OFF, 4, 0) == 1);
	ATF_CHECK(pci_vtscsi_cfgwrite(&sc,
	    VIRTIO14_SCSI_CONFIG_CDB_SIZE_OFF, 2, 16) == 1);

	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtscsi_cfgread(&sc,
	    VIRTIO14_SCSI_CONFIG_CDB_SIZE_OFF, 4, &value), 0);
	ATF_CHECK_EQ(value, 16);
	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtscsi_cfgread(&sc, -1, 1, &value), EINVAL);
	ATF_CHECK_EQ(value, 0);
	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtscsi_cfgread(&sc, 0, 3, &value), EINVAL);
	ATF_CHECK_EQ(value, 0);
	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtscsi_cfgread(&sc,
	    VIRTIO14_SCSI_CONFIG_SIZE - 1, 4,
	    &value), EINVAL);
	ATF_CHECK_EQ(value, 0);

	sc.vss_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	ATF_CHECK(pci_vtscsi_cfgwrite(&sc,
	    VIRTIO14_SCSI_CONFIG_CDB_SIZE_OFF, 4, 12) == 1);
	ATF_CHECK(sc.vss_config.cdb_size == 16);
}

ATF_TC_WITHOUT_HEAD(config_defaults);
ATF_TC_BODY(config_defaults, tc)
{
	struct pci_vtscsi_softc sc;

	memset(&sc, 0, sizeof(sc));
	sc.vss_features = UINT32_MAX;
	pci_vtscsi_reset(&sc);
	ATF_CHECK_EQ(sc.vss_features, 0);
	ATF_CHECK_EQ(sc.vss_config.num_queues, VTSCSI_REQUESTQ);
	ATF_CHECK_EQ(sc.vss_config.seg_max, VTSCSI_MAXSEG - 2);
	ATF_CHECK_EQ(sc.vss_config.max_sectors, VTSCSI_MAX_SECTORS);
	ATF_CHECK(
	    (uint64_t)sc.vss_config.max_sectors *
	    VIRTIO14_SCSI_SECTOR_BYTES +
	    VTSCSI_MAX_OUT_HEADER_LEN <= UINT32_MAX);
	ATF_CHECK(
	    ((uint64_t)sc.vss_config.max_sectors + 1) *
	    VIRTIO14_SCSI_SECTOR_BYTES +
	    VTSCSI_MAX_OUT_HEADER_LEN > UINT32_MAX);
	ATF_CHECK_EQ(sc.vss_config.sense_size,
	    VIRTIO14_SCSI_DEFAULT_SENSE_SIZE);
	ATF_CHECK_EQ(sc.vss_config.cdb_size,
	    VIRTIO14_SCSI_DEFAULT_CDB_SIZE);
	ATF_CHECK_EQ(sc.vss_config.max_channel,
	    VIRTIO14_SCSI_MAX_CHANNEL);
	ATF_CHECK(sc.vss_config.max_target <=
	    VIRTIO14_SCSI_MAX_TARGET_LIMIT);
	ATF_CHECK(sc.vss_config.max_lun <=
	    VIRTIO14_SCSI_MAX_LUN_LIMIT);
}

ATF_TC_WITHOUT_HEAD(document_wire_vectors);
ATF_TC_BODY(document_wire_vectors, tc)
{
	struct pci_vtscsi_softc sc;
	uint64_t aligned[(VIRTIO14_SCSI_TMF_REQUEST_SIZE +
	    VIRTIO14_SCSI_TMF_RESPONSE_SIZE + sizeof(uint64_t) - 1) /
	    sizeof(uint64_t)];
	uint8_t *wire;
	uint64_t id_wire;
	uint32_t response_wire;
	uint32_t config_wire;
	size_t written;

	/*
	 * Encode a TMF request using only section 5.6.6.2 offsets.  An all-zero
	 * LUN is invalid, so the documented BAD_TARGET response is deterministic
	 * and does not depend on a CTL backend.
	 */
	memset(&sc, 0, sizeof(sc));
	wire = (uint8_t *)(void *)aligned;
	memset(wire, 0, VIRTIO14_SCSI_TMF_REQUEST_SIZE +
	    VIRTIO14_SCSI_TMF_RESPONSE_SIZE);
	virtio14_store_le32(wire + VIRTIO14_SCSI_TMF_TYPE_OFF,
	    VIRTIO14_SCSI_T_TMF);
	virtio14_store_le32(wire + VIRTIO14_SCSI_TMF_SUBTYPE_OFF,
	    VIRTIO14_SCSI_T_TMF_ABORT_TASK);
	written = pci_vtscsi_control_handle(&sc, wire,
	    VIRTIO14_SCSI_TMF_REQUEST_SIZE,
	    VIRTIO14_SCSI_TMF_RESPONSE_SIZE);
	ATF_REQUIRE_EQ(written, VIRTIO14_SCSI_TMF_RESPONSE_SIZE);
	ATF_CHECK_EQ(wire[0], VIRTIO14_SCSI_S_BAD_TARGET);

	/*
	 * Section 5.6.6 declares the command id le64 and response lengths le32.
	 * Build both solely as byte vectors, then verify the transport-aware
	 * conversion used by the device model.
	 */
	sc.vss_vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	memset(wire, 0, VIRTIO14_SCSI_CMD_REQUEST_FIXED_SIZE);
	virtio14_store_le64(wire + VIRTIO14_SCSI_CMD_REQUEST_ID_OFF,
	    UINT64_C(0x0123456789abcdef));
	memcpy(&id_wire, wire + VIRTIO14_SCSI_CMD_REQUEST_ID_OFF,
	    VIRTIO14_SCSI_CMD_REQUEST_ID_SIZE);
	ATF_CHECK_EQ(pci_vtscsi_decode64(&sc, id_wire),
	    UINT64_C(0x0123456789abcdef));

	response_wire = pci_vtscsi_encode32(&sc, UINT32_C(0x10203040));
	memcpy(wire, &response_wire, sizeof(response_wire));
	ATF_CHECK_EQ(wire[0], 0x40);
	ATF_CHECK_EQ(wire[1], 0x30);
	ATF_CHECK_EQ(wire[2], 0x20);
	ATF_CHECK_EQ(wire[3], 0x10);

	sc.vss_config.max_lun = UINT32_C(0x01020304);
	ATF_REQUIRE_EQ(pci_vtscsi_cfgread(&sc,
	    VIRTIO14_SCSI_CONFIG_MAX_LUN_OFF, sizeof(config_wire),
	    &config_wire), 0);
	memcpy(wire, &config_wire, sizeof(config_wire));
	ATF_CHECK_EQ(wire[0], 0x04);
	ATF_CHECK_EQ(wire[1], 0x03);
	ATF_CHECK_EQ(wire[2], 0x02);
	ATF_CHECK_EQ(wire[3], 0x01);
}

ATF_TC_WITHOUT_HEAD(request_queue_validation);
ATF_TC_BODY(request_queue_validation, tc)
{
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_request req;
	union ctl_io io;
	uint8_t cmd_rd[VTSCSI_MAX_IN_HEADER_LEN];
	uint8_t cmd_wr[VTSCSI_MAX_OUT_HEADER_LEN];
	uint8_t output;

	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	set_chain(-1, 0, 0, true);
	ATF_CHECK(!pci_vtscsi_queue_request(&sc, &sc.vss_vq[2]));
	ATF_CHECK(!STAILQ_EMPTY(&sc.vss_queues[0].vsq_free_requests));
	ATF_CHECK(g_rel_calls == 0);
	teardown_queue(&sc);

	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	set_chain(VTSCSI_MAXSEG + 1, 1, VTSCSI_MAXSEG, true);
	ATF_CHECK(pci_vtscsi_queue_request(&sc, &sc.vss_vq[2]));
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 0);
	ATF_CHECK(!STAILQ_EMPTY(&sc.vss_queues[0].vsq_free_requests));
	teardown_queue(&sc);

	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	set_chain(2, 1, 1, false);
	ATF_CHECK(pci_vtscsi_queue_request(&sc, &sc.vss_vq[2]));
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 0);
	teardown_queue(&sc);

	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	output = 0xa5;
	set_chain(2, 1, 1, true);
	g_chain.iov[0] = (struct iovec){
		.iov_base = cmd_rd,
		.iov_len = VIRTIO14_SCSI_DEFAULT_CMD_REQUEST_SIZE,
	};
	g_chain.iov[1] = (struct iovec){
		.iov_base = &output,
		.iov_len = sizeof(output),
	};
	ATF_CHECK(pci_vtscsi_queue_request(&sc, &sc.vss_vq[2]));
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 1);
	teardown_queue(&sc);
}

ATF_TC_WITHOUT_HEAD(request_payload_validation);
ATF_TC_BODY(request_payload_validation, tc)
{
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_request req;
	struct pci_vtscsi_req_cmd_wr response;
	struct iovec in, out;
	uint8_t byte;

	memset(&sc, 0, sizeof(sc));
	memset(&req, 0, sizeof(req));
	memset(&response, 0, sizeof(response));
	in = (struct iovec){ .iov_base = &byte, .iov_len = 1 };
	out = (struct iovec){ .iov_base = &byte, .iov_len = 1 };
	req.vsr_cmd_wr = &response;
	req.vsr_data_iov_in = &in;
	req.vsr_data_niov_in = 1;
	req.vsr_data_iov_out = &out;
	req.vsr_data_niov_out = 1;
	ATF_CHECK(pci_vtscsi_request_handle(&sc, &req) == 0);
	ATF_CHECK(response.response == VIRTIO_SCSI_S_FAILURE);

	memset(&response, 0, sizeof(response));
	req.vsr_data_iov_out = NULL;
	req.vsr_data_niov_out = 0;
	in.iov_len = UINT32_MAX;
	ATF_CHECK(pci_vtscsi_request_handle(&sc, &req) == 0);
	ATF_CHECK(response.response == VIRTIO_SCSI_S_FAILURE);
}

ATF_TC_WITHOUT_HEAD(request_response_mapping);
ATF_TC_BODY(request_response_mapping, tc)
{
	union ctl_io io;

	memset(&io, 0, sizeof(io));
	io.io_hdr.status = CTL_SUCCESS;
	io.scsiio.ext_data_filled = 4096;
	ATF_CHECK_EQ(pci_vtscsi_request_response(&io, 4096),
	    VIRTIO_SCSI_S_OK);
	io.scsiio.ext_data_filled++;
	ATF_CHECK_EQ(pci_vtscsi_request_response(&io, 4096),
	    VIRTIO_SCSI_S_OVERRUN);

	memset(&io, 0, sizeof(io));
	io.io_hdr.status = CTL_SCSI_ERROR | CTL_AUTOSENSE;
	io.scsiio.scsi_status = SCSI_STATUS_CHECK_COND;
	ATF_CHECK_EQ(pci_vtscsi_request_response(&io, 0),
	    VIRTIO_SCSI_S_OK);

	io.io_hdr.status = CTL_CMD_ABORTED;
	ATF_CHECK_EQ(pci_vtscsi_request_response(&io, 0),
	    VIRTIO_SCSI_S_ABORTED);
	io.io_hdr.status = CTL_SEL_TIMEOUT;
	ATF_CHECK_EQ(pci_vtscsi_request_response(&io, 0),
	    VIRTIO_SCSI_S_TRANSPORT_FAILURE);
	io.io_hdr.status = CTL_ERROR;
	ATF_CHECK_EQ(pci_vtscsi_request_response(&io, 0),
	    VIRTIO_SCSI_S_FAILURE);
	io.io_hdr.status = CTL_STATUS_NONE;
	ATF_CHECK_EQ(pci_vtscsi_request_response(&io, 0),
	    VIRTIO_SCSI_S_FAILURE);

	io.io_hdr.status = CTL_SUCCESS;
	io.io_hdr.port_status = 1;
	ATF_CHECK_EQ(pci_vtscsi_request_response(&io, 0),
	    VIRTIO_SCSI_S_TRANSPORT_FAILURE);
	io.io_hdr.status = CTL_CMD_ABORTED;
	ATF_CHECK_EQ(pci_vtscsi_request_response(&io, 0),
	    VIRTIO_SCSI_S_TRANSPORT_FAILURE);
}

ATF_TC_WITHOUT_HEAD(reset_completes_pending_requests);
ATF_TC_BODY(reset_completes_pending_requests, tc)
{
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_request req;
	struct pci_vtscsi_queue *q;
	union ctl_io io;
	uint8_t cmd_rd[VTSCSI_MAX_IN_HEADER_LEN];
	uint8_t cmd_wr[VTSCSI_MAX_OUT_HEADER_LEN];
	uint8_t response[VTSCSI_MAX_OUT_HEADER_LEN];
	size_t response_len;

	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	q = &sc.vss_queues[0];
	ATF_REQUIRE(pci_vtscsi_get_request(&q->vsq_free_requests) == &req);
	memset(response, 0, sizeof(response));
	response_len = VIRTIO14_SCSI_DEFAULT_CMD_RESPONSE_SIZE;
	req.vsr_idx = 19;
	req.vsr_iov_out = &req.vsr_iov[0];
	req.vsr_niov_out = 1;
	req.vsr_iov[0] = (struct iovec){
		.iov_base = response,
		.iov_len = response_len,
	};
	pci_vtscsi_put_request(&q->vsq_requests, &req);

	pci_vtscsi_quiesce_queue(q, true);
	ATF_CHECK(q->vsq_quiescing);
	ATF_CHECK(STAILQ_EMPTY(&q->vsq_requests));
	ATF_CHECK(pci_vtscsi_get_request(&q->vsq_free_requests) == &req);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_idx, 19);
	ATF_CHECK_EQ(g_rel_len, response_len);
	ATF_CHECK_EQ(g_end_calls, 1);
	ATF_CHECK_EQ(response[VIRTIO14_SCSI_CMD_RESPONSE_RESPONSE_OFF],
	    VIRTIO14_SCSI_S_RESET);

	pci_vtscsi_resume_queue(q);
	ATF_CHECK(!q->vsq_quiescing);
	teardown_queue(&sc);
}

ATF_TC_WITHOUT_HEAD(queue_reset_quiesces_only_selected_queue);
ATF_TC_BODY(queue_reset_quiesces_only_selected_queue, tc)
{
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_request req;
	struct pci_vtscsi_queue *q;
	union ctl_io io;
	uint8_t cmd_rd[VTSCSI_MAX_IN_HEADER_LEN];
	uint8_t cmd_wr[VTSCSI_MAX_OUT_HEADER_LEN];

	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	q = &sc.vss_queues[0];
	ATF_REQUIRE(pci_vtscsi_get_request(&q->vsq_free_requests) == &req);
	pci_vtscsi_put_request(&q->vsq_requests, &req);
	sc.vss_vq[2].vq_num = 2;

	ATF_CHECK_EQ(pci_vtscsi_qreset(&sc, &sc.vss_vq[2], 9), 0);
	ATF_CHECK(q->vsq_quiescing);
	ATF_CHECK(STAILQ_EMPTY(&q->vsq_requests));
	ATF_CHECK(pci_vtscsi_get_request(&q->vsq_free_requests) == &req);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK((vtscsi_vi_consts.vc_hv_caps &
	    VIRTIO_F_RING_RESET) != 0);

	ATF_CHECK_EQ(pci_vtscsi_qenable(&sc, &sc.vss_vq[2]), 0);
	ATF_CHECK(!q->vsq_quiescing);
	sc.vss_vq[2].vq_num = VTSCSI_MAXQ;
	ATF_CHECK_EQ(pci_vtscsi_qreset(&sc, &sc.vss_vq[2], 10), EINVAL);
	ATF_CHECK_EQ(pci_vtscsi_qenable(&sc, &sc.vss_vq[2]), EINVAL);
	teardown_queue(&sc);
}

ATF_TC_WITHOUT_HEAD(queue_sync_init_failures);
ATF_TC_BODY(queue_sync_init_failures, tc)
{
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_queue *q;

	for (int fail_at = 1; fail_at <= 3; fail_at++) {
		reset_mocks();
		memset(&sc, 0, sizeof(sc));
		g_mutex_init_fail_at = fail_at;
		ATF_CHECK(pci_vtscsi_init_queue(&sc, &sc.vss_queues[0], 0) ==
		    -1);
		q = &sc.vss_queues[0];
		ATF_CHECK(q->vsq_sc == NULL);
		ATF_CHECK(!q->vsq_rmtx_initialized);
		ATF_CHECK(!q->vsq_fmtx_initialized);
		ATF_CHECK(!q->vsq_qmtx_initialized);
		ATF_CHECK(!q->vsq_cv_initialized);
		ATF_CHECK(g_ctl_allocs == g_ctl_frees);
	}

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	g_cond_init_fail_at = 1;
	ATF_CHECK(pci_vtscsi_init_queue(&sc, &sc.vss_queues[0], 0) == -1);
	q = &sc.vss_queues[0];
	ATF_CHECK(q->vsq_sc == NULL);
	ATF_CHECK(!q->vsq_rmtx_initialized);
	ATF_CHECK(!q->vsq_fmtx_initialized);
	ATF_CHECK(!q->vsq_qmtx_initialized);
	ATF_CHECK(!q->vsq_cv_initialized);
	ATF_CHECK(g_ctl_allocs == g_ctl_frees);
}

ATF_TC_WITHOUT_HEAD(tmf_completes_pending_requests);
ATF_TC_BODY(tmf_completes_pending_requests, tc)
{
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_request req;
	struct pci_vtscsi_queue *q;
	struct iovec output_iov;
	union ctl_io io;
	uint8_t cmd_rd[VTSCSI_MAX_IN_HEADER_LEN];
	uint8_t cmd_wr[VTSCSI_MAX_OUT_HEADER_LEN];
	uint8_t output[VIRTIO14_SCSI_DEFAULT_CMD_RESPONSE_SIZE];
	const uint8_t lun[VIRTIO14_SCSI_LUN_SIZE] = {
		VIRTIO14_SCSI_LUN_ADDRESS_METHOD, 0, 0, 1
	};

	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	q = &sc.vss_queues[0];
	ATF_REQUIRE(pci_vtscsi_get_request(&q->vsq_free_requests) == &req);
	memcpy(cmd_rd + VIRTIO14_SCSI_CMD_REQUEST_LUN_OFF, lun,
	    VIRTIO14_SCSI_LUN_SIZE);
	virtio14_store_le64(cmd_rd + VIRTIO14_SCSI_CMD_REQUEST_ID_OFF,
	    UINT64_C(0x1234));
	req.vsr_idx = 23;
	output_iov = (struct iovec){
		.iov_base = output,
		.iov_len = sizeof(output),
	};
	req.vsr_iov_out = &output_iov;
	req.vsr_niov_out = 1;
	pci_vtscsi_put_request(&q->vsq_requests, &req);

	pci_vtscsi_tmf_pause(&sc);
	pci_vtscsi_tmf_complete(&sc, VIRTIO_SCSI_T_TMF_ABORT_TASK, lun,
	    0x1234);
	ATF_CHECK(g_rel_calls == 1 && g_rel_idx == 23 &&
	    g_rel_len == sizeof(output));
	ATF_CHECK(output[VIRTIO14_SCSI_CMD_RESPONSE_RESPONSE_OFF] ==
	    VIRTIO_SCSI_S_ABORTED);
	ATF_CHECK(STAILQ_EMPTY(&q->vsq_requests));
	pci_vtscsi_resume_queue(q);
	teardown_queue(&sc);
}

ATF_TC_WITHOUT_HEAD(virtio_1_4_wire_layout);
ATF_TC_BODY(virtio_1_4_wire_layout, tc)
{

	ATF_CHECK_EQ(sizeof(struct pci_vtscsi_config),
	    VIRTIO14_SCSI_CONFIG_SIZE);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_config, num_queues),
	    VIRTIO14_SCSI_CONFIG_NUM_QUEUES_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_config, seg_max),
	    VIRTIO14_SCSI_CONFIG_SEG_MAX_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_config, max_sectors),
	    VIRTIO14_SCSI_CONFIG_MAX_SECTORS_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_config, cmd_per_lun),
	    VIRTIO14_SCSI_CONFIG_CMD_PER_LUN_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_config, event_info_size),
	    VIRTIO14_SCSI_CONFIG_EVENT_INFO_SIZE_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_config, sense_size),
	    VIRTIO14_SCSI_CONFIG_SENSE_SIZE_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_config, cdb_size),
	    VIRTIO14_SCSI_CONFIG_CDB_SIZE_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_config, max_channel),
	    VIRTIO14_SCSI_CONFIG_MAX_CHANNEL_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_config, max_target),
	    VIRTIO14_SCSI_CONFIG_MAX_TARGET_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_config, max_lun),
	    VIRTIO14_SCSI_CONFIG_MAX_LUN_OFF);

	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_ctrl_tmf, response),
	    VIRTIO14_SCSI_TMF_RESPONSE_OFF);
	ATF_CHECK_EQ(sizeof(struct pci_vtscsi_ctrl_tmf),
	    VIRTIO14_SCSI_TMF_REQUEST_SIZE +
	    VIRTIO14_SCSI_TMF_RESPONSE_SIZE);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_ctrl_an, event_actual),
	    VIRTIO14_SCSI_AN_EVENT_ACTUAL_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_ctrl_an, response),
	    VIRTIO14_SCSI_AN_RESPONSE_OFF);
	ATF_CHECK_EQ(sizeof(struct pci_vtscsi_ctrl_an),
	    VIRTIO14_SCSI_AN_RESPONSE_OFF +
	    VIRTIO14_SCSI_AN_RESPONSE_SIZE);

	ATF_CHECK_EQ(sizeof(struct pci_vtscsi_event),
	    VIRTIO14_SCSI_EVENT_SIZE);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_event, event),
	    VIRTIO14_SCSI_EVENT_EVENT_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_event, lun),
	    VIRTIO14_SCSI_EVENT_LUN_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_event, reason),
	    VIRTIO14_SCSI_EVENT_REASON_OFF);

	ATF_CHECK_EQ(sizeof(struct pci_vtscsi_req_cmd_rd),
	    VIRTIO14_SCSI_CMD_REQUEST_FIXED_SIZE);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_rd, lun),
	    VIRTIO14_SCSI_CMD_REQUEST_LUN_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_rd, id),
	    VIRTIO14_SCSI_CMD_REQUEST_ID_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_rd, task_attr),
	    VIRTIO14_SCSI_CMD_REQUEST_TASK_ATTR_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_rd, prio),
	    VIRTIO14_SCSI_CMD_REQUEST_PRIO_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_rd, crn),
	    VIRTIO14_SCSI_CMD_REQUEST_CRN_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_rd, cdb),
	    VIRTIO14_SCSI_CMD_REQUEST_CDB_OFF);

	ATF_CHECK_EQ(sizeof(struct pci_vtscsi_req_cmd_wr),
	    VIRTIO14_SCSI_CMD_RESPONSE_FIXED_SIZE);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_wr, sense_len),
	    VIRTIO14_SCSI_CMD_RESPONSE_SENSE_LEN_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_wr, residual),
	    VIRTIO14_SCSI_CMD_RESPONSE_RESIDUAL_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_wr, status_qualifier),
	    VIRTIO14_SCSI_CMD_RESPONSE_STATUS_QUALIFIER_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_wr, status),
	    VIRTIO14_SCSI_CMD_RESPONSE_STATUS_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_wr, response),
	    VIRTIO14_SCSI_CMD_RESPONSE_RESPONSE_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_wr, sense),
	    VIRTIO14_SCSI_CMD_RESPONSE_SENSE_OFF);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, control_handler_validation);
	ATF_TP_ADD_TC(tp, control_queue_validation);
	ATF_TP_ADD_TC(tp, tmf_response_mapping);
	ATF_TP_ADD_TC(tp, config_writes);
	ATF_TP_ADD_TC(tp, config_defaults);
	ATF_TP_ADD_TC(tp, document_wire_vectors);
	ATF_TP_ADD_TC(tp, request_queue_validation);
	ATF_TP_ADD_TC(tp, request_payload_validation);
	ATF_TP_ADD_TC(tp, request_response_mapping);
	ATF_TP_ADD_TC(tp, queue_sync_init_failures);
	ATF_TP_ADD_TC(tp, reset_completes_pending_requests);
	ATF_TP_ADD_TC(tp, queue_reset_quiesces_only_selected_queue);
	ATF_TP_ADD_TC(tp, tmf_completes_pending_requests);
	ATF_TP_ADD_TC(tp, virtio_1_4_wire_layout);
	return (atf_no_error());
}
