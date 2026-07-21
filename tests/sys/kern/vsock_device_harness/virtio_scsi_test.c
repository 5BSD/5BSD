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

#include "pci_virtio_scsi.c"
#include "iov.c"

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
	memset(cmd_rd, 0, sizeof(struct pci_vtscsi_req_cmd_rd) + 32);
	memset(cmd_wr, 0, sizeof(struct pci_vtscsi_req_cmd_wr) + 96);
	memset(io, 0, sizeof(*io));
	sc->vss_config.cdb_size = 32;
	sc->vss_config.sense_size = 96;
	sc->vss_vq[2].vq_num = 2;
	q = &sc->vss_queues[0];
	q->vsq_sc = sc;
	q->vsq_vq = &sc->vss_vq[2];
	pthread_mutex_init(&q->vsq_fmtx, NULL);
	pthread_mutex_init(&q->vsq_qmtx, NULL);
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

	pthread_mutex_destroy(&q->vsq_qmtx);
	pthread_mutex_destroy(&q->vsq_fmtx);
}

ATF_TC_WITHOUT_HEAD(control_handler_validation);
ATF_TC_BODY(control_handler_validation, tc)
{
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_ctrl_tmf tmf = {
		.type = htole32(VIRTIO_SCSI_T_TMF),
		.subtype = htole32(UINT32_MAX),
		.lun = { 0x01, 0x00, 0x00, 0x00 },
	};
	struct pci_vtscsi_ctrl_an an = {
		.type = htole32(VIRTIO_SCSI_T_AN_QUERY),
	};
	uint32_t unknown;
	size_t written;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	written = pci_vtscsi_control_handle(&sc, &tmf,
	    offsetof(struct pci_vtscsi_ctrl_tmf, response), 1);
	ATF_CHECK(written == 1);
	ATF_CHECK(*(uint8_t *)&tmf == VIRTIO_SCSI_S_FUNCTION_REJECTED);
	ATF_CHECK(g_ctl_allocs == 1 && g_ctl_frees == 1);

	reset_mocks();
	written = pci_vtscsi_control_handle(&sc, &an,
	    offsetof(struct pci_vtscsi_ctrl_an, event_actual),
	    sizeof(an.event_actual) + sizeof(an.response));
	ATF_CHECK(written == sizeof(an.event_actual) + sizeof(an.response));
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
	struct pci_vtscsi_ctrl_an input = {
		.type = htole32(VIRTIO_SCSI_T_AN_QUERY),
	};
	uint8_t before[sizeof(input)];
	uint8_t output[5];

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	memset(output, 0xa5, sizeof(output));
	memcpy(before, &input, sizeof(before));
	set_chain(2, 1, 1, true);
	g_chain.iov[0] = (struct iovec){
		.iov_base = &input,
		.iov_len = offsetof(struct pci_vtscsi_ctrl_an, event_actual),
	};
	g_chain.iov[1] = (struct iovec){
		.iov_base = output,
		.iov_len = sizeof(output),
	};
	pci_vtscsi_controlq_notify(&sc, &sc.vss_vq[0]);
	ATF_CHECK(memcmp(before, &input, sizeof(input)) == 0);
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

ATF_TC_WITHOUT_HEAD(request_queue_validation);
ATF_TC_BODY(request_queue_validation, tc)
{
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_request req;
	union ctl_io io;
	uint8_t cmd_rd[sizeof(struct pci_vtscsi_req_cmd_rd) + 32];
	uint8_t cmd_wr[sizeof(struct pci_vtscsi_req_cmd_wr) + 96];
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
		.iov_len = sizeof(cmd_rd),
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

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, control_handler_validation);
	ATF_TP_ADD_TC(tp, control_queue_validation);
	ATF_TP_ADD_TC(tp, request_queue_validation);
	ATF_TP_ADD_TC(tp, request_payload_validation);
	return (atf_no_error());
}
