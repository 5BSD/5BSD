/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Fault-injection tests for bhyve's VirtIO 9P device.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "pci_virtio_9p.c"
#include "virtio_1_4_spec.h"

#undef VIRTIO_CONFIG_S_NEEDS_RESET
#define	VIRTIO_CONFIG_S_NEEDS_RESET	VIRTIO14_STATUS_DEVICE_NEEDS_RESET
#undef VIRTIO_9P_F_MOUNT_TAG
#define	VIRTIO_9P_F_MOUNT_TAG		VIRTIO14_9P_F_MOUNT_TAG
#undef VIRTIO_F_RING_RESET
#define	VIRTIO_F_RING_RESET		VIRTIO14_F_RING_RESET
struct nvlist {
	int unused;
};

static char g_names[8][32];
static char g_values[8][128];
static int g_set_count;
static int g_descs;
static int g_chain_n;
static int g_readable;
static int g_writable;
static bool g_ordered;
static int g_recv_result;
static bool g_complete_immediately;
static int g_recv_calls;
static size_t g_recv_niov;
static void *g_recv_aux;
static int g_rel_calls;
static uint32_t g_rel_len;
static int g_end_calls;
static int g_connection_closes;
static int g_connection_inits;
static int g_connection_init_result;
static int g_needs_reset_calls;
static int g_qreset_complete_calls;
static uint64_t g_qreset_complete_generation;
static int g_qreset_complete_error;
static struct pci_vt9p_softc *g_notify_during_close;
static bool g_drop_during_close;
static struct l9p_connection g_connection;

static void
init_recursive_mutex(pthread_mutex_t *mtx)
{
	pthread_mutexattr_t attr;

	ATF_REQUIRE(pthread_mutexattr_init(&attr) == 0);
	ATF_REQUIRE(pthread_mutexattr_settype(&attr,
	    PTHREAD_MUTEX_RECURSIVE) == 0);
	ATF_REQUIRE(pthread_mutex_init(mtx, &attr) == 0);
	ATF_REQUIRE(pthread_mutexattr_destroy(&attr) == 0);
}

static void
reset_mocks(void)
{
	g_set_count = 0;
	g_descs = 1;
	g_chain_n = 2;
	g_readable = 1;
	g_writable = 1;
	g_ordered = true;
	g_recv_result = 0;
	g_complete_immediately = false;
	g_recv_calls = 0;
	g_recv_niov = 0;
	g_recv_aux = NULL;
	g_rel_calls = 0;
	g_rel_len = UINT32_MAX;
	g_end_calls = 0;
	g_connection_closes = 0;
	g_connection_inits = 0;
	g_connection_init_result = 0;
	g_needs_reset_calls = 0;
	g_qreset_complete_calls = 0;
	g_qreset_complete_generation = 0;
	g_qreset_complete_error = 0;
	g_notify_during_close = NULL;
	g_drop_during_close = false;
}

const char *
get_config_value_node(const nvlist_t *nvl __unused, const char *name __unused)
{
	return (NULL);
}

bool
get_config_bool_node_default(const nvlist_t *nvl __unused,
    const char *name __unused, bool value)
{
	return (value);
}

bool
vi_pci_is_modern(const struct virtio_softc *vs)
{

	return (vs->vs_transport == VIRTIO_PCI_TRANSPORT_MODERN);
}

void
set_config_value_node(nvlist_t *nvl __unused, const char *name,
    const char *value)
{
	ATF_REQUIRE(g_set_count < (int)nitems(g_names));
	ATF_REQUIRE(strlcpy(g_names[g_set_count], name,
	    sizeof(g_names[0])) < sizeof(g_names[0]));
	ATF_REQUIRE(strlcpy(g_values[g_set_count], value,
	    sizeof(g_values[0])) < sizeof(g_values[0]));
	g_set_count++;
}

void
set_config_bool_node(nvlist_t *nvl __unused, const char *name, bool value)
{
	ATF_REQUIRE(value);
	set_config_value_node(nvl, name, "true");
}

int
vq_has_descs(struct vqueue_info *vq __unused)
{
	return (g_descs > 0);
}

int
vq_getchain(struct vqueue_info *vq __unused, struct iovec *iov, int niov,
    struct vi_req *req)
{
	static uint8_t request[16], response[32];

	if (g_chain_n <= 0)
		return (g_chain_n);
	ATF_REQUIRE(niov >= 2);
	iov[0].iov_base = request;
	iov[0].iov_len = sizeof(request);
	iov[1].iov_base = response;
	iov[1].iov_len = sizeof(response);
	req->idx = 7;
	req->readable = g_readable;
	req->writable = g_writable;
	req->ordered = g_ordered;
	g_descs--;
	return (g_chain_n);
}

void
vq_relchain(struct vqueue_info *vq __unused, uint16_t idx, uint32_t len)
{
	ATF_CHECK(idx == 7);
	g_rel_calls++;
	g_rel_len = len;
}

void
vq_endchains(struct vqueue_info *vq __unused, int used_all __unused)
{
	g_end_calls++;
}

int
l9p_connection_recv(struct l9p_connection *conn __unused,
    const struct iovec *iov __unused, size_t niov, void *aux)
{
	struct l9p_request req;

	g_recv_calls++;
	g_recv_niov = niov;
	g_recv_aux = aux;
	if (g_recv_result != 0)
		return (g_recv_result);
	if (g_complete_immediately) {
		memset(&req, 0, sizeof(req));
		req.lr_aux = aux;
		(void)pci_vt9p_send(&req, NULL, 0, 17, NULL);
	}
	return (0);
}

void
l9p_connection_close(struct l9p_connection *conn __unused)
{
	struct l9p_request req;

	g_connection_closes++;
	if (g_notify_during_close != NULL)
		pci_vt9p_notify(g_notify_during_close,
		    &g_notify_during_close->vsc_vq);
	if (g_drop_during_close && g_recv_aux != NULL) {
		memset(&req, 0, sizeof(req));
		req.lr_aux = g_recv_aux;
		g_recv_aux = NULL;
		pci_vt9p_drop(&req, NULL, 0, NULL);
	}
}

void
l9p_connection_free(struct l9p_connection *conn __unused)
{
}

int
l9p_connection_init(struct l9p_server *server __unused,
    struct l9p_connection **conn)
{
	memset(&g_connection, 0, sizeof(g_connection));
	if (g_connection_init_result != 0) {
		*conn = NULL;
		g_connection_inits++;
		return (g_connection_init_result);
	}
	*conn = &g_connection;
	g_connection_inits++;
	return (0);
}

void
vi_reset_dev(struct virtio_softc *vs __unused)
{
}

void
vi_set_needs_reset(struct virtio_softc *vs)
{
	g_needs_reset_calls++;
	vs->vs_status |= VIRTIO_CONFIG_S_NEEDS_RESET;
}

void
vi_pci_modern_queue_reset_complete(struct vqueue_info *vq __unused,
    uint64_t generation, int error)
{

	g_qreset_complete_calls++;
	g_qreset_complete_generation = generation;
	g_qreset_complete_error = error;
}

static void
setup_softc(struct pci_vt9p_softc *sc)
{
	memset(sc, 0, sizeof(*sc));
	init_recursive_mutex(&sc->vsc_mtx);
	ATF_REQUIRE(pthread_cond_init(&sc->vsc_reset_cv, NULL) == 0);
	sc->vsc_conn = &g_connection;
}

static void
destroy_softc(struct pci_vt9p_softc *sc)
{

	ATF_REQUIRE(pthread_cond_destroy(&sc->vsc_reset_cv) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc->vsc_mtx) == 0);
}

ATF_TC_WITHOUT_HEAD(config_bounds);
ATF_TC_BODY(config_bounds, tc)
{
	struct pci_vt9p_softc sc;
	uint8_t config[VT9P_CONFIGSPACESZ];
	uint32_t value;

	memset(&sc, 0, sizeof(sc));
	memset(config, 0, sizeof(config));
	sc.vsc_config = (struct pci_vt9p_config *)config;
	sc.vsc_config->tag_len = 9;
	value = 0;
	ATF_CHECK(pci_vt9p_cfgread(&sc, 0, 2, &value) == 0);
	ATF_CHECK(value == 9);
	ATF_CHECK(pci_vt9p_cfgread(&sc, -1, 1, &value) == EINVAL);
	ATF_CHECK(pci_vt9p_cfgread(&sc, VT9P_CONFIGSPACESZ, 1,
	    &value) == EINVAL);
	ATF_CHECK(pci_vt9p_cfgread(&sc, VT9P_CONFIGSPACESZ - 1, 2,
	    &value) == EINVAL);
	ATF_CHECK(pci_vt9p_cfgread(&sc, 0, 0, &value) == EINVAL);
	ATF_CHECK(pci_vt9p_cfgread(&sc, 0, 3, &value) == EINVAL);
	ATF_CHECK(pci_vt9p_cfgread(&sc, 0, 8, &value) == EINVAL);
}

ATF_TC_WITHOUT_HEAD(option_parser);
ATF_TC_BODY(option_parser, tc)
{
	struct nvlist nvl;

	reset_mocks();
	ATF_REQUIRE(pci_vt9p_legacy_config(&nvl,
	    "hostshare=/tmp/share,ro,transport=modern") == 0);
	ATF_REQUIRE(g_set_count == 4);
	ATF_CHECK(strcmp(g_names[0], "sharename") == 0);
	ATF_CHECK(strcmp(g_values[0], "hostshare") == 0);
	ATF_CHECK(strcmp(g_names[1], "path") == 0);
	ATF_CHECK(strcmp(g_values[1], "/tmp/share") == 0);
	ATF_CHECK(strcmp(g_names[2], "ro") == 0);
	ATF_CHECK(strcmp(g_values[2], "true") == 0);
	ATF_CHECK(strcmp(g_names[3], "transport") == 0);
	ATF_CHECK(strcmp(g_values[3], "modern") == 0);
	ATF_CHECK(pci_vt9p_legacy_config(&nvl, "a=/a,b=/b") == -1);

	reset_mocks();
	ATF_REQUIRE(pci_vt9p_legacy_config(&nvl,
	    "transport=modern,hostshare=/tmp/share") == 0);
	ATF_REQUIRE(g_set_count == 3);
	ATF_CHECK(strcmp(g_names[0], "transport") == 0);
	ATF_CHECK(strcmp(g_values[0], "modern") == 0);
	ATF_CHECK(strcmp(g_names[1], "sharename") == 0);
	ATF_CHECK(strcmp(g_names[2], "path") == 0);
}

ATF_TC_WITHOUT_HEAD(descriptor_lifetime);
ATF_TC_BODY(descriptor_lifetime, tc)
{
	struct pci_vt9p_request *preq;
	struct pci_vt9p_softc sc;
	uintptr_t iov_address, request_end, request_start;

	reset_mocks();
	setup_softc(&sc);
	pci_vt9p_notify(&sc, &sc.vsc_vq);
	ATF_REQUIRE(g_recv_aux != NULL);
	preq = g_recv_aux;
	request_start = (uintptr_t)preq;
	request_end = request_start + sizeof(*preq);
	iov_address = (uintptr_t)&preq->vsr_iov[0];
	ATF_CHECK(iov_address >= request_start);
	ATF_CHECK(iov_address + sizeof(preq->vsr_iov) <= request_end);
	ATF_CHECK(preq->vsr_iov[0].iov_len == 16);
	ATF_CHECK(preq->vsr_iov[1].iov_len == 32);
	free(preq);
	destroy_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(invalid_chains);
ATF_TC_BODY(invalid_chains, tc)
{
	struct pci_vt9p_softc sc;

	reset_mocks();
	setup_softc(&sc);
	g_readable = 2;
	g_writable = 0;
	pci_vt9p_notify(&sc, &sc.vsc_vq);
	ATF_CHECK(g_recv_calls == 0);
	ATF_CHECK(g_rel_calls == 1);
	ATF_CHECK(g_rel_len == 0);
	ATF_CHECK(g_end_calls == 1);
	destroy_softc(&sc);

	reset_mocks();
	setup_softc(&sc);
	g_ordered = false;
	pci_vt9p_notify(&sc, &sc.vsc_vq);
	ATF_CHECK(g_recv_calls == 0);
	ATF_CHECK(g_rel_calls == 1);
	ATF_CHECK(g_rel_len == 0);
	ATF_CHECK(g_end_calls == 1);
	destroy_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(reset_discards_stale_notify);
ATF_TC_BODY(reset_discards_stale_notify, tc)
{
	struct pci_vt9p_softc sc;

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_features = UINT64_MAX;
	g_notify_during_close = &sc;
	ATF_REQUIRE(pthread_mutex_lock(&sc.vsc_mtx) == 0);
	pci_vt9p_reset(&sc);
	ATF_REQUIRE(pthread_mutex_unlock(&sc.vsc_mtx) == 0);
	ATF_CHECK(g_connection_closes == 1);
	ATF_CHECK(g_connection_inits == 1);
	ATF_CHECK(g_recv_calls == 0);
	ATF_CHECK(!sc.vsc_notify_pending);
	ATF_CHECK_EQ(sc.vsc_features, 0);
	destroy_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(rejected_request);
ATF_TC_BODY(rejected_request, tc)
{
	struct pci_vt9p_softc sc;

	reset_mocks();
	setup_softc(&sc);
	g_recv_result = -1;
	pci_vt9p_notify(&sc, &sc.vsc_vq);
	ATF_CHECK(g_recv_calls == 1);
	ATF_CHECK(g_recv_niov == 1);
	ATF_CHECK(g_rel_calls == 1);
	ATF_CHECK(g_rel_len == 0);
	ATF_CHECK(g_end_calls == 1);
	destroy_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(synchronous_completion);
ATF_TC_BODY(synchronous_completion, tc)
{
	struct pci_vt9p_softc sc;

	reset_mocks();
	setup_softc(&sc);
	g_complete_immediately = true;
	ATF_REQUIRE(pthread_mutex_lock(&sc.vsc_mtx) == 0);
	pci_vt9p_notify(&sc, &sc.vsc_vq);
	ATF_REQUIRE(pthread_mutex_unlock(&sc.vsc_mtx) == 0);
	ATF_CHECK(g_recv_calls == 1);
	ATF_CHECK(g_rel_calls == 1);
	ATF_CHECK(g_rel_len == 17);
	ATF_CHECK(g_end_calls == 2);
	destroy_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(stale_completion);
ATF_TC_BODY(stale_completion, tc)
{
	struct pci_vt9p_request *preq;
	struct pci_vt9p_softc sc;
	struct l9p_request req;

	reset_mocks();
	setup_softc(&sc);
	preq = calloc(1, sizeof(*preq));
	ATF_REQUIRE(preq != NULL);
	preq->vsr_sc = &sc;
	preq->vsr_idx = 7;
	preq->vsr_generation = sc.vsc_generation;
	memset(&req, 0, sizeof(req));
	req.lr_aux = preq;
	ATF_REQUIRE(pthread_mutex_lock(&sc.vsc_mtx) == 0);
	pci_vt9p_reset(&sc);
	ATF_REQUIRE(pthread_mutex_unlock(&sc.vsc_mtx) == 0);
	(void)pci_vt9p_send(&req, NULL, 0, 17, NULL);
	ATF_CHECK(g_rel_calls == 0);
	ATF_CHECK(g_end_calls == 0);
	ATF_CHECK(g_connection_closes == 1);
	ATF_CHECK(g_connection_inits == 1);
	ATF_CHECK(sc.vsc_conn == &g_connection);
	destroy_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(queue_reset_preserves_connection);
ATF_TC_BODY(queue_reset_preserves_connection, tc)
{
	struct pci_vt9p_request *preq;
	struct pci_vt9p_softc sc;
	struct l9p_request req;
	uint64_t old_generation;

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_vq.vq_num = 0;
	pci_vt9p_notify(&sc, &sc.vsc_vq);
	ATF_REQUIRE(g_recv_aux != NULL);
	preq = g_recv_aux;
	ATF_CHECK_EQ(sc.vsc_active_requests, 1);
	old_generation = sc.vsc_generation;

	ATF_REQUIRE(pthread_mutex_lock(&sc.vsc_mtx) == 0);
	ATF_CHECK_EQ(pci_vt9p_qreset(&sc, &sc.vsc_vq, 37),
	    EINPROGRESS);
	ATF_REQUIRE(pthread_mutex_unlock(&sc.vsc_mtx) == 0);
	ATF_CHECK(sc.vsc_queue_reset);
	ATF_CHECK(sc.vsc_qreset_pending);
	ATF_CHECK_EQ(sc.vsc_generation, old_generation + 1);
	ATF_CHECK_EQ(g_connection_closes, 0);
	ATF_CHECK_EQ(g_connection_inits, 0);

	memset(&req, 0, sizeof(req));
	req.lr_aux = preq;
	(void)pci_vt9p_send(&req, NULL, 0, 17, NULL);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(sc.vsc_active_requests, 0);
	ATF_CHECK(!sc.vsc_qreset_pending);
	ATF_CHECK_EQ(g_qreset_complete_calls, 1);
	ATF_CHECK_EQ(g_qreset_complete_generation, 37);
	ATF_CHECK_EQ(g_qreset_complete_error, 0);

	ATF_REQUIRE(pthread_mutex_lock(&sc.vsc_mtx) == 0);
	ATF_CHECK_EQ(pci_vt9p_qenable(&sc, &sc.vsc_vq), 0);
	ATF_REQUIRE(pthread_mutex_unlock(&sc.vsc_mtx) == 0);
	ATF_CHECK(!sc.vsc_queue_reset);
	ATF_CHECK(sc.vsc_conn == &g_connection);
	destroy_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(queue_reset_without_requests);
ATF_TC_BODY(queue_reset_without_requests, tc)
{
	struct pci_vt9p_softc sc;
	struct vqueue_info impostor;

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_vq.vq_num = 0;
	impostor = sc.vsc_vq;
	ATF_REQUIRE(pthread_mutex_lock(&sc.vsc_mtx) == 0);
	ATF_CHECK_EQ(pci_vt9p_qreset(&sc, &impostor, 1), EINVAL);
	ATF_CHECK_EQ(pci_vt9p_qreset(&sc, &sc.vsc_vq, 2), 0);
	ATF_CHECK(sc.vsc_queue_reset);
	ATF_CHECK_EQ(pci_vt9p_qenable(&sc, &sc.vsc_vq), 0);
	ATF_REQUIRE(pthread_mutex_unlock(&sc.vsc_mtx) == 0);
	ATF_CHECK(!sc.vsc_queue_reset);
	ATF_CHECK_EQ(g_qreset_complete_calls, 0);
	destroy_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(full_reset_drains_active_request);
ATF_TC_BODY(full_reset_drains_active_request, tc)
{
	struct pci_vt9p_softc sc;

	reset_mocks();
	setup_softc(&sc);
	pci_vt9p_notify(&sc, &sc.vsc_vq);
	ATF_REQUIRE(g_recv_aux != NULL);
	ATF_CHECK_EQ(sc.vsc_active_requests, 1);
	g_drop_during_close = true;

	ATF_REQUIRE(pthread_mutex_lock(&sc.vsc_mtx) == 0);
	pci_vt9p_reset(&sc);
	ATF_REQUIRE(pthread_mutex_unlock(&sc.vsc_mtx) == 0);
	ATF_CHECK_EQ(g_connection_closes, 1);
	ATF_CHECK_EQ(g_connection_inits, 1);
	ATF_CHECK_EQ(sc.vsc_active_requests, 0);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(g_end_calls, 1);
	ATF_CHECK_EQ(g_qreset_complete_calls, 0);
	ATF_CHECK(sc.vsc_conn == &g_connection);
	destroy_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(reset_reinit_failure);
ATF_TC_BODY(reset_reinit_failure, tc)
{
	struct pci_vt9p_softc sc;

	reset_mocks();
	setup_softc(&sc);
	g_connection_init_result = -1;
	ATF_REQUIRE(pthread_mutex_lock(&sc.vsc_mtx) == 0);
	pci_vt9p_reset(&sc);
	ATF_CHECK(sc.vsc_conn == NULL);
	ATF_CHECK(!sc.vsc_resetting);
	ATF_CHECK((sc.vsc_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(g_needs_reset_calls == 1);
	ATF_REQUIRE(pthread_mutex_unlock(&sc.vsc_mtx) == 0);
	ATF_CHECK(g_connection_closes == 1);
	ATF_CHECK(g_connection_inits == 1);
	destroy_softc(&sc);
}

static void *
finish_prior_reset(void *arg)
{
	struct pci_vt9p_softc *sc;
	int error, unlock_error;

	sc = arg;
	error = pthread_mutex_lock(&sc->vsc_mtx);
	if (error != 0)
		return ((void *)(uintptr_t)error);
	sc->vsc_resetting = false;
	error = pthread_cond_broadcast(&sc->vsc_reset_cv);
	unlock_error = pthread_mutex_unlock(&sc->vsc_mtx);
	if (error == 0)
		error = unlock_error;
	return ((void *)(uintptr_t)error);
}

ATF_TC_WITHOUT_HEAD(full_reset_waits_for_prior_reconnect);
ATF_TC_BODY(full_reset_waits_for_prior_reconnect, tc)
{
	struct pci_vt9p_softc sc;
	pthread_t thread;
	void *result;

	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_lock(&sc.vsc_mtx) == 0);
	sc.vsc_resetting = true;
	ATF_REQUIRE(pthread_create(&thread, NULL, finish_prior_reset, &sc) == 0);

	pci_vt9p_reset(&sc);

	ATF_REQUIRE(pthread_mutex_unlock(&sc.vsc_mtx) == 0);
	ATF_REQUIRE(pthread_join(thread, &result) == 0);
	ATF_REQUIRE(result == NULL);
	ATF_CHECK_EQ(g_connection_closes, 1);
	ATF_CHECK_EQ(g_connection_inits, 1);
	ATF_CHECK(!sc.vsc_resetting);
	ATF_CHECK(sc.vsc_conn == &g_connection);
	destroy_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(virtio_1_4_wire_layout);
ATF_TC_BODY(virtio_1_4_wire_layout, tc)
{

	ATF_CHECK_EQ(sizeof(struct pci_vt9p_config),
	    VIRTIO14_9P_CONFIG_TAG_LEN_SIZE);
	ATF_CHECK_EQ(offsetof(struct pci_vt9p_config, tag_len),
	    VIRTIO14_9P_CONFIG_TAG_LEN_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vt9p_config, tag),
	    VIRTIO14_9P_CONFIG_TAG_LEN_SIZE);
}

ATF_TC_WITHOUT_HEAD(modern_mount_tag_wire_bytes);
ATF_TC_BODY(modern_mount_tag_wire_bytes, tc)
{
	struct pci_vt9p_softc sc;
	uint8_t config[VT9P_CONFIGSPACESZ];
	char tag[VT9P_MAXTAGSZ + 1];

	/*
	 * Section 2.7 requires non-legacy device configuration fields to be
	 * little-endian.  A 256-byte tag makes both length bytes observable;
	 * the expected bytes are a document-derived vector, not a serialized
	 * DUT structure.
	 */
	memset(&sc, 0, sizeof(sc));
	memset(config, 0, sizeof(config));
	memset(tag, 'x', sizeof(tag) - 1);
	tag[sizeof(tag) - 1] = '\0';
	sc.vsc_config = (struct pci_vt9p_config *)(void *)config;
	sc.vsc_vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	pci_vt9p_set_tag(&sc, tag);

	ATF_CHECK_EQ(config[VIRTIO14_9P_CONFIG_TAG_LEN_OFF], 0x00);
	ATF_CHECK_EQ(config[VIRTIO14_9P_CONFIG_TAG_LEN_OFF + 1], 0x01);
	ATF_CHECK_EQ(config[VIRTIO14_9P_CONFIG_TAG_LEN_SIZE], (uint8_t)'x');
	ATF_CHECK_EQ(config[VIRTIO14_9P_CONFIG_TAG_LEN_SIZE +
	    VT9P_MAXTAGSZ - 1], (uint8_t)'x');
}

ATF_TC_WITHOUT_HEAD(queue_reset_contract);
ATF_TC_BODY(queue_reset_contract, tc)
{

	ATF_CHECK(vt9p_vi_consts.vc_qreset == pci_vt9p_qreset);
	ATF_CHECK(vt9p_vi_consts.vc_qenable == pci_vt9p_qenable);
	ATF_CHECK((vt9p_vi_consts.vc_hv_caps & VIRTIO_F_RING_RESET) != 0);
	ATF_CHECK_EQ(vt9p_vi_consts.vc_hv_caps,
	    VIRTIO14_9P_F_MOUNT_TAG | VIRTIO14_F_RING_RESET);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, config_bounds);
	ATF_TP_ADD_TC(tp, option_parser);
	ATF_TP_ADD_TC(tp, descriptor_lifetime);
	ATF_TP_ADD_TC(tp, invalid_chains);
	ATF_TP_ADD_TC(tp, reset_discards_stale_notify);
	ATF_TP_ADD_TC(tp, rejected_request);
	ATF_TP_ADD_TC(tp, synchronous_completion);
	ATF_TP_ADD_TC(tp, stale_completion);
	ATF_TP_ADD_TC(tp, queue_reset_preserves_connection);
	ATF_TP_ADD_TC(tp, queue_reset_without_requests);
	ATF_TP_ADD_TC(tp, full_reset_drains_active_request);
	ATF_TP_ADD_TC(tp, reset_reinit_failure);
	ATF_TP_ADD_TC(tp, full_reset_waits_for_prior_reconnect);
	ATF_TP_ADD_TC(tp, virtio_1_4_wire_layout);
	ATF_TP_ADD_TC(tp, modern_mount_tag_wire_bytes);
	ATF_TP_ADD_TC(tp, queue_reset_contract);
	return (atf_no_error());
}
