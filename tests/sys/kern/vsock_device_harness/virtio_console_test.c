/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Fault-injection tests for bhyve's VirtIO console device.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "iov.c"
#include "pci_virtio_console.c"
#include "virtio_1_4_spec.h"
#include "virtio_1_4_wire.h"

/*
 * The device above is compiled against production definitions.  From this
 * point onward, protocol expectations come from the independent 1.4 oracle.
 */
#undef VIRTIO_F_IN_ORDER
#define	VIRTIO_F_IN_ORDER	VIRTIO14_F_IN_ORDER
#undef VIRTIO_F_RING_RESET
#define	VIRTIO_F_RING_RESET	VIRTIO14_F_RING_RESET
#undef VIRTIO_ID_CONSOLE
#define	VIRTIO_ID_CONSOLE	VIRTIO14_DEVICE_CONSOLE
#undef VTCON_F_SIZE
#define	VTCON_F_SIZE		VIRTIO14_CONSOLE_F_SIZE_BIT
#undef VTCON_F_MULTIPORT
#define	VTCON_F_MULTIPORT	VIRTIO14_CONSOLE_F_MULTIPORT_BIT
#undef VTCON_F_EMERG_WRITE
#define	VTCON_F_EMERG_WRITE	VIRTIO14_CONSOLE_F_EMERG_WRITE_BIT
#undef VTCON_DEVICE_READY
#define	VTCON_DEVICE_READY	VIRTIO14_CONSOLE_DEVICE_READY
#undef VTCON_DEVICE_ADD
#define	VTCON_DEVICE_ADD	VIRTIO14_CONSOLE_DEVICE_ADD
#undef VTCON_PORT_READY
#define	VTCON_PORT_READY	VIRTIO14_CONSOLE_PORT_READY
#undef VTCON_CONSOLE_PORT
#define	VTCON_CONSOLE_PORT	VIRTIO14_CONSOLE_CONSOLE_PORT
#undef VTCON_PORT_OPEN
#define	VTCON_PORT_OPEN		VIRTIO14_CONSOLE_PORT_OPEN
#undef VTCON_PORT_NAME
#define	VTCON_PORT_NAME		VIRTIO14_CONSOLE_PORT_NAME

struct nvlist {
	int unused;
};

struct mevent {
	int unused;
};

static const char *g_transport;
static char g_set_name[16][32];
static char g_set_value[16][128];
static int g_set_count;
static int g_modern_identity;
static int g_modern_bar;
static int g_io_bar;
static int g_descs;
static int g_chain_n;
static int g_readable;
static int g_writable;
static struct iovec g_chain_iov[4];
static bool g_distinct_chain_ids;
static int g_get_calls;
static int g_rel_calls;
static uint16_t g_rel_order[4];
static uint32_t g_rel_len;
static int g_end_calls;
static int g_ret_calls;
static int g_enable_calls;
static int g_disable_calls;
static int g_callback_calls;
static int g_callback_niov;
static uint8_t g_callback_byte;
static int g_send_override_fd;
static ssize_t g_send_result;
static int g_send_errno;
static int g_send_flags;
static bool g_realloc_fail;

static void
reset_mocks(void)
{
	g_transport = NULL;
	g_set_count = 0;
	g_modern_identity = -1;
	g_modern_bar = -1;
	g_io_bar = -1;
	g_descs = 1;
	g_chain_n = 1;
	g_readable = 1;
	g_writable = 0;
	memset(g_chain_iov, 0, sizeof(g_chain_iov));
	g_distinct_chain_ids = false;
	g_get_calls = 0;
	g_rel_calls = 0;
	memset(g_rel_order, 0, sizeof(g_rel_order));
	g_rel_len = UINT32_MAX;
	g_end_calls = 0;
	g_ret_calls = 0;
	g_enable_calls = 0;
	g_disable_calls = 0;
	g_callback_calls = 0;
	g_callback_niov = 0;
	g_callback_byte = 0;
	g_send_override_fd = -1;
	g_send_result = 0;
	g_send_errno = 0;
	g_send_flags = 0;
	g_realloc_fail = false;
}

ssize_t __real_send(int, const void *, size_t, int);
ssize_t __wrap_send(int, const void *, size_t, int);
void *__real_realloc(void *, size_t);
void *__wrap_realloc(void *, size_t);

ssize_t
__wrap_send(int fd, const void *buf, size_t len, int flags)
{

	if (fd != g_send_override_fd)
		return (__real_send(fd, buf, len, flags));
	g_send_flags = flags;
	if (g_send_result < 0)
		errno = g_send_errno;
	return (g_send_result);
}

void *
__wrap_realloc(void *ptr, size_t size)
{

	if (g_realloc_fail) {
		g_realloc_fail = false;
		return (NULL);
	}
	return (__real_realloc(ptr, size));
}

const char *
get_config_value_node(const nvlist_t *nvl __unused, const char *name)
{
	return (strcmp(name, "transport") == 0 ? g_transport : NULL);
}

void
set_config_value_node(nvlist_t *nvl __unused, const char *name,
    const char *value)
{
	ATF_REQUIRE(g_set_count < (int)nitems(g_set_name));
	ATF_REQUIRE(strlcpy(g_set_name[g_set_count], name,
	    sizeof(g_set_name[0])) < sizeof(g_set_name[0]));
	ATF_REQUIRE(strlcpy(g_set_value[g_set_count], value,
	    sizeof(g_set_value[0])) < sizeof(g_set_value[0]));
	g_set_count++;
}

int
pci_parse_legacy_config(nvlist_t *nvl __unused, const char *opts __unused)
{
	return (0);
}

nvlist_t *
create_relative_config_node(nvlist_t *nvl, const char *name __unused)
{
	return (nvl);
}

nvlist_t *
find_relative_config_node(nvlist_t *nvl __unused, const char *name __unused)
{
	return (NULL);
}

const char *
nvlist_next(const nvlist_t *nvl __unused, int *type __unused,
    void **cookie __unused)
{
	return (NULL);
}

const nvlist_t *
nvlist_get_nvlist(const nvlist_t *nvl, const char *name __unused)
{
	return (nvl);
}

struct mevent *
mevent_add(int fd __unused, enum ev_type type __unused,
    void (*cb)(int, enum ev_type, void *) __unused, void *arg __unused)
{
	static struct mevent ev;

	return (&ev);
}

struct mevent *
mevent_add_disabled(int fd __unused, enum ev_type type __unused,
    void (*cb)(int, enum ev_type, void *) __unused, void *arg __unused)
{
	static struct mevent ev;

	return (&ev);
}

int
mevent_enable(struct mevent *ev __unused)
{
	g_enable_calls++;
	return (0);
}

int
mevent_disable(struct mevent *ev __unused)
{
	g_disable_calls++;
	return (0);
}

int mevent_delete(struct mevent *ev __unused) { return (0); }
int mevent_delete_close(struct mevent *ev __unused) { return (0); }

int
stream_write(int fd, const void *buf, int len)
{
	return ((int)write(fd, buf, len));
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
	if (g_chain_n <= 0)
		return (g_chain_n);
	ATF_REQUIRE(g_chain_n <= niov);
	memcpy(iov, g_chain_iov, g_chain_n * sizeof(*iov));
	req->idx = g_distinct_chain_ids ? 10 + g_get_calls : 7;
	req->readable = g_readable;
	req->writable = g_writable;
	g_get_calls++;
	g_descs--;
	return (g_chain_n);
}

void
vq_retchains(struct vqueue_info *vq __unused, uint16_t count)
{
	g_ret_calls += count;
}

void
vq_relchain(struct vqueue_info *vq __unused, uint16_t idx, uint32_t len)
{
	if (!g_distinct_chain_ids)
		ATF_CHECK(idx == 7);
	ATF_REQUIRE(g_rel_calls < (int)nitems(g_rel_order));
	g_rel_order[g_rel_calls] = idx;
	g_rel_calls++;
	g_rel_len = len;
}

void
vq_endchains(struct vqueue_info *vq __unused, int all_avail __unused)
{
	g_end_calls++;
}

void
vi_softc_linkup(struct virtio_softc *vs, struct virtio_consts *vc,
    void *softc __unused, struct pci_devinst *pi, struct vqueue_info *queues)
{
	memset(vs, 0, sizeof(*vs));
	vs->vs_vc = vc;
	vs->vs_pi = pi;
	vs->vs_queues = queues;
	pi->pi_arg = vs;
	for (int i = 0; i < vc->vc_nvq; i++) {
		queues[i].vq_vs = vs;
		queues[i].vq_num = i;
	}
}

int
vi_pci_select_transport(struct virtio_softc *vs,
    const nvlist_t *nvl __unused, enum virtio_pci_transport_policy policy)
{
	ATF_CHECK(policy == VIRTIO_PCI_LEGACY_DEFAULT);
	if (g_transport == NULL || strcmp(g_transport, "legacy") == 0)
		vs->vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	else if (strcmp(g_transport, "modern") == 0)
		vs->vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	else
		return (-1);
	return (0);
}

bool
vi_pci_is_modern(const struct virtio_softc *vs)
{
	return (vs->vs_transport == VIRTIO_PCI_TRANSPORT_MODERN);
}

void
vi_pci_modern_set_identity(struct virtio_softc *vs __unused, uint16_t id)
{
	g_modern_identity = id;
}

int
vi_pci_modern_init(struct virtio_softc *vs __unused, int bar)
{
	g_modern_bar = bar;
	return (0);
}

int vi_intr_init(struct virtio_softc *vs __unused, int bar __unused,
    int msix __unused) { return (0); }
void vi_set_io_bar(struct virtio_softc *vs __unused, int bar)
{ g_io_bar = bar; }
void vi_reset_dev(struct virtio_softc *vs __unused) {}
int fbsdrun_virtio_msix(void) { return (1); }
int vi_pci_modern_cfgread(struct pci_devinst *pi __unused,
    int off __unused, int size __unused, uint32_t *val __unused) { return (0); }
int vi_pci_modern_cfgwrite(struct pci_devinst *pi __unused,
    int off __unused, int size __unused, uint32_t val __unused) { return (0); }
uint64_t vi_pci_read(struct pci_devinst *pi __unused, int bar __unused,
    uint64_t off __unused, int size __unused) { return (0); }
void vi_pci_write(struct pci_devinst *pi __unused, int bar __unused,
    uint64_t off __unused, int size __unused, uint64_t val __unused) {}
void pci_set_cfgdata8(struct pci_devinst *pi, int off, uint8_t val)
{ pi->pi_cfgdata[off] = val; }
void pci_set_cfgdata16(struct pci_devinst *pi, int off, uint16_t val)
{ memcpy(&pi->pi_cfgdata[off], &val, sizeof(val)); }

static void
capture_cb(struct pci_vtcon_port *port __unused, void *arg __unused,
    struct iovec *iov, int niov)
{
	g_callback_calls++;
	g_callback_niov = niov;
	if (niov > 0 && iov[0].iov_len > 0)
		g_callback_byte = *(const uint8_t *)iov[0].iov_base;
}

static void
free_softc(struct pci_devinst *pi)
{
	struct pci_vtcon_softc *sc;

	sc = pi->pi_arg;
	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc->vsc_config);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(transport_and_features);
ATF_TC_BODY(transport_and_features, tc)
{
	struct pci_devinst pi;
	struct nvlist nvl;
	struct pci_vtcon_softc *sc;
	const uint8_t config_bytes[] = {
		0x50, 0x00, 0x19, 0x00,
		0x10, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	};
	uint32_t val;

	ATF_CHECK(vtcon_vi_consts.vc_hv_caps ==
	    ((1ULL << VTCON_F_SIZE) | (1ULL << VTCON_F_MULTIPORT) |
	    (1ULL << VTCON_F_EMERG_WRITE) |
	    VIRTIO_F_IN_ORDER | VIRTIO_F_RING_RESET));
	ATF_CHECK((vtcon_vi_consts.vc_hv_caps &
	    (1ULL << VTCON_F_EMERG_WRITE)) != 0);

	memset(&pi, 0, sizeof(pi));
	reset_mocks();
	ATF_REQUIRE(pci_vtcon_init(&pi, &nvl) == 0);
	ATF_CHECK(g_io_bar == 0 && g_modern_bar == -1);
	ATF_CHECK(pi.pi_cfgdata[PCIR_DEVICE] ==
	    (VIRTIO14_PCI_TRANSITIONAL_CONSOLE & 0xff));
	ATF_CHECK(pi.pi_cfgdata[PCIR_DEVICE + 1] ==
	    (VIRTIO14_PCI_TRANSITIONAL_CONSOLE >> 8));
	free_softc(&pi);

	memset(&pi, 0, sizeof(pi));
	reset_mocks();
	g_transport = "modern";
	ATF_REQUIRE(pci_vtcon_init(&pi, &nvl) == 0);
	ATF_CHECK(g_modern_identity == VIRTIO_ID_CONSOLE);
	ATF_CHECK(g_modern_bar == 2 && g_io_bar == -1);
	sc = pi.pi_arg;
	ATF_CHECK(memcmp(sc->vsc_config, config_bytes,
	    sizeof(config_bytes)) == 0);
	val = UINT32_MAX;
	ATF_CHECK(pci_vtcon_cfgread(sc, 0, 2, &val) == 0);
	ATF_CHECK(val == 80);
	ATF_CHECK(pci_vtcon_cfgread(sc, -1, 1, &val) == -1);
	ATF_CHECK(pci_vtcon_cfgread(sc, VIRTIO14_CONSOLE_CONFIG_SIZE, 1,
	    &val) == -1);
	ATF_CHECK(pci_vtcon_cfgread(sc, 0, 0, &val) == -1);
	ATF_CHECK(pci_vtcon_cfgread(sc, 0, 3, &val) == -1);
	ATF_CHECK(pci_vtcon_cfgread(sc,
	    VIRTIO14_CONSOLE_CONFIG_SIZE - 1, 4,
	    &val) == -1);
	ATF_CHECK(pci_vtcon_cfgwrite(sc, 0, 4, 1) == -1);
	ATF_CHECK(pci_vtcon_cfgwrite(sc,
	    VIRTIO14_CONSOLE_CONFIG_EMERG_WR_OFF, 4, 'x') == 0);
	free_softc(&pi);
}

ATF_TC_WITHOUT_HEAD(in_order_completion);
ATF_TC_BODY(in_order_completion, tc)
{
	struct pci_vtcon_softc sc;
	struct vqueue_info *vq;
	uint8_t data;
	int i;

	memset(&sc, 0, sizeof(sc));
	vq = &sc.vsc_queues[1];
	vq->vq_num = 1;
	sc.vsc_ports[0].vsp_enabled = true;
	sc.vsc_ports[0].vsp_cb = capture_cb;
	reset_mocks();
	g_descs = 3;
	g_distinct_chain_ids = true;
	g_chain_iov[0] = (struct iovec){
		.iov_base = &data, .iov_len = sizeof(data),
	};

	pci_vtcon_notify_tx(&sc, vq);
	ATF_CHECK((vtcon_vi_consts.vc_hv_caps & VIRTIO_F_IN_ORDER) != 0);
	ATF_CHECK_EQ(g_callback_calls, 3);
	ATF_CHECK_EQ(g_rel_calls, 3);
	for (i = 0; i < 3; i++) {
		ATF_CHECK_EQ(g_rel_order[i], 10 + i);
	}
	ATF_CHECK_EQ(g_rel_len, 0);
}

ATF_TC_WITHOUT_HEAD(emergency_write);
ATF_TC_BODY(emergency_write, tc)
{
	struct pci_vtcon_config config;
	struct pci_vtcon_softc sc;

	memset(&config, 0, sizeof(config));
	memset(&sc, 0, sizeof(sc));
	sc.vsc_config = &config;
	sc.vsc_ports[0].vsp_enabled = true;
	sc.vsc_ports[0].vsp_cb = capture_cb;
	reset_mocks();

	/*
	 * No negotiated features or initialized queue are needed for emergency
	 * output.  Only a complete emerg_wr field access is accepted.
	 */
	ATF_CHECK(pci_vtcon_cfgwrite(&sc,
	    VIRTIO14_CONSOLE_CONFIG_EMERG_WR_OFF, 4,
	    0x12345641) == 0);
	ATF_CHECK(g_callback_calls == 1 && g_callback_niov == 1);
	ATF_CHECK_EQ(g_callback_byte, 'A');
	ATF_CHECK_EQ(config.emerg_wr, 0x12345641);

	ATF_CHECK(pci_vtcon_cfgwrite(&sc,
	    VIRTIO14_CONSOLE_CONFIG_EMERG_WR_OFF, 2, 'B') == -1);
	ATF_CHECK(pci_vtcon_cfgwrite(&sc,
	    VIRTIO14_CONSOLE_CONFIG_EMERG_WR_OFF - 1, 4, 'C') == -1);
	ATF_CHECK(g_callback_calls == 1);

	sc.vsc_ports[0].vsp_enabled = false;
	ATF_CHECK(pci_vtcon_cfgwrite(&sc,
	    VIRTIO14_CONSOLE_CONFIG_EMERG_WR_OFF, 4, 'D') == 0);
	ATF_CHECK(g_callback_calls == 1);
}

ATF_TC_WITHOUT_HEAD(queue_reset_isolated);
ATF_TC_BODY(queue_reset_isolated, tc)
{
	struct pci_vtcon_softc sc;

	memset(&sc, 0, sizeof(sc));
	sc.vsc_ports[0].vsp_rx_ready = true;
	sc.vsc_ports[1].vsp_rx_ready = true;
	sc.vsc_queues[0].vq_num = 0;
	sc.vsc_queues[1].vq_num = 1;
	sc.vsc_queues[4].vq_num = 4;

	ATF_CHECK_EQ(pci_vtcon_qreset(&sc, &sc.vsc_queues[1], 1), 0);
	ATF_CHECK(sc.vsc_ports[0].vsp_rx_ready);
	ATF_CHECK(sc.vsc_ports[1].vsp_rx_ready);

	ATF_CHECK_EQ(pci_vtcon_qreset(&sc, &sc.vsc_queues[0], 2), 0);
	ATF_CHECK(!sc.vsc_ports[0].vsp_rx_ready);
	ATF_CHECK(sc.vsc_ports[1].vsp_rx_ready);

	ATF_CHECK_EQ(pci_vtcon_qreset(&sc, &sc.vsc_queues[4], 3), 0);
	ATF_CHECK(!sc.vsc_ports[1].vsp_rx_ready);

	sc.vsc_queues[0].vq_num = VTCON_MAXQ;
	ATF_CHECK_EQ(pci_vtcon_qreset(&sc, &sc.vsc_queues[0], 4), EINVAL);
}

ATF_TC_WITHOUT_HEAD(legacy_parser_transport);
ATF_TC_BODY(legacy_parser_transport, tc)
{
	struct nvlist nvl;

	reset_mocks();
	ATF_REQUIRE(pci_vtcon_legacy_config(&nvl,
	    "agent=/tmp/a,transport=modern,other=/tmp/b") == 0);
	ATF_CHECK(g_set_count == 5);
	ATF_CHECK(strcmp(g_set_name[2], "transport") == 0);
	ATF_CHECK(strcmp(g_set_value[2], "modern") == 0);
	ATF_CHECK(strcmp(g_set_value[3], "other") == 0);
	ATF_CHECK(pci_vtcon_legacy_config(&nvl, NULL) == 0);
}

ATF_TC_WITHOUT_HEAD(control_validation);
ATF_TC_BODY(control_validation, tc)
{
	struct pci_vtcon_softc sc;
	struct iovec iov[2];
	uint8_t ready[VIRTIO14_CONSOLE_CONTROL_SIZE];
	uint8_t unknown[VIRTIO14_CONSOLE_CONTROL_SIZE];

	memset(&sc, 0, sizeof(sc));
	memset(ready, 0, sizeof(ready));
	virtio14_store_le16(ready + VIRTIO14_CONSOLE_CONTROL_EVENT_OFF,
	    VIRTIO14_CONSOLE_DEVICE_READY);
	virtio14_store_le16(ready + VIRTIO14_CONSOLE_CONTROL_VALUE_OFF, 1);
	memset(unknown, 0, sizeof(unknown));
	virtio14_store_le32(unknown + VIRTIO14_CONSOLE_CONTROL_ID_OFF,
	    UINT32_MAX);
	virtio14_store_le16(unknown + VIRTIO14_CONSOLE_CONTROL_EVENT_OFF,
	    VIRTIO14_CONSOLE_PORT_READY);
	virtio14_store_le16(unknown + VIRTIO14_CONSOLE_CONTROL_VALUE_OFF, 1);
	sc.vsc_vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	sc.vsc_control_port.vsp_sc = &sc;
	sc.vsc_control_port.vsp_rxq = 3;
	sc.vsc_features = 1ULL << VTCON_F_MULTIPORT;
	iov[0] = (struct iovec){ .iov_base = unknown, .iov_len = 3 };
	iov[1] = (struct iovec){
		.iov_base = unknown + 3,
		.iov_len = sizeof(unknown) - 3,
	};
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, iov, 2);
	ATF_CHECK(!sc.vsc_ready);
	iov[1].iov_len--;
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, iov, 2);
	ATF_CHECK(!sc.vsc_ready);

	virtio14_store_le16(ready + VIRTIO14_CONSOLE_CONTROL_VALUE_OFF, 0);
	iov[0] = (struct iovec){ .iov_base = ready, .iov_len = sizeof(ready) };
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, iov, 1);
	ATF_CHECK(!sc.vsc_ready);
	virtio14_store_le16(ready + VIRTIO14_CONSOLE_CONTROL_VALUE_OFF, 1);
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, iov, 1);
	ATF_CHECK(sc.vsc_ready);
}

ATF_TC_WITHOUT_HEAD(document_wire_vectors);
ATF_TC_BODY(document_wire_vectors, tc)
{
	struct pci_vtcon_softc sc;
	struct iovec iov;
	uint8_t control[VIRTIO14_CONSOLE_CONTROL_SIZE];

	memset(&sc, 0, sizeof(sc));
	memset(control, 0, sizeof(control));
	sc.vsc_control_port.vsp_sc = &sc;
	sc.vsc_control_port.vsp_rxq = 3;
	sc.vsc_features = VIRTIO14_CONSOLE_F_MULTIPORT;

	virtio14_store_le32(control + VIRTIO14_CONSOLE_CONTROL_ID_OFF,
	    UINT32_C(0x11223344));
	virtio14_store_le16(control + VIRTIO14_CONSOLE_CONTROL_EVENT_OFF,
	    VIRTIO14_CONSOLE_DEVICE_READY);
	virtio14_store_le16(control + VIRTIO14_CONSOLE_CONTROL_VALUE_OFF, 1);
	iov = (struct iovec){
		.iov_base = control,
		.iov_len = sizeof(control),
	};

	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, &iov, 1);
	ATF_CHECK(sc.vsc_ready);
}

ATF_TC_WITHOUT_HEAD(transmit_validation);
ATF_TC_BODY(transmit_validation, tc)
{
	struct pci_vtcon_softc sc;
	struct vqueue_info *vq;
	uint8_t a[4], b[7];

	memset(&sc, 0, sizeof(sc));
	sc.vsc_features = 1ULL << VTCON_F_MULTIPORT;
	vq = &sc.vsc_queues[4];
	vq->vq_num = 4;
	sc.vsc_ports[1].vsp_enabled = true;
	sc.vsc_ports[1].vsp_cb = capture_cb;
	reset_mocks();
	g_chain_n = 2;
	g_readable = 2;
	g_chain_iov[0] = (struct iovec){ .iov_base = a, .iov_len = sizeof(a) };
	g_chain_iov[1] = (struct iovec){ .iov_base = b, .iov_len = sizeof(b) };
	pci_vtcon_notify_tx(&sc, vq);
	ATF_CHECK(g_callback_calls == 1 && g_callback_niov == 2);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 0);

	reset_mocks();
	g_readable = 0;
	g_writable = 1;
	g_chain_iov[0] = (struct iovec){ .iov_base = a, .iov_len = sizeof(a) };
	pci_vtcon_notify_tx(&sc, vq);
	ATF_CHECK(g_callback_calls == 0);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 0);

	reset_mocks();
	pci_vtcon_notify_tx(&sc, &sc.vsc_queues[6]);
	ATF_CHECK(g_callback_calls == 0 && g_rel_calls == 1);
}

ATF_TC_WITHOUT_HEAD(control_receive_scatter);
ATF_TC_BODY(control_receive_scatter, tc)
{
	struct pci_vtcon_softc sc;
	struct pci_vtcon_control ctrl;
	const uint8_t expected[] = {
		0x78, 0x56, 0x34, 0x12,
		0x01, 0x00,
		0xcd, 0xab,
	};
	uint8_t a[3], b[sizeof(expected) - sizeof(a)], got[sizeof(expected)];

	memset(&sc, 0, sizeof(sc));
	sc.vsc_vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	sc.vsc_control_port.vsp_sc = &sc;
	sc.vsc_control_port.vsp_txq = 2;
	sc.vsc_features = 1ULL << VTCON_F_MULTIPORT;
	reset_mocks();
	g_chain_n = 2;
	g_readable = 0;
	g_writable = 2;
	g_chain_iov[0] = (struct iovec){ .iov_base = a, .iov_len = sizeof(a) };
	g_chain_iov[1] = (struct iovec){ .iov_base = b, .iov_len = sizeof(b) };
	ctrl = (struct pci_vtcon_control){
		.id = 0x12345678, .event = VIRTIO14_CONSOLE_DEVICE_ADD,
		.value = 0xabcd,
	};
	pci_vtcon_control_send(&sc, &ctrl, NULL, 0);
	memcpy(&got, a, sizeof(a));
	memcpy(got + sizeof(a), b, sizeof(b));
	ATF_CHECK(memcmp(got, expected, sizeof(got)) == 0);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == sizeof(expected));

	reset_mocks();
	g_readable = 1;
	g_writable = 0;
	g_chain_iov[0] = (struct iovec){ .iov_base = a, .iov_len = sizeof(a) };
	pci_vtcon_control_send(&sc, &ctrl, NULL, 0);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 0);
}

ATF_TC_WITHOUT_HEAD(multiport_feature_gating);
ATF_TC_BODY(multiport_feature_gating, tc)
{
	struct pci_vtcon_softc sc;
	struct pci_vtcon_control ctrl;
	struct iovec iov;
	uint8_t data;

	memset(&sc, 0, sizeof(sc));
	sc.vsc_control_port.vsp_sc = &sc;
	sc.vsc_control_port.vsp_txq = 2;
	sc.vsc_control_port.vsp_rxq = 3;
	sc.vsc_queues[2].vq_num = 2;
	sc.vsc_queues[3].vq_num = 3;
	sc.vsc_queues[4].vq_num = 4;
	ctrl = (struct pci_vtcon_control){
		.event = VTCON_DEVICE_READY, .value = 1,
	};
	iov = (struct iovec){
		.iov_base = &ctrl,
		.iov_len = VIRTIO14_CONSOLE_CONTROL_SIZE,
	};

	reset_mocks();
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, &iov, 1);
	ATF_CHECK(!sc.vsc_ready);

	reset_mocks();
	g_chain_iov[0] = (struct iovec){
		.iov_base = &data, .iov_len = sizeof(data),
	};
	pci_vtcon_notify_tx(&sc, &sc.vsc_queues[4]);
	ATF_CHECK(g_callback_calls == 0);
	ATF_CHECK(g_rel_calls == 0);

	reset_mocks();
	g_readable = 0;
	g_writable = 1;
	g_chain_iov[0] = (struct iovec){
		.iov_base = &data, .iov_len = sizeof(data),
	};
	pci_vtcon_control_send(&sc, &ctrl, NULL, 0);
	ATF_CHECK(g_rel_calls == 0);

	pci_vtcon_neg_features(&sc, 1ULL << VTCON_F_MULTIPORT);
	reset_mocks();
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, &iov, 1);
	ATF_CHECK(sc.vsc_ready);

	pci_vtcon_neg_features(&sc, 0);
	ATF_CHECK(!sc.vsc_ready);
}

ATF_TC_WITHOUT_HEAD(device_add_lifecycle);
ATF_TC_BODY(device_add_lifecycle, tc)
{
	struct pci_vtcon_softc sc;
	struct pci_vtcon_control ctrl;
	struct iovec iov;
	uint8_t output[64];

	memset(&sc, 0, sizeof(sc));
	sc.vsc_control_port.vsp_sc = &sc;
	sc.vsc_control_port.vsp_txq = 2;
	sc.vsc_control_port.vsp_rxq = 3;
	sc.vsc_ports[0].vsp_sc = &sc;
	sc.vsc_ports[0].vsp_enabled = true;
	sc.vsc_ports[0].vsp_id = 0;
	sc.vsc_ports[0].vsp_name = "console";
	ctrl = (struct pci_vtcon_control){
		.event = VTCON_DEVICE_READY, .value = 1,
	};
	iov = (struct iovec){
		.iov_base = &ctrl,
		.iov_len = VIRTIO14_CONSOLE_CONTROL_SIZE,
	};
	pci_vtcon_neg_features(&sc, 1ULL << VTCON_F_MULTIPORT);

	reset_mocks();
	g_descs = 4;
	g_readable = 0;
	g_writable = 1;
	g_chain_iov[0] = (struct iovec){
		.iov_base = output, .iov_len = sizeof(output),
	};
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, &iov, 1);
	ATF_CHECK(sc.vsc_ports[0].vsp_announced);
	ATF_CHECK(!sc.vsc_ports[0].vsp_guest_ready);
	ATF_CHECK(!sc.vsc_ports[0].vsp_named);
	ATF_CHECK_EQ(g_rel_calls, 1);

	/* DEVICE_READY is idempotent within one device incarnation. */
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, &iov, 1);
	ATF_CHECK_EQ(g_rel_calls, 1);

	/* A failed-ready transition does not remove an existing guest port. */
	ctrl.value = 0;
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, &iov, 1);
	ctrl.value = 1;
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, &iov, 1);
	ATF_CHECK_EQ(g_rel_calls, 1);

	/*
	 * Section 5.3.5: additional port configuration follows the driver's
	 * PORT_READY acknowledgement, not DEVICE_READY.
	 */
	ctrl = (struct pci_vtcon_control){
		.id = 0, .event = VIRTIO14_CONSOLE_PORT_READY, .value = 1,
	};
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, &iov, 1);
	ATF_CHECK(sc.vsc_ports[0].vsp_guest_ready);
	ATF_CHECK(sc.vsc_ports[0].vsp_named);
	ATF_CHECK_EQ(g_rel_calls, 2);

	/* A full device reset starts a new port lifecycle. */
	pci_vtcon_reset(&sc);
	ATF_CHECK(!sc.vsc_ports[0].vsp_announced);
	pci_vtcon_neg_features(&sc, 1ULL << VTCON_F_MULTIPORT);
	ctrl = (struct pci_vtcon_control){
		.event = VIRTIO14_CONSOLE_DEVICE_READY, .value = 1,
	};
	reset_mocks();
	g_descs = 2;
	g_readable = 0;
	g_writable = 1;
	g_chain_iov[0] = (struct iovec){
		.iov_base = output, .iov_len = sizeof(output),
	};
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, &iov, 1);
	ATF_CHECK(sc.vsc_ports[0].vsp_announced);
	ATF_CHECK(!sc.vsc_ports[0].vsp_guest_ready);
	ATF_CHECK(!sc.vsc_ports[0].vsp_named);
	ATF_CHECK_EQ(g_rel_calls, 1);

	/* A rejected DEVICE_ADD remains retryable. */
	pci_vtcon_reset(&sc);
	pci_vtcon_neg_features(&sc, 1ULL << VTCON_F_MULTIPORT);
	ctrl = (struct pci_vtcon_control){
		.event = VIRTIO14_CONSOLE_DEVICE_READY, .value = 1,
	};
	reset_mocks();
	g_readable = 1;
	g_writable = 0;
	g_chain_iov[0] = (struct iovec){
		.iov_base = output, .iov_len = sizeof(output),
	};
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, &iov, 1);
	ATF_CHECK(!sc.vsc_ports[0].vsp_announced);
	ATF_CHECK_EQ(g_rel_calls, 1);

	reset_mocks();
	g_descs = 2;
	g_readable = 0;
	g_writable = 1;
	g_chain_iov[0] = (struct iovec){
		.iov_base = output, .iov_len = sizeof(output),
	};
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, &iov, 1);
	ATF_CHECK(sc.vsc_ports[0].vsp_announced);
	ATF_CHECK(!sc.vsc_ports[0].vsp_named);
	ATF_CHECK_EQ(g_rel_calls, 1);
}

ATF_TC_WITHOUT_HEAD(device_add_name_retry);
ATF_TC_BODY(device_add_name_retry, tc)
{
	struct pci_vtcon_softc sc;
	struct pci_vtcon_control ctrl, event;
	struct iovec iov;
	uint8_t output[64];

	memset(&sc, 0, sizeof(sc));
	sc.vsc_control_port.vsp_sc = &sc;
	sc.vsc_control_port.vsp_txq = 2;
	sc.vsc_control_port.vsp_rxq = 3;
	sc.vsc_control_port.vsp_enabled = true;
	sc.vsc_ports[0].vsp_sc = &sc;
	sc.vsc_ports[0].vsp_enabled = true;
	sc.vsc_ports[0].vsp_id = 0;
	sc.vsc_ports[0].vsp_name = "console";
	sc.vsc_ports[0].vsp_open = true;
	sc.vsc_queues[2].vq_num = 2;
	ctrl = (struct pci_vtcon_control){
		.event = VTCON_DEVICE_READY, .value = 1,
	};
	iov = (struct iovec){
		.iov_base = &ctrl,
		.iov_len = VIRTIO14_CONSOLE_CONTROL_SIZE,
	};
	pci_vtcon_neg_features(&sc, 1ULL << VTCON_F_MULTIPORT);

	/* DEVICE_READY causes only the document-mandated DEVICE_ADD. */
	reset_mocks();
	g_descs = 1;
	g_readable = 0;
	g_writable = 1;
	g_chain_iov[0] = (struct iovec){
		.iov_base = output, .iov_len = sizeof(output),
	};
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, &iov, 1);
	memcpy(&event, output, VIRTIO14_CONSOLE_CONTROL_SIZE);
	ATF_CHECK_EQ(event.event, VTCON_DEVICE_ADD);
	ATF_CHECK(sc.vsc_ports[0].vsp_announced);
	ATF_CHECK(!sc.vsc_ports[0].vsp_named);
	ATF_CHECK(!sc.vsc_ports[0].vsp_guest_ready);
	ATF_CHECK(!sc.vsc_ports[0].vsp_open_pending);
	ATF_CHECK_EQ(g_rel_calls, 1);

	/*
	 * PORT_READY permits additional configuration.  One available buffer
	 * carries PORT_NAME and leaves the host-open state pending.
	 */
	ctrl = (struct pci_vtcon_control){
		.id = 0, .event = VIRTIO14_CONSOLE_PORT_READY, .value = 1,
	};
	reset_mocks();
	g_descs = 1;
	g_readable = 0;
	g_writable = 1;
	g_chain_iov[0] = (struct iovec){
		.iov_base = output, .iov_len = sizeof(output),
	};
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, &iov, 1);
	memcpy(&event, output, VIRTIO14_CONSOLE_CONTROL_SIZE);
	ATF_CHECK_EQ(event.event, VTCON_PORT_NAME);
	ATF_CHECK(memcmp(output + VIRTIO14_CONSOLE_CONTROL_SIZE, "console",
	    strlen("console")) == 0);
	ATF_CHECK(sc.vsc_ports[0].vsp_announced);
	ATF_CHECK(sc.vsc_ports[0].vsp_guest_ready);
	ATF_CHECK(sc.vsc_ports[0].vsp_named);
	ATF_CHECK(sc.vsc_ports[0].vsp_open_pending);
	ATF_CHECK_EQ(g_rel_calls, 1);

	/* The next kick publishes the still-pending host-open state. */
	reset_mocks();
	g_readable = 0;
	g_writable = 1;
	g_chain_iov[0] = (struct iovec){
		.iov_base = output, .iov_len = sizeof(output),
	};
	pci_vtcon_notify_rx(&sc, &sc.vsc_queues[2]);
	memcpy(&event, output, VIRTIO14_CONSOLE_CONTROL_SIZE);
	ATF_CHECK_EQ(event.event, VTCON_PORT_OPEN);
	ATF_CHECK_EQ(event.value, 1);
	ATF_CHECK(!sc.vsc_ports[0].vsp_open_pending);
	ATF_CHECK_EQ(g_rel_calls, 1);

	/* Further receive kicks do not replay any lifecycle event. */
	reset_mocks();
	g_readable = 0;
	g_writable = 1;
	g_chain_iov[0] = (struct iovec){
		.iov_base = output, .iov_len = sizeof(output),
	};
	pci_vtcon_notify_rx(&sc, &sc.vsc_queues[2]);
	ATF_CHECK_EQ(g_rel_calls, 0);
}

ATF_TC_WITHOUT_HEAD(receive_preserves_data);
ATF_TC_BODY(receive_preserves_data, tc)
{
	struct pci_vtcon_softc sc;
	struct pci_vtcon_sock sock;
	struct mevent ev;
	struct vring_used used;
	uint8_t a[2], b[3];
	int sv[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	memset(&sc, 0, sizeof(sc));
	memset(&sock, 0, sizeof(sock));
	memset(&used, 0, sizeof(used));
	ATF_REQUIRE(pthread_mutex_init(&sc.vsc_mtx, NULL) == 0);
	sc.vsc_vs.vs_mtx = &sc.vsc_mtx;
	sc.vsc_ports[0].vsp_sc = &sc;
	sc.vsc_ports[0].vsp_enabled = true;
	sc.vsc_ports[0].vsp_rx_ready = true;
	sc.vsc_ports[0].vsp_txq = 0;
	sc.vsc_queues[0].vq_vs = &sc.vsc_vs;
	sc.vsc_queues[0].vq_used = &used;
	sock.vss_sc = &sc;
	sock.vss_port = &sc.vsc_ports[0];
	sock.vss_open = true;
	sock.vss_conn_fd = sv[1];
	sock.vss_conn_evp = &ev;

	reset_mocks();
	g_descs = 0;
	ATF_REQUIRE(write(sv[0], "hello", 5) == 5);
	pci_vtcon_sock_rx(sv[1], EVF_READ, &sock);
	ATF_CHECK(g_disable_calls == 1);
	ATF_CHECK(!sc.vsc_ports[0].vsp_rx_ready);

	reset_mocks();
	sc.vsc_ports[0].vsp_rx_ready = true;
	g_chain_n = 2;
	g_readable = 0;
	g_writable = 2;
	g_descs = 2;
	g_chain_iov[0] = (struct iovec){ .iov_base = a, .iov_len = sizeof(a) };
	g_chain_iov[1] = (struct iovec){ .iov_base = b, .iov_len = sizeof(b) };
	pci_vtcon_sock_rx(sv[1], EVF_READ, &sock);
	ATF_CHECK(memcmp(a, "he", 2) == 0);
	ATF_CHECK(memcmp(b, "llo", 3) == 0);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 5);
	ATF_CHECK(g_descs == 1);
	ATF_CHECK(sock.vss_open);
	ATF_CHECK(sock.vss_conn_fd == sv[1]);
	close(sv[0]);
	close(sv[1]);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.vsc_mtx) == 0);
}

ATF_TC_WITHOUT_HEAD(transmit_backpressure);
ATF_TC_BODY(transmit_backpressure, tc)
{
	struct pci_vtcon_softc sc;
	struct pci_vtcon_sock sock;
	struct pci_vtcon_port port;
	struct mevent read_ev, write_ev;
	struct iovec iov;
	char fill[4096], drain[16384], got[8];
	int flags, sv[2];
	ssize_t n;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	flags = fcntl(sv[1], F_GETFL);
	ATF_REQUIRE(flags >= 0);
	ATF_REQUIRE(fcntl(sv[1], F_SETFL, flags | O_NONBLOCK) == 0);
	memset(fill, 0xa5, sizeof(fill));
	while (write(sv[1], fill, sizeof(fill)) > 0)
		;
	ATF_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);

	memset(&sc, 0, sizeof(sc));
	memset(&sock, 0, sizeof(sock));
	memset(&port, 0, sizeof(port));
	ATF_REQUIRE(pthread_mutex_init(&sc.vsc_mtx, NULL) == 0);
	sc.vsc_vs.vs_mtx = &sc.vsc_mtx;
	port.vsp_sc = &sc;
	sock.vss_sc = &sc;
	sock.vss_port = &port;
	sock.vss_open = true;
	sock.vss_conn_fd = sv[1];
	sock.vss_conn_evp = &read_ev;
	sock.vss_write_evp = &write_ev;
	iov = (struct iovec){ .iov_base = __DECONST(char *, "marker"),
	    .iov_len = 6 };
	reset_mocks();
	pci_vtcon_sock_tx(&port, &sock, &iov, 1);
	ATF_CHECK(sock.vss_open);
	ATF_CHECK(sock.vss_tx_len - sock.vss_tx_off == 6);
	ATF_CHECK(g_enable_calls == 1);

	flags = fcntl(sv[0], F_GETFL);
	ATF_REQUIRE(flags >= 0);
	ATF_REQUIRE(fcntl(sv[0], F_SETFL, flags | O_NONBLOCK) == 0);
	while (read(sv[0], drain, sizeof(drain)) > 0)
		;
	ATF_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);
	pci_vtcon_sock_tx_event(sv[1], EVF_WRITE, &sock);
	ATF_CHECK(sock.vss_tx_len == 0);
	n = read(sv[0], got, sizeof(got));
	ATF_REQUIRE(n == 6);
	ATF_CHECK(memcmp(got, "marker", 6) == 0);
	free(sock.vss_tx_buf);
	close(sv[0]);
	close(sv[1]);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.vsc_mtx) == 0);
}

ATF_TC_WITHOUT_HEAD(transmit_partial_and_compaction);
ATF_TC_BODY(transmit_partial_and_compaction, tc)
{
	struct pci_vtcon_sock sock;
	struct mevent read_ev, write_ev;
	struct iovec iov;

	memset(&sock, 0, sizeof(sock));
	sock.vss_open = true;
	sock.vss_conn_fd = 101;
	sock.vss_conn_evp = &read_ev;
	sock.vss_write_evp = &write_ev;
	reset_mocks();
	g_send_override_fd = sock.vss_conn_fd;
	g_send_result = 3;
	iov = (struct iovec){
		.iov_base = __DECONST(char *, "abcdef"), .iov_len = 6,
	};
	pci_vtcon_sock_tx(NULL, &sock, &iov, 1);
	ATF_CHECK(sock.vss_open);
	ATF_CHECK((g_send_flags & MSG_NOSIGNAL) != 0);
	ATF_CHECK(sock.vss_tx_off == 3 && sock.vss_tx_len == 6);
	ATF_CHECK(memcmp(sock.vss_tx_buf, "abcdef", 6) == 0);
	ATF_CHECK(g_enable_calls == 1);

	/* Force the next append to compact the three pending bytes first. */
	sock.vss_tx_cap = sock.vss_tx_len;
	g_send_result = -1;
	g_send_errno = EAGAIN;
	iov = (struct iovec){
		.iov_base = __DECONST(char *, "gh"), .iov_len = 2,
	};
	pci_vtcon_sock_tx(NULL, &sock, &iov, 1);
	ATF_CHECK(sock.vss_open);
	ATF_CHECK(sock.vss_tx_off == 0 && sock.vss_tx_len == 5);
	ATF_CHECK(memcmp(sock.vss_tx_buf, "defgh", 5) == 0);
	ATF_CHECK(g_enable_calls == 2);
	free(sock.vss_tx_buf);
}

ATF_TC_WITHOUT_HEAD(transmit_failure_paths);
ATF_TC_BODY(transmit_failure_paths, tc)
{
	struct pci_vtcon_softc sc;
	struct pci_vtcon_sock sock;
	struct pci_vtcon_port port;
	struct mevent read_ev, write_ev;
	struct iovec iov;
	char byte = 0;

	memset(&sc, 0, sizeof(sc));
	memset(&port, 0, sizeof(port));
	port.vsp_sc = &sc;
	memset(&sock, 0, sizeof(sock));
	sock.vss_port = &port;
	sock.vss_open = true;
	sock.vss_conn_fd = 102;
	sock.vss_conn_evp = &read_ev;
	sock.vss_write_evp = &write_ev;
	reset_mocks();
	g_send_override_fd = sock.vss_conn_fd;
	g_realloc_fail = true;
	iov = (struct iovec){ .iov_base = &byte, .iov_len = 1 };
	pci_vtcon_sock_tx(NULL, &sock, &iov, 1);
	ATF_CHECK(!sock.vss_open);
	ATF_CHECK(sock.vss_tx_buf == NULL && sock.vss_tx_len == 0);

	memset(&sock, 0, sizeof(sock));
	sock.vss_port = &port;
	sock.vss_open = true;
	sock.vss_conn_fd = 103;
	sock.vss_conn_evp = &read_ev;
	sock.vss_write_evp = &write_ev;
	sock.vss_tx_buf = malloc(1);
	ATF_REQUIRE(sock.vss_tx_buf != NULL);
	sock.vss_tx_len = VTCON_SOCK_TX_MAX;
	sock.vss_tx_cap = VTCON_SOCK_TX_MAX;
	pci_vtcon_sock_tx(NULL, &sock, &iov, 1);
	ATF_CHECK(!sock.vss_open);
	ATF_CHECK(sock.vss_tx_buf == NULL && sock.vss_tx_len == 0);

	memset(&sock, 0, sizeof(sock));
	sock.vss_port = &port;
	sock.vss_open = true;
	sock.vss_conn_fd = 104;
	sock.vss_conn_evp = &read_ev;
	sock.vss_write_evp = &write_ev;
	sock.vss_tx_buf = malloc(1);
	ATF_REQUIRE(sock.vss_tx_buf != NULL);
	sock.vss_tx_buf[0] = 0x5a;
	sock.vss_tx_len = 1;
	sock.vss_tx_cap = 1;
	g_send_override_fd = sock.vss_conn_fd;
	g_send_result = -1;
	g_send_errno = EPIPE;
	pci_vtcon_sock_drain(&sock);
	ATF_CHECK(!sock.vss_open);
	ATF_CHECK(sock.vss_tx_buf == NULL && sock.vss_tx_len == 0);
}

ATF_TC_WITHOUT_HEAD(virtio_1_4_wire_layout);
ATF_TC_BODY(virtio_1_4_wire_layout, tc)
{
	/* VirtIO 1.4 sections 5.3.4 and 5.3.6.1. */
	ATF_CHECK_EQ(sizeof(struct pci_vtcon_config),
	    VIRTIO14_CONSOLE_CONFIG_SIZE);
	ATF_CHECK_EQ(sizeof(struct pci_vtcon_control),
	    VIRTIO14_CONSOLE_CONTROL_SIZE);
	ATF_CHECK_EQ(offsetof(struct pci_vtcon_config, cols),
	    VIRTIO14_CONSOLE_CONFIG_COLS_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtcon_config, rows),
	    VIRTIO14_CONSOLE_CONFIG_ROWS_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtcon_config, max_nr_ports),
	    VIRTIO14_CONSOLE_CONFIG_MAX_PORTS_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtcon_config, emerg_wr),
	    VIRTIO14_CONSOLE_CONFIG_EMERG_WR_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtcon_control, id),
	    VIRTIO14_CONSOLE_CONTROL_ID_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtcon_control, event),
	    VIRTIO14_CONSOLE_CONTROL_EVENT_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtcon_control, value),
	    VIRTIO14_CONSOLE_CONTROL_VALUE_OFF);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, virtio_1_4_wire_layout);
	ATF_TP_ADD_TC(tp, transport_and_features);
	ATF_TP_ADD_TC(tp, in_order_completion);
	ATF_TP_ADD_TC(tp, emergency_write);
	ATF_TP_ADD_TC(tp, queue_reset_isolated);
	ATF_TP_ADD_TC(tp, legacy_parser_transport);
	ATF_TP_ADD_TC(tp, control_validation);
	ATF_TP_ADD_TC(tp, document_wire_vectors);
	ATF_TP_ADD_TC(tp, transmit_validation);
	ATF_TP_ADD_TC(tp, control_receive_scatter);
	ATF_TP_ADD_TC(tp, multiport_feature_gating);
	ATF_TP_ADD_TC(tp, device_add_lifecycle);
	ATF_TP_ADD_TC(tp, device_add_name_retry);
	ATF_TP_ADD_TC(tp, receive_preserves_data);
	ATF_TP_ADD_TC(tp, transmit_backpressure);
	ATF_TP_ADD_TC(tp, transmit_partial_and_compaction);
	ATF_TP_ADD_TC(tp, transmit_failure_paths);
	return (atf_no_error());
}
