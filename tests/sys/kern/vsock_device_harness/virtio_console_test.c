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
static int g_rel_calls;
static uint32_t g_rel_len;
static int g_end_calls;
static int g_ret_calls;
static int g_enable_calls;
static int g_disable_calls;
static int g_callback_calls;
static int g_callback_niov;

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
	g_rel_calls = 0;
	g_rel_len = UINT32_MAX;
	g_end_calls = 0;
	g_ret_calls = 0;
	g_enable_calls = 0;
	g_disable_calls = 0;
	g_callback_calls = 0;
	g_callback_niov = 0;
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
	req->idx = 7;
	req->readable = g_readable;
	req->writable = g_writable;
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
	ATF_CHECK(idx == 7);
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
    struct iovec *iov __unused, int niov)
{
	g_callback_calls++;
	g_callback_niov = niov;
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
	uint32_t val;

	ATF_CHECK(vtcon_vi_consts.vc_hv_caps ==
	    ((1ULL << VTCON_F_SIZE) | (1ULL << VTCON_F_MULTIPORT)));
	ATF_CHECK((vtcon_vi_consts.vc_hv_caps &
	    (1ULL << VTCON_F_EMERG_WRITE)) == 0);

	memset(&pi, 0, sizeof(pi));
	reset_mocks();
	ATF_REQUIRE(pci_vtcon_init(&pi, &nvl) == 0);
	ATF_CHECK(g_io_bar == 0 && g_modern_bar == -1);
	ATF_CHECK(pi.pi_cfgdata[PCIR_DEVICE] == 0x03);
	ATF_CHECK(pi.pi_cfgdata[PCIR_DEVICE + 1] == 0x10);
	free_softc(&pi);

	memset(&pi, 0, sizeof(pi));
	reset_mocks();
	g_transport = "modern";
	ATF_REQUIRE(pci_vtcon_init(&pi, &nvl) == 0);
	ATF_CHECK(g_modern_identity == VIRTIO_ID_CONSOLE);
	ATF_CHECK(g_modern_bar == 2 && g_io_bar == -1);
	sc = pi.pi_arg;
	val = UINT32_MAX;
	ATF_CHECK(pci_vtcon_cfgread(sc, 0, 2, &val) == 0);
	ATF_CHECK(val == 80);
	ATF_CHECK(pci_vtcon_cfgread(sc, -1, 1, &val) == -1);
	ATF_CHECK(pci_vtcon_cfgread(sc, sizeof(*sc->vsc_config), 1,
	    &val) == -1);
	ATF_CHECK(pci_vtcon_cfgwrite(sc, 0, 4, 1) == -1);
	free_softc(&pi);
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
	struct pci_vtcon_control ctrl;
	struct iovec iov[2];

	memset(&sc, 0, sizeof(sc));
	sc.vsc_control_port.vsp_sc = &sc;
	ctrl = (struct pci_vtcon_control){
		.id = UINT32_MAX,
		.event = VTCON_PORT_READY,
		.value = 1,
	};
	iov[0] = (struct iovec){ .iov_base = &ctrl, .iov_len = 3 };
	iov[1] = (struct iovec){
		.iov_base = (uint8_t *)&ctrl + 3,
		.iov_len = sizeof(ctrl) - 3,
	};
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, iov, 2);
	ATF_CHECK(!sc.vsc_ready);
	iov[1].iov_len--;
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, iov, 2);
	ATF_CHECK(!sc.vsc_ready);

	ctrl.id = 0;
	ctrl.event = VTCON_DEVICE_READY;
	ctrl.value = 0;
	iov[0] = (struct iovec){ .iov_base = &ctrl, .iov_len = sizeof(ctrl) };
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, iov, 1);
	ATF_CHECK(!sc.vsc_ready);
	ctrl.value = 1;
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, iov, 1);
	ATF_CHECK(sc.vsc_ready);
}

ATF_TC_WITHOUT_HEAD(transmit_validation);
ATF_TC_BODY(transmit_validation, tc)
{
	struct pci_vtcon_softc sc;
	struct vqueue_info *vq;
	uint8_t a[4], b[7];

	memset(&sc, 0, sizeof(sc));
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
	struct pci_vtcon_control ctrl, got;
	uint8_t a[3], b[sizeof(ctrl) - sizeof(a)];

	memset(&sc, 0, sizeof(sc));
	sc.vsc_control_port.vsp_sc = &sc;
	sc.vsc_control_port.vsp_txq = 2;
	reset_mocks();
	g_chain_n = 2;
	g_readable = 0;
	g_writable = 2;
	g_chain_iov[0] = (struct iovec){ .iov_base = a, .iov_len = sizeof(a) };
	g_chain_iov[1] = (struct iovec){ .iov_base = b, .iov_len = sizeof(b) };
	ctrl = (struct pci_vtcon_control){
		.id = 3, .event = VTCON_DEVICE_ADD, .value = 1,
	};
	pci_vtcon_control_send(&sc, &ctrl, NULL, 0);
	memcpy(&got, a, sizeof(a));
	memcpy((uint8_t *)&got + sizeof(a), b, sizeof(b));
	ATF_CHECK(memcmp(&got, &ctrl, sizeof(got)) == 0);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == sizeof(ctrl));

	reset_mocks();
	g_readable = 1;
	g_writable = 0;
	g_chain_iov[0] = (struct iovec){ .iov_base = a, .iov_len = sizeof(a) };
	pci_vtcon_control_send(&sc, &ctrl, NULL, 0);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 0);
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
	g_chain_iov[0] = (struct iovec){ .iov_base = a, .iov_len = sizeof(a) };
	g_chain_iov[1] = (struct iovec){ .iov_base = b, .iov_len = sizeof(b) };
	pci_vtcon_sock_rx(sv[1], EVF_READ, &sock);
	ATF_CHECK(memcmp(a, "he", 2) == 0);
	ATF_CHECK(memcmp(b, "llo", 3) == 0);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 5);
	ATF_CHECK(sock.vss_open);
	ATF_CHECK(sock.vss_conn_fd == sv[1]);
	close(sv[0]);
	close(sv[1]);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.vsc_mtx) == 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, transport_and_features);
	ATF_TP_ADD_TC(tp, legacy_parser_transport);
	ATF_TP_ADD_TC(tp, control_validation);
	ATF_TP_ADD_TC(tp, transmit_validation);
	ATF_TP_ADD_TC(tp, control_receive_scatter);
	ATF_TP_ADD_TC(tp, receive_preserves_data);
	return (atf_no_error());
}
