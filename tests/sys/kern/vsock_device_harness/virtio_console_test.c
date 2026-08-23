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

#include "virtio_config_read_test_support.h"
#define	BHYVE_SNAPSHOT
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
#undef VIRTIO_F_RING_PACKED
#define	VIRTIO_F_RING_PACKED	VIRTIO14_F_RING_PACKED
#undef VIRTIO_F_SUSPEND
#define	VIRTIO_F_SUSPEND	VIRTIO14_F_SUSPEND
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
static char g_set_name[64][32];
static char g_set_value[64][128];
static int g_set_count;
static int g_mevent_add_fail;
static int g_mevent_add_disabled_fail;
static int g_port_node_type;
static uint16_t g_config_nodes;
static int g_modern_identity;
static int g_modern_bar;
static int g_io_bar;
static int g_descs;
static int g_descs_delay;
static int g_has_descs_q;
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
static int g_calloc_fail;
static int g_malloc_fail;
static bool g_packed;
static int g_snapshot_validate_calls;
static bool g_snapshot_validate_mutex_owned;
static const char *g_sock_path;
static const char *g_sock_name;
static const char *g_port_node;
static bool g_intr_fail;
static bool g_modern_init_fail;

int
vi_pci_snapshot(struct vm_snapshot_meta *meta)
{
	struct pci_vtcon_softc *sc;

	sc = ((struct pci_devinst *)meta->dev_data)->pi_arg;
	g_snapshot_validate_calls++;
	g_snapshot_validate_mutex_owned = pthread_mutex_isowned_np(&sc->vsc_mtx);
	return (0);
}

void
vm_snapshot_buf_err(const char *name __unused,
    const enum vm_snapshot_op op __unused)
{
}

int
vm_snapshot_buf(void *data, size_t size, struct vm_snapshot_meta *meta)
{

	if (size > meta->buffer.buf_rem)
		return (E2BIG);
	if (meta->op == VM_SNAPSHOT_SAVE)
		memcpy(meta->buffer.buf, data, size);
	else if (vm_snapshot_is_loading(meta))
		memcpy(data, meta->buffer.buf, size);
	else
		return (EINVAL);
	meta->buffer.buf += size;
	meta->buffer.buf_rem -= size;
	return (0);
}

int
vm_snapshot_u8(uint8_t *value, struct vm_snapshot_meta *meta)
{

	return (vm_snapshot_buf(value, sizeof(*value), meta));
}

int
vm_snapshot_le16(uint16_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[2];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE) {
		bytes[0] = *value;
		bytes[1] = *value >> 8;
	}
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = (uint16_t)bytes[0] | (uint16_t)bytes[1] << 8;
	return (error);
}

int
vm_snapshot_le32(uint32_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[4];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE) {
		for (unsigned int i = 0; i < nitems(bytes); i++)
			bytes[i] = *value >> (i * 8);
	}
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta)) {
		*value = 0;
		for (unsigned int i = 0; i < nitems(bytes); i++)
			*value |= (uint32_t)bytes[i] << (i * 8);
	}
	return (error);
}

int
vm_snapshot_le64(uint64_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[8];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE) {
		for (unsigned int i = 0; i < nitems(bytes); i++)
			bytes[i] = *value >> (i * 8);
	}
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta)) {
		*value = 0;
		for (unsigned int i = 0; i < nitems(bytes); i++)
			*value |= (uint64_t)bytes[i] << (i * 8);
	}
	return (error);
}

static void
reset_mocks(void)
{
	g_transport = NULL;
	g_set_count = 0;
	g_config_nodes = 0;
	g_modern_identity = -1;
	g_modern_bar = -1;
	g_io_bar = -1;
	g_descs = 1;
	g_descs_delay = 0;
	g_has_descs_q = -1;
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
	g_calloc_fail = 0;
	g_malloc_fail = 0;
	g_packed = false;
	g_sock_path = NULL;
	g_sock_name = NULL;
	g_port_node = NULL;
	g_intr_fail = false;
	g_modern_init_fail = false;
	g_mevent_add_fail = 0;
	g_mevent_add_disabled_fail = 0;
	g_port_node_type = NV_TYPE_NVLIST;
}

ssize_t __real_send(int, const void *, size_t, int);
ssize_t __wrap_send(int, const void *, size_t, int);
void *__real_realloc(void *, size_t);
void *__wrap_realloc(void *, size_t);
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t, size_t);
void *__real_malloc(size_t);
void *__wrap_malloc(size_t);

void *
__wrap_calloc(size_t nmemb, size_t size)
{

	if (g_calloc_fail > 0 && --g_calloc_fail == 0)
		return (NULL);
	return (__real_calloc(nmemb, size));
}

void *
__wrap_malloc(size_t size)
{

	if (g_malloc_fail > 0 && --g_malloc_fail == 0)
		return (NULL);
	return (__real_malloc(size));
}

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
	if (strcmp(name, "transport") == 0)
		return (g_transport);
	if (strcmp(name, "path") == 0)
		return (g_sock_path);
	if (strcmp(name, "name") == 0)
		return (g_sock_name);
	return (NULL);
}

bool
get_config_bool_node_default(const nvlist_t *nvl __unused,
    const char *name, bool default_value)
{

	if (strcmp(name, "packed") == 0)
		return (g_packed);
	return (default_value);
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
	char *end;
	long value;

	value = strtol(name, &end, 10);
	if (*name != '\0' && *end == '\0' && value >= 0 && value < 16)
		g_config_nodes |= (uint16_t)1U << value;
	return (nvl);
}

nvlist_t *
find_relative_config_node(nvlist_t *nvl, const char *name)
{
	char *end;
	long value;

	/* The device looks up the "port" container before enumerating ports. */
	if (strcmp(name, "port") == 0)
		return (g_port_node != NULL ? nvl : NULL);
	value = strtol(name, &end, 10);
	if (*name != '\0' && *end == '\0' && value >= 0 && value < 16 &&
	    (g_config_nodes & ((uint16_t)1U << value)) != 0)
		return (nvl);
	return (NULL);
}

const char *
nvlist_next(const nvlist_t *nvl __unused, int *type, void **cookie)
{
	/*
	 * Emit a single configured port node once, then stop.  The cookie
	 * doubles as the visited flag so the device's port-enumeration loop
	 * terminates.
	 */
	if (g_port_node == NULL || *cookie != NULL)
		return (NULL);
	*cookie = (void *)1;
	if (type != NULL)
		*type = g_port_node_type;
	return (g_port_node);
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

	if (g_mevent_add_fail > 0 && --g_mevent_add_fail == 0)
		return (NULL);
	return (&ev);
}

struct mevent *
mevent_add_disabled(int fd __unused, enum ev_type type __unused,
    void (*cb)(int, enum ev_type, void *) __unused, void *arg __unused)
{
	static struct mevent ev;

	if (g_mevent_add_disabled_fail > 0 && --g_mevent_add_disabled_fail == 0)
		return (NULL);
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
int mevent_delete_sync(struct mevent *ev __unused) { return (0); }
int mevent_delete_close(struct mevent *ev __unused) { return (0); }

int
stream_write(int fd, const void *buf, int len)
{
	return ((int)write(fd, buf, len));
}

int
vq_has_descs(struct vqueue_info *vq __unused)
{
	g_has_descs_q = vq->vq_num;
	/*
	 * Model a guest that publishes descriptors between the emptiness check
	 * and the kick-enable: the first g_descs_delay probes report empty.
	 */
	if (g_descs_delay > 0) {
		g_descs_delay--;
		return (0);
	}
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
	return (g_modern_init_fail ? -1 : 0);
}

int vi_intr_init(struct virtio_softc *vs __unused, int bar __unused,
    int msix __unused) { return (g_intr_fail ? -1 : 0); }
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
resume_rx_cb(struct pci_vtcon_port *port __unused, void *arg __unused)
{

	g_enable_calls++;
}

static void
disable_rx_cb(struct pci_vtcon_port *port __unused, void *arg __unused)
{

	g_disable_calls++;
}

/*
 * Release the per-port sockets attached to a stack-allocated softc without
 * freeing the softc itself (which pci_vtcon_destroy() would do).
 */
static void
free_port_socks(struct pci_vtcon_softc *sc)
{
	struct pci_vtcon_sock *sock;
	int i;

	for (i = 0; i < VTCON_MAXPORTS; i++) {
		if (!sc->vsc_ports[i].vsp_enabled)
			continue;
		sock = sc->vsc_ports[i].vsp_arg;
		if (sock == NULL)
			continue;
		if (sock->vss_conn_fd >= 0)
			close(sock->vss_conn_fd);
		if (sock->vss_server_fd >= 0)
			close(sock->vss_server_fd);
		free(sock->vss_tx_buf);
		free(sock);
		sc->vsc_ports[i].vsp_arg = NULL;
	}
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
	    VIRTIO_F_IN_ORDER | VIRTIO_F_RING_RESET | VIRTIO_F_SUSPEND));
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
	ATF_CHECK(pci_vtcon_cfgread(sc, 0, 1, NULL) == -1);
	ATF_CHECK(pci_vtcon_cfgwrite(sc, 0, 4, 1) == -1);
	ATF_CHECK(pci_vtcon_cfgwrite(sc,
	    VIRTIO14_CONSOLE_CONFIG_EMERG_WR_OFF, 4, 'x') == 0);
	free_softc(&pi);

	memset(&pi, 0, sizeof(pi));
	reset_mocks();
	g_transport = "modern";
	g_packed = true;
	ATF_REQUIRE(pci_vtcon_init(&pi, &nvl) == 0);
	sc = pi.pi_arg;
	ATF_CHECK((sc->vsc_consts.vc_hv_caps &
	    VIRTIO_F_RING_PACKED) != 0);
	ATF_CHECK((vtcon_vi_consts.vc_hv_caps &
	    VIRTIO_F_RING_PACKED) == 0);
	free_softc(&pi);

	memset(&pi, 0, sizeof(pi));
	reset_mocks();
	g_packed = true;
	ATF_CHECK(pci_vtcon_init(&pi, &nvl) != 0);
}

ATF_TC_WITHOUT_HEAD(suspend_resume_rearms_existing_rx);
ATF_TC_BODY(suspend_resume_rearms_existing_rx, tc)
{
	struct pci_vtcon_softc sc;
	struct pci_vtcon_port *port;
	struct vring_used used;

	memset(&sc, 0, sizeof(sc));
	memset(&used, 0, sizeof(used));
	reset_mocks();
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	sc.vsc_features = 1ULL << VTCON_F_MULTIPORT;
	sc.vsc_control_port.vsp_sc = &sc;
	sc.vsc_control_port.vsp_txq = 2;
	sc.vsc_queues[2].vq_num = 2;
	port = &sc.vsc_ports[0];
	port->vsp_sc = &sc;
	port->vsp_enabled = true;
	port->vsp_txq = 0;
	port->vsp_rxq = 1;
	port->vsp_rx_cb = resume_rx_cb;
	sc.vsc_queues[0].vq_num = 0;
	sc.vsc_queues[0].vq_vs = &sc.vsc_vs;
	sc.vsc_queues[0].vq_used = &used;
	sc.vsc_queues[1].vq_num = 1;
	sc.vsc_queues[1].vq_vs = &sc.vsc_vs;
	sc.vsc_queues[1].vq_used = &used;

	ATF_CHECK((vtcon_vi_consts.vc_hv_caps &
	    VIRTIO14_F_SUSPEND) != 0);
	ATF_CHECK(vtcon_vi_consts.vc_suspend ==
	    pci_vtcon_suspend_device);
	ATF_CHECK(vtcon_vi_consts.vc_resume_complete ==
	    pci_vtcon_resume_complete);
	ATF_REQUIRE_EQ(pci_vtcon_suspend_device(&sc), 0);
	pci_vtcon_resume_complete(&sc);
	ATF_CHECK(port->vsp_rx_ready);
	ATF_CHECK_EQ(g_enable_calls, 1);
	ATF_CHECK_EQ(g_has_descs_q, 0);

	/*
	 * Guest-driven resume calls the completion hook with the VirtIO mutex
	 * already held.  Verify that path does not attempt to relock it.
	 */
	port->vsp_rx_ready = false;
	g_enable_calls = 0;
	pthread_mutex_lock(&sc.vsc_mtx);
	pci_vtcon_resume_complete(&sc);
	ATF_CHECK(pthread_mutex_isowned_np(&sc.vsc_mtx));
	pthread_mutex_unlock(&sc.vsc_mtx);
	ATF_CHECK(port->vsp_rx_ready);
	ATF_CHECK_EQ(g_enable_calls, 1);
	ATF_CHECK_EQ(g_has_descs_q, 0);
	pthread_mutex_destroy(&sc.vsc_mtx);
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
	vq->vq_qsize = VTCON_RINGSZ;
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
	sc.vsc_ports[0].vsp_rx_disable_cb = disable_rx_cb;
	sc.vsc_ports[1].vsp_rx_disable_cb = disable_rx_cb;
	sc.vsc_queues[0].vq_num = 0;
	sc.vsc_queues[1].vq_num = 1;
	sc.vsc_queues[4].vq_num = 4;

	reset_mocks();
	ATF_CHECK_EQ(pci_vtcon_qreset(&sc, &sc.vsc_queues[1], 1), 0);
	ATF_CHECK(sc.vsc_ports[0].vsp_rx_ready);
	ATF_CHECK(sc.vsc_ports[1].vsp_rx_ready);
	ATF_CHECK_EQ(g_disable_calls, 0);

	ATF_CHECK_EQ(pci_vtcon_qreset(&sc, &sc.vsc_queues[0], 2), 0);
	ATF_CHECK(!sc.vsc_ports[0].vsp_rx_ready);
	ATF_CHECK(sc.vsc_ports[1].vsp_rx_ready);
	ATF_CHECK_EQ(g_disable_calls, 1);

	ATF_CHECK_EQ(pci_vtcon_qreset(&sc, &sc.vsc_queues[4], 3), 0);
	ATF_CHECK(!sc.vsc_ports[1].vsp_rx_ready);
	ATF_CHECK_EQ(g_disable_calls, 2);

	sc.vsc_queues[0].vq_num = VTCON_MAXQ;
	ATF_CHECK_EQ(pci_vtcon_qreset(&sc, &sc.vsc_queues[0], 4), EINVAL);
}

ATF_TC_WITHOUT_HEAD(queue_reset_fences_selected_rx_callback);
ATF_TC_BODY(queue_reset_fences_selected_rx_callback, tc)
{
	struct pci_vtcon_softc sc;
	struct pci_vtcon_sock sock;
	struct mevent ev;
	struct vring_used used;
	char byte;
	int sv[2];

	/*
	 * mevent_disable() queues a change for the event thread.  Model a read
	 * callback that kqueue selected before the queue reset, but which does
	 * not acquire the VirtIO mutex until after reset published the cleared
	 * readiness latch.  It must not consume a descriptor or host byte.
	 */
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	memset(&sc, 0, sizeof(sc));
	memset(&sock, 0, sizeof(sock));
	memset(&used, 0, sizeof(used));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	sc.vsc_vs.vs_mtx = &sc.vsc_mtx;
	sc.vsc_ports[0].vsp_sc = &sc;
	sc.vsc_ports[0].vsp_enabled = true;
	sc.vsc_ports[0].vsp_rx_ready = true;
	sc.vsc_ports[0].vsp_rx_disable_cb = pci_vtcon_sock_rx_disable;
	sc.vsc_ports[0].vsp_arg = &sock;
	sc.vsc_ports[0].vsp_txq = 0;
	sc.vsc_queues[0].vq_vs = &sc.vsc_vs;
	sc.vsc_queues[0].vq_used = &used;
	sc.vsc_queues[0].vq_num = 0;
	sc.vsc_queues[0].vq_qsize = VTCON_RINGSZ;
	sock.vss_sc = &sc;
	sock.vss_port = &sc.vsc_ports[0];
	sock.vss_open = true;
	sock.vss_conn_fd = sv[1];
	sock.vss_conn_evp = &ev;

	reset_mocks();
	g_readable = 0;
	g_writable = 1;
	g_chain_iov[0] = (struct iovec){
		.iov_base = &byte, .iov_len = sizeof(byte),
	};
	ATF_REQUIRE_EQ(write(sv[0], "x", 1), 1);
	ATF_REQUIRE_EQ(pci_vtcon_qreset(&sc, &sc.vsc_queues[0], 1), 0);
	ATF_CHECK_EQ(g_disable_calls, 1);

	pci_vtcon_sock_rx(sv[1], EVF_READ, &sock);
	ATF_CHECK_EQ(g_disable_calls, 2);
	ATF_CHECK_EQ(g_get_calls, 0);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(recv(sv[1], &byte, 1, MSG_DONTWAIT), 1);
	ATF_CHECK_EQ(byte, 'x');

	close(sv[0]);
	close(sv[1]);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(stale_connection_callbacks_are_ignored);
ATF_TC_BODY(stale_connection_callbacks_are_ignored, tc)
{
	struct pci_vtcon_softc sc;
	struct pci_vtcon_sock sock;
	struct mevent read_ev, write_ev;
	struct vring_used used;
	char byte;
	int sv[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	ATF_REQUIRE(fcntl(sv[0], F_SETFL,
	    fcntl(sv[0], F_GETFL) | O_NONBLOCK) == 0);
	memset(&sc, 0, sizeof(sc));
	memset(&sock, 0, sizeof(sock));
	memset(&used, 0, sizeof(used));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	sc.vsc_vs.vs_mtx = &sc.vsc_mtx;
	sc.vsc_ports[0].vsp_sc = &sc;
	sc.vsc_ports[0].vsp_enabled = true;
	sc.vsc_ports[0].vsp_rx_ready = true;
	sc.vsc_ports[0].vsp_txq = 0;
	sc.vsc_queues[0].vq_vs = &sc.vsc_vs;
	sc.vsc_queues[0].vq_used = &used;
	sc.vsc_queues[0].vq_qsize = VTCON_RINGSZ;
	sock.vss_sc = &sc;
	sock.vss_port = &sc.vsc_ports[0];
	sock.vss_open = true;
	sock.vss_conn_fd = sv[1];
	sock.vss_conn_evp = &read_ev;
	sock.vss_write_evp = &write_ev;

	reset_mocks();
	g_readable = 0;
	g_writable = 1;
	g_chain_iov[0] = (struct iovec){
		.iov_base = &byte, .iov_len = sizeof(byte),
	};
	ATF_REQUIRE_EQ(write(sv[0], "r", 1), 1);
	pci_vtcon_sock_rx(sv[1] + 100, EVF_READ, &sock);
	ATF_CHECK_EQ(g_get_calls, 0);
	ATF_CHECK_EQ(recv(sv[1], &byte, 1, MSG_DONTWAIT), 1);
	ATF_CHECK_EQ(byte, 'r');

	sock.vss_tx_buf = malloc(1);
	ATF_REQUIRE(sock.vss_tx_buf != NULL);
	sock.vss_tx_buf[0] = 'w';
	sock.vss_tx_len = 1;
	sock.vss_tx_cap = 1;
	pci_vtcon_sock_tx_event(sv[1] + 100, EVF_WRITE, &sock);
	ATF_CHECK_EQ(sock.vss_tx_off, 0);
	ATF_CHECK_EQ(recv(sv[0], &byte, 1, MSG_DONTWAIT), -1);
	ATF_CHECK_EQ(errno, EAGAIN);

	free(sock.vss_tx_buf);
	close(sv[0]);
	close(sv[1]);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(legacy_parser_transport);
ATF_TC_BODY(legacy_parser_transport, tc)
{
	struct nvlist nvl;

	reset_mocks();
	ATF_REQUIRE(pci_vtcon_legacy_config(&nvl,
	    "agent=/tmp/a,transport=modern,console-port=0,packed=true,"
	    "other=/tmp/b") == 0);
	ATF_CHECK(g_set_count == 7);
	ATF_CHECK(strcmp(g_set_name[2], "transport") == 0);
	ATF_CHECK(strcmp(g_set_value[2], "modern") == 0);
	ATF_CHECK(strcmp(g_set_name[3], "console") == 0);
	ATF_CHECK(strcmp(g_set_value[3], "true") == 0);
	ATF_CHECK(strcmp(g_set_name[4], "packed") == 0);
	ATF_CHECK(strcmp(g_set_value[4], "true") == 0);
	ATF_CHECK(strcmp(g_set_value[5], "other") == 0);
	ATF_CHECK(pci_vtcon_legacy_config(&nvl,
	    "agent=/tmp/a,console-port=1") == -1);
	ATF_CHECK(pci_vtcon_legacy_config(&nvl,
	    "agent=/tmp/a,console-port=-1") == -1);
	ATF_CHECK(pci_vtcon_legacy_config(&nvl,
	    "agent=/tmp/a,console-port=") == -1);
	ATF_CHECK(pci_vtcon_legacy_config(&nvl, NULL) == 0);
}

ATF_TC_WITHOUT_HEAD(port_identifier_validation);
ATF_TC_BODY(port_identifier_validation, tc)
{
	const char *errstr;
	int port;

	ATF_REQUIRE_EQ(pci_vtcon_parse_port("0", &port, &errstr), 0);
	ATF_CHECK_EQ(port, 0);
	ATF_REQUIRE_EQ(pci_vtcon_parse_port("15", &port, &errstr), 0);
	ATF_CHECK_EQ(port, 15);
	ATF_CHECK_EQ(pci_vtcon_parse_port(NULL, &port, &errstr), EINVAL);
	ATF_CHECK_EQ(pci_vtcon_parse_port("", &port, &errstr), EINVAL);
	ATF_CHECK_EQ(pci_vtcon_parse_port(" 0", &port, &errstr), EINVAL);
	ATF_CHECK_EQ(pci_vtcon_parse_port("+0", &port, &errstr), EINVAL);
	ATF_CHECK_EQ(pci_vtcon_parse_port("0x1", &port, &errstr), EINVAL);
	ATF_CHECK_EQ(pci_vtcon_parse_port("16", &port, &errstr), EINVAL);
	ATF_CHECK_EQ(pci_vtcon_parse_port("1garbage", &port, &errstr),
	    EINVAL);
}

ATF_TC_WITHOUT_HEAD(control_validation);
ATF_TC_BODY(control_validation, tc)
{
	struct pci_vtcon_softc sc;
	struct iovec iov[3];
	uint8_t ready[VIRTIO14_CONSOLE_CONTROL_SIZE];
	uint8_t unknown[VIRTIO14_CONSOLE_CONTROL_SIZE];
	uint8_t trailing;

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

	/* A valid header prefix with any trailing byte is still malformed. */
	iov[0] = (struct iovec){ .iov_base = ready, .iov_len = sizeof(ready) };
	iov[1] = (struct iovec){ .iov_base = &trailing, .iov_len = 1 };
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, iov, 2);
	ATF_CHECK(!sc.vsc_ready);

	/* Empty descriptor segments do not change the exact aggregate length. */
	iov[0] = (struct iovec){ .iov_base = ready, .iov_len = 3 };
	iov[1] = (struct iovec){ .iov_base = NULL, .iov_len = 0 };
	iov[2] = (struct iovec){
		.iov_base = ready + 3,
		.iov_len = sizeof(ready) - 3,
	};

	virtio14_store_le16(ready + VIRTIO14_CONSOLE_CONTROL_VALUE_OFF, 0);
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, iov, 3);
	ATF_CHECK(!sc.vsc_ready);
	virtio14_store_le16(ready + VIRTIO14_CONSOLE_CONTROL_VALUE_OFF, 1);
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, iov, 3);
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
	vq->vq_qsize = VTCON_RINGSZ;
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
	sc.vsc_queues[6].vq_qsize = VTCON_RINGSZ;
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
	sc.vsc_ports[0].vsp_console = true;
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
	ATF_CHECK(sc.vsc_ports[0].vsp_console_pending);
	ATF_CHECK(sc.vsc_ports[0].vsp_open_pending);
	ATF_CHECK_EQ(g_rel_calls, 1);

	/* The next kick nominates this configured text console. */
	reset_mocks();
	g_readable = 0;
	g_writable = 1;
	g_chain_iov[0] = (struct iovec){
		.iov_base = output, .iov_len = sizeof(output),
	};
	pci_vtcon_notify_rx(&sc, &sc.vsc_queues[2]);
	memcpy(&event, output, VIRTIO14_CONSOLE_CONTROL_SIZE);
	ATF_CHECK_EQ(event.event, VTCON_CONSOLE_PORT);
	ATF_CHECK(!sc.vsc_ports[0].vsp_console_pending);
	ATF_CHECK(sc.vsc_ports[0].vsp_open_pending);
	ATF_CHECK_EQ(g_rel_calls, 1);

	/* A later receive buffer publishes the still-pending host-open state. */
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
	sc.vsc_queues[0].vq_qsize = VTCON_RINGSZ;
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

ATF_TC_WITHOUT_HEAD(malformed_receive_dispatch_is_queue_bounded);
ATF_TC_BODY(malformed_receive_dispatch_is_queue_bounded, tc)
{
	struct pci_vtcon_softc sc;
	struct pci_vtcon_sock sock;
	struct mevent ev;
	struct vring_used used;
	char byte;
	int sv[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	memset(&sc, 0, sizeof(sc));
	memset(&sock, 0, sizeof(sock));
	memset(&used, 0, sizeof(used));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	sc.vsc_vs.vs_mtx = &sc.vsc_mtx;
	sc.vsc_ports[0].vsp_sc = &sc;
	sc.vsc_ports[0].vsp_enabled = true;
	sc.vsc_ports[0].vsp_rx_ready = true;
	sc.vsc_ports[0].vsp_txq = 0;
	sc.vsc_queues[0].vq_vs = &sc.vsc_vs;
	sc.vsc_queues[0].vq_used = &used;
	sc.vsc_queues[0].vq_qsize = 4;
	sock.vss_sc = &sc;
	sock.vss_port = &sc.vsc_ports[0];
	sock.vss_open = true;
	sock.vss_conn_fd = sv[1];
	sock.vss_conn_evp = &ev;

	reset_mocks();
	g_descs = 8;
	g_readable = 1;
	g_writable = 0;
	g_chain_iov[0] = (struct iovec){
		.iov_base = &byte, .iov_len = sizeof(byte),
	};
	ATF_REQUIRE_EQ(write(sv[0], "x", 1), 1);
	pci_vtcon_sock_rx(sv[1], EVF_READ, &sock);
	ATF_CHECK_EQ(g_get_calls, 4);
	ATF_CHECK_EQ(g_rel_calls, 4);
	ATF_CHECK_EQ(g_descs, 4);
	ATF_CHECK_EQ(recv(sv[1], &byte, 1, MSG_DONTWAIT), 1);
	ATF_CHECK_EQ(byte, 'x');

	close(sv[0]);
	close(sv[1]);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
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

static void
setup_snapshot_console(struct pci_vtcon_softc *sc,
    struct pci_vtcon_config *config, struct pci_vtcon_sock *sock,
    const char *name, const char *path)
{
	struct pci_vtcon_port *port;

	memset(sc, 0, sizeof(*sc));
	memset(config, 0, sizeof(*config));
	memset(sock, 0, sizeof(*sock));
	sc->vsc_vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	sc->vsc_features = VIRTIO14_F_VERSION_1 |
	    VIRTIO14_CONSOLE_F_MULTIPORT;
	sc->vsc_vs.vs_negotiated_caps = sc->vsc_features;
	sc->vsc_config = config;
	config->cols = htole16(80);
	config->rows = htole16(25);
	config->max_nr_ports = htole32(VTCON_MAXPORTS);
	port = &sc->vsc_ports[0];
	port->vsp_sc = sc;
	port->vsp_id = 0;
	port->vsp_name = name;
	port->vsp_enabled = true;
	port->vsp_rxq = 1;
	port->vsp_txq = 0;
	port->vsp_arg = sock;
	sock->vss_sc = sc;
	sock->vss_port = port;
	sock->vss_path = path;
	sock->vss_server_fd = 3;
	sock->vss_conn_fd = -1;
}

static void
setup_snapshot_extra_port(struct pci_vtcon_softc *sc,
    struct pci_vtcon_sock *sock, unsigned int id, const char *name,
    const char *path)
{
	struct pci_vtcon_port *port;

	ATF_REQUIRE(id > 0 && id < VTCON_MAXPORTS);
	memset(sock, 0, sizeof(*sock));
	port = &sc->vsc_ports[id];
	port->vsp_sc = sc;
	port->vsp_id = id;
	port->vsp_name = name;
	port->vsp_enabled = true;
	port->vsp_rxq = (id + 1) * 2 + 1;
	port->vsp_txq = (id + 1) * 2;
	port->vsp_arg = sock;
	sock->vss_sc = sc;
	sock->vss_port = port;
	sock->vss_path = path;
	sock->vss_server_fd = 4 + (int)id;
	sock->vss_conn_fd = -1;
}

static int
run_console_snapshot(struct pci_vtcon_softc *sc, void *buffer, size_t size,
    enum vm_snapshot_op op, size_t *used)
{
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf_start = buffer,
			.buf_size = size,
			.buf = buffer,
			.buf_rem = size,
		},
		.op = op,
	};
	int error;

	error = pci_vtcon_snapshot(sc, &meta);
	if (used != NULL)
		*used = size - meta.buffer.buf_rem;
	return (error);
}

ATF_TC_WITHOUT_HEAD(snapshot_wire_identity_and_atomicity);
ATF_TC_BODY(snapshot_wire_identity_and_atomicity, tc)
{
	struct pci_vtcon_config dst_config, src_config;
	struct pci_vtcon_sock dst_sock, dst_sock2, src_sock, src_sock2;
	struct pci_vtcon_softc destination, source;
	uint8_t image[4096];
	size_t used;

	setup_snapshot_console(&source, &src_config, &src_sock,
	    "org.freebsd.console", "/tmp/vtcon-test.sock");
	setup_snapshot_extra_port(&source, &src_sock2, 1,
	    "org.freebsd.agent", "/tmp/vtcon-agent.sock");
	source.vsc_ready = true;
	source.vsc_config->emerg_wr = htole32(0x41);
	source.vsc_ports[0].vsp_rx_ready = true;
	source.vsc_ports[0].vsp_announced = true;
	source.vsc_ports[0].vsp_guest_ready = true;
	source.vsc_ports[0].vsp_named = true;
	source.vsc_ports[0].vsp_open_pending = true;
	source.vsc_ports[1].vsp_rx_ready = true;
	source.vsc_ports[1].vsp_announced = true;
	source.vsc_ports[1].vsp_guest_ready = true;
	source.vsc_ports[1].vsp_named = true;
	source.vsc_ports[1].vsp_console = true;
	source.vsc_ports[1].vsp_console_pending = true;
	source.vsc_features ^= UINT64_C(1);
	ATF_CHECK_EQ(run_console_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, NULL), EINVAL);
	source.vsc_features ^= UINT64_C(1);
	/*
	 * The codec is a self-contained portability boundary: it must reject an
	 * enabled port without a reconstructible backend even when a caller has
	 * bypassed the normal pause callback, which also rejects this state.
	 */
	source.vsc_ports[0].vsp_arg = NULL;
	ATF_CHECK_EQ(run_console_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, NULL), EINVAL);
	source.vsc_ports[0].vsp_arg = &src_sock;
	/* A portable console image cannot encode a live host connection. */
	source.vsc_ports[0].vsp_open = true;
	ATF_CHECK_EQ(run_console_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, NULL), EINVAL);
	source.vsc_ports[0].vsp_open = false;
	ATF_REQUIRE_EQ(run_console_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	ATF_REQUIRE(used > 64);
	ATF_CHECK_EQ(image[0], 'C');
	ATF_CHECK_EQ(image[1], 'O');
	ATF_CHECK_EQ(image[2], 'N');
	ATF_CHECK_EQ(image[3], '1');
	ATF_CHECK_EQ(image[4], 1);
	ATF_CHECK_EQ(image[5], 0);

	setup_snapshot_console(&destination, &dst_config, &dst_sock,
	    "org.freebsd.console", "/tmp/vtcon-test.sock");
	setup_snapshot_extra_port(&destination, &dst_sock2, 1,
	    "org.freebsd.agent", "/tmp/vtcon-agent.sock");
	destination.vsc_ports[1].vsp_console = true;
	ATF_REQUIRE_EQ(run_console_snapshot(&destination, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), 0);
	ATF_CHECK(!destination.vsc_ready);
	ATF_CHECK(!destination.vsc_ports[0].vsp_rx_ready);
	ATF_CHECK_EQ(le32toh(destination.vsc_config->emerg_wr), 0);

	/* The production callback must propagate codec failures to preflight. */
	image[0] ^= 0xff;
	ATF_CHECK_EQ(run_console_snapshot(&destination, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), ENOTSUP);
	ATF_CHECK(!destination.vsc_ready);
	image[0] ^= 0xff;

	/* A portable image can never contain a live host socket. */
	image[31] = 1;		/* port 0 open */
	ATF_CHECK_EQ(run_console_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	ATF_CHECK(!destination.vsc_ready);
	ATF_CHECK(!destination.vsc_ports[0].vsp_open);
	image[31] = 0;

	/*
	 * The first port starts after the fixed 29-byte device header.  Its
	 * announced and guest-ready bytes follow the 15-byte port identity
	 * and the receive-ready byte.
	 */
	image[45] = 0;
	ATF_CHECK_EQ(run_console_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	ATF_CHECK(!destination.vsc_ready);
	ATF_CHECK(!destination.vsc_ports[0].vsp_rx_ready);
	image[45] = 1;

	ATF_CHECK_EQ(run_console_snapshot(&destination, image, used - 1,
	    VM_SNAPSHOT_VALIDATE, NULL), E2BIG);
	ATF_CHECK(!destination.vsc_ready);
	ATF_REQUIRE_EQ(run_console_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK(destination.vsc_ready);
	ATF_CHECK(destination.vsc_ports[0].vsp_rx_ready);
	ATF_CHECK(destination.vsc_ports[0].vsp_announced);
	ATF_CHECK(destination.vsc_ports[0].vsp_guest_ready);
	ATF_CHECK(destination.vsc_ports[0].vsp_named);
	ATF_CHECK(destination.vsc_ports[0].vsp_open_pending);
	ATF_CHECK(destination.vsc_ports[1].vsp_rx_ready);
	ATF_CHECK(destination.vsc_ports[1].vsp_announced);
	ATF_CHECK(destination.vsc_ports[1].vsp_guest_ready);
	ATF_CHECK(destination.vsc_ports[1].vsp_named);
	ATF_CHECK(destination.vsc_ports[1].vsp_console_pending);
	ATF_CHECK_EQ(le32toh(destination.vsc_config->emerg_wr), 0x41);

	/* A late truncation must not publish any earlier port state. */
	destination.vsc_ready = false;
	destination.vsc_ports[0].vsp_rx_ready = false;
	ATF_CHECK_EQ(run_console_snapshot(&destination, image, used - 1,
	    VM_SNAPSHOT_RESTORE, NULL), E2BIG);
	ATF_CHECK(!destination.vsc_ready);
	ATF_CHECK(!destination.vsc_ports[0].vsp_rx_ready);

	/* Listener identity is a destination contract, not restored bytes. */
	setup_snapshot_console(&destination, &dst_config, &dst_sock,
	    "org.freebsd.console", "/tmp/vtcon-test.sock");
	setup_snapshot_extra_port(&destination, &dst_sock2, 1,
	    "org.freebsd.agent", "/tmp/different-agent.sock");
	destination.vsc_ports[1].vsp_console = true;
	ATF_CHECK_EQ(run_console_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	ATF_CHECK(!destination.vsc_ready);

	setup_snapshot_console(&destination, &dst_config, &dst_sock,
	    "org.freebsd.different", "/tmp/vtcon-test.sock");
	setup_snapshot_extra_port(&destination, &dst_sock2, 1,
	    "org.freebsd.agent", "/tmp/vtcon-agent.sock");
	destination.vsc_ports[1].vsp_console = true;
	ATF_CHECK_EQ(run_console_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	ATF_CHECK(!destination.vsc_ready);
}

ATF_TC_WITHOUT_HEAD(snapshot_lifecycle_validation);
ATF_TC_BODY(snapshot_lifecycle_validation, tc)
{
	struct pci_vtcon_port_snapshot state;

	memset(&state, 0, sizeof(state));
	ATF_CHECK(pci_vtcon_snapshot_port_valid(true, false, &state));
	state.open_pending = 1;
	ATF_CHECK(pci_vtcon_snapshot_port_valid(true, false, &state));
	state.open_pending = 0;

	state.announced = 1;
	ATF_CHECK(pci_vtcon_snapshot_port_valid(true, false, &state));
	state.guest_ready = 1;
	ATF_CHECK(pci_vtcon_snapshot_port_valid(true, false, &state));
	state.named = 1;
	ATF_CHECK(pci_vtcon_snapshot_port_valid(true, false, &state));

	state.announced = 0;
	ATF_CHECK(!pci_vtcon_snapshot_port_valid(true, false, &state));
	state.announced = 1;
	state.guest_ready = 0;
	ATF_CHECK(!pci_vtcon_snapshot_port_valid(true, false, &state));
	state.guest_ready = 1;
	state.named = 0;
	state.console_pending = 1;
	ATF_CHECK(!pci_vtcon_snapshot_port_valid(true, false, &state));
	ATF_CHECK(pci_vtcon_snapshot_port_valid(true, true, &state));

	memset(&state, 0, sizeof(state));
	state.rx_ready = 1;
	ATF_CHECK(!pci_vtcon_snapshot_port_valid(false, false, &state));
	memset(&state, 0, sizeof(state));
	ATF_CHECK(!pci_vtcon_snapshot_port_valid(false, true, &state));
}

ATF_TC_WITHOUT_HEAD(checkpoint_rejects_active_host_socket);
ATF_TC_BODY(checkpoint_rejects_active_host_socket, tc)
{
	struct pci_vtcon_config config;
	struct pci_vtcon_sock sock;
	struct pci_vtcon_softc sc;

	setup_snapshot_console(&sc, &config, &sock, "console",
	    "/tmp/vtcon-test.sock");
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	sock.vss_open = true;
	sock.vss_conn_fd = 4;
	ATF_CHECK_EQ(pci_vtcon_pause(&sc), EBUSY);
	sock.vss_open = false;
	sock.vss_conn_fd = -1;
	ATF_REQUIRE_EQ(pci_vtcon_pause(&sc), 0);
	ATF_REQUIRE_EQ(pci_vtcon_resume(&sc), 0);
	pthread_mutex_destroy(&sc.vsc_mtx);
}

ATF_TC_WITHOUT_HEAD(snapshot_preflight_is_locally_serialized);
ATF_TC_BODY(snapshot_preflight_is_locally_serialized, tc)
{
	struct pci_devinst pi;
	struct pci_vtcon_softc sc;
	struct vm_snapshot_meta meta = {
		.dev_data = &pi,
		.op = VM_SNAPSHOT_VALIDATE,
	};

	memset(&pi, 0, sizeof(pi));
	memset(&sc, 0, sizeof(sc));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	pi.pi_arg = &sc;
	g_snapshot_validate_calls = 0;
	g_snapshot_validate_mutex_owned = false;
	ATF_CHECK_EQ(pci_de_vcon.pe_snapshot_validate, pci_vtcon_snapshot_validate);
	ATF_REQUIRE_EQ(pci_vtcon_snapshot_validate(&meta), 0);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 1);
	ATF_CHECK(g_snapshot_validate_mutex_owned);
	/* The normal restore transaction enters preflight with pause ownership. */
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vsc_mtx), 0);
	g_snapshot_validate_mutex_owned = false;
	ATF_REQUIRE_EQ(pci_vtcon_snapshot_validate(&meta), 0);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 2);
	ATF_CHECK(g_snapshot_validate_mutex_owned);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);
	meta.dev_data = NULL;
	ATF_CHECK_EQ(pci_vtcon_snapshot_validate(&meta), EINVAL);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 2);
	pthread_mutex_destroy(&sc.vsc_mtx);
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

/*
 * Connect a client stream socket to an AF_UNIX listener at path.  Returns the
 * client fd (>= 0) or -1 on failure.  The listener is non-blocking, so the
 * connect completes on the kernel accept queue without a peer accept() yet.
 */
static int
connect_unix_client(const char *path)
{
	struct sockaddr_un sun;
	int c;

	c = socket(AF_UNIX, SOCK_STREAM, 0);
	if (c < 0)
		return (-1);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	sun.sun_len = sizeof(sun);
	if (strlcpy(sun.sun_path, path, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path)) {
		close(c);
		return (-1);
	}
	if (connect(c, (struct sockaddr *)&sun, sun.sun_len) < 0) {
		close(c);
		return (-1);
	}
	return (c);
}

ATF_TC_WITHOUT_HEAD(resume_device_is_a_noop);
ATF_TC_BODY(resume_device_is_a_noop, tc)
{
	struct pci_vtcon_softc sc;

	memset(&sc, 0, sizeof(sc));
	ATF_CHECK_EQ(pci_vtcon_suspend_device(&sc), 0);
	ATF_CHECK_EQ(pci_vtcon_resume_device(&sc), 0);
	ATF_CHECK(vtcon_vi_consts.vc_resume_device == pci_vtcon_resume_device);
}

ATF_TC_WITHOUT_HEAD(port_add_assigns_spec_queue_indices);
ATF_TC_BODY(port_add_assigns_spec_queue_indices, tc)
{
	struct pci_vtcon_softc sc;
	struct pci_vtcon_port *p0, *p5;
	int arg;

	memset(&sc, 0, sizeof(sc));
	reset_mocks();

	/*
	 * VirtIO 1.4 5.3.2: port 0 uses queues 0/1; port N>0 uses queues
	 * 2N+2 (rx) and 2N+3 (tx), i.e. tx=(N+1)*2, rx=tx+1.
	 */
	p0 = pci_vtcon_port_add(&sc, 0, "p0", capture_cb, resume_rx_cb,
	    disable_rx_cb, &arg);
	ATF_REQUIRE(p0 != NULL);
	ATF_CHECK_EQ(p0->vsp_txq, 0);
	ATF_CHECK_EQ(p0->vsp_rxq, 1);
	ATF_CHECK(p0->vsp_enabled);
	ATF_CHECK(p0->vsp_sc == &sc);
	ATF_CHECK(p0->vsp_cb == capture_cb);

	p5 = pci_vtcon_port_add(&sc, 5, "p5", capture_cb, NULL, NULL, &arg);
	ATF_REQUIRE(p5 != NULL);
	ATF_CHECK_EQ(p5->vsp_txq, (5 + 1) * 2);
	ATF_CHECK_EQ(p5->vsp_rxq, (5 + 1) * 2 + 1);

	/* A second add of an active port is rejected. */
	errno = 0;
	ATF_CHECK(pci_vtcon_port_add(&sc, 0, "dup", capture_cb, NULL, NULL,
	    &arg) == NULL);
	ATF_CHECK_EQ(errno, EBUSY);
}

ATF_TC_WITHOUT_HEAD(sock_add_argument_validation);
ATF_TC_BODY(sock_add_argument_validation, tc)
{
	struct pci_vtcon_softc sc;
	struct nvlist nvl = { 0 };
	static char longpath[128];

	memset(&sc, 0, sizeof(sc));
	reset_mocks();

	/* An unparseable port node is rejected before any resource is taken. */
	ATF_CHECK_EQ(pci_vtcon_sock_add(&sc, "bogus", &nvl), -1);

	/* A missing path or name is a configuration error. */
	g_sock_path = NULL;
	g_sock_name = "n";
	ATF_CHECK_EQ(pci_vtcon_sock_add(&sc, "0", &nvl), -1);
	g_sock_path = "/tmp/vtcon-x.sock";
	g_sock_name = NULL;
	ATF_CHECK_EQ(pci_vtcon_sock_add(&sc, "0", &nvl), -1);

	/* The per-port bookkeeping allocation can fail. */
	g_sock_path = "/tmp/vtcon-x.sock";
	g_sock_name = "n";
	g_calloc_fail = 1;
	ATF_CHECK_EQ(pci_vtcon_sock_add(&sc, "0", &nvl), -1);

	/* A basename longer than sun_path cannot be bound. */
	memset(longpath, 'a', sizeof(longpath) - 1);
	memcpy(longpath, "/tmp/", 5);
	longpath[sizeof(longpath) - 1] = '\0';
	g_sock_path = longpath;
	g_sock_name = "n";
	errno = 0;
	ATF_CHECK_EQ(pci_vtcon_sock_add(&sc, "0", &nvl), -1);
	ATF_CHECK_EQ(errno, ENAMETOOLONG);

	/* The parent directory of the socket path must be openable. */
	g_sock_path = "/nonexistent-vtcon-dir-9x8y7z/c.sock";
	g_sock_name = "n";
	ATF_CHECK_EQ(pci_vtcon_sock_add(&sc, "0", &nvl), -1);
}

ATF_TC_WITHOUT_HEAD(socket_backend_full_lifecycle);
ATF_TC_BODY(socket_backend_full_lifecycle, tc)
{
	struct pci_devinst pi;
	struct pci_vtcon_softc *sc;
	struct pci_vtcon_sock *sock;
	struct nvlist nvl;
	char dir[] = "/tmp/vtcon-lc.XXXXXX";
	char path[128];
	int client, client2;

	if (mkdtemp(dir) == NULL)
		atf_tc_skip("mkdtemp failed: %s", strerror(errno));
	snprintf(path, sizeof(path), "%s/c.sock", dir);

	memset(&pi, 0, sizeof(pi));
	reset_mocks();
	g_transport = "modern";
	g_sock_path = path;
	g_sock_name = "org.freebsd.console";
	g_port_node = "0";

	if (pci_vtcon_init(&pi, &nvl) != 0) {
		rmdir(dir);
		atf_tc_skip("socket backend unavailable in this environment");
	}
	/* vsc_vs is the first softc member, so pi_arg aliases the softc. */
	sc = pi.pi_arg;
	ATF_REQUIRE(sc->vsc_ports[0].vsp_enabled);
	sock = sc->vsc_ports[0].vsp_arg;
	ATF_REQUIRE(sock != NULL);
	ATF_CHECK(sock->vss_server_fd >= 0);
	ATF_CHECK(!sock->vss_open);
	ATF_CHECK(sock->vss_conn_fd == -1);

	/* No pending connection: the non-blocking accept declines cleanly. */
	pci_vtcon_sock_accept(sock->vss_server_fd, EVF_READ, sock);
	ATF_CHECK(!sock->vss_open);

	/* A real client connection is accepted and the port is opened. */
	client = connect_unix_client(path);
	ATF_REQUIRE(client >= 0);
	pci_vtcon_sock_accept(sock->vss_server_fd, EVF_READ, sock);
	ATF_CHECK(sock->vss_open);
	ATF_CHECK(sock->vss_conn_fd >= 0);
	ATF_CHECK(sc->vsc_ports[0].vsp_open);

	/* The receive-enable callback re-arms the connection read event. */
	g_enable_calls = 0;
	pci_vtcon_sock_rx_enable(sock->vss_port, sock);
	ATF_CHECK_EQ(g_enable_calls, 1);
	g_disable_calls = 0;
	pci_vtcon_sock_rx_disable(sock->vss_port, sock);
	ATF_CHECK_EQ(g_disable_calls, 1);

	/* A second connection while already open is refused and closed. */
	client2 = connect_unix_client(path);
	ATF_REQUIRE(client2 >= 0);
	pci_vtcon_sock_accept(sock->vss_server_fd, EVF_READ, sock);
	ATF_CHECK(sock->vss_open);
	close(client);
	close(client2);

	/*
	 * Force the connection to close so the accept path can be re-driven
	 * through its event-registration failure branches.
	 */
	pci_vtcon_sock_close(sock);
	ATF_CHECK(!sock->vss_open);

	/* mevent_add() for the read event fails: the accepted fd is dropped. */
	client = connect_unix_client(path);
	ATF_REQUIRE(client >= 0);
	g_mevent_add_fail = 1;
	pci_vtcon_sock_accept(sock->vss_server_fd, EVF_READ, sock);
	ATF_CHECK(!sock->vss_open);
	ATF_CHECK_EQ(sock->vss_conn_fd, -1);
	close(client);

	/* mevent_add_disabled() for the write event fails after the read add. */
	client = connect_unix_client(path);
	ATF_REQUIRE(client >= 0);
	g_mevent_add_disabled_fail = 1;
	pci_vtcon_sock_accept(sock->vss_server_fd, EVF_READ, sock);
	ATF_CHECK(!sock->vss_open);
	ATF_CHECK_EQ(sock->vss_conn_fd, -1);
	close(client);

	/*
	 * Re-establish a live connection so device teardown must synchronously
	 * retire the read, write, and listener events and close both fds.
	 */
	client = connect_unix_client(path);
	ATF_REQUIRE(client >= 0);
	pci_vtcon_sock_accept(sock->vss_server_fd, EVF_READ, sock);
	ATF_REQUIRE(sock->vss_open);
	ATF_REQUIRE(sock->vss_conn_fd >= 0);
	close(client);

	/* Device teardown frees the port, its socket, and unlinks the path. */
	pci_vtcon_destroy(sc);
	rmdir(dir);

	/* Destroying a NULL device is a no-op. */
	pci_vtcon_destroy(NULL);
}

ATF_TC_WITHOUT_HEAD(sock_add_teardown_after_late_failure);
ATF_TC_BODY(sock_add_teardown_after_late_failure, tc)
{
	struct pci_vtcon_softc sc;
	struct nvlist nvl = { 0 };
	char dir[] = "/tmp/vtcon-tf.XXXXXX";
	char path[128];

	if (mkdtemp(dir) == NULL)
		atf_tc_skip("mkdtemp failed: %s", strerror(errno));
	snprintf(path, sizeof(path), "%s/c.sock", dir);

	memset(&sc, 0, sizeof(sc));
	reset_mocks();
	g_sock_path = path;
	g_sock_name = "console";
	/* Pre-enable the target port so port_add fails after the bind. */
	sc.vsc_ports[0].vsp_enabled = true;
	ATF_CHECK_EQ(pci_vtcon_sock_add(&sc, "0", &nvl), -1);
	/* The bound path must have been unlinked by the failure cleanup. */
	ATF_CHECK(access(path, F_OK) != 0);

	/*
	 * Registering the listener event can fail; the half-built port is torn
	 * down and the bound path removed.
	 */
	memset(&sc, 0, sizeof(sc));
	reset_mocks();
	g_sock_path = path;
	g_sock_name = "console";
	g_mevent_add_fail = 1;
	ATF_CHECK_EQ(pci_vtcon_sock_add(&sc, "0", &nvl), -1);
	ATF_CHECK(!sc.vsc_ports[0].vsp_enabled);
	ATF_CHECK(access(path, F_OK) != 0);

	/*
	 * Binding a path that is already bound by another port fails.  Port 0
	 * takes the path first, then port 1 tries to reuse it.
	 */
	memset(&sc, 0, sizeof(sc));
	reset_mocks();
	g_sock_path = path;
	g_sock_name = "console";
	ATF_REQUIRE_EQ(pci_vtcon_sock_add(&sc, "0", &nvl), 0);
	ATF_CHECK_EQ(pci_vtcon_sock_add(&sc, "1", &nvl), -1);
	free_port_socks(&sc);
	unlink(path);
	rmdir(dir);
}

ATF_TC_WITHOUT_HEAD(sock_close_without_read_event);
ATF_TC_BODY(sock_close_without_read_event, tc)
{
	struct pci_vtcon_softc sc;
	struct pci_vtcon_port port;
	struct pci_vtcon_sock sock;
	int fd;

	memset(&sc, 0, sizeof(sc));
	memset(&port, 0, sizeof(port));
	memset(&sock, 0, sizeof(sock));
	reset_mocks();
	port.vsp_sc = &sc;
	sock.vss_port = &port;
	sock.vss_open = true;
	sock.vss_conn_evp = NULL;
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	sock.vss_conn_fd = fd;

	/* With no read event registered, close() takes the raw fd path. */
	pci_vtcon_sock_close(&sock);
	ATF_CHECK(!sock.vss_open);
	ATF_CHECK_EQ(sock.vss_conn_fd, -1);
	/* The fd is closed by sock_close; a second close must report EBADF. */
	ATF_CHECK(close(fd) == -1 && errno == EBADF);
}

ATF_TC_WITHOUT_HEAD(receive_kick_rearm_race);
ATF_TC_BODY(receive_kick_rearm_race, tc)
{
	struct pci_vtcon_softc sc;
	struct pci_vtcon_sock sock;
	struct mevent ev;
	struct vring_used used;
	char byte;
	int sv[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	memset(&sc, 0, sizeof(sc));
	memset(&sock, 0, sizeof(sock));
	memset(&used, 0, sizeof(used));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	sc.vsc_vs.vs_mtx = &sc.vsc_mtx;
	sc.vsc_ports[0].vsp_sc = &sc;
	sc.vsc_ports[0].vsp_enabled = true;
	sc.vsc_ports[0].vsp_rx_ready = true;
	sc.vsc_ports[0].vsp_txq = 0;
	sc.vsc_queues[0].vq_vs = &sc.vsc_vs;
	sc.vsc_queues[0].vq_used = &used;
	sc.vsc_queues[0].vq_num = 0;
	sc.vsc_queues[0].vq_qsize = VTCON_RINGSZ;
	sock.vss_sc = &sc;
	sock.vss_port = &sc.vsc_ports[0];
	sock.vss_open = true;
	sock.vss_conn_fd = sv[1];
	sock.vss_conn_evp = &ev;

	reset_mocks();
	g_descs = 1;
	g_descs_delay = 1;	/* first probe empty, then a descriptor appears */
	g_readable = 0;
	g_writable = 1;
	g_chain_iov[0] = (struct iovec){ .iov_base = &byte, .iov_len = 1 };
	ATF_REQUIRE_EQ(write(sv[0], "z", 1), 1);
	pci_vtcon_sock_rx(sv[1], EVF_READ, &sock);
	ATF_CHECK_EQ(g_get_calls, 1);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len, 1);
	ATF_CHECK(sc.vsc_ports[0].vsp_rx_ready);

	close(sv[0]);
	close(sv[1]);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(receive_eof_and_errors);
ATF_TC_BODY(receive_eof_and_errors, tc)
{
	struct pci_vtcon_softc sc;
	struct pci_vtcon_sock sock;
	struct pci_vtcon_port port;
	struct mevent ev;
	struct vring_used used;
	char byte;
	int sv[2], wonly;

	memset(&sc, 0, sizeof(sc));
	memset(&port, 0, sizeof(port));
	memset(&used, 0, sizeof(used));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	sc.vsc_vs.vs_mtx = &sc.vsc_mtx;
	port.vsp_sc = &sc;
	port.vsp_enabled = true;
	port.vsp_rx_ready = true;
	port.vsp_txq = 0;
	sc.vsc_queues[0].vq_vs = &sc.vsc_vs;
	sc.vsc_queues[0].vq_used = &used;
	sc.vsc_queues[0].vq_num = 0;
	sc.vsc_queues[0].vq_qsize = VTCON_RINGSZ;

	/* A stale callback for a superseded connection is a NULL-port no-op. */
	memset(&sock, 0, sizeof(sock));
	sock.vss_sc = &sc;
	sock.vss_port = NULL;
	sock.vss_open = true;
	sock.vss_conn_fd = 200;
	reset_mocks();
	pci_vtcon_sock_rx(200, EVF_READ, &sock);
	ATF_CHECK_EQ(g_get_calls, 0);

	/* A closed session (vss_open false) consumes nothing. */
	sock.vss_port = &port;
	sock.vss_open = false;
	reset_mocks();
	pci_vtcon_sock_rx(200, EVF_READ, &sock);
	ATF_CHECK_EQ(g_get_calls, 0);

	/* getchain returning zero breaks the readiness loop. */
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	memset(&sock, 0, sizeof(sock));
	sock.vss_sc = &sc;
	sock.vss_port = &port;
	sock.vss_open = true;
	sock.vss_conn_fd = sv[1];
	sock.vss_conn_evp = &ev;
	port.vsp_rx_ready = true;
	reset_mocks();
	g_descs = 1;
	g_chain_n = 0;
	pci_vtcon_sock_rx(sv[1], EVF_READ, &sock);
	ATF_CHECK_EQ(g_get_calls, 0);
	close(sv[0]);
	close(sv[1]);

	/* An empty readv (peer hangup) closes the backend. */
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	memset(&sock, 0, sizeof(sock));
	sock.vss_sc = &sc;
	sock.vss_port = &port;
	sock.vss_open = true;
	sock.vss_conn_fd = sv[1];
	sock.vss_conn_evp = &ev;
	port.vsp_rx_ready = true;
	reset_mocks();
	g_descs = 1;
	g_readable = 0;
	g_writable = 1;
	g_chain_iov[0] = (struct iovec){ .iov_base = &byte, .iov_len = 1 };
	close(sv[0]);
	pci_vtcon_sock_rx(sv[1], EVF_READ, &sock);
	ATF_CHECK(!sock.vss_open);
	close(sv[1]);

	/* A hard read error (non-EAGAIN) also closes the backend. */
	wonly = open("/dev/null", O_WRONLY);
	ATF_REQUIRE(wonly >= 0);
	memset(&sock, 0, sizeof(sock));
	sock.vss_sc = &sc;
	sock.vss_port = &port;
	sock.vss_open = true;
	sock.vss_conn_fd = wonly;
	sock.vss_conn_evp = &ev;
	port.vsp_rx_ready = true;
	reset_mocks();
	g_descs = 1;
	g_readable = 0;
	g_writable = 1;
	g_chain_iov[0] = (struct iovec){ .iov_base = &byte, .iov_len = 1 };
	pci_vtcon_sock_rx(wonly, EVF_READ, &sock);
	ATF_CHECK(!sock.vss_open);

	/* No host bytes yet: a non-blocking readv returns EAGAIN and defers. */
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	ATF_REQUIRE(fcntl(sv[1], F_SETFL,
	    fcntl(sv[1], F_GETFL) | O_NONBLOCK) == 0);
	memset(&sock, 0, sizeof(sock));
	sock.vss_sc = &sc;
	sock.vss_port = &port;
	sock.vss_open = true;
	sock.vss_conn_fd = sv[1];
	sock.vss_conn_evp = &ev;
	port.vsp_rx_ready = true;
	reset_mocks();
	g_descs = 1;
	g_readable = 0;
	g_writable = 1;
	g_chain_iov[0] = (struct iovec){ .iov_base = &byte, .iov_len = 1 };
	pci_vtcon_sock_rx(sv[1], EVF_READ, &sock);
	ATF_CHECK(sock.vss_open);		/* deferred, not closed */
	ATF_CHECK_EQ(g_ret_calls, 1);		/* descriptor returned */
	close(sv[0]);
	close(sv[1]);

	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(transmit_edge_conditions);
ATF_TC_BODY(transmit_edge_conditions, tc)
{
	struct pci_vtcon_softc sc;
	struct pci_vtcon_port port;
	struct pci_vtcon_sock sock;
	struct mevent read_ev, write_ev;
	struct iovec iov;
	static uint8_t big[8192];
	int fd;

	memset(&sc, 0, sizeof(sc));
	memset(&port, 0, sizeof(port));
	port.vsp_sc = &sc;

	/* A closed backend drops output without touching the buffer. */
	memset(&sock, 0, sizeof(sock));
	sock.vss_port = &port;
	sock.vss_open = false;
	sock.vss_conn_fd = -1;
	reset_mocks();
	iov = (struct iovec){ .iov_base = big, .iov_len = 1 };
	pci_vtcon_sock_tx(&port, &sock, &iov, 1);
	ATF_CHECK(sock.vss_tx_buf == NULL);

	/* A single chain that exceeds the hard cap closes the backend. */
	memset(&sock, 0, sizeof(sock));
	sock.vss_port = &port;
	sock.vss_open = true;
	sock.vss_conn_fd = 300;
	sock.vss_conn_evp = &read_ev;
	sock.vss_write_evp = &write_ev;
	reset_mocks();
	iov = (struct iovec){ .iov_base = big,
	    .iov_len = (size_t)VTCON_SOCK_TX_MAX + 1 };
	pci_vtcon_sock_tx(&port, &sock, &iov, 1);
	ATF_CHECK(!sock.vss_open);

	/* drain() with nothing pending is a no-op. */
	memset(&sock, 0, sizeof(sock));
	sock.vss_port = &port;
	sock.vss_open = true;
	sock.vss_conn_fd = 301;
	sock.vss_write_evp = &write_ev;
	reset_mocks();
	pci_vtcon_sock_drain(&sock);
	ATF_CHECK(sock.vss_open);

	/* A large append grows the staging buffer through the doubling clamp. */
	fd = open("/dev/null", O_WRONLY);
	ATF_REQUIRE(fd >= 0);
	memset(&sock, 0, sizeof(sock));
	sock.vss_port = &port;
	sock.vss_open = true;
	sock.vss_conn_fd = fd;
	sock.vss_conn_evp = &read_ev;
	sock.vss_write_evp = &write_ev;
	reset_mocks();
	g_send_override_fd = fd;
	g_send_result = sizeof(big);
	iov = (struct iovec){ .iov_base = big, .iov_len = sizeof(big) };
	pci_vtcon_sock_tx(&port, &sock, &iov, 1);
	ATF_CHECK(sock.vss_open);
	ATF_CHECK(sock.vss_tx_cap >= sizeof(big));
	ATF_CHECK_EQ(sock.vss_tx_len, sock.vss_tx_off);
	free(sock.vss_tx_buf);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(control_send_edge_conditions);
ATF_TC_BODY(control_send_edge_conditions, tc)
{
	struct pci_vtcon_softc sc;
	struct pci_vtcon_control ctrl;
	uint8_t out[VIRTIO14_CONSOLE_CONTROL_SIZE];

	memset(&sc, 0, sizeof(sc));
	sc.vsc_control_port.vsp_sc = &sc;
	sc.vsc_control_port.vsp_txq = 2;
	sc.vsc_queues[2].vq_num = 2;
	sc.vsc_features = 1ULL << VTCON_F_MULTIPORT;
	ctrl = (struct pci_vtcon_control){
	    .id = 0, .event = VTCON_DEVICE_ADD, .value = 1,
	};

	/* A payload length that would overflow the message size is rejected. */
	reset_mocks();
	ATF_CHECK(!pci_vtcon_control_send(&sc, &ctrl, "x", SIZE_MAX));

	/* getchain returning zero on an available queue fails the send. */
	reset_mocks();
	g_descs = 1;
	g_chain_n = 0;
	ATF_CHECK(!pci_vtcon_control_send(&sc, &ctrl, NULL, 0));

	/* A message allocation failure fails the send without corrupting state. */
	reset_mocks();
	g_descs = 1;
	g_chain_n = 1;
	g_readable = 0;
	g_writable = 1;
	g_chain_iov[0] = (struct iovec){ .iov_base = out, .iov_len = sizeof(out) };
	g_malloc_fail = 1;
	ATF_CHECK(!pci_vtcon_control_send(&sc, &ctrl, NULL, 0));
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len, 0);
}

ATF_TC_WITHOUT_HEAD(announce_and_open_edge_conditions);
ATF_TC_BODY(announce_and_open_edge_conditions, tc)
{
	struct pci_vtcon_softc sc;
	struct pci_vtcon_port *port;
	struct pci_vtcon_control ctrl;
	struct iovec iov;

	memset(&sc, 0, sizeof(sc));
	sc.vsc_control_port.vsp_sc = &sc;
	sc.vsc_control_port.vsp_txq = 2;
	sc.vsc_control_port.vsp_rxq = 3;
	sc.vsc_queues[2].vq_num = 2;
	sc.vsc_features = 1ULL << VTCON_F_MULTIPORT;
	port = &sc.vsc_ports[0];
	port->vsp_sc = &sc;
	port->vsp_enabled = true;
	port->vsp_id = 0;
	port->vsp_name = "console";

	/* PORT_NAME cannot be published when no receive buffer is available. */
	reset_mocks();
	g_descs = 0;
	port->vsp_announced = true;
	port->vsp_guest_ready = true;
	port->vsp_named = false;
	ATF_CHECK(!pci_vtcon_announce_port(port));
	ATF_CHECK(!port->vsp_named);

	/* open_port on a ready device announces the new host-open state. */
	reset_mocks();
	sc.vsc_ready = true;
	port->vsp_announced = true;
	port->vsp_guest_ready = false;
	pci_vtcon_open_port(port, true);
	ATF_CHECK(port->vsp_open);
	ATF_CHECK(port->vsp_open_pending);

	/* PORT_READY for an unannounced port is refused. */
	sc.vsc_ready = true;
	port->vsp_announced = false;
	ctrl = (struct pci_vtcon_control){
	    .id = 0, .event = VTCON_PORT_READY, .value = 1,
	};
	iov = (struct iovec){ .iov_base = &ctrl,
	    .iov_len = VIRTIO14_CONSOLE_CONTROL_SIZE };
	reset_mocks();
	sc.vsc_vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	pci_vtcon_control_tx(&sc.vsc_control_port, NULL, &iov, 1);
	ATF_CHECK(!port->vsp_guest_ready);
}

ATF_TC_WITHOUT_HEAD(notify_empty_and_inactive);
ATF_TC_BODY(notify_empty_and_inactive, tc)
{
	struct pci_vtcon_softc sc;

	memset(&sc, 0, sizeof(sc));
	sc.vsc_features = 1ULL << VTCON_F_MULTIPORT;
	sc.vsc_ports[1].vsp_enabled = true;
	sc.vsc_ports[1].vsp_cb = capture_cb;
	sc.vsc_queues[4].vq_num = 4;
	sc.vsc_queues[4].vq_qsize = VTCON_RINGSZ;

	/* getchain returning zero breaks the transmit drain loop. */
	reset_mocks();
	g_descs = 1;
	g_chain_n = 0;
	pci_vtcon_notify_tx(&sc, &sc.vsc_queues[4]);
	ATF_CHECK_EQ(g_callback_calls, 0);
	ATF_CHECK_EQ(g_end_calls, 1);

	/* Without multiport, the extra receive queue is inert. */
	memset(&sc, 0, sizeof(sc));
	sc.vsc_queues[4].vq_num = 4;
	reset_mocks();
	pci_vtcon_notify_rx(&sc, &sc.vsc_queues[4]);
	ATF_CHECK_EQ(g_get_calls, 0);
}

ATF_TC_WITHOUT_HEAD(legacy_parser_errors);
ATF_TC_BODY(legacy_parser_errors, tc)
{
	struct nvlist nvl;
	char opts[512];
	int i, off;

	/* A port entry without a path is rejected. */
	reset_mocks();
	ATF_CHECK_EQ(pci_vtcon_legacy_config(&nvl, "namewithoutpath"), -1);

	/* More port entries than the device supports is rejected. */
	reset_mocks();
	off = 0;
	for (i = 0; i < VTCON_MAXPORTS + 1; i++)
		off += snprintf(opts + off, sizeof(opts) - off, "%sp%d=/tmp/p%d",
		    i == 0 ? "" : ",", i, i);
	ATF_CHECK_EQ(pci_vtcon_legacy_config(&nvl, opts), -1);
}

ATF_TC_WITHOUT_HEAD(init_failure_paths);
ATF_TC_BODY(init_failure_paths, tc)
{
	struct pci_devinst pi;
	struct nvlist nvl;

	/* The softc allocation can fail. */
	memset(&pi, 0, sizeof(pi));
	reset_mocks();
	g_calloc_fail = 1;
	ATF_CHECK_EQ(pci_vtcon_init(&pi, &nvl), 1);

	/* The config allocation (second calloc) can fail. */
	memset(&pi, 0, sizeof(pi));
	reset_mocks();
	g_calloc_fail = 2;
	ATF_CHECK_EQ(pci_vtcon_init(&pi, &nvl), 1);

	/* An unknown transport selection fails initialization. */
	memset(&pi, 0, sizeof(pi));
	reset_mocks();
	g_transport = "bogus";
	ATF_CHECK_EQ(pci_vtcon_init(&pi, &nvl), 1);

	/* Interrupt setup failure tears the device down. */
	memset(&pi, 0, sizeof(pi));
	reset_mocks();
	g_intr_fail = true;
	ATF_CHECK_EQ(pci_vtcon_init(&pi, &nvl), 1);

	/* Modern transport init failure tears the device down. */
	memset(&pi, 0, sizeof(pi));
	reset_mocks();
	g_transport = "modern";
	g_modern_init_fail = true;
	ATF_CHECK_EQ(pci_vtcon_init(&pi, &nvl), 1);

	/* A port that cannot be created aborts initialization. */
	memset(&pi, 0, sizeof(pi));
	reset_mocks();
	g_port_node = "0";
	g_sock_path = NULL;	/* missing path -> sock_add fails */
	g_sock_name = "n";
	ATF_CHECK_EQ(pci_vtcon_init(&pi, &nvl), 1);

	/* A non-nvlist entry in the port container is skipped. */
	memset(&pi, 0, sizeof(pi));
	reset_mocks();
	g_port_node = "0";
	g_port_node_type = NV_TYPE_NVLIST + 1;	/* any non-nvlist type */
	ATF_REQUIRE_EQ(pci_vtcon_init(&pi, &nvl), 0);
	ATF_CHECK(!((struct pci_vtcon_softc *)pi.pi_arg)->vsc_ports[0].
	    vsp_enabled);
	pci_vtcon_destroy(pi.pi_arg);
}

ATF_TC_WITHOUT_HEAD(snapshot_negative_load_paths);
ATF_TC_BODY(snapshot_negative_load_paths, tc)
{
	struct pci_vtcon_config src_config, dst_config;
	struct pci_vtcon_sock src_sock, dst_sock;
	struct pci_vtcon_softc source, destination;
	uint8_t image[4096];
	size_t used;

	setup_snapshot_console(&source, &src_config, &src_sock,
	    "console", "/tmp/vtcon-neg.sock");
	source.vsc_ready = true;
	ATF_REQUIRE_EQ(run_console_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);

	/* The device-ready byte (offset 16) is a strict boolean. */
	setup_snapshot_console(&destination, &dst_config, &dst_sock,
	    "console", "/tmp/vtcon-neg.sock");
	image[16] = 2;
	ATF_CHECK_EQ(run_console_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	image[16] = 1;

	/* A features word that disagrees with the destination is rejected. */
	setup_snapshot_console(&destination, &dst_config, &dst_sock,
	    "console", "/tmp/vtcon-neg.sock");
	image[8] ^= 0xff;
	ATF_CHECK_EQ(run_console_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	image[8] ^= 0xff;

	/*
	 * An immutable per-port attribute that disagrees with the destination
	 * (here the console flag on port 0) is rejected on load.
	 */
	setup_snapshot_console(&destination, &dst_config, &dst_sock,
	    "console", "/tmp/vtcon-neg.sock");
	destination.vsc_ports[0].vsp_console = true;
	ATF_CHECK_EQ(run_console_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
}

ATF_TC_WITHOUT_HEAD(snapshot_validate_requires_softc);
ATF_TC_BODY(snapshot_validate_requires_softc, tc)
{
	struct pci_devinst pi;
	struct vm_snapshot_meta meta = {
	    .dev_data = &pi,
	    .op = VM_SNAPSHOT_VALIDATE,
	};

	memset(&pi, 0, sizeof(pi));
	pi.pi_arg = NULL;
	ATF_CHECK_EQ(pci_vtcon_snapshot_validate(&meta), EINVAL);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, virtio_1_4_wire_layout);
	ATF_TP_ADD_TC(tp, transport_and_features);
	ATF_TP_ADD_TC(tp, suspend_resume_rearms_existing_rx);
	ATF_TP_ADD_TC(tp, in_order_completion);
	ATF_TP_ADD_TC(tp, emergency_write);
	ATF_TP_ADD_TC(tp, queue_reset_isolated);
	ATF_TP_ADD_TC(tp, queue_reset_fences_selected_rx_callback);
	ATF_TP_ADD_TC(tp, stale_connection_callbacks_are_ignored);
	ATF_TP_ADD_TC(tp, legacy_parser_transport);
	ATF_TP_ADD_TC(tp, port_identifier_validation);
	ATF_TP_ADD_TC(tp, control_validation);
	ATF_TP_ADD_TC(tp, document_wire_vectors);
	ATF_TP_ADD_TC(tp, transmit_validation);
	ATF_TP_ADD_TC(tp, control_receive_scatter);
	ATF_TP_ADD_TC(tp, multiport_feature_gating);
	ATF_TP_ADD_TC(tp, device_add_lifecycle);
	ATF_TP_ADD_TC(tp, device_add_name_retry);
	ATF_TP_ADD_TC(tp, receive_preserves_data);
	ATF_TP_ADD_TC(tp, malformed_receive_dispatch_is_queue_bounded);
	ATF_TP_ADD_TC(tp, transmit_backpressure);
	ATF_TP_ADD_TC(tp, transmit_partial_and_compaction);
	ATF_TP_ADD_TC(tp, transmit_failure_paths);
	ATF_TP_ADD_TC(tp, snapshot_wire_identity_and_atomicity);
	ATF_TP_ADD_TC(tp, snapshot_preflight_is_locally_serialized);
	ATF_TP_ADD_TC(tp, snapshot_lifecycle_validation);
	ATF_TP_ADD_TC(tp, checkpoint_rejects_active_host_socket);
	ATF_TP_ADD_TC(tp, resume_device_is_a_noop);
	ATF_TP_ADD_TC(tp, port_add_assigns_spec_queue_indices);
	ATF_TP_ADD_TC(tp, sock_add_argument_validation);
	ATF_TP_ADD_TC(tp, socket_backend_full_lifecycle);
	ATF_TP_ADD_TC(tp, sock_add_teardown_after_late_failure);
	ATF_TP_ADD_TC(tp, sock_close_without_read_event);
	ATF_TP_ADD_TC(tp, receive_kick_rearm_race);
	ATF_TP_ADD_TC(tp, receive_eof_and_errors);
	ATF_TP_ADD_TC(tp, transmit_edge_conditions);
	ATF_TP_ADD_TC(tp, control_send_edge_conditions);
	ATF_TP_ADD_TC(tp, announce_and_open_edge_conditions);
	ATF_TP_ADD_TC(tp, notify_empty_and_inactive);
	ATF_TP_ADD_TC(tp, legacy_parser_errors);
	ATF_TP_ADD_TC(tp, init_failure_paths);
	ATF_TP_ADD_TC(tp, snapshot_negative_load_paths);
	ATF_TP_ADD_TC(tp, snapshot_validate_requires_softc);
	return (atf_no_error());
}
