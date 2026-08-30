/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Fault-injection tests for bhyve's VirtIO 9P device.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "virtio_config_read_test_support.h"
#define	BHYVE_SNAPSHOT
#define	VT9P_QUIESCE_TIMEOUT_SECONDS	1
#include "pci_virtio_9p.c"
#include "virtio_1_4_spec.h"

#undef VIRTIO_CONFIG_S_NEEDS_RESET
#define	VIRTIO_CONFIG_S_NEEDS_RESET	VIRTIO14_STATUS_DEVICE_NEEDS_RESET
#undef VIRTIO_ID_9P
#define	VIRTIO_ID_9P			VIRTIO14_DEVICE_9P
#undef VIRTIO_9P_F_MOUNT_TAG
#define	VIRTIO_9P_F_MOUNT_TAG		VIRTIO14_9P_F_MOUNT_TAG
#undef VIRTIO_F_RING_RESET
#define	VIRTIO_F_RING_RESET		VIRTIO14_F_RING_RESET
#undef VIRTIO_F_SUSPEND
#define	VIRTIO_F_SUSPEND		VIRTIO14_F_SUSPEND
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
static bool g_has_fid;
static struct l9p_connection g_connection;
static uint8_t g_config[VT9P_CONFIGSPACESZ];
static int g_snapshot_validate_calls;
static bool g_snapshot_validate_mutex_owned;

/* Init-path mocks (see scsi/console tests: the real bhyve build strips
 * pci_vt9p_init() unless the linker set is referenced; here we drive it
 * directly with a mocked virtio core and lib9p backend). */
static const char *g_cfg_sharename;
static const char *g_cfg_path;
static bool g_cfg_ro;
static bool g_cfg_packed;
static enum virtio_pci_transport g_init_transport;
static int g_init_transport_error;
static int g_modern_init_error;
static int g_intr_init_error;
static int g_backend_init_error;
static int g_server_init_error;
static int g_msix_result;
static uint16_t g_modern_identity;
static int g_linkup_calls;
static struct l9p_backend g_fs_backend;
static struct l9p_server g_server;
static uint16_t g_cfg_device;
static uint16_t g_cfg_vendor;
static uint16_t g_cfg_subdev;
static uint16_t g_cfg_subvend;
static uint8_t g_cfg_class;
/* calloc/strdup fault injection: fail the Nth allocation after arming. */
static int g_calloc_fail_at;
static int g_calloc_calls;
static int g_strdup_fail_at;
static int g_strdup_calls;

extern void *__real_calloc(size_t, size_t);
extern char *__real_strdup(const char *);
void *__wrap_calloc(size_t, size_t);
char *__wrap_strdup(const char *);

void *
__wrap_calloc(size_t nmemb, size_t size)
{

	g_calloc_calls++;
	if (g_calloc_fail_at != 0 && g_calloc_calls == g_calloc_fail_at)
		return (NULL);
	return (__real_calloc(nmemb, size));
}

char *
__wrap_strdup(const char *s)
{

	g_strdup_calls++;
	if (g_strdup_fail_at != 0 && g_strdup_calls == g_strdup_fail_at) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_strdup(s));
}

int
vi_pci_snapshot(struct vm_snapshot_meta *meta)
{
	struct pci_vt9p_softc *sc;

	sc = ((struct pci_devinst *)meta->dev_data)->pi_arg;
	g_snapshot_validate_calls++;
	g_snapshot_validate_mutex_owned = pthread_mutex_isowned_np(&sc->vsc_mtx);
	return (0);
}

ATF_TC_WITHOUT_HEAD(export_root_resolve_beneath);
ATF_TC_BODY(export_root_resolve_beneath, tc)
{
	char base[] = "/tmp/virtio-9p-beneath.XXXXXX";
	char export_path[PATH_MAX], inside_path[PATH_MAX];
	char outside_path[PATH_MAX], escape_path[PATH_MAX];
	int fd, rootfd;

	ATF_REQUIRE(mkdtemp(base) != NULL);
	ATF_REQUIRE(snprintf(export_path, sizeof(export_path), "%s/export",
	    base) > 0);
	ATF_REQUIRE(snprintf(inside_path, sizeof(inside_path), "%s/inside",
	    export_path) > 0);
	ATF_REQUIRE(snprintf(outside_path, sizeof(outside_path), "%s/outside",
	    base) > 0);
	ATF_REQUIRE(snprintf(escape_path, sizeof(escape_path), "%s/escape",
	    export_path) > 0);
	ATF_REQUIRE(mkdir(export_path, 0700) == 0);

	fd = open(inside_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(close(fd) == 0);
	fd = open(outside_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(close(fd) == 0);
	ATF_REQUIRE(symlink("..", escape_path) == 0);

	rootfd = open(export_path, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(rootfd >= 0);
	ATF_REQUIRE(pci_vt9p_confine_rootfd(rootfd) == 0);
	ATF_CHECK((fcntl(rootfd, F_GETFD) & FD_RESOLVE_BENEATH) != 0);

	fd = openat(rootfd, "inside", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(close(fd) == 0);

	errno = 0;
	fd = openat(rootfd, "escape/outside", O_RDONLY);
	ATF_CHECK(fd == -1);
	ATF_CHECK(errno == ENOTCAPABLE);
	if (fd >= 0)
		(void)close(fd);

	ATF_REQUIRE(close(rootfd) == 0);
	ATF_REQUIRE(unlink(escape_path) == 0);
	ATF_REQUIRE(unlink(inside_path) == 0);
	ATF_REQUIRE(unlink(outside_path) == 0);
	ATF_REQUIRE(rmdir(export_path) == 0);
	ATF_REQUIRE(rmdir(base) == 0);
}

ATF_TC_WITHOUT_HEAD(readonly_export_root_rights);
ATF_TC_BODY(readonly_export_root_rights, tc)
{
	cap_rights_t readonly, writable;

	pci_vt9p_root_cap_rights(&readonly, true);
	pci_vt9p_root_cap_rights(&writable, false);
	ATF_CHECK(cap_rights_is_set(&readonly, CAP_LOOKUP));
	ATF_CHECK(cap_rights_is_set(&readonly, CAP_READ));
	ATF_CHECK(cap_rights_is_set(&readonly, CAP_FSTAT));
	ATF_CHECK(!cap_rights_is_set(&readonly, CAP_WRITE));
	ATF_CHECK(!cap_rights_is_set(&readonly, CAP_CREATE));
	ATF_CHECK(!cap_rights_is_set(&readonly, CAP_UNLINKAT));
	ATF_CHECK(!cap_rights_is_set(&readonly, CAP_RENAMEAT_TARGET));
	ATF_CHECK(!cap_rights_is_set(&readonly, CAP_EXTATTR_SET));
	ATF_CHECK(cap_rights_is_set(&writable, CAP_WRITE));
	ATF_CHECK(cap_rights_is_set(&writable, CAP_CREATE));
	ATF_CHECK(cap_rights_is_set(&writable, CAP_UNLINKAT));
	ATF_CHECK(cap_rights_is_set(&writable, CAP_RENAMEAT_TARGET));
	ATF_CHECK(cap_rights_is_set(&writable, CAP_EXTATTR_SET));
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

	return (vm_snapshot_buf(value, 1, meta));
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

void
ht_iter(struct ht *h, struct ht_iter *iter)
{

	memset(iter, 0, sizeof(*iter));
	iter->htit_parent = h;
}

void *
ht_next(struct ht_iter *iter __unused)
{
	static int fid;

	return (g_has_fid ? &fid : NULL);
}

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
	g_has_fid = false;
	g_cfg_sharename = NULL;
	g_cfg_path = NULL;
	g_cfg_ro = false;
	g_cfg_packed = false;
	g_init_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	g_init_transport_error = 0;
	g_modern_init_error = 0;
	g_intr_init_error = 0;
	g_backend_init_error = 0;
	g_server_init_error = 0;
	g_msix_result = 1;
	g_modern_identity = 0;
	g_linkup_calls = 0;
	g_calloc_fail_at = 0;
	g_calloc_calls = 0;
	g_strdup_fail_at = 0;
	g_strdup_calls = 0;
}

const char *
get_config_value_node(const nvlist_t *nvl __unused, const char *name)
{
	if (name != NULL && strcmp(name, "sharename") == 0)
		return (g_cfg_sharename);
	if (name != NULL && strcmp(name, "path") == 0)
		return (g_cfg_path);
	return (NULL);
}

bool
get_config_bool_node_default(const nvlist_t *nvl __unused,
    const char *name, bool value)
{
	if (name != NULL && strcmp(name, "ro") == 0)
		return (g_cfg_ro);
	if (name != NULL && strcmp(name, "packed") == 0)
		return (g_cfg_packed);
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
vi_softc_linkup(struct virtio_softc *vs, struct virtio_consts *vc, void *arg,
    struct pci_devinst *pi, struct vqueue_info *queues)
{

	g_linkup_calls++;
	vs->vs_vc = vc;
	vs->vs_pi = pi;
	vs->vs_queues = queues;
	pi->pi_arg = arg;
	for (int i = 0; i < vc->vc_nvq; i++) {
		queues[i].vq_vs = vs;
		queues[i].vq_num = i;
	}
}

int
vi_pci_select_transport(struct virtio_softc *vs, const nvlist_t *nvl __unused,
    enum virtio_pci_transport_policy policy __unused)
{

	if (g_init_transport_error != 0)
		return (g_init_transport_error);
	vs->vs_transport = g_init_transport;
	return (0);
}

void
vi_pci_modern_set_identity(struct virtio_softc *vs __unused, uint16_t devid)
{

	g_modern_identity = devid;
}

int
vi_pci_modern_init(struct virtio_softc *vs __unused, int barnum __unused)
{

	return (g_modern_init_error);
}

void
vi_set_io_bar(struct virtio_softc *vs __unused, int barnum __unused)
{
}

int
vi_intr_init(struct virtio_softc *vs, int barnum __unused, int use_msix __unused)
{

	if (g_intr_init_error != 0)
		return (g_intr_init_error);
	return (pthread_mutex_init(&vs->vs_isr_mtx, NULL));
}

int
fbsdrun_virtio_msix(void)
{

	return (g_msix_result);
}

void
pci_set_cfgdata8(struct pci_devinst *pi __unused, int reg, uint8_t val)
{

	if (reg == PCIR_CLASS)
		g_cfg_class = val;
}

void
pci_set_cfgdata16(struct pci_devinst *pi __unused, int reg, uint16_t val)
{

	switch (reg) {
	case PCIR_DEVICE:
		g_cfg_device = val;
		break;
	case PCIR_VENDOR:
		g_cfg_vendor = val;
		break;
	case PCIR_SUBDEV_0:
		g_cfg_subdev = val;
		break;
	case PCIR_SUBVEND_0:
		g_cfg_subvend = val;
		break;
	default:
		break;
	}
}

int
l9p_backend_fs_init(struct l9p_backend **backendp, int rootfd __unused,
    bool ro __unused)
{

	if (g_backend_init_error != 0)
		return (g_backend_init_error);
	*backendp = &g_fs_backend;
	return (0);
}

int
l9p_server_init(struct l9p_server **serverp, struct l9p_backend *backend __unused)
{

	if (g_server_init_error != 0)
		return (g_server_init_error);
	*serverp = &g_server;
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
	pthread_condattr_t attr;

	memset(sc, 0, sizeof(*sc));
	init_recursive_mutex(&sc->vsc_mtx);
	ATF_REQUIRE_EQ(pthread_condattr_init(&attr), 0);
	ATF_REQUIRE_EQ(pthread_condattr_setclock(&attr, CLOCK_MONOTONIC), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&sc->vsc_reset_cv, &attr), 0);
	ATF_REQUIRE_EQ(pthread_condattr_destroy(&attr), 0);
	sc->vsc_conn = &g_connection;
	sc->vsc_vq.vq_qsize = VT9P_RINGSZ;
}

static void
setup_snapshot_softc(struct pci_vt9p_softc *sc)
{

	setup_softc(sc);
	memset(g_config, 0, sizeof(g_config));
	sc->vsc_config = (struct pci_vt9p_config *)(void *)g_config;
	sc->vsc_vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	pci_vt9p_set_tag(sc, "hostshare");
	sc->vsc_rootpath = __DECONST(char *, "/host/share");
	sc->vsc_rootdev = 12;
	sc->vsc_rootino = 34;
	sc->vsc_readonly = true;
	sc->vsc_features = UINT64_C(0x1122334455667788);
	sc->vsc_vs.vs_negotiated_caps = sc->vsc_features;
	sc->vsc_generation = 9;
	sc->vsc_conn->lc_version = L9P_2000L;
	sc->vsc_conn->lc_msize = 8192;
	sc->vsc_conn->lc_max_io_size = 8192 - 24;
}

static int
run_snapshot(struct pci_vt9p_softc *sc, uint8_t *image, size_t size,
    enum vm_snapshot_op op, size_t *used)
{
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf = image,
			.buf_rem = size,
		},
		.op = op,
	};
	int error;

	error = pci_vt9p_snapshot(sc, &meta);
	if (used != NULL)
		*used = size - meta.buffer.buf_rem;
	return (error);
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
	ATF_CHECK(pci_vt9p_cfgread(&sc, 0, 1, NULL) == EINVAL);
}

ATF_TC_WITHOUT_HEAD(option_parser);
ATF_TC_BODY(option_parser, tc)
{
	struct nvlist nvl;

	reset_mocks();
	ATF_REQUIRE(pci_vt9p_legacy_config(&nvl,
	    "hostshare=/tmp/share,ro,transport=modern,packed=true") == 0);
	ATF_REQUIRE(g_set_count == 5);
	ATF_CHECK(strcmp(g_names[0], "sharename") == 0);
	ATF_CHECK(strcmp(g_values[0], "hostshare") == 0);
	ATF_CHECK(strcmp(g_names[1], "path") == 0);
	ATF_CHECK(strcmp(g_values[1], "/tmp/share") == 0);
	ATF_CHECK(strcmp(g_names[2], "ro") == 0);
	ATF_CHECK(strcmp(g_values[2], "true") == 0);
	ATF_CHECK(strcmp(g_names[3], "transport") == 0);
	ATF_CHECK(strcmp(g_values[3], "modern") == 0);
	ATF_CHECK(strcmp(g_names[4], "packed") == 0);
	ATF_CHECK(strcmp(g_values[4], "true") == 0);
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
	preq->vsr_req.idx = 7;
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

static void *
finish_suspended_request(void *arg)
{
	struct l9p_request *req;

	req = arg;
	return ((void *)(uintptr_t)pci_vt9p_send(req, NULL, 0, 17, NULL));
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
	ATF_CHECK(vt9p_vi_consts.vc_suspend == pci_vt9p_suspend_device);
	ATF_CHECK(vt9p_vi_consts.vc_resume_device ==
	    pci_vt9p_resume_device);
	ATF_CHECK((vt9p_vi_consts.vc_hv_caps & VIRTIO_F_RING_RESET) != 0);
	ATF_CHECK_EQ(vt9p_vi_consts.vc_hv_caps,
	    VIRTIO14_9P_F_MOUNT_TAG | VIRTIO14_F_RING_RESET |
	    VIRTIO14_F_SUSPEND);
}

ATF_TC_WITHOUT_HEAD(suspend_drains_and_preserves_session);
ATF_TC_BODY(suspend_drains_and_preserves_session, tc)
{
	struct pci_vt9p_softc sc;
	struct l9p_request req;
	pthread_t thread;
	void *thread_result;

	reset_mocks();
	setup_softc(&sc);
	pci_vt9p_notify(&sc, &sc.vsc_vq);
	ATF_REQUIRE(g_recv_aux != NULL);
	ATF_REQUIRE_EQ(sc.vsc_active_requests, 1);
	memset(&req, 0, sizeof(req));
	req.lr_aux = g_recv_aux;
	ATF_REQUIRE_EQ(pthread_create(&thread, NULL, finish_suspended_request,
	    &req), 0);
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vsc_mtx), 0);
	ATF_CHECK_EQ(pci_vt9p_suspend_device(&sc), 0);
	ATF_CHECK_EQ(sc.vsc_active_requests, 0);
	ATF_CHECK(sc.vsc_conn == &g_connection);
	ATF_CHECK_EQ(g_connection_closes, 0);
	ATF_CHECK_EQ(g_connection_inits, 0);
	ATF_CHECK_EQ(pci_vt9p_resume_device(&sc), 0);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);
	ATF_REQUIRE_EQ(pthread_join(thread, &thread_result), 0);
	ATF_CHECK_EQ((uintptr_t)thread_result, 0);

	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vsc_mtx), 0);
	sc.vsc_conn = NULL;
	ATF_CHECK_EQ(pci_vt9p_suspend_device(&sc), EIO);
	ATF_CHECK_EQ(pci_vt9p_resume_device(&sc), EIO);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);
	destroy_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(snapshot_identity_and_atomicity);
ATF_TC_BODY(snapshot_identity_and_atomicity, tc)
{
	struct pci_vt9p_softc destination, source;
	uint8_t image[1024];
	size_t used;

	reset_mocks();
	setup_snapshot_softc(&source);
	ATF_REQUIRE_EQ(run_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	ATF_REQUIRE(used > 16);
	/* Internal save-state magic is a fixed little-endian "V9P2". */
	ATF_CHECK_EQ(image[0], (uint8_t)'V');
	ATF_CHECK_EQ(image[1], (uint8_t)'9');
	ATF_CHECK_EQ(image[2], (uint8_t)'P');
	ATF_CHECK_EQ(image[3], (uint8_t)'2');
	source.vsc_features ^= UINT64_C(1);
	ATF_CHECK_EQ(run_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, NULL), EINVAL);
	source.vsc_features ^= UINT64_C(1);
	source.vsc_conn->lc_max_io_size++;
	ATF_CHECK_EQ(run_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, NULL), EINVAL);
	source.vsc_conn->lc_max_io_size--;
	ATF_REQUIRE_EQ(run_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);

	setup_snapshot_softc(&destination);
	destination.vsc_features = 7;
	destination.vsc_generation = 41;
	destination.vsc_conn->lc_version = L9P_2000;
	destination.vsc_conn->lc_msize = 1024;
	destination.vsc_conn->lc_max_io_size = 512;
	ATF_REQUIRE_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), 0);
	ATF_CHECK_EQ(destination.vsc_features, 7);
	ATF_CHECK_EQ(destination.vsc_generation, 41);
	ATF_CHECK_EQ(destination.vsc_conn->lc_version, L9P_2000);
	ATF_CHECK_EQ(destination.vsc_conn->lc_msize, 1024);
	ATF_CHECK_EQ(run_snapshot(&destination, image, used - 1,
	    VM_SNAPSHOT_VALIDATE, NULL), E2BIG);
	ATF_CHECK_EQ(destination.vsc_generation, 41);
	ATF_CHECK_EQ(run_snapshot(&destination, image, used - 1,
	    VM_SNAPSHOT_RESTORE, NULL), E2BIG);
	ATF_CHECK_EQ(destination.vsc_features, 7);
	ATF_CHECK_EQ(destination.vsc_generation, 41);
	ATF_CHECK_EQ(destination.vsc_conn->lc_version, L9P_2000);
	ATF_CHECK_EQ(destination.vsc_conn->lc_msize, 1024);

	destination.vsc_rootino++;
	ATF_CHECK_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	ATF_CHECK_EQ(destination.vsc_features, 7);
	ATF_CHECK_EQ(destination.vsc_generation, 41);
	destination.vsc_rootino--;

	ATF_REQUIRE_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(destination.vsc_features, source.vsc_features);
	ATF_CHECK_EQ(destination.vsc_generation, 42);
	ATF_CHECK_EQ(destination.vsc_conn->lc_version, L9P_2000L);
	ATF_CHECK_EQ(destination.vsc_conn->lc_msize, 8192);
	ATF_CHECK_EQ(destination.vsc_conn->lc_max_io_size, 8192 - 24);

	ATF_REQUIRE_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(destination.vsc_generation, 43);

	destination.vsc_generation = UINT64_MAX;
	ATF_CHECK_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EOVERFLOW);
	ATF_CHECK_EQ(destination.vsc_generation, UINT64_MAX);

	destroy_softc(&destination);
	destroy_softc(&source);
}

ATF_TC_WITHOUT_HEAD(snapshot_preflight_is_locally_serialized);
ATF_TC_BODY(snapshot_preflight_is_locally_serialized, tc)
{
	struct pci_devinst pi;
	struct pci_vt9p_softc sc;
	struct vm_snapshot_meta meta = {
		.dev_data = &pi,
		.op = VM_SNAPSHOT_VALIDATE,
	};

	memset(&pi, 0, sizeof(pi));
	memset(&sc, 0, sizeof(sc));
	/* Production 9P uses this recursive mutex across pause and preflight. */
	init_recursive_mutex(&sc.vsc_mtx);
	pi.pi_arg = &sc;
	g_snapshot_validate_calls = 0;
	g_snapshot_validate_mutex_owned = false;
	ATF_CHECK_EQ(pci_de_v9p.pe_snapshot_validate, pci_vt9p_snapshot_validate);
	ATF_REQUIRE_EQ(pci_vt9p_snapshot_validate(&meta), 0);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 1);
	ATF_CHECK(g_snapshot_validate_mutex_owned);
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vsc_mtx), 0);
	g_snapshot_validate_mutex_owned = false;
	ATF_REQUIRE_EQ(pci_vt9p_snapshot_validate(&meta), 0);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 2);
	ATF_CHECK(g_snapshot_validate_mutex_owned);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);
	meta.dev_data = NULL;
	ATF_CHECK_EQ(pci_vt9p_snapshot_validate(&meta), EINVAL);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 2);
	pthread_mutex_destroy(&sc.vsc_mtx);
}

ATF_TC_WITHOUT_HEAD(suspend_timeout_preserves_session);
ATF_TC_BODY(suspend_timeout_preserves_session, tc)
{
	struct pci_vt9p_softc sc;
	struct timespec before, after;

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_active_requests = 1;
	ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &before), 0);
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vsc_mtx), 0);
	ATF_CHECK_EQ(pci_vt9p_suspend_device(&sc), ETIMEDOUT);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);
	ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &after), 0);
	ATF_CHECK(after.tv_sec > before.tv_sec ||
	    (after.tv_sec == before.tv_sec &&
	    after.tv_nsec >= before.tv_nsec));
	ATF_CHECK_EQ(sc.vsc_active_requests, 1);
	ATF_CHECK(sc.vsc_conn == &g_connection);
	ATF_CHECK_EQ(g_connection_closes, 0);
	sc.vsc_active_requests = 0;
	destroy_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(checkpoint_rejects_live_session);
ATF_TC_BODY(checkpoint_rejects_live_session, tc)
{
	struct pci_vt9p_softc sc;

	reset_mocks();
	setup_snapshot_softc(&sc);
	ATF_REQUIRE_EQ(pci_vt9p_pause(&sc), 0);
	ATF_REQUIRE_EQ(pci_vt9p_resume(&sc), 0);

	sc.vsc_active_requests = 1;
	ATF_CHECK_EQ(pci_vt9p_pause(&sc), EBUSY);
	sc.vsc_active_requests = 0;
	g_has_fid = true;
	sc.vsc_conn->lc_files.ht_entries = (void *)(uintptr_t)1;
	ATF_CHECK_EQ(pci_vt9p_pause(&sc), EBUSY);
	sc.vsc_conn->lc_files.ht_entries = NULL;
	g_has_fid = false;
	sc.vsc_qreset_pending = true;
	ATF_CHECK_EQ(pci_vt9p_pause(&sc), EBUSY);
	sc.vsc_qreset_pending = false;
	sc.vsc_resetting = true;
	ATF_CHECK_EQ(pci_vt9p_pause(&sc), EBUSY);
	sc.vsc_resetting = false;

	destroy_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(neg_features_records);
ATF_TC_BODY(neg_features_records, tc)
{
	struct pci_vt9p_softc sc;

	memset(&sc, 0, sizeof(sc));
	ATF_CHECK_EQ(pci_vt9p_neg_features(&sc,
	    VIRTIO14_9P_F_MOUNT_TAG), 0);
	ATF_CHECK_EQ(sc.vsc_features, VIRTIO14_9P_F_MOUNT_TAG);
	ATF_CHECK_EQ(pci_vt9p_neg_features(&sc, 0), 0);
	ATF_CHECK_EQ(sc.vsc_features, 0);
}

ATF_TC_WITHOUT_HEAD(get_response_buffer_slices);
ATF_TC_BODY(get_response_buffer_slices, tc)
{
	struct pci_vt9p_request preq;
	struct l9p_request req;
	struct iovec out[VT9P_MAX_IOV];
	size_t niov;

	memset(&preq, 0, sizeof(preq));
	preq.vsr_niov = 4;
	preq.vsr_respidx = 1;
	for (size_t i = 0; i < preq.vsr_niov; i++) {
		preq.vsr_iov[i].iov_base = (void *)(uintptr_t)(0x1000 + i);
		preq.vsr_iov[i].iov_len = 10 + i;
	}
	memset(&req, 0, sizeof(req));
	req.lr_aux = &preq;
	niov = 0;
	ATF_CHECK_EQ(pci_vt9p_get_buffer(&req, out, &niov, NULL), 0);
	/*
	 * The write-only tail begins at readable descriptors (respidx); lib9p
	 * must receive exactly the response half of the chain, in order.
	 */
	ATF_CHECK_EQ(niov, preq.vsr_niov - preq.vsr_respidx);
	for (size_t i = 0; i < niov; i++) {
		ATF_CHECK_EQ(out[i].iov_base,
		    preq.vsr_iov[preq.vsr_respidx + i].iov_base);
		ATF_CHECK_EQ(out[i].iov_len,
		    preq.vsr_iov[preq.vsr_respidx + i].iov_len);
	}
}

ATF_TC_WITHOUT_HEAD(qenable_rejects_foreign_queue);
ATF_TC_BODY(qenable_rejects_foreign_queue, tc)
{
	struct pci_vt9p_softc sc;
	struct vqueue_info impostor;

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_vq.vq_num = 0;
	memset(&impostor, 0, sizeof(impostor));
	ATF_REQUIRE(pthread_mutex_lock(&sc.vsc_mtx) == 0);
	/* Only queue 0's own vqueue_info may be re-enabled. */
	ATF_CHECK_EQ(pci_vt9p_qenable(&sc, &impostor), EINVAL);
	impostor = sc.vsc_vq;
	impostor.vq_num = 1;
	ATF_CHECK_EQ(pci_vt9p_qenable(&sc, &impostor), EINVAL);
	sc.vsc_qreset_pending = true;
	ATF_CHECK_EQ(pci_vt9p_qenable(&sc, &sc.vsc_vq), EINVAL);
	sc.vsc_qreset_pending = false;
	ATF_REQUIRE(pthread_mutex_unlock(&sc.vsc_mtx) == 0);
	destroy_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(drop_relays_and_completes_reset);
ATF_TC_BODY(drop_relays_and_completes_reset, tc)
{
	struct pci_vt9p_request *preq;
	struct pci_vt9p_softc sc;
	struct l9p_request req;

	/* A current-generation drop returns the chain with zero length. */
	reset_mocks();
	setup_softc(&sc);
	preq = calloc(1, sizeof(*preq));
	ATF_REQUIRE(preq != NULL);
	preq->vsr_sc = &sc;
	preq->vsr_req.idx = 7;
	preq->vsr_generation = sc.vsc_generation;
	memset(&req, 0, sizeof(req));
	req.lr_aux = preq;
	pci_vt9p_drop(&req, NULL, 0, NULL);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len, 0);
	ATF_CHECK_EQ(g_end_calls, 1);
	ATF_CHECK_EQ(g_qreset_complete_calls, 0);
	destroy_softc(&sc);

	/* The last active drop finishes an in-progress queue reset. */
	reset_mocks();
	setup_softc(&sc);
	preq = calloc(1, sizeof(*preq));
	ATF_REQUIRE(preq != NULL);
	preq->vsr_sc = &sc;
	preq->vsr_req.idx = 7;
	preq->vsr_generation = sc.vsc_generation;
	preq->vsr_active = true;
	sc.vsc_active_requests = 1;
	sc.vsc_qreset_pending = true;
	sc.vsc_qreset_vq = &sc.vsc_vq;
	sc.vsc_qreset_generation = 99;
	memset(&req, 0, sizeof(req));
	req.lr_aux = preq;
	pci_vt9p_drop(&req, NULL, 0, NULL);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(sc.vsc_active_requests, 0);
	ATF_CHECK(!sc.vsc_qreset_pending);
	ATF_CHECK_EQ(g_qreset_complete_calls, 1);
	ATF_CHECK_EQ(g_qreset_complete_generation, 99);
	destroy_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(notify_stops_on_empty_chain);
ATF_TC_BODY(notify_stops_on_empty_chain, tc)
{
	struct pci_vt9p_softc sc;

	reset_mocks();
	setup_softc(&sc);
	g_descs = 1;
	g_chain_n = 0;
	pci_vt9p_notify(&sc, &sc.vsc_vq);
	ATF_CHECK_EQ(g_recv_calls, 0);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(g_end_calls, 1);
	destroy_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(notify_request_alloc_failure);
ATF_TC_BODY(notify_request_alloc_failure, tc)
{
	struct pci_vt9p_softc sc;

	reset_mocks();
	setup_softc(&sc);
	g_calloc_calls = 0;
	g_calloc_fail_at = 1;
	pci_vt9p_notify(&sc, &sc.vsc_vq);
	g_calloc_fail_at = 0;
	ATF_CHECK_EQ(g_recv_calls, 0);
	ATF_CHECK_EQ(sc.vsc_active_requests, 0);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len, 0);
	ATF_CHECK_EQ(g_end_calls, 1);
	destroy_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(snapshot_rejects_busy_and_bad_images);
ATF_TC_BODY(snapshot_rejects_busy_and_bad_images, tc)
{
	struct pci_vt9p_softc sc;
	uint8_t image[1024];
	size_t used;

	/* A live request forbids any checkpoint transfer. */
	reset_mocks();
	setup_snapshot_softc(&sc);
	sc.vsc_active_requests = 1;
	ATF_CHECK_EQ(run_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, NULL), EBUSY);
	sc.vsc_active_requests = 0;

	/* A version-less session carries no negotiated I/O size. */
	sc.vsc_conn->lc_version = L9P_INVALID_VERSION;
	sc.vsc_conn->lc_max_io_size = 0;
	ATF_REQUIRE_EQ(run_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	sc.vsc_conn->lc_version = L9P_2000L;
	sc.vsc_conn->lc_max_io_size = 8192 - 24;

	/* Corrupted on-disk magic is rejected as an unsupported image. */
	ATF_REQUIRE_EQ(run_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	image[0] ^= 0xFF;
	ATF_CHECK_EQ(run_snapshot(&sc, image, used, VM_SNAPSHOT_RESTORE,
	    NULL), ENOTSUP);
	image[0] ^= 0xFF;

	/* A restore whose saved mount tag differs from ours is rejected. */
	ATF_REQUIRE_EQ(run_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	pci_vt9p_set_tag(&sc, "othershare");
	ATF_CHECK_EQ(run_snapshot(&sc, image, used, VM_SNAPSHOT_RESTORE,
	    NULL), EINVAL);
	pci_vt9p_set_tag(&sc, "hostshare");

	destroy_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(snapshot_validate_null_softc);
ATF_TC_BODY(snapshot_validate_null_softc, tc)
{
	struct pci_devinst pi;
	struct vm_snapshot_meta meta = {
		.dev_data = &pi,
		.op = VM_SNAPSHOT_VALIDATE,
	};

	memset(&pi, 0, sizeof(pi));
	pi.pi_arg = NULL;
	g_snapshot_validate_calls = 0;
	ATF_CHECK_EQ(pci_vt9p_snapshot_validate(&meta), EINVAL);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 0);
}

ATF_TC_WITHOUT_HEAD(legacy_config_edge_cases);
ATF_TC_BODY(legacy_config_edge_cases, tc)
{
	struct nvlist nvl;

	reset_mocks();
	/* A device with no options string is a no-op success. */
	ATF_CHECK_EQ(pci_vt9p_legacy_config(&nvl, NULL), 0);
	ATF_CHECK_EQ(g_set_count, 0);

	/* strdup failure surfaces as a parse error. */
	g_strdup_calls = 0;
	g_strdup_fail_at = 1;
	ATF_CHECK_EQ(pci_vt9p_legacy_config(&nvl, "hostshare=/tmp/s"), -1);
	g_strdup_fail_at = 0;
}

ATF_TC_WITHOUT_HEAD(confine_rootfd_rejects_bad_fd);
ATF_TC_BODY(confine_rootfd_rejects_bad_fd, tc)
{

	/* F_GETFD on a closed descriptor fails and aborts confinement. */
	ATF_CHECK_EQ(pci_vt9p_confine_rootfd(-1), -1);
}

static char *
make_export_dir(char *tmpl)
{

	strcpy(tmpl, "/tmp/virtio-9p-init.XXXXXX");
	return (mkdtemp(tmpl));
}

static void
cleanup_inited_softc(struct pci_devinst *pi)
{
	struct pci_vt9p_softc *sc = pi->pi_arg;

	if (sc == NULL)
		return;
	pthread_cond_destroy(&sc->vsc_reset_cv);
	pthread_mutex_destroy(&sc->vsc_mtx);
	pthread_mutex_destroy(&sc->vsc_vs.vs_isr_mtx);
	free(sc->vsc_vs.vs_modern);
	free(sc->vsc_config);
	free(sc->vsc_rootpath);
	free(sc);
	pi->pi_arg = NULL;
}

ATF_TC_WITHOUT_HEAD(init_modern_success);
ATF_TC_BODY(init_modern_success, tc)
{
	struct pci_devinst pi;
	struct pci_vt9p_softc *sc;
	struct nvlist nvl;
	char dir[64];

	reset_mocks();
	ATF_REQUIRE(make_export_dir(dir) != NULL);
	memset(&pi, 0, sizeof(pi));
	g_cfg_sharename = "hostshare";
	g_cfg_path = dir;
	g_cfg_ro = false;
	g_cfg_packed = false;
	g_init_transport = VIRTIO_PCI_TRANSPORT_MODERN;

	ATF_REQUIRE_EQ(pci_vt9p_init(&pi, &nvl), 0);
	sc = pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(g_linkup_calls, 1);
	ATF_CHECK(!sc->vsc_readonly);
	ATF_CHECK_EQ(sc->vsc_vq.vq_qsize, VT9P_RINGSZ);
	/* Modern devices advertise the virtio 9P device id. */
	ATF_CHECK_EQ(g_modern_identity, VIRTIO_ID_9P);
	ATF_CHECK_EQ(le16toh(sc->vsc_config->tag_len),
	    (uint16_t)strlen("hostshare"));
	ATF_CHECK(sc->vsc_conn == &g_connection);
	cleanup_inited_softc(&pi);
	ATF_REQUIRE_EQ(rmdir(dir), 0);
}

ATF_TC_WITHOUT_HEAD(init_modern_packed_success);
ATF_TC_BODY(init_modern_packed_success, tc)
{
	struct pci_devinst pi;
	struct pci_vt9p_softc *sc;
	struct nvlist nvl;
	char dir[64];

	reset_mocks();
	ATF_REQUIRE(make_export_dir(dir) != NULL);
	memset(&pi, 0, sizeof(pi));
	g_cfg_sharename = "packshare";
	g_cfg_path = dir;
	g_cfg_packed = true;
	g_init_transport = VIRTIO_PCI_TRANSPORT_MODERN;

	ATF_REQUIRE_EQ(pci_vt9p_init(&pi, &nvl), 0);
	sc = pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	/* Packed queues on a modern transport advertise the packed feature. */
	ATF_CHECK((sc->vsc_consts.vc_hv_caps & VIRTIO14_F_RING_PACKED) != 0);
	cleanup_inited_softc(&pi);
	ATF_REQUIRE_EQ(rmdir(dir), 0);
}

ATF_TC_WITHOUT_HEAD(init_legacy_readonly_success);
ATF_TC_BODY(init_legacy_readonly_success, tc)
{
	struct pci_devinst pi;
	struct pci_vt9p_softc *sc;
	struct nvlist nvl;
	char dir[64];

	reset_mocks();
	ATF_REQUIRE(make_export_dir(dir) != NULL);
	memset(&pi, 0, sizeof(pi));
	g_cfg_sharename = "roshare";
	g_cfg_path = dir;
	g_cfg_ro = true;
	g_init_transport = VIRTIO_PCI_TRANSPORT_LEGACY;

	ATF_REQUIRE_EQ(pci_vt9p_init(&pi, &nvl), 0);
	sc = pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK(sc->vsc_readonly);
	/* Legacy transitional 9P device id is programmed into config space. */
	ATF_CHECK_EQ(g_cfg_device, VIRTIO_PCI_TRANSITIONAL_9P);
	ATF_CHECK_EQ(g_cfg_subdev, VIRTIO_ID_9P);
	ATF_CHECK_EQ(g_cfg_vendor, VIRTIO_VENDOR);
	ATF_CHECK_EQ(g_cfg_subvend, VIRTIO_VENDOR);
	ATF_CHECK_EQ(g_cfg_class, PCIC_STORAGE);
	/* tag_len is host-order on legacy transports. */
	ATF_CHECK_EQ(sc->vsc_config->tag_len, (uint16_t)strlen("roshare"));
	cleanup_inited_softc(&pi);
	ATF_REQUIRE_EQ(rmdir(dir), 0);
}

ATF_TC_WITHOUT_HEAD(init_rejects_configuration_errors);
ATF_TC_BODY(init_rejects_configuration_errors, tc)
{
	struct pci_devinst pi;
	struct nvlist nvl;
	char dir[64];
	char longshare[VT9P_MAXTAGSZ + 2];

	ATF_REQUIRE(make_export_dir(dir) != NULL);

	/* Missing share name. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_sharename = NULL;
	g_cfg_path = dir;
	ATF_CHECK_EQ(pci_vt9p_init(&pi, &nvl), -1);
	ATF_CHECK(pi.pi_arg == NULL);

	/* Over-long share name. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	memset(longshare, 'a', sizeof(longshare) - 1);
	longshare[sizeof(longshare) - 1] = '\0';
	g_cfg_sharename = longshare;
	g_cfg_path = dir;
	ATF_CHECK_EQ(pci_vt9p_init(&pi, &nvl), -1);

	/* Missing path. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_sharename = "s";
	g_cfg_path = NULL;
	ATF_CHECK_EQ(pci_vt9p_init(&pi, &nvl), -1);

	/* Unopenable path. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_sharename = "s";
	g_cfg_path = "/nonexistent/virtio-9p/path";
	ATF_CHECK_EQ(pci_vt9p_init(&pi, &nvl), -1);

	/* Packed queues require the modern transport. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_sharename = "s";
	g_cfg_path = dir;
	g_cfg_packed = true;
	g_init_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	ATF_CHECK_EQ(pci_vt9p_init(&pi, &nvl), -1);

	ATF_REQUIRE_EQ(rmdir(dir), 0);
}

ATF_TC_WITHOUT_HEAD(init_cleans_up_on_late_failures);
ATF_TC_BODY(init_cleans_up_on_late_failures, tc)
{
	struct pci_devinst pi;
	struct nvlist nvl;
	char dir[64];

	ATF_REQUIRE(make_export_dir(dir) != NULL);

	/* softc allocation failure (first calloc). */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_sharename = "s";
	g_cfg_path = dir;
	g_calloc_calls = 0;
	g_calloc_fail_at = 1;
	ATF_CHECK_EQ(pci_vt9p_init(&pi, &nvl), -1);
	g_calloc_fail_at = 0;

	/* rootpath strdup failure. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_sharename = "s";
	g_cfg_path = dir;
	g_strdup_calls = 0;
	g_strdup_fail_at = 1;
	ATF_CHECK_EQ(pci_vt9p_init(&pi, &nvl), -1);
	g_strdup_fail_at = 0;

	/* config-space allocation failure (second calloc). */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_sharename = "s";
	g_cfg_path = dir;
	g_calloc_calls = 0;
	g_calloc_fail_at = 2;
	ATF_CHECK_EQ(pci_vt9p_init(&pi, &nvl), -1);
	g_calloc_fail_at = 0;

	/* transport selection failure. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_sharename = "s";
	g_cfg_path = dir;
	g_init_transport_error = -1;
	ATF_CHECK_EQ(pci_vt9p_init(&pi, &nvl), -1);

	/* interrupt setup failure. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_sharename = "s";
	g_cfg_path = dir;
	g_intr_init_error = -1;
	ATF_CHECK_EQ(pci_vt9p_init(&pi, &nvl), -1);

	/* modern BAR init failure. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_sharename = "s";
	g_cfg_path = dir;
	g_init_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	g_modern_init_error = -1;
	ATF_CHECK_EQ(pci_vt9p_init(&pi, &nvl), -1);

	/* lib9p backend / server / connection failures exercise full teardown. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_sharename = "s";
	g_cfg_path = dir;
	g_backend_init_error = -1;
	ATF_CHECK_EQ(pci_vt9p_init(&pi, &nvl), -1);

	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_sharename = "s";
	g_cfg_path = dir;
	g_server_init_error = -1;
	ATF_CHECK_EQ(pci_vt9p_init(&pi, &nvl), -1);

	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_sharename = "s";
	g_cfg_path = dir;
	g_connection_init_result = -1;
	ATF_CHECK_EQ(pci_vt9p_init(&pi, &nvl), -1);

	ATF_REQUIRE_EQ(rmdir(dir), 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, export_root_resolve_beneath);
	ATF_TP_ADD_TC(tp, readonly_export_root_rights);
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
	ATF_TP_ADD_TC(tp, suspend_drains_and_preserves_session);
	ATF_TP_ADD_TC(tp, suspend_timeout_preserves_session);
	ATF_TP_ADD_TC(tp, snapshot_identity_and_atomicity);
	ATF_TP_ADD_TC(tp, snapshot_preflight_is_locally_serialized);
	ATF_TP_ADD_TC(tp, checkpoint_rejects_live_session);
	ATF_TP_ADD_TC(tp, neg_features_records);
	ATF_TP_ADD_TC(tp, get_response_buffer_slices);
	ATF_TP_ADD_TC(tp, qenable_rejects_foreign_queue);
	ATF_TP_ADD_TC(tp, drop_relays_and_completes_reset);
	ATF_TP_ADD_TC(tp, notify_stops_on_empty_chain);
	ATF_TP_ADD_TC(tp, notify_request_alloc_failure);
	ATF_TP_ADD_TC(tp, snapshot_rejects_busy_and_bad_images);
	ATF_TP_ADD_TC(tp, snapshot_validate_null_softc);
	ATF_TP_ADD_TC(tp, legacy_config_edge_cases);
	ATF_TP_ADD_TC(tp, confine_rootfd_rejects_bad_fd);
	ATF_TP_ADD_TC(tp, init_modern_success);
	ATF_TP_ADD_TC(tp, init_modern_packed_success);
	ATF_TP_ADD_TC(tp, init_legacy_readonly_success);
	ATF_TP_ADD_TC(tp, init_rejects_configuration_errors);
	ATF_TP_ADD_TC(tp, init_cleans_up_on_late_failures);
	return (atf_no_error());
}
