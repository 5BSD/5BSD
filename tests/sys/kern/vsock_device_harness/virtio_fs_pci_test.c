/*
 * Independent VirtIO 1.4 section 5.11 PCI composition tests.
 */
#include <sys/endian.h>
#include <sys/param.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "pci_emul.h"
#undef PCI_EMUL_SET
#define	PCI_EMUL_SET(name)

#include "virtio_fs_host.c"
#include "virtio_fs_state.c"
#include "pci_virtio_fs.c"
#include "virtio_1_4_spec.h"
#include "virtio_config_read_test_support.h"

/* Compile the DUT first, then obtain expectations from the 1.4 oracle. */
#undef VIRTIO_F_RING_RESET
#define	VIRTIO_F_RING_RESET	VIRTIO14_F_RING_RESET
#undef VIRTIO_F_RING_PACKED
#define	VIRTIO_F_RING_PACKED	VIRTIO14_F_RING_PACKED
#undef VIRTIO_F_SUSPEND
#define	VIRTIO_F_SUSPEND	VIRTIO14_F_SUSPEND

static unsigned int vq_has_descs_calls;
static unsigned int vq_relchain_calls;
static uint32_t connection_events;
static int mevent_enable_error;
static int mevent_enable_read_error;
static int mevent_enable_write_error;
static int mevent_disable_error;
static unsigned int mevent_enable_read_calls;
static unsigned int mevent_enable_write_calls;
static unsigned int mevent_disable_read_calls;
static unsigned int mevent_disable_write_calls;
static unsigned int notification_retry_calls;
static int notification_retry_error;
static int connection_reset_error;
static unsigned int needs_reset_calls;
/* Controls for the request/notification/init coverage cases (defaults are the
 * historical always-empty-ring behaviour so pre-existing cases are unchanged). */
static int vq_has_descs_result;
static int vq_getchain_result;
static struct vi_req vq_getchain_req_template;
static int connection_submit_error;
static unsigned int connection_submit_calls;
static bool connection_active_result = true;
static int connection_set_discard_error;
static int connection_set_reset_complete_error;
static int connection_set_notification_error;
static unsigned int connection_set_discard_calls;
static unsigned int connection_set_reset_complete_calls;
static unsigned int connection_set_notification_calls;
static int connection_progress_error;
static int connection_control_status_result;
static int connection_begin_quiesce_result;
static int connection_begin_thaw_saved_error;
static size_t buf_to_iov_result;
static bool buf_to_iov_result_valid;
static unsigned int buf_to_iov_calls;
static unsigned int vi_intr_init_calls;
static int vi_intr_init_error;
static int vi_pci_modern_init_error;
static int vi_pci_select_transport_error;
static unsigned int vi_pci_modern_queue_reset_complete_calls;
static unsigned int vi_pci_modern_set_identity_calls;
static unsigned int pci_set_cfgdata8_calls;
static unsigned int vi_softc_linkup_calls;
/* Config-node map consulted by the get_config_*_node() mocks. */
static const char *cfg_path;
static const char *cfg_tag;
static const char *cfg_identity;
static const char *cfg_queues;
static bool cfg_notifications;
static bool cfg_packed;
static int connect_required_error;

#ifdef BHYVE_SNAPSHOT
static int restore_session_calls;
static int checkpoint_contract_calls;
static int checkpoint_contract_error;
static int checkpoint_copy_error;
static int checkpoint_thaw_error;
static int checkpoint_thaw_calls;

void
vm_snapshot_buf_err(const char *name __unused,
    enum vm_snapshot_op op __unused)
{
}

int
vm_snapshot_buf(void *data, size_t size, struct vm_snapshot_meta *meta)
{

	if (meta == NULL || meta->buffer.buf == NULL ||
	    meta->buffer.buf_rem < size)
		return (E2BIG);
	if (meta->op == VM_SNAPSHOT_SAVE)
		memcpy(meta->buffer.buf, data, size);
	else
		memcpy(data, meta->buffer.buf, size);
	meta->buffer.buf = (uint8_t *)meta->buffer.buf + size;
	meta->buffer.buf_rem -= size;
	return (0);
}

int
vm_snapshot_le32(uint32_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[sizeof(*value)];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		le32enc(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && meta->op != VM_SNAPSHOT_SAVE)
		*value = le32dec(bytes);
	return (error);
}

int
vi_pci_snapshot(struct vm_snapshot_meta *meta __unused)
{

	return (0);
}

int
vi_pci_snapshot_compat(struct pci_devinst *pi __unused,
    struct pci_snapshot_compat *compat __unused)
{

	return (0);
}

int
vi_pci_pause(struct pci_devinst *pi __unused)
{

	return (0);
}

int
vi_pci_resume(struct pci_devinst *pi __unused)
{

	return (0);
}

static int
run_snapshot(struct pci_vtfs_softc *sc, uint8_t *image, size_t size,
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

	error = pci_vtfs_snapshot(sc, &meta);
	if (used != NULL)
		*used = size - meta.buffer.buf_rem;
	return (error);
}
#endif

uint32_t
virtio_fs_connection_events(
    struct virtio_fs_connection *connection __unused)
{

	return (connection_events);
}

int
virtio_fs_connection_retry_notification(
    struct virtio_fs_connection *connection __unused)
{

	notification_retry_calls++;
	return (notification_retry_error);
}

int
mevent_enable(struct mevent *event)
{
	if (event == (struct mevent *)(uintptr_t)1) {
		mevent_enable_read_calls++;
		if (mevent_enable_read_error != 0)
			return (mevent_enable_read_error);
	}
	if (event == (struct mevent *)(uintptr_t)2) {
		mevent_enable_write_calls++;
		if (mevent_enable_write_error != 0)
			return (mevent_enable_write_error);
	}

	return (mevent_enable_error);
}

int
mevent_disable(struct mevent *event)
{
	if (event == (struct mevent *)(uintptr_t)1)
		mevent_disable_read_calls++;
	if (event == (struct mevent *)(uintptr_t)2)
		mevent_disable_write_calls++;

	return (mevent_disable_error);
}

struct mevent *
mevent_add_disabled(int fd __unused, enum ev_type type __unused,
    void (*callback)(int, enum ev_type, void *) __unused,
    void *argument __unused)
{

	return ((struct mevent *)(uintptr_t)1);
}

int
mevent_delete_sync(struct mevent *event __unused)
{

	return (0);
}

void
vi_reset_dev(struct virtio_softc *vs __unused)
{
}

void
vi_set_needs_reset(struct virtio_softc *vs __unused)
{

	needs_reset_calls++;
}

int
vq_has_descs(struct vqueue_info *vq __unused)
{

	vq_has_descs_calls++;
	return (vq_has_descs_result);
}

int
vq_getchain(struct vqueue_info *vq __unused, struct iovec *iov __unused,
    int niov __unused, struct vi_req *request)
{

	if (request != NULL)
		*request = vq_getchain_req_template;
	return (vq_getchain_result);
}

void
vq_retchains(struct vqueue_info *vq __unused, uint16_t count __unused)
{
}

void
vq_relchain(struct vqueue_info *vq __unused, uint16_t index __unused,
    uint32_t length __unused)
{

	vq_relchain_calls++;
}

void
vq_endchains(struct vqueue_info *vq __unused, int used_all __unused)
{
}

int
virtio_fs_connection_connect_required(const char *path __unused,
    uid_t uid __unused, gid_t gid __unused,
    const struct virtio_fs_backend_hello *hello __unused,
    uint32_t queues __unused, uint32_t depth __unused,
    uint32_t features __unused,
    virtio_fs_queue_complete_cb complete __unused, void *argument __unused,
    struct virtio_fs_connection **connection)
{

	if (connect_required_error != 0)
		return (connect_required_error);
	if (connection != NULL)
		*connection = (struct virtio_fs_connection *)(uintptr_t)1;
	return (0);
}

void
virtio_fs_connection_destroy(
    struct virtio_fs_connection *connection __unused)
{
}

#ifdef BHYVE_SNAPSHOT
int
virtio_fs_connection_restore_session(
    struct virtio_fs_connection *connection __unused,
    const struct virtio_fs_session *session)
{

	if (session == NULL)
		return (EINVAL);
	restore_session_calls++;
	return (0);
}
#endif

int
virtio_fs_connection_fd(
    const struct virtio_fs_connection *connection __unused)
{

	return (-1);
}

int
virtio_fs_connection_progress(
    struct virtio_fs_connection *connection __unused,
    bool readable __unused, bool writable __unused)
{

	return (connection_progress_error);
}

uint32_t
virtio_fs_connection_pending(
    struct virtio_fs_connection *connection __unused)
{

	return (0);
}

uint32_t
virtio_fs_connection_outgoing(
    struct virtio_fs_connection *connection __unused)
{

	return (0);
}

int
virtio_fs_connection_checkpoint_contract(
    const struct virtio_fs_connection *connection __unused,
    struct virtio_fs_backend_session *backend_session)
{
	checkpoint_contract_calls++;
	if (checkpoint_contract_error != 0)
		return (checkpoint_contract_error);

	if (backend_session == NULL)
		return (EINVAL);
	memset(backend_session, 0, sizeof(*backend_session));
	backend_session->phase = VIRTIO_FS_BACKEND_QUIESCED;
	backend_session->incarnation = 1;
	backend_session->version = VIRTIO_FS_BACKEND_VERSION;
	backend_session->features = VIRTIO_FS_BACKEND_F_FREEZE |
	    VIRTIO_FS_BACKEND_F_STATE_TRANSFER;
	backend_session->maximum_message = 1024;
	backend_session->maximum_inflight = 4;
	backend_session->maximum_pending_bytes = 4096;
	return (0);
}

size_t
virtio_fs_connection_checkpoint_size(
    const struct virtio_fs_connection *connection __unused)
{

	/* This PCI composition harness has no opaque backend payload. */
	return (0);
}

int
virtio_fs_connection_checkpoint_copy(
    const struct virtio_fs_connection *connection __unused,
    struct virtio_fs_session *session,
    struct virtio_fs_backend_session *backend_session, void *state,
    size_t state_length, size_t *used)
{
	if (checkpoint_copy_error != 0)
		return (checkpoint_copy_error);

	if (session == NULL || backend_session == NULL || used == NULL ||
	    (state == NULL && state_length != 0))
		return (EINVAL);
	memset(session, 0, sizeof(*session));
	if (virtio_fs_connection_checkpoint_contract(NULL, backend_session) != 0)
		return (EIO);
	*used = 0;
	return (0);
}

int
virtio_fs_connection_submit_on(
    struct virtio_fs_connection *connection __unused,
    uint32_t queue __unused, enum virtio_fs_queue_class class __unused,
    const struct iovec *iov __unused, size_t readable __unused,
    size_t writable __unused, size_t count __unused, bool ordered __unused,
    uintptr_t token __unused)
{

	connection_submit_calls++;
	return (connection_submit_error);
}

int
virtio_fs_connection_reset_queue(
    struct virtio_fs_connection *connection __unused,
    uint32_t queue __unused, size_t *cancelled)
{

	if (cancelled != NULL)
		*cancelled = 0;
	return (connection_reset_error);
}

int
virtio_fs_connection_begin_quiesce(
    struct virtio_fs_connection *connection __unused)
{

	return (connection_begin_quiesce_result);
}

void
virtio_fs_connection_resume(
    struct virtio_fs_connection *connection __unused)
{
}

int
virtio_fs_connection_begin_thaw(
    struct virtio_fs_connection *connection __unused,
    const void *state __unused, size_t state_length __unused)
{

	checkpoint_thaw_calls++;
	return (checkpoint_thaw_error);
}

int
virtio_fs_connection_begin_thaw_saved(
    struct virtio_fs_connection *connection __unused)
{

	return (connection_begin_thaw_saved_error);
}

int
virtio_fs_connection_control_status(
    const struct virtio_fs_connection *connection __unused)
{

	return (connection_control_status_result);
}

int
virtio_fs_connection_abort_control(
    struct virtio_fs_connection *connection __unused, int error __unused)
{

	return (0);
}

bool
virtio_fs_connection_active(
    const struct virtio_fs_connection *connection __unused)
{

	return (connection_active_result);
}

int
virtio_fs_connection_set_discard(struct virtio_fs_connection *connection __unused,
    virtio_fs_queue_discard_cb callback __unused, void *argument __unused)
{

	connection_set_discard_calls++;
	return (connection_set_discard_error);
}

int
virtio_fs_connection_set_reset_complete(
    struct virtio_fs_connection *connection __unused,
    virtio_fs_queue_reset_complete_cb callback __unused,
    void *argument __unused)
{

	connection_set_reset_complete_calls++;
	return (connection_set_reset_complete_error);
}

int
virtio_fs_connection_set_notification(
    struct virtio_fs_connection *connection __unused,
    virtio_fs_connection_notify_cb callback __unused, void *argument __unused)
{

	connection_set_notification_calls++;
	return (connection_set_notification_error);
}

size_t
buf_to_iov(const void *buf __unused, size_t buflen,
    const struct iovec *iov __unused, size_t niov __unused)
{

	buf_to_iov_calls++;
	return (buf_to_iov_result_valid ? buf_to_iov_result : buflen);
}

const char *
get_config_value_node(const nvlist_t *parent __unused, const char *name)
{

	if (strcmp(name, "path") == 0)
		return (cfg_path);
	if (strcmp(name, "tag") == 0)
		return (cfg_tag);
	if (strcmp(name, "identity") == 0)
		return (cfg_identity);
	if (strcmp(name, "queues") == 0)
		return (cfg_queues);
	return (NULL);
}

bool
get_config_bool_node_default(const nvlist_t *parent __unused, const char *name,
    bool value)
{

	if (strcmp(name, "notifications") == 0)
		return (cfg_notifications);
	if (strcmp(name, "packed") == 0)
		return (cfg_packed);
	return (value);
}

void
pci_set_cfgdata8(struct pci_devinst *pi __unused, int offset __unused,
    uint8_t value __unused)
{

	pci_set_cfgdata8_calls++;
}

int
fbsdrun_virtio_msix(void)
{

	return (1);
}

void
vi_softc_linkup(struct virtio_softc *vs, struct virtio_consts *consts,
    void *pci_virtio_softc, struct pci_devinst *pi,
    struct vqueue_info *queues)
{

	vi_softc_linkup_calls++;
	vs->vs_vc = consts;
	vs->vs_pi = pi;
	vs->vs_queues = queues;
	if (pi != NULL)
		pi->pi_arg = pci_virtio_softc;
}

/*
 * Release everything a successful pci_vtfs_init() allocated.  Mirrors the
 * teardown order of the init failure path without re-entering the (mocked)
 * transport, so composed init cases stay leak-free.
 */
static void
pci_vtfs_test_teardown(struct pci_vtfs_softc *sc)
{

	if (sc == NULL)
		return;
	pci_vtfs_disconnect_sync(sc);
	pthread_cond_destroy(&sc->vsc_checkpoint_cv);
	free(sc->vsc_vs.vs_modern);
	pthread_mutex_destroy(&sc->vsc_vs.vs_isr_mtx);
	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc->vsc_notify_pending);
	free(sc->vsc_reset);
	free(sc->vsc_vq);
#ifdef BHYVE_SNAPSHOT
	pci_vtfs_checkpoint_state_clear(sc);
#endif
	free(sc->vsc_backend_identity);
	free(sc->vsc_backend_path);
	free(sc);
}

int
vi_pci_select_transport(struct virtio_softc *vs __unused,
    const nvlist_t *nvl __unused,
    enum virtio_pci_transport_policy policy __unused)
{

	return (vi_pci_select_transport_error);
}

void
vi_pci_modern_set_identity(struct virtio_softc *vs __unused,
    uint16_t device_id __unused)
{

	vi_pci_modern_set_identity_calls++;
}

int
vi_intr_init(struct virtio_softc *vs, int barnum __unused, int use_msix __unused)
{

	if (vi_intr_init_error != 0)
		return (vi_intr_init_error);
	vi_intr_init_calls++;
	(void)pthread_mutex_init(&vs->vs_isr_mtx, NULL);
	return (0);
}

int
vi_pci_modern_init(struct virtio_softc *vs __unused, int barnum __unused)
{

	return (vi_pci_modern_init_error);
}

void
vi_pci_modern_queue_reset_complete(struct vqueue_info *vq __unused,
    uint64_t generation __unused, int error __unused)
{

	vi_pci_modern_queue_reset_complete_calls++;
}

int
vi_pci_modern_cfgread(struct pci_devinst *pi __unused, int offset __unused,
    int size __unused, uint32_t *value __unused)
{

	return (0);
}

int
vi_pci_modern_cfgwrite(struct pci_devinst *pi __unused, int offset __unused,
    int size __unused, uint32_t value __unused)
{

	return (0);
}

uint64_t
vi_pci_read(struct pci_devinst *pi __unused, int baridx __unused,
    uint64_t offset __unused, int size __unused)
{

	return (0);
}

void
vi_pci_write(struct pci_devinst *pi __unused, int baridx __unused,
    uint64_t offset __unused, int size __unused, uint64_t value __unused)
{
}

/* Reset every mock control to its default before each composed case. */
static void
reset_mock_state(void)
{

	vq_has_descs_calls = 0;
	vq_relchain_calls = 0;
	vq_has_descs_result = 0;
	vq_getchain_result = 0;
	memset(&vq_getchain_req_template, 0, sizeof(vq_getchain_req_template));
	connection_events = 0;
	connection_submit_error = 0;
	connection_submit_calls = 0;
	connection_active_result = true;
	connection_set_discard_error = 0;
	connection_set_reset_complete_error = 0;
	connection_set_notification_error = 0;
	connection_set_discard_calls = 0;
	connection_set_reset_complete_calls = 0;
	connection_set_notification_calls = 0;
	connection_progress_error = 0;
	connection_control_status_result = 0;
	connection_begin_quiesce_result = 0;
	connection_begin_thaw_saved_error = 0;
	connection_reset_error = 0;
	notification_retry_calls = 0;
	notification_retry_error = 0;
	buf_to_iov_result = 0;
	buf_to_iov_result_valid = false;
	buf_to_iov_calls = 0;
	mevent_enable_error = 0;
	mevent_enable_read_error = 0;
	mevent_enable_write_error = 0;
	mevent_disable_error = 0;
	needs_reset_calls = 0;
	vi_intr_init_calls = 0;
	vi_intr_init_error = 0;
	vi_pci_modern_init_error = 0;
	vi_pci_select_transport_error = 0;
	vi_pci_modern_queue_reset_complete_calls = 0;
	vi_pci_modern_set_identity_calls = 0;
	pci_set_cfgdata8_calls = 0;
	vi_softc_linkup_calls = 0;
	cfg_path = NULL;
	cfg_tag = NULL;
	cfg_identity = NULL;
	cfg_queues = NULL;
	cfg_notifications = false;
	cfg_packed = false;
	connect_required_error = 0;
#ifdef BHYVE_SNAPSHOT
	checkpoint_contract_error = 0;
	checkpoint_copy_error = 0;
	checkpoint_thaw_error = 0;
	checkpoint_thaw_calls = 0;
	restore_session_calls = 0;
	checkpoint_contract_calls = 0;
#endif
}

ATF_TC_WITHOUT_HEAD(option_bounds);
ATF_TC_BODY(option_bounds, tc)
{
	uint32_t value;

	ATF_REQUIRE_EQ(VTFS_MAX_REQUEST_QUEUES, 64U);
	ATF_REQUIRE_EQ(VTFS_MAX_INFLIGHT, 4096U);

	ATF_REQUIRE_EQ(pci_vtfs_parse_u32("1", 1, 64, &value), 0);
	ATF_CHECK_EQ(value, 1);
	ATF_REQUIRE_EQ(pci_vtfs_parse_u32("64", 1, 64, &value), 0);
	ATF_CHECK_EQ(value, 64);
	ATF_REQUIRE_EQ(pci_vtfs_parse_u32("0x10", 1, 64, &value), 0);
	ATF_CHECK_EQ(value, 16);

	ATF_CHECK_EQ(pci_vtfs_parse_u32(NULL, 1, 64, &value), EINVAL);
	ATF_CHECK_EQ(pci_vtfs_parse_u32("", 1, 64, &value), EINVAL);
	ATF_CHECK_EQ(pci_vtfs_parse_u32("0", 1, 64, &value), EINVAL);
	ATF_CHECK_EQ(pci_vtfs_parse_u32("65", 1, 64, &value), EINVAL);
	ATF_CHECK_EQ(pci_vtfs_parse_u32("-1", 1, 64, &value), EINVAL);
	ATF_CHECK_EQ(pci_vtfs_parse_u32("1x", 1, 64, &value), EINVAL);
	ATF_CHECK_EQ(pci_vtfs_parse_u32("1", 1, 64, NULL), EINVAL);
}

ATF_TC_WITHOUT_HEAD(configuration_layout);
ATF_TC_BODY(configuration_layout, tc)
{
	struct pci_vtfs_softc sc;
	uint32_t value;

	memset(&sc, 0, sizeof(sc));
	ATF_REQUIRE_EQ(virtio_fs_config_encode("waspnest", 8, 7,
	    sc.vsc_config), 0);

	ATF_REQUIRE_EQ(pci_vtfs_cfgread(&sc, 0, 4, &value), 0);
	ATF_CHECK_EQ(value, htole32(UINT32_C(0x70736177)));
	ATF_REQUIRE_EQ(pci_vtfs_cfgread(&sc, 32, 4, &value), 0);
	ATF_CHECK_EQ(value, 0);
	ATF_REQUIRE_EQ(pci_vtfs_cfgread(&sc, 36, 4, &value), 0);
	ATF_CHECK_EQ(le32toh(value), 7);
	ATF_CHECK_EQ(pci_vtfs_cfgread(&sc, 40, 4, &value), EINVAL);
	sc.vsc_notifications = true;
	ATF_REQUIRE_EQ(virtio_fs_config_encode_notification("waspnest", 8, 7,
	    BHYVE_VIRTIO_FS_NOTIFY_BUF_SIZE, sc.vsc_config), 0);
	ATF_REQUIRE_EQ(pci_vtfs_cfgread(&sc, 40, 4, &value), 0);
	ATF_CHECK_EQ(le32toh(value), BHYVE_VIRTIO_FS_NOTIFY_BUF_SIZE);

	ATF_CHECK_EQ(pci_vtfs_cfgread(&sc, -1, 1, &value), EINVAL);
	ATF_CHECK_EQ(pci_vtfs_cfgread(&sc, 0, 3, &value), EINVAL);
	ATF_CHECK_EQ(pci_vtfs_cfgread(&sc,
	    BHYVE_VIRTIO_FS_CONFIG_SIZE, 1, &value), EINVAL);
	ATF_CHECK_EQ(pci_vtfs_cfgread(&sc,
	    BHYVE_VIRTIO_FS_CONFIG_SIZE - 1, 2, &value), EINVAL);
	ATF_CHECK_EQ(pci_vtfs_cfgread(&sc, 0, 1, NULL), EINVAL);
}

ATF_TC_WITHOUT_HEAD(device_contract);
ATF_TC_BODY(device_contract, tc)
{

	ATF_CHECK_STREQ(pci_de_vtfs.pe_emu, "virtio-fs");
	ATF_CHECK_STREQ(vtfs_vi_consts.vc_name, "vtfs");
	ATF_CHECK_EQ(vtfs_vi_consts.vc_cfgsize,
	    BHYVE_VIRTIO_FS_CONFIG_BASE_SIZE);
	ATF_CHECK_EQ(vtfs_vi_consts.vc_hv_caps,
	    VIRTIO14_F_RING_INDIRECT_DESC | VIRTIO_F_RING_RESET);
	ATF_CHECK(vtfs_vi_consts.vc_reset == pci_vtfs_reset);
	ATF_CHECK(vtfs_vi_consts.vc_qnotify == pci_vtfs_notify);
	ATF_CHECK(vtfs_vi_consts.vc_qreset == pci_vtfs_qreset);
	ATF_CHECK(vtfs_vi_consts.vc_suspend == pci_vtfs_suspend_device);
	ATF_CHECK(vtfs_vi_consts.vc_resume_device ==
	    pci_vtfs_resume_device);
	ATF_CHECK(vtfs_vi_consts.vc_cfgread == pci_vtfs_cfgread);
	ATF_CHECK(pci_de_vtfs.pe_init == pci_vtfs_init);
	ATF_CHECK(pci_de_vtfs.pe_cfgwrite == vi_pci_modern_cfgwrite);
	ATF_CHECK(pci_de_vtfs.pe_cfgread == vi_pci_modern_cfgread);
}

ATF_TC_WITHOUT_HEAD(suspend_capability_requires_reconstructible_backend);
ATF_TC_BODY(suspend_capability_requires_reconstructible_backend, tc)
{
	struct pci_vtfs_softc sc;

	memset(&sc, 0, sizeof(sc));
	sc.vsc_consts = vtfs_vi_consts;
	pci_vtfs_configure_instance_features(&sc);
	ATF_CHECK_EQ(sc.vsc_consts.vc_hv_caps,
	    VIRTIO14_F_RING_INDIRECT_DESC | VIRTIO_F_RING_RESET);

	sc.vsc_backend_identity = __DECONST(char *, "backend-identity");
	pci_vtfs_configure_instance_features(&sc);
	ATF_CHECK_EQ(sc.vsc_consts.vc_hv_caps,
	    VIRTIO14_F_RING_INDIRECT_DESC | VIRTIO14_F_RING_RESET |
	    VIRTIO14_F_SUSPEND);

	sc.vsc_backend_identity = NULL;
	pci_vtfs_configure_instance_features(&sc);
	ATF_CHECK_EQ(sc.vsc_consts.vc_hv_caps,
	    VIRTIO14_F_RING_INDIRECT_DESC | VIRTIO_F_RING_RESET);
}

ATF_TC_WITHOUT_HEAD(restored_suspend_selects_destination_state);
ATF_TC_BODY(restored_suspend_selects_destination_state, tc)
{
	struct pci_vtfs_softc sc;
	const void *state;
	uint8_t restored[] = { 0x56, 0x46, 0x53, 0x42 };
	size_t state_len;

	memset(&sc, 0, sizeof(sc));
	ATF_CHECK(!pci_vtfs_restored_thaw_state(&sc, &state, &state_len));
	sc.vsc_checkpoint_backend_state = restored;
	sc.vsc_checkpoint_backend_state_len = sizeof(restored);
	ATF_REQUIRE(pci_vtfs_restored_thaw_state(&sc, &state, &state_len));
	ATF_CHECK(state == restored);
	ATF_CHECK_EQ(state_len, sizeof(restored));
}

ATF_TC_WITHOUT_HEAD(suspended_checkpoint_keeps_backend_quiesced);
ATF_TC_BODY(suspended_checkpoint_keeps_backend_quiesced, tc)
{
	struct pci_vtfs_softc sc;

	memset(&sc, 0, sizeof(sc));
	ATF_CHECK(!sc.vsc_checkpoint_borrowed_suspend &&
	    !sc.vsc_vs.vs_suspended);
	sc.vsc_checkpoint_borrowed_suspend = true;
	ATF_CHECK(sc.vsc_checkpoint_borrowed_suspend ||
	    sc.vsc_vs.vs_suspended);
	sc.vsc_checkpoint_borrowed_suspend = false;
	sc.vsc_vs.vs_suspended = true;
	ATF_CHECK(sc.vsc_checkpoint_borrowed_suspend ||
	    sc.vsc_vs.vs_suspended);
}

#ifdef BHYVE_SNAPSHOT
ATF_TC_WITHOUT_HEAD(checkpoint_pause_transfers_mutex_to_resume);
ATF_TC_BODY(checkpoint_pause_transfers_mutex_to_resume, tc)
{
	struct pci_vtfs_softc sc;
	struct pci_vtfs_reset reset;
	static char identity[] = "backend-identity";

	memset(&sc, 0, sizeof(sc));
	/* pci_vtfs_init() allocates one reset record for queue zero. */
	memset(&reset, 0, sizeof(reset));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	sc.vsc_reset = &reset;
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	sc.vsc_callbacks_set = true;
	sc.vsc_backend_identity = identity;
	checkpoint_thaw_error = 0;
	checkpoint_thaw_calls = 0;
	ATF_REQUIRE_EQ(pci_vtfs_pause(&sc), 0);
	ATF_CHECK(sc.vsc_checkpoint_lock_held);
	ATF_CHECK(pthread_mutex_isowned_np(&sc.vsc_mtx));
	ATF_REQUIRE_EQ(pci_vtfs_resume(&sc), 0);
	ATF_CHECK_EQ(checkpoint_thaw_calls, 1);
	ATF_CHECK(!sc.vsc_checkpoint_lock_held);
	ATF_CHECK(!pthread_mutex_isowned_np(&sc.vsc_mtx));
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(suspended_destination_runnable_restore_thaws_backend);
ATF_TC_BODY(suspended_destination_runnable_restore_thaws_backend, tc)
{
	struct pci_vtfs_softc sc;
	uint8_t *state;

	memset(&sc, 0, sizeof(sc));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	state = malloc(4);
	ATF_REQUIRE(state != NULL);
	memset(state, 0xa5, 4);
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	sc.vsc_guest_suspended = true;
	sc.vsc_checkpoint_borrowed_suspend = true;
	/* Exercise the retry-safe resume entry, which reacquires this lock. */
	sc.vsc_checkpoint_lock_held = false;
	sc.vsc_checkpoint_backend_state = state;
	sc.vsc_checkpoint_backend_state_len = 4;
	/* The source image is runnable even though the destination was not. */
	sc.vsc_vs.vs_suspended = false;
	checkpoint_thaw_calls = 0;
	ATF_REQUIRE_EQ(pci_vtfs_resume(&sc), 0);
	ATF_CHECK_EQ(checkpoint_thaw_calls, 1);
	ATF_CHECK(!sc.vsc_guest_suspended);
	ATF_CHECK(!sc.vsc_checkpoint_borrowed_suspend);
	ATF_CHECK(!sc.vsc_checkpoint_lock_held);
	ATF_CHECK(sc.vsc_checkpoint_backend_state == NULL);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}
#endif

#ifdef BHYVE_SNAPSHOT
/*
 * pci_vtfs_resume() consumes the mutex retained by the paired checkpoint
 * pause callback.  The test deliberately constructs that transferred-owner
 * state; keep the compiler-only ownership exception scoped to the helper.
 */
static void
checkpoint_thaw_failure_resume_locked(struct pci_vtfs_softc *sc)
    __no_lock_analysis;

static void
checkpoint_thaw_failure_resume_locked(struct pci_vtfs_softc *sc)
{
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc->vsc_mtx), 0);
	ATF_CHECK_EQ(pci_vtfs_resume(sc), EIO);
}

ATF_TC_WITHOUT_HEAD(checkpoint_thaw_failure_is_retryable);
ATF_TC_BODY(checkpoint_thaw_failure_is_retryable, tc)
{
	struct pci_vtfs_softc sc;
	uint8_t *state;

	memset(&sc, 0, sizeof(sc));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	state = malloc(4);
	ATF_REQUIRE(state != NULL);
	memset(state, 0xa5, 4);
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	sc.vsc_checkpoint_backend_state = state;
	sc.vsc_checkpoint_backend_state_len = 4;
	/*
	 * Resume is entered after a successful checkpoint pause, which retained
	 * the private mutex.  A backend thaw failure must release only that
	 * ownership, retain the opaque recovery state, and leave a later common
	 * resume retry able to thaw the same backend incarnation.
	 */
	sc.vsc_checkpoint_lock_held = true;
	checkpoint_thaw_calls = 0;
	checkpoint_thaw_error = EIO;
	checkpoint_thaw_failure_resume_locked(&sc);
	ATF_CHECK_EQ(checkpoint_thaw_calls, 1);
	ATF_CHECK(!sc.vsc_checkpoint_lock_held);
	ATF_CHECK(!pthread_mutex_isowned_np(&sc.vsc_mtx));
	ATF_CHECK(sc.vsc_checkpoint_backend_state == state);
	ATF_CHECK_EQ(sc.vsc_checkpoint_backend_state_len, 4);

	checkpoint_thaw_error = 0;
	ATF_REQUIRE_EQ(pci_vtfs_resume(&sc), 0);
	ATF_CHECK_EQ(checkpoint_thaw_calls, 2);
	ATF_CHECK(!sc.vsc_checkpoint_lock_held);
	ATF_CHECK(sc.vsc_checkpoint_backend_state == NULL);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}
#endif

#ifdef BHYVE_SNAPSHOT
ATF_TC_WITHOUT_HEAD(suspended_checkpoint_failure_preserves_thaw_blob);
ATF_TC_BODY(suspended_checkpoint_failure_preserves_thaw_blob, tc)
{
	struct pci_vtfs_softc sc;
	struct pci_vtfs_reset reset;
	static char identity[] = "backend-identity";
	static uint8_t thaw_blob[] = { 0x56, 0x46, 0x53, 0x42 };

	memset(&sc, 0, sizeof(sc));
	memset(&reset, 0, sizeof(reset));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	sc.vsc_reset = &reset;
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	sc.vsc_callbacks_set = true;
	sc.vsc_guest_suspended = true;
	sc.vsc_backend_identity = identity;
	sc.vsc_checkpoint_backend_state = thaw_blob;
	sc.vsc_checkpoint_backend_state_len = sizeof(thaw_blob);
	checkpoint_copy_error = EIO;
	ATF_CHECK_EQ(pci_vtfs_pause(&sc), EIO);
	ATF_CHECK(sc.vsc_checkpoint_backend_state == thaw_blob);
	ATF_CHECK_EQ(sc.vsc_checkpoint_backend_state_len, sizeof(thaw_blob));
	ATF_CHECK(!sc.vsc_checkpoint_lock_held);
	ATF_CHECK(!sc.vsc_checkpoint_borrowed_suspend);
	checkpoint_copy_error = 0;
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}
#endif

ATF_TC_WITHOUT_HEAD(snapshot_serializer_reuses_pause_ownership);
ATF_TC_BODY(snapshot_serializer_reuses_pause_ownership, tc)
{
	struct pci_vtfs_softc sc;
	bool acquired;

	memset(&sc, 0, sizeof(sc));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);

	acquired = pci_vtfs_serializer_enter(&sc);
	ATF_CHECK(acquired);
	ATF_CHECK(pthread_mutex_isowned_np(&sc.vsc_mtx));
	pci_vtfs_serializer_exit(&sc, acquired);
	ATF_CHECK(!pthread_mutex_isowned_np(&sc.vsc_mtx));

	/* Simulate vm_pause_devices() retaining this non-recursive mutex. */
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vsc_mtx), 0);
	acquired = pci_vtfs_serializer_enter(&sc);
	ATF_CHECK(!acquired);
	ATF_CHECK(pthread_mutex_isowned_np(&sc.vsc_mtx));
	pci_vtfs_serializer_exit(&sc, acquired);
	ATF_CHECK(pthread_mutex_isowned_np(&sc.vsc_mtx));
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);

	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

#ifdef BHYVE_SNAPSHOT
ATF_TC_WITHOUT_HEAD(snapshot_callback_validates_before_backend_publication);
ATF_TC_BODY(snapshot_callback_validates_before_backend_publication, tc)
{
	struct pci_vtfs_softc source, destination;
	uint8_t image[256], damaged[sizeof(image)];
	static const uint8_t opaque[] = { 0x61, 0x62, 0x63, 0x64 };
	static char identity[] = "backend-identity";
	size_t used;

	memset(&source, 0, sizeof(source));
	memset(&destination, 0, sizeof(destination));
	ATF_REQUIRE_EQ(virtio_fs_config_encode("share", 5, 2,
	    source.vsc_config), 0);
	memcpy(destination.vsc_config, source.vsc_config,
	    sizeof(source.vsc_config));
	source.vsc_num_request_queues = 2;
	destination.vsc_num_request_queues = 2;
	source.vsc_vs.vs_negotiated_caps = VIRTIO14_F_RING_RESET;
	destination.vsc_vs.vs_negotiated_caps = VIRTIO14_F_RING_RESET;
	source.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	destination.vsc_connection = source.vsc_connection;
	source.vsc_backend_identity = identity;
	destination.vsc_backend_identity = identity;
	source.vsc_checkpoint_lock_held = true;
	destination.vsc_checkpoint_lock_held = true;
	source.vsc_checkpoint_fuse = (struct virtio_fs_session) {
		.byte_order = VIRTIO_FS_BYTE_ORDER_LITTLE,
		.initialized = true,
		.incarnation = 7,
	};
	source.vsc_checkpoint_backend = (struct virtio_fs_backend_session) {
		.phase = VIRTIO_FS_BACKEND_QUIESCED,
		.version = VIRTIO_FS_BACKEND_VERSION,
		.features = VIRTIO_FS_BACKEND_F_FREEZE |
		    VIRTIO_FS_BACKEND_F_STATE_TRANSFER,
		.maximum_message = 1024,
		.maximum_inflight = 4,
		.maximum_pending_bytes = 4096,
		.incarnation = 9,
	};
	source.vsc_checkpoint_backend_state = __DECONST(uint8_t *, opaque);
	source.vsc_checkpoint_backend_state_len = sizeof(opaque);

	ATF_REQUIRE_EQ(run_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	ATF_REQUIRE_EQ(le32dec(image), used - sizeof(uint32_t));
	ATF_CHECK_EQ(le32dec(image + sizeof(uint32_t)), VIRTIO_FS_STATE_MAGIC);

	/* Validation uses the destination contract and must not publish state. */
	restore_session_calls = 0;
	checkpoint_contract_calls = 0;
	ATF_REQUIRE_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), 0);
	ATF_CHECK(destination.vsc_checkpoint_backend_state == NULL);
	ATF_CHECK_EQ(restore_session_calls, 0);
	ATF_CHECK_EQ(checkpoint_contract_calls, 1);

	/* Header corruption is rejected before a session or opaque state changes. */
	memcpy(damaged, image, used);
	damaged[sizeof(uint32_t)] ^= 1;
	ATF_CHECK_EQ(run_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_VALIDATE, NULL), EPROTO);
	ATF_CHECK(destination.vsc_checkpoint_backend_state == NULL);
	ATF_CHECK_EQ(restore_session_calls, 0);

	ATF_REQUIRE_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(restore_session_calls, 1);
	ATF_CHECK_EQ(checkpoint_contract_calls, 3);
	ATF_REQUIRE(destination.vsc_checkpoint_backend_state != NULL);
	ATF_CHECK_EQ(destination.vsc_checkpoint_backend_state_len,
	    sizeof(opaque));
	ATF_CHECK_EQ(memcmp(destination.vsc_checkpoint_backend_state, opaque,
	    sizeof(opaque)), 0);
	free(destination.vsc_checkpoint_backend_state);
}
#endif


ATF_TC_WITHOUT_HEAD(generation_scoped_reset_completion);
ATF_TC_BODY(generation_scoped_reset_completion, tc)
{
	struct pci_vtfs_reset_completion completions[3];
	struct pci_vtfs_reset resets[3];
	struct pci_vtfs_softc sc;
	struct vqueue_info queues[3];
	size_t count;

	memset(&sc, 0, sizeof(sc));
	memset(completions, 0, sizeof(completions));
	memset(resets, 0, sizeof(resets));
	memset(queues, 0, sizeof(queues));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	sc.vsc_num_request_queues = 2;
	/*
	 * The completion callback validates the translated guest queue against
	 * the device's complete queue count.  This fixture has hiprio plus two
	 * request queues, so model that topology as well as providing the reset
	 * array; otherwise every callback is (correctly) rejected before the
	 * generation-scoped state is exercised.
	 */
	sc.vsc_nvq = nitems(resets);
	sc.vsc_reset = resets;
	resets[2].vq = &queues[2];
	resets[2].generation = 17;
	resets[2].pending = true;

	pci_vtfs_reset_complete(&sc, 3, EIO);
	ATF_CHECK(!resets[2].complete);
	pci_vtfs_reset_complete(&sc, 1, EIO);
	ATF_CHECK(!resets[2].complete);
	pci_vtfs_reset_complete(&sc, 2, 0);
	ATF_CHECK(resets[2].complete);
	ATF_CHECK_EQ(resets[2].error, 0);
	ATF_CHECK_EQ(resets[2].generation, 17);
	ATF_CHECK(resets[2].vq == &queues[2]);

	resets[0] = (struct pci_vtfs_reset) {
		.vq = &queues[0],
		.generation = 19,
		.error = EIO,
		.pending = true,
		.complete = true,
	};
	resets[1] = (struct pci_vtfs_reset) {
		.vq = &queues[1],
		.generation = 23,
		.pending = true,
		.complete = true,
	};
	count = pci_vtfs_take_reset_completions(&sc, completions,
	    nitems(completions));
	ATF_REQUIRE_EQ(count, 3);
	ATF_CHECK(completions[0].vq == &queues[0]);
	ATF_CHECK_EQ(completions[0].generation, 19);
	ATF_CHECK_EQ(completions[0].error, EIO);
	ATF_CHECK(completions[1].vq == &queues[1]);
	ATF_CHECK_EQ(completions[1].generation, 23);
	ATF_CHECK_EQ(completions[1].error, 0);
	ATF_CHECK(completions[2].vq == &queues[2]);
	ATF_CHECK_EQ(completions[2].generation, 17);
	ATF_CHECK_EQ(completions[2].error, 0);
	for (size_t i = 0; i < nitems(resets); i++)
		ATF_CHECK(!resets[i].pending && !resets[i].complete);
	ATF_CHECK(!pthread_mutex_isowned_np(&sc.vsc_mtx));
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(async_reset_event_failure_retains_ownership);
ATF_TC_BODY(async_reset_event_failure_retains_ownership, tc)
{
	struct pci_vtfs_reset reset[2];
	struct pci_vtfs_softc sc;
	struct vqueue_info vq;
	bool notify_pending[2];

	memset(&sc, 0, sizeof(sc));
	memset(&vq, 0, sizeof(vq));
	memset(reset, 0, sizeof(reset));
	memset(notify_pending, 0, sizeof(notify_pending));
	sc.vsc_num_request_queues = 1;
	sc.vsc_nvq = nitems(reset);
	sc.vsc_reset = reset;
	sc.vsc_notify_pending = notify_pending;
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	sc.vsc_read_event = (struct mevent *)(uintptr_t)1;
	vq.vq_num = 1;
	connection_events = VIRTIO_FS_CONNECTION_READ;
	connection_reset_error = EINPROGRESS;
	mevent_enable_error = 0;
	mevent_enable_read_error = EIO;
	mevent_enable_write_error = 0;
	needs_reset_calls = 0;

	ATF_CHECK_EQ(pci_vtfs_qreset(&sc, &vq, 31), EINPROGRESS);
	ATF_CHECK(reset[1].pending);
	ATF_CHECK(!reset[1].complete);
	ATF_CHECK_EQ(reset[1].generation, 31);
	ATF_CHECK_EQ(needs_reset_calls, 1U);

	/* A synchronous reset has no outstanding owner and reports arm failure. */
	memset(reset, 0, sizeof(reset));
	connection_reset_error = 0;
	ATF_CHECK_EQ(pci_vtfs_qreset(&sc, &vq, 32), EIO);
	ATF_CHECK(!reset[1].pending);
	ATF_CHECK_EQ(needs_reset_calls, 2U);

	connection_reset_error = 0;
	mevent_enable_read_error = 0;
	connection_events = 0;
}

ATF_TC_WITHOUT_HEAD(reconnecting_event_is_ignored);
ATF_TC_BODY(reconnecting_event_is_ignored, tc)
{
	struct pci_vtfs_softc sc;

	memset(&sc, 0, sizeof(sc));
	sc.vsc_reconnecting = true;

	/*
	 * A readiness event selected before reset's acknowledged deletion must
	 * not dereference the disconnected or replacement backend.
	 */
	ATF_CHECK(pci_vtfs_event_blocked(&sc));
	ATF_CHECK(sc.vsc_reconnecting);
	ATF_CHECK(sc.vsc_connection == NULL);
	sc.vsc_reconnecting = false;
	ATF_CHECK(pci_vtfs_event_blocked(&sc));
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	ATF_CHECK(!pci_vtfs_event_blocked(&sc));
}

ATF_TC_WITHOUT_HEAD(disconnected_event_sync_is_safe);
ATF_TC_BODY(disconnected_event_sync_is_safe, tc)
{
	struct pci_vtfs_softc sc;

	memset(&sc, 0, sizeof(sc));
	/*
	 * A failed full-reset reconnect leaves all three handles null.  Queue
	 * reset and cleanup paths may still synchronize readiness while the
	 * device reports NEEDS_RESET; that operation must be a no-op.
	 */
	connection_events = 0;
	mevent_enable_error = 0;
	mevent_enable_read_error = 0;
	mevent_enable_write_error = 0;
	mevent_disable_error = 0;
	mevent_enable_read_calls = 0;
	mevent_enable_write_calls = 0;
	mevent_disable_read_calls = 0;
	mevent_disable_write_calls = 0;
	ATF_CHECK_EQ(pci_vtfs_sync_events(&sc), 0);
	ATF_CHECK(sc.vsc_connection == NULL);
	ATF_CHECK(sc.vsc_read_event == NULL);
	ATF_CHECK(sc.vsc_write_event == NULL);
}

ATF_TC_WITHOUT_HEAD(event_sync_reports_registration_failure);
ATF_TC_BODY(event_sync_reports_registration_failure, tc)
{
	struct pci_vtfs_softc sc;

	memset(&sc, 0, sizeof(sc));
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	sc.vsc_read_event = (struct mevent *)(uintptr_t)1;
	sc.vsc_write_event = (struct mevent *)(uintptr_t)2;
	connection_events = VIRTIO_FS_CONNECTION_READ |
	    VIRTIO_FS_CONNECTION_WRITE;
	mevent_enable_error = EBUSY;
	mevent_enable_read_error = 0;
	mevent_enable_write_error = 0;
	mevent_disable_error = 0;
	mevent_enable_read_calls = 0;
	mevent_enable_write_calls = 0;
	ATF_CHECK_EQ(pci_vtfs_sync_events(&sc), EBUSY);
	/* Both registrations are attempted, but the first failure is retained. */
	mevent_enable_error = 0;
	mevent_enable_read_error = EIO;
	mevent_enable_write_error = EBUSY;
	mevent_enable_read_calls = 0;
	mevent_enable_write_calls = 0;
	ATF_CHECK_EQ(pci_vtfs_sync_events(&sc), EIO);
	ATF_CHECK_EQ(mevent_enable_read_calls, 1U);
	ATF_CHECK_EQ(mevent_enable_write_calls, 1U);

	connection_events = 0;
	mevent_enable_error = 0;
	mevent_enable_read_error = 0;
	mevent_enable_write_error = 0;
	mevent_disable_error = EIO;
	mevent_disable_read_calls = 0;
	mevent_disable_write_calls = 0;
	ATF_CHECK_EQ(pci_vtfs_sync_events(&sc), EIO);
	ATF_CHECK_EQ(mevent_disable_read_calls, 1U);
	ATF_CHECK_EQ(mevent_disable_write_calls, 1U);
	mevent_disable_error = 0;
}

ATF_TC_WITHOUT_HEAD(completion_uses_device_context_for_pressure);
ATF_TC_BODY(completion_uses_device_context_for_pressure, tc)
{
	struct pci_vtfs_request *request;
	struct pci_vtfs_softc sc;
	struct vqueue_info vq;

	memset(&sc, 0, sizeof(sc));
	memset(&vq, 0, sizeof(vq));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	request = calloc(1, sizeof(*request));
	ATF_REQUIRE(request != NULL);
	/*
	 * The completion callback receives the device context supplied during
	 * connection creation.  It must retain that context for the pressure
	 * probe after it publishes the used chain.
	 */
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	vq.vq_num = 1;
	vq.vq_generation = 11;
	request->vq = &vq;
	request->generation = vq.vq_generation;
	request->req.idx = 7;
	vq_relchain_calls = 0;
	/* Teardown drains this callback after dropping vsc_mtx. */
	pci_vtfs_complete(&sc, (uintptr_t)request, 64);
	ATF_CHECK_EQ(vq_relchain_calls, 1U);
	ATF_CHECK(!pthread_mutex_isowned_np(&sc.vsc_mtx));
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(reconnecting_queue_callbacks_are_fenced);
ATF_TC_BODY(reconnecting_queue_callbacks_are_fenced, tc)
{
	struct pci_vtfs_reset reset[2];
	struct pci_vtfs_softc sc;
	struct vqueue_info vq;

	memset(&sc, 0, sizeof(sc));
	memset(&vq, 0, sizeof(vq));
	memset(reset, 0, sizeof(reset));
	sc.vsc_num_request_queues = 1;
	/* hiprio queue plus one request queue used by this reset fixture */
	sc.vsc_nvq = nitems(reset);
	sc.vsc_reset = reset;
	sc.vsc_reconnecting = true;
	vq.vq_num = 1;
	vq_has_descs_calls = 0;

	pci_vtfs_notify(&sc, &vq);
	ATF_CHECK_EQ(vq_has_descs_calls, 0);
	ATF_CHECK_EQ(pci_vtfs_qreset(&sc, &vq, 7), EBUSY);
	ATF_CHECK(!reset[1].pending);

	sc.vsc_reconnecting = false;
	sc.vsc_connection = NULL;
	pci_vtfs_notify(&sc, &vq);
	ATF_CHECK_EQ(vq_has_descs_calls, 0);
	ATF_CHECK_EQ(pci_vtfs_qreset(&sc, &vq, 9), EBUSY);
	ATF_CHECK(!reset[1].pending);
}

ATF_TC_WITHOUT_HEAD(notification_queue_reset_defers_delivery);
ATF_TC_BODY(notification_queue_reset_defers_delivery, tc)
{
	struct pci_vtfs_softc sc;
	struct vqueue_info vq[2];
	static const uint8_t notification[] = { 0x7f, 0x45, 0x4c, 0x46 };

	memset(&sc, 0, sizeof(sc));
	memset(vq, 0, sizeof(vq));
	sc.vsc_notifications = true;
	sc.vsc_nvq = nitems(vq);
	sc.vsc_vq = vq;
	sc.vsc_callbacks_set = true;
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	vq[1].vq_num = 1;
	vq_set_resetting(&vq[1], true);
	/*
	 * The notification is retained by the connection and must be retried by
	 * a later q1 kick, never copied into a queue selective-reset owns.
	 */
	ATF_CHECK_EQ(pci_vtfs_receive_notification(&sc, notification,
	    sizeof(notification)), EAGAIN);
	ATF_CHECK_EQ(vq_has_descs_calls, 0U);
	vq_set_resetting(&vq[1], false);
	notification_retry_calls = 0;
	notification_retry_error = EAGAIN;
	pci_vtfs_notify(&sc, &vq[1]);
	ATF_CHECK_EQ(notification_retry_calls, 1U);
	notification_retry_error = 0;
}

/*
 * Drive the full device-model init composition.  The transport, interrupt and
 * config-space primitives are mocked; the spec-derived expectations are the
 * VirtIO 5.11 queue topology (hiprio + request [+ notification]) and the
 * feature bits the device offers.
 */
ATF_TC_WITHOUT_HEAD(init_composes_device_topology);
ATF_TC_BODY(init_composes_device_topology, tc)
{
	struct pci_devinst pi;
	struct pci_vtfs_softc *sc;

	reset_mock_state();
	memset(&pi, 0, sizeof(pi));
	cfg_path = "/nonexistent.sock";
	cfg_tag = "waspnest";
	/* Default request-queue count is one; total queues = hiprio + request. */
	ATF_REQUIRE_EQ(pci_vtfs_init(&pi, NULL), 0);
	sc = pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(sc->vsc_num_request_queues, VTFS_DEFAULT_REQUEST_QUEUES);
	ATF_CHECK_EQ(sc->vsc_nvq, VTFS_DEFAULT_REQUEST_QUEUES + 1);
	ATF_CHECK_EQ((int)sc->vsc_consts.vc_nvq, (int)sc->vsc_nvq);
	ATF_CHECK_EQ(sc->vsc_consts.vc_cfgsize,
	    BHYVE_VIRTIO_FS_CONFIG_BASE_SIZE);
	/* No identity => no guest-visible suspend capability. */
	ATF_CHECK_EQ(sc->vsc_consts.vc_hv_caps &
	    VIRTIO14_F_SUSPEND, 0U);
	ATF_CHECK_EQ(vi_softc_linkup_calls, 1U);
	ATF_CHECK_EQ(vi_pci_modern_set_identity_calls, 1U);
	ATF_CHECK_EQ(pci_set_cfgdata8_calls, 2U);
	for (uint32_t i = 0; i < sc->vsc_nvq; i++)
		ATF_CHECK_EQ(sc->vsc_vq[i].vq_qsize, VTFS_RINGSZ);
	pci_vtfs_test_teardown(sc);
}

ATF_TC_WITHOUT_HEAD(init_enables_notifications_packed_and_suspend);
ATF_TC_BODY(init_enables_notifications_packed_and_suspend, tc)
{
	struct pci_devinst pi;
	struct pci_vtfs_softc *sc;

	reset_mock_state();
	memset(&pi, 0, sizeof(pi));
	cfg_path = "/nonexistent.sock";
	cfg_tag = "waspnest";
	cfg_identity = "backend-identity";
	cfg_queues = "4";
	cfg_notifications = true;
	cfg_packed = true;
	ATF_REQUIRE_EQ(pci_vtfs_init(&pi, NULL), 0);
	sc = pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(sc->vsc_num_request_queues, 4U);
	/* hiprio + four request + notification queues. */
	ATF_CHECK_EQ(sc->vsc_nvq, 4U + 1U + 1U);
	ATF_CHECK(sc->vsc_notifications);
	ATF_CHECK_EQ(sc->vsc_consts.vc_cfgsize, BHYVE_VIRTIO_FS_CONFIG_SIZE);
	ATF_CHECK((sc->vsc_consts.vc_hv_caps &
	    BHYVE_VIRTIO_FS_F_NOTIFICATION) != 0);
	ATF_CHECK((sc->vsc_consts.vc_hv_caps & VIRTIO_F_RING_PACKED) != 0);
	/* identity= makes the instance advertise VIRTIO_F_SUSPEND. */
	ATF_CHECK((sc->vsc_consts.vc_hv_caps & VIRTIO14_F_SUSPEND) != 0);
	pci_vtfs_test_teardown(sc);
}

ATF_TC_WITHOUT_HEAD(init_rejects_invalid_configuration);
ATF_TC_BODY(init_rejects_invalid_configuration, tc)
{
	struct pci_devinst pi;

	memset(&pi, 0, sizeof(pi));

	reset_mock_state();
	cfg_tag = "t"; /* no path */
	ATF_CHECK_EQ(pci_vtfs_init(&pi, NULL), 1);

	reset_mock_state();
	cfg_path = "/s"; /* no tag */
	ATF_CHECK_EQ(pci_vtfs_init(&pi, NULL), 1);

	reset_mock_state();
	cfg_path = "/s";
	cfg_tag = "t";
	cfg_identity = ""; /* empty identity is invalid */
	ATF_CHECK_EQ(pci_vtfs_init(&pi, NULL), 1);

	reset_mock_state();
	cfg_path = "/s";
	cfg_tag = "t";
	cfg_queues = "0"; /* below the minimum of one */
	ATF_CHECK_EQ(pci_vtfs_init(&pi, NULL), 1);

	reset_mock_state();
	cfg_path = "/s";
	cfg_tag = "t";
	cfg_queues = "65"; /* above VTFS_MAX_REQUEST_QUEUES */
	ATF_CHECK_EQ(pci_vtfs_init(&pi, NULL), 1);
}

ATF_TC_WITHOUT_HEAD(init_unwinds_on_transport_failures);
ATF_TC_BODY(init_unwinds_on_transport_failures, tc)
{
	struct pci_devinst pi;

	memset(&pi, 0, sizeof(pi));

	reset_mock_state();
	cfg_path = "/s";
	cfg_tag = "t";
	vi_pci_select_transport_error = EINVAL;
	ATF_CHECK_EQ(pci_vtfs_init(&pi, NULL), 1);

	reset_mock_state();
	cfg_path = "/s";
	cfg_tag = "t";
	vi_intr_init_error = EBUSY;
	ATF_CHECK_EQ(pci_vtfs_init(&pi, NULL), 1);

	reset_mock_state();
	cfg_path = "/s";
	cfg_tag = "t";
	vi_pci_modern_init_error = EIO;
	ATF_CHECK_EQ(pci_vtfs_init(&pi, NULL), 1);
}

ATF_TC_WITHOUT_HEAD(init_fails_when_backend_connect_fails);
ATF_TC_BODY(init_fails_when_backend_connect_fails, tc)
{
	struct pci_devinst pi;

	memset(&pi, 0, sizeof(pi));
	reset_mock_state();
	cfg_path = "/s";
	cfg_tag = "t";
	connect_required_error = ECONNREFUSED;
	ATF_CHECK_EQ(pci_vtfs_init(&pi, NULL), 1);
	connect_required_error = 0;
}

ATF_TC_WITHOUT_HEAD(install_callbacks_registers_all_handlers);
ATF_TC_BODY(install_callbacks_registers_all_handlers, tc)
{
	struct pci_vtfs_softc sc;

	memset(&sc, 0, sizeof(sc));
	reset_mock_state();
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;

	/* Inactive connection is a no-op success. */
	connection_active_result = false;
	ATF_CHECK_EQ(pci_vtfs_install_callbacks(&sc), 0);
	ATF_CHECK(!sc.vsc_callbacks_set);

	/* Active, no notifications: discard + reset-complete only. */
	connection_active_result = true;
	ATF_CHECK_EQ(pci_vtfs_install_callbacks(&sc), 0);
	ATF_CHECK(sc.vsc_callbacks_set);
	ATF_CHECK_EQ(connection_set_discard_calls, 1U);
	ATF_CHECK_EQ(connection_set_reset_complete_calls, 1U);
	ATF_CHECK_EQ(connection_set_notification_calls, 0U);

	/* Already installed short-circuits. */
	ATF_CHECK_EQ(pci_vtfs_install_callbacks(&sc), 0);
	ATF_CHECK_EQ(connection_set_discard_calls, 1U);

	/* With notifications, the notification handler is also registered. */
	sc.vsc_callbacks_set = false;
	sc.vsc_notifications = true;
	ATF_CHECK_EQ(pci_vtfs_install_callbacks(&sc), 0);
	ATF_CHECK_EQ(connection_set_notification_calls, 1U);

	/* Each setter failure is propagated. */
	sc.vsc_callbacks_set = false;
	connection_set_discard_error = EIO;
	ATF_CHECK_EQ(pci_vtfs_install_callbacks(&sc), EIO);
	connection_set_discard_error = 0;

	sc.vsc_callbacks_set = false;
	connection_set_reset_complete_error = EBUSY;
	ATF_CHECK_EQ(pci_vtfs_install_callbacks(&sc), EBUSY);
	connection_set_reset_complete_error = 0;

	sc.vsc_callbacks_set = false;
	connection_set_notification_error = ENOSPC;
	ATF_CHECK_EQ(pci_vtfs_install_callbacks(&sc), ENOSPC);
	connection_set_notification_error = 0;
}

ATF_TC_WITHOUT_HEAD(notify_forwards_requests_to_backend);
ATF_TC_BODY(notify_forwards_requests_to_backend, tc)
{
	struct pci_vtfs_softc sc;
	struct vqueue_info vq[2];
	bool notify_pending[2];

	memset(&sc, 0, sizeof(sc));
	memset(vq, 0, sizeof(vq));
	memset(notify_pending, 0, sizeof(notify_pending));
	reset_mock_state();
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	sc.vsc_num_request_queues = 1;
	sc.vsc_nvq = nitems(vq);
	sc.vsc_vq = vq;
	sc.vsc_notify_pending = notify_pending;
	sc.vsc_callbacks_set = true;
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	vq[0].vq_num = 0; /* hiprio */
	vq[0].vq_qsize = 1;
	vq[1].vq_num = 1; /* request */
	vq[1].vq_qsize = 1;
	vq_getchain_req_template.readable = 2;
	vq_getchain_req_template.writable = 1;
	vq_getchain_req_template.ordered = true;

	/* One descriptor available, submit succeeds: request forwarded. */
	vq_has_descs_result = 1;
	vq_getchain_result = 3;
	connection_submit_calls = 0;
	pci_vtfs_notify(&sc, &vq[0]);
	ATF_CHECK_EQ(connection_submit_calls, 1U);

	/* Backend backpressure retains the chain and defers a retry. */
	notify_pending[1] = false;
	connection_submit_error = ENOBUFS;
	pci_vtfs_notify(&sc, &vq[1]);
	ATF_CHECK(notify_pending[1]);

	/* A hard submit error requests a device reset. */
	connection_submit_error = EIO;
	needs_reset_calls = 0;
	pci_vtfs_notify(&sc, &vq[1]);
	ATF_CHECK(needs_reset_calls >= 1U);

	/* Empty getchain simply stops draining the ring. */
	connection_submit_error = 0;
	vq_getchain_result = 0;
	pci_vtfs_notify(&sc, &vq[1]);

	/* vq_num beyond the device topology forces a reset. */
	vq[1].vq_num = 99;
	needs_reset_calls = 0;
	pci_vtfs_notify(&sc, &vq[1]);
	ATF_CHECK_EQ(needs_reset_calls, 1U);

	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(notify_defers_when_callbacks_absent);
ATF_TC_BODY(notify_defers_when_callbacks_absent, tc)
{
	struct pci_vtfs_softc sc;
	struct vqueue_info vq[2];
	bool notify_pending[2];

	memset(&sc, 0, sizeof(sc));
	memset(vq, 0, sizeof(vq));
	memset(notify_pending, 0, sizeof(notify_pending));
	reset_mock_state();
	sc.vsc_num_request_queues = 1;
	sc.vsc_nvq = nitems(vq);
	sc.vsc_vq = vq;
	sc.vsc_notify_pending = notify_pending;
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	sc.vsc_callbacks_set = false;
	vq[1].vq_num = 1;

	pci_vtfs_notify(&sc, &vq[1]);
	ATF_CHECK(notify_pending[1]);
}

ATF_TC_WITHOUT_HEAD(receive_notification_publishes_to_queue);
ATF_TC_BODY(receive_notification_publishes_to_queue, tc)
{
	struct pci_vtfs_softc sc;
	struct vqueue_info vq[2];
	static const uint8_t payload[] = { 0x7f, 0x45, 0x4c, 0x46 };

	memset(&sc, 0, sizeof(sc));
	memset(vq, 0, sizeof(vq));
	reset_mock_state();
	sc.vsc_notifications = true;
	sc.vsc_nvq = nitems(vq);
	sc.vsc_vq = vq;
	vq[1].vq_num = 1;

	/* Rejected shapes: null/empty/oversized payload, no notifications. */
	ATF_CHECK_EQ(pci_vtfs_receive_notification(&sc, NULL,
	    sizeof(payload)), EPROTO);
	ATF_CHECK_EQ(pci_vtfs_receive_notification(&sc, payload, 0), EPROTO);
	ATF_CHECK_EQ(pci_vtfs_receive_notification(&sc, payload,
	    BHYVE_VIRTIO_FS_NOTIFY_BUF_SIZE + 1U), EPROTO);

	/* No guest descriptor: retained for a later retry. */
	vq_has_descs_result = 0;
	ATF_CHECK_EQ(pci_vtfs_receive_notification(&sc, payload,
	    sizeof(payload)), EAGAIN);

	/* getchain failure is a protocol error. */
	vq_has_descs_result = 1;
	vq_getchain_result = 0;
	ATF_CHECK_EQ(pci_vtfs_receive_notification(&sc, payload,
	    sizeof(payload)), EPROTO);

	/* A read-only / unordered / too-small buffer is rejected. */
	vq_getchain_result = 1;
	vq_getchain_req_template.ordered = false;
	ATF_CHECK_EQ(pci_vtfs_receive_notification(&sc, payload,
	    sizeof(payload)), EPROTO);
	vq_getchain_req_template.ordered = true;
	vq_getchain_req_template.readable = 0;
	vq_getchain_req_template.writable = 1;
	vq_getchain_req_template.writable_bytes = sizeof(payload);

	/* Short copy into the guest buffer is a protocol error. */
	buf_to_iov_result_valid = true;
	buf_to_iov_result = sizeof(payload) - 1U;
	ATF_CHECK_EQ(pci_vtfs_receive_notification(&sc, payload,
	    sizeof(payload)), EPROTO);

	/* Full copy publishes the notification. */
	buf_to_iov_result = sizeof(payload);
	vq_relchain_calls = 0;
	ATF_CHECK_EQ(pci_vtfs_receive_notification(&sc, payload,
	    sizeof(payload)), 0);
	ATF_CHECK_EQ(vq_relchain_calls, 1U);

	/* A device without a notification queue cannot receive one. */
	sc.vsc_nvq = 1;
	ATF_CHECK_EQ(pci_vtfs_receive_notification(&sc, payload,
	    sizeof(payload)), EPROTO);
}

ATF_TC_WITHOUT_HEAD(discard_callback_cancels_request);
ATF_TC_BODY(discard_callback_cancels_request, tc)
{
	struct pci_vtfs_request *request;
	struct pci_vtfs_softc sc;
	struct vqueue_info vq;
	struct timespec now;

	memset(&sc, 0, sizeof(sc));
	memset(&vq, 0, sizeof(vq));
	reset_mock_state();
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	vq.vq_num = 1;

	/* submitted_valid with a past timestamp exercises the elapsed-ns math. */
	request = calloc(1, sizeof(*request));
	ATF_REQUIRE(request != NULL);
	request->vq = &vq;
	ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &now), 0);
	request->submitted_valid = true;
	request->submitted.tv_sec = now.tv_sec - 1;
	request->submitted.tv_nsec = 999999999L; /* forces the borrow branch */
	pci_vtfs_discard(&sc, (uintptr_t)request);

	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(complete_discards_stale_generation);
ATF_TC_BODY(complete_discards_stale_generation, tc)
{
	struct pci_vtfs_request *request;
	struct pci_vtfs_softc sc;
	struct vqueue_info vq;

	memset(&sc, 0, sizeof(sc));
	memset(&vq, 0, sizeof(vq));
	reset_mock_state();
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	vq.vq_num = 1;
	vq.vq_generation = 5;

	request = calloc(1, sizeof(*request));
	ATF_REQUIRE(request != NULL);
	request->vq = &vq;
	request->generation = 4; /* stale relative to the queue generation */
	vq_relchain_calls = 0;
	/* A stale completion is discarded rather than published. */
	pci_vtfs_complete(&sc, (uintptr_t)request, 32);
	ATF_CHECK_EQ(vq_relchain_calls, 0U);

	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(take_reset_completions_skips_and_clamps);
ATF_TC_BODY(take_reset_completions_skips_and_clamps, tc)
{
	struct pci_vtfs_reset_completion completions[1];
	struct pci_vtfs_reset resets[3];
	struct pci_vtfs_softc sc;
	struct vqueue_info queues[3];
	size_t count;

	memset(&sc, 0, sizeof(sc));
	memset(resets, 0, sizeof(resets));
	memset(queues, 0, sizeof(queues));
	reset_mock_state();
	sc.vsc_nvq = nitems(resets);
	sc.vsc_reset = resets;
	/* Index 0 incomplete (continue), 1 and 2 complete (clamped by capacity). */
	resets[1] = (struct pci_vtfs_reset){ .vq = &queues[1], .complete = true };
	resets[2] = (struct pci_vtfs_reset){ .vq = &queues[2], .complete = true };
	count = pci_vtfs_take_reset_completions(&sc, completions,
	    nitems(completions));
	ATF_CHECK_EQ(count, 1U);
	ATF_CHECK(completions[0].vq == &queues[1]);
	/* Capacity stopped collection before index 2 was cleared. */
	ATF_CHECK(resets[2].complete);
}

ATF_TC_WITHOUT_HEAD(qreset_rejects_out_of_range_and_notification);
ATF_TC_BODY(qreset_rejects_out_of_range_and_notification, tc)
{
	struct pci_vtfs_reset reset[3];
	struct pci_vtfs_softc sc;
	struct vqueue_info vq;

	memset(&sc, 0, sizeof(sc));
	memset(&vq, 0, sizeof(vq));
	memset(reset, 0, sizeof(reset));
	reset_mock_state();
	sc.vsc_notifications = true;
	sc.vsc_num_request_queues = 1;
	sc.vsc_nvq = nitems(reset);
	sc.vsc_reset = reset;
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;

	/* Queue index outside the topology is invalid. */
	vq.vq_num = 99;
	ATF_CHECK_EQ(pci_vtfs_qreset(&sc, &vq, 1), EINVAL);

	/* The notification queue (index 1) is never guest-resettable. */
	vq.vq_num = 1;
	ATF_CHECK_EQ(pci_vtfs_qreset(&sc, &vq, 1), 0);
}

ATF_TC_WITHOUT_HEAD(event_processes_progress_and_completions);
ATF_TC_BODY(event_processes_progress_and_completions, tc)
{
	struct pci_vtfs_softc sc;
	struct vqueue_info vq[2];
	struct pci_vtfs_reset reset[2];
	bool notify_pending[2];
	pthread_condattr_t condattr;

	memset(&sc, 0, sizeof(sc));
	memset(vq, 0, sizeof(vq));
	memset(reset, 0, sizeof(reset));
	memset(notify_pending, 0, sizeof(notify_pending));
	reset_mock_state();
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_condattr_init(&condattr), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&sc.vsc_checkpoint_cv, &condattr), 0);
	ATF_REQUIRE_EQ(pthread_condattr_destroy(&condattr), 0);
	sc.vsc_num_request_queues = 1;
	sc.vsc_nvq = nitems(vq);
	sc.vsc_vq = vq;
	sc.vsc_reset = reset;
	sc.vsc_notify_pending = notify_pending;
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	sc.vsc_read_event = (struct mevent *)(uintptr_t)1;
	sc.vsc_write_event = (struct mevent *)(uintptr_t)2;
	vq[0].vq_num = 0;
	vq[1].vq_num = 1;
	/* A pending kick is retried once callbacks install. */
	notify_pending[0] = true;
	/* A completed queue reset is delivered after the lock is dropped. */
	reset[1].vq = &vq[1];
	reset[1].generation = 3;
	reset[1].complete = true;
	sc.vsc_checkpoint_waiting = true;
	connection_control_status_result = 0; /* != EINPROGRESS -> broadcast */

	pci_vtfs_event(-1, EVF_READ, &sc);
	ATF_CHECK(sc.vsc_callbacks_set);
	ATF_CHECK_EQ(vi_pci_modern_queue_reset_complete_calls, 1U);

	/* A backend progress error requests a reset. */
	sc.vsc_callbacks_set = false;
	connection_progress_error = EIO;
	needs_reset_calls = 0;
	pci_vtfs_event(-1, EVF_WRITE, &sc);
	ATF_CHECK(needs_reset_calls >= 1U);

	/* A reconnecting device drops the event immediately. */
	connection_progress_error = 0;
	sc.vsc_reconnecting = true;
	vq_has_descs_calls = 0;
	pci_vtfs_event(-1, EVF_READ, &sc);

	ATF_REQUIRE_EQ(pthread_cond_destroy(&sc.vsc_checkpoint_cv), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(reset_reconnects_backend);
ATF_TC_BODY(reset_reconnects_backend, tc)
{
	struct pci_vtfs_softc sc;
	struct vqueue_info vq[2];
	struct pci_vtfs_reset reset[2];
	bool notify_pending[2];

	memset(&sc, 0, sizeof(sc));
	memset(vq, 0, sizeof(vq));
	memset(reset, 0, sizeof(reset));
	memset(notify_pending, 0, sizeof(notify_pending));
	reset_mock_state();
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	sc.vsc_num_request_queues = 1;
	sc.vsc_nvq = nitems(vq);
	sc.vsc_vq = vq;
	sc.vsc_reset = reset;
	sc.vsc_notify_pending = notify_pending;
	sc.vsc_backend_path = strdup("/s");
	ATF_REQUIRE(sc.vsc_backend_path != NULL);
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	sc.vsc_read_event = (struct mevent *)(uintptr_t)1;
	sc.vsc_write_event = (struct mevent *)(uintptr_t)2;

	/* Reset is entered with the device mutex held. */
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vsc_mtx), 0);
	pci_vtfs_reset(&sc);
	ATF_CHECK(!sc.vsc_reconnecting);
	ATF_CHECK(!sc.vsc_guest_suspended);
	/* A fresh connection was established by the reconnect. */
	ATF_CHECK(sc.vsc_connection != NULL);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);

	pci_vtfs_disconnect_sync(&sc);
	free(sc.vsc_backend_path);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(reset_reconnect_failure_sets_needs_reset);
ATF_TC_BODY(reset_reconnect_failure_sets_needs_reset, tc)
{
	struct pci_vtfs_softc sc;
	struct vqueue_info vq[2];
	struct pci_vtfs_reset reset[2];
	bool notify_pending[2];

	memset(&sc, 0, sizeof(sc));
	memset(vq, 0, sizeof(vq));
	memset(reset, 0, sizeof(reset));
	memset(notify_pending, 0, sizeof(notify_pending));
	reset_mock_state();
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	sc.vsc_num_request_queues = 1;
	sc.vsc_nvq = nitems(vq);
	sc.vsc_vq = vq;
	sc.vsc_reset = reset;
	sc.vsc_notify_pending = notify_pending;
	sc.vsc_backend_path = strdup("/s");
	ATF_REQUIRE(sc.vsc_backend_path != NULL);
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;

	connect_required_error = ECONNREFUSED;
	needs_reset_calls = 0;
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vsc_mtx), 0);
	pci_vtfs_reset(&sc);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);
	ATF_CHECK_EQ(needs_reset_calls, 1U);
	connect_required_error = 0;

	pci_vtfs_disconnect_sync(&sc);
	free(sc.vsc_backend_path);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(suspend_and_resume_device_quiesce_backend);
ATF_TC_BODY(suspend_and_resume_device_quiesce_backend, tc)
{
	struct pci_vtfs_softc sc;
	struct pci_vtfs_reset reset[2];
	pthread_condattr_t condattr;

	memset(&sc, 0, sizeof(sc));
	memset(reset, 0, sizeof(reset));
	reset_mock_state();
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_condattr_init(&condattr), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&sc.vsc_checkpoint_cv, &condattr), 0);
	ATF_REQUIRE_EQ(pthread_condattr_destroy(&condattr), 0);
	sc.vsc_nvq = nitems(reset);
	sc.vsc_reset = reset;
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;

	/* Without an installed backend suspend is refused. */
	ATF_CHECK_EQ(pci_vtfs_suspend_device(&sc), EBUSY);

	/* A quiesced backend suspends: begin_quiesce completes immediately. */
	sc.vsc_callbacks_set = true;
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vsc_mtx), 0);
	ATF_CHECK_EQ(pci_vtfs_suspend_device(&sc), 0);
	ATF_CHECK(sc.vsc_guest_suspended);

	/* Resume thaws the backend back to a runnable state. */
	ATF_CHECK_EQ(pci_vtfs_resume_device(&sc), 0);
	ATF_CHECK(!sc.vsc_guest_suspended);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);

	/* Resume without a prior suspend is invalid. */
	ATF_CHECK_EQ(pci_vtfs_resume_device(&sc), EINVAL);

	ATF_REQUIRE_EQ(pthread_cond_destroy(&sc.vsc_checkpoint_cv), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

#ifdef BHYVE_SNAPSHOT
ATF_TC_WITHOUT_HEAD(snapshot_validate_serializes_with_device_lock);
ATF_TC_BODY(snapshot_validate_serializes_with_device_lock, tc)
{
	struct pci_vtfs_softc sc;
	struct pci_devinst pi;
	struct vm_snapshot_meta meta = { .op = VM_SNAPSHOT_SAVE };

	memset(&sc, 0, sizeof(sc));
	memset(&pi, 0, sizeof(pi));
	reset_mock_state();
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);

	/* Argument validation. */
	ATF_CHECK_EQ(pci_vtfs_snapshot_validate(NULL), EINVAL);
	meta.op = VM_SNAPSHOT_SAVE;
	ATF_CHECK_EQ(pci_vtfs_snapshot_validate(&meta), EINVAL);
	meta.op = VM_SNAPSHOT_VALIDATE;
	ATF_CHECK_EQ(pci_vtfs_snapshot_validate(&meta), EINVAL);
	meta.dev_data = &pi;
	pi.pi_arg = NULL;
	ATF_CHECK_EQ(pci_vtfs_snapshot_validate(&meta), EINVAL);

	/* Valid path acquires the device mutex around vi_pci_snapshot(). */
	pi.pi_arg = &sc;
	ATF_CHECK_EQ(pci_vtfs_snapshot_validate(&meta), 0);
	ATF_CHECK(!pthread_mutex_isowned_np(&sc.vsc_mtx));

	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}
#endif

ATF_TC_WITHOUT_HEAD(qreset_pending_and_success);
ATF_TC_BODY(qreset_pending_and_success, tc)
{
	struct pci_vtfs_reset reset[2];
	struct pci_vtfs_softc sc;
	struct vqueue_info vq;
	bool notify_pending[2];

	memset(&sc, 0, sizeof(sc));
	memset(&vq, 0, sizeof(vq));
	memset(reset, 0, sizeof(reset));
	memset(notify_pending, 0, sizeof(notify_pending));
	reset_mock_state();
	sc.vsc_num_request_queues = 1;
	sc.vsc_nvq = nitems(reset);
	sc.vsc_reset = reset;
	sc.vsc_notify_pending = notify_pending;
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	vq.vq_num = 1;

	/* Synchronous success: backend cancels immediately, readiness re-armed. */
	connection_reset_error = 0;
	ATF_CHECK_EQ(pci_vtfs_qreset(&sc, &vq, 5), 0);
	ATF_CHECK(!reset[1].pending);

	/* A second reset while one is pending is rejected. */
	reset[1].pending = true;
	ATF_CHECK_EQ(pci_vtfs_qreset(&sc, &vq, 6), EBUSY);
}

ATF_TC_WITHOUT_HEAD(notify_notification_queue_retry_error);
ATF_TC_BODY(notify_notification_queue_retry_error, tc)
{
	struct pci_vtfs_softc sc;
	struct vqueue_info vq[2];
	bool notify_pending[2];

	memset(&sc, 0, sizeof(sc));
	memset(vq, 0, sizeof(vq));
	memset(notify_pending, 0, sizeof(notify_pending));
	reset_mock_state();
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	sc.vsc_notifications = true;
	sc.vsc_num_request_queues = 1;
	sc.vsc_nvq = nitems(vq);
	sc.vsc_vq = vq;
	sc.vsc_notify_pending = notify_pending;
	sc.vsc_callbacks_set = true;
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	vq[1].vq_num = 1; /* notification queue */

	/* A hard retry failure on the notification queue forces a reset. */
	notification_retry_error = EIO;
	needs_reset_calls = 0;
	pci_vtfs_notify(&sc, &vq[1]);
	ATF_CHECK_EQ(notification_retry_calls, 1U);
	ATF_CHECK_EQ(needs_reset_calls, 1U);

	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(notify_event_arm_failure_sets_needs_reset);
ATF_TC_BODY(notify_event_arm_failure_sets_needs_reset, tc)
{
	struct pci_vtfs_softc sc;
	struct vqueue_info vq[2];
	bool notify_pending[2];

	memset(&sc, 0, sizeof(sc));
	memset(vq, 0, sizeof(vq));
	memset(notify_pending, 0, sizeof(notify_pending));
	reset_mock_state();
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	sc.vsc_num_request_queues = 1;
	sc.vsc_nvq = nitems(vq);
	sc.vsc_vq = vq;
	sc.vsc_notify_pending = notify_pending;
	sc.vsc_callbacks_set = true;
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	sc.vsc_read_event = (struct mevent *)(uintptr_t)1;
	vq[1].vq_num = 1;
	vq[1].vq_qsize = 1;

	/* Empty ring, but re-arming readiness fails: request a reset. */
	vq_has_descs_result = 0;
	connection_events = VIRTIO_FS_CONNECTION_READ;
	mevent_enable_read_error = EIO;
	needs_reset_calls = 0;
	pci_vtfs_notify(&sc, &vq[1]);
	ATF_CHECK(needs_reset_calls >= 1U);

	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(event_install_failure_and_arm_failure);
ATF_TC_BODY(event_install_failure_and_arm_failure, tc)
{
	struct pci_vtfs_softc sc;
	struct vqueue_info vq[2];
	struct pci_vtfs_reset reset[2];
	bool notify_pending[2];
	pthread_condattr_t condattr;

	memset(&sc, 0, sizeof(sc));
	memset(vq, 0, sizeof(vq));
	memset(reset, 0, sizeof(reset));
	memset(notify_pending, 0, sizeof(notify_pending));
	reset_mock_state();
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_condattr_init(&condattr), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&sc.vsc_checkpoint_cv, &condattr), 0);
	ATF_REQUIRE_EQ(pthread_condattr_destroy(&condattr), 0);
	sc.vsc_num_request_queues = 1;
	sc.vsc_nvq = nitems(vq);
	sc.vsc_vq = vq;
	sc.vsc_reset = reset;
	sc.vsc_notify_pending = notify_pending;
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	sc.vsc_read_event = (struct mevent *)(uintptr_t)1;
	vq[1].vq_num = 1;

	/* Progress succeeds but installing the callbacks fails. */
	connection_set_discard_error = EIO;
	connection_events = VIRTIO_FS_CONNECTION_READ;
	mevent_enable_read_error = EBUSY; /* also fails the final re-arm */
	needs_reset_calls = 0;
	pci_vtfs_event(-1, EVF_READ, &sc);
	ATF_CHECK(needs_reset_calls >= 2U);

	ATF_REQUIRE_EQ(pthread_cond_destroy(&sc.vsc_checkpoint_cv), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(resume_device_restored_state_and_sync_failure);
ATF_TC_BODY(resume_device_restored_state_and_sync_failure, tc)
{
	struct pci_vtfs_softc sc;
	uint8_t *state;
	pthread_condattr_t condattr;

	memset(&sc, 0, sizeof(sc));
	reset_mock_state();
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_condattr_init(&condattr), 0);
	ATF_REQUIRE_EQ(pthread_condattr_setclock(&condattr, CLOCK_MONOTONIC), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&sc.vsc_checkpoint_cv, &condattr), 0);
	ATF_REQUIRE_EQ(pthread_condattr_destroy(&condattr), 0);
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	sc.vsc_guest_suspended = true;
	state = malloc(4);
	ATF_REQUIRE(state != NULL);
	memset(state, 0x5a, 4);
	sc.vsc_checkpoint_backend_state = state;
	sc.vsc_checkpoint_backend_state_len = 4;

	/* A restored thaw blob selects begin_thaw() and then completes. */
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vsc_mtx), 0);
	ATF_CHECK_EQ(pci_vtfs_resume_device(&sc), 0);
	ATF_CHECK(!sc.vsc_guest_suspended);
	ATF_CHECK(sc.vsc_checkpoint_backend_state == NULL);

	/* A sync-events failure after thaw requests a device reset. */
	sc.vsc_guest_suspended = true;
	connection_events = VIRTIO_FS_CONNECTION_READ;
	sc.vsc_read_event = (struct mevent *)(uintptr_t)1;
	mevent_enable_read_error = EIO;
	needs_reset_calls = 0;
	ATF_CHECK(pci_vtfs_resume_device(&sc) != 0);
	ATF_CHECK(needs_reset_calls >= 1U);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);

	ATF_REQUIRE_EQ(pthread_cond_destroy(&sc.vsc_checkpoint_cv), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(control_wait_times_out_and_aborts);
ATF_TC_BODY(control_wait_times_out_and_aborts, tc)
{
	struct pci_vtfs_softc sc;

	memset(&sc, 0, sizeof(sc));
	reset_mock_state();
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	/*
	 * Initialise the condition variable on CLOCK_REALTIME while the code
	 * computes its deadline on CLOCK_MONOTONIC.  The monotonic deadline is
	 * far in the REALTIME past, so the timed wait returns immediately and
	 * the control wait exercises its timeout/abort path without blocking.
	 */
	ATF_REQUIRE_EQ(pthread_cond_init(&sc.vsc_checkpoint_cv, NULL), 0);
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	sc.vsc_guest_suspended = true;
	connection_control_status_result = EINPROGRESS;
	needs_reset_calls = 0;

	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vsc_mtx), 0);
	/* resume_device drives begin_thaw_saved -> sync -> control_wait. */
	ATF_CHECK(pci_vtfs_resume_device(&sc) != 0);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);
	ATF_CHECK(needs_reset_calls >= 1U);

	ATF_REQUIRE_EQ(pthread_cond_destroy(&sc.vsc_checkpoint_cv), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(begin_quiesce_wait_inprogress_paths);
ATF_TC_BODY(begin_quiesce_wait_inprogress_paths, tc)
{
	struct pci_vtfs_softc sc;
	struct pci_vtfs_reset reset[2];

	memset(&sc, 0, sizeof(sc));
	memset(reset, 0, sizeof(reset));
	reset_mock_state();
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	/* REALTIME cond => the monotonic deadline is already past. */
	ATF_REQUIRE_EQ(pthread_cond_init(&sc.vsc_checkpoint_cv, NULL), 0);
	sc.vsc_nvq = nitems(reset);
	sc.vsc_reset = reset;
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	sc.vsc_callbacks_set = true;
	sc.vsc_read_event = (struct mevent *)(uintptr_t)1;

	/* begin_quiesce is in progress; re-arming readiness fails immediately. */
	connection_begin_quiesce_result = EINPROGRESS;
	connection_events = VIRTIO_FS_CONNECTION_READ;
	mevent_enable_read_error = EIO;
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vsc_mtx), 0);
	ATF_CHECK(pci_vtfs_suspend_device(&sc) != 0);

	/* Re-arm succeeds, but the drain wait times out (past deadline). */
	mevent_enable_read_error = 0;
	connection_events = 0;
	ATF_CHECK(pci_vtfs_suspend_device(&sc) != 0);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);

	ATF_REQUIRE_EQ(pthread_cond_destroy(&sc.vsc_checkpoint_cv), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

#ifdef BHYVE_SNAPSHOT
ATF_TC_WITHOUT_HEAD(pause_failure_paths_and_rollback);
ATF_TC_BODY(pause_failure_paths_and_rollback, tc)
{
	struct pci_vtfs_softc sc;
	struct pci_vtfs_reset reset[2];
	static char identity[] = "backend-identity";
	pthread_condattr_t condattr;

	memset(&sc, 0, sizeof(sc));
	memset(reset, 0, sizeof(reset));
	reset_mock_state();
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_condattr_init(&condattr), 0);
	ATF_REQUIRE_EQ(pthread_condattr_setclock(&condattr, CLOCK_MONOTONIC), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&sc.vsc_checkpoint_cv, &condattr), 0);
	ATF_REQUIRE_EQ(pthread_condattr_destroy(&condattr), 0);
	sc.vsc_nvq = nitems(reset);
	sc.vsc_reset = reset;

	/* Without identity the device is not reconstructible: ENOTSUP. */
	ATF_CHECK_EQ(pci_vtfs_pause(&sc), ENOTSUP);
	ATF_CHECK(!pthread_mutex_isowned_np(&sc.vsc_mtx));

	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	sc.vsc_callbacks_set = true;
	sc.vsc_backend_identity = identity;

	/* A pending queue reset blocks a checkpoint. */
	reset[1].pending = true;
	ATF_CHECK_EQ(pci_vtfs_pause(&sc), EBUSY);
	reset[1].pending = false;

	/* begin_quiesce_wait failure aborts the checkpoint. */
	connection_begin_quiesce_result = EIO;
	ATF_CHECK_EQ(pci_vtfs_pause(&sc), EIO);
	connection_begin_quiesce_result = 0;

	/* checkpoint_copy failure triggers a quiesce rollback. */
	checkpoint_copy_error = EIO;
	ATF_CHECK_EQ(pci_vtfs_pause(&sc), EIO);
	checkpoint_copy_error = 0;

	/* A rollback whose thaw also fails demands a device reset. */
	checkpoint_copy_error = EIO;
	checkpoint_thaw_error = 0;
	connection_begin_thaw_saved_error = EIO;
	needs_reset_calls = 0;
	ATF_CHECK(pci_vtfs_pause(&sc) != 0);
	ATF_CHECK(needs_reset_calls >= 1U);
	connection_begin_thaw_saved_error = 0;
	checkpoint_copy_error = 0;

	ATF_REQUIRE_EQ(pthread_cond_destroy(&sc.vsc_checkpoint_cv), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(resume_restores_suspended_destination);
ATF_TC_BODY(resume_restores_suspended_destination, tc)
{
	struct pci_vtfs_softc sc;

	memset(&sc, 0, sizeof(sc));
	reset_mock_state();
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;
	/*
	 * The restored image is itself suspended: common resume must record the
	 * guest-suspended state and hand ownership back without thawing.
	 */
	sc.vsc_vs.vs_suspended = true;
	sc.vsc_checkpoint_lock_held = false;
	checkpoint_thaw_calls = 0;
	ATF_CHECK_EQ(pci_vtfs_resume(&sc), 0);
	ATF_CHECK(sc.vsc_guest_suspended);
	ATF_CHECK_EQ(checkpoint_thaw_calls, 0);
	ATF_CHECK(!sc.vsc_checkpoint_lock_held);
	ATF_CHECK(!pthread_mutex_isowned_np(&sc.vsc_mtx));

	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(snapshot_rejects_unowned_and_contract_failure);
ATF_TC_BODY(snapshot_rejects_unowned_and_contract_failure, tc)
{
	struct pci_vtfs_softc sc;
	static char identity[] = "backend-identity";
	uint8_t image[64];

	memset(&sc, 0, sizeof(sc));
	reset_mock_state();
	sc.vsc_backend_identity = identity;
	sc.vsc_connection = (struct virtio_fs_connection *)(uintptr_t)1;

	/* SAVE without the pause-held lock is rejected. */
	sc.vsc_checkpoint_lock_held = false;
	ATF_CHECK_EQ(run_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, NULL), EBUSY);

	/* A failed destination contract query aborts a restore. */
	sc.vsc_checkpoint_lock_held = true;
	checkpoint_contract_error = EIO;
	ATF_CHECK_EQ(run_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_RESTORE, NULL), EIO);
	checkpoint_contract_error = 0;
}
#endif

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, option_bounds);
	ATF_TP_ADD_TC(tp, configuration_layout);
	ATF_TP_ADD_TC(tp, device_contract);
	ATF_TP_ADD_TC(tp,
	    suspend_capability_requires_reconstructible_backend);
	ATF_TP_ADD_TC(tp, restored_suspend_selects_destination_state);
	ATF_TP_ADD_TC(tp, suspended_checkpoint_keeps_backend_quiesced);
	ATF_TP_ADD_TC(tp, snapshot_serializer_reuses_pause_ownership);
#ifdef BHYVE_SNAPSHOT
	ATF_TP_ADD_TC(tp,
	    snapshot_callback_validates_before_backend_publication);
	ATF_TP_ADD_TC(tp,
	    checkpoint_pause_transfers_mutex_to_resume);
	ATF_TP_ADD_TC(tp,
	    suspended_destination_runnable_restore_thaws_backend);
	ATF_TP_ADD_TC(tp, checkpoint_thaw_failure_is_retryable);
	ATF_TP_ADD_TC(tp,
	    suspended_checkpoint_failure_preserves_thaw_blob);
#endif
	ATF_TP_ADD_TC(tp, generation_scoped_reset_completion);
	ATF_TP_ADD_TC(tp, async_reset_event_failure_retains_ownership);
	ATF_TP_ADD_TC(tp, reconnecting_event_is_ignored);
	ATF_TP_ADD_TC(tp, disconnected_event_sync_is_safe);
	ATF_TP_ADD_TC(tp, event_sync_reports_registration_failure);
	ATF_TP_ADD_TC(tp, completion_uses_device_context_for_pressure);
	ATF_TP_ADD_TC(tp, reconnecting_queue_callbacks_are_fenced);
	ATF_TP_ADD_TC(tp, notification_queue_reset_defers_delivery);
	ATF_TP_ADD_TC(tp, init_composes_device_topology);
	ATF_TP_ADD_TC(tp, init_enables_notifications_packed_and_suspend);
	ATF_TP_ADD_TC(tp, init_rejects_invalid_configuration);
	ATF_TP_ADD_TC(tp, init_unwinds_on_transport_failures);
	ATF_TP_ADD_TC(tp, init_fails_when_backend_connect_fails);
	ATF_TP_ADD_TC(tp, install_callbacks_registers_all_handlers);
	ATF_TP_ADD_TC(tp, notify_forwards_requests_to_backend);
	ATF_TP_ADD_TC(tp, notify_defers_when_callbacks_absent);
	ATF_TP_ADD_TC(tp, receive_notification_publishes_to_queue);
	ATF_TP_ADD_TC(tp, discard_callback_cancels_request);
	ATF_TP_ADD_TC(tp, complete_discards_stale_generation);
	ATF_TP_ADD_TC(tp, take_reset_completions_skips_and_clamps);
	ATF_TP_ADD_TC(tp, qreset_rejects_out_of_range_and_notification);
	ATF_TP_ADD_TC(tp, event_processes_progress_and_completions);
	ATF_TP_ADD_TC(tp, reset_reconnects_backend);
	ATF_TP_ADD_TC(tp, reset_reconnect_failure_sets_needs_reset);
	ATF_TP_ADD_TC(tp, suspend_and_resume_device_quiesce_backend);
	ATF_TP_ADD_TC(tp, qreset_pending_and_success);
	ATF_TP_ADD_TC(tp, notify_notification_queue_retry_error);
	ATF_TP_ADD_TC(tp, notify_event_arm_failure_sets_needs_reset);
	ATF_TP_ADD_TC(tp, event_install_failure_and_arm_failure);
	ATF_TP_ADD_TC(tp, resume_device_restored_state_and_sync_failure);
	ATF_TP_ADD_TC(tp, control_wait_times_out_and_aborts);
	ATF_TP_ADD_TC(tp, begin_quiesce_wait_inprogress_paths);
#ifdef BHYVE_SNAPSHOT
	ATF_TP_ADD_TC(tp, snapshot_validate_serializes_with_device_lock);
	ATF_TP_ADD_TC(tp, pause_failure_paths_and_rollback);
	ATF_TP_ADD_TC(tp, resume_restores_suspended_destination);
	ATF_TP_ADD_TC(tp, snapshot_rejects_unowned_and_contract_failure);
#endif
	return (atf_no_error());
}
