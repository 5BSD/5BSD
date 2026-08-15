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

#ifdef BHYVE_SNAPSHOT
static int restore_session_calls;
static int checkpoint_contract_calls;
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
	return (0);
}

int
vq_getchain(struct vqueue_info *vq __unused, struct iovec *iov __unused,
    int niov __unused, struct vi_req *request __unused)
{

	return (0);
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

	return (0);
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

	return (0);
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

	return (0);
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

	return (0);
}

int
virtio_fs_connection_control_status(
    const struct virtio_fs_connection *connection __unused)
{

	return (0);
}

int
virtio_fs_connection_abort_control(
    struct virtio_fs_connection *connection __unused, int error __unused)
{

	return (0);
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
	ATF_CHECK_EQ(vtfs_vi_consts.vc_hv_caps, VIRTIO_F_RING_RESET);
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
	ATF_CHECK_EQ(sc.vsc_consts.vc_hv_caps, VIRTIO_F_RING_RESET);

	sc.vsc_backend_identity = __DECONST(char *, "backend-identity");
	pci_vtfs_configure_instance_features(&sc);
	ATF_CHECK_EQ(sc.vsc_consts.vc_hv_caps,
	    VIRTIO14_F_RING_RESET | VIRTIO14_F_SUSPEND);

	sc.vsc_backend_identity = NULL;
	pci_vtfs_configure_instance_features(&sc);
	ATF_CHECK_EQ(sc.vsc_consts.vc_hv_caps, VIRTIO_F_RING_RESET);
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
	return (atf_no_error());
}
