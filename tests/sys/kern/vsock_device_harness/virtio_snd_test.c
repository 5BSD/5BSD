/* Device-composition tests for bhyve's VirtIO 1.4 sound device. */
#include <sys/endian.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <stdbool.h>
#include <stdint.h>
#include <pthread_np.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "debug.h"
#include "virtio_snd_async.c"
#include "virtio_snd_host.c"
#include "virtio_snd_queue.c"
#include "pci_virtio_snd.c"
#include "virtio_config_read_test_support.h"
#include "virtio_1_4_spec.h"

enum {
	DUT_SOUND_DEVICE_ID = VIRTIO_ID_SOUND,
};

#undef VIRTIO_ID_SOUND
#define	VIRTIO_ID_SOUND	VIRTIO14_DEVICE_SOUND
#undef VIRTIO_F_RING_PACKED
#define	VIRTIO_F_RING_PACKED	VIRTIO14_F_RING_PACKED

static uint8_t g_readable[1032], g_writable[1032];
static int g_descs, g_chain_n, g_readable_count, g_writable_count;
static size_t g_readable_size, g_writable_size;
static bool g_ordered;
static int g_rel_calls, g_end_calls, g_needs_reset;
static uint32_t g_rel_len;
static struct vqueue_info *g_vq_base;

struct mock_vq {
	uint8_t readable[1032];
	uint8_t writable[1032];
	size_t readable_size;
	size_t writable_size;
	int readable_count;
	int writable_count;
	int chain_n;
	int descs;
	bool ordered;
};

static struct mock_vq g_vqs[VIRTIO14_SND_VQ_COUNT];
static bool g_use_vqs;
static int g_completion_order[16], g_completion_count;
static uint32_t g_completion_len[16];
static int g_release_error;
static bool g_release_observed_pending;
static ssize_t g_audio_result;
static int g_audio_errno;
static int g_audio_set_params_result;
static int g_mevent_enable_calls, g_mevent_disable_calls;
static int g_mevent_delete_sync_calls;
static bool g_mevent_enable_fail;
static const char *g_cfg_backend, *g_cfg_play, *g_cfg_record;
static bool g_cfg_packed;
static int g_select_transport_result;
static int g_intr_init_result;
static int g_modern_init_result;
static int g_modern_set_identity_calls;
static uint16_t g_modern_set_identity_id;
#ifdef BHYVE_SNAPSHOT
static int g_snapshot_validate_calls;
static int g_snapshot_validate_result;
static bool g_snapshot_validate_saw_lock;
#endif

static struct mock_vq *
mock_vq(struct vqueue_info *vq)
{
	ptrdiff_t queue;

	ATF_REQUIRE(g_vq_base != NULL);
	queue = vq - g_vq_base;
	ATF_REQUIRE(queue >= 0);
	ATF_REQUIRE(queue < VIRTIO14_SND_VQ_COUNT);
	return (&g_vqs[queue]);
}

static void
mock_vq_set(unsigned int queue, const void *readable, size_t readable_size,
    size_t writable_size)
{
	struct mock_vq *mq;

	ATF_REQUIRE(queue < nitems(g_vqs));
	ATF_REQUIRE(readable_size <= sizeof(mq->readable));
	ATF_REQUIRE(writable_size <= sizeof(mq->writable));
	mq = &g_vqs[queue];
	memset(mq, 0, sizeof(*mq));
	memcpy(mq->readable, readable, readable_size);
	memset(mq->writable, 0xa5, writable_size);
	mq->readable_size = readable_size;
	mq->writable_size = writable_size;
	mq->readable_count = 2;
	mq->writable_count = 2;
	mq->chain_n = 4;
	mq->descs = 1;
	mq->ordered = true;
}

static void
reset_mocks(void)
{
	memset(g_readable, 0, sizeof(g_readable));
	memset(g_writable, 0xa5, sizeof(g_writable));
	g_descs = 1;
	g_chain_n = 4;
	g_readable_count = 2;
	g_writable_count = 2;
	g_ordered = true;
	g_readable_size = sizeof(g_readable);
	g_writable_size = sizeof(g_writable);
	g_rel_calls = 0;
	g_end_calls = 0;
	g_needs_reset = 0;
	g_rel_len = UINT32_MAX;
	g_vq_base = NULL;
	memset(g_vqs, 0, sizeof(g_vqs));
	g_use_vqs = false;
	g_completion_count = 0;
	g_release_error = 0;
	g_release_observed_pending = false;
	g_audio_result = -1;
	g_audio_errno = EAGAIN;
	g_audio_set_params_result = 0;
	g_mevent_enable_calls = 0;
	g_mevent_disable_calls = 0;
	g_mevent_delete_sync_calls = 0;
	g_mevent_enable_fail = false;
	g_cfg_backend = NULL;
	g_cfg_play = NULL;
	g_cfg_record = NULL;
	g_cfg_packed = false;
	g_select_transport_result = 0;
	g_intr_init_result = 0;
	g_modern_init_result = 0;
	g_modern_set_identity_calls = 0;
	g_modern_set_identity_id = 0;
#ifdef BHYVE_SNAPSHOT
	g_snapshot_validate_calls = 0;
	g_snapshot_validate_result = 0;
	g_snapshot_validate_saw_lock = false;
#endif
	memset(g_completion_order, 0xff, sizeof(g_completion_order));
	memset(g_completion_len, 0xff, sizeof(g_completion_len));
}

static int
failing_release(void *arg __unused, uint32_t stream_id __unused)
{

	return (g_release_error);
}

static int
observing_release(void *arg, uint32_t stream_id)
{

	if (g_use_vqs) {
		unsigned int queue;

		queue = stream_id == 0 ? VTSND_TXQ : VTSND_RXQ;
		g_release_observed_pending |= g_vqs[queue].descs != 0;
	}
	return (pci_vtsnd_release(arg, stream_id));
}

static int
stalling_progress(void *arg __unused,
    enum virtio_snd_async_direction direction __unused,
    void *buffer __unused, size_t remaining __unused, size_t *progress)
{

	*progress = 0;
	return (EAGAIN);
}

static void
setup_softc_release_failure(struct pci_vtsnd_softc *sc)
{
	struct virtio_snd_async_ops async_ops = {
		.progress = pci_vtsnd_async_progress,
		.complete = pci_vtsnd_async_complete,
	};
	struct virtio_snd_host_ops ops = {
		.set_params = pci_vtsnd_set_params,
		.prepare = pci_vtsnd_lifecycle,
		.start = pci_vtsnd_lifecycle,
		.stop = pci_vtsnd_lifecycle,
		.release = failing_release,
		.playback = pci_vtsnd_playback,
		.capture = pci_vtsnd_capture,
	};

	memset(sc, 0, sizeof(*sc));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc->vssc_mtx, NULL), 0);
	ops.arg = sc;
	ATF_REQUIRE_EQ(virtio_snd_host_create(&ops, &sc->vssc_host), 0);
	async_ops.arg = sc;
	ATF_REQUIRE_EQ(virtio_snd_async_create(&async_ops,
	    BHYVE_VTSND_MAX_BUFFER_BYTES, &sc->vssc_async), 0);
	sc->vssc_progress = pci_vtsnd_null_progress;
	sc->vssc_progress_arg = sc;
	sc->vssc_consts = vtsnd_vi_consts;
	sc->vssc_vs.vs_vc = &sc->vssc_consts;
	g_vq_base = sc->vssc_vq;
	for (unsigned int i = 0; i < nitems(sc->vssc_vq); i++)
		sc->vssc_vq[i].vq_qsize = VTSND_RINGSZ;
}

static void
setup_softc(struct pci_vtsnd_softc *sc)
{
	struct virtio_snd_async_ops async_ops = {
		.progress = pci_vtsnd_async_progress,
		.complete = pci_vtsnd_async_complete,
	};
	struct virtio_snd_host_ops ops = {
		.set_params = pci_vtsnd_set_params,
		.prepare = pci_vtsnd_lifecycle,
		.start = pci_vtsnd_lifecycle,
		.stop = pci_vtsnd_lifecycle,
		.release = observing_release,
		.playback = pci_vtsnd_playback,
		.capture = pci_vtsnd_capture,
	};

	memset(sc, 0, sizeof(*sc));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc->vssc_mtx, NULL), 0);
	ops.arg = sc;
	ATF_REQUIRE_EQ(virtio_snd_host_create(&ops, &sc->vssc_host), 0);
	async_ops.arg = sc;
	ATF_REQUIRE_EQ(virtio_snd_async_create(&async_ops,
	    BHYVE_VTSND_MAX_BUFFER_BYTES, &sc->vssc_async), 0);
	sc->vssc_progress = pci_vtsnd_null_progress;
	sc->vssc_progress_arg = sc;
	sc->vssc_consts = vtsnd_vi_consts;
	sc->vssc_vs.vs_vc = &sc->vssc_consts;
	g_vq_base = sc->vssc_vq;
	for (unsigned int i = 0; i < nitems(sc->vssc_vq); i++)
		sc->vssc_vq[i].vq_qsize = VTSND_RINGSZ;
}

static void
teardown_softc(struct pci_vtsnd_softc *sc)
{

	ATF_REQUIRE_EQ(virtio_snd_async_destroy(sc->vssc_async), 0);
	virtio_snd_host_destroy(sc->vssc_host);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc->vssc_mtx), 0);
}

static bool g_audio_init_fail;
static bool g_mevent_add_fail;

struct audio *
audio_init_nonblock(const char *path __unused, uint8_t direction __unused)
{

	if (g_audio_init_fail)
		return (NULL);
	return ((struct audio *)(uintptr_t)1);
}

void
audio_destroy(struct audio *audio __unused)
{
}

int
audio_fd(const struct audio *audio __unused)
{

	return (3);
}

int
audio_set_params(struct audio *audio __unused,
    struct audio_params *params __unused)
{

	return (g_audio_set_params_result);
}

ssize_t
audio_playback_some(struct audio *audio __unused,
    const uint8_t *buffer __unused, size_t size __unused)
{

	errno = g_audio_errno;
	return (g_audio_result);
}

ssize_t
audio_record_some(struct audio *audio __unused, uint8_t *buffer,
    size_t size)
{

	errno = g_audio_errno;
	if (g_audio_result > 0 && (size_t)g_audio_result <= size)
		memset(buffer, 0x5a, (size_t)g_audio_result);
	return (g_audio_result);
}

struct mevent *
mevent_add_disabled(int fd __unused, enum ev_type type __unused,
    void (*callback)(int, enum ev_type, void *) __unused,
    void *arg __unused)
{

	if (g_mevent_add_fail)
		return (NULL);
	return ((struct mevent *)(uintptr_t)1);
}

int
mevent_enable(struct mevent *event __unused)
{

	g_mevent_enable_calls++;
	if (g_mevent_enable_fail)
		return (-1);
	return (0);
}

int
mevent_disable(struct mevent *event __unused)
{

	g_mevent_disable_calls++;
	return (0);
}

int
mevent_delete(struct mevent *event __unused)
{

	return (0);
}

int
mevent_delete_sync(struct mevent *event __unused)
{

	g_mevent_delete_sync_calls++;
	return (0);
}

int
vq_has_descs(struct vqueue_info *vq)
{
	if (g_use_vqs)
		return (mock_vq(vq)->descs > 0);
	return (g_descs > 0);
}

int
vq_getchain(struct vqueue_info *vq, struct iovec *iov, int niov,
    struct vi_req *req)
{
	struct mock_vq *mq;

	ATF_REQUIRE_EQ(niov, BHYVE_VTSND_MAX_CHAIN_SEGMENTS);
	if (g_use_vqs) {
		mq = mock_vq(vq);
		ATF_REQUIRE(mq->chain_n <= niov);
		memset(req, 0, sizeof(*req));
		req->idx = 7;
		req->readable = mq->readable_count;
		req->writable = mq->writable_count;
		req->ordered = mq->ordered;
		req->queue_generation = vq->vq_generation;
		req->outstanding = true;
		iov[0] = (struct iovec){ mq->readable, 3 };
		iov[1] = (struct iovec){ mq->readable + 3,
		    mq->readable_size - 3 };
		iov[2] = (struct iovec){ mq->writable, 1 };
		iov[3] = (struct iovec){ mq->writable + 1,
		    mq->writable_size - 1 };
		mq->descs--;
		return (mq->chain_n);
	}
	ATF_REQUIRE(g_chain_n <= niov);
	memset(req, 0, sizeof(*req));
	req->idx = 7;
	req->readable = g_readable_count;
	req->writable = g_writable_count;
	req->ordered = g_ordered;
	req->queue_generation = vq->vq_generation;
	req->outstanding = true;
	iov[0] = (struct iovec){ g_readable, 3 };
	iov[1] = (struct iovec){ g_readable + 3,
	    g_readable_size - 3 };
	iov[2] = (struct iovec){ g_writable, 5 };
	iov[3] = (struct iovec){ g_writable + 5,
	    g_writable_size - 5 };
	g_descs--;
	return (g_chain_n);
}

void
vq_retchains(struct vqueue_info *vq __unused, uint16_t count __unused)
{
}

void
vq_relchain(struct vqueue_info *vq, uint16_t idx, uint32_t len)
{
	ptrdiff_t queue;

	ATF_CHECK_EQ(idx, 7);
	g_rel_calls++;
	g_rel_len = len;
	if (g_use_vqs) {
		queue = vq - g_vq_base;
		ATF_REQUIRE((size_t)g_completion_count <
		    nitems(g_completion_order));
		g_completion_order[g_completion_count] = (int)queue;
		g_completion_len[g_completion_count] = len;
		g_completion_count++;
	}
}

void
vq_endchains(struct vqueue_info *vq __unused, int all_avail)
{
	g_end_calls++;
	ATF_CHECK(all_avail == 0 || all_avail == 1);
}

void
vi_set_needs_reset(struct virtio_softc *vs __unused)
{
	g_needs_reset++;
}

void
vi_snapshot_restore_incomplete(struct virtio_softc *vs)
{

	vs->vs_restore_incomplete = true;
	vi_set_needs_reset(vs);
}

#ifdef BHYVE_SNAPSHOT
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

static int
run_snapshot(struct pci_vtsnd_softc *sc, uint8_t *image, size_t size,
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

	error = pci_vtsnd_snapshot(sc, &meta);
	if (used != NULL)
		*used = size - meta.buffer.buf_rem;
	return (error);
}
#endif

void
vi_reset_dev(struct virtio_softc *vs __unused)
{
}

int
vi_pci_lifecycle_noop(void *arg __unused)
{
	return (0);
}

#ifdef BHYVE_SNAPSHOT
int
vi_pci_snapshot(struct vm_snapshot_meta *meta)
{
	struct pci_vtsnd_softc *sc;

	g_snapshot_validate_calls++;
	sc = ((struct pci_devinst *)meta->dev_data)->pi_arg;
	g_snapshot_validate_saw_lock = pthread_mutex_isowned_np(&sc->vssc_mtx);
	return (g_snapshot_validate_result);
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
#endif

/*
 * VirtIO PCI transport and configuration stubs.  The production device
 * registration (pci_de_vtsnd) and initialization (pci_vtsnd_init) reference the
 * common VirtIO/PCI plumbing that a device-composition harness deliberately
 * does not link.  These test-controlled stubs let pci_vtsnd_init exercise every
 * admission, backend-selection and teardown branch without a live PCI bus.
 */
const char *
get_config_value_node(const nvlist_t *parent __unused, const char *name)
{

	if (strcmp(name, "backend") == 0)
		return (g_cfg_backend);
	if (strcmp(name, "play") == 0)
		return (g_cfg_play);
	if (strcmp(name, "record") == 0)
		return (g_cfg_record);
	return (NULL);
}

bool
get_config_bool_node_default(const nvlist_t *parent __unused,
    const char *name __unused, bool value)
{

	return (g_cfg_packed ? true : value);
}

void
vi_softc_linkup(struct virtio_softc *vs, struct virtio_consts *vc,
    void *dev_softc, struct pci_devinst *pi, struct vqueue_info *queues)
{

	vs->vs_vc = vc;
	vs->vs_pi = pi;
	vs->vs_queues = queues;
	if (pi != NULL)
		pi->pi_arg = dev_softc;
}

int
vi_pci_select_transport(struct virtio_softc *vs __unused,
    const struct nvlist *nvl __unused,
    enum virtio_pci_transport_policy policy __unused)
{

	return (g_select_transport_result);
}

void
vi_pci_modern_set_identity(struct virtio_softc *vs __unused, uint16_t device_id)
{

	g_modern_set_identity_calls++;
	g_modern_set_identity_id = device_id;
}

int
vi_intr_init(struct virtio_softc *vs, int barnum __unused, int use_msix __unused)
{

	if (g_intr_init_result != 0)
		return (g_intr_init_result);
	return (pthread_mutex_init(&vs->vs_isr_mtx, NULL));
}

int
vi_pci_modern_init(struct virtio_softc *vs __unused, int barnum __unused)
{

	return (g_modern_init_result);
}

int
fbsdrun_virtio_msix(void)
{

	return (1);
}

int
vi_pci_modern_cfgread(struct pci_devinst *pi __unused, int offset __unused,
    int size __unused, uint32_t *retval __unused)
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

void
pci_set_cfgdata8(struct pci_devinst *pi, int offset, uint8_t val)
{

	ATF_REQUIRE(offset >= 0 && (size_t)offset < sizeof(pi->pi_cfgdata));
	pi->pi_cfgdata[offset] = val;
}

uint8_t
pci_get_cfgdata8(struct pci_devinst *pi, int offset)
{

	ATF_REQUIRE(offset >= 0 && (size_t)offset < sizeof(pi->pi_cfgdata));
	return (pi->pi_cfgdata[offset]);
}

static void
configure_playback(struct pci_vtsnd_softc *sc)
{
	uint8_t request[24], response[4];
	size_t used;

	memset(request, 0, sizeof(request));
	le32enc(request, VIRTIO14_SND_R_PCM_SET_PARAMS);
	le32enc(request + 8, 4096);
	le32enc(request + 12, 1024);
	request[20] = 2;
	request[21] = VIRTIO14_SND_PCM_FMT_S16;
	request[22] = VIRTIO14_SND_PCM_RATE_48000;
	ATF_REQUIRE_EQ(virtio_snd_host_control(sc->vssc_host, request,
	    sizeof(request), response, sizeof(response), &used), 0);
	ATF_REQUIRE_EQ(le32dec(response), VIRTIO14_SND_S_OK);
	memset(request, 0, 8);
	le32enc(request, VIRTIO14_SND_R_PCM_PREPARE);
	ATF_REQUIRE_EQ(virtio_snd_host_control(sc->vssc_host, request, 8,
	    response, sizeof(response), &used), 0);
	ATF_REQUIRE_EQ(le32dec(response), VIRTIO14_SND_S_OK);
}

static void
configure_capture(struct pci_vtsnd_softc *sc)
{
	uint8_t request[24], response[4];
	size_t used;

	memset(request, 0, sizeof(request));
	le32enc(request, VIRTIO14_SND_R_PCM_SET_PARAMS);
	le32enc(request + 4, 1);
	le32enc(request + 8, 4096);
	le32enc(request + 12, 1024);
	request[20] = 2;
	request[21] = VIRTIO14_SND_PCM_FMT_S16;
	request[22] = VIRTIO14_SND_PCM_RATE_48000;
	ATF_REQUIRE_EQ(virtio_snd_host_control(sc->vssc_host, request,
	    sizeof(request), response, sizeof(response), &used), 0);
	ATF_REQUIRE_EQ(le32dec(response), VIRTIO14_SND_S_OK);
	memset(request, 0, 8);
	le32enc(request, VIRTIO14_SND_R_PCM_PREPARE);
	le32enc(request + 4, 1);
	ATF_REQUIRE_EQ(virtio_snd_host_control(sc->vssc_host, request, 8,
	    response, sizeof(response), &used), 0);
	ATF_REQUIRE_EQ(le32dec(response), VIRTIO14_SND_S_OK);
}

static void
start_stream(struct pci_vtsnd_softc *sc, uint32_t stream_id)
{
	uint8_t request[8], response[4];
	size_t used;

	memset(request, 0, sizeof(request));
	le32enc(request, VIRTIO14_SND_R_PCM_START);
	le32enc(request + 4, stream_id);
	ATF_REQUIRE_EQ(virtio_snd_host_control(sc->vssc_host, request,
	    sizeof(request), response, sizeof(response), &used), 0);
	ATF_REQUIRE_EQ(used, sizeof(response));
	ATF_REQUIRE_EQ(le32dec(response), VIRTIO14_SND_S_OK);
}

static void
stop_stream(struct pci_vtsnd_softc *sc, uint32_t stream_id)
{
	uint8_t request[8], response[4];
	size_t used;

	memset(request, 0, sizeof(request));
	le32enc(request, VIRTIO14_SND_R_PCM_STOP);
	le32enc(request + 4, stream_id);
	ATF_REQUIRE_EQ(virtio_snd_host_control(sc->vssc_host, request,
	    sizeof(request), response, sizeof(response), &used), 0);
	ATF_REQUIRE_EQ(used, sizeof(response));
	ATF_REQUIRE_EQ(le32dec(response), VIRTIO14_SND_S_OK);
}

ATF_TC_WITHOUT_HEAD(composition_and_config);
ATF_TC_BODY(composition_and_config, tc)
{
	struct pci_vtsnd_softc sc;
	uint32_t value;

	ATF_CHECK_EQ(DUT_SOUND_DEVICE_ID, VIRTIO14_DEVICE_SOUND);
	ATF_CHECK_STREQ(pci_de_vtsnd.pe_emu, "virtio-snd");
	ATF_CHECK_STREQ(vtsnd_vi_consts.vc_name, "vtsnd");
	ATF_CHECK_EQ(vtsnd_vi_consts.vc_nvq, VIRTIO14_SND_VQ_COUNT);
	ATF_CHECK_EQ(vtsnd_vi_consts.vc_cfgsize, VIRTIO14_SND_CONFIG_SIZE);
	ATF_CHECK_EQ(VTSND_CONTROLQ, VIRTIO14_SND_VQ_CONTROL);
	ATF_CHECK_EQ(VTSND_EVENTQ, VIRTIO14_SND_VQ_EVENT);
	ATF_CHECK_EQ(VTSND_TXQ, VIRTIO14_SND_VQ_TX);
	ATF_CHECK_EQ(VTSND_RXQ, VIRTIO14_SND_VQ_RX);
	ATF_CHECK_EQ(vtsnd_vi_consts.vc_hv_caps,
	    VIRTIO14_F_RING_RESET | VIRTIO14_F_SUSPEND);
	ATF_CHECK((vtsnd_vi_consts.vc_hv_caps & VIRTIO14_F_IN_ORDER) == 0);
	ATF_CHECK(pci_vtsnd_backend_valid(NULL));
	ATF_CHECK(pci_vtsnd_backend_valid("null"));
	ATF_CHECK(pci_vtsnd_backend_valid("oss"));
	ATF_CHECK(!pci_vtsnd_backend_valid(""));
	ATF_CHECK(!pci_vtsnd_backend_valid("NULL"));
	ATF_CHECK(vtsnd_vi_consts.vc_qreset == pci_vtsnd_qreset);
	ATF_CHECK(vtsnd_vi_consts.vc_suspend == pci_vtsnd_suspend);
	ATF_CHECK(vtsnd_vi_consts.vc_resume_device ==
	    pci_vtsnd_resume_device);
#ifdef BHYVE_SNAPSHOT
	ATF_CHECK(vtsnd_vi_consts.vc_pause == pci_vtsnd_pause);
	ATF_CHECK(vtsnd_vi_consts.vc_resume == pci_vtsnd_resume);
#else
	ATF_CHECK(vtsnd_vi_consts.vc_pause == vi_pci_lifecycle_noop);
	ATF_CHECK(vtsnd_vi_consts.vc_resume == vi_pci_lifecycle_noop);
#endif
	setup_softc(&sc);
	ATF_REQUIRE_EQ(pci_vtsnd_cfgread(&sc, 4, 4, &value), 0);
	ATF_CHECK_EQ(value, 2);
	ATF_REQUIRE_EQ(pci_vtsnd_cfgread(&sc, 0, 4, &value), 0);
	ATF_CHECK_EQ(value, 0);
	ATF_CHECK_EQ(pci_vtsnd_cfgread(&sc, 15, 2, &value), EINVAL);
	ATF_CHECK_EQ(pci_vtsnd_cfgread(&sc, 0, 3, &value), EINVAL);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(playback_queue_drives_backend_and_completion);
ATF_TC_BODY(playback_queue_drives_backend_and_completion, tc)
{
	struct pci_vtsnd_softc sc;

	reset_mocks();
	setup_softc(&sc);
	configure_playback(&sc);
	le32enc(g_readable, 0);
	memset(g_readable + 4, 0x33, 1024);
	g_readable_count = 2;
	g_writable_count = 2;
	g_chain_n = 4;
	g_readable_size = 4 + 1024;
	g_writable_size = 8;
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_TXQ]);
	ATF_CHECK_EQ(sc.vssc_playback_bytes, 1024);
	ATF_CHECK_EQ(g_descs, 0);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len, VIRTIO14_SND_PCM_STATUS_SIZE);
	ATF_CHECK_EQ(le32dec(g_writable), VIRTIO14_SND_S_OK);
	start_stream(&sc, 0);
	reset_mocks();
	le32enc(g_readable, 0);
	memset(g_readable + 4, 0x33, 1024);
	g_readable_size = 4 + 1024;
	g_writable_size = 8;
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_TXQ]);
	ATF_CHECK_EQ(sc.vssc_playback_bytes, 2048);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len, VIRTIO14_SND_PCM_STATUS_SIZE);
	ATF_CHECK_EQ(le32dec(g_writable), VIRTIO14_SND_S_OK);
	ATF_CHECK_EQ(g_needs_reset, 0);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(control_transitions_order_pending_data);
ATF_TC_BODY(control_transitions_order_pending_data, tc)
{
	struct pci_vtsnd_softc sc;
	uint8_t control[8], playback[4 + 1024];

	reset_mocks();
	setup_softc(&sc);
	configure_playback(&sc);
	g_use_vqs = true;

	/*
	 * Output prebuffering is a normative PREPARE-to-START lifecycle step.
	 * A TX kick must therefore complete before START rather than relying
	 * on a later control transition to revisit the queue.
	 */
	memset(playback, 0x33, sizeof(playback));
	le32enc(playback, 0);
	mock_vq_set(VTSND_TXQ, playback, sizeof(playback),
	    VIRTIO14_SND_PCM_STATUS_SIZE);
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_TXQ]);
	ATF_CHECK_EQ(g_vqs[VTSND_TXQ].descs, 0);
	ATF_REQUIRE_EQ(g_completion_count, 1);
	ATF_CHECK_EQ(g_completion_order[0], VTSND_TXQ);
	ATF_CHECK_EQ(le32dec(g_vqs[VTSND_TXQ].writable),
	    VIRTIO14_SND_S_OK);
	ATF_CHECK_EQ(sc.vssc_playback_bytes, 1024);

	g_completion_count = 0;
	memset(control, 0, sizeof(control));
	le32enc(control, VIRTIO14_SND_R_PCM_START);
	mock_vq_set(VTSND_CONTROLQ, control, sizeof(control),
	    VIRTIO14_SND_STATUS_SIZE);
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_CONTROLQ]);
	ATF_REQUIRE_EQ(g_completion_count, 1);
	ATF_CHECK_EQ(g_completion_order[0], VTSND_CONTROLQ);
	ATF_CHECK_EQ(le32dec(g_vqs[VTSND_CONTROLQ].writable),
	    VIRTIO14_SND_S_OK);
	ATF_CHECK_EQ(sc.vssc_playback_bytes, 1024);

	/*
	 * RELEASE has the inverse lifecycle obligation: every outstanding
	 * data request is returned before the RELEASE response.  A stopped
	 * null-backend stream returns the queued request with IO_ERR.
	 */
	stop_stream(&sc, 0);
	mock_vq_set(VTSND_TXQ, playback, sizeof(playback),
	    VIRTIO14_SND_PCM_STATUS_SIZE);
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_TXQ]);
	ATF_CHECK_EQ(g_vqs[VTSND_TXQ].descs, 1);
	g_completion_count = 0;
	memset(control, 0, sizeof(control));
	le32enc(control, VIRTIO14_SND_R_PCM_RELEASE);
	mock_vq_set(VTSND_CONTROLQ, control, sizeof(control),
	    VIRTIO14_SND_STATUS_SIZE);
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_CONTROLQ]);
	ATF_REQUIRE_EQ(g_completion_count, 2);
	ATF_CHECK_EQ(g_completion_order[0], VTSND_TXQ);
	ATF_CHECK_EQ(g_completion_order[1], VTSND_CONTROLQ);
	ATF_CHECK_EQ(le32dec(g_vqs[VTSND_TXQ].writable),
	    VIRTIO14_SND_S_IO_ERR);
	ATF_CHECK_EQ(le32dec(g_vqs[VTSND_CONTROLQ].writable),
	    VIRTIO14_SND_S_OK);
	ATF_CHECK_EQ(sc.vssc_playback_bytes, 1024);
	ATF_CHECK_EQ(g_needs_reset, 0);
	ATF_CHECK(!g_release_observed_pending);

	/*
	 * Exercise the Linux capture shape independently: RX buffers are
	 * populated before START and must be filled only after the control
	 * transition becomes visible.
	 */
	configure_capture(&sc);
	memset(playback, 0, sizeof(playback));
	le32enc(playback, 1);
	mock_vq_set(VTSND_RXQ, playback, VIRTIO14_SND_PCM_XFER_SIZE,
	    1024 + VIRTIO14_SND_PCM_STATUS_SIZE);
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_RXQ]);
	ATF_CHECK_EQ(g_vqs[VTSND_RXQ].descs, 1);
	g_completion_count = 0;
	memset(control, 0, sizeof(control));
	le32enc(control, VIRTIO14_SND_R_PCM_START);
	le32enc(control + 4, 1);
	mock_vq_set(VTSND_CONTROLQ, control, sizeof(control),
	    VIRTIO14_SND_STATUS_SIZE);
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_CONTROLQ]);
	ATF_REQUIRE_EQ(g_completion_count, 2);
	ATF_CHECK_EQ(g_completion_order[0], VTSND_RXQ);
	ATF_CHECK_EQ(g_completion_order[1], VTSND_CONTROLQ);
	for (size_t i = 0; i < 1024; i++)
		ATF_CHECK_EQ(g_vqs[VTSND_RXQ].writable[i], 0);
	ATF_CHECK_EQ(le32dec(g_vqs[VTSND_RXQ].writable + 1024),
	    VIRTIO14_SND_S_OK);
	ATF_CHECK_EQ(sc.vssc_capture_bytes, 1024);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(capture_backend_error_completes_request_without_reset);
ATF_TC_BODY(capture_backend_error_completes_request_without_reset, tc)
{
	struct pci_vtsnd_softc sc;
	uint8_t xfer[VIRTIO14_SND_PCM_XFER_SIZE];

	reset_mocks();
	setup_softc(&sc);
	sc.vssc_backend = VTSND_BACKEND_KIND_OSS;
	sc.vssc_audio[1] = (struct audio *)(uintptr_t)2;
	sc.vssc_progress = pci_vtsnd_oss_progress;
	sc.vssc_progress_arg = &sc;
	configure_capture(&sc);
	start_stream(&sc, 1);
	g_use_vqs = true;

	/*
	 * A capture backend I/O error is a per-request failure: the RX
	 * request must be returned with S_IO_ERR, a zeroed payload, and
	 * the full used length, without escalating to NEEDS_RESET.
	 */
	g_audio_result = -1;
	g_audio_errno = EIO;
	memset(xfer, 0, sizeof(xfer));
	le32enc(xfer, 1);
	mock_vq_set(VTSND_RXQ, xfer, sizeof(xfer),
	    1024 + VIRTIO14_SND_PCM_STATUS_SIZE);
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_RXQ]);
	ATF_CHECK_EQ(g_vqs[VTSND_RXQ].descs, 0);
	ATF_REQUIRE_EQ(g_completion_count, 1);
	ATF_CHECK_EQ(g_completion_order[0], VTSND_RXQ);
	ATF_CHECK_EQ(g_completion_len[0],
	    1024 + VIRTIO14_SND_PCM_STATUS_SIZE);
	for (size_t i = 0; i < 1024; i++)
		ATF_CHECK_EQ(g_vqs[VTSND_RXQ].writable[i], 0);
	ATF_CHECK_EQ(le32dec(g_vqs[VTSND_RXQ].writable + 1024),
	    VIRTIO14_SND_S_IO_ERR);
	ATF_CHECK_EQ(g_needs_reset, 0);

	/*
	 * The stream must remain usable: once the backend recovers, a
	 * subsequent request on the same stream completes with S_OK.
	 */
	g_audio_result = 1024;
	g_audio_errno = 0;
	g_completion_count = 0;
	mock_vq_set(VTSND_RXQ, xfer, sizeof(xfer),
	    1024 + VIRTIO14_SND_PCM_STATUS_SIZE);
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_RXQ]);
	ATF_REQUIRE_EQ(g_completion_count, 1);
	ATF_CHECK_EQ(g_completion_len[0],
	    1024 + VIRTIO14_SND_PCM_STATUS_SIZE);
	for (size_t i = 0; i < 1024; i++)
		ATF_CHECK_EQ(g_vqs[VTSND_RXQ].writable[i], 0x5a);
	ATF_CHECK_EQ(le32dec(g_vqs[VTSND_RXQ].writable + 1024),
	    VIRTIO14_SND_S_OK);
	ATF_CHECK_EQ(g_needs_reset, 0);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(retained_io_release_and_queue_reset_are_generation_safe);
ATF_TC_BODY(retained_io_release_and_queue_reset_are_generation_safe, tc)
{
	struct pci_vtsnd_softc sc;
	struct pci_vtsnd_pending *pending;
	uint8_t control[8], playback[4 + 1024];
	uint8_t state[BHYVE_VTSND_STATE_SIZE];
	bool async_pending;
	size_t remaining;

	reset_mocks();
	setup_softc(&sc);
	configure_playback(&sc);
	sc.vssc_progress = stalling_progress;
	sc.vssc_progress_arg = NULL;
	sc.vssc_audio_event[0] = (struct mevent *)(uintptr_t)1;
	g_use_vqs = true;
	memset(playback, 0x42, sizeof(playback));
	le32enc(playback, 0);
	mock_vq_set(VTSND_TXQ, playback, sizeof(playback),
	    VIRTIO14_SND_PCM_STATUS_SIZE);
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_TXQ]);
	pending = &sc.vssc_pending[0];
	ATF_CHECK(pending->active);
	ATF_CHECK(pending->req.outstanding);
	ATF_CHECK_EQ(g_mevent_enable_calls, 1);
	ATF_CHECK_EQ(g_completion_count, 0);
	ATF_REQUIRE_EQ(virtio_snd_async_pending(sc.vssc_async, 0,
	    &async_pending, &remaining), 0);
	ATF_CHECK(async_pending);
	ATF_CHECK_EQ(remaining, 1024);
	ATF_CHECK_EQ(virtio_snd_host_state_encode(sc.vssc_host, state,
	    sizeof(state)), EBUSY);
	ATF_CHECK_EQ(pci_vtsnd_suspend(&sc), EBUSY);

	/*
	 * RELEASE cancels the retained request first.  Its IO_ERR completion
	 * must be visible before the successful control completion and before
	 * the backend release callback observes the stream.
	 */
	memset(control, 0, sizeof(control));
	le32enc(control, VIRTIO14_SND_R_PCM_RELEASE);
	mock_vq_set(VTSND_CONTROLQ, control, sizeof(control),
	    VIRTIO14_SND_STATUS_SIZE);
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_CONTROLQ]);
	ATF_REQUIRE_EQ(g_completion_count, 2);
	ATF_CHECK_EQ(g_completion_order[0], VTSND_TXQ);
	ATF_CHECK_EQ(g_completion_order[1], VTSND_CONTROLQ);
	ATF_CHECK_EQ(le32dec(g_vqs[VTSND_TXQ].writable),
	    VIRTIO14_SND_S_IO_ERR);
	ATF_CHECK_EQ(le32dec(g_vqs[VTSND_CONTROLQ].writable),
	    VIRTIO14_SND_S_OK);
	ATF_CHECK(!pending->active);
	ATF_CHECK(!g_release_observed_pending);
	ATF_CHECK_EQ(g_mevent_disable_calls, 1);

	/*
	 * RELEASE must also retire an output request which was available but
	 * not yet admitted when the control command arrived.  The stalling
	 * backend makes drain_data() retain that request; the control response
	 * must follow its IO_ERR completion and the release callback must see no
	 * outstanding descriptor or asynchronous owner.
	 */
	configure_playback(&sc);
	g_completion_count = 0;
	mock_vq_set(VTSND_TXQ, playback, sizeof(playback),
	    VIRTIO14_SND_PCM_STATUS_SIZE);
	memset(control, 0, sizeof(control));
	le32enc(control, VIRTIO14_SND_R_PCM_RELEASE);
	mock_vq_set(VTSND_CONTROLQ, control, sizeof(control),
	    VIRTIO14_SND_STATUS_SIZE);
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_CONTROLQ]);
	ATF_REQUIRE_EQ(g_completion_count, 2);
	ATF_CHECK_EQ(g_completion_order[0], VTSND_TXQ);
	ATF_CHECK_EQ(g_completion_order[1], VTSND_CONTROLQ);
	ATF_CHECK_EQ(le32dec(g_vqs[VTSND_TXQ].writable),
	    VIRTIO14_SND_S_IO_ERR);
	ATF_CHECK_EQ(le32dec(g_vqs[VTSND_CONTROLQ].writable),
	    VIRTIO14_SND_S_OK);
	ATF_CHECK(!pending->active);
	ATF_CHECK(!g_release_observed_pending);
	ATF_REQUIRE_EQ(virtio_snd_async_pending(sc.vssc_async, 0,
	    &async_pending, &remaining), 0);
	ATF_CHECK(!async_pending);

	/*
	 * A selective queue reset has already advanced the generation.  Its
	 * cancellation retires ownership without writing a status or used
	 * entry into the old queue incarnation.
	 */
	configure_playback(&sc);
	g_completion_count = 0;
	mock_vq_set(VTSND_TXQ, playback, sizeof(playback),
	    VIRTIO14_SND_PCM_STATUS_SIZE);
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_TXQ]);
	ATF_REQUIRE(pending->active);
	sc.vssc_vq[VTSND_TXQ].vq_generation++;
	ATF_REQUIRE_EQ(pci_vtsnd_qreset(&sc,
	    &sc.vssc_vq[VTSND_TXQ],
	    sc.vssc_vq[VTSND_TXQ].vq_generation), 0);
	ATF_CHECK(!pending->active);
	ATF_CHECK_EQ(g_mevent_disable_calls, 4);
	ATF_CHECK_EQ(g_completion_count, 0);
	ATF_CHECK_EQ(g_needs_reset, 0);

	/*
	 * Full device reset uses the same owner cancellation but suppresses
	 * publication even before the common core advances every generation.
	 */
	mock_vq_set(VTSND_TXQ, playback, sizeof(playback),
	    VIRTIO14_SND_PCM_STATUS_SIZE);
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_TXQ]);
	ATF_REQUIRE(pending->active);
	g_completion_count = 0;
	pci_vtsnd_reset(&sc);
	ATF_CHECK(!pending->active);
	ATF_CHECK_EQ(g_mevent_disable_calls, 6);
	ATF_CHECK_EQ(g_completion_count, 0);
	ATF_CHECK_EQ(g_needs_reset, 0);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(retained_capture_is_private_until_readiness_completion);
ATF_TC_BODY(retained_capture_is_private_until_readiness_completion, tc)
{
	struct pci_vtsnd_softc sc;
	struct pci_vtsnd_pending *pending;
	uint8_t request[VIRTIO14_SND_PCM_XFER_SIZE];
	uint64_t generation;

	reset_mocks();
	setup_softc(&sc);
	configure_capture(&sc);
	start_stream(&sc, 1);
	sc.vssc_progress = stalling_progress;
	sc.vssc_progress_arg = NULL;
	g_use_vqs = true;
	le32enc(request, 1);
	mock_vq_set(VTSND_RXQ, request, sizeof(request),
	    1024 + VIRTIO14_SND_PCM_STATUS_SIZE);
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_RXQ]);
	pending = &sc.vssc_pending[1];
	ATF_REQUIRE(pending->active);
	generation = pending->claim.generation;
	ATF_CHECK_EQ(g_completion_count, 0);
	for (size_t i = 0; i < 1024 + VIRTIO14_SND_PCM_STATUS_SIZE; i++)
		ATF_CHECK_EQ(g_vqs[VTSND_RXQ].writable[i], 0xa5);

	/*
	 * A host-readiness callback advances the retained private capture
	 * buffer.  Guest memory and the used ring become visible together only
	 * after the complete payload exists.
	 */
	sc.vssc_progress = pci_vtsnd_null_progress;
	sc.vssc_progress_arg = &sc;
	ATF_REQUIRE_EQ(pci_vtsnd_backend_ready(&sc, 1), 0);
	ATF_CHECK(!pending->active);
	ATF_REQUIRE_EQ(g_completion_count, 1);
	ATF_CHECK_EQ(g_completion_order[0], VTSND_RXQ);
	ATF_CHECK_EQ(g_completion_len[0],
	    1024 + VIRTIO14_SND_PCM_STATUS_SIZE);
	for (size_t i = 0; i < 1024; i++)
		ATF_CHECK_EQ(g_vqs[VTSND_RXQ].writable[i], 0);
	ATF_CHECK_EQ(le32dec(g_vqs[VTSND_RXQ].writable + 1024),
	    VIRTIO14_SND_S_OK);
	ATF_CHECK_EQ(pci_vtsnd_backend_ready(&sc, 1), ENOENT);
	ATF_CHECK_EQ(virtio_snd_async_progress(sc.vssc_async, 1,
	    generation), ENOENT);
	ATF_CHECK_EQ(sc.vssc_capture_bytes, 1024);

	ATF_REQUIRE_EQ(virtio_snd_host_reset(sc.vssc_host), 0);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(readiness_completion_disables_source_once);
ATF_TC_BODY(readiness_completion_disables_source_once, tc)
{
	struct pci_vtsnd_softc sc;
	uint8_t playback[VIRTIO14_SND_PCM_XFER_SIZE + 1024];

	reset_mocks();
	setup_softc(&sc);
	configure_playback(&sc);
	sc.vssc_progress = stalling_progress;
	sc.vssc_progress_arg = NULL;
	sc.vssc_audio_event[0] = (struct mevent *)(uintptr_t)1;
	g_use_vqs = true;
	memset(playback, 0x42, sizeof(playback));
	le32enc(playback, 0);
	mock_vq_set(VTSND_TXQ, playback, sizeof(playback),
	    VIRTIO14_SND_PCM_STATUS_SIZE);
	/* The second descriptor is already available under the same guest kick. */
	g_vqs[VTSND_TXQ].descs = 2;
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_TXQ]);
	ATF_REQUIRE(sc.vssc_pending[0].active);
	ATF_CHECK_EQ(g_vqs[VTSND_TXQ].descs, 1);
	ATF_REQUIRE_EQ(g_mevent_enable_calls, 1);

	/*
	 * Model the event thread observing backend readiness.  Each completion
	 * owns its serialized disable.  A disable after backend_ready() drops
	 * vssc_mtx would race a replacement job enabling the same event.
	 */
	sc.vssc_progress = pci_vtsnd_null_progress;
	sc.vssc_progress_arg = &sc;
	pci_vtsnd_audio_event(3, EVF_WRITE, &sc.vssc_pending[0]);
	ATF_CHECK(!sc.vssc_pending[0].active);
	ATF_CHECK_EQ(g_vqs[VTSND_TXQ].descs, 0);
	ATF_CHECK_EQ(g_completion_count, 2);
	ATF_CHECK_EQ(g_completion_order[0], VTSND_TXQ);
	ATF_CHECK_EQ(g_completion_order[1], VTSND_TXQ);
	ATF_CHECK_EQ(g_mevent_disable_calls, 2);

	/* A stale readiness delivery is retired once under the device lock. */
	pci_vtsnd_audio_event(3, EVF_WRITE, &sc.vssc_pending[0]);
	ATF_CHECK_EQ(g_mevent_disable_calls, 3);
	ATF_REQUIRE_EQ(virtio_snd_host_reset(sc.vssc_host), 0);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(portable_state_binds_backend_identity);
ATF_TC_BODY(portable_state_binds_backend_identity, tc)
{
	struct pci_vtsnd_softc sc;
	uint8_t state[PCI_VTSND_STATE_SIZE];

	reset_mocks();
	setup_softc(&sc);
	sc.vssc_backend = VTSND_BACKEND_KIND_NULL;
	configure_playback(&sc);
	ATF_REQUIRE_EQ(pci_vtsnd_state_encode(&sc, state), 0);
	ATF_CHECK_EQ(le32dec(state), PCI_VTSND_STATE_MAGIC);
	ATF_CHECK_EQ(le16dec(state + 4), PCI_VTSND_STATE_VERSION);
	ATF_CHECK_EQ(le16dec(state + 6), PCI_VTSND_STATE_HEADER_SIZE);
	ATF_CHECK_EQ(le32dec(state + 8), VTSND_BACKEND_KIND_NULL);
	ATF_CHECK_EQ(pci_vtsnd_state_validate(&sc, state, sizeof(state)), 0);
	ATF_CHECK_EQ(pci_vtsnd_state_restore(&sc, state, sizeof(state)), 0);

	sc.vssc_backend = (enum pci_vtsnd_backend)1;
	ATF_CHECK_EQ(pci_vtsnd_state_validate(&sc, state, sizeof(state)),
	    ENOTSUP);
	sc.vssc_backend = VTSND_BACKEND_KIND_NULL;

	le32enc(state + 8, UINT32_MAX);
	ATF_CHECK_EQ(pci_vtsnd_state_validate(&sc, state, sizeof(state)),
	    EINVAL);
	le32enc(state + 8, VTSND_BACKEND_KIND_NULL);
	state[12] = 1;
	ATF_CHECK_EQ(pci_vtsnd_state_validate(&sc, state, sizeof(state)),
	    EINVAL);
	state[12] = 0;
	ATF_CHECK_EQ(pci_vtsnd_state_validate(&sc, state,
	    sizeof(state) - 1), EINVAL);
	ATF_CHECK_EQ(pci_vtsnd_state_validate(&sc, NULL, sizeof(state)),
	    EINVAL);

	sc.vssc_backend = VTSND_BACKEND_KIND_OSS;
	strlcpy(sc.vssc_play_path, "/dev/dsp-play",
	    sizeof(sc.vssc_play_path));
	strlcpy(sc.vssc_record_path, "/dev/dsp-record",
	    sizeof(sc.vssc_record_path));
	ATF_REQUIRE_EQ(pci_vtsnd_state_encode(&sc, state), 0);
	ATF_CHECK_EQ(le32dec(state + 8), VTSND_BACKEND_KIND_OSS);
	ATF_CHECK_STREQ((const char *)state + 16, "/dev/dsp-play");
	ATF_CHECK_STREQ((const char *)state + 80, "/dev/dsp-record");
	ATF_CHECK_EQ(pci_vtsnd_state_validate(&sc, state, sizeof(state)), 0);
	strlcpy(sc.vssc_record_path, "/dev/dsp-different",
	    sizeof(sc.vssc_record_path));
	ATF_CHECK_EQ(pci_vtsnd_state_validate(&sc, state, sizeof(state)),
	    ENOTSUP);
	strlcpy(sc.vssc_record_path, "/dev/dsp-record",
	    sizeof(sc.vssc_record_path));
	state[16 + strlen("/dev/dsp-play") + 1] = 1;
	ATF_CHECK_EQ(pci_vtsnd_state_validate(&sc, state, sizeof(state)),
	    EINVAL);
	teardown_softc(&sc);
}

#ifdef BHYVE_SNAPSHOT
ATF_TC_WITHOUT_HEAD(snapshot_callback_preserves_validation_and_restore_rules);
ATF_TC_BODY(snapshot_callback_preserves_validation_and_restore_rules, tc)
{
	struct pci_vtsnd_softc source, destination;
	uint8_t before[PCI_VTSND_STATE_SIZE];
	uint8_t after[PCI_VTSND_STATE_SIZE];
	uint8_t image[PCI_VTSND_STATE_SIZE];
	uint8_t damaged[PCI_VTSND_STATE_SIZE];
	size_t used;

	reset_mocks();
	setup_softc(&source);
	setup_softc(&destination);
	source.vssc_backend = VTSND_BACKEND_KIND_NULL;
	destination.vssc_backend = VTSND_BACKEND_KIND_NULL;
	ATF_REQUIRE_EQ(pci_vtsnd_state_encode(&destination, before), 0);

	/* The callback transfers only the fixed portable sound state. */
	ATF_REQUIRE_EQ(run_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	ATF_CHECK_EQ(used, PCI_VTSND_STATE_SIZE);
	ATF_CHECK_EQ(le32dec(image), PCI_VTSND_STATE_MAGIC);
	ATF_CHECK_EQ(le16dec(image + 4), PCI_VTSND_STATE_VERSION);

	/* Validate accepts the image without mutating the destination backend. */
	ATF_REQUIRE_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), 0);
	ATF_REQUIRE_EQ(pci_vtsnd_state_encode(&destination, after), 0);
	ATF_CHECK_EQ(memcmp(before, after, sizeof(before)), 0);

	/* A rejected wire image similarly cannot publish a backend change. */
	memcpy(damaged, image, used);
	damaged[0] ^= 1;
	ATF_CHECK_EQ(run_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_VALIDATE, NULL), EINVAL);
	ATF_REQUIRE_EQ(pci_vtsnd_state_encode(&destination, after), 0);
	ATF_CHECK_EQ(memcmp(before, after, sizeof(before)), 0);

	ATF_REQUIRE_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK(!destination.vssc_vs.vs_restore_incomplete);
	teardown_softc(&destination);
	teardown_softc(&source);
}

ATF_TC_WITHOUT_HEAD(snapshot_preflight_is_locally_serialized);
ATF_TC_BODY(snapshot_preflight_is_locally_serialized, tc)
{
	struct pci_devinst pi;
	struct pci_vtsnd_softc sc;
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf_start = NULL,
			.buf_size = 0,
		},
	};

	reset_mocks();
	setup_softc(&sc);
	memset(&pi, 0, sizeof(pi));
	pi.pi_arg = &sc;
	meta.dev_data = &pi;
	meta.op = VM_SNAPSHOT_VALIDATE;
	g_snapshot_validate_result = E2BIG;

	/* Direct preflight acquires and releases the local codec lock. */
	ATF_CHECK_EQ(pci_vtsnd_snapshot_validate(&meta), E2BIG);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 1);
	ATF_CHECK(g_snapshot_validate_saw_lock);
	ATF_CHECK(!pthread_mutex_isowned_np(&sc.vssc_mtx));

	/* Commit-time pause owns the non-recursive mutex already. */
	ATF_REQUIRE_EQ(pci_vtsnd_pause(&sc), 0);
	g_snapshot_validate_result = 0;
	g_snapshot_validate_saw_lock = false;
	ATF_CHECK_EQ(pci_vtsnd_snapshot_validate(&meta), 0);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 2);
	ATF_CHECK(g_snapshot_validate_saw_lock);
	ATF_CHECK(pthread_mutex_isowned_np(&sc.vssc_mtx));
	ATF_REQUIRE_EQ(pci_vtsnd_resume(&sc), 0);

	teardown_softc(&sc);
}
#endif

ATF_TC_WITHOUT_HEAD(oss_progress_is_nonblocking_and_accounts_partial_io);
ATF_TC_BODY(oss_progress_is_nonblocking_and_accounts_partial_io, tc)
{
	struct pci_vtsnd_softc sc;
	struct virtio_snd_host_params params;
	uint8_t buffer[64];
	size_t progress;

	reset_mocks();
	setup_softc(&sc);
	sc.vssc_backend = VTSND_BACKEND_KIND_OSS;
	sc.vssc_audio[0] = (struct audio *)(uintptr_t)1;
	sc.vssc_audio[1] = (struct audio *)(uintptr_t)2;
	params = (struct virtio_snd_host_params){
		.channels = 2,
		.format = BHYVE_VTSND_FMT_S16,
		.rate = BHYVE_VTSND_RATE_48000,
	};
	ATF_CHECK_EQ(pci_vtsnd_set_params(&sc, 0, &params), 0);
	params.rate = BHYVE_VTSND_RATE_44100;
	ATF_CHECK_EQ(pci_vtsnd_set_params(&sc, 1, &params), 0);
	params.rate = UINT8_MAX;
	ATF_CHECK_EQ(pci_vtsnd_set_params(&sc, 0, &params), EINVAL);
	params.rate = BHYVE_VTSND_RATE_48000;
	g_audio_set_params_result = -1;
	ATF_CHECK_EQ(pci_vtsnd_set_params(&sc, 0, &params), EIO);
	g_audio_set_params_result = 0;

	g_audio_result = 17;
	g_audio_errno = 0;
	ATF_CHECK_EQ(pci_vtsnd_oss_progress(&sc,
	    BHYVE_VTSND_ASYNC_PLAYBACK, buffer, sizeof(buffer), &progress), 0);
	ATF_CHECK_EQ(progress, 17);
	ATF_CHECK_EQ(sc.vssc_playback_bytes, 17);

	g_audio_result = 23;
	ATF_CHECK_EQ(pci_vtsnd_oss_progress(&sc,
	    BHYVE_VTSND_ASYNC_CAPTURE, buffer, sizeof(buffer), &progress), 0);
	ATF_CHECK_EQ(progress, 23);
	ATF_CHECK_EQ(sc.vssc_capture_bytes, 23);
	for (size_t i = 0; i < progress; i++)
		ATF_CHECK_EQ(buffer[i], 0x5a);

	g_audio_result = -1;
	g_audio_errno = EAGAIN;
	ATF_CHECK_EQ(pci_vtsnd_oss_progress(&sc,
	    BHYVE_VTSND_ASYNC_PLAYBACK, buffer, sizeof(buffer), &progress),
	    EAGAIN);
	ATF_CHECK_EQ(progress, 0);
	ATF_CHECK_EQ(sc.vssc_playback_bytes, 17);

	g_audio_errno = EIO;
	ATF_CHECK_EQ(pci_vtsnd_oss_progress(&sc,
	    BHYVE_VTSND_ASYNC_CAPTURE, buffer, sizeof(buffer), &progress), EIO);
	ATF_CHECK_EQ(progress, 0);
	ATF_CHECK_EQ(sc.vssc_capture_bytes, 23);

	g_audio_result = 0;
	g_audio_errno = 0;
	ATF_CHECK_EQ(pci_vtsnd_oss_progress(&sc,
	    BHYVE_VTSND_ASYNC_PLAYBACK, buffer, sizeof(buffer), &progress), EIO);
	g_audio_result = (ssize_t)sizeof(buffer) + 1;
	ATF_CHECK_EQ(pci_vtsnd_oss_progress(&sc,
	    BHYVE_VTSND_ASYNC_PLAYBACK, buffer, sizeof(buffer), &progress), EIO);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(release_failure_withholds_successful_control_response);
ATF_TC_BODY(release_failure_withholds_successful_control_response, tc)
{
	struct pci_vtsnd_softc sc;
	uint8_t control[8], playback[4 + 1024];

	reset_mocks();
	setup_softc(&sc);
	configure_playback(&sc);
	start_stream(&sc, 0);
	stop_stream(&sc, 0);
	g_use_vqs = true;

	memset(playback, 0x33, sizeof(playback));
	le32enc(playback, 0);
	mock_vq_set(VTSND_TXQ, playback, sizeof(playback),
	    VIRTIO14_SND_PCM_STATUS_SIZE);
	g_vqs[VTSND_TXQ].ordered = false;

	memset(control, 0, sizeof(control));
	le32enc(control, VIRTIO14_SND_R_PCM_RELEASE);
	mock_vq_set(VTSND_CONTROLQ, control, sizeof(control),
	    VIRTIO14_SND_STATUS_SIZE);
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_CONTROLQ]);

	ATF_REQUIRE_EQ(g_completion_count, 2);
	ATF_CHECK_EQ(g_completion_order[0], VTSND_TXQ);
	ATF_CHECK_EQ(g_completion_len[0], 0);
	ATF_CHECK_EQ(g_completion_order[1], VTSND_CONTROLQ);
	ATF_CHECK_EQ(g_completion_len[1], 0);
	ATF_CHECK_EQ(g_needs_reset, 1);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(control_and_capture_queues_use_standard_roles);
ATF_TC_BODY(control_and_capture_queues_use_standard_roles, tc)
{
	struct pci_vtsnd_softc sc;
	uint8_t request[24], response[4];
	size_t used;

	reset_mocks();
	setup_softc(&sc);
	memset(g_readable, 0, 16);
	le32enc(g_readable, VIRTIO14_SND_R_PCM_INFO);
	le32enc(g_readable + 8, 2);
	le32enc(g_readable + 12, VIRTIO14_SND_PCM_INFO_SIZE);
	g_readable_size = 16;
	g_writable_size = VIRTIO14_SND_STATUS_SIZE +
	    2 * VIRTIO14_SND_PCM_INFO_SIZE;
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_CONTROLQ]);
	ATF_CHECK_EQ(g_rel_len, g_writable_size);
	ATF_CHECK_EQ(le32dec(g_writable), VIRTIO14_SND_S_OK);
	ATF_CHECK_EQ(g_writable[28], VIRTIO14_SND_D_OUTPUT);
	ATF_CHECK_EQ(g_writable[60], VIRTIO14_SND_D_INPUT);

	memset(request, 0, sizeof(request));
	le32enc(request, VIRTIO14_SND_R_PCM_SET_PARAMS);
	le32enc(request + 4, 1);
	le32enc(request + 8, 4096);
	le32enc(request + 12, 1024);
	request[20] = 2;
	request[21] = VIRTIO14_SND_PCM_FMT_S16;
	request[22] = VIRTIO14_SND_PCM_RATE_48000;
	ATF_REQUIRE_EQ(virtio_snd_host_control(sc.vssc_host, request,
	    sizeof(request), response, sizeof(response), &used), 0);
	ATF_REQUIRE_EQ(le32dec(response), VIRTIO14_SND_S_OK);
	memset(request, 0, 8);
	le32enc(request, VIRTIO14_SND_R_PCM_PREPARE);
	le32enc(request + 4, 1);
	ATF_REQUIRE_EQ(virtio_snd_host_control(sc.vssc_host, request, 8,
	    response, sizeof(response), &used), 0);
	le32enc(request, VIRTIO14_SND_R_PCM_START);
	ATF_REQUIRE_EQ(virtio_snd_host_control(sc.vssc_host, request, 8,
	    response, sizeof(response), &used), 0);

	reset_mocks();
	le32enc(g_readable, 1);
	g_readable_size = VIRTIO14_SND_PCM_XFER_SIZE;
	g_writable_size = 1024 + VIRTIO14_SND_PCM_STATUS_SIZE;
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_RXQ]);
	ATF_CHECK_EQ(sc.vssc_capture_bytes, 1024);
	ATF_CHECK_EQ(g_rel_len, g_writable_size);
	for (size_t i = 0; i < 1024; i++)
		ATF_CHECK_EQ(g_writable[i], 0);
	ATF_CHECK_EQ(le32dec(g_writable + 1024), VIRTIO14_SND_S_OK);
	ATF_CHECK_EQ(le32dec(g_writable + 1028), 0);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(malformed_and_event_queue_behavior);
ATF_TC_BODY(malformed_and_event_queue_behavior, tc)
{
	struct pci_vtsnd_softc sc;

	reset_mocks();
	setup_softc(&sc);
	g_ordered = false;
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_CONTROLQ]);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len, 0);
	ATF_CHECK_EQ(g_needs_reset, 1);
	reset_mocks();
	g_chain_n = -1;
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_CONTROLQ]);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(g_needs_reset, 1);
	reset_mocks();
	configure_playback(&sc);
	start_stream(&sc, 0);
	g_chain_n = -1;
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_TXQ]);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(g_needs_reset, 1);
	reset_mocks();
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_EVENTQ]);
	ATF_CHECK_EQ(g_descs, 1);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(g_needs_reset, 0);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(queue_notify_preserves_transport_mutex_ownership);
ATF_TC_BODY(queue_notify_preserves_transport_mutex_ownership, tc)
{
	struct pci_vtsnd_softc sc;

	/*
	 * vi_pci_modern_write() invokes vc_notify while it owns vs_mtx.  Sound
	 * aliases that lock to vssc_mtx; recursively taking it deadlocks the vCPU
	 * on the first guest kick.  Exercise the real callback ownership contract.
	 */
	reset_mocks();
	setup_softc(&sc);
	sc.vssc_vs.vs_mtx = &sc.vssc_mtx;
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vssc_mtx), 0);
	ATF_REQUIRE(pthread_mutex_isowned_np(&sc.vssc_mtx));
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_EVENTQ]);
	ATF_CHECK(pthread_mutex_isowned_np(&sc.vssc_mtx));
	ATF_CHECK_EQ(g_descs, 1);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(g_end_calls, 1);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vssc_mtx), 0);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(reset_backend_failure_requests_driver_reset);
ATF_TC_BODY(reset_backend_failure_requests_driver_reset, tc)
{
	struct pci_vtsnd_softc sc;
	enum virtio_snd_host_stream_state state;

	reset_mocks();
	setup_softc_release_failure(&sc);
	configure_playback(&sc);
	g_release_error = EIO;
	pci_vtsnd_reset(&sc);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK(sc.vssc_vs.vs_restore_incomplete);
	ATF_REQUIRE_EQ(virtio_snd_host_stream_get(sc.vssc_host, 0, &state,
	    NULL), 0);
	ATF_CHECK_EQ(state, BHYVE_VTSND_PREPARED);
	g_release_error = 0;
	ATF_CHECK_EQ(virtio_snd_host_reset(sc.vssc_host), 0);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(audio_event_cleanup_acknowledges_callbacks);
ATF_TC_BODY(audio_event_cleanup_acknowledges_callbacks, tc)
{
	struct pci_vtsnd_softc sc;

	memset(&sc, 0, sizeof(sc));
	reset_mocks();
	sc.vssc_audio_event[0] = (struct mevent *)(uintptr_t)1;
	sc.vssc_audio_event[1] = (struct mevent *)(uintptr_t)2;
	pci_vtsnd_delete_audio_events(&sc);
	ATF_CHECK_EQ(g_mevent_delete_sync_calls, 2);
	ATF_CHECK(sc.vssc_audio_event[0] == NULL);
	ATF_CHECK(sc.vssc_audio_event[1] == NULL);

	/* Repeated partial-init cleanup is idempotent. */
	pci_vtsnd_delete_audio_events(&sc);
	ATF_CHECK_EQ(g_mevent_delete_sync_calls, 2);
}

#ifdef BHYVE_SNAPSHOT
ATF_TC_WITHOUT_HEAD(checkpoint_resume_error_is_retry_safe);
ATF_TC_BODY(checkpoint_resume_error_is_retry_safe, tc)
{
	struct pci_vtsnd_softc sc;

	/*
	 * The normal pause protocol makes this state unreachable, but resume's
	 * defensive EBUSY path must still release its private pause lock.  The
	 * common checkpoint layer retains ownership after a callback error and
	 * retries resume; exercising that retry catches an unlock of an unheld
	 * mutex without relying on a timing race.
	 */
	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE_EQ(pci_vtsnd_pause(&sc), 0);
	ATF_REQUIRE(pthread_mutex_isowned_np(&sc.vssc_mtx));
	sc.vssc_async->jobs[0].active = true;
	ATF_CHECK_EQ(pci_vtsnd_resume(&sc), EBUSY);
	ATF_CHECK(!pthread_mutex_isowned_np(&sc.vssc_mtx));
	memset(&sc.vssc_async->jobs[0], 0,
	    sizeof(sc.vssc_async->jobs[0]));
	ATF_REQUIRE_EQ(pci_vtsnd_pause(&sc), 0);
	ATF_CHECK_EQ(pci_vtsnd_resume(&sc), 0);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(checkpoint_restore_retains_guest_suspend_admission_fence);
ATF_TC_BODY(checkpoint_restore_retains_guest_suspend_admission_fence, tc)
{
	struct pci_vtsnd_softc sc;

	/*
	 * A source image may have been guest-suspended before checkpoint.  The
	 * checkpoint callback owns vssc_mtx transiently, but must not undo that
	 * independently-owned asynchronous admission fence as it releases the
	 * checkpoint ownership after restore.
	 */
	reset_mocks();
	setup_softc(&sc);
	sc.vssc_vs.vs_suspended = true;
	ATF_REQUIRE_EQ(pci_vtsnd_pause(&sc), 0);
	ATF_REQUIRE(pthread_mutex_isowned_np(&sc.vssc_mtx));
	ATF_REQUIRE(sc.vssc_async->quiescing);
	ATF_CHECK_EQ(pci_vtsnd_resume(&sc), 0);
	ATF_CHECK(!pthread_mutex_isowned_np(&sc.vssc_mtx));
	ATF_CHECK(sc.vssc_async->quiescing);

	/* Guest resume, rather than checkpoint resume, reopens admission. */
	ATF_CHECK_EQ(pci_vtsnd_resume_device(&sc), 0);
	ATF_CHECK(!sc.vssc_async->quiescing);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(guest_suspend_preserves_transport_mutex_ownership);
ATF_TC_BODY(guest_suspend_preserves_transport_mutex_ownership, tc)
{
	struct pci_vtsnd_softc sc;

	/*
	 * vi_modern_suspend() runs from a status write while vs_mtx is held.
	 * Sound aliases that mutex to vssc_mtx.  The device hook must close async
	 * admission without recursively taking, or releasing, transport ownership.
	 */
	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vssc_mtx), 0);
	ATF_REQUIRE(pthread_mutex_isowned_np(&sc.vssc_mtx));
	ATF_CHECK_EQ(pci_vtsnd_suspend(&sc), 0);
	ATF_CHECK(pthread_mutex_isowned_np(&sc.vssc_mtx));
	ATF_CHECK(sc.vssc_async->quiescing);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vssc_mtx), 0);
	ATF_CHECK_EQ(pci_vtsnd_resume_device(&sc), 0);
	ATF_CHECK(!sc.vssc_async->quiescing);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(guest_reset_preserves_transport_mutex_ownership);
ATF_TC_BODY(guest_reset_preserves_transport_mutex_ownership, tc)
{
	struct pci_vtsnd_softc sc;

	/*
	 * vi_modern_status_write() likewise calls vc_reset while it owns vs_mtx.
	 * Confirm that sound does not recursively acquire, or accidentally
	 * release, its aliased transport mutex during the complete reset path.
	 */
	reset_mocks();
	setup_softc(&sc);
	sc.vssc_vs.vs_mtx = &sc.vssc_mtx;
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vssc_mtx), 0);
	ATF_REQUIRE(pthread_mutex_isowned_np(&sc.vssc_mtx));
	pci_vtsnd_reset(&sc);
	ATF_CHECK(pthread_mutex_isowned_np(&sc.vssc_mtx));
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vssc_mtx), 0);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(queue_reset_preserves_transport_mutex_ownership);
ATF_TC_BODY(queue_reset_preserves_transport_mutex_ownership, tc)
{
	struct pci_vtsnd_softc sc;

	/* Queue-reset common-capability writes invoke vc_qreset under vs_mtx. */
	reset_mocks();
	setup_softc(&sc);
	sc.vssc_vs.vs_mtx = &sc.vssc_mtx;
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vssc_mtx), 0);
	ATF_REQUIRE(pthread_mutex_isowned_np(&sc.vssc_mtx));
	ATF_CHECK_EQ(pci_vtsnd_qreset(&sc, &sc.vssc_vq[VTSND_TXQ], 1), 0);
	ATF_CHECK(pthread_mutex_isowned_np(&sc.vssc_mtx));
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vssc_mtx), 0);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(checkpoint_restore_runnable_reopens_prior_suspend_fence);
ATF_TC_BODY(checkpoint_restore_runnable_reopens_prior_suspend_fence, tc)
{
	struct pci_vtsnd_softc sc;

	/*
	 * Conversely, checkpoint pause may have borrowed a destination's old guest
	 * suspend while the incoming common snapshot is runnable.  Once restore
	 * commits that state, the checkpoint callback must release the old fence;
	 * otherwise the device looks runnable to VirtIO while every PCM submission
	 * remains permanently rejected by the asynchronous owner.
	 */
	reset_mocks();
	setup_softc(&sc);
	sc.vssc_vs.vs_suspended = true;
	ATF_REQUIRE_EQ(pci_vtsnd_pause(&sc), 0);
	ATF_REQUIRE(sc.vssc_async->quiescing);

	/* The common snapshot has committed a runnable source image. */
	sc.vssc_vs.vs_suspended = false;
	ATF_CHECK_EQ(pci_vtsnd_resume(&sc), 0);
	ATF_CHECK(!sc.vssc_async->quiescing);
	teardown_softc(&sc);
}
#endif

static void
cleanup_after_init(struct pci_vtsnd_softc *sc)
{

	pci_vtsnd_delete_audio_events(sc);
	for (uint32_t stream_id = 0;
	    stream_id < nitems(sc->vssc_audio_event); stream_id++)
		audio_destroy(sc->vssc_audio[stream_id]);
	if (sc->vssc_async != NULL)
		(void)virtio_snd_async_destroy(sc->vssc_async);
	virtio_snd_host_destroy(sc->vssc_host);
	free(sc->vssc_vs.vs_modern);
	pthread_mutex_destroy(&sc->vssc_vs.vs_isr_mtx);
	pthread_mutex_destroy(&sc->vssc_mtx);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(device_init_admits_and_rejects_configurations);
ATF_TC_BODY(device_init_admits_and_rejects_configurations, tc)
{
	struct pci_devinst pi;
	struct pci_vtsnd_softc *sc;

	/*
	 * A default (null-backend) device admits and links up the modern
	 * transport, publishing the multimedia/audio PCI class identity.
	 */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	ATF_REQUIRE_EQ(pci_vtsnd_init(&pi, NULL), 0);
	sc = pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(sc->vssc_backend, VTSND_BACKEND_KIND_NULL);
	ATF_CHECK_EQ(g_modern_set_identity_calls, 1);
	ATF_CHECK_EQ(g_modern_set_identity_id, VIRTIO_ID_SOUND);
	ATF_CHECK_EQ(pci_get_cfgdata8(&pi, PCIR_CLASS), PCIC_MULTIMEDIA);
	ATF_CHECK_EQ(pci_get_cfgdata8(&pi, PCIR_SUBCLASS),
	    PCIS_MULTIMEDIA_AUDIO);
	ATF_CHECK_EQ(sc->vssc_progress, pci_vtsnd_null_progress);
	cleanup_after_init(sc);

	/* An explicit null backend with a packed-ring request is honoured. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_backend = "null";
	g_cfg_packed = true;
	ATF_REQUIRE_EQ(pci_vtsnd_init(&pi, NULL), 0);
	sc = pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK((sc->vssc_consts.vc_hv_caps & VIRTIO_F_RING_PACKED) != 0);
	cleanup_after_init(sc);

	/* An OSS backend opens both paths and installs the OSS progress hook. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_backend = "oss";
	g_cfg_play = "/dev/dsp0";
	g_cfg_record = "/dev/dsp1";
	ATF_REQUIRE_EQ(pci_vtsnd_init(&pi, NULL), 0);
	sc = pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(sc->vssc_backend, VTSND_BACKEND_KIND_OSS);
	ATF_CHECK_STREQ(sc->vssc_play_path, "/dev/dsp0");
	ATF_CHECK_STREQ(sc->vssc_record_path, "/dev/dsp1");
	ATF_CHECK_EQ(sc->vssc_progress, pci_vtsnd_oss_progress);
	cleanup_after_init(sc);

	/* OSS with defaulted paths falls back to /dev/dsp for both streams. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_backend = "oss";
	ATF_REQUIRE_EQ(pci_vtsnd_init(&pi, NULL), 0);
	sc = pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_STREQ(sc->vssc_play_path, "/dev/dsp");
	ATF_CHECK_STREQ(sc->vssc_record_path, "/dev/dsp");
	cleanup_after_init(sc);

	/* An unknown backend name is rejected before any allocation. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_backend = "pulse";
	ATF_CHECK_EQ(pci_vtsnd_init(&pi, NULL), 1);
	ATF_CHECK(pi.pi_arg == NULL);

	/* play/record are meaningful only for the OSS backend. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_play = "/dev/dsp0";
	ATF_CHECK_EQ(pci_vtsnd_init(&pi, NULL), 1);
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_record = "/dev/dsp1";
	ATF_CHECK_EQ(pci_vtsnd_init(&pi, NULL), 1);

	/* An over-long OSS path is rejected. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_backend = "oss";
	static char long_path[512];
	memset(long_path, 'a', sizeof(long_path) - 1);
	g_cfg_play = long_path;
	ATF_CHECK_EQ(pci_vtsnd_init(&pi, NULL), 1);

	/* Transport, interrupt and modern-init failures each unwind cleanly. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_select_transport_result = EINVAL;
	ATF_CHECK_EQ(pci_vtsnd_init(&pi, NULL), 1);
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_intr_init_result = ENXIO;
	ATF_CHECK_EQ(pci_vtsnd_init(&pi, NULL), 1);
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_modern_init_result = ENXIO;
	ATF_CHECK_EQ(pci_vtsnd_init(&pi, NULL), 1);

	/* An OSS backend which cannot open its dsp nodes unwinds. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_backend = "oss";
	g_audio_init_fail = true;
	ATF_CHECK_EQ(pci_vtsnd_init(&pi, NULL), 1);
	g_audio_init_fail = false;

	/* An OSS backend which cannot register readiness events unwinds. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_backend = "oss";
	g_mevent_add_fail = true;
	ATF_CHECK_EQ(pci_vtsnd_init(&pi, NULL), 1);
	g_mevent_add_fail = false;

	/* A numeric BHYVE_VIRTIO_DEBUG selects the diagnostic verbosity. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	ATF_REQUIRE_EQ(setenv("BHYVE_VIRTIO_DEBUG", "3", 1), 0);
	ATF_REQUIRE_EQ(pci_vtsnd_init(&pi, NULL), 0);
	sc = pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(sc->vssc_debug, 3u);
	cleanup_after_init(sc);

	/* A non-numeric value leaves the verbosity at its default. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	ATF_REQUIRE_EQ(setenv("BHYVE_VIRTIO_DEBUG", "loud", 1), 0);
	ATF_REQUIRE_EQ(pci_vtsnd_init(&pi, NULL), 0);
	sc = pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(sc->vssc_debug, 0u);
	cleanup_after_init(sc);
	ATF_REQUIRE_EQ(unsetenv("BHYVE_VIRTIO_DEBUG"), 0);
}

ATF_TC_WITHOUT_HEAD(diagnostic_and_defensive_edges);
ATF_TC_BODY(diagnostic_and_defensive_edges, tc)
{
	struct pci_vtsnd_softc sc;
	struct virtio_snd_host_params params;
	struct pci_vtsnd_pending fake_pending;
	struct vqueue_info *one_past;
	uint8_t buffer[64];
	uint8_t state[PCI_VTSND_STATE_SIZE];
	size_t progress;

	reset_mocks();
	setup_softc(&sc);

	/* Verbose accounting emits playback and capture diagnostics. */
	sc.vssc_debug = 2;
	ATF_CHECK_EQ(pci_vtsnd_playback(&sc, 0, buffer, 10), 0);
	ATF_CHECK_EQ(pci_vtsnd_capture(&sc, 1, buffer, 8), 0);
	ATF_CHECK_EQ(sc.vssc_playback_bytes, 10);
	ATF_CHECK_EQ(sc.vssc_capture_bytes, 8);

	/* Verbose release logs the running byte totals. */
	sc.vssc_debug = 1;
	ATF_CHECK_EQ(pci_vtsnd_release(&sc, 0), 0);
	sc.vssc_debug = 0;

	/* set_params rejects a non-S16 format on an open OSS stream. */
	sc.vssc_backend = VTSND_BACKEND_KIND_OSS;
	sc.vssc_audio[0] = (struct audio *)(uintptr_t)1;
	params = (struct virtio_snd_host_params){
		.channels = 2,
		.format = 0xff,
		.rate = BHYVE_VTSND_RATE_48000,
	};
	ATF_CHECK_EQ(pci_vtsnd_set_params(&sc, 0, &params), EINVAL);

	/* null and OSS progress reject an unknown transfer direction. */
	ATF_CHECK_EQ(pci_vtsnd_null_progress(&sc,
	    (enum virtio_snd_async_direction)99, buffer, sizeof(buffer),
	    &progress), EINVAL);
	ATF_CHECK_EQ(pci_vtsnd_oss_progress(&sc,
	    (enum virtio_snd_async_direction)99, buffer, sizeof(buffer),
	    &progress), EINVAL);
	/* OSS progress reports ENXIO when the stream device is absent. */
	sc.vssc_audio[0] = NULL;
	ATF_CHECK_EQ(pci_vtsnd_oss_progress(&sc, BHYVE_VTSND_ASYNC_PLAYBACK,
	    buffer, sizeof(buffer), &progress), ENXIO);
	sc.vssc_backend = VTSND_BACKEND_KIND_NULL;

	/* async_progress surfaces ENXIO when no backend hook is installed. */
	sc.vssc_progress = NULL;
	ATF_CHECK_EQ(pci_vtsnd_async_progress(&sc, BHYVE_VTSND_ASYNC_PLAYBACK,
	    buffer, sizeof(buffer), &progress), ENXIO);
	ATF_CHECK_EQ(progress, 0);
	sc.vssc_progress = pci_vtsnd_null_progress;
	sc.vssc_progress_arg = &sc;

	/* backend_ready validates its stream id and honours the reset fence. */
	ATF_CHECK_EQ(pci_vtsnd_backend_ready(&sc, 99), EINVAL);
	ATF_CHECK_EQ(pci_vtsnd_backend_ready(NULL, 0), EINVAL);
	sc.vssc_resetting = true;
	ATF_CHECK_EQ(pci_vtsnd_backend_ready(&sc, 0), EBUSY);
	sc.vssc_resetting = false;

	/* cancel_pending rejects an out-of-range stream id. */
	ATF_CHECK_EQ(pci_vtsnd_cancel_pending(&sc, 99), EINVAL);

	/* audio_event ignores a foreign pending and a mismatched event type. */
	memset(&fake_pending, 0, sizeof(fake_pending));
	fake_pending.sc = &sc;
	pci_vtsnd_audio_event(3, EVF_WRITE, &fake_pending);
	pci_vtsnd_audio_event(3, EVF_READ, &sc.vssc_pending[0]);
	pci_vtsnd_audio_event(3, EVF_WRITE, &sc.vssc_pending[1]);
	ATF_CHECK_EQ(g_completion_count, 0);

	/* async_complete latches NEEDS_RESET on an unowned token. */
	pci_vtsnd_async_complete(&sc, (uintptr_t)&fake_pending,
	    BHYVE_VTSND_ASYNC_OK, NULL, 0);
	ATF_CHECK(g_needs_reset > 0);
	g_needs_reset = 0;

	/* qreset ignores control/event queues and rejects a foreign vq. */
	ATF_CHECK_EQ(pci_vtsnd_qreset(&sc, &sc.vssc_vq[VTSND_CONTROLQ], 0), 0);
	one_past = sc.vssc_vq + VTSND_NVQ;
	ATF_CHECK_EQ(pci_vtsnd_qreset(&sc, one_past, 0), EINVAL);

	/* The data paths reject a non-stream queue with NEEDS_RESET. */
	g_needs_reset = 0;
	ATF_CHECK(!pci_vtsnd_drain_data(&sc, &sc.vssc_vq[VTSND_CONTROLQ]));
	ATF_CHECK(!pci_vtsnd_fail_data(&sc, &sc.vssc_vq[VTSND_CONTROLQ]));
	ATF_CHECK_EQ(g_needs_reset, 2);
	g_needs_reset = 0;

	/* A direct guest SUSPEND with no retained work takes and drops vssc_mtx. */
	ATF_CHECK_EQ(pci_vtsnd_suspend(&sc), 0);
	ATF_CHECK(!pthread_mutex_isowned_np(&sc.vssc_mtx));
	ATF_CHECK(sc.vssc_async->quiescing);
	ATF_CHECK_EQ(pci_vtsnd_resume_device(&sc), 0);
	ATF_CHECK(!sc.vssc_async->quiescing);

	/* state_restore forwards a validation failure. */
	memset(state, 0, sizeof(state));
	ATF_CHECK_EQ(pci_vtsnd_state_restore(&sc, state, sizeof(state) - 1),
	    EINVAL);

	/* A null-backend image with a non-empty path field is rejected. */
	le32enc(state, PCI_VTSND_STATE_MAGIC);
	le16enc(state + 4, PCI_VTSND_STATE_VERSION);
	le16enc(state + 6, PCI_VTSND_STATE_HEADER_SIZE);
	le32enc(state + 8, VTSND_BACKEND_KIND_NULL);
	state[16] = 1;
	ATF_CHECK_EQ(pci_vtsnd_state_validate(&sc, state, sizeof(state)),
	    EINVAL);

	/* An OSS image whose path field never terminates is rejected. */
	memset(state, 0, sizeof(state));
	le32enc(state, PCI_VTSND_STATE_MAGIC);
	le16enc(state + 4, PCI_VTSND_STATE_VERSION);
	le16enc(state + 6, PCI_VTSND_STATE_HEADER_SIZE);
	le32enc(state + 8, VTSND_BACKEND_KIND_OSS);
	memset(state + 16, 'x', 64);
	ATF_CHECK_EQ(pci_vtsnd_state_validate(&sc, state, sizeof(state)),
	    EINVAL);

#ifdef BHYVE_SNAPSHOT
	/* snapshot_validate rejects a missing meta or an unbound instance. */
	ATF_CHECK_EQ(pci_vtsnd_snapshot_validate(NULL), EINVAL);
	{
		struct pci_devinst pi2;
		struct vm_snapshot_meta m = {
			.op = VM_SNAPSHOT_VALIDATE,
			.dev_data = &pi2,
		};

		memset(&pi2, 0, sizeof(pi2));
		pi2.pi_arg = NULL;
		ATF_CHECK_EQ(pci_vtsnd_snapshot_validate(&m), EINVAL);
	}
#endif
	teardown_softc(&sc);

	/*
	 * A retained request makes portable-state capture unavailable: the host
	 * codec refuses to serialize live stream ownership.
	 */
	{
		struct pci_vtsnd_softc s2;
		uint8_t st[PCI_VTSND_STATE_SIZE];
		uint8_t playback[4 + 1024];

		reset_mocks();
		setup_softc(&s2);
		s2.vssc_backend = VTSND_BACKEND_KIND_NULL;
		configure_playback(&s2);
		s2.vssc_progress = stalling_progress;
		s2.vssc_progress_arg = NULL;
		g_use_vqs = true;
		memset(playback, 0x42, sizeof(playback));
		le32enc(playback, 0);
		mock_vq_set(VTSND_TXQ, playback, sizeof(playback),
		    VIRTIO14_SND_PCM_STATUS_SIZE);
		pci_vtsnd_notify(&s2, &s2.vssc_vq[VTSND_TXQ]);
		ATF_REQUIRE(s2.vssc_pending[0].active);
		ATF_CHECK_EQ(pci_vtsnd_state_encode(&s2, st), EBUSY);
#ifdef BHYVE_SNAPSHOT
		{
			uint8_t img[PCI_VTSND_STATE_SIZE];
			struct vm_snapshot_meta m = {
				.buffer = {
					.buf = img,
					.buf_rem = sizeof(img),
				},
				.op = VM_SNAPSHOT_SAVE,
			};

			ATF_CHECK_EQ(pci_vtsnd_snapshot(&s2, &m), EBUSY);
		}
#endif
		pci_vtsnd_reset(&s2);
		g_use_vqs = false;
		teardown_softc(&s2);
	}
}

ATF_TC_WITHOUT_HEAD(data_path_error_and_retain_failures);
ATF_TC_BODY(data_path_error_and_retain_failures, tc)
{
	struct pci_vtsnd_softc sc;
	struct vqueue_info *one_past;
	uint8_t playback[4 + 1024];

	/* notify rejects an out-of-range queue index with NEEDS_RESET. */
	reset_mocks();
	setup_softc(&sc);
	one_past = sc.vssc_vq + VTSND_NVQ;
	pci_vtsnd_notify(&sc, one_past);
	ATF_CHECK_EQ(g_needs_reset, 1);
	teardown_softc(&sc);

	/*
	 * A running output stream that drains a malformed descriptor chain
	 * (no writable status segment) latches NEEDS_RESET and returns the
	 * chain with a zero used length.
	 */
	reset_mocks();
	setup_softc(&sc);
	configure_playback(&sc);
	start_stream(&sc, 0);
	g_use_vqs = true;
	memset(playback, 0x33, sizeof(playback));
	le32enc(playback, 0);
	mock_vq_set(VTSND_TXQ, playback, sizeof(playback),
	    VIRTIO14_SND_PCM_STATUS_SIZE);
	g_vqs[VTSND_TXQ].writable_count = 0;
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_TXQ]);
	ATF_CHECK(g_needs_reset > 0);
	ATF_CHECK_EQ(g_rel_len, 0);
	g_use_vqs = false;
	pci_vtsnd_reset(&sc);
	teardown_softc(&sc);

	/*
	 * When a nonblocking backend retains an output request but its
	 * readiness source cannot be enabled, drain_data() cancels the retained
	 * request and latches NEEDS_RESET rather than leaking the descriptor.
	 */
	reset_mocks();
	setup_softc(&sc);
	configure_playback(&sc);
	sc.vssc_progress = stalling_progress;
	sc.vssc_progress_arg = NULL;
	sc.vssc_audio_event[0] = (struct mevent *)(uintptr_t)1;
	g_mevent_enable_fail = true;
	g_use_vqs = true;
	memset(playback, 0x42, sizeof(playback));
	le32enc(playback, 0);
	mock_vq_set(VTSND_TXQ, playback, sizeof(playback),
	    VIRTIO14_SND_PCM_STATUS_SIZE);
	pci_vtsnd_notify(&sc, &sc.vssc_vq[VTSND_TXQ]);
	ATF_CHECK_EQ(g_mevent_enable_calls, 1);
	ATF_CHECK(g_needs_reset > 0);
	g_mevent_enable_fail = false;
	g_use_vqs = false;
	pci_vtsnd_reset(&sc);
	teardown_softc(&sc);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, composition_and_config);
	ATF_TP_ADD_TC(tp, device_init_admits_and_rejects_configurations);
	ATF_TP_ADD_TC(tp, diagnostic_and_defensive_edges);
	ATF_TP_ADD_TC(tp, data_path_error_and_retain_failures);
	ATF_TP_ADD_TC(tp, playback_queue_drives_backend_and_completion);
	ATF_TP_ADD_TC(tp, control_transitions_order_pending_data);
	ATF_TP_ADD_TC(tp,
	    capture_backend_error_completes_request_without_reset);
	ATF_TP_ADD_TC(tp,
	    retained_io_release_and_queue_reset_are_generation_safe);
	ATF_TP_ADD_TC(tp,
	    retained_capture_is_private_until_readiness_completion);
	ATF_TP_ADD_TC(tp, readiness_completion_disables_source_once);
	ATF_TP_ADD_TC(tp, portable_state_binds_backend_identity);
#ifdef BHYVE_SNAPSHOT
	ATF_TP_ADD_TC(tp,
	    snapshot_callback_preserves_validation_and_restore_rules);
	ATF_TP_ADD_TC(tp, snapshot_preflight_is_locally_serialized);
	ATF_TP_ADD_TC(tp, checkpoint_resume_error_is_retry_safe);
	ATF_TP_ADD_TC(tp,
	    checkpoint_restore_retains_guest_suspend_admission_fence);
	ATF_TP_ADD_TC(tp,
	    guest_suspend_preserves_transport_mutex_ownership);
	ATF_TP_ADD_TC(tp,
	    guest_reset_preserves_transport_mutex_ownership);
	ATF_TP_ADD_TC(tp,
	    queue_reset_preserves_transport_mutex_ownership);
	ATF_TP_ADD_TC(tp,
	    checkpoint_restore_runnable_reopens_prior_suspend_fence);
#endif
	ATF_TP_ADD_TC(tp,
	    oss_progress_is_nonblocking_and_accounts_partial_io);
	ATF_TP_ADD_TC(tp,
	    release_failure_withholds_successful_control_response);
	ATF_TP_ADD_TC(tp, control_and_capture_queues_use_standard_roles);
	ATF_TP_ADD_TC(tp, malformed_and_event_queue_behavior);
	ATF_TP_ADD_TC(tp, queue_notify_preserves_transport_mutex_ownership);
	ATF_TP_ADD_TC(tp, reset_backend_failure_requests_driver_reset);
	ATF_TP_ADD_TC(tp, audio_event_cleanup_acknowledges_callbacks);
	return (atf_no_error());
}
