/* Device-level tests for bhyve's VirtIO 1.4 RTC device. */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <atf-c.h>

#include "virtio_rtc_alarm.c"
#include "virtio_rtc_host.c"

/*
 * Fault-injection wrappers for allocation and object construction inside
 * pci_virtio_rtc.c only.  They are defined before the redirecting macros
 * below so their bodies still resolve to the genuine libc/library symbols;
 * the wrapped virtio_rtc_alarm.c above therefore keeps its real calloc and
 * mutex, letting pci_vtrtc_init's own early-failure paths be exercised in
 * isolation.
 */
static bool g_calloc_fail;
static bool g_mtxinit_fail;
static bool g_alarm_create_fail;

static void *
vtrtc_test_calloc(size_t nmemb, size_t size)
{

	if (g_calloc_fail)
		return (NULL);
	return (calloc(nmemb, size));
}

static int
vtrtc_test_mutex_init(pthread_mutex_t *mtx, const pthread_mutexattr_t *attr)
{

	if (g_mtxinit_fail)
		return (EAGAIN);
	return (pthread_mutex_init(mtx, attr));
}

static int
vtrtc_test_alarm_create(struct virtio_rtc_alarm **result)
{

	if (g_alarm_create_fail)
		return (ENOMEM);
	return (virtio_rtc_alarm_create(result));
}

struct mevent;
int vtrtc_test_timerfd_create(int, int);
int vtrtc_test_timerfd_settime(int, int, const struct itimerspec *,
    struct itimerspec *);
ssize_t vtrtc_test_read(int, void *, size_t);
int vtrtc_test_close(int);
int vtrtc_test_clock_gettime(clockid_t, struct timespec *);
int vtrtc_test_mevent_delete_close_sync(struct mevent *);
#define	timerfd_create	vtrtc_test_timerfd_create
#define	timerfd_settime	vtrtc_test_timerfd_settime
#define	read		vtrtc_test_read
#define	close		vtrtc_test_close
#define	clock_gettime	vtrtc_test_clock_gettime
#define	mevent_add	vtrtc_test_mevent_add
#define	mevent_delete_close_sync vtrtc_test_mevent_delete_close_sync
#define	calloc		vtrtc_test_calloc
#define	pthread_mutex_init vtrtc_test_mutex_init
#define	virtio_rtc_alarm_create vtrtc_test_alarm_create
#define	BHYVE_SNAPSHOT
#include "pci_virtio_rtc.c"
#include "virtio_1_4_spec.h"

enum {
	DUT_RTC_DEVICE_ID = VIRTIO_ID_CLOCK,
};
static const uint64_t dut_rtc_hv_caps =
    VIRTIO_F_RING_RESET | VIRTIO_F_SUSPEND;

/* Keep expectations independent from the included implementation. */
#undef VIRTIO_ID_CLOCK
#define	VIRTIO_ID_CLOCK		VIRTIO14_RTC_DEVICE_ID
#undef VIRTIO_F_IN_ORDER
#define	VIRTIO_F_IN_ORDER	VIRTIO14_F_IN_ORDER
#undef VIRTIO_F_RING_PACKED
#define	VIRTIO_F_RING_PACKED	VIRTIO14_F_RING_PACKED
#undef VIRTIO_F_RING_RESET
#define	VIRTIO_F_RING_RESET	VIRTIO14_F_RING_RESET
#undef VIRTIO_F_SUSPEND
#define	VIRTIO_F_SUSPEND	VIRTIO14_F_SUSPEND
#undef VIRTIO_CONFIG_S_NEEDS_RESET
#define	VIRTIO_CONFIG_S_NEEDS_RESET VIRTIO14_STATUS_DEVICE_NEEDS_RESET

struct nvlist { int unused; };

static uint8_t g_request[64], g_response[64];
static size_t g_request_len, g_response_len;
static int g_descs, g_chain_n, g_readable, g_writable;
static bool g_ordered, g_fragmented, g_config_alarm, g_config_packed;
static int g_rel_calls, g_end_calls, g_needs_reset, g_reset_calls;
static int g_end_all;
static uint32_t g_rel_len;
static uint16_t g_identity;
static struct itimerspec g_timer_value;
static bool g_timer_created;
static int g_timer_error, g_timer_set_calls, g_timer_flags;
static int g_timer_error_at;
static int g_timer_read_error;
static timerfd_t g_timer_expirations;
static void (*g_timer_callback)(int, enum ev_type, void *);
static void *g_timer_callback_arg;
static uint64_t g_clock_ns, g_clock_verify_ns;
static bool g_clock_verify_valid;
static unsigned int g_clock_reads;
static int g_clock_fault, g_clock_verify_fault;
static bool g_clock_raw;
static time_t g_clock_raw_sec;
static long g_clock_raw_nsec;
static bool g_timer_short_read;
static bool g_alarm_relaxed;
static bool g_transport_fail, g_intr_fail, g_modern_fail;
static bool g_timerfd_create_fail, g_mevent_fail;

static void
reset_mocks(void)
{

	memset(g_request, 0, sizeof(g_request));
	memset(g_response, 0xa5, sizeof(g_response));
	g_request_len = VIRTIO14_RTC_REQ_CFG_SIZE;
	g_response_len = VIRTIO14_RTC_RESP_CFG_SIZE;
	g_descs = 1;
	g_chain_n = 2;
	g_readable = 1;
	g_writable = 1;
	g_ordered = true;
	g_fragmented = false;
	g_config_packed = false;
	g_config_alarm = false;
	g_rel_calls = 0;
	g_end_calls = 0;
	g_end_all = -1;
	g_needs_reset = 0;
	g_reset_calls = 0;
	g_rel_len = UINT32_MAX;
	g_identity = 0;
	memset(&g_timer_value, 0, sizeof(g_timer_value));
	g_timer_error = 0;
	g_timer_error_at = 0;
	g_timer_set_calls = 0;
	g_timer_flags = 0;
	g_timer_read_error = 0;
	g_timer_expirations = 1;
	g_timer_callback = NULL;
	g_timer_callback_arg = NULL;
	g_clock_ns = 0;
	g_clock_verify_ns = 0;
	g_clock_verify_valid = false;
	g_clock_reads = 0;
	g_clock_fault = 0;
	g_clock_verify_fault = 0;
	g_clock_raw = false;
	g_clock_raw_sec = 0;
	g_clock_raw_nsec = 0;
	g_timer_short_read = false;
	g_alarm_relaxed = false;
	g_transport_fail = false;
	g_intr_fail = false;
	g_modern_fail = false;
	g_timerfd_create_fail = false;
	g_mevent_fail = false;
	g_calloc_fail = false;
	g_mtxinit_fail = false;
	g_alarm_create_fail = false;
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
vm_snapshot_le32(uint32_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[4];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		le32enc(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = le32dec(bytes);
	return (error);
}

static int
run_snapshot(struct pci_vtrtc_softc *sc, void *buffer, size_t size,
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

	error = pci_vtrtc_snapshot(sc, &meta);
	if (used != NULL)
		*used = size - meta.buffer.buf_rem;
	return (error);
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
	ATF_REQUIRE(niov == VTRTC_MAXSEGS);
	ATF_REQUIRE(g_chain_n <= niov);
	memset(req, 0, sizeof(*req));
	req->idx = 9;
	req->readable = g_readable;
	req->writable = g_writable;
	req->ordered = g_ordered;
	if (vq->vq_num == VTRTC_ALARMQ) {
		if (g_alarm_relaxed) {
			/* Model a malformed alarm chain shape for validation. */
			for (int i = 0; i < g_chain_n; i++) {
				iov[i].iov_base = g_response;
				iov[i].iov_len = g_response_len;
			}
			g_descs--;
			return (g_chain_n);
		}
		ATF_REQUIRE(g_chain_n == 1);
		ATF_REQUIRE(g_readable == 0);
		ATF_REQUIRE(g_writable == 1);
		iov[0].iov_base = g_response;
		iov[0].iov_len = g_response_len;
		g_descs--;
		return (g_chain_n);
	}
	if (g_fragmented) {
		ATF_REQUIRE(g_chain_n == 4);
		ATF_REQUIRE(g_readable == 2);
		ATF_REQUIRE(g_writable == 2);
		iov[0].iov_base = g_request;
		iov[0].iov_len = 3;
		iov[1].iov_base = g_request + 3;
		iov[1].iov_len = g_request_len - 3;
		iov[2].iov_base = g_response;
		iov[2].iov_len = 7;
		iov[3].iov_base = g_response + 7;
		iov[3].iov_len = g_response_len - 7;
	} else {
		iov[0].iov_base = g_request;
		iov[0].iov_len = g_request_len;
		iov[1].iov_base = g_response;
		iov[1].iov_len = g_response_len;
	}
	g_descs--;
	return (g_chain_n);
}

void
vq_relchain(struct vqueue_info *vq __unused, uint16_t idx, uint32_t len)
{

	ATF_CHECK_EQ(idx, 9);
	g_rel_calls++;
	g_rel_len = len;
}

void
vq_retchains(struct vqueue_info *vq __unused, uint16_t count)
{

	ATF_CHECK_EQ(count, 1);
	g_descs += count;
}

void
vq_endchains(struct vqueue_info *vq __unused, int all_avail)
{

	g_end_all = all_avail;
	g_end_calls++;
}

size_t
count_iov(const struct iovec *iov, size_t niov)
{
	size_t total;

	total = 0;
	for (size_t i = 0; i < niov; i++)
		total += iov[i].iov_len;
	return (total);
}

size_t
buf_to_iov(const void *buffer, size_t len, const struct iovec *iov,
    size_t niov)
{
	const uint8_t *source;
	size_t copied;

	source = buffer;
	copied = 0;
	for (size_t i = 0; i < niov && copied < len; i++) {
		size_t count;

		count = MIN(iov[i].iov_len, len - copied);
		memcpy(iov[i].iov_base, source + copied, count);
		copied += count;
	}
	return (copied);
}

int
vi_pci_lifecycle_noop(void *arg __unused)
{

	return (0);
}

void
vi_reset_dev(struct virtio_softc *vs)
{

	g_reset_calls++;
	vs->vs_status = 0;
	vs->vs_restore_incomplete = false;
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
	vs->vs_status |= VIRTIO_CONFIG_S_NEEDS_RESET;
	g_needs_reset++;
}

bool
get_config_bool_node_default(const nvlist_t *nvl __unused,
    const char *name, bool default_value)
{

	if (strcmp(name, "packed") == 0)
		return (g_config_packed);
	if (strcmp(name, "alarm") == 0)
		return (g_config_alarm);
	return (default_value);
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
vtrtc_test_timerfd_create(int clock_id, int flags)
{

	ATF_CHECK_EQ(clock_id, CLOCK_REALTIME);
	ATF_CHECK_EQ(flags, TFD_CLOEXEC | TFD_NONBLOCK);
	if (g_timerfd_create_fail) {
		errno = EMFILE;
		return (-1);
	}
	g_timer_created = true;
	return (7);
}

int
vtrtc_test_close(int fd)
{

	ATF_CHECK_EQ(fd, 7);
	g_timer_created = false;
	return (0);
}

int
vtrtc_test_timerfd_settime(int fd, int flags,
    const struct itimerspec *value, struct itimerspec *old_value __unused)
{

	ATF_CHECK_EQ(fd, 7);
	g_timer_set_calls++;
	ATF_CHECK(flags == 0 ||
	    flags == (TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET));
	g_timer_flags = flags;
	g_timer_value = *value;
	if (g_timer_error != 0) {
		errno = g_timer_error;
		return (-1);
	}
	if (g_timer_error_at != 0 && g_timer_set_calls == g_timer_error_at) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

int
vtrtc_test_clock_gettime(clockid_t clock_id, struct timespec *value)
{

	ATF_CHECK_EQ(clock_id, CLOCK_REALTIME);
	unsigned int call = g_clock_reads++;
	int fault = call == 0 ? g_clock_fault : g_clock_verify_fault;

	if (fault != 0) {
		errno = fault;
		return (-1);
	}
	if (g_clock_raw) {
		value->tv_sec = g_clock_raw_sec;
		value->tv_nsec = g_clock_raw_nsec;
		return (0);
	}
	uint64_t reading = g_clock_verify_valid && call != 0 ?
	    g_clock_verify_ns : g_clock_ns;

	value->tv_sec = (time_t)(reading / VTRTC_NSEC_PER_SEC);
	value->tv_nsec = (long)(reading % VTRTC_NSEC_PER_SEC);
	return (0);
}

ssize_t
vtrtc_test_read(int fd, void *buffer, size_t length)
{

	ATF_CHECK_EQ(fd, 7);
	ATF_CHECK_EQ(length, sizeof(timerfd_t));
	if (g_timer_read_error != 0) {
		errno = g_timer_read_error;
		return (-1);
	}
	memcpy(buffer, &g_timer_expirations, sizeof(g_timer_expirations));
	if (g_timer_short_read)
		return (sizeof(g_timer_expirations) - 1);
	return (sizeof(g_timer_expirations));
}

struct mevent *
vtrtc_test_mevent_add(int fd, enum ev_type type,
    void (*callback)(int, enum ev_type, void *), void *arg)
{

	ATF_CHECK_EQ(fd, 7);
	ATF_CHECK_EQ(type, EVF_READ);
	if (g_mevent_fail)
		return (NULL);
	g_timer_callback = callback;
	g_timer_callback_arg = arg;
	return ((struct mevent *)(uintptr_t)1);
}

int
vtrtc_test_mevent_delete_close_sync(struct mevent *evp)
{

	ATF_CHECK_EQ(evp, (struct mevent *)(uintptr_t)1);
	g_timer_created = false;
	return (0);
}

int
vi_pci_select_transport(struct virtio_softc *vs,
    const nvlist_t *nvl __unused, enum virtio_pci_transport_policy policy)
{

	ATF_CHECK_EQ(policy, VIRTIO_PCI_MODERN_ONLY);
	if (g_transport_fail)
		return (1);
	vs->vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	return (0);
}

void
vi_pci_modern_set_identity(struct virtio_softc *vs __unused, uint16_t id)
{

	g_identity = id;
}

int
vi_pci_modern_init(struct virtio_softc *vs __unused, int bar __unused)
{

	return (g_modern_fail ? 1 : 0);
}

int
vi_intr_init(struct virtio_softc *vs, int bar __unused,
    int msix __unused)
{

	if (g_intr_fail)
		return (1);
	pthread_mutex_init(&vs->vs_isr_mtx, NULL);
	return (0);
}

int
fbsdrun_virtio_msix(void)
{

	return (1);
}

int
vi_pci_modern_cfgread(struct pci_devinst *pi __unused, int off __unused,
    int size __unused, uint32_t *val __unused)
{

	return (0);
}

int
vi_pci_modern_cfgwrite(struct pci_devinst *pi __unused, int off __unused,
    int size __unused, uint32_t val __unused)
{

	return (0);
}

uint64_t
vi_pci_read(struct pci_devinst *pi __unused, int bar __unused,
    uint64_t off __unused, int size __unused)
{

	return (0);
}

void
vi_pci_write(struct pci_devinst *pi __unused, int bar __unused,
    uint64_t off __unused, int size __unused, uint64_t val __unused)
{
}

void
pci_set_cfgdata8(struct pci_devinst *pi, int off, uint8_t val)
{

	pi->pi_cfgdata[off] = val;
}

ATF_TC_WITHOUT_HEAD(advertised_and_initialization_contract);
ATF_TC_BODY(advertised_and_initialization_contract, tc)
{
	struct pci_vtrtc_softc *sc;
	struct pci_devinst pi;
	struct nvlist nvl;

	ATF_CHECK_EQ(DUT_RTC_DEVICE_ID, VIRTIO_ID_CLOCK);
	ATF_CHECK_EQ(vtrtc_vi_consts.vc_hv_caps, dut_rtc_hv_caps);
	ATF_CHECK_EQ(vtrtc_vi_consts.vc_nvq, 1);
	ATF_CHECK_EQ(vtrtc_vi_consts.vc_cfgsize, 0);

	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	memset(&nvl, 0, sizeof(nvl));
	g_config_packed = true;
	ATF_REQUIRE_EQ(pci_vtrtc_init(&pi, &nvl), 0);
	sc = (struct pci_vtrtc_softc *)pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(g_identity, VIRTIO_ID_CLOCK);
	ATF_CHECK_EQ(sc->vrsc_vs.vs_transport,
	    VIRTIO_PCI_TRANSPORT_MODERN);
	ATF_CHECK((sc->vrsc_consts.vc_hv_caps &
	    VIRTIO_F_RING_PACKED) != 0);
	ATF_CHECK_EQ(sc->vrsc_vq[VTRTC_REQUESTQ].vq_qsize, VTRTC_RINGSZ);
	ATF_CHECK_EQ(sc->vrsc_consts.vc_nvq, 1);
	virtio_rtc_alarm_destroy(sc->vrsc_alarm);
	pthread_mutex_destroy(&sc->vrsc_mtx);
	free(sc);

	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_config_alarm = true;
	ATF_REQUIRE_EQ(pci_vtrtc_init(&pi, &nvl), 0);
	sc = (struct pci_vtrtc_softc *)pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(sc->vrsc_consts.vc_nvq, VTRTC_NVQ);
	ATF_CHECK((sc->vrsc_consts.vc_hv_caps &
	    VIRTIO_RTC_F_ALARM) != 0);
	ATF_CHECK_EQ(sc->vrsc_vq[VTRTC_ALARMQ].vq_qsize, VTRTC_RINGSZ);
	ATF_CHECK_EQ(sc->vrsc_alarm_fd, 7);
	ATF_CHECK(sc->vrsc_alarm_evp != NULL);
	ATF_CHECK(g_timer_created);
	ATF_CHECK(g_timer_callback != NULL);
	ATF_CHECK_EQ(g_timer_callback_arg, sc);
	(void)mevent_delete_close_sync(sc->vrsc_alarm_evp);
	virtio_rtc_alarm_destroy(sc->vrsc_alarm);
	pthread_mutex_destroy(&sc->vrsc_mtx);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(request_queue_and_descriptor_validation);
ATF_TC_BODY(request_queue_and_descriptor_validation, tc)
{
	static const uint8_t expected[VIRTIO14_RTC_RESP_CFG_SIZE] = {
		0, 0, 0, 0, 0, 0, 0, 0,
		1, 0, 0, 0, 0, 0, 0, 0,
	};
	struct pci_vtrtc_softc sc;

	memset(&sc, 0, sizeof(sc));
	sc.vrsc_vs.vs_vc = &sc.vrsc_consts;
	sc.vrsc_vq[VTRTC_REQUESTQ].vq_qsize = VTRTC_RINGSZ;
	reset_mocks();
	g_request[0] = VIRTIO14_RTC_REQ_CFG & 0xff;
	g_request[1] = VIRTIO14_RTC_REQ_CFG >> 8;
	pci_vtrtc_notify(&sc, &sc.vrsc_vq[VTRTC_REQUESTQ]);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len, sizeof(expected));
	ATF_CHECK(memcmp(g_response, expected, sizeof(expected)) == 0);
	ATF_CHECK_EQ(g_end_calls, 1);
	ATF_CHECK_EQ(g_end_all, 1);
	ATF_CHECK_EQ(g_needs_reset, 0);

	/* Extra device-readable space is ignored per section 5.23.6.2. */
	reset_mocks();
	g_request[0] = VIRTIO14_RTC_REQ_CFG & 0xff;
	g_request[1] = VIRTIO14_RTC_REQ_CFG >> 8;
	g_request_len = sizeof(g_request);
	pci_vtrtc_notify(&sc, &sc.vrsc_vq[VTRTC_REQUESTQ]);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len, sizeof(expected));
	ATF_CHECK(memcmp(g_response, expected, sizeof(expected)) == 0);
	ATF_CHECK_EQ(g_needs_reset, 0);

	reset_mocks();
	g_request[0] = VIRTIO14_RTC_REQ_CFG & 0xff;
	g_request[1] = VIRTIO14_RTC_REQ_CFG >> 8;
	g_fragmented = true;
	g_chain_n = 4;
	g_readable = 2;
	g_writable = 2;
	pci_vtrtc_notify(&sc, &sc.vrsc_vq[VTRTC_REQUESTQ]);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len, sizeof(expected));
	ATF_CHECK(memcmp(g_response, expected, sizeof(expected)) == 0);
	ATF_CHECK_EQ(g_needs_reset, 0);

	reset_mocks();
	g_ordered = false;
	pci_vtrtc_notify(&sc, &sc.vrsc_vq[VTRTC_REQUESTQ]);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len, 0);

	reset_mocks();
	g_chain_n = -1;
	pci_vtrtc_notify(&sc, &sc.vrsc_vq[VTRTC_REQUESTQ]);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(g_end_all, 0);
}

ATF_TC_WITHOUT_HEAD(reset_disarm_failure_requests_driver_reset);
ATF_TC_BODY(reset_disarm_failure_requests_driver_reset, tc)
{
	struct pci_vtrtc_softc sc;
	uint8_t state[VTRTC_ALARM_STATE_SIZE];

	memset(&sc, 0, sizeof(sc));
	reset_mocks();
	sc.vrsc_consts = vtrtc_vi_consts;
	sc.vrsc_vs.vs_vc = &sc.vrsc_consts;
	sc.vrsc_alarm_fd = 7;
	ATF_REQUIRE_EQ(virtio_rtc_alarm_create(&sc.vrsc_alarm), 0);
	ATF_REQUIRE_EQ(virtio_rtc_alarm_set(sc.vrsc_alarm, 1234, true, 100),
	    0);
	g_timer_error = EIO;
	pci_vtrtc_reset(&sc);
	ATF_CHECK_EQ(g_timer_set_calls, 1);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(g_reset_calls, 1);
	ATF_CHECK(sc.vrsc_vs.vs_restore_incomplete);
	ATF_CHECK((sc.vrsc_vs.vs_status &
	    VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_REQUIRE_EQ(virtio_rtc_alarm_snapshot(sc.vrsc_alarm, state,
	    sizeof(state)), 0);
	ATF_CHECK_EQ(le64dec(state + 8), 0);
	ATF_CHECK_EQ(state[24], 0);
	virtio_rtc_alarm_destroy(sc.vrsc_alarm);
}

ATF_TC_WITHOUT_HEAD(notification_budget_is_queue_bounded);
ATF_TC_BODY(notification_budget_is_queue_bounded, tc)
{
	struct pci_vtrtc_softc sc;

	memset(&sc, 0, sizeof(sc));
	sc.vrsc_vs.vs_vc = &sc.vrsc_consts;
	sc.vrsc_vq[VTRTC_REQUESTQ].vq_qsize = 2;
	reset_mocks();
	g_descs = 3;
	g_request[0] = VIRTIO14_RTC_REQ_CFG & 0xff;
	g_request[1] = VIRTIO14_RTC_REQ_CFG >> 8;
	pci_vtrtc_notify(&sc, &sc.vrsc_vq[VTRTC_REQUESTQ]);
	ATF_CHECK_EQ(g_rel_calls, 2);
	ATF_CHECK_EQ(g_descs, 1);
	ATF_CHECK_EQ(g_end_all, 0);
}

ATF_TC_WITHOUT_HEAD(snapshot_wire_and_rejection);
ATF_TC_BODY(snapshot_wire_and_rejection, tc)
{
	struct pci_vtrtc_softc sc;
	uint8_t damaged[48], image[48], obsolete[8];
	uint64_t alarm_time;
	bool enabled;
	size_t used;

	memset(&sc, 0, sizeof(sc));
	ATF_REQUIRE_EQ(virtio_rtc_alarm_create(&sc.vrsc_alarm), 0);
	ATF_REQUIRE_EQ(run_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	ATF_CHECK_EQ(used, sizeof(image));
	ATF_CHECK_EQ(image[0], 'R');
	ATF_CHECK_EQ(image[1], 'T');
	ATF_CHECK_EQ(image[2], 'C');
	ATF_CHECK_EQ(image[3], '1');
	ATF_CHECK_EQ(le32dec(image + 4), 2);
	ATF_CHECK_EQ(run_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	memcpy(obsolete, image, sizeof(obsolete));
	le32enc(obsolete + 4, 1);
	ATF_REQUIRE_EQ(virtio_rtc_alarm_set(sc.vrsc_alarm, 123, true, 123),
	    0);
	ATF_CHECK(virtio_rtc_alarm_pending(sc.vrsc_alarm));
	ATF_CHECK_EQ(run_snapshot(&sc, obsolete, sizeof(obsolete),
	    VM_SNAPSHOT_VALIDATE, NULL), ENOTSUP);
	ATF_REQUIRE_EQ(virtio_rtc_alarm_read(sc.vrsc_alarm, &alarm_time,
	    &enabled), 0);
	ATF_CHECK_EQ(alarm_time, 123);
	ATF_CHECK(enabled);
	ATF_CHECK(virtio_rtc_alarm_pending(sc.vrsc_alarm));
	ATF_CHECK_EQ(run_snapshot(&sc, obsolete, sizeof(obsolete),
	    VM_SNAPSHOT_RESTORE, NULL), ENOTSUP);
	ATF_REQUIRE_EQ(virtio_rtc_alarm_read(sc.vrsc_alarm, &alarm_time,
	    &enabled), 0);
	ATF_CHECK_EQ(alarm_time, 123);
	ATF_CHECK(enabled);
	ATF_CHECK_EQ(run_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(run_snapshot(&sc, image, sizeof(image) - 1,
	    VM_SNAPSHOT_RESTORE, NULL), E2BIG);

	memcpy(damaged, image, sizeof(damaged));
	damaged[0] ^= 1;
	ATF_CHECK_EQ(run_snapshot(&sc, damaged, sizeof(damaged),
	    VM_SNAPSHOT_RESTORE, NULL), ENOTSUP);
	memcpy(damaged, image, sizeof(damaged));
	damaged[4] = 3;
	ATF_CHECK_EQ(run_snapshot(&sc, damaged, sizeof(damaged),
	    VM_SNAPSHOT_RESTORE, NULL), ENOTSUP);
	virtio_rtc_alarm_destroy(sc.vrsc_alarm);
}

ATF_TC_WITHOUT_HEAD(alarm_queue_and_short_buffer);
ATF_TC_BODY(alarm_queue_and_short_buffer, tc)
{
	struct pci_vtrtc_softc sc;

	memset(&sc, 0, sizeof(sc));
	sc.vrsc_vs.vs_vc = &sc.vrsc_consts;
	sc.vrsc_vs.vs_negotiated_caps = VIRTIO_RTC_F_ALARM;
	sc.vrsc_alarm_offered = true;
	sc.vrsc_alarm_fd = 7;
	sc.vrsc_vq[VTRTC_ALARMQ].vq_num = VTRTC_ALARMQ;
	ATF_REQUIRE_EQ(virtio_rtc_alarm_create(&sc.vrsc_alarm), 0);

	sc.vrsc_vs.vs_negotiated_caps = 0;
	reset_mocks();
	pci_vtrtc_notify(&sc, &sc.vrsc_vq[VTRTC_ALARMQ]);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(g_rel_calls, 0);

	sc.vrsc_vs.vs_negotiated_caps = VIRTIO_RTC_F_ALARM;
	ATF_REQUIRE_EQ(virtio_rtc_alarm_set(sc.vrsc_alarm, 10, true, 10), 0);
	reset_mocks();
	g_chain_n = -1;
	pci_vtrtc_notify(&sc, &sc.vrsc_vq[VTRTC_ALARMQ]);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK(virtio_rtc_alarm_pending(sc.vrsc_alarm));

	ATF_REQUIRE_EQ(virtio_rtc_alarm_set(sc.vrsc_alarm, 10, true, 10), 0);
	reset_mocks();
	g_chain_n = 1;
	g_readable = 0;
	g_writable = 1;
	g_response_len = VIRTIO14_RTC_NOTIF_ALARM_SIZE;
	pci_vtrtc_notify(&sc, &sc.vrsc_vq[VTRTC_ALARMQ]);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len, VIRTIO14_RTC_NOTIF_ALARM_SIZE);
	ATF_CHECK_EQ(le16dec(g_response), VIRTIO14_RTC_NOTIF_ALARM);
	ATF_CHECK_EQ(le16dec(g_response + 8), 0);
	ATF_CHECK(!virtio_rtc_alarm_pending(sc.vrsc_alarm));

	ATF_REQUIRE_EQ(virtio_rtc_alarm_set(sc.vrsc_alarm, 10, true, 10), 0);
	reset_mocks();
	g_chain_n = 1;
	g_readable = 0;
	g_writable = 1;
	g_response_len = VIRTIO14_RTC_NOTIF_ALARM_SIZE - 1;
	pci_vtrtc_notify(&sc, &sc.vrsc_vq[VTRTC_ALARMQ]);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(g_rel_len, 0);
	ATF_CHECK(virtio_rtc_alarm_pending(sc.vrsc_alarm));
	virtio_rtc_alarm_destroy(sc.vrsc_alarm);
}

ATF_TC_WITHOUT_HEAD(alarm_timer_failure_propagation);
ATF_TC_BODY(alarm_timer_failure_propagation, tc)
{
	struct pci_vtrtc_softc sc;

	memset(&sc, 0, sizeof(sc));
	sc.vrsc_consts.vc_name = "vtrtc-test";
	sc.vrsc_vs.vs_vc = &sc.vrsc_consts;
	sc.vrsc_alarm_offered = true;
	sc.vrsc_alarm_fd = 7;
	ATF_REQUIRE_EQ(virtio_rtc_alarm_create(&sc.vrsc_alarm), 0);
	ATF_REQUIRE_EQ(virtio_rtc_alarm_set(sc.vrsc_alarm, UINT64_MAX, true,
	    0), 0);

	reset_mocks();
	g_timer_error = EIO;
	ATF_CHECK_EQ(pci_vtrtc_alarm_schedule(&sc), EIO);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(pci_vtrtc_suspend(&sc), EIO);

	g_timer_error = 0;
	ATF_CHECK_EQ(vi_pci_lifecycle_noop(&sc), 0);
	ATF_CHECK_EQ(g_timer_set_calls, 2);
	pthread_mutex_init(&sc.vrsc_mtx, NULL);
	sc.vrsc_vs.vs_mtx = &sc.vrsc_mtx;
	pci_vtrtc_resume_complete(&sc);
	ATF_CHECK_EQ(g_timer_set_calls, 3);
	ATF_CHECK_EQ(g_timer_value.it_value.tv_sec,
	    (time_t)(UINT64_MAX / VTRTC_NSEC_PER_SEC));
	ATF_CHECK_EQ(g_timer_flags,
	    TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET);
	/*
	 * Guest resume invokes the same completion hook from the status-write
	 * path while the VirtIO mutex is already owned.
	 */
	pthread_mutex_lock(&sc.vrsc_mtx);
	pci_vtrtc_resume_complete(&sc);
	pthread_mutex_unlock(&sc.vrsc_mtx);
	ATF_CHECK_EQ(g_timer_set_calls, 4);
	pthread_mutex_destroy(&sc.vrsc_mtx);
	virtio_rtc_alarm_destroy(sc.vrsc_alarm);
}

ATF_TC_WITHOUT_HEAD(checkpoint_pause_serializes_timer);
ATF_TC_BODY(checkpoint_pause_serializes_timer, tc)
{
	struct pci_vtrtc_softc sc;

	memset(&sc, 0, sizeof(sc));
	sc.vrsc_alarm_fd = 7;
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vrsc_mtx, NULL), 0);
	sc.vrsc_vs.vs_mtx = &sc.vrsc_mtx;

	reset_mocks();
	ATF_CHECK_EQ(pci_vtrtc_checkpoint_pause(&sc), 0);
	ATF_CHECK_EQ(g_timer_set_calls, 1);
	ATF_CHECK_EQ(g_timer_value.it_value.tv_sec, 0);
	ATF_CHECK_EQ(g_timer_value.it_value.tv_nsec, 0);
	pthread_mutex_destroy(&sc.vrsc_mtx);
}

ATF_TC_WITHOUT_HEAD(alarm_clock_steps_are_event_driven);
ATF_TC_BODY(alarm_clock_steps_are_event_driven, tc)
{
	struct pci_vtrtc_softc sc;

	memset(&sc, 0, sizeof(sc));
	reset_mocks();
	sc.vrsc_consts.vc_name = "vtrtc-test";
	sc.vrsc_vs.vs_vc = &sc.vrsc_consts;
	sc.vrsc_vs.vs_negotiated_caps = VIRTIO_RTC_F_ALARM;
	sc.vrsc_alarm_offered = true;
	sc.vrsc_alarm_fd = 7;
	sc.vrsc_vq[VTRTC_ALARMQ].vq_num = VTRTC_ALARMQ;
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vrsc_mtx, NULL), 0);
	sc.vrsc_vs.vs_mtx = &sc.vrsc_mtx;
	ATF_REQUIRE_EQ(virtio_rtc_alarm_create(&sc.vrsc_alarm), 0);
	ATF_REQUIRE_EQ(virtio_rtc_alarm_set(sc.vrsc_alarm,
	    20 * VTRTC_NSEC_PER_SEC, true, 10 * VTRTC_NSEC_PER_SEC), 0);

	g_clock_ns = 10 * VTRTC_NSEC_PER_SEC;
	ATF_REQUIRE_EQ(pci_vtrtc_alarm_schedule(&sc), 0);
	ATF_CHECK_EQ(g_timer_value.it_value.tv_sec, 20);
	ATF_CHECK_EQ(g_timer_flags,
	    TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET);

	/* A forward step crosses the alarm and delivers one notification. */
	g_clock_ns = 30 * VTRTC_NSEC_PER_SEC;
	g_timer_read_error = ECANCELED;
	g_chain_n = 1;
	g_readable = 0;
	g_writable = 1;
	g_response_len = VIRTIO14_RTC_NOTIF_ALARM_SIZE;
	pci_vtrtc_alarm_timerfd(7, EVF_READ, &sc);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK(!virtio_rtc_alarm_pending(sc.vrsc_alarm));
	ATF_CHECK_EQ(g_timer_value.it_value.tv_sec,
	    pci_vtrtc_time_t_max());

	/* A backward step replaces the sentinel with the real deadline. */
	g_clock_ns = 15 * VTRTC_NSEC_PER_SEC;
	pci_vtrtc_alarm_timerfd(7, EVF_READ, &sc);
	ATF_CHECK_EQ(g_timer_value.it_value.tv_sec, 20);
	ATF_CHECK_EQ(g_rel_calls, 1);

	/* Crossing the same still-enabled alarm again notifies exactly once. */
	g_clock_ns = 21 * VTRTC_NSEC_PER_SEC;
	g_descs = 1;
	pci_vtrtc_alarm_timerfd(7, EVF_READ, &sc);
	ATF_CHECK_EQ(g_rel_calls, 2);
	ATF_CHECK(!virtio_rtc_alarm_pending(sc.vrsc_alarm));
	ATF_CHECK_EQ(g_timer_value.it_value.tv_sec,
	    pci_vtrtc_time_t_max());
	ATF_CHECK_EQ(g_needs_reset, 0);

	pthread_mutex_destroy(&sc.vrsc_mtx);
	virtio_rtc_alarm_destroy(sc.vrsc_alarm);
}

ATF_TC_WITHOUT_HEAD(alarm_unread_clock_step_is_not_device_failure);
ATF_TC_BODY(alarm_unread_clock_step_is_not_device_failure, tc)
{
	struct pci_vtrtc_softc sc;

	memset(&sc, 0, sizeof(sc));
	reset_mocks();
	sc.vrsc_consts.vc_name = "vtrtc-test";
	sc.vrsc_vs.vs_vc = &sc.vrsc_consts;
	sc.vrsc_alarm_offered = true;
	sc.vrsc_alarm_fd = 7;
	ATF_REQUIRE_EQ(virtio_rtc_alarm_create(&sc.vrsc_alarm), 0);
	ATF_REQUIRE_EQ(virtio_rtc_alarm_set(sc.vrsc_alarm,
	    20 * VTRTC_NSEC_PER_SEC, true, 10 * VTRTC_NSEC_PER_SEC), 0);
	g_clock_ns = 10 * VTRTC_NSEC_PER_SEC;
	g_timer_error = ECANCELED;
	ATF_CHECK_EQ(pci_vtrtc_alarm_schedule(&sc), 0);
	ATF_CHECK_EQ(g_needs_reset, 0);
	ATF_CHECK_EQ(g_timer_value.it_value.tv_sec, 20);
	virtio_rtc_alarm_destroy(sc.vrsc_alarm);
}

ATF_TC_WITHOUT_HEAD(alarm_backward_step_during_sentinel_arm);
ATF_TC_BODY(alarm_backward_step_during_sentinel_arm, tc)
{
	struct pci_vtrtc_softc sc;
	uint8_t notification[VIRTIO14_RTC_NOTIF_ALARM_SIZE];
	size_t written;

	memset(&sc, 0, sizeof(sc));
	reset_mocks();
	sc.vrsc_consts.vc_name = "vtrtc-test";
	sc.vrsc_vs.vs_vc = &sc.vrsc_consts;
	sc.vrsc_alarm_offered = true;
	sc.vrsc_alarm_fd = 7;
	ATF_REQUIRE_EQ(virtio_rtc_alarm_create(&sc.vrsc_alarm), 0);
	ATF_REQUIRE_EQ(virtio_rtc_alarm_set(sc.vrsc_alarm,
	    20 * VTRTC_NSEC_PER_SEC, true, 30 * VTRTC_NSEC_PER_SEC), 0);
	ATF_REQUIRE_EQ(virtio_rtc_alarm_notify(sc.vrsc_alarm, notification,
	    sizeof(notification), &written), 0);
	ATF_REQUIRE_EQ(written, sizeof(notification));

	/*
	 * The first sample selects the post-service sentinel.  The second
	 * sample models a backward step immediately before that sentinel
	 * became active; the final host arm must be the real alarm deadline.
	 */
	g_clock_ns = 30 * VTRTC_NSEC_PER_SEC;
	g_clock_verify_ns = 15 * VTRTC_NSEC_PER_SEC;
	g_clock_verify_valid = true;
	ATF_REQUIRE_EQ(pci_vtrtc_alarm_schedule(&sc), 0);
	ATF_CHECK_EQ(g_clock_reads, 2);
	ATF_CHECK_EQ(g_timer_set_calls, 2);
	ATF_CHECK_EQ(g_timer_value.it_value.tv_sec, 20);
	ATF_CHECK_EQ(g_needs_reset, 0);
	virtio_rtc_alarm_destroy(sc.vrsc_alarm);
}

ATF_TC_WITHOUT_HEAD(init_failure_paths_release_all_state);
ATF_TC_BODY(init_failure_paths_release_all_state, tc)
{
	struct pci_devinst pi;
	struct nvlist nvl;

	memset(&nvl, 0, sizeof(nvl));

	/* Softc allocation failure returns before any teardown. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_calloc_fail = true;
	ATF_CHECK_EQ(pci_vtrtc_init(&pi, &nvl), 1);

	/* Mutex construction failure takes the early failed: label. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_mtxinit_fail = true;
	ATF_CHECK_EQ(pci_vtrtc_init(&pi, &nvl), 1);

	/* Alarm-model construction failure unwinds the mutex. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_alarm_create_fail = true;
	ATF_CHECK_EQ(pci_vtrtc_init(&pi, &nvl), 1);

	/* Transport selection failure unwinds alarm + mutex. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_transport_fail = true;
	ATF_CHECK_EQ(pci_vtrtc_init(&pi, &nvl), 1);

	/* Interrupt setup failure before the ISR mutex is published. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_intr_fail = true;
	ATF_CHECK_EQ(pci_vtrtc_init(&pi, &nvl), 1);

	/* Modern-BAR failure exercises the intr_initialized cleanup. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_modern_fail = true;
	ATF_CHECK_EQ(pci_vtrtc_init(&pi, &nvl), 1);

	/* Alarm offered: timerfd creation failure. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_config_alarm = true;
	g_timerfd_create_fail = true;
	ATF_CHECK_EQ(pci_vtrtc_init(&pi, &nvl), 1);

	/* Alarm offered: event registration failure closes the fd. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_config_alarm = true;
	g_mevent_fail = true;
	ATF_CHECK_EQ(pci_vtrtc_init(&pi, &nvl), 1);
	ATF_CHECK(!g_timer_created);
}

ATF_TC_WITHOUT_HEAD(alarm_queue_pending_and_chain_edges);
ATF_TC_BODY(alarm_queue_pending_and_chain_edges, tc)
{
	struct pci_vtrtc_softc sc;

	memset(&sc, 0, sizeof(sc));
	sc.vrsc_consts.vc_name = "vtrtc-test";
	sc.vrsc_vs.vs_vc = &sc.vrsc_consts;
	sc.vrsc_vs.vs_negotiated_caps = VIRTIO_RTC_F_ALARM;
	sc.vrsc_alarm_offered = true;
	sc.vrsc_alarm_fd = 7;
	sc.vrsc_vq[VTRTC_ALARMQ].vq_num = VTRTC_ALARMQ;
	ATF_REQUIRE_EQ(virtio_rtc_alarm_create(&sc.vrsc_alarm), 0);

	/* Negotiated but nothing pending: silent, no descriptor consumed. */
	reset_mocks();
	pci_vtrtc_alarmq_notify(&sc);
	ATF_CHECK_EQ(g_needs_reset, 0);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(g_end_calls, 0);

	/* Pending but the queue has no available descriptors. */
	ATF_REQUIRE_EQ(virtio_rtc_alarm_set(sc.vrsc_alarm, 10, true, 10), 0);
	reset_mocks();
	g_descs = 0;
	pci_vtrtc_alarmq_notify(&sc);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(g_end_calls, 0);
	ATF_CHECK(virtio_rtc_alarm_pending(sc.vrsc_alarm));

	/* Pending with a malformed writable-only chain shape. */
	ATF_REQUIRE_EQ(virtio_rtc_alarm_set(sc.vrsc_alarm, 10, true, 10), 0);
	reset_mocks();
	g_alarm_relaxed = true;
	g_chain_n = 1;
	g_readable = 1;
	g_writable = 1;
	pci_vtrtc_alarmq_notify(&sc);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len, 0);
	ATF_CHECK_EQ(g_end_calls, 1);
	virtio_rtc_alarm_destroy(sc.vrsc_alarm);
}

ATF_TC_WITHOUT_HEAD(alarm_schedule_error_paths);
ATF_TC_BODY(alarm_schedule_error_paths, tc)
{
	struct pci_vtrtc_softc sc;
	uint8_t notification[VIRTIO14_RTC_NOTIF_ALARM_SIZE];
	size_t written;

	/* State read failure when the alarm model is absent. */
	memset(&sc, 0, sizeof(sc));
	sc.vrsc_consts.vc_name = "vtrtc-test";
	sc.vrsc_vs.vs_vc = &sc.vrsc_consts;
	sc.vrsc_alarm_offered = true;
	sc.vrsc_alarm_fd = 7;
	sc.vrsc_alarm = NULL;
	reset_mocks();
	ATF_CHECK_EQ(pci_vtrtc_alarm_schedule(&sc), EINVAL);
	ATF_CHECK_EQ(g_needs_reset, 1);

	ATF_REQUIRE_EQ(virtio_rtc_alarm_create(&sc.vrsc_alarm), 0);

	/* Disabled alarm disarms the host timer with flags == 0. */
	ATF_REQUIRE_EQ(virtio_rtc_alarm_set(sc.vrsc_alarm, 10, false, 0), 0);
	reset_mocks();
	ATF_CHECK_EQ(pci_vtrtc_alarm_schedule(&sc), 0);
	ATF_CHECK_EQ(g_timer_set_calls, 1);
	ATF_CHECK_EQ(g_timer_flags, 0);

	/* Disarm failure for a disabled alarm requests driver reset. */
	reset_mocks();
	g_timer_error = EIO;
	ATF_CHECK_EQ(pci_vtrtc_alarm_schedule(&sc), EIO);
	ATF_CHECK_EQ(g_needs_reset, 1);

	/* Clock read failure while the alarm is enabled and not yet due. */
	ATF_REQUIRE_EQ(virtio_rtc_alarm_set(sc.vrsc_alarm,
	    20 * VTRTC_NSEC_PER_SEC, true, 10 * VTRTC_NSEC_PER_SEC), 0);
	reset_mocks();
	g_clock_fault = EIO;
	ATF_CHECK_EQ(pci_vtrtc_alarm_schedule(&sc), EIO);
	ATF_CHECK_EQ(g_needs_reset, 1);

	/* An enabled, now-due alarm disarms; a disarm failure is fatal. */
	ATF_REQUIRE_EQ(virtio_rtc_alarm_set(sc.vrsc_alarm,
	    10 * VTRTC_NSEC_PER_SEC, true, 5 * VTRTC_NSEC_PER_SEC), 0);
	reset_mocks();
	g_clock_ns = 20 * VTRTC_NSEC_PER_SEC;
	g_timer_error = EIO;
	ATF_CHECK_EQ(pci_vtrtc_alarm_schedule(&sc), EIO);
	ATF_CHECK_EQ(g_needs_reset, 1);

	/* Sentinel path: the post-arm verification read fails. */
	ATF_REQUIRE_EQ(virtio_rtc_alarm_set(sc.vrsc_alarm,
	    20 * VTRTC_NSEC_PER_SEC, true, 30 * VTRTC_NSEC_PER_SEC), 0);
	ATF_REQUIRE_EQ(virtio_rtc_alarm_notify(sc.vrsc_alarm, notification,
	    sizeof(notification), &written), 0);
	reset_mocks();
	g_clock_ns = 30 * VTRTC_NSEC_PER_SEC;
	g_clock_verify_fault = EIO;
	ATF_CHECK_EQ(pci_vtrtc_alarm_schedule(&sc), EIO);
	ATF_CHECK_EQ(g_needs_reset, 1);

	/* Sentinel race: a verified backward step re-arms, and that fails. */
	ATF_REQUIRE_EQ(virtio_rtc_alarm_set(sc.vrsc_alarm,
	    20 * VTRTC_NSEC_PER_SEC, true, 30 * VTRTC_NSEC_PER_SEC), 0);
	ATF_REQUIRE_EQ(virtio_rtc_alarm_notify(sc.vrsc_alarm, notification,
	    sizeof(notification), &written), 0);
	reset_mocks();
	g_clock_ns = 30 * VTRTC_NSEC_PER_SEC;
	g_clock_verify_ns = 15 * VTRTC_NSEC_PER_SEC;
	g_clock_verify_valid = true;
	g_timer_error_at = 2;
	ATF_CHECK_EQ(pci_vtrtc_alarm_schedule(&sc), EIO);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(g_timer_set_calls, 2);
	virtio_rtc_alarm_destroy(sc.vrsc_alarm);
}

ATF_TC_WITHOUT_HEAD(timerfd_callback_read_failures);
ATF_TC_BODY(timerfd_callback_read_failures, tc)
{
	struct pci_vtrtc_softc sc;

	memset(&sc, 0, sizeof(sc));
	sc.vrsc_consts.vc_name = "vtrtc-test";
	sc.vrsc_vs.vs_vc = &sc.vrsc_consts;
	sc.vrsc_alarm_offered = true;
	sc.vrsc_alarm_fd = 7;
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vrsc_mtx, NULL), 0);
	sc.vrsc_vs.vs_mtx = &sc.vrsc_mtx;
	ATF_REQUIRE_EQ(virtio_rtc_alarm_create(&sc.vrsc_alarm), 0);

	/* EAGAIN is a spurious wakeup: return without touching the model. */
	reset_mocks();
	g_timer_read_error = EAGAIN;
	pci_vtrtc_alarm_timerfd(7, EVF_READ, &sc);
	ATF_CHECK_EQ(g_needs_reset, 0);
	ATF_CHECK_EQ(g_timer_set_calls, 0);

	/* Any other read error is a device failure. */
	reset_mocks();
	g_timer_read_error = EIO;
	pci_vtrtc_alarm_timerfd(7, EVF_READ, &sc);
	ATF_CHECK_EQ(g_needs_reset, 1);

	/* A short read of the expiration word is a device failure. */
	reset_mocks();
	g_timer_short_read = true;
	pci_vtrtc_alarm_timerfd(7, EVF_READ, &sc);
	ATF_CHECK_EQ(g_needs_reset, 1);

	pthread_mutex_destroy(&sc.vrsc_mtx);
	virtio_rtc_alarm_destroy(sc.vrsc_alarm);
}

ATF_TC_WITHOUT_HEAD(read_clock_error_and_overflow);
ATF_TC_BODY(read_clock_error_and_overflow, tc)
{
	uint64_t reading;

	/* clock_gettime failure is surfaced as its errno. */
	reset_mocks();
	g_clock_fault = EPERM;
	ATF_CHECK_EQ(pci_vtrtc_read_clock(NULL, &reading), EPERM);

	/* A seconds count that cannot be scaled to ns overflows. */
	reset_mocks();
	g_clock_raw = true;
	g_clock_raw_sec = (time_t)(INT64_MAX);
	g_clock_raw_nsec = 0;
	ATF_CHECK_EQ(pci_vtrtc_read_clock(NULL, &reading), EOVERFLOW);
}

ATF_TC_WITHOUT_HEAD(request_handler_failure_requests_reset);
ATF_TC_BODY(request_handler_failure_requests_reset, tc)
{
	struct pci_vtrtc_softc sc;

	memset(&sc, 0, sizeof(sc));
	sc.vrsc_consts.vc_name = "vtrtc-test";
	sc.vrsc_vs.vs_vc = &sc.vrsc_consts;
	sc.vrsc_vq[VTRTC_REQUESTQ].vq_qsize = VTRTC_RINGSZ;
	/*
	 * Advertise ALARM but leave the model absent: the shared handler
	 * rejects the contract violation with a hard error, which the device
	 * turns into a needs-reset with a zero-length completion.
	 */
	sc.vrsc_vs.vs_negotiated_caps = VIRTIO_RTC_F_ALARM;
	sc.vrsc_alarm_offered = true;
	sc.vrsc_alarm = NULL;
	reset_mocks();
	g_request[0] = VIRTIO14_RTC_REQ_CFG & 0xff;
	g_request[1] = VIRTIO14_RTC_REQ_CFG >> 8;
	pci_vtrtc_notify(&sc, &sc.vrsc_vq[VTRTC_REQUESTQ]);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len, 0);
	ATF_CHECK_EQ(g_end_calls, 1);
}

ATF_TC_WITHOUT_HEAD(notify_unknown_queue_requests_reset);
ATF_TC_BODY(notify_unknown_queue_requests_reset, tc)
{
	struct pci_vtrtc_softc sc;
	struct vqueue_info other;

	memset(&sc, 0, sizeof(sc));
	memset(&other, 0, sizeof(other));
	sc.vrsc_vs.vs_vc = &sc.vrsc_consts;
	reset_mocks();
	pci_vtrtc_notify(&sc, &other);
	ATF_CHECK_EQ(g_needs_reset, 1);
}

ATF_TC_WITHOUT_HEAD(snapshot_save_error_and_valid_validate);
ATF_TC_BODY(snapshot_save_error_and_valid_validate, tc)
{
	struct pci_vtrtc_softc sc;
	uint8_t image[48];
	size_t used;

	/* A save with no alarm model propagates the model's error. */
	memset(&sc, 0, sizeof(sc));
	sc.vrsc_alarm = NULL;
	reset_mocks();
	ATF_CHECK_EQ(run_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, NULL), EINVAL);

	/* A well-formed image passes structural validation. */
	ATF_REQUIRE_EQ(virtio_rtc_alarm_create(&sc.vrsc_alarm), 0);
	ATF_REQUIRE_EQ(run_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	ATF_CHECK_EQ(used, sizeof(image));
	ATF_CHECK_EQ(run_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_VALIDATE, NULL), 0);
	virtio_rtc_alarm_destroy(sc.vrsc_alarm);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, advertised_and_initialization_contract);
	ATF_TP_ADD_TC(tp, request_queue_and_descriptor_validation);
	ATF_TP_ADD_TC(tp, notification_budget_is_queue_bounded);
	ATF_TP_ADD_TC(tp, reset_disarm_failure_requests_driver_reset);
	ATF_TP_ADD_TC(tp, snapshot_wire_and_rejection);
	ATF_TP_ADD_TC(tp, alarm_queue_and_short_buffer);
	ATF_TP_ADD_TC(tp, alarm_timer_failure_propagation);
	ATF_TP_ADD_TC(tp, checkpoint_pause_serializes_timer);
	ATF_TP_ADD_TC(tp, alarm_clock_steps_are_event_driven);
	ATF_TP_ADD_TC(tp, alarm_unread_clock_step_is_not_device_failure);
	ATF_TP_ADD_TC(tp, alarm_backward_step_during_sentinel_arm);
	ATF_TP_ADD_TC(tp, init_failure_paths_release_all_state);
	ATF_TP_ADD_TC(tp, alarm_queue_pending_and_chain_edges);
	ATF_TP_ADD_TC(tp, alarm_schedule_error_paths);
	ATF_TP_ADD_TC(tp, timerfd_callback_read_failures);
	ATF_TP_ADD_TC(tp, read_clock_error_and_overflow);
	ATF_TP_ADD_TC(tp, request_handler_failure_requests_reset);
	ATF_TP_ADD_TC(tp, notify_unknown_queue_requests_reset);
	ATF_TP_ADD_TC(tp, snapshot_save_error_and_valid_validate);
	return (atf_no_error());
}
