/*
 * Unit tests for bhyve's VirtIO input device.  The real device source is
 * included so queue validation, frame handling, and transport wiring can be
 * exercised without an evdev device or VM.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <dev/evdev/input.h>

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

int pthread_mutex_isowned_np(pthread_mutex_t *);

static int test_open(const char *, int, ...);
static int test_close(int);
static int test_fstat(int, struct stat *);
static int test_ioctl(int, unsigned long, ...);
static ssize_t test_read(int, void *, size_t);
static ssize_t test_write(int, const void *, size_t);

#define open test_open
#define close test_close
#define fstat test_fstat
#define ioctl test_ioctl
#define read test_read
#define write test_write
#define	BHYVE_SNAPSHOT
#include "pci_virtio_input.c"
#include "virtio_config_read_test_support.h"
#undef open
#undef close
#undef fstat
#undef ioctl
#undef read
#undef write
#include "virtio_1_4_spec.h"
#include "bhyve_virtio_compat.h"

/* Keep test stimuli independent of the device's protocol definitions. */
#undef VIRTIO_CONFIG_STATUS_DRIVER_OK
#define	VIRTIO_CONFIG_STATUS_DRIVER_OK	VIRTIO14_STATUS_DRIVER_OK
#undef VIRTIO_F_IN_ORDER
#define	VIRTIO_F_IN_ORDER		VIRTIO14_F_IN_ORDER
#undef VIRTIO_F_RING_PACKED
#define	VIRTIO_F_RING_PACKED		VIRTIO14_F_RING_PACKED
#undef VIRTIO_F_SUSPEND
#define	VIRTIO_F_SUSPEND		VIRTIO14_F_SUSPEND
#undef VIRTIO_ID_INPUT
#define	VIRTIO_ID_INPUT			VIRTIO14_DEVICE_INPUT
#undef VTINPUT_CFG_ABS_INFO
#define	VTINPUT_CFG_ABS_INFO		VIRTIO14_INPUT_CFG_ABS_INFO
#undef VTINPUT_CFG_UNSET
#define	VTINPUT_CFG_UNSET		VIRTIO14_INPUT_CFG_UNSET
#undef VTINPUT_CFG_ID_NAME
#define	VTINPUT_CFG_ID_NAME		VIRTIO14_INPUT_CFG_ID_NAME
#undef VTINPUT_CFG_ID_SERIAL
#define	VTINPUT_CFG_ID_SERIAL		VIRTIO14_INPUT_CFG_ID_SERIAL
#undef VTINPUT_CFG_ID_DEVIDS
#define	VTINPUT_CFG_ID_DEVIDS		VIRTIO14_INPUT_CFG_ID_DEVIDS
#undef VTINPUT_CFG_PROP_BITS
#define	VTINPUT_CFG_PROP_BITS		VIRTIO14_INPUT_CFG_PROP_BITS
#undef VTINPUT_CFG_EV_BITS
#define	VTINPUT_CFG_EV_BITS		VIRTIO14_INPUT_CFG_EV_BITS
#undef VTINPUT_EVENTQ
#define	VTINPUT_EVENTQ			VIRTIO14_INPUT_EVENTQ
#undef VTINPUT_STATUSQ
#define	VTINPUT_STATUSQ			VIRTIO14_INPUT_STATUSQ

struct nvlist {
	int unused;
};

struct mevent {
	int unused;
};

static const char *g_transport;
static bool g_packed;
static int g_modern_init;
static int g_modern_identity;
static int g_io_bar;
static int g_cfgread_hook;
static int g_cfgwrite_hook;
static int g_descs;
static int g_getchain_n;
static int g_getchain_readable;
static int g_getchain_writable;
static size_t g_getchain_len;
static bool g_getchain_null;
static bool g_getchain_split;
static int g_getchain_calls;
static bool g_require_queue_lock;
static int g_bad_chain_call;
static int g_bad_chain_n;
static uint8_t g_iov_buf[64][VIRTIO14_INPUT_EVENT_SIZE + 1];
static int g_rel_calls;
static uint32_t g_rel_len[64];
static uint16_t g_rel_idx[64];
static int g_end_calls;
static int g_end_all;
static int g_ret_calls;
static uint16_t g_ret_count;
static int g_host_write_calls;
static struct input_event g_host_write_event;
static struct input_event g_read_events[VTINPUT_HOST_EVENT_BUDGET + 1];
static int g_read_event_count;
static int g_read_event_index;
static char g_config_path[128];
static char g_legacy_opts[128];
static int g_legacy_parse_calls;
static bool g_ioctl_abs_success;
static bool g_ioctl_name_success;
static bool g_ioctl_devids_success;
static bool g_ioctl_prop_success;
static bool g_ioctl_ev_success;
static unsigned long g_last_ioctl;
static int g_mevent_enable_calls;
static int g_mevent_disable_calls;
static int g_mevent_enable_error;
static int g_mevent_disable_error;
static int g_snapshot_validate_calls;
static int g_snapshot_validate_result;
static bool g_snapshot_validate_saw_lock;
/* Fault-injection controls for evdev/backend and transport wiring. */
static bool g_open_fail;
static bool g_fstat_fail;
static bool g_evversion_fail;
static bool g_evgrab_fail;
static bool g_path_null;
static bool g_mevent_add_null;
static bool g_intr_init_fail;
static bool g_modern_init_fail;
static bool g_getchain_overflow;
static bool g_read_short;
static int g_read_error_errno;
static int g_write_force;	/* 0: normal; -1: error; >0: short byte count */
/*
 * Allocation and pthread fault injection via ld --wrap.  Each __wrap_ defers to
 * __real_ except when armed, so libatf and the coverage runtime are unaffected.
 * calloc failures are armed by ordinal: g_calloc_fail_after counts successful
 * calloc()s the model is allowed to make before the next one fails.  Ordinals
 * keep the stimulus independent of any production struct layout.
 */
static int g_calloc_fail_after = -1;	/* -1 disabled; else fail after N callocs */
/*
 * Fail the next malloc/realloc after arming.  Both are covered because at -O2
 * the compiler may rewrite realloc(NULL, n) into malloc(n) at inlined sites
 * where the pointer is provably null.  Nothing allocates between arming and the
 * device call under test, so "next allocation" is deterministic.
 */
static bool g_realloc_fail_armed;
static bool g_strdup_fail_armed;
static int g_pthread_fail_which;	/* 0 none;1 attrinit;2 settype;3 mutexinit */

extern void *__real_malloc(size_t);
extern void *__real_calloc(size_t, size_t);
extern void *__real_realloc(void *, size_t);
extern char *__real_strdup(const char *);
extern int __real_pthread_mutexattr_init(pthread_mutexattr_t *);
extern int __real_pthread_mutexattr_settype(pthread_mutexattr_t *, int);
extern int __real_pthread_mutex_init(pthread_mutex_t *,
    const pthread_mutexattr_t *);

void *__wrap_malloc(size_t);
void *__wrap_calloc(size_t, size_t);
void *__wrap_realloc(void *, size_t);
char *__wrap_strdup(const char *);
int __wrap_pthread_mutexattr_init(pthread_mutexattr_t *);
int __wrap_pthread_mutexattr_settype(pthread_mutexattr_t *, int);
int __wrap_pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);

void *
__wrap_malloc(size_t size)
{
	if (g_realloc_fail_armed) {
		g_realloc_fail_armed = false;
		return (NULL);
	}
	return (__real_malloc(size));
}

void *
__wrap_calloc(size_t nmemb, size_t size)
{
	if (g_calloc_fail_after == 0) {
		g_calloc_fail_after = -1;
		return (NULL);
	}
	if (g_calloc_fail_after > 0)
		g_calloc_fail_after--;
	return (__real_calloc(nmemb, size));
}

void *
__wrap_realloc(void *ptr, size_t size)
{
	if (g_realloc_fail_armed) {
		g_realloc_fail_armed = false;
		return (NULL);
	}
	return (__real_realloc(ptr, size));
}

char *
__wrap_strdup(const char *s)
{
	if (g_strdup_fail_armed) {
		g_strdup_fail_armed = false;
		return (NULL);
	}
	return (__real_strdup(s));
}

int
__wrap_pthread_mutexattr_init(pthread_mutexattr_t *attr)
{
	if (g_pthread_fail_which == 1) {
		g_pthread_fail_which = 0;
		return (EINVAL);
	}
	return (__real_pthread_mutexattr_init(attr));
}

int
__wrap_pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type)
{
	if (g_pthread_fail_which == 2) {
		g_pthread_fail_which = 0;
		return (EINVAL);
	}
	return (__real_pthread_mutexattr_settype(attr, type));
}

int
__wrap_pthread_mutex_init(pthread_mutex_t *mtx, const pthread_mutexattr_t *attr)
{
	if (g_pthread_fail_which == 3) {
		g_pthread_fail_which = 0;
		return (EINVAL);
	}
	return (__real_pthread_mutex_init(mtx, attr));
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

static void
reset_mocks(void)
{
	g_transport = NULL;
	g_packed = false;
	g_modern_init = 0;
	g_modern_identity = -1;
	g_io_bar = 0;
	g_cfgread_hook = 0;
	g_cfgwrite_hook = 0;
	g_descs = 0;
	g_getchain_n = 1;
	g_getchain_readable = 0;
	g_getchain_writable = 1;
	g_getchain_len = VIRTIO14_INPUT_EVENT_SIZE;
	g_getchain_null = false;
	g_getchain_split = false;
	g_getchain_calls = 0;
	g_require_queue_lock = false;
	g_bad_chain_call = -1;
	g_bad_chain_n = 1;
	memset(g_iov_buf, 0, sizeof(g_iov_buf));
	g_rel_calls = 0;
	memset(g_rel_len, 0, sizeof(g_rel_len));
	memset(g_rel_idx, 0, sizeof(g_rel_idx));
	g_end_calls = 0;
	g_end_all = -1;
	g_ret_calls = 0;
	g_ret_count = 0;
	g_host_write_calls = 0;
	memset(&g_host_write_event, 0, sizeof(g_host_write_event));
	g_read_event_count = 0;
	g_read_event_index = 0;
	g_config_path[0] = '\0';
	g_legacy_opts[0] = '\0';
	g_legacy_parse_calls = 0;
	g_ioctl_abs_success = false;
	g_ioctl_name_success = false;
	g_ioctl_devids_success = false;
	g_ioctl_prop_success = false;
	g_ioctl_ev_success = false;
	g_last_ioctl = 0;
	g_mevent_enable_calls = 0;
	g_mevent_disable_calls = 0;
	g_mevent_enable_error = 0;
	g_mevent_disable_error = 0;
	g_snapshot_validate_calls = 0;
	g_snapshot_validate_result = 0;
	g_snapshot_validate_saw_lock = false;
	g_open_fail = false;
	g_fstat_fail = false;
	g_evversion_fail = false;
	g_evgrab_fail = false;
	g_path_null = false;
	g_mevent_add_null = false;
	g_intr_init_fail = false;
	g_modern_init_fail = false;
	g_getchain_overflow = false;
	g_read_short = false;
	g_read_error_errno = 0;
	g_write_force = 0;
	g_calloc_fail_after = -1;
	g_realloc_fail_armed = false;
	g_strdup_fail_armed = false;
	g_pthread_fail_which = 0;
}

const char *
get_config_value_node(const nvlist_t *nvl __unused, const char *name)
{
	if (strcmp(name, "path") == 0)
		return (g_path_null ? NULL : "/dev/input/mock");
	if (strcmp(name, "transport") == 0)
		return (g_transport);
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
	if (strcmp(name, "path") == 0)
		ATF_REQUIRE(strlcpy(g_config_path, value,
		    sizeof(g_config_path)) < sizeof(g_config_path));
}

int
pci_parse_legacy_config(nvlist_t *nvl __unused, const char *opts)
{
	g_legacy_parse_calls++;
	ATF_REQUIRE(strlcpy(g_legacy_opts, opts,
	    sizeof(g_legacy_opts)) < sizeof(g_legacy_opts));
	return (0);
}

static int
test_open(const char *path __unused, int flags __unused, ...)
{
	if (g_open_fail) {
		errno = EACCES;
		return (-1);
	}
	return (10);
}

static int
test_close(int fd __unused)
{
	return (0);
}

static int
test_fstat(int fd __unused, struct stat *st)
{

	if (g_fstat_fail) {
		errno = EBADF;
		return (-1);
	}
	memset(st, 0, sizeof(*st));
	st->st_rdev = 42;
	return (0);
}

static int
test_ioctl(int fd __unused, unsigned long request, ...)
{
	const int key_count = howmany(KEY_CNT, sizeof(long) * 8) *
	    sizeof(long);
	const int prop_count = howmany(INPUT_PROP_CNT, sizeof(long) * 8) *
	    sizeof(long);
	va_list ap;

	g_last_ioctl = request;
	if (request == EVIOCGVERSION) {
		if (g_evversion_fail) {
			errno = ENOTTY;
			return (-1);
		}
		va_start(ap, request);
		*va_arg(ap, int *) = EV_VERSION;
		va_end(ap);
		return (0);
	}
	if (request == EVIOCGRAB) {
		if (g_evgrab_fail) {
			errno = EBUSY;
			return (-1);
		}
		return (0);
	}
	if (request == EVIOCGABS(ABS_X)) {
		struct input_absinfo *abs;

		if (!g_ioctl_abs_success) {
			errno = EINVAL;
			return (-1);
		}
		va_start(ap, request);
		abs = va_arg(ap, struct input_absinfo *);
		va_end(ap);
		memset(abs, 0, sizeof(*abs));
		abs->minimum = -100;
		abs->maximum = 100;
		abs->fuzz = 2;
		abs->flat = 3;
		abs->resolution = 4;
		return (0);
	}
	if (request == EVIOCGNAME(127)) {
		char *name;

		if (!g_ioctl_name_success) {
			errno = EINVAL;
			return (-1);
		}
		va_start(ap, request);
		name = va_arg(ap, char *);
		va_end(ap);
		memcpy(name, "mock-input", sizeof("mock-input"));
		return (sizeof("mock-input"));
	}
	if (request == EVIOCGID) {
		struct input_id *ids;

		if (!g_ioctl_devids_success) {
			errno = EINVAL;
			return (-1);
		}
		va_start(ap, request);
		ids = va_arg(ap, struct input_id *);
		va_end(ap);
		ids->bustype = UINT16_C(0x1122);
		ids->vendor = UINT16_C(0x3344);
		ids->product = UINT16_C(0x5566);
		ids->version = UINT16_C(0x7788);
		return (0);
	}
	if (request == EVIOCGPROP(prop_count)) {
		unsigned long *bitmap;
		const size_t bit = 31;

		if (!g_ioctl_prop_success) {
			errno = EINVAL;
			return (-1);
		}
		va_start(ap, request);
		bitmap = va_arg(ap, unsigned long *);
		va_end(ap);
		bitmap[bit / (sizeof(*bitmap) * CHAR_BIT)] |=
		    1UL << (bit % (sizeof(*bitmap) * CHAR_BIT));
		return (0);
	}
	if (request == EVIOCGBIT(EV_KEY, key_count)) {
		unsigned long *bitmap;
		const size_t bit = 138;

		if (!g_ioctl_ev_success) {
			errno = EINVAL;
			return (-1);
		}
		va_start(ap, request);
		bitmap = va_arg(ap, unsigned long *);
		va_end(ap);
		bitmap[bit / (sizeof(*bitmap) * CHAR_BIT)] |=
		    1UL << (bit % (sizeof(*bitmap) * CHAR_BIT));
		return (0);
	}
	return (0);
}

static ssize_t
test_read(int fd __unused, void *buf, size_t len)
{
	if (g_read_event_index >= g_read_event_count) {
		if (g_read_error_errno != 0) {
			errno = g_read_error_errno;
			return (-1);
		}
		errno = EAGAIN;
		return (-1);
	}
	ATF_REQUIRE(len >= sizeof(struct input_event));
	memcpy(buf, &g_read_events[g_read_event_index++],
	    sizeof(struct input_event));
	if (g_read_short)
		return ((ssize_t)sizeof(struct input_event) - 1);
	return (sizeof(struct input_event));
}

static ssize_t
test_write(int fd __unused, const void *buf, size_t len)
{
	g_host_write_calls++;
	if (len == sizeof(g_host_write_event))
		memcpy(&g_host_write_event, buf, len);
	if (g_write_force < 0) {
		errno = EIO;
		return (-1);
	}
	if (g_write_force > 0)
		return ((ssize_t)g_write_force);
	return (len);
}

struct mevent *
mevent_add(int fd __unused, enum ev_type type __unused,
    void (*cb)(int, enum ev_type, void *) __unused, void *arg __unused)
{
	static struct mevent ev;
	if (g_mevent_add_null)
		return (NULL);
	return (&ev);
}

int
mevent_delete(struct mevent *ev __unused)
{
	return (0);
}

int
mevent_delete_sync(struct mevent *ev __unused)
{
	return (0);
}

int
mevent_enable(struct mevent *ev __unused)
{
	g_mevent_enable_calls++;
	return (g_mevent_enable_error);
}

int
mevent_disable(struct mevent *ev __unused)
{
	g_mevent_disable_calls++;
	return (g_mevent_disable_error);
}

int
mevent_delete_close(struct mevent *ev __unused)
{
	return (0);
}

int
fbsdrun_virtio_msix(void)
{
	return (1);
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
vi_pci_select_transport(struct virtio_softc *vs, const nvlist_t *nvl __unused,
    enum virtio_pci_transport_policy policy)
{
	ATF_CHECK(policy == VIRTIO_PCI_MODERN_DEFAULT);
	if (g_transport != NULL && strcmp(g_transport, "bogus") == 0)
		return (EINVAL);
	if (g_transport == NULL)
		vs->vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	else
		vs->vs_transport = strcmp(g_transport, "legacy") == 0 ?
		    VIRTIO_PCI_TRANSPORT_LEGACY :
		    VIRTIO_PCI_TRANSPORT_MODERN;
	return (0);
}

bool
vi_pci_is_modern(const struct virtio_softc *vs)
{
	return (vs->vs_transport == VIRTIO_PCI_TRANSPORT_MODERN);
}

void
vi_pci_modern_set_identity(struct virtio_softc *vs __unused, uint16_t type)
{
	g_modern_identity = type;
}

int
vi_pci_modern_init(struct virtio_softc *vs __unused, int bar)
{
	g_modern_init = bar;
	return (g_modern_init_fail ? -1 : 0);
}

int
vi_intr_init(struct virtio_softc *vs __unused, int bar __unused,
    int use_msix __unused)
{
	return (g_intr_init_fail ? -1 : 0);
}

void
vi_set_io_bar(struct virtio_softc *vs __unused, int bar)
{
	g_io_bar = bar + 1;
}

void
vi_reset_dev(struct virtio_softc *vs)
{
	vs->vs_status = 0;
}

int
vi_pci_modern_cfgread(struct pci_devinst *pi __unused, int offset __unused,
    int size __unused, uint32_t *value __unused)
{
	g_cfgread_hook++;
	return (0);
}

int
vi_pci_modern_cfgwrite(struct pci_devinst *pi __unused, int offset __unused,
    int size __unused, uint32_t value __unused)
{
	g_cfgwrite_hook++;
	return (0);
}

uint64_t
vi_pci_read(struct pci_devinst *pi __unused, int bar __unused,
    uint64_t offset __unused, int size __unused)
{
	return (0);
}

void
vi_pci_write(struct pci_devinst *pi __unused, int bar __unused,
    uint64_t offset __unused, int size __unused, uint64_t value __unused)
{
}

int
vq_has_descs(struct vqueue_info *vq __unused)
{
	return (g_descs > 0);
}

int
vq_getchain(struct vqueue_info *vq, struct iovec *iov, int niov,
    struct vi_req *req)
{
	int n, slot;

	if (g_require_queue_lock) {
		int error;

		ATF_REQUIRE(vq->vq_vs != NULL && vq->vq_vs->vs_mtx != NULL);
		error = pthread_mutex_trylock(vq->vq_vs->vs_mtx);
		ATF_CHECK(error == EBUSY);
		if (error == 0)
			pthread_mutex_unlock(vq->vq_vs->vs_mtx);
	}
	slot = g_getchain_calls++;
	n = slot == g_bad_chain_call ? g_bad_chain_n : g_getchain_n;
	if (n <= 0)
		return (n);
	ATF_REQUIRE(slot < (int)nitems(g_iov_buf));
	if (g_getchain_overflow) {
		ATF_REQUIRE(n == 2 && niov >= 2);
		iov[0].iov_base = g_iov_buf[slot];
		iov[0].iov_len = SIZE_MAX;
		iov[1].iov_base = g_iov_buf[slot];
		iov[1].iov_len = 1;
	} else if (g_getchain_split) {
		ATF_REQUIRE(n == 2 && niov >= 2);
		iov[0].iov_base = g_iov_buf[slot];
		iov[0].iov_len = 3;
		iov[1].iov_base = g_iov_buf[slot] + 3;
		iov[1].iov_len = VIRTIO14_INPUT_EVENT_SIZE - 3;
	} else if (niov > 0) {
		iov[0].iov_base = g_getchain_null ? NULL : g_iov_buf[slot];
		iov[0].iov_len = g_getchain_len;
	}
	req->idx = slot;
	req->readable = g_getchain_readable;
	req->writable = g_getchain_writable;
	g_descs--;
	return (n);
}

void
vq_relchain(struct vqueue_info *vq __unused, uint16_t idx,
    uint32_t len)
{
	ATF_REQUIRE(g_rel_calls < (int)nitems(g_rel_len));
	g_rel_idx[g_rel_calls] = idx;
	g_rel_len[g_rel_calls++] = len;
}

void
vq_retchains(struct vqueue_info *vq __unused, uint16_t count)
{
	g_ret_calls++;
	g_ret_count += count;
	g_descs += count;
}

void
vq_endchains(struct vqueue_info *vq __unused, int all_avail)
{
	g_end_calls++;
	g_end_all = all_avail;
}

void
pci_set_cfgdata8(struct pci_devinst *pi, int offset, uint8_t value)
{
	pi->pi_cfgdata[offset] = value;
}

void
pci_set_cfgdata16(struct pci_devinst *pi, int offset, uint16_t value)
{
	memcpy(&pi->pi_cfgdata[offset], &value, sizeof(value));
}

void
pci_set_cfgdata32(struct pci_devinst *pi, int offset, uint32_t value)
{
	memcpy(&pi->pi_cfgdata[offset], &value, sizeof(value));
}

uint8_t
pci_get_cfgdata8(struct pci_devinst *pi, int offset)
{
	return (pi->pi_cfgdata[offset]);
}

uint32_t
pci_get_cfgdata32(struct pci_devinst *pi, int offset)
{
	uint32_t value;
	memcpy(&value, &pi->pi_cfgdata[offset], sizeof(value));
	return (value);
}

static void
free_input_softc(struct pci_devinst *pi)
{
	struct pci_vtinput_softc *sc;

	sc = pi->pi_arg;
	free(sc->vsc_eventqueue.events);
	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc);
	pi->pi_arg = NULL;
}

ATF_TC_WITHOUT_HEAD(transport_compatibility);
ATF_TC_BODY(transport_compatibility, tc)
{
	struct pci_devinst pi;
	struct nvlist nvl;
	uint16_t value;
	uint8_t revision;

	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	ATF_REQUIRE(pci_vtinput_init(&pi, &nvl) == 0);
	ATF_CHECK(g_modern_init == 2);
	ATF_CHECK(g_io_bar == 0);
	ATF_CHECK(g_modern_identity == VIRTIO_ID_INPUT);
	ATF_CHECK(pci_de_vinput.pe_cfgread == vi_pci_modern_cfgread);
	ATF_CHECK(pci_de_vinput.pe_cfgwrite == vi_pci_modern_cfgwrite);
	free_input_softc(&pi);

	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_transport = "legacy";
	ATF_REQUIRE(pci_vtinput_init(&pi, &nvl) == 0);
	ATF_CHECK(g_modern_init == 0);
	ATF_CHECK(g_io_bar == 1);
	memcpy(&value, &pi.pi_cfgdata[PCIR_DEVICE], sizeof(value));
	/*
	 * Explicit legacy mode preserves bhyve's historical non-standard
	 * identity.  It is deliberately not represented by a VIRTIO14_ oracle
	 * value because section 4.1.2 defines no transitional input ID.
	 */
	ATF_CHECK(value == BHYVE_COMPAT_VIRTIO_INPUT_LEGACY_DEVICE_ID);
	revision = pi.pi_cfgdata[PCIR_REVID];
	ATF_CHECK(revision ==
	    BHYVE_COMPAT_VIRTIO_INPUT_LEGACY_REVISION);
	memcpy(&value, &pi.pi_cfgdata[PCIR_SUBVEND_0], sizeof(value));
	ATF_CHECK(value ==
	    BHYVE_COMPAT_VIRTIO_INPUT_LEGACY_SUBVENDOR);
	memcpy(&value, &pi.pi_cfgdata[PCIR_SUBDEV_0], sizeof(value));
	ATF_CHECK(value ==
	    BHYVE_COMPAT_VIRTIO_INPUT_LEGACY_SUBDEVICE);
	free_input_softc(&pi);

	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_transport = "modern";
	ATF_REQUIRE(pci_vtinput_init(&pi, &nvl) == 0);
	ATF_CHECK(g_modern_init == 2);
	ATF_CHECK(g_io_bar == 0);
	ATF_CHECK(g_modern_identity == VIRTIO_ID_INPUT);
	ATF_CHECK(pci_de_vinput.pe_cfgread == vi_pci_modern_cfgread);
	ATF_CHECK(pci_de_vinput.pe_cfgwrite == vi_pci_modern_cfgwrite);
	free_input_softc(&pi);

	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_transport = "modern";
	g_packed = true;
	ATF_REQUIRE(pci_vtinput_init(&pi, &nvl) == 0);
	ATF_CHECK((((struct pci_vtinput_softc *)pi.pi_arg)->
	    vsc_consts.vc_hv_caps & VIRTIO_F_RING_PACKED) != 0);
	ATF_CHECK((vtinput_vi_consts.vc_hv_caps &
	    VIRTIO_F_RING_PACKED) == 0);
	free_input_softc(&pi);

	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_transport = "legacy";
	g_packed = true;
	ATF_CHECK(pci_vtinput_init(&pi, &nvl) != 0);
}

ATF_TC_WITHOUT_HEAD(command_line_config);
ATF_TC_BODY(command_line_config, tc)
{
	struct nvlist nvl;

	reset_mocks();
	ATF_CHECK(pci_vtinput_legacy_config(&nvl, NULL) == -1);
	ATF_CHECK(g_config_path[0] == '\0');
	ATF_CHECK(g_legacy_parse_calls == 0);

	ATF_CHECK(pci_vtinput_legacy_config(&nvl,
	    "/dev/input/event11") == 0);
	ATF_CHECK(strcmp(g_config_path, "/dev/input/event11") == 0);
	ATF_CHECK(g_legacy_parse_calls == 0);

	reset_mocks();
	ATF_CHECK(pci_vtinput_legacy_config(&nvl,
	    "/dev/input/event12,transport=modern") == 0);
	ATF_CHECK(strcmp(g_config_path, "/dev/input/event12") == 0);
	ATF_CHECK(g_legacy_parse_calls == 1);
	ATF_CHECK(strcmp(g_legacy_opts, "transport=modern") == 0);
}

ATF_TC_WITHOUT_HEAD(eventqueue_growth);
ATF_TC_BODY(eventqueue_growth, tc)
{
	struct vtinput_eventqueue queue;
	struct input_event event;

	reset_mocks();
	ATF_REQUIRE_EQ(VTINPUT_MAX_FRAME_EVENTS, 4096);
	memset(&queue, 0, sizeof(queue));
	memset(&event, 0, sizeof(event));
	for (int i = 0; i < 1000; i++) {
		event.code = i;
		ATF_REQUIRE(vtinput_eventqueue_add_event(&queue, &event) == 0);
	}
	ATF_CHECK(queue.idx == 1000);
	ATF_CHECK(queue.size >= queue.idx);
	ATF_CHECK(queue.events[999].event.code == 999);
	free(queue.events);

	memset(&queue, 0, sizeof(queue));
	queue.size = UINT32_MAX / 2 + 1;
	queue.idx = queue.size;
	ATF_CHECK(vtinput_eventqueue_add_event(&queue, &event) == 1);

	memset(&queue, 0, sizeof(queue));
	queue.size = VTINPUT_MAX_FRAME_EVENTS;
	queue.idx = queue.size;
	ATF_CHECK(vtinput_eventqueue_add_event(&queue, &event) == 1);
}

ATF_TC_WITHOUT_HEAD(syn_report_flushes_frame);
ATF_TC_BODY(syn_report_flushes_frame, tc)
{
	struct pci_vtinput_softc sc;
	pthread_mutex_t mtx;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	ATF_REQUIRE(pthread_mutex_init(&mtx, NULL) == 0);
	sc.vsc_vs.vs_mtx = &mtx;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_vs = &sc.vsc_vs;
	vq_set_allocated(&sc.vsc_queues[VTINPUT_EVENTQ], true);
	g_require_queue_lock = true;
	sc.vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	sc.vsc_eventqueue.size = VTINPUT_MAX_PKT_LEN;
	sc.vsc_eventqueue.events = calloc(sc.vsc_eventqueue.size,
	    sizeof(*sc.vsc_eventqueue.events));
	ATF_REQUIRE(sc.vsc_eventqueue.events != NULL);
	g_read_events[0].type = EV_KEY;
	g_read_events[0].code = KEY_A;
	g_read_events[0].value = 1;
	g_read_events[1].type = EV_SYN;
	g_read_events[1].code = SYN_REPORT;
	g_read_event_count = 2;
	g_descs = 3;
	vtinput_read_event(10, EVF_READ, &sc);
	ATF_CHECK(g_read_event_index == 2);
	ATF_CHECK(g_rel_calls == 2);
	ATF_CHECK(g_rel_len[0] == VIRTIO14_INPUT_EVENT_SIZE);
	ATF_CHECK(g_rel_len[1] == VIRTIO14_INPUT_EVENT_SIZE);
	ATF_CHECK(g_end_calls == 1);
	ATF_CHECK_EQ(g_end_all, 0);
	ATF_CHECK_EQ(g_descs, 1);
	ATF_CHECK(sc.vsc_eventqueue.idx == 0);
	free(sc.vsc_eventqueue.events);
	pthread_mutex_destroy(&mtx);
}

ATF_TC_WITHOUT_HEAD(complete_frame_retries_on_guest_kick);
ATF_TC_BODY(complete_frame_retries_on_guest_kick, tc)
{
	struct pci_vtinput_softc sc;
	struct vtinput_event delivered;
	pthread_mutex_t mtx;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	ATF_REQUIRE_EQ(pthread_mutex_init(&mtx, NULL), 0);
	sc.vsc_vs.vs_mtx = &mtx;
	sc.vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_vs = &sc.vsc_vs;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_qsize = VTINPUT_RINGSZ;
	vq_set_allocated(&sc.vsc_queues[VTINPUT_EVENTQ], true);
	sc.vsc_eventqueue.size = VTINPUT_MAX_PKT_LEN;
	sc.vsc_eventqueue.events = calloc(sc.vsc_eventqueue.size,
	    sizeof(*sc.vsc_eventqueue.events));
	ATF_REQUIRE(sc.vsc_eventqueue.events != NULL);

	g_read_events[0].type = EV_KEY;
	g_read_events[0].code = KEY_A;
	g_read_events[0].value = 1;
	g_read_events[1].type = EV_SYN;
	g_read_events[1].code = SYN_REPORT;
	g_read_event_count = 2;
	g_descs = 1;
	vtinput_read_event(10, EVF_READ, &sc);
	ATF_CHECK_EQ(g_read_event_index, 2);
	ATF_CHECK_EQ(g_getchain_calls, 1);
	ATF_CHECK_EQ(g_ret_calls, 1);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(g_end_calls, 0);
	ATF_CHECK_EQ(sc.vsc_eventqueue.idx, 2);
	ATF_CHECK(vtinput_eventqueue_frame_complete(&sc.vsc_eventqueue));

	/* Posting the missing buffers must deliver the retained frame. */
	g_descs = 2;
	pci_vtinput_notify_eventq(&sc, &sc.vsc_queues[VTINPUT_EVENTQ]);
	ATF_CHECK_EQ(g_getchain_calls, 3);
	ATF_CHECK_EQ(g_rel_calls, 2);
	ATF_CHECK_EQ(g_rel_len[0], VIRTIO14_INPUT_EVENT_SIZE);
	ATF_CHECK_EQ(g_rel_len[1], VIRTIO14_INPUT_EVENT_SIZE);
	ATF_CHECK_EQ(g_end_calls, 1);
	ATF_CHECK_EQ(sc.vsc_eventqueue.idx, 0);
	memcpy(&delivered, g_iov_buf[1], VIRTIO14_INPUT_EVENT_SIZE);
	ATF_CHECK_EQ(le16toh(delivered.type), EV_KEY);
	ATF_CHECK_EQ(le16toh(delivered.code), KEY_A);
	ATF_CHECK_EQ((int32_t)le32toh(delivered.value), 1);
	memcpy(&delivered, g_iov_buf[2], VIRTIO14_INPUT_EVENT_SIZE);
	ATF_CHECK_EQ(le16toh(delivered.type), EV_SYN);
	ATF_CHECK_EQ(le16toh(delivered.code), SYN_REPORT);

	free(sc.vsc_eventqueue.events);
	pthread_mutex_destroy(&mtx);
}

ATF_TC_WITHOUT_HEAD(host_event_dispatch_is_bounded);
ATF_TC_BODY(host_event_dispatch_is_bounded, tc)
{
	struct pci_vtinput_softc sc;
	struct mevent event;
	pthread_mutex_t mtx;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	ATF_REQUIRE(pthread_mutex_init(&mtx, NULL) == 0);
	sc.vsc_vs.vs_mtx = &mtx;
	g_read_event_count = (int)nitems(g_read_events);

	/*
	 * An inactive queue is deliberately drained, but a permanently readable
	 * host descriptor must not monopolize the mevent thread.  Level-triggered
	 * readiness schedules the remainder on a later dispatch.
	 */
	vtinput_read_event(10, EVF_READ, &sc);
	ATF_CHECK_EQ(g_read_event_index, VTINPUT_HOST_EVENT_BUDGET);
	vtinput_read_event(10, EVF_READ, &sc);
	ATF_CHECK_EQ(g_read_event_index, (int)nitems(g_read_events));

	/* Reset-time generation isolation is bounded by the same dispatch cap. */
	g_read_event_index = 0;
	memset(&event, 0, sizeof(event));
	sc.vsc_evp = &event;
	ATF_CHECK(!vtinput_drain_host_events(&sc));
	ATF_CHECK_EQ(g_read_event_index, VTINPUT_HOST_EVENT_BUDGET);
	sc.vsc_discard_host_events = true;
	vtinput_read_event(10, EVF_READ, &sc);
	ATF_CHECK_EQ(g_read_event_index, (int)nitems(g_read_events));
	ATF_CHECK(!sc.vsc_discard_host_events);

	pthread_mutex_destroy(&mtx);
}

ATF_TC_WITHOUT_HEAD(hostile_status_descriptors);
ATF_TC_BODY(hostile_status_descriptors, tc)
{
	struct pci_vtinput_softc sc;
	struct vqueue_info vq;

	memset(&sc, 0, sizeof(sc));
	memset(&vq, 0, sizeof(vq));
	vq.vq_qsize = VTINPUT_RINGSZ;
	sc.vsc_fd = 10;

	for (int kind = 0; kind < 6; kind++) {
		reset_mocks();
		g_descs = 1;
		g_getchain_readable = 1;
		g_getchain_writable = 0;
		switch (kind) {
		case 0: g_getchain_n = VTINPUT_RINGSZ + 1; break;
		case 1: g_getchain_readable = 0; g_getchain_writable = 1; break;
		case 2:
			g_getchain_len = VIRTIO14_INPUT_EVENT_SIZE - 1;
			break;
		case 3: g_getchain_null = true; break;
		case 4: g_getchain_n = -1; break;
		case 5:
			g_getchain_len = VIRTIO14_INPUT_EVENT_SIZE + 1;
			break;
		}
		pci_vtinput_notify_statusq(&sc, &vq);
		ATF_CHECK(g_host_write_calls == 0);
		if (kind == 4)
			ATF_CHECK(g_rel_calls == 0);
		else
			ATF_CHECK(g_rel_calls == 1 && g_rel_len[0] == 0);
	}
}

ATF_TC_WITHOUT_HEAD(hostile_event_descriptors);
ATF_TC_BODY(hostile_event_descriptors, tc)
{
	struct vtinput_eventqueue queue;
	struct vqueue_info vq;
	struct input_event event;

	memset(&vq, 0, sizeof(vq));
	vq.vq_qsize = VTINPUT_RINGSZ;
	memset(&event, 0, sizeof(event));
	for (int kind = 0; kind < 4; kind++) {
		reset_mocks();
		memset(&queue, 0, sizeof(queue));
		ATF_REQUIRE(vtinput_eventqueue_add_event(&queue, &event) == 0);
		g_descs = 1;
		switch (kind) {
		case 0: g_getchain_n = VTINPUT_RINGSZ + 1; break;
		case 1: g_getchain_readable = 1; g_getchain_writable = 0; break;
		case 2:
			g_getchain_len = VIRTIO14_INPUT_EVENT_SIZE - 1;
			break;
		case 3: g_getchain_null = true; break;
		}
		vtinput_eventqueue_send_events(&queue, &vq);
		ATF_CHECK(g_rel_calls == 1 && g_rel_len[0] == 0);
		free(queue.events);
	}
}

ATF_TC_WITHOUT_HEAD(scatter_gather_events);
ATF_TC_BODY(scatter_gather_events, tc)
{
	struct pci_vtinput_softc sc;
	struct vtinput_eventqueue queue;
	struct input_event host_event;
	struct vqueue_info vq;
	const uint8_t status_wire[VIRTIO14_INPUT_EVENT_SIZE] = {
		0x11, 0x00, 0x01, 0x00, 0x78, 0x56, 0x34, 0x12
	};
	const uint8_t expected_event_wire[VIRTIO14_INPUT_EVENT_SIZE] = {
		0x34, 0x12, 0x78, 0x56, 0x78, 0x56, 0x34, 0x12
	};

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	memset(&vq, 0, sizeof(vq));
	vq.vq_qsize = VTINPUT_RINGSZ;
	sc.vsc_fd = 10;
	memcpy(g_iov_buf[0], status_wire, sizeof(status_wire));
	g_descs = 1;
	g_getchain_n = 2;
	g_getchain_readable = 2;
	g_getchain_writable = 0;
	g_getchain_split = true;
	pci_vtinput_notify_statusq(&sc, &vq);
	ATF_CHECK(g_host_write_calls == 1);
	ATF_CHECK(g_host_write_event.type == 0x11);
	ATF_CHECK(g_host_write_event.code == 0x01);
	ATF_CHECK(g_host_write_event.value == 0x12345678);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len[0] == 0);

	reset_mocks();
	memset(&queue, 0, sizeof(queue));
	memset(&host_event, 0, sizeof(host_event));
	host_event.type = 0x1234;
	host_event.code = 0x5678;
	host_event.value = 0x12345678;
	ATF_REQUIRE(vtinput_eventqueue_add_event(&queue, &host_event) == 0);
	g_descs = 1;
	g_getchain_n = 2;
	g_getchain_readable = 0;
	g_getchain_writable = 2;
	g_getchain_split = true;
	vtinput_eventqueue_send_events(&queue, &vq);
	ATF_CHECK(g_rel_calls == 1 &&
	    g_rel_len[0] == VIRTIO14_INPUT_EVENT_SIZE);
	ATF_CHECK(memcmp(g_iov_buf[0], expected_event_wire,
	    sizeof(expected_event_wire)) == 0);
	free(queue.events);
}

ATF_TC_WITHOUT_HEAD(status_error_finishes_completions);
ATF_TC_BODY(status_error_finishes_completions, tc)
{
	struct pci_vtinput_softc sc;
	struct vqueue_info vq;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	memset(&vq, 0, sizeof(vq));
	vq.vq_qsize = VTINPUT_RINGSZ;
	sc.vsc_fd = 10;
	g_descs = 2;
	g_getchain_readable = 1;
	g_getchain_writable = 0;
	g_bad_chain_call = 1;
	g_bad_chain_n = -1;
	pci_vtinput_notify_statusq(&sc, &vq);
	ATF_CHECK(g_host_write_calls == 1);
	ATF_CHECK(g_rel_calls == 1);
	ATF_CHECK(g_end_calls == 1);
}

ATF_TC_WITHOUT_HEAD(in_order_completion);
ATF_TC_BODY(in_order_completion, tc)
{
	struct pci_vtinput_softc sc;
	struct vtinput_eventqueue queue;
	struct vtinput_event events[3];
	struct input_event host_event;
	struct vqueue_info vq;

	ATF_CHECK((vtinput_vi_consts.vc_hv_caps & VIRTIO_F_IN_ORDER) != 0);

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	memset(&vq, 0, sizeof(vq));
	vq.vq_qsize = VTINPUT_RINGSZ;
	sc.vsc_fd = 10;
	g_descs = nitems(events);
	g_getchain_readable = 1;
	g_getchain_writable = 0;
	for (size_t i = 0; i < nitems(events); i++) {
		events[i].type = EV_LED;
		events[i].code = LED_CAPSL;
		events[i].value = i;
		memcpy(g_iov_buf[i], &events[i], VIRTIO14_INPUT_EVENT_SIZE);
	}
	pci_vtinput_notify_statusq(&sc, &vq);
	ATF_CHECK(g_host_write_calls == (int)nitems(events));
	ATF_CHECK(g_rel_calls == (int)nitems(events));
	for (size_t i = 0; i < nitems(events); i++)
		ATF_CHECK(g_rel_idx[i] == i && g_rel_len[i] == 0);

	reset_mocks();
	memset(&queue, 0, sizeof(queue));
	memset(&host_event, 0, sizeof(host_event));
	host_event.type = EV_KEY;
	host_event.code = KEY_A;
	g_descs = nitems(events);
	for (size_t i = 0; i < nitems(events); i++) {
		host_event.value = i;
		ATF_REQUIRE(vtinput_eventqueue_add_event(&queue,
		    &host_event) == 0);
		events[i] = queue.events[i].event;
	}
	vtinput_eventqueue_send_events(&queue, &vq);
	ATF_CHECK(g_rel_calls == (int)nitems(events));
	for (size_t i = 0; i < nitems(events); i++) {
		ATF_CHECK(g_rel_idx[i] == i &&
		    g_rel_len[i] == VIRTIO14_INPUT_EVENT_SIZE);
		ATF_CHECK(memcmp(g_iov_buf[i], &events[i],
		    VIRTIO14_INPUT_EVENT_SIZE) == 0);
	}
	free(queue.events);
}

ATF_TC_WITHOUT_HEAD(partial_frame_rollback);
ATF_TC_BODY(partial_frame_rollback, tc)
{
	struct vtinput_eventqueue queue;
	struct vqueue_info vq;
	struct input_event event;

	reset_mocks();
	memset(&queue, 0, sizeof(queue));
	memset(&vq, 0, sizeof(vq));
	vq.vq_qsize = VTINPUT_RINGSZ;
	memset(&event, 0, sizeof(event));
	ATF_REQUIRE(vtinput_eventqueue_add_event(&queue, &event) == 0);
	ATF_REQUIRE(vtinput_eventqueue_add_event(&queue, &event) == 0);
	g_descs = 2;
	g_bad_chain_call = 1;
	g_bad_chain_n = 2;
	vtinput_eventqueue_send_events(&queue, &vq);
	ATF_CHECK(g_getchain_calls == 2);
	ATF_CHECK(g_rel_calls == 2);
	ATF_CHECK(g_rel_idx[0] == 0 && g_rel_idx[1] == 1);
	ATF_CHECK(g_rel_len[0] == 0 && g_rel_len[1] == 0);
	ATF_CHECK(g_ret_calls == 0 && g_ret_count == 0);
	ATF_CHECK(g_end_calls == 1);
	ATF_CHECK(queue.idx == 0);
	free(queue.events);
}

ATF_TC_WITHOUT_HEAD(oversized_frame_dropped);
ATF_TC_BODY(oversized_frame_dropped, tc)
{
	struct pci_vtinput_softc sc;
	struct vtinput_event delivered;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_vs = &sc.vsc_vs;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_qsize = VTINPUT_RINGSZ;
	vq_set_allocated(&sc.vsc_queues[VTINPUT_EVENTQ], true);
	sc.vsc_eventqueue.size = VTINPUT_MAX_FRAME_EVENTS;
	sc.vsc_eventqueue.idx = VTINPUT_MAX_FRAME_EVENTS;
	sc.vsc_eventqueue.events = calloc(sc.vsc_eventqueue.size,
	    sizeof(*sc.vsc_eventqueue.events));
	ATF_REQUIRE(sc.vsc_eventqueue.events != NULL);
	/* Model an oversized partial frame, not a completed SYN_REPORT. */
	sc.vsc_eventqueue.events[sc.vsc_eventqueue.idx - 1].event.type =
	    htole16(EV_KEY);
	sc.vsc_eventqueue.events[sc.vsc_eventqueue.idx - 1].event.code =
	    htole16(KEY_A);
	g_descs = 2;
	g_read_events[0].type = EV_SYN;
	g_read_events[0].code = SYN_REPORT;
	g_read_event_count = 1;
	vtinput_read_event(10, EVF_READ, &sc);
	ATF_CHECK(sc.vsc_eventqueue.idx == 0);
	ATF_CHECK(!sc.vsc_drop_frame);
	ATF_CHECK_EQ(g_rel_calls, 2);
	memcpy(&delivered, g_iov_buf[0], VIRTIO14_INPUT_EVENT_SIZE);
	ATF_CHECK_EQ(le16toh(delivered.type), VIRTIO14_INPUT_EV_SYN);
	ATF_CHECK_EQ(le16toh(delivered.code),
	    VIRTIO14_INPUT_SYN_DROPPED);
	memcpy(&delivered, g_iov_buf[1], VIRTIO14_INPUT_EVENT_SIZE);
	ATF_CHECK_EQ(le16toh(delivered.type), VIRTIO14_INPUT_EV_SYN);
	ATF_CHECK_EQ(le16toh(delivered.code), VIRTIO14_INPUT_SYN_REPORT);
	free(sc.vsc_eventqueue.events);
}

ATF_TC_WITHOUT_HEAD(frame_larger_than_guest_ring_reports_loss);
ATF_TC_BODY(frame_larger_than_guest_ring_reports_loss, tc)
{
	struct pci_vtinput_softc sc;
	struct vtinput_event delivered;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_vs = &sc.vsc_vs;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_qsize = 4;
	vq_set_allocated(&sc.vsc_queues[VTINPUT_EVENTQ], true);
	for (size_t i = 0; i < 5; i++) {
		g_read_events[i].type = EV_KEY;
		g_read_events[i].code = KEY_A;
		g_read_events[i].value = (int32_t)i;
	}
	g_read_events[5].type = EV_SYN;
	g_read_events[5].code = SYN_REPORT;
	g_read_event_count = 6;
	g_descs = 2;
	vtinput_read_event(10, EVF_READ, &sc);
	ATF_CHECK_EQ(g_getchain_calls, 2);
	ATF_CHECK_EQ(g_rel_calls, 2);
	ATF_CHECK_EQ(sc.vsc_eventqueue.idx, 0);
	ATF_CHECK(!sc.vsc_drop_frame);
	memcpy(&delivered, g_iov_buf[0], VIRTIO14_INPUT_EVENT_SIZE);
	ATF_CHECK_EQ(le16toh(delivered.type), VIRTIO14_INPUT_EV_SYN);
	ATF_CHECK_EQ(le16toh(delivered.code),
	    VIRTIO14_INPUT_SYN_DROPPED);
	memcpy(&delivered, g_iov_buf[1], VIRTIO14_INPUT_EVENT_SIZE);
	ATF_CHECK_EQ(le16toh(delivered.type), VIRTIO14_INPUT_EV_SYN);
	ATF_CHECK_EQ(le16toh(delivered.code), VIRTIO14_INPUT_SYN_REPORT);
	free(sc.vsc_eventqueue.events);
}

ATF_TC_WITHOUT_HEAD(syn_dropped_resynchronizes_guest);
ATF_TC_BODY(syn_dropped_resynchronizes_guest, tc)
{
	struct pci_vtinput_softc sc;
	struct vtinput_event delivered;
	pthread_mutex_t mtx;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	ATF_REQUIRE_EQ(pthread_mutex_init(&mtx, NULL), 0);
	sc.vsc_vs.vs_mtx = &mtx;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_vs = &sc.vsc_vs;
	vq_set_allocated(&sc.vsc_queues[VTINPUT_EVENTQ], true);
	g_descs = 2;

	/* Staged and post-overrun state must not reach the guest. */
	g_read_events[0].type = EV_KEY;
	g_read_events[0].code = KEY_A;
	g_read_events[0].value = 1;
	g_read_events[1].type = VIRTIO14_INPUT_EV_SYN;
	g_read_events[1].code = VIRTIO14_INPUT_SYN_DROPPED;
	g_read_events[2].type = EV_KEY;
	g_read_events[2].code = KEY_A;
	g_read_events[2].value = 0;
	g_read_events[3].type = EV_ABS;
	g_read_events[3].code = ABS_X;
	g_read_events[3].value = 1234;
	g_read_events[4].type = VIRTIO14_INPUT_EV_SYN;
	g_read_events[4].code = VIRTIO14_INPUT_SYN_REPORT;
	g_read_event_count = 5;

	vtinput_read_event(10, EVF_READ, &sc);

	ATF_CHECK_EQ(g_read_event_index, 5);
	ATF_CHECK_EQ(g_rel_calls, 2);
	ATF_CHECK_EQ(g_rel_len[0], VIRTIO14_INPUT_EVENT_SIZE);
	ATF_CHECK_EQ(g_rel_len[1], VIRTIO14_INPUT_EVENT_SIZE);
	memcpy(&delivered, g_iov_buf[0], VIRTIO14_INPUT_EVENT_SIZE);
	ATF_CHECK_EQ(le16toh(delivered.type), VIRTIO14_INPUT_EV_SYN);
	ATF_CHECK_EQ(le16toh(delivered.code),
	    VIRTIO14_INPUT_SYN_DROPPED);
	memcpy(&delivered, g_iov_buf[1], VIRTIO14_INPUT_EVENT_SIZE);
	ATF_CHECK_EQ(le16toh(delivered.type), VIRTIO14_INPUT_EV_SYN);
	ATF_CHECK_EQ(le16toh(delivered.code), VIRTIO14_INPUT_SYN_REPORT);
	ATF_CHECK_EQ(sc.vsc_eventqueue.idx, 0);
	ATF_CHECK(!sc.vsc_drop_frame);
	ATF_CHECK(!sc.vsc_resync_frame);

	free(sc.vsc_eventqueue.events);
	pthread_mutex_destroy(&mtx);
}

ATF_TC_WITHOUT_HEAD(reset_discards_stale_events);
ATF_TC_BODY(reset_discards_stale_events, tc)
{
	struct pci_vtinput_softc sc;
	pthread_mutex_t mtx;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_eventqueue.idx = 2;
	sc.vsc_drop_frame = true;
	sc.vsc_resync_frame = true;
	memset(&sc.vsc_config, 0xa5, sizeof(sc.vsc_config));
	sc.vsc_config_valid = 1;
	pci_vtinput_reset(&sc);
	ATF_CHECK(sc.vsc_eventqueue.idx == 0);
	ATF_CHECK(!sc.vsc_drop_frame);
	ATF_CHECK(!sc.vsc_resync_frame);
	ATF_CHECK(!sc.vsc_config_valid);
	for (size_t i = 0; i < sizeof(sc.vsc_config); i++)
		ATF_CHECK_EQ(((uint8_t *)&sc.vsc_config)[i], 0);

	ATF_REQUIRE(pthread_mutex_init(&mtx, NULL) == 0);
	sc.vsc_vs.vs_mtx = &mtx;
	g_read_events[0].type = EV_KEY;
	g_read_events[1].type = EV_SYN;
	g_read_event_count = 2;
	vtinput_read_event(10, EVF_READ, &sc);
	ATF_CHECK(g_read_event_index == 2);
	ATF_CHECK(sc.vsc_eventqueue.idx == 0);
	ATF_CHECK(g_rel_calls == 0);
	pthread_mutex_destroy(&mtx);
}

ATF_TC_WITHOUT_HEAD(queue_reset_drops_host_events);
ATF_TC_BODY(queue_reset_drops_host_events, tc)
{
	struct pci_vtinput_softc sc;
	pthread_mutex_t mtx;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	ATF_REQUIRE(pthread_mutex_init(&mtx, NULL) == 0);
	sc.vsc_vs.vs_mtx = &mtx;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_vs = &sc.vsc_vs;
	/* Queue reset has completed, so VQ_ALLOC and all mappings are zero. */
	g_read_events[0].type = EV_KEY;
	g_read_events[1].type = EV_SYN;
	g_read_events[1].code = SYN_REPORT;
	g_read_event_count = 2;

	vtinput_read_event(10, EVF_READ, &sc);

	ATF_CHECK_EQ(g_read_event_index, 2);
	ATF_CHECK_EQ(g_getchain_calls, 0);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(g_end_calls, 0);
	pthread_mutex_destroy(&mtx);
}

ATF_TC_WITHOUT_HEAD(queue_reset_drains_before_fast_reenable);
ATF_TC_BODY(queue_reset_drains_before_fast_reenable, tc)
{
	struct pci_vtinput_softc sc;
	pthread_mutex_t mtx;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_evp = (struct mevent *)(uintptr_t)1;
	sc.vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	ATF_REQUIRE(pthread_mutex_init(&mtx, NULL) == 0);
	sc.vsc_vs.vs_mtx = &mtx;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_vs = &sc.vsc_vs;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_num = VTINPUT_EVENTQ;
	g_read_events[0].type = EV_KEY;
	g_read_events[1].type = EV_SYN;
	g_read_events[1].code = SYN_REPORT;
	g_read_event_count = 2;

	ATF_REQUIRE_EQ(pci_vtinput_qreset(&sc,
	    &sc.vsc_queues[VTINPUT_EVENTQ], 1), 0);
	ATF_CHECK_EQ(g_read_event_index, 2);

	/* Model an immediate replacement queue before mevent dispatch. */
	vq_set_allocated(&sc.vsc_queues[VTINPUT_EVENTQ], true);
	vtinput_read_event(10, EVF_READ, &sc);
	ATF_CHECK_EQ(g_getchain_calls, 0);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(g_end_calls, 0);
	pthread_mutex_destroy(&mtx);
}

ATF_TC_WITHOUT_HEAD(queue_reset_isolated);
ATF_TC_BODY(queue_reset_isolated, tc)
{
	struct pci_vtinput_softc sc;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_queues[VTINPUT_EVENTQ].vq_num = VTINPUT_EVENTQ;
	sc.vsc_queues[VTINPUT_STATUSQ].vq_num = VTINPUT_STATUSQ;
	sc.vsc_eventqueue.idx = 2;
	sc.vsc_drop_frame = true;
	sc.vsc_resync_frame = true;

	ATF_CHECK_EQ(pci_vtinput_qreset(&sc,
	    &sc.vsc_queues[VTINPUT_STATUSQ], 1), 0);
	ATF_CHECK_EQ(sc.vsc_eventqueue.idx, 2);
	ATF_CHECK(sc.vsc_drop_frame);
	ATF_CHECK(sc.vsc_resync_frame);

	ATF_CHECK_EQ(pci_vtinput_qreset(&sc,
	    &sc.vsc_queues[VTINPUT_EVENTQ], 2), 0);
	ATF_CHECK_EQ(sc.vsc_eventqueue.idx, 0);
	ATF_CHECK(!sc.vsc_drop_frame);
	ATF_CHECK(!sc.vsc_resync_frame);

	sc.vsc_queues[VTINPUT_EVENTQ].vq_num = VTINPUT_MAXQ;
	ATF_CHECK_EQ(pci_vtinput_qreset(&sc,
	    &sc.vsc_queues[VTINPUT_EVENTQ], 3), EINVAL);
}

ATF_TC_WITHOUT_HEAD(suspend_discards_partial_frame);
ATF_TC_BODY(suspend_discards_partial_frame, tc)
{
	struct pci_vtinput_softc sc;
	struct input_event event;

	memset(&sc, 0, sizeof(sc));
	memset(&event, 0, sizeof(event));
	event.type = EV_KEY;
	event.code = KEY_A;
	event.value = 1;
	ATF_REQUIRE_EQ(vtinput_eventqueue_add_event(&sc.vsc_eventqueue,
	    &event), 0);
	sc.vsc_drop_frame = true;
	sc.vsc_resync_frame = true;

	ATF_CHECK((vtinput_vi_consts.vc_hv_caps &
	    VIRTIO14_F_SUSPEND) != 0);
	ATF_CHECK(vtinput_vi_consts.vc_suspend ==
	    pci_vtinput_suspend_device);
	ATF_CHECK(vtinput_vi_consts.vc_resume_device ==
	    pci_vtinput_resume_device);
	ATF_REQUIRE_EQ(pci_vtinput_suspend_device(&sc), 0);
	ATF_CHECK_EQ(sc.vsc_eventqueue.idx, 0);
	ATF_CHECK(!sc.vsc_drop_frame);
	ATF_CHECK(!sc.vsc_resync_frame);

	free(sc.vsc_eventqueue.events);
}

ATF_TC_WITHOUT_HEAD(config_bounds);
ATF_TC_BODY(config_bounds, tc)
{
	struct pci_vtinput_softc sc;
	uint32_t value;

	memset(&sc, 0, sizeof(sc));
	value = UINT32_MAX;
	ATF_CHECK(pci_vtinput_cfgread(&sc, -1, 1, &value) == 0);
	ATF_CHECK(value == 0);
	value = UINT32_MAX;
	ATF_CHECK(pci_vtinput_cfgread(&sc, VIRTIO14_INPUT_CONFIG_SIZE, 4,
	    &value) == 0);
	ATF_CHECK(value == 0);
	value = UINT32_MAX;
	ATF_CHECK(pci_vtinput_cfgread(&sc, INT_MAX, INT_MAX, &value) == 0);
	ATF_CHECK(value == 0);
	ATF_CHECK(pci_vtinput_cfgread(&sc, 0, 3, &value) == 0);
	ATF_CHECK_EQ(pci_vtinput_cfgread(&sc, 0, 1, NULL), EINVAL);
	ATF_CHECK(pci_vtinput_cfgwrite(&sc, -1, 1, 0) == 1);
	ATF_CHECK(pci_vtinput_cfgwrite(&sc, INT_MAX, INT_MAX, 0) == 1);
	ATF_CHECK(pci_vtinput_cfgwrite(&sc, 1, 2, 0) == 1);
	ATF_CHECK(pci_vtinput_cfgwrite(&sc, 0, 2,
	    VIRTIO14_INPUT_CFG_ID_NAME |
	    VIRTIO14_INPUT_CFG_EV_BITS << 8) == 0);
	ATF_CHECK(sc.vsc_config.select == VIRTIO14_INPUT_CFG_ID_NAME);
	ATF_CHECK(sc.vsc_config.subsel == VIRTIO14_INPUT_CFG_EV_BITS);
}

ATF_TC_WITHOUT_HEAD(config_responses);
ATF_TC_BODY(config_responses, tc)
{
	struct pci_vtinput_softc sc;
	uint32_t value;

	reset_mocks();
	memset(&sc, 0xa5, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_config.select = VTINPUT_CFG_ABS_INFO;
	sc.vsc_config.subsel = ABS_X;
	sc.vsc_config_valid = 0;
	g_ioctl_abs_success = true;
	value = 0;
	ATF_CHECK_EQ(pci_vtinput_cfgread(&sc,
	    VIRTIO14_INPUT_CONFIG_SIZE_OFF, 1, &value), 0);
	ATF_CHECK_EQ(value, VIRTIO14_INPUT_ABSINFO_SIZE);
	ATF_CHECK_EQ(g_last_ioctl, EVIOCGABS(ABS_X));
	ATF_CHECK_EQ(sc.vsc_config.u.abs.min, (uint32_t)-100);
	ATF_CHECK_EQ(sc.vsc_config.u.abs.max, 100);
	ATF_CHECK_EQ(sc.vsc_config.u.abs.fuzz, 2);
	ATF_CHECK_EQ(sc.vsc_config.u.abs.flat, 3);
	ATF_CHECK_EQ(sc.vsc_config.u.abs.res, 4);
	for (size_t i = 0; i < VIRTIO14_INPUT_CONFIG_RESERVED_SIZE; i++)
		ATF_CHECK_EQ(sc.vsc_config.reserved[i], 0);

	memset(sc.vsc_config.u.bitmap, 0xa5,
	    VIRTIO14_INPUT_CONFIG_UNION_SIZE);
	sc.vsc_config.select = UINT8_MAX;
	sc.vsc_config.subsel = UINT8_MAX;
	sc.vsc_config.size = UINT8_MAX;
	sc.vsc_config_valid = 0;
	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtinput_cfgread(&sc,
	    VIRTIO14_INPUT_CONFIG_SIZE_OFF, 1, &value), 0);
	ATF_CHECK_EQ(value, 0);
	ATF_CHECK(sc.vsc_config_valid);
	for (size_t i = 0; i < VIRTIO14_INPUT_CONFIG_UNION_SIZE; i++)
		ATF_CHECK_EQ(sc.vsc_config.u.bitmap[i], 0);

	sc.vsc_config.select = VTINPUT_CFG_ID_NAME;
	sc.vsc_config.subsel = 0;
	sc.vsc_config_valid = 0;
	g_ioctl_name_success = true;
	value = 0;
	ATF_CHECK_EQ(pci_vtinput_cfgread(&sc,
	    VIRTIO14_INPUT_CONFIG_SIZE_OFF, 1, &value), 0);
	ATF_CHECK_EQ(value, strlen("mock-input"));
	ATF_CHECK(memcmp(sc.vsc_config.u.string, "mock-input",
	    strlen("mock-input")) == 0);
	for (size_t i = strlen("mock-input");
	    i < VIRTIO14_INPUT_CONFIG_STRING_SIZE; i++)
		ATF_CHECK_EQ(sc.vsc_config.u.string[i], 0);
}

ATF_TC_WITHOUT_HEAD(config_selector_matrix);
ATF_TC_BODY(config_selector_matrix, tc)
{
	struct pci_vtinput_softc sc;
	uint32_t value;

	/* An unsupported serial number is represented by a zero size. */
	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_config.select = VIRTIO14_INPUT_CFG_ID_SERIAL;
	ATF_CHECK_EQ(pci_vtinput_cfgread(&sc,
	    VIRTIO14_INPUT_CONFIG_SIZE_OFF, 1, &value), 0);
	ATF_CHECK_EQ(value, 0);
	ATF_CHECK_EQ(g_last_ioctl, 0);

	/* Device IDs are converted into the document's little-endian fields. */
	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_config.select = VIRTIO14_INPUT_CFG_ID_DEVIDS;
	g_ioctl_devids_success = true;
	ATF_CHECK_EQ(pci_vtinput_cfgread(&sc,
	    VIRTIO14_INPUT_CONFIG_SIZE_OFF, 1, &value), 0);
	ATF_CHECK_EQ(value, VIRTIO14_INPUT_DEVIDS_SIZE);
	ATF_CHECK_EQ(g_last_ioctl, EVIOCGID);
	ATF_CHECK_EQ(le16toh(sc.vsc_config.u.ids.bustype),
	    UINT16_C(0x1122));
	ATF_CHECK_EQ(le16toh(sc.vsc_config.u.ids.vendor),
	    UINT16_C(0x3344));
	ATF_CHECK_EQ(le16toh(sc.vsc_config.u.ids.product),
	    UINT16_C(0x5566));
	ATF_CHECK_EQ(le16toh(sc.vsc_config.u.ids.version),
	    UINT16_C(0x7788));

	/* Bitmap size is the last nonzero byte, not the ioctl buffer capacity. */
	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_config.select = VIRTIO14_INPUT_CFG_PROP_BITS;
	g_ioctl_prop_success = true;
	ATF_CHECK_EQ(pci_vtinput_cfgread(&sc,
	    VIRTIO14_INPUT_CONFIG_SIZE_OFF, 1, &value), 0);
	ATF_CHECK_EQ(value, 4);
	ATF_CHECK_EQ(sc.vsc_config.u.bitmap[3], 0x80);
	ATF_CHECK_EQ(sc.vsc_config.u.bitmap[4], 0);

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_config.select = VIRTIO14_INPUT_CFG_EV_BITS;
	sc.vsc_config.subsel = EV_KEY;
	g_ioctl_ev_success = true;
	ATF_CHECK_EQ(pci_vtinput_cfgread(&sc,
	    VIRTIO14_INPUT_CONFIG_SIZE_OFF, 1, &value), 0);
	ATF_CHECK_EQ(value, 18);
	ATF_CHECK_EQ(sc.vsc_config.u.bitmap[17], 0x04);
	ATF_CHECK_EQ(sc.vsc_config.u.bitmap[18], 0);

	/*
	 * Output sound and repeat capabilities use the same byte-stream
	 * bitmap protocol.  An empty host bitmap is a supported empty response,
	 * not an unrecognized selector.
	 */
	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_config.select = VIRTIO14_INPUT_CFG_EV_BITS;
	sc.vsc_config.subsel = EV_SND;
	ATF_CHECK_EQ(pci_vtinput_cfgread(&sc,
	    VIRTIO14_INPUT_CONFIG_SIZE_OFF, 1, &value), 0);
	ATF_CHECK_EQ(value, 0);
	ATF_CHECK_EQ(g_last_ioctl, EVIOCGBIT(EV_SND,
	    howmany(SND_CNT, sizeof(long) * 8) * sizeof(long)));

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_config.select = VIRTIO14_INPUT_CFG_EV_BITS;
	sc.vsc_config.subsel = EV_REP;
	ATF_CHECK_EQ(pci_vtinput_cfgread(&sc,
	    VIRTIO14_INPUT_CONFIG_SIZE_OFF, 1, &value), 0);
	ATF_CHECK_EQ(value, 0);
	ATF_CHECK_EQ(g_last_ioctl, EVIOCGBIT(EV_REP,
	    howmany(REP_CNT, sizeof(long) * 8) * sizeof(long)));

	/* Unsupported event types must return an empty, scrubbed response. */
	reset_mocks();
	memset(&sc, 0xa5, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_config.select = VIRTIO14_INPUT_CFG_EV_BITS;
	sc.vsc_config.subsel = UINT8_MAX;
	sc.vsc_config_valid = 0;
	ATF_CHECK_EQ(pci_vtinput_cfgread(&sc,
	    VIRTIO14_INPUT_CONFIG_SIZE_OFF, 1, &value), 0);
	ATF_CHECK_EQ(value, 0);
	ATF_CHECK_EQ(g_last_ioctl, 0);
	for (size_t i = 0; i < VIRTIO14_INPUT_CONFIG_UNION_SIZE; i++)
		ATF_CHECK_EQ(sc.vsc_config.u.bitmap[i], 0);
}

static void
setup_snapshot_softc(struct pci_vtinput_softc *sc, struct mevent *event)
{
	struct input_event host_event;
	pthread_mutexattr_t attr;

	memset(sc, 0, sizeof(*sc));
	ATF_REQUIRE_EQ(pthread_mutexattr_init(&attr), 0);
	ATF_REQUIRE_EQ(pthread_mutexattr_settype(&attr,
	    PTHREAD_MUTEX_RECURSIVE), 0);
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc->vsc_mtx, &attr), 0);
	ATF_REQUIRE_EQ(pthread_mutexattr_destroy(&attr), 0);
	sc->vsc_mtx_initialized = true;
	sc->vsc_evp = event;
	sc->vsc_evdev = __DECONST(char *, "/dev/input/event-test");
	sc->vsc_evdev_rdev = 42;
	sc->vsc_eventqueue.size = VTINPUT_MAX_PKT_LEN;
	sc->vsc_eventqueue.events = calloc(sc->vsc_eventqueue.size,
	    sizeof(*sc->vsc_eventqueue.events));
	ATF_REQUIRE(sc->vsc_eventqueue.events != NULL);
	sc->vsc_queues[VTINPUT_EVENTQ].vq_qsize = VTINPUT_RINGSZ;
	memset(&host_event, 0, sizeof(host_event));
	host_event.type = EV_KEY;
	host_event.code = KEY_A;
	host_event.value = 1;
	ATF_REQUIRE_EQ(vtinput_eventqueue_add_event(
	    &sc->vsc_eventqueue, &host_event), 0);
	sc->vsc_config.select = VIRTIO14_INPUT_CFG_EV_BITS;
	sc->vsc_config.subsel = EV_KEY;
	sc->vsc_config.size = 2;
	sc->vsc_config.u.bitmap[1] = 0x40;
	sc->vsc_config_valid = 1;
}

static void
destroy_snapshot_softc(struct pci_vtinput_softc *sc)
{

	free(sc->vsc_eventqueue.events);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc->vsc_mtx), 0);
}

int
vi_pci_snapshot(struct vm_snapshot_meta *meta)
{
	struct pci_devinst *pi;
	struct pci_vtinput_softc *sc;

	pi = meta->dev_data;
	if (pi == NULL || pi->pi_arg == NULL)
		return (EINVAL);
	sc = pi->pi_arg;
	g_snapshot_validate_saw_lock =
	    pthread_mutex_isowned_np(&sc->vsc_mtx);
	g_snapshot_validate_calls++;
	return (g_snapshot_validate_result);
}

static int
run_snapshot(struct pci_vtinput_softc *sc, uint8_t *image, size_t size,
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

	error = pci_vtinput_snapshot(sc, &meta);
	if (used != NULL)
		*used = size - meta.buffer.buf_rem;
	return (error);
}

ATF_TC_WITHOUT_HEAD(snapshot_staged_frame_and_atomicity);
ATF_TC_BODY(snapshot_staged_frame_and_atomicity, tc)
{
	struct pci_vtinput_softc destination, source;
	struct mevent destination_event, source_event;
	uint8_t image[2048], obsolete[2048];
	uint8_t saved_tail;
	size_t used;

	reset_mocks();
	setup_snapshot_softc(&source, &source_event);
	ATF_REQUIRE_EQ(run_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	ATF_REQUIRE(used > VIRTIO14_INPUT_CONFIG_SIZE);
	ATF_CHECK_EQ(image[0], (uint8_t)'I');
	ATF_CHECK_EQ(image[1], (uint8_t)'N');
	ATF_CHECK_EQ(image[2], (uint8_t)'P');
	ATF_CHECK_EQ(image[3], (uint8_t)'1');

	setup_snapshot_softc(&destination, &destination_event);
	destination.vsc_config.select = VIRTIO14_INPUT_CFG_ID_NAME;
	destination.vsc_eventqueue.idx = 0;
	ATF_REQUIRE_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), 0);
	ATF_CHECK_EQ(destination.vsc_config.select,
	    VIRTIO14_INPUT_CFG_ID_NAME);
	ATF_CHECK_EQ(destination.vsc_eventqueue.idx, 0);
	ATF_CHECK_EQ(run_snapshot(&destination, image, used - 1,
	    VM_SNAPSHOT_VALIDATE, NULL), E2BIG);
	ATF_CHECK_EQ(destination.vsc_eventqueue.idx, 0);
	ATF_CHECK_EQ(run_snapshot(&destination, image, used - 1,
	    VM_SNAPSHOT_RESTORE, NULL), E2BIG);
	ATF_CHECK_EQ(destination.vsc_config.select,
	    VIRTIO14_INPUT_CFG_ID_NAME);
	ATF_CHECK_EQ(destination.vsc_eventqueue.idx, 0);

	destination.vsc_evdev_rdev++;
	ATF_CHECK_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	ATF_CHECK_EQ(destination.vsc_config.select,
	    VIRTIO14_INPUT_CFG_ID_NAME);
	ATF_CHECK_EQ(destination.vsc_eventqueue.idx, 0);
	destination.vsc_evdev_rdev--;

	/*
	 * INP1 fields through size consume 27 bytes.  The source advertises a
	 * two-byte selector payload, so byte 29 is the first guest-readable tail
	 * byte and must retain the live path's zero value.
	 */
	saved_tail = image[29];
	image[29] = 0xa5;
	ATF_CHECK_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), EINVAL);
	ATF_CHECK_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	ATF_CHECK_EQ(destination.vsc_config.select,
	    VIRTIO14_INPUT_CFG_ID_NAME);
	ATF_CHECK_EQ(destination.vsc_eventqueue.idx, 0);
	image[29] = saved_tail;

	/* A staged frame can never exceed the event virtqueue capacity. */
	memcpy(obsolete, image, used);
	obsolete[155] = VTINPUT_RINGSZ + 1;
	obsolete[156] = 0;
	obsolete[157] = 0;
	obsolete[158] = 0;
	ATF_REQUIRE_EQ(run_snapshot(&destination, obsolete, used,
	    VM_SNAPSHOT_VALIDATE, NULL), EINVAL);
	ATF_REQUIRE_EQ(run_snapshot(&destination, obsolete, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	ATF_CHECK_EQ(destination.vsc_eventqueue.idx, 0);

	/* Unreleased obsolete versions are rejected without changing state. */
	memcpy(obsolete, image, used);
	obsolete[4] = 1;
	obsolete[5] = 0;
	obsolete[6] = 0;
	obsolete[7] = 0;
	ATF_REQUIRE_EQ(run_snapshot(&destination, obsolete, used,
	    VM_SNAPSHOT_RESTORE, NULL), ENOTSUP);
	ATF_CHECK_EQ(destination.vsc_config.select,
	    VIRTIO14_INPUT_CFG_ID_NAME);
	ATF_CHECK_EQ(destination.vsc_eventqueue.idx, 0);

	ATF_REQUIRE_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(destination.vsc_config.select,
	    VIRTIO14_INPUT_CFG_EV_BITS);
	ATF_CHECK_EQ(destination.vsc_config.subsel, EV_KEY);
	ATF_CHECK_EQ(destination.vsc_eventqueue.idx, 1);
	ATF_CHECK_EQ(le16toh(
	    destination.vsc_eventqueue.events[0].event.type), EV_KEY);
	ATF_CHECK_EQ(le16toh(
	    destination.vsc_eventqueue.events[0].event.code), KEY_A);
	ATF_CHECK_EQ(le32toh(
	    destination.vsc_eventqueue.events[0].event.value), 1);

	destroy_snapshot_softc(&destination);
	destroy_snapshot_softc(&source);
}

ATF_TC_WITHOUT_HEAD(snapshot_resynchronization_state);
ATF_TC_BODY(snapshot_resynchronization_state, tc)
{
	struct pci_vtinput_softc destination, source;
	struct input_event host_event;
	struct mevent destination_event, source_event;
	uint8_t image[2048], saved_resync;
	size_t used;

	reset_mocks();
	setup_snapshot_softc(&source, &source_event);
	vtinput_eventqueue_clear(&source.vsc_eventqueue);
	memset(&host_event, 0, sizeof(host_event));
	host_event.type = VIRTIO14_INPUT_EV_SYN;
	host_event.code = VIRTIO14_INPUT_SYN_DROPPED;
	ATF_REQUIRE_EQ(vtinput_eventqueue_add_event(
	    &source.vsc_eventqueue, &host_event), 0);
	source.vsc_resync_frame = true;
	ATF_REQUIRE_EQ(run_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	ATF_CHECK_EQ(image[4], 2);

	setup_snapshot_softc(&destination, &destination_event);
	destination.vsc_eventqueue.idx = 0;
	ATF_REQUIRE_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), 0);
	saved_resync = image[18];
	image[18] = 2;
	ATF_CHECK_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), EINVAL);
	ATF_CHECK_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	ATF_CHECK_EQ(destination.vsc_eventqueue.idx, 0);
	ATF_CHECK(!destination.vsc_resync_frame);
	image[18] = saved_resync;

	ATF_REQUIRE_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK(destination.vsc_resync_frame);
	ATF_CHECK(!destination.vsc_drop_frame);
	ATF_CHECK_EQ(destination.vsc_eventqueue.idx, 1);
	ATF_CHECK_EQ(le16toh(
	    destination.vsc_eventqueue.events[0].event.type),
	    VIRTIO14_INPUT_EV_SYN);
	ATF_CHECK_EQ(le16toh(
	    destination.vsc_eventqueue.events[0].event.code),
	    VIRTIO14_INPUT_SYN_DROPPED);

	destroy_snapshot_softc(&destination);
	destroy_snapshot_softc(&source);
}

ATF_TC_WITHOUT_HEAD(snapshot_preflight_is_locally_serialized);
ATF_TC_BODY(snapshot_preflight_is_locally_serialized, tc)
{
	struct mevent event;
	struct pci_devinst pi;
	struct pci_vtinput_softc sc;
	struct vm_snapshot_meta meta = {
		.op = VM_SNAPSHOT_VALIDATE,
	};

	reset_mocks();
	setup_snapshot_softc(&sc, &event);
	memset(&pi, 0, sizeof(pi));
	pi.pi_arg = &sc;
	meta.dev_data = &pi;

	ATF_REQUIRE_EQ(pci_vtinput_snapshot_validate(&meta), 0);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 1);
	ATF_CHECK(g_snapshot_validate_saw_lock);
	ATF_CHECK_EQ(pthread_mutex_trylock(&sc.vsc_mtx), 0);
	pthread_mutex_unlock(&sc.vsc_mtx);

	/* The recursive serializer composes with checkpoint pause ownership. */
	pthread_mutex_lock(&sc.vsc_mtx);
	g_snapshot_validate_saw_lock = false;
	ATF_REQUIRE_EQ(pci_vtinput_snapshot_validate(&meta), 0);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 2);
	ATF_CHECK(g_snapshot_validate_saw_lock);
	pthread_mutex_unlock(&sc.vsc_mtx);

	meta.dev_data = NULL;
	ATF_CHECK_EQ(pci_vtinput_snapshot_validate(&meta), EINVAL);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 2);
	destroy_snapshot_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(checkpoint_event_source_lifecycle);
ATF_TC_BODY(checkpoint_event_source_lifecycle, tc)
{
	struct pci_vtinput_softc sc;
	struct mevent event;

	reset_mocks();
	setup_snapshot_softc(&sc, &event);
	g_mevent_disable_error = EIO;
	ATF_CHECK_EQ(pci_vtinput_pause(&sc), EIO);
	ATF_CHECK_EQ(g_mevent_disable_calls, 1);

	g_mevent_disable_error = 0;
	ATF_REQUIRE_EQ(pci_vtinput_pause(&sc), 0);
	ATF_CHECK_EQ(pci_vtinput_pause(&sc), EBUSY);
	ATF_CHECK_EQ(g_mevent_disable_calls, 2);
	g_mevent_enable_error = EBUSY;
	ATF_CHECK_EQ(pci_vtinput_resume(&sc), EBUSY);
	/* A failed resume is retryable without retaining the private mutex. */
	ATF_REQUIRE_EQ(pthread_mutex_trylock(&sc.vsc_mtx), 0);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);
	g_mevent_enable_error = 0;
	ATF_REQUIRE_EQ(pci_vtinput_resume(&sc), 0);
	ATF_REQUIRE_EQ(pthread_mutex_trylock(&sc.vsc_mtx), 0);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);
	ATF_CHECK_EQ(g_mevent_enable_calls, 2);

	destroy_snapshot_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(virtio_1_4_wire_layout);
ATF_TC_BODY(virtio_1_4_wire_layout, tc)
{
	/* VirtIO 1.4 sections 5.8.4 and 5.8.6. */
	ATF_CHECK_EQ(sizeof(struct vtinput_config),
	    VIRTIO14_INPUT_CONFIG_SIZE);
	ATF_CHECK_EQ(sizeof(struct vtinput_absinfo),
	    VIRTIO14_INPUT_ABSINFO_SIZE);
	ATF_CHECK_EQ(sizeof(struct vtinput_devids),
	    VIRTIO14_INPUT_DEVIDS_SIZE);
	ATF_CHECK_EQ(sizeof(struct vtinput_event),
	    VIRTIO14_INPUT_EVENT_SIZE);
	ATF_CHECK_EQ(offsetof(struct vtinput_event, type),
	    VIRTIO14_INPUT_EVENT_TYPE_OFF);
	ATF_CHECK_EQ(offsetof(struct vtinput_event, code),
	    VIRTIO14_INPUT_EVENT_CODE_OFF);
	ATF_CHECK_EQ(offsetof(struct vtinput_event, value),
	    VIRTIO14_INPUT_EVENT_VALUE_OFF);
	ATF_CHECK_EQ(offsetof(struct vtinput_config, select),
	    VIRTIO14_INPUT_CONFIG_SELECT_OFF);
	ATF_CHECK_EQ(offsetof(struct vtinput_config, subsel),
	    VIRTIO14_INPUT_CONFIG_SUBSEL_OFF);
	ATF_CHECK_EQ(offsetof(struct vtinput_config, size),
	    VIRTIO14_INPUT_CONFIG_SIZE_OFF);
	ATF_CHECK_EQ(offsetof(struct vtinput_config, u),
	    VIRTIO14_INPUT_CONFIG_UNION_OFF);
}

ATF_TC_WITHOUT_HEAD(resume_device_is_noop);
ATF_TC_BODY(resume_device_is_noop, tc)
{
	struct pci_vtinput_softc sc;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	/* The device carries no transport state that survives a live resume. */
	ATF_CHECK_EQ(pci_vtinput_resume_device(&sc), 0);
	ATF_CHECK(vtinput_vi_consts.vc_resume_device ==
	    pci_vtinput_resume_device);
}

ATF_TC_WITHOUT_HEAD(debug_env_and_verbose_paths);
ATF_TC_BODY(debug_env_and_verbose_paths, tc)
{
	struct pci_devinst pi;
	struct nvlist nvl;
	struct pci_vtinput_softc sc;
	struct vqueue_info vq;
	const uint8_t status_wire[VIRTIO14_INPUT_EVENT_SIZE] = {
		VIRTIO14_INPUT_EV_SYN, 0x00, VIRTIO14_INPUT_SYN_REPORT, 0x00,
		0x00, 0x00, 0x00, 0x00
	};

	/* Verbose selection through the environment, level >= 2. */
	reset_mocks();
	ATF_REQUIRE_EQ(setenv("BHYVE_VTINPUT_DEBUG", "2", 1), 0);
	memset(&pi, 0, sizeof(pi));
	ATF_REQUIRE_EQ(pci_vtinput_init(&pi, &nvl), 0);
	ATF_CHECK_EQ(pci_vtinput_debug, 2);
	free_input_softc(&pi);

	/*
	 * A non-numeric or non-positive level still enables base tracing so the
	 * operator sees output.  Confirm the floor clamp.
	 */
	reset_mocks();
	ATF_REQUIRE_EQ(setenv("BHYVE_VTINPUT_DEBUG", "0", 1), 0);
	memset(&pi, 0, sizeof(pi));
	ATF_REQUIRE_EQ(pci_vtinput_init(&pi, &nvl), 0);
	ATF_CHECK_EQ(pci_vtinput_debug, 1);
	free_input_softc(&pi);
	ATF_REQUIRE_EQ(unsetenv("BHYVE_VTINPUT_DEBUG"), 0);

	/* Drive a successful status write with verbose tracing active. */
	pci_vtinput_debug = 2;
	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	memset(&vq, 0, sizeof(vq));
	vq.vq_qsize = VTINPUT_RINGSZ;
	sc.vsc_fd = 10;
	memcpy(g_iov_buf[0], status_wire, sizeof(status_wire));
	g_descs = 1;
	g_getchain_readable = 1;
	g_getchain_writable = 0;
	pci_vtinput_notify_statusq(&sc, &vq);
	ATF_CHECK_EQ(g_host_write_calls, 1);
	pci_vtinput_notify_eventq(&sc, &sc.vsc_queues[VTINPUT_EVENTQ]);
	pci_vtinput_debug = 0;
}

ATF_TC_WITHOUT_HEAD(host_drain_diagnostics);
ATF_TC_BODY(host_drain_diagnostics, tc)
{
	struct pci_vtinput_softc sc;
	struct mevent event;
	pthread_mutex_t mtx;

	/* A short read during reset drain is reported, not treated as a frame. */
	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_evp = &event;
	g_read_events[0].type = EV_KEY;
	g_read_event_count = 1;
	g_read_short = true;
	ATF_CHECK(vtinput_drain_host_events(&sc));

	/* A hard read error on an active queue is logged and ends the batch. */
	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	ATF_REQUIRE_EQ(pthread_mutex_init(&mtx, NULL), 0);
	sc.vsc_vs.vs_mtx = &mtx;
	sc.vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_vs = &sc.vsc_vs;
	vq_set_allocated(&sc.vsc_queues[VTINPUT_EVENTQ], true);
	g_read_event_count = 0;
	g_read_error_errno = EIO;
	vtinput_read_event(10, EVF_READ, &sc);
	ATF_CHECK_EQ(g_getchain_calls, 0);
	pthread_mutex_destroy(&mtx);
}

ATF_TC_WITHOUT_HEAD(statusq_event_variants);
ATF_TC_BODY(statusq_event_variants, tc)
{
	struct pci_vtinput_softc sc;
	struct vqueue_info vq;
	struct vtinput_event msc = {
		.type = htole16(EV_MSC),
		.code = htole16(MSC_SCAN),
		.value = htole32(1),
	};
	struct vtinput_event key = {
		.type = htole16(EV_KEY),
		.code = htole16(KEY_A),
		.value = htole32(1),
	};

	/* EV_MSC is dropped to break the multi-touch echo loop. */
	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	memset(&vq, 0, sizeof(vq));
	vq.vq_qsize = VTINPUT_RINGSZ;
	sc.vsc_fd = 10;
	memcpy(g_iov_buf[0], &msc, VIRTIO14_INPUT_EVENT_SIZE);
	g_descs = 1;
	g_getchain_readable = 1;
	g_getchain_writable = 0;
	pci_vtinput_notify_statusq(&sc, &vq);
	ATF_CHECK_EQ(g_host_write_calls, 0);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len[0] == 0);

	/* A failed host write is completed and logged, never retried forever. */
	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	memcpy(g_iov_buf[0], &key, VIRTIO14_INPUT_EVENT_SIZE);
	g_descs = 1;
	g_getchain_readable = 1;
	g_getchain_writable = 0;
	g_write_force = -1;
	pci_vtinput_notify_statusq(&sc, &vq);
	ATF_CHECK_EQ(g_host_write_calls, 1);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len[0] == 0);

	/* A short host write is likewise completed and logged. */
	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	memcpy(g_iov_buf[0], &key, VIRTIO14_INPUT_EVENT_SIZE);
	g_descs = 1;
	g_getchain_readable = 1;
	g_getchain_writable = 0;
	g_write_force = 1;
	pci_vtinput_notify_statusq(&sc, &vq);
	ATF_CHECK_EQ(g_host_write_calls, 1);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len[0] == 0);

	/*
	 * A descriptor whose iovec lengths overflow SIZE_MAX cannot equal the
	 * required event size and is rejected without a copy.
	 */
	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	g_descs = 1;
	g_getchain_n = 2;
	g_getchain_readable = 2;
	g_getchain_writable = 0;
	g_getchain_overflow = true;
	pci_vtinput_notify_statusq(&sc, &vq);
	ATF_CHECK_EQ(g_host_write_calls, 0);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len[0] == 0);
}

ATF_TC_WITHOUT_HEAD(config_error_paths);
ATF_TC_BODY(config_error_paths, tc)
{
	struct pci_vtinput_softc sc;
	uint32_t value;
	static const uint8_t ev_subsels[] = {
		EV_REL, EV_ABS, EV_MSC, EV_SW, EV_LED,
	};

	/* An unset selector reports a zero-length response without any ioctl. */
	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_config.select = VIRTIO14_INPUT_CFG_UNSET;
	ATF_CHECK_EQ(pci_vtinput_cfgread(&sc,
	    VIRTIO14_INPUT_CONFIG_SIZE_OFF, 1, &value), 0);
	ATF_CHECK_EQ(value, 0);
	ATF_CHECK_EQ(g_last_ioctl, 0);

	/* Each backend query surfaces an ioctl failure as an empty response. */
	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_config.select = VIRTIO14_INPUT_CFG_ID_NAME;
	g_ioctl_name_success = false;
	ATF_CHECK_EQ(pci_vtinput_cfgread(&sc,
	    VIRTIO14_INPUT_CONFIG_SIZE_OFF, 1, &value), 0);
	ATF_CHECK_EQ(value, 0);

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_config.select = VIRTIO14_INPUT_CFG_ID_DEVIDS;
	g_ioctl_devids_success = false;
	ATF_CHECK_EQ(pci_vtinput_cfgread(&sc,
	    VIRTIO14_INPUT_CONFIG_SIZE_OFF, 1, &value), 0);
	ATF_CHECK_EQ(value, 0);

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_config.select = VIRTIO14_INPUT_CFG_PROP_BITS;
	g_ioctl_prop_success = false;
	ATF_CHECK_EQ(pci_vtinput_cfgread(&sc,
	    VIRTIO14_INPUT_CONFIG_SIZE_OFF, 1, &value), 0);
	ATF_CHECK_EQ(value, 0);

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_config.select = VIRTIO14_INPUT_CFG_ABS_INFO;
	sc.vsc_config.subsel = ABS_X;
	g_ioctl_abs_success = false;
	ATF_CHECK_EQ(pci_vtinput_cfgread(&sc,
	    VIRTIO14_INPUT_CONFIG_SIZE_OFF, 1, &value), 0);
	ATF_CHECK_EQ(value, 0);

	/* Every event-bits selector class is dispatched by subselector. */
	for (size_t i = 0; i < nitems(ev_subsels); i++) {
		reset_mocks();
		memset(&sc, 0, sizeof(sc));
		sc.vsc_fd = 10;
		sc.vsc_config.select = VIRTIO14_INPUT_CFG_EV_BITS;
		sc.vsc_config.subsel = ev_subsels[i];
		ATF_CHECK_EQ(pci_vtinput_cfgread(&sc,
		    VIRTIO14_INPUT_CONFIG_SIZE_OFF, 1, &value), 0);
	}

	/* The bitmap helper rejects out-of-range counts. */
	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	ATF_CHECK_EQ(pci_vtinput_get_bitmap(&sc, EVIOCGPROP(0), 0), -1);
	ATF_CHECK_EQ(pci_vtinput_get_bitmap(&sc, EVIOCGPROP(INT_MAX), INT_MAX),
	    -1);
}

ATF_TC_WITHOUT_HEAD(send_events_no_descriptor);
ATF_TC_BODY(send_events_no_descriptor, tc)
{
	struct vtinput_eventqueue queue;
	struct vqueue_info vq;
	struct input_event event;

	reset_mocks();
	memset(&queue, 0, sizeof(queue));
	memset(&vq, 0, sizeof(vq));
	memset(&event, 0, sizeof(event));
	vq.vq_qsize = VTINPUT_RINGSZ;
	ATF_REQUIRE_EQ(vtinput_eventqueue_add_event(&queue, &event), 0);
	/* A descriptor is available, but the ring reports a zero-length chain. */
	g_descs = 1;
	g_getchain_n = 0;
	ATF_CHECK(vtinput_eventqueue_send_events(&queue, &vq));
	ATF_CHECK_EQ(g_getchain_calls, 1);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(g_end_calls, 1);
	ATF_CHECK_EQ(queue.idx, 0);
	free(queue.events);
}

ATF_TC_WITHOUT_HEAD(retained_frame_blocks_new_input);
ATF_TC_BODY(retained_frame_blocks_new_input, tc)
{
	struct pci_vtinput_softc sc;
	struct input_event event;
	pthread_mutex_t mtx;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	ATF_REQUIRE_EQ(pthread_mutex_init(&mtx, NULL), 0);
	sc.vsc_vs.vs_mtx = &mtx;
	sc.vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_vs = &sc.vsc_vs;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_qsize = VTINPUT_RINGSZ;
	vq_set_allocated(&sc.vsc_queues[VTINPUT_EVENTQ], true);

	/* Stage a complete frame that cannot yet be published (no descriptors). */
	memset(&event, 0, sizeof(event));
	event.type = EV_SYN;
	event.code = SYN_REPORT;
	ATF_REQUIRE_EQ(vtinput_eventqueue_add_event(&sc.vsc_eventqueue,
	    &event), 0);
	ATF_REQUIRE(vtinput_eventqueue_frame_complete(&sc.vsc_eventqueue));

	g_descs = 0;
	g_read_events[0].type = EV_KEY;
	g_read_events[0].code = KEY_A;
	g_read_event_count = 1;
	vtinput_read_event(10, EVF_READ, &sc);
	/* No new host events are read while the prior frame is unsent. */
	ATF_CHECK_EQ(g_read_event_index, 0);
	ATF_CHECK_EQ(sc.vsc_eventqueue.idx, 1);
	free(sc.vsc_eventqueue.events);
	pthread_mutex_destroy(&mtx);
}

ATF_TC_WITHOUT_HEAD(drop_frame_report_loss_without_descriptors);
ATF_TC_BODY(drop_frame_report_loss_without_descriptors, tc)
{
	struct pci_vtinput_softc sc;
	pthread_mutex_t mtx;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	ATF_REQUIRE_EQ(pthread_mutex_init(&mtx, NULL), 0);
	sc.vsc_vs.vs_mtx = &mtx;
	sc.vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_vs = &sc.vsc_vs;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_qsize = 2;
	vq_set_allocated(&sc.vsc_queues[VTINPUT_EVENTQ], true);

	for (int i = 0; i < 3; i++) {
		g_read_events[i].type = EV_KEY;
		g_read_events[i].code = KEY_A;
		g_read_events[i].value = i;
	}
	g_read_events[3].type = EV_SYN;
	g_read_events[3].code = SYN_REPORT;
	g_read_event_count = 4;
	/* No descriptors: the oversized frame's loss report cannot be delivered. */
	g_descs = 0;
	vtinput_read_event(10, EVF_READ, &sc);
	ATF_CHECK(!sc.vsc_drop_frame);
	ATF_CHECK_EQ(g_rel_calls, 0);
	free(sc.vsc_eventqueue.events);
	pthread_mutex_destroy(&mtx);
}

ATF_TC_WITHOUT_HEAD(resync_completes_after_syn_report);
ATF_TC_BODY(resync_completes_after_syn_report, tc)
{
	struct pci_vtinput_softc sc;
	struct vtinput_event delivered;
	pthread_mutex_t mtx;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	ATF_REQUIRE_EQ(pthread_mutex_init(&mtx, NULL), 0);
	sc.vsc_vs.vs_mtx = &mtx;
	sc.vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_vs = &sc.vsc_vs;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_qsize = VTINPUT_RINGSZ;
	vq_set_allocated(&sc.vsc_queues[VTINPUT_EVENTQ], true);

	g_read_events[0].type = VIRTIO14_INPUT_EV_SYN;
	g_read_events[0].code = VIRTIO14_INPUT_SYN_DROPPED;
	g_read_events[1].type = VIRTIO14_INPUT_EV_SYN;
	g_read_events[1].code = VIRTIO14_INPUT_SYN_REPORT;
	g_read_event_count = 2;
	g_descs = 2;
	vtinput_read_event(10, EVF_READ, &sc);
	ATF_CHECK(!sc.vsc_resync_frame);
	ATF_CHECK(!sc.vsc_drop_frame);
	ATF_CHECK_EQ(sc.vsc_eventqueue.idx, 0);
	ATF_CHECK_EQ(g_rel_calls, 2);
	memcpy(&delivered, g_iov_buf[0], VIRTIO14_INPUT_EVENT_SIZE);
	ATF_CHECK_EQ(le16toh(delivered.type), VIRTIO14_INPUT_EV_SYN);
	ATF_CHECK_EQ(le16toh(delivered.code), VIRTIO14_INPUT_SYN_DROPPED);
	free(sc.vsc_eventqueue.events);
	pthread_mutex_destroy(&mtx);
}

ATF_TC_WITHOUT_HEAD(snapshot_negative_paths);
ATF_TC_BODY(snapshot_negative_paths, tc)
{
	struct pci_vtinput_softc source, destination, sc;
	struct mevent source_event, destination_event, sc_event;
	struct pci_devinst pi;
	struct vm_snapshot_meta meta = { .op = VM_SNAPSHOT_VALIDATE };
	uint8_t image[2048], mutated[2048];
	uint8_t saved;
	size_t used;

	/* SAVE rejects an inconsistent staged frame before serializing. */
	reset_mocks();
	setup_snapshot_softc(&source, &source_event);
	source.vsc_eventqueue.idx = source.vsc_eventqueue.size + 1;
	ATF_CHECK_EQ(run_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, NULL), EINVAL);
	source.vsc_eventqueue.idx = 1;
	ATF_REQUIRE_EQ(run_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	destroy_snapshot_softc(&source);

	setup_snapshot_softc(&destination, &destination_event);
	destination.vsc_eventqueue.idx = 0;

	/* An advertised payload larger than the union is impossible. */
	memcpy(mutated, image, used);
	saved = mutated[21];
	mutated[21] = (uint8_t)(sizeof(source.vsc_config.u) + 1);
	ATF_CHECK_EQ(run_snapshot(&destination, mutated, used,
	    VM_SNAPSHOT_VALIDATE, NULL), EINVAL);
	mutated[21] = saved;

	/* A nonzero reserved byte is outside the live config state space. */
	memcpy(mutated, image, used);
	mutated[22] = 0xa5;
	ATF_CHECK_EQ(run_snapshot(&destination, mutated, used,
	    VM_SNAPSHOT_VALIDATE, NULL), EINVAL);

	/* resync=1 with an empty, non-dropped frame is an impossible combo. */
	memcpy(mutated, image, used);
	mutated[17] = 0;	/* drop_frame */
	mutated[18] = 1;	/* resync_frame */
	mutated[155] = mutated[156] = mutated[157] = mutated[158] = 0; /* count */
	ATF_CHECK_EQ(run_snapshot(&destination, mutated, used,
	    VM_SNAPSHOT_VALIDATE, NULL), EINVAL);
	destroy_snapshot_softc(&destination);

	/* RESTORE into a device with no backing buffer adopts the new events. */
	reset_mocks();
	setup_snapshot_softc(&sc, &sc_event);
	free(sc.vsc_eventqueue.events);
	sc.vsc_eventqueue.events = NULL;
	sc.vsc_eventqueue.size = 0;
	sc.vsc_eventqueue.idx = 0;
	ATF_REQUIRE_EQ(run_snapshot(&sc, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(sc.vsc_eventqueue.idx, 1);
	ATF_CHECK(sc.vsc_eventqueue.events != NULL);
	ATF_CHECK_EQ(sc.vsc_eventqueue.size, 1);
	destroy_snapshot_softc(&sc);

	/* Preflight validation rejects a device instance with no softc. */
	memset(&pi, 0, sizeof(pi));
	pi.pi_arg = NULL;
	meta.dev_data = &pi;
	ATF_CHECK_EQ(pci_vtinput_snapshot_validate(&meta), EINVAL);
}

ATF_TC_WITHOUT_HEAD(init_failure_paths);
ATF_TC_BODY(init_failure_paths, tc)
{
	struct pci_devinst pi;
	struct nvlist nvl;

	/* Missing device path. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_path_null = true;
	ATF_CHECK_EQ(pci_vtinput_init(&pi, &nvl), -1);

	/* open(2) failure. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_open_fail = true;
	ATF_CHECK_EQ(pci_vtinput_init(&pi, &nvl), -1);

	/* fstat(2) failure. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_fstat_fail = true;
	ATF_CHECK_EQ(pci_vtinput_init(&pi, &nvl), -1);

	/* Not an evdev node (EVIOCGVERSION fails). */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_evversion_fail = true;
	ATF_CHECK_EQ(pci_vtinput_init(&pi, &nvl), -1);

	/* Exclusive grab fails. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_evgrab_fail = true;
	ATF_CHECK_EQ(pci_vtinput_init(&pi, &nvl), -1);

	/* mevent registration fails. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_mevent_add_null = true;
	ATF_CHECK_EQ(pci_vtinput_init(&pi, &nvl), -1);

	/* Transport selection fails. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_transport = "bogus";
	ATF_CHECK_EQ(pci_vtinput_init(&pi, &nvl), -1);

	/* Interrupt/MSI-X BAR setup fails. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_intr_init_fail = true;
	ATF_CHECK_EQ(pci_vtinput_init(&pi, &nvl), -1);

	/* Modern transport BAR init fails after interrupts were set up. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_modern_init_fail = true;
	ATF_CHECK_EQ(pci_vtinput_init(&pi, &nvl), -1);
}

ATF_TC_WITHOUT_HEAD(eventqueue_alloc_failures);
ATF_TC_BODY(eventqueue_alloc_failures, tc)
{
	struct vtinput_eventqueue queue;
	struct vqueue_info vq;
	struct input_event event;

	/* A growth allocation failure is reported without corrupting the queue. */
	reset_mocks();
	memset(&queue, 0, sizeof(queue));
	memset(&event, 0, sizeof(event));
	g_realloc_fail_armed = true;
	ATF_CHECK_EQ(vtinput_eventqueue_add_event(&queue, &event), 1);
	ATF_CHECK_EQ(queue.idx, 0);
	ATF_CHECK(queue.events == NULL);

	/*
	 * If the loss-marker frame itself cannot be allocated, the queue is left
	 * empty and the drop is absorbed silently rather than crashing.
	 */
	reset_mocks();
	memset(&queue, 0, sizeof(queue));
	memset(&vq, 0, sizeof(vq));
	vq.vq_qsize = VTINPUT_RINGSZ;
	g_realloc_fail_armed = true;
	ATF_CHECK(vtinput_eventqueue_report_loss(&queue, &vq));
	ATF_CHECK_EQ(queue.idx, 0);
	ATF_CHECK_EQ(g_rel_calls, 0);
	free(queue.events);
}

ATF_TC_WITHOUT_HEAD(read_event_alloc_failures);
ATF_TC_BODY(read_event_alloc_failures, tc)
{
	struct pci_vtinput_softc sc;
	pthread_mutex_t mtx;

	/* A staging allocation failure after SYN_DROPPED forces a frame drop. */
	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	ATF_REQUIRE_EQ(pthread_mutex_init(&mtx, NULL), 0);
	sc.vsc_vs.vs_mtx = &mtx;
	sc.vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_vs = &sc.vsc_vs;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_qsize = VTINPUT_RINGSZ;
	vq_set_allocated(&sc.vsc_queues[VTINPUT_EVENTQ], true);
	g_read_events[0].type = VIRTIO14_INPUT_EV_SYN;
	g_read_events[0].code = VIRTIO14_INPUT_SYN_DROPPED;
	g_read_event_count = 1;
	g_descs = 2;
	g_realloc_fail_armed = true;
	vtinput_read_event(10, EVF_READ, &sc);
	ATF_CHECK(sc.vsc_drop_frame);
	free(sc.vsc_eventqueue.events);
	sc.vsc_eventqueue.events = NULL;
	sc.vsc_eventqueue.size = 0;

	/* A staging allocation failure on an ordinary event also drops the frame. */
	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vsc_fd = 10;
	sc.vsc_vs.vs_mtx = &mtx;
	sc.vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_vs = &sc.vsc_vs;
	sc.vsc_queues[VTINPUT_EVENTQ].vq_qsize = VTINPUT_RINGSZ;
	vq_set_allocated(&sc.vsc_queues[VTINPUT_EVENTQ], true);
	g_read_events[0].type = EV_KEY;
	g_read_events[0].code = KEY_A;
	g_read_events[0].value = 1;
	g_read_event_count = 1;
	g_descs = 2;
	g_realloc_fail_armed = true;
	vtinput_read_event(10, EVF_READ, &sc);
	ATF_CHECK(sc.vsc_drop_frame);
	free(sc.vsc_eventqueue.events);
	pthread_mutex_destroy(&mtx);
}

ATF_TC_WITHOUT_HEAD(snapshot_restore_alloc_failure);
ATF_TC_BODY(snapshot_restore_alloc_failure, tc)
{
	struct pci_vtinput_softc source, destination;
	struct mevent source_event, destination_event;
	uint8_t image[2048];
	size_t used;

	reset_mocks();
	setup_snapshot_softc(&source, &source_event);
	ATF_REQUIRE_EQ(run_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	destroy_snapshot_softc(&source);

	setup_snapshot_softc(&destination, &destination_event);
	destination.vsc_eventqueue.idx = 0;
	/* The restore-time staging buffer allocation fails (first calloc). */
	g_calloc_fail_after = 0;
	ATF_CHECK_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), ENOMEM);
	destroy_snapshot_softc(&destination);
}

ATF_TC_WITHOUT_HEAD(init_resource_failures);
ATF_TC_BODY(init_resource_failures, tc)
{
	struct pci_devinst pi;
	struct nvlist nvl;

	/* softc allocation fails (first calloc). */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_calloc_fail_after = 0;
	ATF_CHECK_EQ(pci_vtinput_init(&pi, &nvl), -1);

	/* Duplicating the device path fails. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_strdup_fail_armed = true;
	ATF_CHECK_EQ(pci_vtinput_init(&pi, &nvl), -1);

	/* mutexattr initialization fails. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_pthread_fail_which = 1;
	ATF_CHECK_EQ(pci_vtinput_init(&pi, &nvl), -1);

	/* mutexattr settype fails (attr cleanup path). */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_pthread_fail_which = 2;
	ATF_CHECK_EQ(pci_vtinput_init(&pi, &nvl), -1);

	/* mutex initialization fails (attr cleanup path). */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_pthread_fail_which = 3;
	ATF_CHECK_EQ(pci_vtinput_init(&pi, &nvl), -1);

	/* Event-queue allocation fails (second calloc, after the softc). */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_calloc_fail_after = 1;
	ATF_CHECK_EQ(pci_vtinput_init(&pi, &nvl), -1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, virtio_1_4_wire_layout);
	ATF_TP_ADD_TC(tp, transport_compatibility);
	ATF_TP_ADD_TC(tp, command_line_config);
	ATF_TP_ADD_TC(tp, eventqueue_growth);
	ATF_TP_ADD_TC(tp, syn_report_flushes_frame);
	ATF_TP_ADD_TC(tp, complete_frame_retries_on_guest_kick);
	ATF_TP_ADD_TC(tp, host_event_dispatch_is_bounded);
	ATF_TP_ADD_TC(tp, hostile_status_descriptors);
	ATF_TP_ADD_TC(tp, hostile_event_descriptors);
	ATF_TP_ADD_TC(tp, scatter_gather_events);
	ATF_TP_ADD_TC(tp, status_error_finishes_completions);
	ATF_TP_ADD_TC(tp, in_order_completion);
	ATF_TP_ADD_TC(tp, partial_frame_rollback);
	ATF_TP_ADD_TC(tp, oversized_frame_dropped);
	ATF_TP_ADD_TC(tp, frame_larger_than_guest_ring_reports_loss);
	ATF_TP_ADD_TC(tp, syn_dropped_resynchronizes_guest);
	ATF_TP_ADD_TC(tp, reset_discards_stale_events);
	ATF_TP_ADD_TC(tp, queue_reset_drops_host_events);
	ATF_TP_ADD_TC(tp, queue_reset_drains_before_fast_reenable);
	ATF_TP_ADD_TC(tp, queue_reset_isolated);
	ATF_TP_ADD_TC(tp, suspend_discards_partial_frame);
	ATF_TP_ADD_TC(tp, config_bounds);
	ATF_TP_ADD_TC(tp, config_responses);
	ATF_TP_ADD_TC(tp, config_selector_matrix);
	ATF_TP_ADD_TC(tp, snapshot_staged_frame_and_atomicity);
	ATF_TP_ADD_TC(tp, snapshot_resynchronization_state);
	ATF_TP_ADD_TC(tp, snapshot_preflight_is_locally_serialized);
	ATF_TP_ADD_TC(tp, checkpoint_event_source_lifecycle);
	ATF_TP_ADD_TC(tp, resume_device_is_noop);
	ATF_TP_ADD_TC(tp, debug_env_and_verbose_paths);
	ATF_TP_ADD_TC(tp, host_drain_diagnostics);
	ATF_TP_ADD_TC(tp, statusq_event_variants);
	ATF_TP_ADD_TC(tp, config_error_paths);
	ATF_TP_ADD_TC(tp, send_events_no_descriptor);
	ATF_TP_ADD_TC(tp, retained_frame_blocks_new_input);
	ATF_TP_ADD_TC(tp, drop_frame_report_loss_without_descriptors);
	ATF_TP_ADD_TC(tp, resync_completes_after_syn_report);
	ATF_TP_ADD_TC(tp, snapshot_negative_paths);
	ATF_TP_ADD_TC(tp, init_failure_paths);
	ATF_TP_ADD_TC(tp, eventqueue_alloc_failures);
	ATF_TP_ADD_TC(tp, read_event_alloc_failures);
	ATF_TP_ADD_TC(tp, snapshot_restore_alloc_failure);
	ATF_TP_ADD_TC(tp, init_resource_failures);
	return (atf_no_error());
}
