/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Fault-injection tests for bhyve's VirtIO SCSI device.
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <atf-c.h>

#include "virtio_config_read_test_support.h"
#include "virtio_1_4_spec.h"
#include "virtio_1_4_wire.h"

#define	BHYVE_SNAPSHOT
#define	VTSCSI_QUIESCE_TIMEOUT_SECONDS	0
struct vqueue_info;
struct vi_req;
static void test_vq_discard_observer(struct vqueue_info *, struct vi_req *);
#define	VQ_DISCARD_REQ_OBSERVER(_vq, _req) \
	test_vq_discard_observer((_vq), (_req))
static int test_ioctl(int, unsigned long, ...);
static int test_clock_gettime(clockid_t, struct timespec *);
static int test_open(const char *, int, ...);
#define	ioctl	test_ioctl
#define	clock_gettime	test_clock_gettime
#define	open	test_open
#include "virtio_scsi_event.c"
#include "pci_virtio_scsi.c"
#undef open
#undef clock_gettime
#undef ioctl
#include "iov.c"

/* Test-side command and response values come from VirtIO 1.4. */
#undef VIRTIO_SCSI_T_TMF
#define	VIRTIO_SCSI_T_TMF		VIRTIO14_SCSI_T_TMF
#undef VIRTIO_SCSI_T_TMF_ABORT_TASK
#define	VIRTIO_SCSI_T_TMF_ABORT_TASK	VIRTIO14_SCSI_T_TMF_ABORT_TASK
#undef VIRTIO_SCSI_T_AN_QUERY
#define	VIRTIO_SCSI_T_AN_QUERY		VIRTIO14_SCSI_T_AN_QUERY
#undef VIRTIO_SCSI_T_AN_SUBSCRIBE
#define	VIRTIO_SCSI_T_AN_SUBSCRIBE	VIRTIO14_SCSI_T_AN_SUBSCRIBE
#undef VIRTIO_SCSI_S_FUNCTION_COMPLETE
#define	VIRTIO_SCSI_S_FUNCTION_COMPLETE \
	VIRTIO14_SCSI_S_FUNCTION_COMPLETE
#undef VIRTIO_SCSI_S_FUNCTION_SUCCEEDED
#define	VIRTIO_SCSI_S_FUNCTION_SUCCEEDED \
	VIRTIO14_SCSI_S_FUNCTION_SUCCEEDED
#undef VIRTIO_SCSI_S_FUNCTION_REJECTED
#define	VIRTIO_SCSI_S_FUNCTION_REJECTED \
	VIRTIO14_SCSI_S_FUNCTION_REJECTED
#undef VIRTIO_SCSI_S_OK
#define	VIRTIO_SCSI_S_OK		VIRTIO14_SCSI_S_OK
#undef VIRTIO_SCSI_S_OVERRUN
#define	VIRTIO_SCSI_S_OVERRUN		VIRTIO14_SCSI_S_OVERRUN
#undef VIRTIO_SCSI_S_ABORTED
#define	VIRTIO_SCSI_S_ABORTED		VIRTIO14_SCSI_S_ABORTED
#undef VIRTIO_SCSI_S_BAD_TARGET
#define	VIRTIO_SCSI_S_BAD_TARGET	VIRTIO14_SCSI_S_BAD_TARGET
#undef VIRTIO_SCSI_S_RESET
#define	VIRTIO_SCSI_S_RESET		VIRTIO14_SCSI_S_RESET
#undef VIRTIO_SCSI_S_TRANSPORT_FAILURE
#define	VIRTIO_SCSI_S_TRANSPORT_FAILURE \
	VIRTIO14_SCSI_S_TRANSPORT_FAILURE
#undef VIRTIO_SCSI_S_FAILURE
#define	VIRTIO_SCSI_S_FAILURE		VIRTIO14_SCSI_S_FAILURE
#undef VIRTIO_ID_SCSI
#define	VIRTIO_ID_SCSI			VIRTIO14_DEVICE_SCSI
#undef VIRTIO_SCSI_S_SIMPLE
#define	VIRTIO_SCSI_S_SIMPLE		VIRTIO14_SCSI_TASK_ATTR_SIMPLE
#undef VIRTIO_SCSI_S_ORDERED
#define	VIRTIO_SCSI_S_ORDERED		VIRTIO14_SCSI_TASK_ATTR_ORDERED
#undef VIRTIO_SCSI_S_HEAD
#define	VIRTIO_SCSI_S_HEAD		VIRTIO14_SCSI_TASK_ATTR_HEAD
#undef VIRTIO_SCSI_S_ACA
#define	VIRTIO_SCSI_S_ACA		VIRTIO14_SCSI_TASK_ATTR_ACA
#undef VIRTIO_CONFIG_STATUS_DRIVER_OK
#define	VIRTIO_CONFIG_STATUS_DRIVER_OK	VIRTIO14_STATUS_DRIVER_OK
#undef VIRTIO_F_RING_RESET
#define	VIRTIO_F_RING_RESET		VIRTIO14_F_RING_RESET

#define MOCK_MAX_IOV 70

struct mock_chain {
	int n;
	struct vi_req req;
	struct iovec iov[MOCK_MAX_IOV];
};

static struct mock_chain g_chain;
static int g_chain_ready;
static int g_rel_calls;
static int g_discard_calls;
static bool g_discard_had_vq_lock;
static bool g_discard_was_outstanding;
static uint16_t g_rel_idx;
static uint32_t g_rel_len;
static int g_end_calls;
static int g_end_all;
static int g_ctl_allocs;
static int g_ctl_frees;
static union ctl_io g_ctl_io;
static int g_mutex_init_calls;
static int g_mutex_init_fail_at;
static int g_cond_init_calls;
static int g_cond_init_fail_at;
static pthread_mutex_t *g_expected_vq_mutex;
static bool g_getchain_had_vq_lock;
static const char *g_lun_inventory = "<ctllunlist/>";
static int g_lun_inventory_error;
static int g_lun_inventory_calls;
static bool g_ctl_io_success;
static uint32_t g_ctl_last_targ_lun;
static int g_needs_reset;
static int g_clock_calls;
static bool g_clock_nonmonotonic;
static int g_snapshot_validate_calls;
static int g_snapshot_validate_result;
static bool g_snapshot_validate_saw_lock;
static struct ctl_lun_event g_lun_events[VTSCSI_EVENT_CAPACITY + 2];
static size_t g_lun_event_count;
static size_t g_lun_event_next;
/* Extended CTL_IO result controls (default reproduces the legacy behavior). */
static bool g_ctl_alloc_fail;
static int g_ctl_io_status;
static uint8_t g_ctl_io_scsi_status;
static uint32_t g_ctl_io_sense_len;
static uint8_t g_ctl_io_sense_byte;
static uint32_t g_ctl_io_ext_data_filled;
static uint8_t g_ctl_io_task_status;
static uint32_t g_ctl_io_port_status;
static int g_ctl_io_calls;
static uint8_t g_ctl_last_opcode;
static int g_ctl_last_flags;
/* clock and LUN-inventory fault injection. */
static bool g_clock_fail;
static int g_lun_list_force_status;	/* -1: default; else forced list.status */
static bool g_lun_list_force_need;	/* always report NEED_MORE_SPACE */
/* PCI/virtio init plumbing controls and observations. */
static enum virtio_pci_transport g_init_transport;
static int g_init_transport_error;
static int g_intr_init_error;
static int g_modern_init_error;
static int g_boot_device_error;
static bool g_subscribe_ok;
static int g_subscribe_errno;
static bool g_mevent_add_fail;
static int g_mevent_add_calls;
static int g_mevent_delete_calls;
static int g_open_fd;
static int g_open_calls;
static char g_open_path[256];
static uint16_t g_cfg_device;
static uint16_t g_cfg_vendor;
static uint8_t g_cfg_class;
static uint16_t g_modern_identity;
static int g_linkup_calls;
/* Config-node store consulted by the mocked bhyve config API. */
static const char *g_cfg_queues;
static const char *g_cfg_iid;
static const char *g_cfg_bootindex;
static const char *g_cfg_dev;
static bool g_cfg_packed;
static int g_legacy_parse_calls;
static int g_legacy_parse_ret;
static char g_legacy_dev[256];

static void
test_vq_discard_observer(struct vqueue_info *vq __unused, struct vi_req *req)
{
	int error;

	g_discard_calls++;
	g_discard_was_outstanding = req->outstanding;
	if (g_expected_vq_mutex == NULL)
		return;
	error = pthread_mutex_trylock(g_expected_vq_mutex);
	if (error == EBUSY)
		g_discard_had_vq_lock = true;
	else if (error == 0)
		pthread_mutex_unlock(g_expected_vq_mutex);
}

int __real_pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);
int __real_pthread_cond_init(pthread_cond_t *, const pthread_condattr_t *);
int __wrap_pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);
int __wrap_pthread_cond_init(pthread_cond_t *, const pthread_condattr_t *);

static int
test_clock_gettime(clockid_t clock_id, struct timespec *ts)
{

	g_clock_calls++;
	if (clock_id != CLOCK_MONOTONIC)
		g_clock_nonmonotonic = true;
	if (g_clock_fail) {
		errno = EINVAL;
		return (-1);
	}
	return (clock_gettime(clock_id, ts));
}

static int
test_ioctl(int fd __unused, unsigned long request, ...)
{
	struct ctl_lun_list *list;
	va_list ap;
	size_t length;

	va_start(ap, request);
	if (request == CTL_LUN_EVENT_NEXT) {
		struct ctl_lun_event *event;

		event = va_arg(ap, struct ctl_lun_event *);
		va_end(ap);
		if (g_lun_event_next == g_lun_event_count) {
			errno = EAGAIN;
			return (-1);
		}
		*event = g_lun_events[g_lun_event_next++];
		return (0);
	}
	if (request == CTL_LUN_EVENT_SUBSCRIBE) {
		va_end(ap);
		if (g_subscribe_ok)
			return (0);
		errno = g_subscribe_errno;
		return (-1);
	}
	if (request == CTL_IO) {
		union ctl_io *io;

		io = va_arg(ap, union ctl_io *);
		va_end(ap);
		g_ctl_io_calls++;
		g_ctl_last_targ_lun = io->io_hdr.nexus.targ_lun;
		if (io->io_hdr.io_type == CTL_IO_SCSI)
			g_ctl_last_opcode = io->scsiio.cdb[0];
		g_ctl_last_flags = io->io_hdr.flags;
		if (g_ctl_io_success) {
			io->io_hdr.status = g_ctl_io_status;
			io->io_hdr.port_status = g_ctl_io_port_status;
			if (io->io_hdr.io_type == CTL_IO_TASK) {
				io->taskio.task_status = g_ctl_io_task_status;
			} else {
				io->scsiio.scsi_status = g_ctl_io_scsi_status;
				io->scsiio.sense_len = g_ctl_io_sense_len;
				io->scsiio.ext_data_filled =
				    g_ctl_io_ext_data_filled;
				memset(&io->scsiio.sense_data, g_ctl_io_sense_byte,
				    sizeof(io->scsiio.sense_data));
			}
			return (0);
		}
		errno = ENOTTY;
		return (-1);
	}
	if (request != CTL_LUN_LIST) {
		va_end(ap);
		errno = ENOTTY;
		return (-1);
	}
	g_lun_inventory_calls++;
	if (g_lun_inventory_error != 0) {
		va_end(ap);
		errno = g_lun_inventory_error;
		return (-1);
	}
	list = va_arg(ap, struct ctl_lun_list *);
	va_end(ap);
	if (g_lun_list_force_need) {
		list->status = CTL_LUN_LIST_NEED_MORE_SPACE;
		return (0);
	}
	if (g_lun_list_force_status >= 0) {
		list->status = g_lun_list_force_status;
		list->fill_len = 0;
		return (0);
	}
	length = strlen(g_lun_inventory) + 1;
	if (length > list->alloc_len) {
		list->status = CTL_LUN_LIST_NEED_MORE_SPACE;
		return (0);
	}
	memcpy(list->lun_xml, g_lun_inventory, length);
	list->fill_len = (uint32_t)length;
	list->status = CTL_LUN_LIST_OK;
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
vi_pci_snapshot(struct vm_snapshot_meta *meta)
{
	struct pci_devinst *pi;
	struct pci_vtscsi_softc *sc;

	ATF_REQUIRE(meta != NULL);
	pi = meta->dev_data;
	ATF_REQUIRE(pi != NULL);
	sc = pi->pi_arg;
	ATF_REQUIRE(sc != NULL);
	g_snapshot_validate_saw_lock =
	    pthread_mutex_isowned_np(&sc->vss_mtx);
	g_snapshot_validate_calls++;
	return (g_snapshot_validate_result);
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

int
__wrap_pthread_mutex_init(pthread_mutex_t *mutex,
    const pthread_mutexattr_t *attr)
{

	g_mutex_init_calls++;
	if (g_mutex_init_fail_at != 0 &&
	    g_mutex_init_calls == g_mutex_init_fail_at)
		return (EAGAIN);
	return (__real_pthread_mutex_init(mutex, attr));
}

int
__wrap_pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr)
{

	g_cond_init_calls++;
	if (g_cond_init_fail_at != 0 &&
	    g_cond_init_calls == g_cond_init_fail_at)
		return (EAGAIN);
	return (__real_pthread_cond_init(cond, attr));
}

static void
reset_mocks(void)
{

	memset(&g_chain, 0, sizeof(g_chain));
	memset(&g_ctl_io, 0, sizeof(g_ctl_io));
	g_chain_ready = 0;
	g_rel_calls = 0;
	g_discard_calls = 0;
	g_discard_had_vq_lock = false;
	g_discard_was_outstanding = false;
	g_rel_idx = 0;
	g_rel_len = UINT32_MAX;
	g_end_calls = 0;
	g_end_all = -1;
	g_ctl_allocs = 0;
	g_ctl_frees = 0;
	g_mutex_init_calls = 0;
	g_mutex_init_fail_at = 0;
	g_cond_init_calls = 0;
	g_cond_init_fail_at = 0;
	g_expected_vq_mutex = NULL;
	g_getchain_had_vq_lock = false;
	g_lun_inventory = "<ctllunlist/>";
	g_lun_inventory_error = 0;
	g_lun_inventory_calls = 0;
	g_ctl_io_success = false;
	g_ctl_last_targ_lun = 0;
	g_needs_reset = 0;
	g_clock_calls = 0;
	g_clock_nonmonotonic = false;
	g_snapshot_validate_calls = 0;
	g_snapshot_validate_result = 0;
	g_snapshot_validate_saw_lock = false;
	memset(g_lun_events, 0, sizeof(g_lun_events));
	g_lun_event_count = 0;
	g_lun_event_next = 0;
	g_ctl_alloc_fail = false;
	g_ctl_io_status = CTL_SUCCESS;
	g_ctl_io_scsi_status = 0;
	g_ctl_io_sense_len = 0;
	g_ctl_io_sense_byte = 0;
	g_ctl_io_ext_data_filled = 0;
	g_ctl_io_task_status = 0;
	g_ctl_io_port_status = 0;
	g_ctl_io_calls = 0;
	g_ctl_last_opcode = 0;
	g_ctl_last_flags = 0;
	g_clock_fail = false;
	g_lun_list_force_status = -1;
	g_lun_list_force_need = false;
	g_init_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	g_init_transport_error = 0;
	g_intr_init_error = 0;
	g_modern_init_error = 0;
	g_boot_device_error = 0;
	g_subscribe_ok = false;
	g_subscribe_errno = ENOTTY;
	g_mevent_add_fail = false;
	g_mevent_add_calls = 0;
	g_mevent_delete_calls = 0;
	g_open_fd = 900;
	g_open_calls = 0;
	memset(g_open_path, 0, sizeof(g_open_path));
	g_cfg_device = 0;
	g_cfg_vendor = 0;
	g_cfg_class = 0;
	g_modern_identity = 0;
	g_linkup_calls = 0;
	pci_vtscsi_debug = 0;
	g_cfg_queues = NULL;
	g_cfg_iid = NULL;
	g_cfg_bootindex = NULL;
	g_cfg_dev = "/dev/cam/ctl";
	g_cfg_packed = false;
	g_legacy_parse_calls = 0;
	g_legacy_parse_ret = 0;
	memset(g_legacy_dev, 0, sizeof(g_legacy_dev));
}

static void
set_chain(int n, int readable, int writable, bool ordered)
{

	g_chain.n = n;
	g_chain.req.idx = 7;
	g_chain.req.readable = readable;
	g_chain.req.writable = writable;
	g_chain.req.ordered = ordered;
	g_chain_ready = 1;
}

int
vq_has_descs(struct vqueue_info *vq __unused)
{

	return (g_chain_ready);
}

int
vq_getchain(struct vqueue_info *vq __unused, struct iovec *iov, int niov,
    struct vi_req *req)
{
	int copied;
	int error;

	if (g_expected_vq_mutex != NULL) {
		error = pthread_mutex_trylock(g_expected_vq_mutex);
		if (error == EBUSY)
			g_getchain_had_vq_lock = true;
		else if (error == 0)
			pthread_mutex_unlock(g_expected_vq_mutex);
	}

	if (!g_chain_ready)
		return (0);
	g_chain_ready--;
	*req = g_chain.req;
	if (g_chain.n > 0) {
		copied = MIN(g_chain.n, niov);
		memcpy(iov, g_chain.iov, copied * sizeof(iov[0]));
	}
	return (g_chain.n);
}

void
vq_relchain(struct vqueue_info *vq __unused, uint16_t idx, uint32_t len)
{

	g_rel_calls++;
	g_rel_idx = idx;
	g_rel_len = len;
}

void
vq_endchains(struct vqueue_info *vq __unused, int used_all)
{

	g_end_calls++;
	g_end_all = used_all;
}

void
vi_reset_dev(struct virtio_softc *vs __unused)
{
}

void
vi_set_needs_reset(struct virtio_softc *vs __unused)
{

	g_needs_reset++;
}

bool
vi_pci_is_modern(const struct virtio_softc *vs)
{

	return (vs->vs_transport == VIRTIO_PCI_TRANSPORT_MODERN);
}

union ctl_io *
ctl_scsi_alloc_io(uint32_t initid __unused)
{

	g_ctl_allocs++;
	if (g_ctl_alloc_fail) {
		errno = ENOMEM;
		return (NULL);
	}
	memset(&g_ctl_io, 0, sizeof(g_ctl_io));
	return (&g_ctl_io);
}

void
ctl_scsi_free_io(union ctl_io *io __unused)
{

	g_ctl_frees++;
}

void
ctl_scsi_zero_io(union ctl_io *io)
{

	memset(io, 0, sizeof(*io));
}

void
ctl_io_sbuf(union ctl_io *io __unused, struct sbuf *sb __unused)
{

	sbuf_cat(sb, "ctl-io");
}

static int
test_open(const char *path, int flags __unused, ...)
{

	g_open_calls++;
	strlcpy(g_open_path, path, sizeof(g_open_path));
	if (g_open_fd < 0) {
		errno = ENOENT;
		return (-1);
	}
	return (g_open_fd);
}

/* bhyve configuration node API (single-device store). */
const char *
get_config_value_node(const nvlist_t *nvl __unused, const char *name)
{

	if (strcmp(name, "queues") == 0)
		return (g_cfg_queues);
	if (strcmp(name, "iid") == 0)
		return (g_cfg_iid);
	if (strcmp(name, "bootindex") == 0)
		return (g_cfg_bootindex);
	if (strcmp(name, "dev") == 0)
		return (g_cfg_dev);
	return (NULL);
}

bool
get_config_bool_node_default(const nvlist_t *nvl __unused,
    const char *name __unused, bool value __unused)
{

	return (g_cfg_packed);
}

void
set_config_value_node(nvlist_t *nvl __unused, const char *name,
    const char *value)
{

	if (strcmp(name, "dev") == 0) {
		strlcpy(g_legacy_dev, value, sizeof(g_legacy_dev));
		g_cfg_dev = g_legacy_dev;
	}
}

int
pci_parse_legacy_config(nvlist_t *nvl __unused, const char *opts __unused)
{

	g_legacy_parse_calls++;
	return (g_legacy_parse_ret);
}

int
pci_emul_add_boot_device(struct pci_devinst *pi __unused, int bootindex __unused)
{

	return (g_boot_device_error);
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
	__real_pthread_mutex_init(&vs->vs_isr_mtx, NULL);
	return (0);
}

int
fbsdrun_virtio_msix(void)
{

	return (1);
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
	default:
		break;
	}
}

struct mevent *
mevent_add(int fd __unused, enum ev_type type __unused,
    void (*func)(int, enum ev_type, void *) __unused, void *param __unused)
{

	g_mevent_add_calls++;
	if (g_mevent_add_fail)
		return (NULL);
	return ((struct mevent *)(uintptr_t)0x1);
}

int
mevent_delete_sync(struct mevent *evp __unused)
{

	g_mevent_delete_calls++;
	return (0);
}

static void
setup_request_queue(struct pci_vtscsi_softc *sc, unsigned int queue_index,
    struct pci_vtscsi_request *req,
    uint8_t *cmd_rd, uint8_t *cmd_wr, union ctl_io *io)
{
	pthread_condattr_t condattr;
	struct pci_vtscsi_queue *q;

	memset(req, 0, sizeof(*req));
	memset(cmd_rd, 0, VTSCSI_MAX_IN_HEADER_LEN);
	memset(cmd_wr, 0, VTSCSI_MAX_OUT_HEADER_LEN);
	memset(io, 0, sizeof(*io));
	sc->vss_vq[queue_index + 2].vq_num = queue_index + 2;
	q = &sc->vss_queues[queue_index];
	q->vsq_sc = sc;
	q->vsq_vq = &sc->vss_vq[queue_index + 2];
	pthread_mutex_init(&q->vsq_rmtx, NULL);
	pthread_mutex_init(&q->vsq_fmtx, NULL);
	pthread_mutex_init(&q->vsq_qmtx, NULL);
	ATF_REQUIRE_EQ(pthread_condattr_init(&condattr), 0);
	ATF_REQUIRE_EQ(pthread_condattr_setclock(&condattr, CLOCK_MONOTONIC), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&q->vsq_cv, &condattr), 0);
	ATF_REQUIRE_EQ(pthread_condattr_destroy(&condattr), 0);
	STAILQ_INIT(&q->vsq_requests);
	STAILQ_INIT(&q->vsq_free_requests);
	req->vsr_cmd_rd = (struct pci_vtscsi_req_cmd_rd *)cmd_rd;
	req->vsr_cmd_wr = (struct pci_vtscsi_req_cmd_wr *)cmd_wr;
	req->vsr_ctl_io = io;
	pci_vtscsi_put_request(&q->vsq_free_requests, req);
}

static void
setup_queue(struct pci_vtscsi_softc *sc, struct pci_vtscsi_request *req,
    uint8_t *cmd_rd, uint8_t *cmd_wr, union ctl_io *io)
{

	memset(sc, 0, sizeof(*sc));
	sc->vss_config.cdb_size = VIRTIO14_SCSI_DEFAULT_CDB_SIZE;
	sc->vss_config.sense_size = VIRTIO14_SCSI_DEFAULT_SENSE_SIZE;
	sc->vss_nrequestq = VTSCSI_DEFAULT_REQUESTQ;
	setup_request_queue(sc, 0, req, cmd_rd, cmd_wr, io);
}

static void
teardown_request_queue(struct pci_vtscsi_softc *sc,
    unsigned int queue_index)
{
	struct pci_vtscsi_queue *q = &sc->vss_queues[queue_index];

	pthread_cond_destroy(&q->vsq_cv);
	pthread_mutex_destroy(&q->vsq_qmtx);
	pthread_mutex_destroy(&q->vsq_fmtx);
	pthread_mutex_destroy(&q->vsq_rmtx);
}

static void
teardown_queue(struct pci_vtscsi_softc *sc)
{

	teardown_request_queue(sc, 0);
}

static int
run_snapshot(struct pci_vtscsi_softc *sc, void *buffer, size_t size,
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

	error = pci_vtscsi_snapshot(sc, &meta);
	if (used != NULL)
		*used = size - meta.buffer.buf_rem;
	return (error);
}

static void
setup_snapshot_softc(struct pci_vtscsi_softc *sc)
{

	memset(sc, 0, sizeof(*sc));
	sc->vss_iid = 17;
	sc->vss_ctl_fd = 3;
	sc->vss_nrequestq = 2;
	sc->vss_features = VIRTIO14_F_VERSION_1 |
	    VIRTIO14_F_RING_RESET | VIRTIO14_SCSI_F_INOUT;
	sc->vss_vs.vs_negotiated_caps = sc->vss_features;
	sc->vss_config.num_queues = 2;
	sc->vss_config.seg_max = VTSCSI_MAXSEG - 2;
	sc->vss_config.max_sectors = 4096;
	sc->vss_config.cmd_per_lun = 64;
	sc->vss_config.event_info_size = VIRTIO14_SCSI_EVENT_SIZE;
	sc->vss_config.sense_size = VIRTIO14_SCSI_DEFAULT_SENSE_SIZE;
	sc->vss_config.cdb_size = VIRTIO14_SCSI_DEFAULT_CDB_SIZE;
	sc->vss_config.max_channel = 0;
	sc->vss_config.max_target = 0;
	sc->vss_config.max_lun = 16383;
	ATF_REQUIRE_EQ(virtio_scsi_event_state_init(&sc->vss_event_state,
	    sc->vss_event_records, nitems(sc->vss_event_records)), 0);
}

ATF_TC_WITHOUT_HEAD(snapshot_wire_and_validation);
ATF_TC_BODY(snapshot_wire_and_validation, tc)
{
	struct pci_vtscsi_softc destination, source;
	struct pci_vtscsi_config original_config;
	struct virtio_scsi_event_record event, restored_event;
	uint8_t image[512], damaged[512];
	uint64_t original_features;
	size_t used;

	reset_mocks();
	setup_snapshot_softc(&source);
	memset(image, 0xa5, sizeof(image));
	source.vss_features ^= UINT64_C(1);
	ATF_CHECK_EQ(run_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, NULL), EINVAL);
	source.vss_features ^= UINT64_C(1);
	ATF_REQUIRE_EQ(run_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	ATF_REQUIRE(used > 62);

	/* Independent byte vector: the state format is always little-endian. */
	ATF_CHECK_EQ(image[0], 'S');
	ATF_CHECK_EQ(image[1], 'C');
	ATF_CHECK_EQ(image[2], 'S');
	ATF_CHECK_EQ(image[3], '1');
	ATF_CHECK_EQ(image[4], 1);
	ATF_CHECK_EQ(image[5], 0);
	ATF_CHECK_EQ(image[8], 17);
	ATF_CHECK_EQ(image[12], 2);

	setup_snapshot_softc(&destination);
	destination.vss_features = 0;
	destination.vss_config.sense_size = 32;
	destination.vss_config.cdb_size = 16;
	event = (struct virtio_scsi_event_record){
		.event = VIRTIO14_SCSI_T_TRANSPORT_RESET,
		.reason = VIRTIO14_SCSI_EVT_RESET_RESCAN,
		.source_sequence = 40,
	};
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(
	    &destination.vss_event_state, &event), 0);
	original_features = destination.vss_features;
	original_config = destination.vss_config;
	ATF_REQUIRE_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), 0);
	ATF_CHECK_EQ(destination.vss_features, original_features);
	ATF_CHECK(memcmp(&destination.vss_config, &original_config,
	    VIRTIO14_SCSI_CONFIG_SIZE) == 0);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&destination.vss_event_state,
	    &restored_event));
	ATF_CHECK_EQ(restored_event.source_sequence, 40);
	g_lun_inventory_calls = 0;
	ATF_CHECK_EQ(run_snapshot(&destination, image, used - 1,
	    VM_SNAPSHOT_VALIDATE, NULL), E2BIG);
	ATF_CHECK_EQ(g_lun_inventory_calls, 0);
	ATF_CHECK_EQ(destination.vss_features, original_features);
	memcpy(damaged, image, used);
	damaged[4] = 2;
	g_lun_inventory_error = EIO;
	g_lun_inventory_calls = 0;
	ATF_CHECK_EQ(run_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_VALIDATE, NULL), ENOTSUP);
	ATF_CHECK_EQ(g_lun_inventory_calls, 0);
	g_lun_inventory_error = 0;
	ATF_CHECK_EQ(destination.vss_features, original_features);
	ATF_REQUIRE_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(destination.vss_features, source.vss_features);
	ATF_CHECK_EQ(destination.vss_config.sense_size,
	    source.vss_config.sense_size);
	ATF_CHECK_EQ(destination.vss_config.cdb_size,
	    source.vss_config.cdb_size);

	/*
	 * CTL event subscriptions and their sequence space belong to the
	 * destination host.  A restore must discard records queued by the old
	 * device incarnation.  If the destination has a live subscription, the
	 * next guest-visible record is the specification-defined loss marker so
	 * the guest rescans the reconstructed backend rather than trusting stale
	 * topology.  A destination without event support must remain quiet.
	 */
	setup_snapshot_softc(&destination);
	destination.vss_event_source = true;
	event = (struct virtio_scsi_event_record){
		.event = VIRTIO14_SCSI_T_TRANSPORT_RESET,
		.reason = VIRTIO14_SCSI_EVT_RESET_RESCAN,
		.source_sequence = 41,
	};
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(
	    &destination.vss_event_state, &event), 0);
	ATF_REQUIRE_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(virtio_scsi_event_state_count(
	    &destination.vss_event_state), 0);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&destination.vss_event_state,
	    &restored_event));
	ATF_CHECK_EQ(restored_event.event, BHYVE_VTSCSI_EVENT_MISSED);
	ATF_CHECK_EQ(restored_event.reason, 0);
	ATF_CHECK_EQ(restored_event.source_sequence, 0);
	ATF_CHECK(!virtio_scsi_event_state_pending(
	    &destination.vss_event_state));

	/* Repeated restore re-establishes the same destination-local boundary. */
	event.source_sequence = 42;
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(
	    &destination.vss_event_state, &event), 0);
	ATF_REQUIRE_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(virtio_scsi_event_state_count(
	    &destination.vss_event_state), 0);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&destination.vss_event_state,
	    &restored_event));
	ATF_CHECK_EQ(restored_event.event, BHYVE_VTSCSI_EVENT_MISSED);
	ATF_CHECK_EQ(restored_event.source_sequence, 0);
	ATF_CHECK(!virtio_scsi_event_state_pending(
	    &destination.vss_event_state));

	setup_snapshot_softc(&destination);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(
	    &destination.vss_event_state, &event), 0);
	ATF_REQUIRE_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK(!virtio_scsi_event_state_pending(
	    &destination.vss_event_state));
	ATF_CHECK(!destination.vss_event_state.sequence_initialized);

	/* A truncated record must not mutate any destination state. */
	setup_snapshot_softc(&destination);
	destination.vss_features = 0x55;
	original_features = destination.vss_features;
	original_config = destination.vss_config;
	ATF_CHECK_EQ(run_snapshot(&destination, image, used - 1,
	    VM_SNAPSHOT_RESTORE, NULL), E2BIG);
	ATF_CHECK_EQ(destination.vss_features, original_features);
	ATF_CHECK(memcmp(&destination.vss_config, &original_config,
	    VIRTIO14_SCSI_CONFIG_SIZE) == 0);

	/* Unknown versions, invalid CDB sizes, and backend drift are rejected. */
	memcpy(damaged, image, used);
	damaged[4] = 2;
	ATF_CHECK_EQ(run_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), ENOTSUP);

	memcpy(damaged, image, used);
	memset(&damaged[46], 0, sizeof(uint32_t));	/* cdb_size */
	ATF_CHECK_EQ(run_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	ATF_CHECK_EQ(destination.vss_features, original_features);

	/*
	 * Private compatibility fields are independent of the common PCI
	 * envelope.  Exercise each boundary from the documented little-endian
	 * snapshot vector and require failure before destination publication.
	 */
	memcpy(damaged, image, used);
	virtio14_store_le32(&damaged[8], 18);	/* CTL initiator id */
	ATF_CHECK_EQ(run_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	memcpy(damaged, image, used);
	virtio14_store_le16(&damaged[12], 1);	/* request queues */
	ATF_CHECK_EQ(run_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	memcpy(damaged, image, used);
	virtio14_store_le64(&damaged[14], source.vss_features ^
	    VIRTIO14_SCSI_F_INOUT);
	ATF_CHECK_EQ(run_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	memcpy(damaged, image, used);
	virtio14_store_le32(&damaged[26], source.vss_config.seg_max - 1);
	ATF_CHECK_EQ(run_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	memcpy(damaged, image, used);
	virtio14_store_le32(&damaged[38],
	    source.vss_config.event_info_size + 1);
	ATF_CHECK_EQ(run_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	ATF_CHECK_EQ(destination.vss_features, original_features);
	ATF_CHECK(memcmp(&destination.vss_config, &original_config,
	    VIRTIO14_SCSI_CONFIG_SIZE) == 0);

	g_lun_inventory = "<ctllunlist><lun id=\"1\"/></ctllunlist>";
	ATF_CHECK_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	ATF_CHECK_EQ(destination.vss_features, original_features);
}

ATF_TC_WITHOUT_HEAD(snapshot_preflight_is_locally_serialized);
ATF_TC_BODY(snapshot_preflight_is_locally_serialized, tc)
{
	struct pci_devinst pi;
	struct pci_vtscsi_softc sc;
	struct vm_snapshot_meta meta = {
		.dev_data = &pi,
		.op = VM_SNAPSHOT_VALIDATE,
	};

	reset_mocks();
	setup_snapshot_softc(&sc);
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vss_mtx, NULL), 0);
	memset(&pi, 0, sizeof(pi));
	pi.pi_arg = &sc;

	/* Direct preflight serializes the SCSI-private codec. */
	ATF_REQUIRE_EQ(pci_vtscsi_snapshot_validate(&meta), 0);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 1);
	ATF_CHECK(g_snapshot_validate_saw_lock);
	ATF_CHECK_EQ(pthread_mutex_trylock(&sc.vss_mtx), 0);
	pthread_mutex_unlock(&sc.vss_mtx);

	/* A pause-held non-recursive mutex is reused rather than re-acquired. */
	pthread_mutex_lock(&sc.vss_mtx);
	g_snapshot_validate_saw_lock = false;
	ATF_REQUIRE_EQ(pci_vtscsi_snapshot_validate(&meta), 0);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 2);
	ATF_CHECK(g_snapshot_validate_saw_lock);
	pthread_mutex_unlock(&sc.vss_mtx);

	/* Invalid metadata reaches neither the common codec nor CTL. */
	meta.dev_data = NULL;
	ATF_CHECK_EQ(pci_vtscsi_snapshot_validate(&meta), EINVAL);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 2);
	ATF_CHECK_EQ(g_lun_inventory_calls, 0);
	pthread_mutex_destroy(&sc.vss_mtx);
}

ATF_TC_WITHOUT_HEAD(checkpoint_pause_preserves_queue_ownership);
ATF_TC_BODY(checkpoint_pause_preserves_queue_ownership, tc)
{
	struct pci_vtscsi_request blocked_req;
	struct pci_vtscsi_request req;
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_queue *q;
	union ctl_io io;
	uint8_t cmd_rd[VTSCSI_MAX_IN_HEADER_LEN];
	uint8_t cmd_wr[VTSCSI_MAX_OUT_HEADER_LEN];

	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vss_mtx, NULL), 0);

	ATF_REQUIRE_EQ(pci_vtscsi_pause(&sc), 0);
	ATF_CHECK_EQ(g_clock_calls, 1);
	ATF_CHECK(!g_clock_nonmonotonic);
	ATF_CHECK(sc.vss_queues[0].vsq_quiescing);
	ATF_CHECK(sc.vss_checkpoint_resume[0]);
	ATF_REQUIRE_EQ(pci_vtscsi_resume(&sc), 0);
	ATF_CHECK(!sc.vss_queues[0].vsq_quiescing);
	ATF_CHECK(!sc.vss_checkpoint_resume[0]);

	/*
	 * A worker which does not drain by the device-wide deadline makes the
	 * checkpoint fail without transferring queue ownership.  The common
	 * layer can then remove its admission fence and leave the running VM
	 * unchanged.
	 */
	q = &sc.vss_queues[0];
	q->vsq_active = 1;
	g_clock_calls = 0;
	ATF_REQUIRE_EQ(pci_vtscsi_pause(&sc), ETIMEDOUT);
	ATF_CHECK_EQ(g_clock_calls, 1);
	ATF_CHECK(!g_clock_nonmonotonic);
	ATF_CHECK(!q->vsq_quiescing);
	ATF_CHECK(!sc.vss_checkpoint_resume[0]);
	q->vsq_active = 0;

	/* Selective queue reset owns this queue across a checkpoint. */
	sc.vss_queues[0].vsq_quiescing = true;
	ATF_REQUIRE_EQ(pci_vtscsi_pause(&sc), 0);
	ATF_CHECK(!sc.vss_checkpoint_resume[0]);
	ATF_REQUIRE_EQ(pci_vtscsi_resume(&sc), 0);
	ATF_CHECK(sc.vss_queues[0].vsq_quiescing);

	/*
	 * A reset-owned queue with a request still in flight cannot be taken
	 * over by checkpoint.  Failure must leave both owners unchanged and
	 * must not arm a later checkpoint resume.
	 */
	memset(&blocked_req, 0, sizeof(blocked_req));
	STAILQ_INSERT_TAIL(&q->vsq_requests, &blocked_req, vsr_link);
	ATF_REQUIRE_EQ(pci_vtscsi_pause(&sc), EBUSY);
	ATF_CHECK(q->vsq_quiescing);
	ATF_CHECK(!sc.vss_checkpoint_resume[0]);
	STAILQ_REMOVE_HEAD(&q->vsq_requests, vsr_link);

	pthread_mutex_destroy(&sc.vss_mtx);
	teardown_queue(&sc);
}

ATF_TC_WITHOUT_HEAD(guest_suspend_nests_with_checkpoint);
ATF_TC_BODY(guest_suspend_nests_with_checkpoint, tc)
{
	struct pci_vtscsi_request req;
	struct pci_vtscsi_softc sc;
	union ctl_io io;
	uint8_t cmd_rd[VTSCSI_MAX_IN_HEADER_LEN];
	uint8_t cmd_wr[VTSCSI_MAX_OUT_HEADER_LEN];

	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vss_mtx, NULL), 0);

	pthread_mutex_lock(&sc.vss_mtx);
	ATF_REQUIRE_EQ(pci_vtscsi_suspend_device(&sc), 0);
	pthread_mutex_unlock(&sc.vss_mtx);
	ATF_CHECK(sc.vss_suspend_resume[0]);
	ATF_CHECK(sc.vss_queues[0].vsq_quiescing);

	ATF_REQUIRE_EQ(pci_vtscsi_pause(&sc), 0);
	ATF_CHECK(!sc.vss_checkpoint_resume[0]);
	ATF_REQUIRE_EQ(pci_vtscsi_resume(&sc), 0);
	ATF_CHECK(sc.vss_queues[0].vsq_quiescing);

	pthread_mutex_lock(&sc.vss_mtx);
	ATF_REQUIRE_EQ(pci_vtscsi_resume_device(&sc), 0);
	pthread_mutex_unlock(&sc.vss_mtx);
	ATF_CHECK(!sc.vss_suspend_resume[0]);
	ATF_CHECK(!sc.vss_queues[0].vsq_quiescing);

	/*
	 * A restored guest-suspended device transfers the destination's
	 * checkpoint owner instead of briefly restarting the worker.
	 */
	ATF_REQUIRE_EQ(pci_vtscsi_pause(&sc), 0);
	ATF_CHECK(sc.vss_checkpoint_resume[0]);
	pci_vtscsi_restore_suspended(&sc);
	ATF_CHECK(!sc.vss_checkpoint_resume[0]);
	ATF_CHECK(sc.vss_suspend_resume[0]);
	ATF_REQUIRE_EQ(pci_vtscsi_resume(&sc), 0);
	ATF_CHECK(sc.vss_queues[0].vsq_quiescing);
	pthread_mutex_lock(&sc.vss_mtx);
	ATF_REQUIRE_EQ(pci_vtscsi_resume_device(&sc), 0);
	pthread_mutex_unlock(&sc.vss_mtx);
	ATF_CHECK(!sc.vss_queues[0].vsq_quiescing);

	/*
	 * Conversely, a runnable image releases only the destination's old
	 * guest-suspend queue markers.  Checkpoint pause saw that queue already
	 * quiesced and therefore has no second per-queue marker to consume.
	 */
	pthread_mutex_lock(&sc.vss_mtx);
	ATF_REQUIRE_EQ(pci_vtscsi_suspend_device(&sc), 0);
	pthread_mutex_unlock(&sc.vss_mtx);
	ATF_CHECK(sc.vss_suspend_resume[0]);
	ATF_REQUIRE_EQ(pci_vtscsi_pause(&sc), 0);
	ATF_CHECK(!sc.vss_checkpoint_resume[0]);
	/* Drop checkpoint ownership first: restore must also work lock-free. */
	ATF_REQUIRE_EQ(pci_vtscsi_resume(&sc), 0);
	pci_vtscsi_restore_resumed(&sc);
	ATF_CHECK(!sc.vss_suspend_resume[0]);
	ATF_CHECK(!sc.vss_queues[0].vsq_quiescing);

	pthread_mutex_destroy(&sc.vss_mtx);
	teardown_queue(&sc);
}

ATF_TC_WITHOUT_HEAD(checkpoint_multiqueue_failure_rolls_back_earlier_queues);
ATF_TC_BODY(checkpoint_multiqueue_failure_rolls_back_earlier_queues, tc)
{
	struct pci_vtscsi_request requests[2];
	struct pci_vtscsi_softc sc;
	union ctl_io ios[2];
	uint8_t cmd_rd[2][VTSCSI_MAX_IN_HEADER_LEN];
	uint8_t cmd_wr[2][VTSCSI_MAX_OUT_HEADER_LEN];

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vss_config.cdb_size = VIRTIO14_SCSI_DEFAULT_CDB_SIZE;
	sc.vss_config.sense_size = VIRTIO14_SCSI_DEFAULT_SENSE_SIZE;
	sc.vss_nrequestq = 2;
	setup_request_queue(&sc, 0, &requests[0], cmd_rd[0], cmd_wr[0],
	    &ios[0]);
	setup_request_queue(&sc, 1, &requests[1], cmd_rd[1], cmd_wr[1],
	    &ios[1]);
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vss_mtx, NULL), 0);

	/* Queue 0 is acquired first; queue 1 forces the bounded drain failure. */
	sc.vss_queues[1].vsq_active = 1;
	ATF_REQUIRE_EQ(pci_vtscsi_pause(&sc), ETIMEDOUT);
	ATF_CHECK_EQ(g_clock_calls, 1);
	ATF_CHECK(!g_clock_nonmonotonic);
	ATF_CHECK(!sc.vss_queues[0].vsq_quiescing);
	ATF_CHECK(!sc.vss_queues[1].vsq_quiescing);
	ATF_CHECK(!sc.vss_checkpoint_resume[0]);
	ATF_CHECK(!sc.vss_checkpoint_resume[1]);

	sc.vss_queues[1].vsq_active = 0;
	pthread_mutex_destroy(&sc.vss_mtx);
	teardown_request_queue(&sc, 1);
	teardown_request_queue(&sc, 0);
}

ATF_TC_WITHOUT_HEAD(control_handler_validation);
ATF_TC_BODY(control_handler_validation, tc)
{
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_ctrl_tmf tmf = {
		.type = htole32(VIRTIO_SCSI_T_TMF),
		.subtype = htole32(UINT32_MAX),
		.lun = { VIRTIO14_SCSI_LUN_ADDRESS_METHOD, 0x00, 0x00,
		    0x00 },
	};
	struct pci_vtscsi_ctrl_an an = {
		.type = htole32(VIRTIO_SCSI_T_AN_QUERY),
	};
	uint8_t an_wire[VIRTIO14_SCSI_AN_REQUEST_SIZE +
	    VIRTIO14_SCSI_AN_RESPONSE_SIZE];
	uint32_t unknown;
	size_t written;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	written = pci_vtscsi_control_handle(&sc, &tmf,
	    VIRTIO14_SCSI_TMF_RESPONSE_OFF, VIRTIO14_SCSI_TMF_RESPONSE_SIZE);
	ATF_CHECK(written == 1);
	ATF_CHECK(*(uint8_t *)&tmf == VIRTIO_SCSI_S_FUNCTION_REJECTED);
	ATF_CHECK(g_ctl_allocs == 1 && g_ctl_frees == 1);

	reset_mocks();
	written = pci_vtscsi_control_handle(&sc, &an,
	    VIRTIO14_SCSI_AN_EVENT_ACTUAL_OFF,
	    VIRTIO14_SCSI_AN_EVENT_ACTUAL_SIZE +
	    VIRTIO14_SCSI_AN_RESPONSE_SIZE);
	ATF_CHECK(written == VIRTIO14_SCSI_AN_EVENT_ACTUAL_SIZE +
	    VIRTIO14_SCSI_AN_RESPONSE_SIZE);
	for (size_t i = 0; i < written; i++)
		ATF_CHECK(((uint8_t *)&an)[i] == 0);

	/*
	 * Section 5.6.6.2 assigns AN_SUBSCRIBE the independent wire value 2
	 * and the same response layout as AN_QUERY.  With no event source
	 * advertised, the supported subscription set is empty.
	 */
	memset(&an, 0, sizeof(an));
	virtio14_store_le32((uint8_t *)&an,
	    VIRTIO14_SCSI_T_AN_SUBSCRIBE);
	written = pci_vtscsi_control_handle(&sc, &an,
	    VIRTIO14_SCSI_AN_EVENT_ACTUAL_OFF,
	    VIRTIO14_SCSI_AN_EVENT_ACTUAL_SIZE +
	    VIRTIO14_SCSI_AN_RESPONSE_SIZE);
	ATF_REQUIRE_EQ(written, VIRTIO14_SCSI_AN_EVENT_ACTUAL_SIZE +
	    VIRTIO14_SCSI_AN_RESPONSE_SIZE);
	for (size_t i = 0; i < written; i++)
		ATF_CHECK_EQ(((uint8_t *)&an)[i], 0);

	/*
	 * Section 5.6.6.2 places the AN response after the le32
	 * event_actual field.  A malformed request with a complete writable
	 * response must not put FAILURE into event_actual.
	 */
	memset(an_wire, 0xa5, sizeof(an_wire));
	virtio14_store_le32(an_wire, VIRTIO14_SCSI_T_AN_QUERY);
	written = pci_vtscsi_control_handle(&sc, an_wire,
	    VIRTIO14_SCSI_AN_EVENT_ACTUAL_OFF - 1,
	    VIRTIO14_SCSI_AN_EVENT_ACTUAL_SIZE +
	    VIRTIO14_SCSI_AN_RESPONSE_SIZE);
	ATF_REQUIRE_EQ(written, VIRTIO14_SCSI_AN_EVENT_ACTUAL_SIZE +
	    VIRTIO14_SCSI_AN_RESPONSE_SIZE);
	for (size_t i = 0; i < VIRTIO14_SCSI_AN_EVENT_ACTUAL_SIZE; i++)
		ATF_CHECK_EQ(an_wire[i], 0);
	ATF_CHECK_EQ(an_wire[VIRTIO14_SCSI_AN_EVENT_ACTUAL_SIZE],
	    VIRTIO_SCSI_S_FAILURE);

	memset(an_wire, 0xa5, sizeof(an_wire));
	virtio14_store_le32(an_wire, VIRTIO14_SCSI_T_AN_QUERY);
	written = pci_vtscsi_control_handle(&sc, an_wire,
	    VIRTIO14_SCSI_AN_EVENT_ACTUAL_OFF - 1,
	    VIRTIO14_SCSI_AN_EVENT_ACTUAL_SIZE);
	ATF_CHECK_EQ(written, 0);

	unknown = htole32(UINT32_MAX);
	written = pci_vtscsi_control_handle(&sc, &unknown, sizeof(unknown), 1);
	ATF_CHECK(written == 1);
	ATF_CHECK(*(uint8_t *)&unknown == VIRTIO_SCSI_S_FAILURE);

	unknown = htole32(VIRTIO_SCSI_T_TMF);
	written = pci_vtscsi_control_handle(&sc, &unknown, sizeof(unknown), 0);
	ATF_CHECK(written == 0);
}

ATF_TC_WITHOUT_HEAD(control_queue_validation);
ATF_TC_BODY(control_queue_validation, tc)
{
	struct pci_vtscsi_softc sc;
	uint8_t input[VIRTIO14_SCSI_AN_REQUEST_SIZE];
	uint8_t before[VIRTIO14_SCSI_AN_REQUEST_SIZE];
	uint8_t output[VIRTIO14_SCSI_AN_EVENT_ACTUAL_SIZE +
	    VIRTIO14_SCSI_AN_RESPONSE_SIZE];

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vss_vq[0].vq_qsize = VTSCSI_RINGSZ;
	memset(input, 0, sizeof(input));
	virtio14_store_le32(input, VIRTIO14_SCSI_T_AN_QUERY);
	memset(output, 0xa5, sizeof(output));
	memcpy(before, input, sizeof(before));
	set_chain(2, 1, 1, true);
	g_chain.iov[0] = (struct iovec){
		.iov_base = input,
		.iov_len = VIRTIO14_SCSI_AN_EVENT_ACTUAL_OFF,
	};
	g_chain.iov[1] = (struct iovec){
		.iov_base = output,
		.iov_len = sizeof(output),
	};
	pci_vtscsi_controlq_notify(&sc, &sc.vss_vq[0]);
	ATF_CHECK(memcmp(before, input, sizeof(input)) == 0);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == sizeof(output));
	for (size_t i = 0; i < sizeof(output); i++)
		ATF_CHECK(output[i] == 0);

	reset_mocks();
	set_chain(2, 2, 0, true);
	pci_vtscsi_controlq_notify(&sc, &sc.vss_vq[0]);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 0);

	reset_mocks();
	set_chain(VTSCSI_MAXSEG + 1, 1, VTSCSI_MAXSEG, true);
	pci_vtscsi_controlq_notify(&sc, &sc.vss_vq[0]);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 0);

	reset_mocks();
	set_chain(-1, 0, 0, true);
	pci_vtscsi_controlq_notify(&sc, &sc.vss_vq[0]);
	ATF_CHECK(g_rel_calls == 0);
}

ATF_TC_WITHOUT_HEAD(tmf_response_mapping);
ATF_TC_BODY(tmf_response_mapping, tc)
{

	ATF_CHECK(pci_vtscsi_tmf_response(CTL_TASK_FUNCTION_COMPLETE) ==
	    VIRTIO_SCSI_S_FUNCTION_COMPLETE);
	ATF_CHECK(pci_vtscsi_tmf_response(CTL_TASK_FUNCTION_SUCCEEDED) ==
	    VIRTIO_SCSI_S_FUNCTION_SUCCEEDED);
	ATF_CHECK(pci_vtscsi_tmf_response(CTL_TASK_FUNCTION_REJECTED) ==
	    VIRTIO_SCSI_S_FUNCTION_REJECTED);
	ATF_CHECK(pci_vtscsi_tmf_response(CTL_TASK_FUNCTION_NOT_SUPPORTED) ==
	    VIRTIO_SCSI_S_FUNCTION_REJECTED);
	ATF_CHECK(pci_vtscsi_tmf_response(CTL_TASK_LUN_DOES_NOT_EXIST) ==
	    VIRTIO_SCSI_S_BAD_TARGET);
	ATF_CHECK(pci_vtscsi_tmf_response(UINT8_MAX) ==
	    VIRTIO_SCSI_S_FAILURE);
}

ATF_TC_WITHOUT_HEAD(config_writes);
ATF_TC_BODY(config_writes, tc)
{
	struct pci_vtscsi_softc sc;
	uint32_t old_num_queues;
	uint32_t value;

	memset(&sc, 0, sizeof(sc));
	sc.vss_config.num_queues = 1;
	sc.vss_config.sense_size = VIRTIO14_SCSI_DEFAULT_SENSE_SIZE;
	sc.vss_config.cdb_size = VIRTIO14_SCSI_DEFAULT_CDB_SIZE;
	old_num_queues = sc.vss_config.num_queues;

	ATF_CHECK(pci_vtscsi_cfgwrite(&sc,
	    VIRTIO14_SCSI_CONFIG_SENSE_SIZE_OFF, 4, 64) == 0);
	ATF_CHECK(sc.vss_config.sense_size == 64);
	ATF_CHECK(pci_vtscsi_cfgwrite(&sc,
	    VIRTIO14_SCSI_CONFIG_CDB_SIZE_OFF, 4, 16) == 0);
	ATF_CHECK(sc.vss_config.cdb_size == 16);
	ATF_CHECK(pci_vtscsi_cfgwrite(&sc,
	    VIRTIO14_SCSI_CONFIG_NUM_QUEUES_OFF, 4, 2) == 1);
	ATF_CHECK(sc.vss_config.num_queues == old_num_queues);
	ATF_CHECK(pci_vtscsi_cfgwrite(&sc,
	    VIRTIO14_SCSI_CONFIG_SENSE_SIZE_OFF, 4,
	    SSD_FULL_SIZE + 1) == 1);
	ATF_CHECK(pci_vtscsi_cfgwrite(&sc,
	    VIRTIO14_SCSI_CONFIG_CDB_SIZE_OFF, 4, 0) == 1);
	ATF_CHECK(pci_vtscsi_cfgwrite(&sc,
	    VIRTIO14_SCSI_CONFIG_CDB_SIZE_OFF, 2, 16) == 1);

	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtscsi_cfgread(&sc,
	    VIRTIO14_SCSI_CONFIG_CDB_SIZE_OFF, 4, &value), 0);
	ATF_CHECK_EQ(value, 16);
	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtscsi_cfgread(&sc, -1, 1, &value), EINVAL);
	ATF_CHECK_EQ(value, 0);
	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtscsi_cfgread(&sc, 0, 3, &value), EINVAL);
	ATF_CHECK_EQ(value, 0);
	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtscsi_cfgread(&sc,
	    VIRTIO14_SCSI_CONFIG_SIZE - 1, 4,
	    &value), EINVAL);
	ATF_CHECK_EQ(value, 0);
	ATF_CHECK_EQ(pci_vtscsi_cfgread(&sc, 0, 1, NULL), EINVAL);

	sc.vss_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	ATF_CHECK(pci_vtscsi_cfgwrite(&sc,
	    VIRTIO14_SCSI_CONFIG_CDB_SIZE_OFF, 4, 12) == 1);
	ATF_CHECK(sc.vss_config.cdb_size == 16);
}

ATF_TC_WITHOUT_HEAD(config_defaults);
ATF_TC_BODY(config_defaults, tc)
{
	struct pci_vtscsi_softc sc;

	memset(&sc, 0, sizeof(sc));
	sc.vss_nrequestq = VTSCSI_DEFAULT_REQUESTQ;
	sc.vss_features = UINT32_MAX;
	pci_vtscsi_reset(&sc);
	ATF_CHECK_EQ(sc.vss_features, 0);
	ATF_CHECK_EQ(sc.vss_config.num_queues, VTSCSI_DEFAULT_REQUESTQ);
	ATF_CHECK_EQ(sc.vss_config.seg_max, VTSCSI_MAXSEG - 2);
	ATF_CHECK_EQ(sc.vss_config.max_sectors, VTSCSI_MAX_SECTORS);
	ATF_CHECK_EQ(sc.vss_config.cmd_per_lun, VTSCSI_TOTAL_THR);
	ATF_CHECK(
	    (uint64_t)sc.vss_config.max_sectors *
	    VIRTIO14_SCSI_SECTOR_BYTES +
	    VTSCSI_MAX_OUT_HEADER_LEN <= UINT32_MAX);
	ATF_CHECK(
	    ((uint64_t)sc.vss_config.max_sectors + 1) *
	    VIRTIO14_SCSI_SECTOR_BYTES +
	    VTSCSI_MAX_OUT_HEADER_LEN > UINT32_MAX);
	ATF_CHECK_EQ(sc.vss_config.sense_size,
	    VIRTIO14_SCSI_DEFAULT_SENSE_SIZE);
	ATF_CHECK_EQ(sc.vss_config.cdb_size,
	    VIRTIO14_SCSI_DEFAULT_CDB_SIZE);
	ATF_CHECK_EQ(sc.vss_config.max_channel,
	    VIRTIO14_SCSI_MAX_CHANNEL);
	ATF_CHECK(sc.vss_config.max_target <=
	    VIRTIO14_SCSI_MAX_TARGET_LIMIT);
	ATF_CHECK(sc.vss_config.max_lun <=
	    VIRTIO14_SCSI_MAX_LUN_LIMIT);
}

ATF_TC_WITHOUT_HEAD(document_wire_vectors);
ATF_TC_BODY(document_wire_vectors, tc)
{
	struct pci_vtscsi_softc sc;
	uint64_t aligned[(VIRTIO14_SCSI_TMF_REQUEST_SIZE +
	    VIRTIO14_SCSI_TMF_RESPONSE_SIZE + sizeof(uint64_t) - 1) /
	    sizeof(uint64_t)];
	uint8_t *wire;
	uint64_t id_wire;
	uint32_t response_wire;
	uint32_t config_wire;
	size_t written;

	/*
	 * Encode a TMF request using only section 5.6.6.2 offsets.  An all-zero
	 * LUN is invalid, so the documented BAD_TARGET response is deterministic
	 * and does not depend on a CTL backend.
	 */
	memset(&sc, 0, sizeof(sc));
	wire = (uint8_t *)(void *)aligned;
	memset(wire, 0, VIRTIO14_SCSI_TMF_REQUEST_SIZE +
	    VIRTIO14_SCSI_TMF_RESPONSE_SIZE);
	virtio14_store_le32(wire + VIRTIO14_SCSI_TMF_TYPE_OFF,
	    VIRTIO14_SCSI_T_TMF);
	virtio14_store_le32(wire + VIRTIO14_SCSI_TMF_SUBTYPE_OFF,
	    VIRTIO14_SCSI_T_TMF_ABORT_TASK);
	written = pci_vtscsi_control_handle(&sc, wire,
	    VIRTIO14_SCSI_TMF_REQUEST_SIZE,
	    VIRTIO14_SCSI_TMF_RESPONSE_SIZE);
	ATF_REQUIRE_EQ(written, VIRTIO14_SCSI_TMF_RESPONSE_SIZE);
	ATF_CHECK_EQ(wire[0], VIRTIO14_SCSI_S_BAD_TARGET);

	/*
	 * Section 5.6.6 declares the command id le64 and response lengths le32.
	 * Build both solely as byte vectors, then verify the transport-aware
	 * conversion used by the device model.
	 */
	sc.vss_vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	memset(wire, 0, VIRTIO14_SCSI_CMD_REQUEST_FIXED_SIZE);
	virtio14_store_le64(wire + VIRTIO14_SCSI_CMD_REQUEST_ID_OFF,
	    UINT64_C(0x0123456789abcdef));
	memcpy(&id_wire, wire + VIRTIO14_SCSI_CMD_REQUEST_ID_OFF,
	    VIRTIO14_SCSI_CMD_REQUEST_ID_SIZE);
	ATF_CHECK_EQ(pci_vtscsi_decode64(&sc, id_wire),
	    UINT64_C(0x0123456789abcdef));

	response_wire = pci_vtscsi_encode32(&sc, UINT32_C(0x10203040));
	memcpy(wire, &response_wire, sizeof(response_wire));
	ATF_CHECK_EQ(wire[0], 0x40);
	ATF_CHECK_EQ(wire[1], 0x30);
	ATF_CHECK_EQ(wire[2], 0x20);
	ATF_CHECK_EQ(wire[3], 0x10);

	sc.vss_config.max_lun = UINT32_C(0x01020304);
	ATF_REQUIRE_EQ(pci_vtscsi_cfgread(&sc,
	    VIRTIO14_SCSI_CONFIG_MAX_LUN_OFF, sizeof(config_wire),
	    &config_wire), 0);
	memcpy(wire, &config_wire, sizeof(config_wire));
	ATF_CHECK_EQ(wire[0], 0x04);
	ATF_CHECK_EQ(wire[1], 0x03);
	ATF_CHECK_EQ(wire[2], 0x02);
	ATF_CHECK_EQ(wire[3], 0x01);
}

ATF_TC_WITHOUT_HEAD(request_queue_validation);
ATF_TC_BODY(request_queue_validation, tc)
{
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_request req;
	struct vqueue_info impostor;
	union ctl_io io;
	uint8_t cmd_rd[VTSCSI_MAX_IN_HEADER_LEN];
	uint8_t cmd_wr[VTSCSI_MAX_OUT_HEADER_LEN];
	uint8_t output;

	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	impostor = sc.vss_vq[2];
	set_chain(-1, 0, 0, true);
	pci_vtscsi_requestq_notify(&sc, &impostor);
	ATF_CHECK_EQ(g_chain_ready, 1);
	sc.vss_vq[2].vq_num = 1;
	pci_vtscsi_requestq_notify(&sc, &sc.vss_vq[2]);
	ATF_CHECK_EQ(g_chain_ready, 1);
	sc.vss_vq[2].vq_num = 2;
	teardown_queue(&sc);

	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	g_expected_vq_mutex = &sc.vss_queues[0].vsq_qmtx;
	set_chain(-1, 0, 0, true);
	ATF_CHECK(!pci_vtscsi_queue_request(&sc, &sc.vss_vq[2]));
	ATF_CHECK(g_getchain_had_vq_lock);
	ATF_CHECK(!STAILQ_EMPTY(&sc.vss_queues[0].vsq_free_requests));
	ATF_CHECK(g_rel_calls == 0);
	teardown_queue(&sc);

	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	set_chain(VTSCSI_MAXSEG + 1, 1, VTSCSI_MAXSEG, true);
	ATF_CHECK(pci_vtscsi_queue_request(&sc, &sc.vss_vq[2]));
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 0);
	ATF_CHECK(!STAILQ_EMPTY(&sc.vss_queues[0].vsq_free_requests));
	teardown_queue(&sc);

	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	set_chain(2, 1, 1, false);
	ATF_CHECK(pci_vtscsi_queue_request(&sc, &sc.vss_vq[2]));
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 0);
	teardown_queue(&sc);

	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	output = 0xa5;
	set_chain(2, 1, 1, true);
	g_chain.iov[0] = (struct iovec){
		.iov_base = cmd_rd,
		.iov_len = VIRTIO14_SCSI_DEFAULT_CMD_REQUEST_SIZE,
	};
	g_chain.iov[1] = (struct iovec){
		.iov_base = &output,
		.iov_len = sizeof(output),
	};
	ATF_CHECK(pci_vtscsi_queue_request(&sc, &sc.vss_vq[2]));
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 1);
	teardown_queue(&sc);
}

ATF_TC_WITHOUT_HEAD(report_luns_well_known_lun);
ATF_TC_BODY(report_luns_well_known_lun, tc)
{
	struct pci_vtscsi_req_cmd_rd *command;
	struct pci_vtscsi_req_cmd_wr response;
	struct pci_vtscsi_request request;
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_ctrl_tmf *control_request;
	union {
		max_align_t alignment;
		uint8_t bytes[VIRTIO14_SCSI_TMF_REQUEST_SIZE +
		    VIRTIO14_SCSI_TMF_RESPONSE_SIZE];
	} tmf_storage;
	uint8_t command_bytes[VTSCSI_MAX_IN_HEADER_LEN];
	/*
	 * VirtIO 1.4 section 5.6.6.1 recommends accepting this exact
	 * extended-addressing form for the REPORT LUNS well-known logical
	 * unit.  Keep the literal independent of the production parser.
	 */
	static const uint8_t report_luns[8] =
	    { 0xc1, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	static const uint8_t malformed_report_luns[8] =
	    { 0xc1, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	static const uint8_t target_zero_lun_zero[8] =
	    { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	ATF_CHECK(pci_vtscsi_check_lun(report_luns));
	ATF_CHECK(pci_vtscsi_report_luns_well_known(report_luns));
	ATF_CHECK_EQ(pci_vtscsi_get_lun(report_luns), UINT32_MAX);
	ATF_CHECK(!pci_vtscsi_check_lun(malformed_report_luns));
	ATF_CHECK(pci_vtscsi_check_lun(target_zero_lun_zero));

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	memset(&request, 0, sizeof(request));
	memset(command_bytes, 0, sizeof(command_bytes));
	memset(&response, 0, sizeof(response));
	command = (struct pci_vtscsi_req_cmd_rd *)(void *)command_bytes;
	memcpy(command_bytes, report_luns, sizeof(report_luns));
	command_bytes[VIRTIO14_SCSI_CMD_REQUEST_CDB_OFF] =
	    0xa0;	/* REPORT LUNS, SPC */
	request.vsr_cmd_rd = command;
	request.vsr_cmd_wr = &response;
	request.vsr_ctl_io = &g_ctl_io;
	sc.vss_config.cdb_size = VIRTIO14_SCSI_DEFAULT_CDB_SIZE;
	sc.vss_config.sense_size = VIRTIO14_SCSI_DEFAULT_SENSE_SIZE;
	g_ctl_io_success = true;
	ATF_CHECK_EQ(pci_vtscsi_request_handle(&sc, &request), 0);
	ATF_CHECK_EQ(g_ctl_last_targ_lun, UINT32_MAX);
	ATF_CHECK_EQ(response.response, VIRTIO14_SCSI_S_OK);

	memset(&tmf_storage, 0, sizeof(tmf_storage));
	control_request =
	    (struct pci_vtscsi_ctrl_tmf *)(void *)tmf_storage.bytes;
	memcpy(tmf_storage.bytes + VIRTIO14_SCSI_TMF_LUN_OFF, report_luns,
	    sizeof(report_luns));
	pci_vtscsi_tmf_handle(&sc, control_request);
	ATF_CHECK_EQ(control_request->response, VIRTIO14_SCSI_S_BAD_TARGET);
	ATF_CHECK_EQ(g_ctl_allocs, 0);
}

ATF_TC_WITHOUT_HEAD(request_payload_validation);
ATF_TC_BODY(request_payload_validation, tc)
{
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_request req;
	struct pci_vtscsi_req_cmd_wr response;
	struct iovec in, out;
	uint8_t byte;

	memset(&sc, 0, sizeof(sc));
	memset(&req, 0, sizeof(req));
	memset(&response, 0, sizeof(response));
	in = (struct iovec){ .iov_base = &byte, .iov_len = 1 };
	out = (struct iovec){ .iov_base = &byte, .iov_len = 1 };
	req.vsr_cmd_wr = &response;
	req.vsr_data_iov_in = &in;
	req.vsr_data_niov_in = 1;
	req.vsr_data_iov_out = &out;
	req.vsr_data_niov_out = 1;
	ATF_CHECK(pci_vtscsi_request_handle(&sc, &req) == 0);
	ATF_CHECK(response.response == VIRTIO_SCSI_S_FAILURE);

	memset(&response, 0, sizeof(response));
	req.vsr_data_iov_out = NULL;
	req.vsr_data_niov_out = 0;
	in.iov_len = UINT32_MAX;
	ATF_CHECK(pci_vtscsi_request_handle(&sc, &req) == 0);
	ATF_CHECK(response.response == VIRTIO_SCSI_S_FAILURE);
}

ATF_TC_WITHOUT_HEAD(request_response_mapping);
ATF_TC_BODY(request_response_mapping, tc)
{
	union ctl_io io;

	memset(&io, 0, sizeof(io));
	io.io_hdr.status = CTL_SUCCESS;
	io.scsiio.ext_data_filled = 4096;
	ATF_CHECK_EQ(pci_vtscsi_request_response(&io, 4096),
	    VIRTIO_SCSI_S_OK);
	io.scsiio.ext_data_filled++;
	ATF_CHECK_EQ(pci_vtscsi_request_response(&io, 4096),
	    VIRTIO_SCSI_S_OVERRUN);

	memset(&io, 0, sizeof(io));
	io.io_hdr.status = CTL_SCSI_ERROR | CTL_AUTOSENSE;
	io.scsiio.scsi_status = SCSI_STATUS_CHECK_COND;
	ATF_CHECK_EQ(pci_vtscsi_request_response(&io, 0),
	    VIRTIO_SCSI_S_OK);

	io.io_hdr.status = CTL_CMD_ABORTED;
	ATF_CHECK_EQ(pci_vtscsi_request_response(&io, 0),
	    VIRTIO_SCSI_S_ABORTED);
	io.io_hdr.status = CTL_SEL_TIMEOUT;
	ATF_CHECK_EQ(pci_vtscsi_request_response(&io, 0),
	    VIRTIO_SCSI_S_TRANSPORT_FAILURE);
	io.io_hdr.status = CTL_ERROR;
	ATF_CHECK_EQ(pci_vtscsi_request_response(&io, 0),
	    VIRTIO_SCSI_S_FAILURE);
	io.io_hdr.status = CTL_STATUS_NONE;
	ATF_CHECK_EQ(pci_vtscsi_request_response(&io, 0),
	    VIRTIO_SCSI_S_FAILURE);

	io.io_hdr.status = CTL_SUCCESS;
	io.io_hdr.port_status = 1;
	ATF_CHECK_EQ(pci_vtscsi_request_response(&io, 0),
	    VIRTIO_SCSI_S_TRANSPORT_FAILURE);
	io.io_hdr.status = CTL_CMD_ABORTED;
	ATF_CHECK_EQ(pci_vtscsi_request_response(&io, 0),
	    VIRTIO_SCSI_S_TRANSPORT_FAILURE);
}

ATF_TC_WITHOUT_HEAD(reset_completes_pending_requests);
ATF_TC_BODY(reset_completes_pending_requests, tc)
{
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_request req;
	struct pci_vtscsi_queue *q;
	union ctl_io io;
	uint8_t cmd_rd[VTSCSI_MAX_IN_HEADER_LEN];
	uint8_t cmd_wr[VTSCSI_MAX_OUT_HEADER_LEN];
	uint8_t response[VTSCSI_MAX_OUT_HEADER_LEN];
	size_t response_len;

	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	q = &sc.vss_queues[0];
	ATF_REQUIRE(pci_vtscsi_get_request(&q->vsq_free_requests) == &req);
	memset(response, 0, sizeof(response));
	response_len = VIRTIO14_SCSI_DEFAULT_CMD_RESPONSE_SIZE;
	req.vsr_idx = 19;
	req.vsr_vreq.idx = 19;
	req.vsr_iov_out = &req.vsr_iov[0];
	req.vsr_niov_out = 1;
	req.vsr_iov[0] = (struct iovec){
		.iov_base = response,
		.iov_len = response_len,
	};
	pci_vtscsi_put_request(&q->vsq_requests, &req);

	ATF_REQUIRE_EQ(pci_vtscsi_quiesce_queue(q, true, false), 0);
	ATF_CHECK(q->vsq_quiescing);
	ATF_CHECK(STAILQ_EMPTY(&q->vsq_requests));
	ATF_CHECK(pci_vtscsi_get_request(&q->vsq_free_requests) == &req);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_idx, 19);
	ATF_CHECK_EQ(g_rel_len, response_len);
	ATF_CHECK_EQ(g_end_calls, 1);
	ATF_CHECK_EQ(response[VIRTIO14_SCSI_CMD_RESPONSE_RESPONSE_OFF],
	    VIRTIO14_SCSI_S_RESET);

	pci_vtscsi_resume_queue(q);
	ATF_CHECK(!q->vsq_quiescing);
	teardown_queue(&sc);
}

ATF_TC_WITHOUT_HEAD(reset_timeout_requires_device_reset);
ATF_TC_BODY(reset_timeout_requires_device_reset, tc)
{
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_request req;
	union ctl_io io;
	uint8_t cmd_rd[VTSCSI_MAX_IN_HEADER_LEN];
	uint8_t cmd_wr[VTSCSI_MAX_OUT_HEADER_LEN];
	struct pci_vtscsi_queue *q;

	(void)tc;
	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	q = &sc.vss_queues[0];
	q->vsq_active = 1;
	pci_vtscsi_reset(&sc);
	ATF_CHECK_EQ(g_clock_calls, 1);
	ATF_CHECK(!g_clock_nonmonotonic);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK(q->vsq_quiescing);
	ATF_CHECK_EQ(q->vsq_active, 1);
	q->vsq_active = 0;
	pci_vtscsi_resume_queue(q);
	teardown_queue(&sc);
}

ATF_TC_WITHOUT_HEAD(reset_timeout_uses_one_device_deadline);
ATF_TC_BODY(reset_timeout_uses_one_device_deadline, tc)
{
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_request req[2];
	union ctl_io io[2];
	uint8_t cmd_rd[2][VTSCSI_MAX_IN_HEADER_LEN];
	uint8_t cmd_wr[2][VTSCSI_MAX_OUT_HEADER_LEN];

	(void)tc;
	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vss_nrequestq = 2;
	setup_request_queue(&sc, 0, &req[0], cmd_rd[0], cmd_wr[0], &io[0]);
	setup_request_queue(&sc, 1, &req[1], cmd_rd[1], cmd_wr[1], &io[1]);
	sc.vss_queues[1].vsq_active = 1;
	pci_vtscsi_reset(&sc);
	ATF_CHECK_EQ(g_clock_calls, 1);
	ATF_CHECK(!g_clock_nonmonotonic);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK(sc.vss_queues[0].vsq_quiescing);
	ATF_CHECK(sc.vss_queues[1].vsq_quiescing);
	sc.vss_queues[1].vsq_active = 0;
	pci_vtscsi_resume_queue(&sc.vss_queues[1]);
	pci_vtscsi_resume_queue(&sc.vss_queues[0]);
	teardown_request_queue(&sc, 1);
	teardown_request_queue(&sc, 0);
}

ATF_TC_WITHOUT_HEAD(queue_reset_quiesces_only_selected_queue);
ATF_TC_BODY(queue_reset_quiesces_only_selected_queue, tc)
{
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_request req[2];
	struct pci_vtscsi_queue *q0, *q1;
	union ctl_io io[2];
	uint8_t cmd_rd[2][VTSCSI_MAX_IN_HEADER_LEN];
	uint8_t cmd_wr[2][VTSCSI_MAX_OUT_HEADER_LEN];

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vss_nrequestq = 2;
	setup_request_queue(&sc, 0, &req[0], cmd_rd[0], cmd_wr[0], &io[0]);
	setup_request_queue(&sc, 1, &req[1], cmd_rd[1], cmd_wr[1], &io[1]);
	q0 = &sc.vss_queues[0];
	q1 = &sc.vss_queues[1];
	ATF_REQUIRE(pci_vtscsi_get_request(&q0->vsq_free_requests) ==
	    &req[0]);
	ATF_REQUIRE(pci_vtscsi_get_request(&q1->vsq_free_requests) ==
	    &req[1]);
	req[0].vsr_vreq.outstanding = true;
	req[0].vsr_vreq.queue_generation = 8;
	pci_vtscsi_put_request(&q0->vsq_requests, &req[0]);
	pci_vtscsi_put_request(&q1->vsq_requests, &req[1]);

	g_expected_vq_mutex = &q0->vsq_qmtx;
	ATF_CHECK_EQ(pci_vtscsi_qreset(&sc, &sc.vss_vq[2], 9), 0);
	g_expected_vq_mutex = NULL;
	ATF_CHECK(q0->vsq_quiescing);
	ATF_CHECK(STAILQ_EMPTY(&q0->vsq_requests));
	ATF_CHECK(pci_vtscsi_get_request(&q0->vsq_free_requests) ==
	    &req[0]);
	ATF_CHECK(!q1->vsq_quiescing);
	ATF_CHECK(STAILQ_FIRST(&q1->vsq_requests) == &req[1]);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(g_discard_calls, 1);
	ATF_CHECK(g_discard_had_vq_lock);
	ATF_CHECK(g_discard_was_outstanding);
	ATF_CHECK((vtscsi_vi_consts.vc_hv_caps &
	    VIRTIO_F_RING_RESET) != 0);

	ATF_CHECK_EQ(pci_vtscsi_qenable(&sc, &sc.vss_vq[2]), 0);
	ATF_CHECK(!q0->vsq_quiescing);
	q0->vsq_active = 1;
	ATF_CHECK_EQ(pci_vtscsi_qreset(&sc, &sc.vss_vq[2], 10),
	    ETIMEDOUT);
	ATF_CHECK(q0->vsq_quiescing);
	ATF_CHECK_EQ(q0->vsq_active, 1);
	q0->vsq_active = 0;
	pci_vtscsi_resume_queue(q0);
	sc.vss_vq[2].vq_num = sc.vss_nrequestq + 2;
	ATF_CHECK_EQ(pci_vtscsi_qreset(&sc, &sc.vss_vq[2], 11), EINVAL);
	ATF_CHECK_EQ(pci_vtscsi_qenable(&sc, &sc.vss_vq[2]), EINVAL);
	req[1].vsr_vreq.outstanding = true;
	ATF_REQUIRE_EQ(pci_vtscsi_quiesce_queue(q1, false, false), 0);
	pci_vtscsi_resume_queue(q1);
	teardown_request_queue(&sc, 1);
	teardown_request_queue(&sc, 0);
}

ATF_TC_WITHOUT_HEAD(multiqueue_configuration);
ATF_TC_BODY(multiqueue_configuration, tc)
{
	struct pci_vtscsi_softc sc;
	const char *errstr;
	uint16_t queues;

	ATF_REQUIRE_EQ(pci_vtscsi_parse_queues(NULL, &queues, &errstr), 0);
	ATF_CHECK_EQ(queues, VTSCSI_DEFAULT_REQUESTQ);
	ATF_REQUIRE_EQ(pci_vtscsi_parse_queues("8", &queues, &errstr), 0);
	ATF_CHECK_EQ(queues, VTSCSI_MAX_REQUESTQ);
	ATF_CHECK_EQ(pci_vtscsi_parse_queues("0", &queues, &errstr), EINVAL);
	ATF_CHECK(errstr != NULL);
	ATF_CHECK_EQ(pci_vtscsi_parse_queues("9", &queues, &errstr), EINVAL);
	ATF_CHECK(errstr != NULL);
	ATF_CHECK_EQ(pci_vtscsi_parse_queues("many", &queues, &errstr),
	    EINVAL);
	ATF_CHECK(errstr != NULL);

	memset(&sc, 0, sizeof(sc));
	sc.vss_nrequestq = 4;
	sc.vss_consts = vtscsi_vi_consts;
	sc.vss_consts.vc_nvq = sc.vss_nrequestq + 2;
	pci_vtscsi_reset(&sc);
	ATF_CHECK_EQ(sc.vss_config.num_queues, 4);
	ATF_CHECK_EQ(sc.vss_consts.vc_nvq, 6);
	for (uint16_t nrequestq = 1; nrequestq <= VTSCSI_MAX_REQUESTQ;
	    nrequestq++) {
		unsigned int nworkers;

		nworkers = MAX(VTSCSI_MIN_THR_PER_Q,
		    VTSCSI_TOTAL_THR / nrequestq);
		ATF_CHECK(nworkers >= VTSCSI_MIN_THR_PER_Q);
		ATF_CHECK(nworkers * nrequestq <= VTSCSI_TOTAL_THR);
	}
}

ATF_TC_WITHOUT_HEAD(initiator_id_configuration);
ATF_TC_BODY(initiator_id_configuration, tc)
{
	const char *errstr;
	int iid;

	ATF_REQUIRE_EQ(pci_vtscsi_parse_iid(NULL, &iid, &errstr), 0);
	ATF_CHECK_EQ(iid, 0);
	ATF_REQUIRE_EQ(pci_vtscsi_parse_iid("0", &iid, &errstr), 0);
	ATF_CHECK_EQ(iid, 0);
	ATF_REQUIRE_EQ(pci_vtscsi_parse_iid("2047", &iid, &errstr), 0);
	ATF_CHECK_EQ(iid, 2047);

	ATF_CHECK_EQ(pci_vtscsi_parse_iid("-1", &iid, &errstr), EINVAL);
	ATF_REQUIRE(errstr != NULL);
	ATF_CHECK_EQ(pci_vtscsi_parse_iid("2048", &iid, &errstr), EINVAL);
	ATF_REQUIRE(errstr != NULL);
	ATF_CHECK_EQ(pci_vtscsi_parse_iid("1garbage", &iid, &errstr),
	    EINVAL);
	ATF_REQUIRE(errstr != NULL);
	ATF_CHECK_EQ(pci_vtscsi_parse_iid("18446744073709551615", &iid,
	    &errstr), EINVAL);
	ATF_REQUIRE(errstr != NULL);
}

ATF_TC_WITHOUT_HEAD(queue_sync_init_failures);
ATF_TC_BODY(queue_sync_init_failures, tc)
{
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_queue *q;

	for (int fail_at = 1; fail_at <= 3; fail_at++) {
		reset_mocks();
		memset(&sc, 0, sizeof(sc));
		sc.vss_nrequestq = VTSCSI_DEFAULT_REQUESTQ;
		g_mutex_init_fail_at = fail_at;
		ATF_CHECK(pci_vtscsi_init_queue(&sc, &sc.vss_queues[0], 0) ==
		    -1);
		q = &sc.vss_queues[0];
		ATF_CHECK(q->vsq_sc == NULL);
		ATF_CHECK(!q->vsq_rmtx_initialized);
		ATF_CHECK(!q->vsq_fmtx_initialized);
		ATF_CHECK(!q->vsq_qmtx_initialized);
		ATF_CHECK(!q->vsq_cv_initialized);
		ATF_CHECK(g_ctl_allocs == g_ctl_frees);
	}

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vss_nrequestq = VTSCSI_DEFAULT_REQUESTQ;
	g_cond_init_fail_at = 1;
	ATF_CHECK(pci_vtscsi_init_queue(&sc, &sc.vss_queues[0], 0) == -1);
	q = &sc.vss_queues[0];
	ATF_CHECK(q->vsq_sc == NULL);
	ATF_CHECK(!q->vsq_rmtx_initialized);
	ATF_CHECK(!q->vsq_fmtx_initialized);
	ATF_CHECK(!q->vsq_qmtx_initialized);
	ATF_CHECK(!q->vsq_cv_initialized);
	ATF_CHECK(g_ctl_allocs == g_ctl_frees);
}

ATF_TC_WITHOUT_HEAD(packed_ring_option_validation);
ATF_TC_BODY(packed_ring_option_validation, tc)
{
	struct pci_vtscsi_softc sc;

	memset(&sc, 0, sizeof(sc));
	sc.vss_consts = vtscsi_vi_consts;
	sc.vss_vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	ATF_REQUIRE_EQ(pci_vtscsi_configure_ring_format(&sc, true), 0);
	ATF_CHECK((sc.vss_consts.vc_hv_caps &
	    VIRTIO14_F_RING_PACKED) != 0);
	ATF_REQUIRE_EQ(pci_vtscsi_configure_ring_format(&sc, false), 0);
	ATF_CHECK_EQ(sc.vss_consts.vc_hv_caps &
	    VIRTIO14_F_RING_PACKED, 0);

	sc.vss_vs.vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	ATF_CHECK_EQ(pci_vtscsi_configure_ring_format(&sc, true), EINVAL);
	ATF_CHECK_EQ(sc.vss_consts.vc_hv_caps &
	    VIRTIO14_F_RING_PACKED, 0);
}

ATF_TC_WITHOUT_HEAD(event_features_require_subscription);
ATF_TC_BODY(event_features_require_subscription, tc)
{
	struct virtio_consts instance;

	ATF_CHECK_EQ(VIRTIO14_SCSI_F_HOTPLUG_BIT, 1);
	ATF_CHECK_EQ(VIRTIO14_SCSI_F_CHANGE_BIT, 2);
	ATF_CHECK_EQ(vtscsi_vi_consts.vc_hv_caps &
	    (VIRTIO14_SCSI_F_HOTPLUG | VIRTIO14_SCSI_F_CHANGE), 0);
	instance = vtscsi_vi_consts;
	instance.vc_hv_caps |= VIRTIO14_SCSI_F_HOTPLUG |
	    VIRTIO14_SCSI_F_CHANGE;
	ATF_CHECK_EQ(instance.vc_hv_caps &
	    (VIRTIO14_SCSI_F_HOTPLUG | VIRTIO14_SCSI_F_CHANGE),
	    VIRTIO14_SCSI_F_HOTPLUG | VIRTIO14_SCSI_F_CHANGE);
}

ATF_TC_WITHOUT_HEAD(event_queue_wire_and_validation);
ATF_TC_BODY(event_queue_wire_and_validation, tc)
{
	struct virtio_scsi_event_record record;
	struct pci_vtscsi_softc sc;
	uint8_t wire[VIRTIO14_SCSI_EVENT_SIZE];

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	memset(&record, 0, sizeof(record));
	memset(wire, 0xa5, sizeof(wire));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vss_mtx, NULL), 0);
	sc.vss_mtx_initialized = true;
	sc.vss_vs.vs_mtx = &sc.vss_mtx;
	sc.vss_vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	sc.vss_vq[1].vq_qsize = 1;
	ATF_REQUIRE_EQ(virtio_scsi_event_state_init(&sc.vss_event_state,
	    sc.vss_event_records, nitems(sc.vss_event_records)), 0);
	record.source_sequence = 7;
	record.event = 1;	/* Section 5.6 transport-reset event. */
	record.reason = 1;	/* Section 5.6 rescan reason. */
	record.lun[0] = 1;
	record.lun[3] = 9;
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&sc.vss_event_state,
	    &record), 0);

	set_chain(1, 0, 1, true);
	g_chain.iov[0] = (struct iovec){
		.iov_base = wire,
		.iov_len = sizeof(wire),
	};
	pthread_mutex_lock(&sc.vss_mtx);
	pci_vtscsi_eventq_notify(&sc, &sc.vss_vq[1]);
	pthread_mutex_unlock(&sc.vss_mtx);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len, VIRTIO14_SCSI_EVENT_SIZE);
	ATF_CHECK_EQ(g_end_calls, 1);
	ATF_CHECK_EQ(virtio14_load_le32(wire +
	    VIRTIO14_SCSI_EVENT_EVENT_OFF), 1);
	ATF_CHECK_EQ(wire[VIRTIO14_SCSI_EVENT_LUN_OFF], 1);
	ATF_CHECK_EQ(wire[VIRTIO14_SCSI_EVENT_LUN_OFF + 3], 9);
	ATF_CHECK_EQ(virtio14_load_le32(wire +
	    VIRTIO14_SCSI_EVENT_REASON_OFF), 1);
	ATF_CHECK_EQ(virtio_scsi_event_state_count(&sc.vss_event_state), 0);

	/* A retained available event buffer means NOTIFY_ON_EMPTY is false. */
	record.source_sequence = 8;
	record.event = 1;
	record.reason = 1;
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&sc.vss_event_state,
	    &record), 0);
	record.source_sequence = 9;
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&sc.vss_event_state,
	    &record), 0);
	set_chain(1, 0, 1, true);
	g_chain_ready = 2;
	pthread_mutex_lock(&sc.vss_mtx);
	pci_vtscsi_eventq_notify(&sc, &sc.vss_vq[1]);
	pthread_mutex_unlock(&sc.vss_mtx);
	ATF_CHECK_EQ(g_end_all, 0);
	ATF_CHECK_EQ(g_chain_ready, 1);
	ATF_CHECK_EQ(virtio_scsi_event_state_count(&sc.vss_event_state), 1);

	/* A new notify consumes the retained descriptor and pending event. */
	pthread_mutex_lock(&sc.vss_mtx);
	pci_vtscsi_eventq_notify(&sc, &sc.vss_vq[1]);
	pthread_mutex_unlock(&sc.vss_mtx);
	ATF_CHECK_EQ(g_chain_ready, 0);
	ATF_CHECK_EQ(virtio_scsi_event_state_count(&sc.vss_event_state), 0);

	record.source_sequence = 10;
	record.event = 3;	/* Section 5.6 parameter-change event. */
	record.reason = 0x092a;
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&sc.vss_event_state,
	    &record), 0);
	set_chain(1, 1, 0, true);
	g_chain.iov[0] = (struct iovec){
		.iov_base = wire,
		.iov_len = sizeof(wire),
	};
	pthread_mutex_lock(&sc.vss_mtx);
	pci_vtscsi_eventq_notify(&sc, &sc.vss_vq[1]);
	pthread_mutex_unlock(&sc.vss_mtx);
	ATF_CHECK_EQ(g_rel_len, 0);
	ATF_CHECK_EQ(virtio_scsi_event_state_count(&sc.vss_event_state), 1);
	pthread_mutex_destroy(&sc.vss_mtx);
}

ATF_TC_WITHOUT_HEAD(event_source_record_validation);
ATF_TC_BODY(event_source_record_validation, tc)
{
	struct virtio_scsi_event_record record;
	struct pci_vtscsi_softc sc;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vss_mtx, NULL), 0);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_init(&sc.vss_event_state,
	    sc.vss_event_records, nitems(sc.vss_event_records)), 0);
	sc.vss_vs.vs_status = VIRTIO14_STATUS_DRIVER_OK;
	sc.vss_features = VIRTIO14_SCSI_F_HOTPLUG |
	    VIRTIO14_SCSI_F_CHANGE;

	/*
	 * The kernel subscription barrier is not a LUN event.  UINT32_MAX is
	 * its documented sentinel and must not be mistaken for an invalid LUN.
	 */
	g_lun_events[0] = (struct ctl_lun_event){
		.version = CTL_LUN_EVENT_VERSION,
		.type = CTL_LUN_EVENT_RESCAN,
		.lun_id = UINT32_MAX,
		.device_type = CTL_LUN_EVENT_DEVICE_TYPE_UNKNOWN,
	};
	g_lun_event_count = 1;
	pci_vtscsi_ctl_event(9, EVF_READ, &sc);
	ATF_CHECK(!virtio_scsi_event_state_pending(&sc.vss_event_state));
	ATF_CHECK_EQ(g_needs_reset, 0);

	/* Flat-space LUN 0x123 uses the section 5.6.6 0x40 marker. */
	g_lun_event_next = 0;
	g_lun_event_count = 1;
	g_lun_events[0] = (struct ctl_lun_event){
		.version = CTL_LUN_EVENT_VERSION,
		.type = CTL_LUN_EVENT_ADDED,
		.lun_id = 0x123,
		.sequence = 1,
		.device_type = T_DIRECT,
	};
	pci_vtscsi_ctl_event(9, EVF_READ, &sc);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&sc.vss_event_state,
	    &record));
	ATF_CHECK_EQ(record.event, 1);	/* TRANSPORT_RESET */
	ATF_CHECK_EQ(record.reason, 1);	/* RESCAN */
	ATF_CHECK_EQ(record.lun[0], 1);
	ATF_CHECK_EQ(record.lun[2], 0x41);
	ATF_CHECK_EQ(record.lun[3], 0x23);

	/*
	 * Unknown source flags are an ABI violation.  Preserve only a
	 * specification-defined loss marker; never reinterpret future flags.
	 */
	g_lun_event_next = 0;
	g_lun_event_count = 1;
	g_lun_events[0] = (struct ctl_lun_event){
		.version = CTL_LUN_EVENT_VERSION,
		.type = CTL_LUN_EVENT_CHANGED,
		.flags = 0x80000000,
		.lun_id = 7,
		.sequence = 2,
		.device_type = T_DIRECT,
	};
	pci_vtscsi_ctl_event(9, EVF_READ, &sc);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&sc.vss_event_state,
	    &record));
	ATF_CHECK_EQ(record.event, UINT32_C(0x80000000));

	/* A real event may not use the RESCAN sentinel as its LUN. */
	g_lun_event_next = 0;
	g_lun_event_count = 1;
	g_lun_events[0] = (struct ctl_lun_event){
		.version = CTL_LUN_EVENT_VERSION,
		.type = CTL_LUN_EVENT_REMOVED,
		.lun_id = UINT32_MAX,
		.sequence = 3,
		.device_type = T_DIRECT,
	};
	pci_vtscsi_ctl_event(9, EVF_READ, &sc);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&sc.vss_event_state,
	    &record));
	ATF_CHECK_EQ(record.event, UINT32_C(0x80000000));

	/*
	 * VirtIO 1.4 forbids parameter-change events for MMC devices.
	 * Suppression is intentional rather than loss: the following accepted
	 * source record must retain continuity and must not carry EVENTS_MISSED.
	 */
	virtio_scsi_event_state_reset(&sc.vss_event_state, false);
	g_lun_event_next = 0;
	g_lun_event_count = 2;
	g_lun_events[0] = (struct ctl_lun_event){
		.version = CTL_LUN_EVENT_VERSION,
		.type = CTL_LUN_EVENT_CHANGED,
		.lun_id = 8,
		.sequence = 1,
		.device_type = T_CDROM,
	};
	g_lun_events[1] = (struct ctl_lun_event){
		.version = CTL_LUN_EVENT_VERSION,
		.type = CTL_LUN_EVENT_ADDED,
		.lun_id = 9,
		.sequence = 2,
		.device_type = T_DIRECT,
	};
	pci_vtscsi_ctl_event(9, EVF_READ, &sc);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&sc.vss_event_state,
	    &record));
	ATF_CHECK_EQ(record.event, 1);	/* VirtIO 1.4 TRANSPORT_RESET. */
	ATF_CHECK(!virtio_scsi_event_state_pending(&sc.vss_event_state));

	pthread_mutex_destroy(&sc.vss_mtx);
}

ATF_TC_WITHOUT_HEAD(event_source_respects_lifecycle_fence);
ATF_TC_BODY(event_source_respects_lifecycle_fence, tc)
{
	struct pci_vtscsi_softc sc;
	uint8_t wire[VIRTIO14_SCSI_EVENT_SIZE];

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	memset(wire, 0xa5, sizeof(wire));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vss_mtx, NULL), 0);
	sc.vss_vs.vs_mtx = &sc.vss_mtx;
	sc.vss_vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	sc.vss_vs.vs_status = VIRTIO14_STATUS_DRIVER_OK;
	sc.vss_vq[1].vq_qsize = 1;
	sc.vss_features = VIRTIO14_SCSI_F_HOTPLUG;
	ATF_REQUIRE_EQ(virtio_scsi_event_state_init(&sc.vss_event_state,
	    sc.vss_event_records, nitems(sc.vss_event_records)), 0);

	set_chain(1, 0, 1, true);
	g_chain.iov[0] = (struct iovec){
		.iov_base = wire,
		.iov_len = sizeof(wire),
	};
	g_lun_events[0] = (struct ctl_lun_event){
		.version = CTL_LUN_EVENT_VERSION,
		.type = CTL_LUN_EVENT_ADDED,
		.lun_id = 7,
		.sequence = 1,
		.device_type = T_DIRECT,
	};
	g_lun_event_count = 1;

	/*
	 * The host source remains live during checkpoint pause, but it may only
	 * retain the event.  It must not inspect or complete the guest ring.
	 */
	sc.vss_vs.vs_checkpoint_paused = true;
	pci_vtscsi_ctl_event(9, EVF_READ, &sc);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(virtio_scsi_event_state_count(&sc.vss_event_state), 1);

	sc.vss_vs.vs_checkpoint_paused = false;
	pci_vtscsi_resume_complete(&sc);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len, VIRTIO14_SCSI_EVENT_SIZE);
	ATF_CHECK_EQ(g_end_calls, 1);
	ATF_CHECK_EQ(virtio_scsi_event_state_count(&sc.vss_event_state), 0);
	ATF_CHECK_EQ(virtio14_load_le32(wire +
	    VIRTIO14_SCSI_EVENT_EVENT_OFF), VIRTIO14_SCSI_T_TRANSPORT_RESET);
	ATF_CHECK_EQ(wire[VIRTIO14_SCSI_EVENT_LUN_OFF + 3], 7);

	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vss_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(event_source_saturation_reports_loss);
ATF_TC_BODY(event_source_saturation_reports_loss, tc)
{
	struct virtio_scsi_event_record record;
	struct pci_vtscsi_softc sc;
	size_t i;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vss_mtx, NULL), 0);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_init(&sc.vss_event_state,
	    sc.vss_event_records, nitems(sc.vss_event_records)), 0);
	sc.vss_vs.vs_status = VIRTIO14_STATUS_DRIVER_OK;
	sc.vss_features = VIRTIO14_SCSI_F_HOTPLUG;

	/*
	 * Feed one more CTL record than the bounded host queue can retain
	 * while the guest supplies no event buffers.  The source callback
	 * must preserve every accepted record in order and report the single
	 * dropped suffix as a trailing NO_EVENT|EVENTS_MISSED marker.
	 */
	g_lun_event_count = VTSCSI_EVENT_CAPACITY + 1;
	for (i = 0; i < g_lun_event_count; i++) {
		g_lun_events[i] = (struct ctl_lun_event){
			.version = CTL_LUN_EVENT_VERSION,
			.type = CTL_LUN_EVENT_ADDED,
			.lun_id = (uint32_t)i,
			.sequence = i + 1,
			.device_type = T_DIRECT,
		};
	}
	pci_vtscsi_ctl_event(9, EVF_READ, &sc);
	ATF_CHECK_EQ(g_lun_event_next, VTSCSI_HOST_EVENT_BUDGET);
	ATF_CHECK_EQ(virtio_scsi_event_state_count(&sc.vss_event_state),
	    VTSCSI_EVENT_CAPACITY);
	/* Level-triggered readability delivers the retained suffix next. */
	pci_vtscsi_ctl_event(9, EVF_READ, &sc);
	ATF_CHECK_EQ(g_lun_event_next, g_lun_event_count);
	ATF_CHECK_EQ(virtio_scsi_event_state_count(&sc.vss_event_state),
	    VTSCSI_EVENT_CAPACITY);
	for (i = 0; i < VTSCSI_EVENT_CAPACITY; i++) {
		ATF_REQUIRE(virtio_scsi_event_state_pop(
		    &sc.vss_event_state, &record));
		ATF_CHECK_EQ(record.source_sequence, i + 1);
		ATF_CHECK_EQ(record.event, 1);	/* TRANSPORT_RESET */
		ATF_CHECK_EQ(record.reason, 1);	/* RESCAN */
	}
	ATF_REQUIRE(virtio_scsi_event_state_pop(&sc.vss_event_state,
	    &record));
	ATF_CHECK_EQ(record.source_sequence, 0);
	ATF_CHECK_EQ(record.event, UINT32_C(0x80000000));
	ATF_CHECK_EQ(record.reason, 0);
	ATF_CHECK(!virtio_scsi_event_state_pop(&sc.vss_event_state,
	    &record));

	pthread_mutex_destroy(&sc.vss_mtx);
}

ATF_TC_WITHOUT_HEAD(tmf_completes_pending_requests);
ATF_TC_BODY(tmf_completes_pending_requests, tc)
{
	bool resume[VTSCSI_MAX_REQUESTQ];
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_request req;
	struct pci_vtscsi_queue *q;
	struct iovec output_iov;
	union ctl_io io;
	uint8_t cmd_rd[VTSCSI_MAX_IN_HEADER_LEN];
	uint8_t cmd_wr[VTSCSI_MAX_OUT_HEADER_LEN];
	uint8_t output[VIRTIO14_SCSI_DEFAULT_CMD_RESPONSE_SIZE];
	const uint8_t lun[VIRTIO14_SCSI_LUN_SIZE] = {
		VIRTIO14_SCSI_LUN_ADDRESS_METHOD, 0, 0, 1
	};

	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	q = &sc.vss_queues[0];
	ATF_REQUIRE(pci_vtscsi_get_request(&q->vsq_free_requests) == &req);
	memcpy(cmd_rd + VIRTIO14_SCSI_CMD_REQUEST_LUN_OFF, lun,
	    VIRTIO14_SCSI_LUN_SIZE);
	virtio14_store_le64(cmd_rd + VIRTIO14_SCSI_CMD_REQUEST_ID_OFF,
	    UINT64_C(0x1234));
	req.vsr_idx = 23;
	req.vsr_vreq.idx = 23;
	output_iov = (struct iovec){
		.iov_base = output,
		.iov_len = sizeof(output),
	};
	req.vsr_iov_out = &output_iov;
	req.vsr_niov_out = 1;
	pci_vtscsi_put_request(&q->vsq_requests, &req);

	memset(resume, 0, sizeof(resume));
	pci_vtscsi_tmf_pause(&sc, resume);
	ATF_CHECK(resume[0]);
	q->vsq_active = 1;
	ATF_CHECK_EQ(pci_vtscsi_tmf_complete(&sc,
	    VIRTIO_SCSI_T_TMF_ABORT_TASK, lun, 0x1234), ETIMEDOUT);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK(!STAILQ_EMPTY(&q->vsq_requests));
	ATF_CHECK(q->vsq_quiescing);

	q->vsq_active = 0;
	ATF_REQUIRE_EQ(pci_vtscsi_tmf_complete(&sc,
	    VIRTIO_SCSI_T_TMF_ABORT_TASK, lun, 0x1234), 0);
	ATF_CHECK(g_rel_calls == 1 && g_rel_idx == 23 &&
	    g_rel_len == sizeof(output));
	ATF_CHECK(output[VIRTIO14_SCSI_CMD_RESPONSE_RESPONSE_OFF] ==
	    VIRTIO_SCSI_S_ABORTED);
	ATF_CHECK(STAILQ_EMPTY(&q->vsq_requests));
	pci_vtscsi_resume_queue(q);
	teardown_queue(&sc);
}

ATF_TC_WITHOUT_HEAD(tmf_preserves_existing_queue_owner);
ATF_TC_BODY(tmf_preserves_existing_queue_owner, tc)
{
	struct {
		max_align_t alignment;
		uint8_t bytes[VIRTIO14_SCSI_TMF_REQUEST_SIZE +
		    VIRTIO14_SCSI_TMF_RESPONSE_SIZE];
	} storage;
	struct pci_vtscsi_ctrl_tmf *tmf;
	struct pci_vtscsi_request req;
	struct pci_vtscsi_softc sc;
	union ctl_io io;
	uint8_t cmd_rd[VTSCSI_MAX_IN_HEADER_LEN];
	uint8_t cmd_wr[VTSCSI_MAX_OUT_HEADER_LEN];

	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	sc.vss_queues[0].vsq_quiescing = true;
	memset(&storage, 0, sizeof(storage));
	tmf = (struct pci_vtscsi_ctrl_tmf *)(void *)storage.bytes;
	storage.bytes[VIRTIO14_SCSI_TMF_LUN_OFF] =
	    VIRTIO14_SCSI_LUN_ADDRESS_METHOD;
	virtio14_store_le32(storage.bytes + VIRTIO14_SCSI_TMF_SUBTYPE_OFF,
	    VIRTIO14_SCSI_T_TMF_ABORT_TASK);

	/*
	 * The failed CTL operation exercises the ordinary TMF release path.
	 * A queue already parked by selective reset, guest suspend, or
	 * checkpoint is not owned by this TMF and must remain parked.
	 */
	pci_vtscsi_tmf_handle(&sc, tmf);
	ATF_CHECK_EQ(tmf->response, VIRTIO14_SCSI_S_FAILURE);
	ATF_CHECK(sc.vss_queues[0].vsq_quiescing);

	pci_vtscsi_resume_queue(&sc.vss_queues[0]);
	teardown_queue(&sc);
}

ATF_TC_WITHOUT_HEAD(tmf_timeout_requires_device_reset);
ATF_TC_BODY(tmf_timeout_requires_device_reset, tc)
{
	struct {
		max_align_t alignment;
		uint8_t bytes[VIRTIO14_SCSI_TMF_REQUEST_SIZE +
		    VIRTIO14_SCSI_TMF_RESPONSE_SIZE];
	} storage;
	struct pci_vtscsi_ctrl_tmf *tmf;
	struct pci_vtscsi_request req;
	struct pci_vtscsi_softc sc;
	union ctl_io io;
	uint8_t cmd_rd[VTSCSI_MAX_IN_HEADER_LEN];
	uint8_t cmd_wr[VTSCSI_MAX_OUT_HEADER_LEN];

	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	memset(&storage, 0, sizeof(storage));
	tmf = (struct pci_vtscsi_ctrl_tmf *)(void *)storage.bytes;
	storage.bytes[VIRTIO14_SCSI_TMF_LUN_OFF] =
	    VIRTIO14_SCSI_LUN_ADDRESS_METHOD;
	virtio14_store_le32(storage.bytes + VIRTIO14_SCSI_TMF_SUBTYPE_OFF,
	    VIRTIO14_SCSI_T_TMF_ABORT_TASK);
	virtio14_store_le64(storage.bytes + VIRTIO14_SCSI_TMF_ID_OFF,
	    UINT64_C(0x5678));
	sc.vss_queues[0].vsq_active = 1;
	g_ctl_io_success = true;

	pci_vtscsi_tmf_handle(&sc, tmf);
	ATF_CHECK_EQ(tmf->response, VIRTIO14_SCSI_S_FAILURE);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK(sc.vss_queues[0].vsq_quiescing);

	sc.vss_queues[0].vsq_active = 0;
	pci_vtscsi_resume_queue(&sc.vss_queues[0]);
	teardown_queue(&sc);
}

ATF_TC_WITHOUT_HEAD(virtio_1_4_wire_layout);
ATF_TC_BODY(virtio_1_4_wire_layout, tc)
{

	ATF_CHECK_EQ(sizeof(struct pci_vtscsi_config),
	    VIRTIO14_SCSI_CONFIG_SIZE);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_config, num_queues),
	    VIRTIO14_SCSI_CONFIG_NUM_QUEUES_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_config, seg_max),
	    VIRTIO14_SCSI_CONFIG_SEG_MAX_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_config, max_sectors),
	    VIRTIO14_SCSI_CONFIG_MAX_SECTORS_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_config, cmd_per_lun),
	    VIRTIO14_SCSI_CONFIG_CMD_PER_LUN_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_config, event_info_size),
	    VIRTIO14_SCSI_CONFIG_EVENT_INFO_SIZE_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_config, sense_size),
	    VIRTIO14_SCSI_CONFIG_SENSE_SIZE_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_config, cdb_size),
	    VIRTIO14_SCSI_CONFIG_CDB_SIZE_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_config, max_channel),
	    VIRTIO14_SCSI_CONFIG_MAX_CHANNEL_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_config, max_target),
	    VIRTIO14_SCSI_CONFIG_MAX_TARGET_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_config, max_lun),
	    VIRTIO14_SCSI_CONFIG_MAX_LUN_OFF);

	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_ctrl_tmf, response),
	    VIRTIO14_SCSI_TMF_RESPONSE_OFF);
	ATF_CHECK_EQ(sizeof(struct pci_vtscsi_ctrl_tmf),
	    VIRTIO14_SCSI_TMF_REQUEST_SIZE +
	    VIRTIO14_SCSI_TMF_RESPONSE_SIZE);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_ctrl_an, event_actual),
	    VIRTIO14_SCSI_AN_EVENT_ACTUAL_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_ctrl_an, response),
	    VIRTIO14_SCSI_AN_RESPONSE_OFF);
	ATF_CHECK_EQ(sizeof(struct pci_vtscsi_ctrl_an),
	    VIRTIO14_SCSI_AN_RESPONSE_OFF +
	    VIRTIO14_SCSI_AN_RESPONSE_SIZE);

	ATF_CHECK_EQ(sizeof(struct pci_vtscsi_event),
	    VIRTIO14_SCSI_EVENT_SIZE);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_event, event),
	    VIRTIO14_SCSI_EVENT_EVENT_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_event, lun),
	    VIRTIO14_SCSI_EVENT_LUN_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_event, reason),
	    VIRTIO14_SCSI_EVENT_REASON_OFF);

	ATF_CHECK_EQ(sizeof(struct pci_vtscsi_req_cmd_rd),
	    VIRTIO14_SCSI_CMD_REQUEST_FIXED_SIZE);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_rd, lun),
	    VIRTIO14_SCSI_CMD_REQUEST_LUN_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_rd, id),
	    VIRTIO14_SCSI_CMD_REQUEST_ID_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_rd, task_attr),
	    VIRTIO14_SCSI_CMD_REQUEST_TASK_ATTR_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_rd, prio),
	    VIRTIO14_SCSI_CMD_REQUEST_PRIO_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_rd, crn),
	    VIRTIO14_SCSI_CMD_REQUEST_CRN_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_rd, cdb),
	    VIRTIO14_SCSI_CMD_REQUEST_CDB_OFF);

	ATF_CHECK_EQ(sizeof(struct pci_vtscsi_req_cmd_wr),
	    VIRTIO14_SCSI_CMD_RESPONSE_FIXED_SIZE);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_wr, sense_len),
	    VIRTIO14_SCSI_CMD_RESPONSE_SENSE_LEN_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_wr, residual),
	    VIRTIO14_SCSI_CMD_RESPONSE_RESIDUAL_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_wr, status_qualifier),
	    VIRTIO14_SCSI_CMD_RESPONSE_STATUS_QUALIFIER_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_wr, status),
	    VIRTIO14_SCSI_CMD_RESPONSE_STATUS_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_wr, response),
	    VIRTIO14_SCSI_CMD_RESPONSE_RESPONSE_OFF);
	ATF_CHECK_EQ(offsetof(struct pci_vtscsi_req_cmd_wr, sense),
	    VIRTIO14_SCSI_CMD_RESPONSE_SENSE_OFF);
}

ATF_TC_WITHOUT_HEAD(feature_negotiation_and_reset_clock_failure);
ATF_TC_BODY(feature_negotiation_and_reset_clock_failure, tc)
{
	struct pci_vtscsi_softc sc;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	/*
	 * neg_features caches exactly the common-layer negotiated value; it is
	 * not filtered here.
	 */
	ATF_CHECK_EQ(pci_vtscsi_neg_features(&sc,
	    VIRTIO14_SCSI_F_INOUT | VIRTIO14_F_VERSION_1), 0);
	ATF_CHECK_EQ(sc.vss_features,
	    VIRTIO14_SCSI_F_INOUT | VIRTIO14_F_VERSION_1);

	/*
	 * A device reset which cannot read the monotonic clock cannot compute a
	 * drain deadline.  It must still reset the common device and demand a
	 * driver-visible reset rather than proceeding without a budget.
	 */
	memset(&sc, 0, sizeof(sc));
	sc.vss_nrequestq = 1;
	g_clock_fail = true;
	pci_vtscsi_reset(&sc);
	ATF_CHECK_EQ(g_clock_calls, 1);
	ATF_CHECK_EQ(g_needs_reset, 1);
	/* The early failure must not have rebuilt the configuration space. */
	ATF_CHECK_EQ(sc.vss_config.num_queues, 0);
}

ATF_TC_WITHOUT_HEAD(request_handle_data_and_status_paths);
ATF_TC_BODY(request_handle_data_and_status_paths, tc)
{
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_request req;
	struct pci_vtscsi_req_cmd_rd *cmd;
	struct pci_vtscsi_req_cmd_wr resp;
	union ctl_io io;
	uint8_t cmd_bytes[VTSCSI_MAX_IN_HEADER_LEN];
	uint8_t inbuf[512], outbuf[512];
	struct iovec in_iov, out_iov;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vss_config.cdb_size = VIRTIO14_SCSI_DEFAULT_CDB_SIZE;
	sc.vss_config.sense_size = VIRTIO14_SCSI_DEFAULT_SENSE_SIZE;
	sc.vss_features = VIRTIO14_SCSI_F_INOUT;
	sc.vss_iid = 1;
	memset(cmd_bytes, 0, sizeof(cmd_bytes));
	cmd = (struct pci_vtscsi_req_cmd_rd *)(void *)cmd_bytes;
	cmd_bytes[VIRTIO14_SCSI_CMD_REQUEST_LUN_OFF] =
	    VIRTIO14_SCSI_LUN_ADDRESS_METHOD;
	cmd_bytes[VIRTIO14_SCSI_CMD_REQUEST_LUN_OFF + 3] = 1;

	memset(&req, 0, sizeof(req));
	req.vsr_cmd_rd = cmd;
	req.vsr_cmd_wr = &resp;
	req.vsr_ctl_io = &io;

	/* DATA IN: writable payload, ORDERED attribute, full transfer. */
	memset(&resp, 0, sizeof(resp));
	memset(&io, 0, sizeof(io));
	out_iov = (struct iovec){ .iov_base = outbuf, .iov_len = sizeof(outbuf) };
	req.vsr_data_iov_out = &out_iov;
	req.vsr_data_niov_out = 1;
	req.vsr_data_iov_in = NULL;
	req.vsr_data_niov_in = 0;
	cmd_bytes[VIRTIO14_SCSI_CMD_REQUEST_TASK_ATTR_OFF] = VIRTIO_SCSI_S_ORDERED;
	g_ctl_io_success = true;
	g_ctl_io_ext_data_filled = sizeof(outbuf);
	ATF_CHECK_EQ(pci_vtscsi_request_handle(&sc, &req), sizeof(outbuf));
	ATF_CHECK_EQ(resp.response, VIRTIO14_SCSI_S_OK);
	ATF_CHECK_EQ(io.scsiio.tag_type, CTL_TAG_ORDERED);
	ATF_CHECK((g_ctl_last_flags & CTL_FLAG_DATA_MASK) == CTL_FLAG_DATA_IN);

	/* DATA OUT: readable payload, HEAD attribute; no writable bytes. */
	memset(&resp, 0, sizeof(resp));
	memset(&io, 0, sizeof(io));
	in_iov = (struct iovec){ .iov_base = inbuf, .iov_len = sizeof(inbuf) };
	req.vsr_data_iov_out = NULL;
	req.vsr_data_niov_out = 0;
	req.vsr_data_iov_in = &in_iov;
	req.vsr_data_niov_in = 1;
	cmd_bytes[VIRTIO14_SCSI_CMD_REQUEST_TASK_ATTR_OFF] = VIRTIO_SCSI_S_HEAD;
	g_ctl_io_ext_data_filled = 0;
	ATF_CHECK_EQ(pci_vtscsi_request_handle(&sc, &req), 0);
	ATF_CHECK_EQ(io.scsiio.tag_type, CTL_TAG_HEAD_OF_QUEUE);
	ATF_CHECK((g_ctl_last_flags & CTL_FLAG_DATA_MASK) == CTL_FLAG_DATA_OUT);

	/* SCSI error with autosense: ACA attribute, sense copied and clamped. */
	memset(&resp, 0, sizeof(resp));
	memset(&io, 0, sizeof(io));
	req.vsr_data_iov_in = NULL;
	req.vsr_data_niov_in = 0;
	cmd_bytes[VIRTIO14_SCSI_CMD_REQUEST_TASK_ATTR_OFF] = VIRTIO_SCSI_S_ACA;
	g_ctl_io_status = CTL_SCSI_ERROR;
	g_ctl_io_scsi_status = SCSI_STATUS_CHECK_COND;
	g_ctl_io_sense_len = VIRTIO14_SCSI_DEFAULT_SENSE_SIZE;
	g_ctl_io_sense_byte = 0xab;
	pci_vtscsi_debug = 1;	/* also exercise the ctl_io_sbuf debug leg */
	ATF_CHECK_EQ(pci_vtscsi_request_handle(&sc, &req), 0);
	pci_vtscsi_debug = 0;
	ATF_CHECK_EQ(io.scsiio.tag_type, CTL_TAG_ACA);
	ATF_CHECK_EQ(resp.status, SCSI_STATUS_CHECK_COND);
	ATF_CHECK_EQ(pci_vtscsi_decode32(&sc, resp.sense_len),
	    VIRTIO14_SCSI_DEFAULT_SENSE_SIZE);
	ATF_CHECK_EQ(resp.sense[0], 0xab);

	/* Overfill reports zero residual (device wrote at least the request). */
	memset(&resp, 0, sizeof(resp));
	memset(&io, 0, sizeof(io));
	out_iov = (struct iovec){ .iov_base = outbuf, .iov_len = 256 };
	req.vsr_data_iov_out = &out_iov;
	req.vsr_data_niov_out = 1;
	cmd_bytes[VIRTIO14_SCSI_CMD_REQUEST_TASK_ATTR_OFF] = VIRTIO_SCSI_S_SIMPLE;
	g_ctl_io_status = CTL_SUCCESS;
	g_ctl_io_scsi_status = 0;
	g_ctl_io_sense_len = 0;
	g_ctl_io_ext_data_filled = 512;	/* more than the 256-byte request */
	ATF_CHECK_EQ(pci_vtscsi_request_handle(&sc, &req), 256);
	ATF_CHECK_EQ(pci_vtscsi_decode32(&sc, resp.residual), 0);

	/* Underfill reports the shortfall as residual. */
	memset(&resp, 0, sizeof(resp));
	memset(&io, 0, sizeof(io));
	g_ctl_io_ext_data_filled = 100;
	ATF_CHECK_EQ(pci_vtscsi_request_handle(&sc, &req), 100);
	ATF_CHECK_EQ(pci_vtscsi_decode32(&sc, resp.residual), 256 - 100);

	/* A failed ioctl is a transport failure, not a completed command. */
	memset(&resp, 0, sizeof(resp));
	memset(&io, 0, sizeof(io));
	g_ctl_io_success = false;
	ATF_CHECK_EQ(pci_vtscsi_request_handle(&sc, &req), 0);
	ATF_CHECK_EQ(resp.response, VIRTIO14_SCSI_S_FAILURE);
}

ATF_TC_WITHOUT_HEAD(tmf_handle_task_function_mapping);
ATF_TC_BODY(tmf_handle_task_function_mapping, tc)
{
	/*
	 * VirtIO 1.4 section 5.6.6.2 assigns these fixed TMF subtype wire values.
	 * Encode them as literals so the mapping is verified against the
	 * specification rather than the device's own header.
	 */
	static const struct {
		uint32_t subtype;
		uint8_t action;
	} cases[] = {
		{ 0, CTL_TASK_ABORT_TASK },		/* ABORT TASK */
		{ 1, CTL_TASK_ABORT_TASK_SET },		/* ABORT TASK SET */
		{ 2, CTL_TASK_CLEAR_ACA },		/* CLEAR ACA */
		{ 3, CTL_TASK_CLEAR_TASK_SET },		/* CLEAR TASK SET */
		{ 4, CTL_TASK_I_T_NEXUS_RESET },	/* I_T NEXUS RESET */
		{ 5, CTL_TASK_LUN_RESET },		/* LOGICAL UNIT RESET */
		{ 6, CTL_TASK_QUERY_TASK },		/* QUERY TASK */
		{ 7, CTL_TASK_QUERY_TASK_SET },		/* QUERY TASK SET */
	};
	struct pci_vtscsi_request req;
	struct pci_vtscsi_softc sc;
	union ctl_io io;
	uint8_t cmd_rd[VTSCSI_MAX_IN_HEADER_LEN];
	uint8_t cmd_wr[VTSCSI_MAX_OUT_HEADER_LEN];

	for (size_t i = 0; i < nitems(cases); i++) {
		struct {
			max_align_t alignment;
			uint8_t bytes[VIRTIO14_SCSI_TMF_REQUEST_SIZE +
			    VIRTIO14_SCSI_TMF_RESPONSE_SIZE];
		} storage;
		struct pci_vtscsi_ctrl_tmf *tmf;

		reset_mocks();
		setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
		memset(&storage, 0, sizeof(storage));
		tmf = (struct pci_vtscsi_ctrl_tmf *)(void *)storage.bytes;
		storage.bytes[VIRTIO14_SCSI_TMF_LUN_OFF] =
		    VIRTIO14_SCSI_LUN_ADDRESS_METHOD;
		storage.bytes[VIRTIO14_SCSI_TMF_LUN_OFF + 3] = 1;
		virtio14_store_le32(storage.bytes +
		    VIRTIO14_SCSI_TMF_SUBTYPE_OFF, cases[i].subtype);
		g_ctl_io_success = true;
		g_ctl_io_task_status = CTL_TASK_FUNCTION_SUCCEEDED;
		if (i == 0)
			pci_vtscsi_debug = 1;	/* debug sbuf leg once */
		pci_vtscsi_tmf_handle(&sc, tmf);
		pci_vtscsi_debug = 0;
		/* tmf_handle allocates its own ctl_io via the mocked allocator. */
		ATF_CHECK_EQ(g_ctl_io.taskio.task_action, cases[i].action);
		ATF_CHECK_EQ(tmf->response,
		    VIRTIO14_SCSI_S_FUNCTION_SUCCEEDED);
		teardown_queue(&sc);
	}

	/* An unallocatable ctl_io yields a controller failure, not a crash. */
	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	{
		struct {
			max_align_t alignment;
			uint8_t bytes[VIRTIO14_SCSI_TMF_REQUEST_SIZE +
			    VIRTIO14_SCSI_TMF_RESPONSE_SIZE];
		} storage;
		struct pci_vtscsi_ctrl_tmf *tmf;

		memset(&storage, 0, sizeof(storage));
		tmf = (struct pci_vtscsi_ctrl_tmf *)(void *)storage.bytes;
		storage.bytes[VIRTIO14_SCSI_TMF_LUN_OFF] =
		    VIRTIO14_SCSI_LUN_ADDRESS_METHOD;
		storage.bytes[VIRTIO14_SCSI_TMF_LUN_OFF + 3] = 1;
		virtio14_store_le32(storage.bytes +
		    VIRTIO14_SCSI_TMF_SUBTYPE_OFF,
		    VIRTIO14_SCSI_T_TMF_ABORT_TASK);
		g_ctl_alloc_fail = true;
		pci_vtscsi_tmf_handle(&sc, tmf);
		ATF_CHECK_EQ(tmf->response, VIRTIO14_SCSI_S_FAILURE);
	}
	teardown_queue(&sc);
}

ATF_TC_WITHOUT_HEAD(control_queue_oversized_request);
ATF_TC_BODY(control_queue_oversized_request, tc)
{
	struct pci_vtscsi_softc sc;
	uint8_t huge[4096];
	uint8_t out[16];

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vss_vq[0].vq_qsize = VTSCSI_RINGSZ;
	memset(huge, 0, sizeof(huge));
	set_chain(2, 1, 1, true);
	g_chain.iov[0] = (struct iovec){
		.iov_base = huge,
		.iov_len = sizeof(huge),	/* exceeds the control union */
	};
	g_chain.iov[1] = (struct iovec){
		.iov_base = out,
		.iov_len = sizeof(out),
	};
	pci_vtscsi_controlq_notify(&sc, &sc.vss_vq[0]);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len, 0);
}

ATF_TC_WITHOUT_HEAD(lun_inventory_backend_faults);
ATF_TC_BODY(lun_inventory_backend_faults, tc)
{
	struct pci_vtscsi_softc sc;
	char *inventory;
	uint32_t length;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vss_ctl_fd = 900;

	/* Nominal query returns the payload without its terminating NUL. */
	g_lun_inventory = "<ctllunlist/>";
	ATF_REQUIRE_EQ(pci_vtscsi_lun_inventory(&sc, &inventory, &length), 0);
	ATF_CHECK_EQ(length, strlen("<ctllunlist/>"));
	ATF_CHECK_EQ(memcmp(inventory, "<ctllunlist/>", length), 0);
	free(inventory);

	/* An ioctl error is reported verbatim. */
	g_lun_inventory_error = EIO;
	ATF_CHECK_EQ(pci_vtscsi_lun_inventory(&sc, &inventory, &length), EIO);
	ATF_CHECK(inventory == NULL);
	g_lun_inventory_error = 0;

	/* A malformed status (no fill) is a backend I/O error. */
	g_lun_list_force_status = CTL_LUN_LIST_ERROR;
	ATF_CHECK_EQ(pci_vtscsi_lun_inventory(&sc, &inventory, &length), EIO);
	g_lun_list_force_status = -1;

	/* Unbounded NEED_MORE_SPACE growth is capped with E2BIG. */
	g_lun_list_force_need = true;
	ATF_CHECK_EQ(pci_vtscsi_lun_inventory(&sc, &inventory, &length), E2BIG);
	g_lun_list_force_need = false;
}

ATF_TC_WITHOUT_HEAD(worker_thread_processes_request);
ATF_TC_BODY(worker_thread_processes_request, tc)
{
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_queue *q;
	struct pci_vtscsi_request *req;
	struct iovec out_iov;
	uint8_t resp_buf[VTSCSI_MAX_OUT_HEADER_LEN];
	int spins;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vss_config.cdb_size = VIRTIO14_SCSI_DEFAULT_CDB_SIZE;
	sc.vss_config.sense_size = VIRTIO14_SCSI_DEFAULT_SENSE_SIZE;
	sc.vss_nrequestq = VTSCSI_DEFAULT_REQUESTQ;
	sc.vss_iid = 1;
	sc.vss_vq[2].vq_qsize = VTSCSI_RINGSZ;

	/* Start the real worker pool: this covers alloc_request and proc(). */
	ATF_REQUIRE_EQ(pci_vtscsi_init_queue(&sc, &sc.vss_queues[0], 0), 0);
	q = &sc.vss_queues[0];
	ATF_CHECK(q->vsq_nworkers >= VTSCSI_MIN_THR_PER_Q);

	pthread_mutex_lock(&q->vsq_fmtx);
	req = pci_vtscsi_get_request(&q->vsq_free_requests);
	pthread_mutex_unlock(&q->vsq_fmtx);
	ATF_REQUIRE(req != NULL);
	((uint8_t *)req->vsr_cmd_rd)[VIRTIO14_SCSI_CMD_REQUEST_LUN_OFF] =
	    VIRTIO14_SCSI_LUN_ADDRESS_METHOD;
	((uint8_t *)req->vsr_cmd_rd)[VIRTIO14_SCSI_CMD_REQUEST_LUN_OFF + 3] = 1;
	memset(resp_buf, 0, sizeof(resp_buf));
	out_iov = (struct iovec){ .iov_base = resp_buf, .iov_len = sizeof(resp_buf) };
	req->vsr_iov_out = &out_iov;
	req->vsr_niov_out = 1;
	req->vsr_idx = 31;
	req->vsr_vreq.idx = 31;
	g_ctl_io_success = true;

	pthread_mutex_lock(&q->vsq_rmtx);
	pci_vtscsi_put_request(&q->vsq_requests, req);
	pthread_cond_broadcast(&q->vsq_cv);
	pthread_mutex_unlock(&q->vsq_rmtx);

	for (spins = 0; spins < 10000; spins++) {
		if (g_rel_calls >= 1)
			break;
		usleep(1000);
	}
	ATF_CHECK(g_rel_calls >= 1);
	ATF_CHECK_EQ(g_rel_idx, 31);

	/* Tearing the queue down joins the workers and frees every request. */
	pci_vtscsi_destroy_queue(q);
	ATF_CHECK(q->vsq_sc == NULL);
	ATF_CHECK_EQ(q->vsq_nworkers, 0);
}

ATF_TC_WITHOUT_HEAD(request_enqueue_splits_data_segments);
ATF_TC_BODY(request_enqueue_splits_data_segments, tc)
{
	struct pci_vtscsi_softc sc;
	struct pci_vtscsi_request req;
	struct pci_vtscsi_queue *q;
	union ctl_io io;
	uint8_t cmd_rd[VTSCSI_MAX_IN_HEADER_LEN];
	uint8_t cmd_wr[VTSCSI_MAX_OUT_HEADER_LEN];
	uint8_t hdr_in[VTSCSI_MAX_IN_HEADER_LEN];
	uint8_t hdr_out[VTSCSI_MAX_OUT_HEADER_LEN];
	uint8_t data_out[512], data_in[512];
	struct pci_vtscsi_request *queued;
	size_t in_hdr, out_hdr;

	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	sc.vss_features = VIRTIO14_SCSI_F_INOUT;
	sc.vss_vq[2].vq_qsize = VTSCSI_RINGSZ;
	q = &sc.vss_queues[0];
	in_hdr = VTSCSI_IN_HEADER_LEN((&sc));
	out_hdr = VTSCSI_OUT_HEADER_LEN((&sc));

	/*
	 * A well-formed chain: an exact request header plus a readable DATA OUT
	 * segment, then an exact response header plus a writable DATA IN
	 * segment.  A valid LUN must land the request on the worker queue.
	 */
	memset(hdr_in, 0, sizeof(hdr_in));
	hdr_in[VIRTIO14_SCSI_CMD_REQUEST_LUN_OFF] =
	    VIRTIO14_SCSI_LUN_ADDRESS_METHOD;
	hdr_in[VIRTIO14_SCSI_CMD_REQUEST_LUN_OFF + 3] = 1;
	set_chain(4, 2, 2, true);
	g_chain.req.idx = 12;
	g_chain.iov[0] = (struct iovec){ .iov_base = hdr_in, .iov_len = in_hdr };
	g_chain.iov[1] = (struct iovec){
	    .iov_base = data_out, .iov_len = sizeof(data_out) };
	g_chain.iov[2] = (struct iovec){
	    .iov_base = hdr_out, .iov_len = out_hdr };
	g_chain.iov[3] = (struct iovec){
	    .iov_base = data_in, .iov_len = sizeof(data_in) };

	pci_vtscsi_requestq_notify(&sc, &sc.vss_vq[2]);

	/* The request is enqueued (not completed): no chain was released. */
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK(!STAILQ_EMPTY(&q->vsq_requests));
	queued = STAILQ_FIRST(&q->vsq_requests);
	ATF_CHECK_EQ(queued->vsr_idx, 12);
	ATF_CHECK_EQ(queued->vsr_data_niov_in, 1);
	ATF_CHECK_EQ(queued->vsr_data_niov_out, 1);
	ATF_CHECK_EQ(queued->vsr_cmd_rd->lun[0],
	    VIRTIO14_SCSI_LUN_ADDRESS_METHOD);

	/* Drain so teardown starts from a clean free list. */
	(void)pci_vtscsi_get_request(&q->vsq_requests);
	pci_vtscsi_put_request(&q->vsq_free_requests, queued);
	teardown_queue(&sc);

	/* An output chain too short for the response header is failed inline. */
	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	q = &sc.vss_queues[0];
	memset(hdr_out, 0xa5, sizeof(hdr_out));
	set_chain(2, 1, 1, true);
	g_chain.iov[0] = (struct iovec){ .iov_base = hdr_in, .iov_len = in_hdr };
	g_chain.iov[1] = (struct iovec){ .iov_base = hdr_out, .iov_len = 1 };
	ATF_CHECK(pci_vtscsi_queue_request(&sc, &sc.vss_vq[2]));
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK(STAILQ_EMPTY(&q->vsq_requests));
	teardown_queue(&sc);

	/* An input chain too short for the request header is failed inline. */
	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	q = &sc.vss_queues[0];
	memset(hdr_out, 0, sizeof(hdr_out));
	set_chain(2, 1, 1, true);
	g_chain.iov[0] = (struct iovec){ .iov_base = hdr_in, .iov_len = 1 };
	g_chain.iov[1] = (struct iovec){
	    .iov_base = hdr_out, .iov_len = out_hdr };
	ATF_CHECK(pci_vtscsi_queue_request(&sc, &sc.vss_vq[2]));
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK(STAILQ_EMPTY(&q->vsq_requests));
	ATF_CHECK_EQ(hdr_out[VIRTIO14_SCSI_CMD_RESPONSE_RESPONSE_OFF],
	    VIRTIO14_SCSI_S_FAILURE);
	teardown_queue(&sc);

	/* A syntactically valid chain to an invalid LUN yields BAD_TARGET. */
	reset_mocks();
	setup_queue(&sc, &req, cmd_rd, cmd_wr, &io);
	q = &sc.vss_queues[0];
	memset(hdr_in, 0, sizeof(hdr_in));	/* all-zero LUN is invalid */
	memset(hdr_out, 0, sizeof(hdr_out));
	set_chain(2, 1, 1, true);
	g_chain.iov[0] = (struct iovec){ .iov_base = hdr_in, .iov_len = in_hdr };
	g_chain.iov[1] = (struct iovec){
	    .iov_base = hdr_out, .iov_len = out_hdr };
	ATF_CHECK(pci_vtscsi_queue_request(&sc, &sc.vss_vq[2]));
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK(STAILQ_EMPTY(&q->vsq_requests));
	ATF_CHECK_EQ(hdr_out[VIRTIO14_SCSI_CMD_RESPONSE_RESPONSE_OFF],
	    VIRTIO14_SCSI_S_BAD_TARGET);
	teardown_queue(&sc);
}

ATF_TC_WITHOUT_HEAD(hotplug_removal_and_admin_queue_reset);
ATF_TC_BODY(hotplug_removal_and_admin_queue_reset, tc)
{
	struct virtio_scsi_event_record record;
	struct pci_vtscsi_softc sc;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vss_mtx, NULL), 0);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_init(&sc.vss_event_state,
	    sc.vss_event_records, nitems(sc.vss_event_records)), 0);
	sc.vss_vs.vs_status = VIRTIO14_STATUS_DRIVER_OK;
	sc.vss_features = VIRTIO14_SCSI_F_HOTPLUG;
	sc.vss_nrequestq = 1;

	/*
	 * VirtIO 1.4 section 5.6.6.4: a removed LUN is reported as a transport
	 * reset carrying the "removed" reason (wire values 1 and 2).
	 */
	g_lun_events[0] = (struct ctl_lun_event){
		.version = CTL_LUN_EVENT_VERSION,
		.type = CTL_LUN_EVENT_REMOVED,
		.lun_id = 0x10,
		.sequence = 1,
		.device_type = T_DIRECT,
	};
	g_lun_event_count = 1;
	pci_vtscsi_ctl_event(9, EVF_READ, &sc);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&sc.vss_event_state, &record));
	ATF_CHECK_EQ(record.event, 1);	/* TRANSPORT_RESET */
	ATF_CHECK_EQ(record.reason, 2);	/* RESET_REMOVED */
	ATF_CHECK_EQ(record.lun[3], 0x10);

	/* Resetting the event queue (vq 1) clears device-local event state. */
	sc.vss_vq[1].vq_num = 1;
	g_lun_event_next = 0;
	g_lun_event_count = 1;
	pci_vtscsi_ctl_event(9, EVF_READ, &sc);
	ATF_CHECK(virtio_scsi_event_state_pending(&sc.vss_event_state));
	ATF_CHECK_EQ(pci_vtscsi_qreset(&sc, &sc.vss_vq[1], 0), 0);
	ATF_CHECK(!virtio_scsi_event_state_pending(&sc.vss_event_state));

	/* Resetting the control queue (vq 0) is a no-op success. */
	sc.vss_vq[0].vq_num = 0;
	ATF_CHECK_EQ(pci_vtscsi_qreset(&sc, &sc.vss_vq[0], 0), 0);

	pthread_mutex_destroy(&sc.vss_mtx);
}

ATF_TC_WITHOUT_HEAD(legacy_config_option_parsing);
ATF_TC_BODY(legacy_config_option_parsing, tc)
{

	reset_mocks();
	/* No options at all is a no-op success. */
	ATF_CHECK_EQ(pci_vtscsi_legacy_config(NULL, NULL), 0);

	/* A bare device path sets only "dev". */
	ATF_CHECK_EQ(pci_vtscsi_legacy_config(NULL, "/dev/cam/ctl"), 0);
	ATF_CHECK_STREQ(g_legacy_dev, "/dev/cam/ctl");
	ATF_CHECK_EQ(g_legacy_parse_calls, 0);

	/* A device path plus trailing options delegates the remainder. */
	g_legacy_parse_ret = 0;
	ATF_CHECK_EQ(pci_vtscsi_legacy_config(NULL, "/dev/other,iid=3"), 0);
	ATF_CHECK_STREQ(g_legacy_dev, "/dev/other");
	ATF_CHECK_EQ(g_legacy_parse_calls, 1);

	/* The delegated parser's error propagates. */
	g_legacy_parse_ret = EINVAL;
	ATF_CHECK_EQ(pci_vtscsi_legacy_config(NULL, "/dev/x,bogus"), EINVAL);
}

static void
destroy_scsi_device(struct pci_vtscsi_softc *sc)
{
	int i;

	for (i = 0; i < sc->vss_nrequestq; i++)
		pci_vtscsi_destroy_queue(&sc->vss_queues[i]);
	pthread_mutex_destroy(&sc->vss_vs.vs_isr_mtx);
	pthread_mutex_destroy(&sc->vss_mtx);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(device_init_lifecycle);
ATF_TC_BODY(device_init_lifecycle, tc)
{
	struct pci_devinst pi;
	struct pci_vtscsi_softc *sc;

	/* Full modern multiqueue bring-up with a live CTL event source. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_queues = "4";
	g_cfg_iid = "5";
	g_cfg_bootindex = "1";
	g_init_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	g_subscribe_ok = true;
	ATF_REQUIRE_EQ(pci_vtscsi_init(&pi, NULL), 0);
	sc = pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(sc->vss_nrequestq, 4);
	ATF_CHECK_EQ(sc->vss_iid, 5);
	ATF_CHECK(sc->vss_event_source);
	ATF_CHECK_EQ(g_mevent_add_calls, 1);
	ATF_CHECK_EQ(g_modern_identity, VIRTIO_ID_SCSI);
	/* A modern device advertises hotplug/change once subscribed. */
	ATF_CHECK((sc->vss_consts.vc_hv_caps &
	    (VIRTIO14_SCSI_F_HOTPLUG | VIRTIO14_SCSI_F_CHANGE)) ==
	    (VIRTIO14_SCSI_F_HOTPLUG | VIRTIO14_SCSI_F_CHANGE));
	destroy_scsi_device(sc);

	/* Legacy single-queue bring-up writes the transitional PCI identity. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_queues = "1";
	g_init_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	ATF_REQUIRE_EQ(pci_vtscsi_init(&pi, NULL), 0);
	sc = pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(g_cfg_device, VIRTIO_PCI_TRANSITIONAL_SCSI);
	ATF_CHECK_EQ(g_cfg_class, PCIC_STORAGE);
	ATF_CHECK(!sc->vss_event_source);
	destroy_scsi_device(sc);

	/* Rejected queue counts fail before any allocation. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_queues = "0";
	ATF_CHECK_EQ(pci_vtscsi_init(&pi, NULL), -1);

	/* An invalid initiator id fails after the softc is allocated. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_iid = "999999";
	ATF_CHECK_EQ(pci_vtscsi_init(&pi, NULL), -1);

	/* A bad bootindex is rejected. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_bootindex = "3";
	g_boot_device_error = 1;
	ATF_CHECK_EQ(pci_vtscsi_init(&pi, NULL), -1);

	/* A CTL device that cannot be opened fails cleanly. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_open_fd = -1;
	ATF_CHECK_EQ(pci_vtscsi_init(&pi, NULL), -1);

	/* A non-ENOTTY subscription error disables events but still succeeds. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_queues = "1";
	g_subscribe_ok = false;
	g_subscribe_errno = EPERM;
	ATF_REQUIRE_EQ(pci_vtscsi_init(&pi, NULL), 0);
	sc = pi.pi_arg;
	ATF_CHECK(!sc->vss_event_source);
	destroy_scsi_device(sc);

	/* Multiqueue over a legacy transport is a configuration error. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_queues = "4";
	g_init_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	ATF_CHECK_EQ(pci_vtscsi_init(&pi, NULL), -1);

	/* Packed rings over a legacy transport are rejected. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_queues = "1";
	g_cfg_packed = true;
	g_init_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	ATF_CHECK_EQ(pci_vtscsi_init(&pi, NULL), -1);

	/* Transport selection failure aborts bring-up. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_init_transport_error = EINVAL;
	ATF_CHECK_EQ(pci_vtscsi_init(&pi, NULL), -1);

	/* Interrupt init failure aborts bring-up. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_queues = "1";
	g_intr_init_error = ENXIO;
	ATF_CHECK_EQ(pci_vtscsi_init(&pi, NULL), -1);

	/* Modern transport BAR init failure aborts bring-up. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_queues = "1";
	g_init_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	g_modern_init_error = ENXIO;
	ATF_CHECK_EQ(pci_vtscsi_init(&pi, NULL), -1);

	/* A failed CTL event registration tears the device back down. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_cfg_queues = "1";
	g_subscribe_ok = true;
	g_mevent_add_fail = true;
	ATF_CHECK_EQ(pci_vtscsi_init(&pi, NULL), -1);
	ATF_CHECK_EQ(g_mevent_add_calls, 1);
}

ATF_TC_WITHOUT_HEAD(snapshot_backend_faults);
ATF_TC_BODY(snapshot_backend_faults, tc)
{
	struct pci_vtscsi_softc source, destination;
	uint8_t image[512], damaged[512];
	size_t used, inv_off;

	reset_mocks();

	/* A save whose backend inventory query fails publishes nothing. */
	setup_snapshot_softc(&source);
	g_lun_inventory_error = EIO;
	ATF_CHECK_EQ(run_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, NULL), EIO);
	g_lun_inventory_error = 0;

	/* Produce a good image to mutate for the restore-side fault paths. */
	ATF_REQUIRE_EQ(run_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);

	/* An oversized declared inventory length is rejected before any alloc. */
	inv_off = 22 + VIRTIO14_SCSI_CONFIG_SIZE;
	ATF_REQUIRE(inv_off + sizeof(uint32_t) <= used);
	memcpy(damaged, image, used);
	virtio14_store_le32(&damaged[inv_off],
	    VTSCSI_LUN_INVENTORY_MAX + 1U);
	setup_snapshot_softc(&destination);
	destination.vss_iid = source.vss_iid;
	destination.vss_nrequestq = source.vss_nrequestq;
	destination.vss_vs.vs_negotiated_caps = source.vss_features;
	ATF_CHECK_EQ(run_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), E2BIG);

	/*
	 * A record that passes every local compatibility gate still fails if the
	 * destination backend inventory cannot be read for comparison.
	 */
	setup_snapshot_softc(&destination);
	destination.vss_iid = source.vss_iid;
	destination.vss_nrequestq = source.vss_nrequestq;
	destination.vss_vs.vs_negotiated_caps = source.vss_features;
	g_lun_inventory_error = EIO;
	ATF_CHECK_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EIO);
	g_lun_inventory_error = 0;
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, control_handler_validation);
	ATF_TP_ADD_TC(tp, control_queue_validation);
	ATF_TP_ADD_TC(tp, tmf_response_mapping);
	ATF_TP_ADD_TC(tp, config_writes);
	ATF_TP_ADD_TC(tp, config_defaults);
	ATF_TP_ADD_TC(tp, document_wire_vectors);
	ATF_TP_ADD_TC(tp, request_queue_validation);
	ATF_TP_ADD_TC(tp, report_luns_well_known_lun);
	ATF_TP_ADD_TC(tp, request_payload_validation);
	ATF_TP_ADD_TC(tp, request_response_mapping);
	ATF_TP_ADD_TC(tp, queue_sync_init_failures);
	ATF_TP_ADD_TC(tp, packed_ring_option_validation);
	ATF_TP_ADD_TC(tp, reset_completes_pending_requests);
	ATF_TP_ADD_TC(tp, reset_timeout_requires_device_reset);
	ATF_TP_ADD_TC(tp, reset_timeout_uses_one_device_deadline);
	ATF_TP_ADD_TC(tp, queue_reset_quiesces_only_selected_queue);
	ATF_TP_ADD_TC(tp, multiqueue_configuration);
	ATF_TP_ADD_TC(tp, initiator_id_configuration);
	ATF_TP_ADD_TC(tp, event_features_require_subscription);
	ATF_TP_ADD_TC(tp, event_queue_wire_and_validation);
	ATF_TP_ADD_TC(tp, event_source_record_validation);
	ATF_TP_ADD_TC(tp, event_source_respects_lifecycle_fence);
	ATF_TP_ADD_TC(tp, event_source_saturation_reports_loss);
	ATF_TP_ADD_TC(tp, tmf_completes_pending_requests);
	ATF_TP_ADD_TC(tp, tmf_preserves_existing_queue_owner);
	ATF_TP_ADD_TC(tp, tmf_timeout_requires_device_reset);
	ATF_TP_ADD_TC(tp, snapshot_wire_and_validation);
	ATF_TP_ADD_TC(tp, snapshot_preflight_is_locally_serialized);
	ATF_TP_ADD_TC(tp, checkpoint_pause_preserves_queue_ownership);
	ATF_TP_ADD_TC(tp,
	    checkpoint_multiqueue_failure_rolls_back_earlier_queues);
	ATF_TP_ADD_TC(tp, guest_suspend_nests_with_checkpoint);
	ATF_TP_ADD_TC(tp, virtio_1_4_wire_layout);
	ATF_TP_ADD_TC(tp, feature_negotiation_and_reset_clock_failure);
	ATF_TP_ADD_TC(tp, request_handle_data_and_status_paths);
	ATF_TP_ADD_TC(tp, tmf_handle_task_function_mapping);
	ATF_TP_ADD_TC(tp, control_queue_oversized_request);
	ATF_TP_ADD_TC(tp, lun_inventory_backend_faults);
	ATF_TP_ADD_TC(tp, request_enqueue_splits_data_segments);
	ATF_TP_ADD_TC(tp, hotplug_removal_and_admin_queue_reset);
	ATF_TP_ADD_TC(tp, worker_thread_processes_request);
	ATF_TP_ADD_TC(tp, legacy_config_option_parsing);
	ATF_TP_ADD_TC(tp, device_init_lifecycle);
	ATF_TP_ADD_TC(tp, snapshot_backend_faults);
	return (atf_no_error());
}
