/* Tests for transport-independent FreeBSD guest VirtIO contracts. */
#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include <dev/virtio/mmio/virtio_mmio.h>
#include <dev/virtio/balloon/virtio_balloon.h>
#include <dev/virtio/balloon/virtio_balloon_var.h>
#include <dev/virtio/gpu/virtio_gpu.h>
#include <dev/virtio/gpu/virtio_gpu_geometry.h>
#include <dev/virtio/input/virtio_input.h>
#include <dev/virtio/console/virtio_console.h>
#include <dev/virtio/pci/virtio_pci_modern_var.h>
#include <dev/virtio/pci/virtio_pci_var.h>
#include <dev/virtio/rtc/virtio_rtc.h>
#include <dev/virtio/random/virtio_random_var.h>
#include <dev/virtio/scsi/virtio_scsi.h>
#include <dev/virtio/vsock/virtio_vsock_var.h>
#include <dev/virtio/virtio_ids.h>
#include <dev/virtio/virtio.h>
#include <dev/virtio/virtio_ring.h>

#include "virtio_1_4_spec.h"
#include "virtio_1_4_wire.h"

ATF_TC_WITHOUT_HEAD(virtio_1_4_wire_constants);
ATF_TC_BODY(virtio_1_4_wire_constants, tc)
{

	ATF_CHECK_EQ(VIRTIO_CONFIG_STATUS_ACK,
	    VIRTIO14_STATUS_ACKNOWLEDGE);
	ATF_CHECK_EQ(VIRTIO_CONFIG_STATUS_DRIVER, VIRTIO14_STATUS_DRIVER);
	ATF_CHECK_EQ(VIRTIO_CONFIG_STATUS_DRIVER_OK,
	    VIRTIO14_STATUS_DRIVER_OK);
	ATF_CHECK_EQ(VIRTIO_CONFIG_S_FEATURES_OK,
	    VIRTIO14_STATUS_FEATURES_OK);
	ATF_CHECK_EQ(VIRTIO_CONFIG_S_NEEDS_RESET,
	    VIRTIO14_STATUS_DEVICE_NEEDS_RESET);
	ATF_CHECK_EQ(VIRTIO_CONFIG_STATUS_FAILED, VIRTIO14_STATUS_FAILED);

	ATF_CHECK_EQ(VIRTIO_RING_F_INDIRECT_DESC,
	    VIRTIO14_F_RING_INDIRECT_DESC);
	ATF_CHECK_EQ(VIRTIO_RING_F_EVENT_IDX, VIRTIO14_F_RING_EVENT_IDX);
	ATF_CHECK_EQ(VIRTIO_F_VERSION_1, VIRTIO14_F_VERSION_1);
	ATF_CHECK_EQ(VIRTIO_F_ACCESS_PLATFORM,
	    VIRTIO14_F_ACCESS_PLATFORM);
	ATF_CHECK_EQ(VIRTIO_F_RING_PACKED, VIRTIO14_F_RING_PACKED);
	ATF_CHECK_EQ(VIRTIO_F_IN_ORDER, VIRTIO14_F_IN_ORDER);
	ATF_CHECK_EQ(VIRTIO_F_ORDER_PLATFORM, VIRTIO14_F_ORDER_PLATFORM);
	ATF_CHECK_EQ(VIRTIO_F_SR_IOV, VIRTIO14_F_SR_IOV);
	ATF_CHECK_EQ(VIRTIO_F_NOTIFICATION_DATA,
	    VIRTIO14_F_NOTIFICATION_DATA);
	ATF_CHECK_EQ(VIRTIO_F_NOTIF_CONFIG_DATA,
	    VIRTIO14_F_NOTIF_CONFIG_DATA);
	ATF_CHECK_EQ(VIRTIO_F_RING_RESET, VIRTIO14_F_RING_RESET);
	ATF_CHECK_EQ(VIRTIO_F_ADMIN_VQ, VIRTIO14_F_ADMIN_VQ);
	ATF_CHECK_EQ(VIRTIO_F_SUSPEND, VIRTIO14_F_SUSPEND);

	ATF_CHECK_EQ(VIRTIO_ID_NETWORK, VIRTIO14_DEVICE_NETWORK);
	ATF_CHECK_EQ(VIRTIO_ID_BLOCK, VIRTIO14_DEVICE_BLOCK);
	ATF_CHECK_EQ(VIRTIO_ID_CONSOLE, VIRTIO14_DEVICE_CONSOLE);
	ATF_CHECK_EQ(VIRTIO_ID_ENTROPY, VIRTIO14_DEVICE_ENTROPY);
	ATF_CHECK_EQ(VIRTIO_ID_SCSI, VIRTIO14_DEVICE_SCSI);
	ATF_CHECK_EQ(VIRTIO_ID_9P, VIRTIO14_DEVICE_9P);
	ATF_CHECK_EQ(VIRTIO_ID_INPUT, VIRTIO14_DEVICE_INPUT);
	ATF_CHECK_EQ(VIRTIO_ID_GPU, VIRTIO14_DEVICE_GPU);
	ATF_CHECK_EQ(VIRTIO_ID_CLOCK, VIRTIO14_RTC_DEVICE_ID);
	ATF_CHECK_EQ(VIRTIO_ID_VSOCK, VIRTIO14_DEVICE_VSOCK);

	ATF_CHECK_EQ(VIRTIO_PCI_CAP_COMMON_CFG,
	    VIRTIO14_PCI_CAP_COMMON_CFG);
	ATF_CHECK_EQ(VIRTIO_PCI_CAP_NOTIFY_CFG,
	    VIRTIO14_PCI_CAP_NOTIFY_CFG);
	ATF_CHECK_EQ(VIRTIO_PCI_CAP_ISR_CFG, VIRTIO14_PCI_CAP_ISR_CFG);
	ATF_CHECK_EQ(VIRTIO_PCI_CAP_DEVICE_CFG,
	    VIRTIO14_PCI_CAP_DEVICE_CFG);
	ATF_CHECK_EQ(VIRTIO_PCI_CAP_PCI_CFG, VIRTIO14_PCI_CAP_PCI_CFG);
	ATF_CHECK_EQ(VIRTIO_PCI_CAP_SHARED_MEMORY_CFG,
	    VIRTIO14_PCI_CAP_SHARED_MEMORY_CFG);
	ATF_CHECK_EQ(VIRTIO_PCI_ISR_INTR, VIRTIO14_ISR_QUEUE);
	ATF_CHECK_EQ(VIRTIO_PCI_ISR_CONFIG, VIRTIO14_ISR_CONFIG);
	ATF_CHECK_EQ(VIRTIO_MSI_NO_VECTOR, VIRTIO14_MSI_NO_VECTOR);
}

ATF_TC_WITHOUT_HEAD(scsi_event_used_length_contract);
ATF_TC_BODY(scsi_event_used_length_contract, tc)
{

	ATF_CHECK_EQ(sizeof(struct virtio_scsi_event),
	    VIRTIO14_SCSI_EVENT_SIZE);
	ATF_CHECK(!virtio_scsi_event_used_len_valid(0,
	    VIRTIO14_SCSI_EVENT_SIZE));
	ATF_CHECK(!virtio_scsi_event_used_len_valid(
	    VIRTIO14_SCSI_EVENT_SIZE - 1, VIRTIO14_SCSI_EVENT_SIZE));
	ATF_CHECK(virtio_scsi_event_used_len_valid(
	    VIRTIO14_SCSI_EVENT_SIZE, VIRTIO14_SCSI_EVENT_SIZE));
	ATF_CHECK(virtio_scsi_event_used_len_valid(
	    VIRTIO14_SCSI_EVENT_SIZE, VIRTIO14_SCSI_EVENT_SIZE + 16));
	ATF_CHECK(virtio_scsi_event_used_len_valid(
	    VIRTIO14_SCSI_EVENT_SIZE + 16, VIRTIO14_SCSI_EVENT_SIZE + 16));
	ATF_CHECK(!virtio_scsi_event_used_len_valid(
	    VIRTIO14_SCSI_EVENT_SIZE + 17, VIRTIO14_SCSI_EVENT_SIZE + 16));
}

ATF_TC_WITHOUT_HEAD(scsi_response_bounds_contract);
ATF_TC_BODY(scsi_response_bounds_contract, tc)
{

	ATF_CHECK_EQ(VIRTIO_SCSI_SENSE_SIZE,
	    VIRTIO14_SCSI_DEFAULT_SENSE_SIZE);
	ATF_CHECK_EQ(virtio_scsi_sense_copy_len(0, 252), 0);
	ATF_CHECK_EQ(virtio_scsi_sense_copy_len(1, 252), 1);
	ATF_CHECK_EQ(virtio_scsi_sense_copy_len(
	    VIRTIO14_SCSI_DEFAULT_SENSE_SIZE, 252),
	    VIRTIO14_SCSI_DEFAULT_SENSE_SIZE);
	ATF_CHECK_EQ(virtio_scsi_sense_copy_len(
	    VIRTIO14_SCSI_DEFAULT_SENSE_SIZE + 1, 252),
	    VIRTIO14_SCSI_DEFAULT_SENSE_SIZE);
	ATF_CHECK_EQ(virtio_scsi_sense_copy_len(UINT32_MAX, 252),
	    VIRTIO14_SCSI_DEFAULT_SENSE_SIZE);
	ATF_CHECK_EQ(virtio_scsi_sense_copy_len(80, 32), 32);
	ATF_CHECK_EQ(virtio_scsi_sense_copy_len(UINT32_MAX, 32), 32);

	ATF_CHECK(virtio_scsi_resid_valid(0, 0));
	ATF_CHECK(virtio_scsi_resid_valid(0, 4096));
	ATF_CHECK(virtio_scsi_resid_valid(4095, 4096));
	ATF_CHECK(virtio_scsi_resid_valid(4096, 4096));
	ATF_CHECK(!virtio_scsi_resid_valid(4097, 4096));
	ATF_CHECK(!virtio_scsi_resid_valid(UINT32_MAX, 4096));
}

ATF_TC_WITHOUT_HEAD(console_control_used_length_contract);
ATF_TC_BODY(console_control_used_length_contract, tc)
{
	const uint32_t buffer_len = 128;

	ATF_CHECK_EQ(sizeof(struct virtio_console_control),
	    VIRTIO14_CONSOLE_CONTROL_SIZE);
	ATF_CHECK(!virtio_console_control_used_len_valid(0, buffer_len));
	ATF_CHECK(!virtio_console_control_used_len_valid(
	    sizeof(struct virtio_console_control) - 1, buffer_len));
	ATF_CHECK(virtio_console_control_used_len_valid(
	    sizeof(struct virtio_console_control), buffer_len));
	ATF_CHECK(virtio_console_control_used_len_valid(buffer_len,
	    buffer_len));
	ATF_CHECK(!virtio_console_control_used_len_valid(buffer_len + 1,
	    buffer_len));
}

ATF_TC_WITHOUT_HEAD(vsock_used_length_contract);
ATF_TC_BODY(vsock_used_length_contract, tc)
{
	const uint32_t rx_buffer_len = 4096;

	ATF_CHECK(virtio_vsock_rx_used_len_valid(0, rx_buffer_len));
	ATF_CHECK(virtio_vsock_rx_used_len_valid(rx_buffer_len,
	    rx_buffer_len));
	ATF_CHECK(!virtio_vsock_rx_used_len_valid(rx_buffer_len + 1,
	    rx_buffer_len));

	ATF_CHECK(virtio_vsock_event_used_len_valid(
	    VIRTIO14_VSOCK_EVENT_SIZE, VIRTIO14_VSOCK_EVENT_SIZE));
	ATF_CHECK(!virtio_vsock_event_used_len_valid(
	    VIRTIO14_VSOCK_EVENT_SIZE - 1, VIRTIO14_VSOCK_EVENT_SIZE));
	ATF_CHECK(!virtio_vsock_event_used_len_valid(
	    VIRTIO14_VSOCK_EVENT_SIZE + 1, VIRTIO14_VSOCK_EVENT_SIZE));
}

ATF_TC_WITHOUT_HEAD(random_used_length_contract);
ATF_TC_BODY(random_used_length_contract, tc)
{
	const size_t buffer_len = 1024;

	ATF_CHECK(virtio_random_used_len_valid(0, buffer_len));
	ATF_CHECK(virtio_random_used_len_valid(buffer_len, buffer_len));
	ATF_CHECK(!virtio_random_used_len_valid(buffer_len + 1, buffer_len));
	ATF_CHECK(virtio_random_used_len_valid(UINT32_MAX,
	    (size_t)UINT32_MAX));
}

ATF_TC_WITHOUT_HEAD(gpu_wire_and_geometry_contract);
ATF_TC_BODY(gpu_wire_and_geometry_contract, tc)
{
	uint32_t stride;
	uint64_t size;

	ATF_CHECK_EQ(VIRTIO_GPU_CMD_GET_DISPLAY_INFO,
	    VIRTIO14_GPU_CMD_GET_DISPLAY_INFO);
	ATF_CHECK_EQ(VIRTIO_GPU_RESP_OK_DISPLAY_INFO,
	    VIRTIO14_GPU_RESP_OK_DISPLAY_INFO);
	ATF_CHECK_EQ(VIRTIO_GPU_MAX_SCANOUTS,
	    VIRTIO14_GPU_MAX_SCANOUTS);
	ATF_CHECK_EQ(sizeof(struct virtio_gpu_ctrl_hdr),
	    VIRTIO14_GPU_CTRL_HDR_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_gpu_rect),
	    VIRTIO14_GPU_RECT_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_gpu_display_one),
	    VIRTIO14_GPU_DISPLAY_ONE_SIZE);
	ATF_CHECK_EQ(offsetof(struct virtio_gpu_display_one, enabled),
	    VIRTIO14_GPU_DISPLAY_ENABLED_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_gpu_display_one, flags),
	    VIRTIO14_GPU_DISPLAY_FLAGS_OFF);
	ATF_CHECK_EQ(sizeof(struct virtio_gpu_resp_display_info),
	    VIRTIO14_GPU_DISPLAY_INFO_SIZE);

	ATF_CHECK(virtio_gpu_framebuffer_geometry(1920, 1080, 4,
	    UINT32_MAX, UINT64_MAX, &stride, &size));
	ATF_CHECK_EQ(stride, 7680);
	ATF_CHECK_EQ(size, UINT64_C(8294400));
	ATF_CHECK(!virtio_gpu_framebuffer_geometry(0, 1080, 4,
	    UINT32_MAX, UINT64_MAX, &stride, &size));
	ATF_CHECK(!virtio_gpu_framebuffer_geometry(UINT32_MAX, 2, 4,
	    UINT32_MAX, UINT64_MAX, &stride, &size));
	ATF_CHECK(!virtio_gpu_framebuffer_geometry(1024, 1024, 4,
	    UINT32_MAX, UINT64_C(1024), &stride, &size));

	ATF_CHECK(virtio_gpu_rect_within(1920, 1080, 0, 0, 1920, 1080));
	ATF_CHECK(virtio_gpu_rect_within(1920, 1080, 1919, 1079, 1, 1));
	ATF_CHECK(!virtio_gpu_rect_within(1920, 1080, 1920, 0, 1, 1));
	ATF_CHECK(!virtio_gpu_rect_within(1920, 1080, 0, 1080, 1, 1));
	ATF_CHECK(!virtio_gpu_rect_within(1920, 1080, 0, 0, 0, 1));
	ATF_CHECK(!virtio_gpu_rect_within(1920, 1080, UINT32_MAX, 0,
	    UINT32_MAX, 1));
}

ATF_TC_WITHOUT_HEAD(rtc_guest_wire_contract);
ATF_TC_BODY(rtc_guest_wire_contract, tc)
{

	ATF_CHECK_EQ(VIRTIO_RTC_REQ_READ, VIRTIO14_RTC_REQ_READ);
	ATF_CHECK_EQ(VIRTIO_RTC_REQ_READ_CROSS,
	    VIRTIO14_RTC_REQ_READ_CROSS);
	ATF_CHECK_EQ(VIRTIO_RTC_REQ_CFG, VIRTIO14_RTC_REQ_CFG);
	ATF_CHECK_EQ(VIRTIO_RTC_REQ_CLOCK_CAP,
	    VIRTIO14_RTC_REQ_CLOCK_CAP);
	ATF_CHECK_EQ(VIRTIO_RTC_REQ_CROSS_CAP,
	    VIRTIO14_RTC_REQ_CROSS_CAP);
	ATF_CHECK_EQ(VIRTIO_RTC_REQ_READ_ALARM,
	    VIRTIO14_RTC_REQ_READ_ALARM);
	ATF_CHECK_EQ(VIRTIO_RTC_REQ_SET_ALARM,
	    VIRTIO14_RTC_REQ_SET_ALARM);
	ATF_CHECK_EQ(VIRTIO_RTC_REQ_SET_ALARM_ENABLED,
	    VIRTIO14_RTC_REQ_SET_ALARM_ENABLED);
	ATF_CHECK_EQ(VIRTIO_RTC_NOTIF_ALARM,
	    VIRTIO14_RTC_NOTIF_ALARM);
	ATF_CHECK_EQ(VIRTIO_RTC_F_ALARM,
	    UINT64_C(1) << VIRTIO14_RTC_F_ALARM);

	ATF_CHECK_EQ(VIRTIO_RTC_S_OK, VIRTIO14_RTC_STATUS_OK);
	ATF_CHECK_EQ(VIRTIO_RTC_S_EOPNOTSUPP,
	    VIRTIO14_RTC_STATUS_EOPNOTSUPP);
	ATF_CHECK_EQ(VIRTIO_RTC_S_ENODEV,
	    VIRTIO14_RTC_STATUS_ENODEV);
	ATF_CHECK_EQ(VIRTIO_RTC_S_EINVAL,
	    VIRTIO14_RTC_STATUS_EINVAL);
	ATF_CHECK_EQ(VIRTIO_RTC_S_EIO, VIRTIO14_RTC_STATUS_EIO);
	ATF_CHECK_EQ(VIRTIO_RTC_CLOCK_UTC, VIRTIO14_RTC_CLOCK_UTC);
	ATF_CHECK_EQ(VIRTIO_RTC_CLOCK_UTC_MAYBE_SMEARED,
	    VIRTIO14_RTC_CLOCK_UTC_MAYBE_SMEARED);
	ATF_CHECK_EQ(VIRTIO_RTC_COUNTER_ARM_VCT,
	    VIRTIO14_RTC_COUNTER_ARM_VCT);
	ATF_CHECK_EQ(VIRTIO_RTC_COUNTER_X86_TSC,
	    VIRTIO14_RTC_COUNTER_X86_TSC);
	ATF_CHECK_EQ(VIRTIO_RTC_FLAG_ALARM_ENABLED,
	    VIRTIO14_RTC_FLAG_ALARM_ENABLED);
	ATF_CHECK_EQ(VIRTIO_RTC_FLAG_ALARM_CAP,
	    VIRTIO14_RTC_FLAG_ALARM_CAP);

	ATF_CHECK_EQ(sizeof(struct virtio_rtc_req_head),
	    VIRTIO14_RTC_REQ_HEAD_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_resp_head),
	    VIRTIO14_RTC_RESP_HEAD_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_req_cfg),
	    VIRTIO14_RTC_REQ_CFG_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_req_clock_cap),
	    VIRTIO14_RTC_REQ_CLOCK_CAP_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_req_cross_cap),
	    VIRTIO14_RTC_REQ_CROSS_CAP_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_req_read),
	    VIRTIO14_RTC_REQ_READ_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_resp_read),
	    VIRTIO14_RTC_RESP_READ_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_resp_cfg),
	    VIRTIO14_RTC_RESP_CFG_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_resp_clock_cap),
	    VIRTIO14_RTC_RESP_CLOCK_CAP_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_resp_cross_cap),
	    VIRTIO14_RTC_RESP_CROSS_CAP_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_req_read_alarm),
	    VIRTIO14_RTC_REQ_READ_ALARM_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_resp_read_alarm),
	    VIRTIO14_RTC_RESP_READ_ALARM_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_req_set_alarm),
	    VIRTIO14_RTC_REQ_SET_ALARM_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_req_set_alarm_enabled),
	    VIRTIO14_RTC_REQ_SET_ALARM_ENABLED_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_notif_head),
	    VIRTIO14_RTC_NOTIF_HEAD_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_notif_alarm),
	    VIRTIO14_RTC_NOTIF_ALARM_SIZE);

	ATF_CHECK_EQ(offsetof(struct virtio_rtc_req_read, clock_id),
	    VIRTIO14_RTC_REQ_HEAD_SIZE);
	ATF_CHECK_EQ(offsetof(struct virtio_rtc_resp_read, clock_reading),
	    VIRTIO14_RTC_RESP_HEAD_SIZE);
	ATF_CHECK_EQ(offsetof(struct virtio_rtc_resp_cfg, num_clocks),
	    VIRTIO14_RTC_RESP_HEAD_SIZE);
}

ATF_TC_WITHOUT_HEAD(input_guest_wire_contract);
ATF_TC_BODY(input_guest_wire_contract, tc)
{

	ATF_CHECK_EQ(VIRTIO_INPUT_CFG_UNSET, VIRTIO14_INPUT_CFG_UNSET);
	ATF_CHECK_EQ(VIRTIO_INPUT_CFG_ID_NAME,
	    VIRTIO14_INPUT_CFG_ID_NAME);
	ATF_CHECK_EQ(VIRTIO_INPUT_CFG_ID_SERIAL,
	    VIRTIO14_INPUT_CFG_ID_SERIAL);
	ATF_CHECK_EQ(VIRTIO_INPUT_CFG_ID_DEVIDS,
	    VIRTIO14_INPUT_CFG_ID_DEVIDS);
	ATF_CHECK_EQ(VIRTIO_INPUT_CFG_PROP_BITS,
	    VIRTIO14_INPUT_CFG_PROP_BITS);
	ATF_CHECK_EQ(VIRTIO_INPUT_CFG_EV_BITS,
	    VIRTIO14_INPUT_CFG_EV_BITS);
	ATF_CHECK_EQ(VIRTIO_INPUT_CFG_ABS_INFO,
	    VIRTIO14_INPUT_CFG_ABS_INFO);

	ATF_CHECK_EQ(sizeof(struct virtio_input_absinfo),
	    VIRTIO14_INPUT_ABSINFO_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_input_devids),
	    VIRTIO14_INPUT_DEVIDS_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_input_config),
	    VIRTIO14_INPUT_CONFIG_SIZE);
	ATF_CHECK_EQ(offsetof(struct virtio_input_config, select),
	    VIRTIO14_INPUT_CONFIG_SELECT_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_input_config, subsel),
	    VIRTIO14_INPUT_CONFIG_SUBSEL_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_input_config, size),
	    VIRTIO14_INPUT_CONFIG_SIZE_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_input_config, u),
	    VIRTIO14_INPUT_CONFIG_UNION_OFF);
	ATF_CHECK_EQ(sizeof(((struct virtio_input_config *)0)->reserved),
	    VIRTIO14_INPUT_CONFIG_RESERVED_SIZE);
	ATF_CHECK_EQ(sizeof(((struct virtio_input_config *)0)->u),
	    VIRTIO14_INPUT_CONFIG_UNION_SIZE);
	ATF_CHECK_EQ(sizeof(((struct virtio_input_config *)0)->u.string),
	    VIRTIO14_INPUT_CONFIG_STRING_SIZE);

	ATF_CHECK_EQ(sizeof(struct virtio_input_event),
	    VIRTIO14_INPUT_EVENT_SIZE);
	ATF_CHECK_EQ(offsetof(struct virtio_input_event, type),
	    VIRTIO14_INPUT_EVENT_TYPE_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_input_event, code),
	    VIRTIO14_INPUT_EVENT_CODE_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_input_event, value),
	    VIRTIO14_INPUT_EVENT_VALUE_OFF);
}

ATF_TC_WITHOUT_HEAD(balloon_statistics_wire_contract);
ATF_TC_BODY(balloon_statistics_wire_contract, tc)
{

	ATF_CHECK_EQ(VIRTIO_BALLOON_F_MUST_TELL_HOST,
	    VIRTIO14_BALLOON_F_MUST_TELL_HOST);
	ATF_CHECK_EQ(VIRTIO_BALLOON_F_STATS_VQ,
	    VIRTIO14_BALLOON_F_STATS_VQ);
	ATF_CHECK_EQ(VIRTIO_BALLOON_S_SWAP_IN,
	    VIRTIO14_BALLOON_S_SWAP_IN);
	ATF_CHECK_EQ(VIRTIO_BALLOON_S_MEMFREE,
	    VIRTIO14_BALLOON_S_MEMFREE);
	ATF_CHECK_EQ(VIRTIO_BALLOON_S_MEMTOT,
	    VIRTIO14_BALLOON_S_MEMTOT);
	ATF_CHECK_EQ(sizeof(struct virtio_balloon_stat),
	    VIRTIO14_BALLOON_STAT_SIZE);
	ATF_CHECK_EQ(offsetof(struct virtio_balloon_stat, tag),
	    VIRTIO14_BALLOON_STAT_TAG_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_balloon_stat, val),
	    VIRTIO14_BALLOON_STAT_VALUE_OFF);
	ATF_CHECK_EQ((3 * sizeof(struct virtio_balloon_stat)) %
	    VIRTIO14_BALLOON_STATS_BUFFER_MULTIPLE, 0);
}

ATF_TC_WITHOUT_HEAD(balloon_page_poison_wire_contract);
ATF_TC_BODY(balloon_page_poison_wire_contract, tc)
{

	ATF_CHECK_EQ(VIRTIO_BALLOON_F_PAGE_POISON,
	    VIRTIO14_BALLOON_F_PAGE_POISON);
	ATF_CHECK_EQ(offsetof(struct virtio_balloon_config, poison_val),
	    VIRTIO14_BALLOON_POISON_VAL_OFF);
	ATF_CHECK_EQ(VIRTIO_BALLOON_S_HTLB_PGALLOC, 8);
	ATF_CHECK_EQ(VIRTIO_BALLOON_S_HTLB_PGFAIL, 9);
	ATF_CHECK_EQ(VIRTIO_BALLOON_S_NR, 10);
}

ATF_TC_WITHOUT_HEAD(balloon_request_failure_contract);
ATF_TC_BODY(balloon_request_failure_contract, tc)
{

	ATF_CHECK_EQ(virtio_balloon_request_result(true, true, 0), 0);
	ATF_CHECK_EQ(virtio_balloon_request_result(true, false, 0), EPROTO);
	ATF_CHECK_EQ(virtio_balloon_request_result(false, false,
	    EWOULDBLOCK), ETIMEDOUT);
	ATF_CHECK_EQ(virtio_balloon_request_result(false, false,
	    ECANCELED), ECANCELED);
	ATF_CHECK_EQ(virtio_balloon_request_result(false, false, 0), EIO);
}

ATF_TC_WITHOUT_HEAD(balloon_lowmem_target_contract);
ATF_TC_BODY(balloon_lowmem_target_contract, tc)
{

	ATF_CHECK_EQ(virtio_balloon_lowmem_target(0, 256), 0);
	ATF_CHECK_EQ(virtio_balloon_lowmem_target(1, 256), 0);
	ATF_CHECK_EQ(virtio_balloon_lowmem_target(256, 256), 0);
	ATF_CHECK_EQ(virtio_balloon_lowmem_target(257, 256), 1);
	ATF_CHECK_EQ(virtio_balloon_lowmem_target(UINT32_MAX, 256),
	    UINT32_MAX - 256);
	ATF_CHECK_EQ(virtio_balloon_lowmem_target(4096, 0), 0);
}

ATF_TC_WITHOUT_HEAD(balloon_pfn_portability_contract);
ATF_TC_BODY(balloon_pfn_portability_contract, tc)
{
	uint32_t pfn;

	pfn = UINT32_C(0xa5a5a5a5);
	ATF_REQUIRE_EQ(virtio_balloon_encode_pfn(0, 1, &pfn), 0);
	ATF_CHECK_EQ(pfn, 0);
	ATF_REQUIRE_EQ(virtio_balloon_encode_pfn(
	    UINT64_C(0xffffffff) << 12, 1, &pfn), 0);
	ATF_CHECK_EQ(pfn, UINT32_MAX);

	/* A 16-KiB guest page consumes four consecutive 4-KiB PFNs. */
	ATF_REQUIRE_EQ(virtio_balloon_encode_pfn(
	    UINT64_C(0xfffffffc) << 12, 4, &pfn), 0);
	ATF_CHECK_EQ(pfn, UINT32_C(0xfffffffc));
	pfn = UINT32_C(0x5a5a5a5a);
	ATF_CHECK_EQ(virtio_balloon_encode_pfn(
	    UINT64_C(0xfffffffd) << 12, 4, &pfn), ERANGE);
	ATF_CHECK_EQ(pfn, UINT32_C(0x5a5a5a5a));
	ATF_CHECK_EQ(virtio_balloon_encode_pfn(UINT64_C(0x100000000) << 12,
	    1, &pfn), ERANGE);
	ATF_CHECK_EQ(virtio_balloon_encode_pfn(1, 1, &pfn), EINVAL);
	ATF_CHECK_EQ(virtio_balloon_encode_pfn(0, 0, &pfn), EINVAL);
	ATF_CHECK_EQ(virtio_balloon_encode_pfn(0, 1, NULL), EINVAL);

	ATF_CHECK_EQ(virtio_balloon_align_target(0, 4), 0);
	ATF_CHECK_EQ(virtio_balloon_align_target(1, 4), 4);
	ATF_CHECK_EQ(virtio_balloon_align_target(4, 4), 4);
	ATF_CHECK_EQ(virtio_balloon_align_target(5, 4), 8);
	ATF_CHECK_EQ(virtio_balloon_align_target(UINT32_MAX, 4),
	    UINT32_MAX - 3);
	ATF_CHECK_EQ(virtio_balloon_align_target(1, 0), 0);
}

ATF_TC_WITHOUT_HEAD(virtio_1_4_pci_layout);
ATF_TC_BODY(virtio_1_4_pci_layout, tc)
{

	ATF_CHECK_EQ(sizeof(struct virtio_pci_cap),
	    VIRTIO14_PCI_CAP_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_pci_notify_cap),
	    VIRTIO14_PCI_NOTIFY_CAP_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_pci_cfg_cap),
	    VIRTIO14_PCI_CFG_CAP_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_pci_cap64),
	    VIRTIO14_PCI_CAP64_SIZE);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_cap, cap_vndr),
	    VIRTIO14_PCI_CAP_VNDR_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_cap, cap_next),
	    VIRTIO14_PCI_CAP_NEXT_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_cap, cap_len),
	    VIRTIO14_PCI_CAP_LEN_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_cap, cfg_type),
	    VIRTIO14_PCI_CAP_CFG_TYPE_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_cap, bar),
	    VIRTIO14_PCI_CAP_BAR_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_cap, id),
	    VIRTIO14_PCI_CAP_ID_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_cap, offset),
	    VIRTIO14_PCI_CAP_OFFSET_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_cap, length),
	    VIRTIO14_PCI_CAP_LENGTH_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_cap64, offset_hi),
	    VIRTIO14_PCI_CAP64_OFFSET_HI_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_cap64, length_hi),
	    VIRTIO14_PCI_CAP64_LENGTH_HI_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_notify_cap,
	    notify_off_multiplier), VIRTIO14_PCI_NOTIFY_MULT_OFF);

	ATF_CHECK_EQ(sizeof(struct virtio_pci_common_cfg),
	    VIRTIO14_COMMON_BASE_SIZE);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg,
	    device_feature_select), VIRTIO14_COMMON_DEVICE_FEATURE_SELECT);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, device_feature),
	    VIRTIO14_COMMON_DEVICE_FEATURE);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg,
	    guest_feature_select), VIRTIO14_COMMON_DRIVER_FEATURE_SELECT);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, guest_feature),
	    VIRTIO14_COMMON_DRIVER_FEATURE);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, msix_config),
	    VIRTIO14_COMMON_CONFIG_MSIX_VECTOR);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, num_queues),
	    VIRTIO14_COMMON_NUM_QUEUES);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, device_status),
	    VIRTIO14_COMMON_DEVICE_STATUS);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg,
	    config_generation), VIRTIO14_COMMON_CONFIG_GENERATION);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, queue_select),
	    VIRTIO14_COMMON_QUEUE_SELECT);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, queue_size),
	    VIRTIO14_COMMON_QUEUE_SIZE);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg,
	    queue_msix_vector), VIRTIO14_COMMON_QUEUE_MSIX_VECTOR);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, queue_enable),
	    VIRTIO14_COMMON_QUEUE_ENABLE);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, queue_notify_off),
	    VIRTIO14_COMMON_QUEUE_NOTIFY_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, queue_desc_lo),
	    VIRTIO14_COMMON_QUEUE_DESC);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, queue_avail_lo),
	    VIRTIO14_COMMON_QUEUE_DRIVER);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, queue_used_lo),
	    VIRTIO14_COMMON_QUEUE_DEVICE);
}

ATF_TC_WITHOUT_HEAD(virtio_1_4_mmio_layout);
ATF_TC_BODY(virtio_1_4_mmio_layout, tc)
{

	ATF_CHECK_EQ(VIRTIO_MMIO_MAGIC_VALUE, VIRTIO14_MMIO_MAGIC_VALUE);
	ATF_CHECK_EQ(VIRTIO_MMIO_VERSION, VIRTIO14_MMIO_VERSION);
	ATF_CHECK_EQ(VIRTIO_MMIO_DEVICE_ID, VIRTIO14_MMIO_DEVICE_ID);
	ATF_CHECK_EQ(VIRTIO_MMIO_VENDOR_ID, VIRTIO14_MMIO_VENDOR_ID);
	ATF_CHECK_EQ(VIRTIO_MMIO_HOST_FEATURES,
	    VIRTIO14_MMIO_DEVICE_FEATURES);
	ATF_CHECK_EQ(VIRTIO_MMIO_HOST_FEATURES_SEL,
	    VIRTIO14_MMIO_DEVICE_FEATURES_SEL);
	ATF_CHECK_EQ(VIRTIO_MMIO_GUEST_FEATURES,
	    VIRTIO14_MMIO_DRIVER_FEATURES);
	ATF_CHECK_EQ(VIRTIO_MMIO_GUEST_FEATURES_SEL,
	    VIRTIO14_MMIO_DRIVER_FEATURES_SEL);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_SEL, VIRTIO14_MMIO_QUEUE_SEL);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_NUM_MAX,
	    VIRTIO14_MMIO_QUEUE_NUM_MAX);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_NUM, VIRTIO14_MMIO_QUEUE_NUM);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_READY, VIRTIO14_MMIO_QUEUE_READY);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_NOTIFY, VIRTIO14_MMIO_QUEUE_NOTIFY);
	ATF_CHECK_EQ(VIRTIO_MMIO_INTERRUPT_STATUS,
	    VIRTIO14_MMIO_INTERRUPT_STATUS);
	ATF_CHECK_EQ(VIRTIO_MMIO_INTERRUPT_ACK,
	    VIRTIO14_MMIO_INTERRUPT_ACK);
	ATF_CHECK_EQ(VIRTIO_MMIO_STATUS, VIRTIO14_MMIO_STATUS);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_DESC_LOW,
	    VIRTIO14_MMIO_QUEUE_DESC_LOW);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_DESC_HIGH,
	    VIRTIO14_MMIO_QUEUE_DESC_HIGH);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_AVAIL_LOW,
	    VIRTIO14_MMIO_QUEUE_DRIVER_LOW);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_AVAIL_HIGH,
	    VIRTIO14_MMIO_QUEUE_DRIVER_HIGH);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_USED_LOW,
	    VIRTIO14_MMIO_QUEUE_DEVICE_LOW);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_USED_HIGH,
	    VIRTIO14_MMIO_QUEUE_DEVICE_HIGH);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_RESET, VIRTIO14_MMIO_QUEUE_RESET);
	ATF_CHECK_EQ(VIRTIO_MMIO_CONFIG_GENERATION,
	    VIRTIO14_MMIO_CONFIG_GENERATION);
	ATF_CHECK_EQ(VIRTIO_MMIO_CONFIG, VIRTIO14_MMIO_CONFIG);
	ATF_CHECK_EQ(VIRTIO_MMIO_MAGIC_VIRT, VIRTIO14_MMIO_MAGIC_VIRT);
	ATF_CHECK_EQ(VIRTIO_MMIO_INT_VRING,
	    VIRTIO14_MMIO_INTERRUPT_VRING);
	ATF_CHECK_EQ(VIRTIO_MMIO_INT_CONFIG,
	    VIRTIO14_MMIO_INTERRUPT_CONFIG);
}

ATF_TC_WITHOUT_HEAD(reinit_feature_ceiling);
ATF_TC_BODY(reinit_feature_ceiling, tc)
{
	const uint64_t original = VIRTIO14_NET_F_MTU |
	    VIRTIO14_NET_F_CTRL_VQ | VIRTIO14_F_IN_ORDER;
	uint64_t reduced;

	ATF_CHECK(virtio_features_subset(original, original));
	ATF_CHECK(virtio_features_subset(original, 0));

	reduced = original & ~VIRTIO14_NET_F_CTRL_VQ;
	ATF_CHECK(virtio_features_subset(original, reduced));

	/*
	 * A feature disabled by one reinitialization can be restored because
	 * the ceiling is the original negotiation, not the current subset.
	 */
	ATF_CHECK(virtio_features_subset(original, original));

	ATF_CHECK(!virtio_features_subset(original,
	    original | VIRTIO14_NET_F_GUEST_RSC6));
	ATF_CHECK(!virtio_features_subset(0, VIRTIO14_F_VERSION_1));

	/*
	 * Reinitialization must fail if the device no longer offers the
	 * complete requested subset; the API cannot report a reduced set.
	 */
	ATF_CHECK(!virtio_features_subset(reduced, original));
}

ATF_TC_WITHOUT_HEAD(notification_write_width);
ATF_TC_BODY(notification_write_width, tc)
{
	uint32_t expected;

	ATF_CHECK_EQ(virtio_pci_queue_notify_size(false),
	    VIRTIO14_PCI_NOTIFY_NO_DATA_SIZE);
	ATF_CHECK_EQ(virtio_pci_queue_notify_size(true),
	    VIRTIO14_PCI_NOTIFY_DATA_SIZE);
	ATF_CHECK_EQ(VIRTIO14_MMIO_CONTROL_ACCESS_SIZE,
	    VIRTIO14_CONFIG_FIELD_U32_SIZE);

	expected = (UINT32_C(0xa55a) <<
	    VIRTIO14_NOTIFICATION_NEXT_OFF_SHIFT) |
	    (UINT32_C(0x1234) & VIRTIO14_NOTIFICATION_VQ_INDEX_MASK);
	ATF_CHECK_EQ(virtio_split_notification_data(0x1234, 0xa55a),
	    expected);

	/*
	 * The expected values are literal examples from the section 4.1.4.3
	 * rule, not values imported from the production PCI transport.
	 */
	ATF_CHECK_EQ(virtio_pci_notification_identifier(0x1234, 0xbeef,
	    false), UINT16_C(0x1234));
	ATF_CHECK_EQ(virtio_pci_notification_identifier(0x1234, 0xbeef,
	    true), UINT16_C(0xbeef));
	ATF_CHECK_EQ(virtio_split_notification_data(
	    virtio_pci_notification_identifier(0x1234, 0xbeef, true),
	    0xa55a), (UINT32_C(0xa55a) << 16) | UINT32_C(0xbeef));
}

ATF_TC_WITHOUT_HEAD(notification_feature_validation);
ATF_TC_BODY(notification_feature_validation, tc)
{
	const uint64_t unrelated = VIRTIO14_NET_F_MTU;

	/*
	 * Section 4.1.4.4 requires the 32-bit notification capability layout
	 * when NotificationData is negotiated.  The expected masks below use
	 * only the document oracle; in particular, a child-requested copy of
	 * the transport feature cannot survive an invalid layout.
	 */
	ATF_CHECK_EQ(virtio_modern_notification_data_features(
	    unrelated | VIRTIO14_F_NOTIFICATION_DATA,
	    VIRTIO14_F_NOTIFICATION_DATA, false), unrelated);
	ATF_CHECK_EQ(virtio_modern_notification_data_features(
	    unrelated, VIRTIO14_F_NOTIFICATION_DATA, true),
	    unrelated | VIRTIO14_F_NOTIFICATION_DATA);
	ATF_CHECK_EQ(virtio_modern_notification_data_features(
	    unrelated | VIRTIO14_F_NOTIFICATION_DATA, 0, true), unrelated);
}

ATF_TC_WITHOUT_HEAD(split_queue_size_limits);
ATF_TC_BODY(split_queue_size_limits, tc)
{

	ATF_CHECK_EQ(VIRTIO_SPLIT_QUEUE_SIZE_MAX,
	    VIRTIO14_SPLIT_QUEUE_SIZE_MAX);
	ATF_CHECK(!virtio_split_queue_size_valid(0));
	ATF_CHECK(virtio_split_queue_size_valid(1));
	ATF_CHECK(virtio_split_queue_size_valid(
	    VIRTIO14_SPLIT_QUEUE_SIZE_MAX));
	ATF_CHECK(!virtio_split_queue_size_valid(
	    VIRTIO14_SPLIT_QUEUE_SIZE_MAX - 1));
	ATF_CHECK(!virtio_split_queue_size_valid(
	    VIRTIO14_SPLIT_QUEUE_SIZE_MAX + 1));
	ATF_CHECK(!virtio_split_queue_size_valid(UINT32_MAX));
}

ATF_TC_WITHOUT_HEAD(packed_queue_contract);

static bool
packed_event_oracle(unsigned int num, unsigned int event,
    unsigned int old, unsigned int added)
{
	unsigned int i, position;

	position = old;
	for (i = 0; i < added; i++) {
		if (position == event)
			return (true);
		position = (position + 1) % (2 * num);
	}
	return (false);
}

ATF_TC_BODY(packed_queue_contract, tc)
{
	struct vring_packed_desc *desc;
	struct vring_packed_desc indirect;
	struct vring_packed_event *device_event, *driver_event;
	uint8_t storage[4 * VIRTIO14_PACKED_DESC_SIZE +
	    2 * VIRTIO14_PACKED_EVENT_SIZE];
	vm_paddr_t desc_paddr, device_paddr, driver_paddr;
	const vm_paddr_t base = UINT64_C(0x12345000);
	unsigned int added, event, new_position, num, old;
	uint16_t event_off_wrap, offset;
	bool expected, wrap;

	ATF_CHECK_EQ(sizeof(struct vring_packed_desc),
	    VIRTIO14_PACKED_DESC_SIZE);
	ATF_CHECK_EQ(offsetof(struct vring_packed_desc, addr),
	    VIRTIO14_PACKED_DESC_ADDR_OFF);
	ATF_CHECK_EQ(offsetof(struct vring_packed_desc, len),
	    VIRTIO14_PACKED_DESC_LEN_OFF);
	ATF_CHECK_EQ(offsetof(struct vring_packed_desc, id),
	    VIRTIO14_PACKED_DESC_ID_OFF);
	ATF_CHECK_EQ(offsetof(struct vring_packed_desc, flags),
	    VIRTIO14_PACKED_DESC_FLAGS_OFF);
	ATF_CHECK_EQ(sizeof(struct vring_packed_event),
	    VIRTIO14_PACKED_EVENT_SIZE);
	ATF_CHECK_EQ(offsetof(struct vring_packed_event, off_wrap),
	    VIRTIO14_PACKED_EVENT_OFF_WRAP_OFF);
	ATF_CHECK_EQ(offsetof(struct vring_packed_event, flags),
	    VIRTIO14_PACKED_EVENT_FLAGS_OFF);
	ATF_CHECK_EQ(VRING_PACKED_DESC_F_AVAIL,
	    VIRTIO14_PACKED_DESC_F_AVAIL);
	ATF_CHECK_EQ(VRING_PACKED_DESC_F_USED,
	    VIRTIO14_PACKED_DESC_F_USED);
	ATF_CHECK_EQ(VRING_PACKED_EVENT_FLAG_ENABLE,
	    VIRTIO14_PACKED_EVENT_F_ENABLE);
	ATF_CHECK_EQ(VRING_PACKED_EVENT_FLAG_DISABLE,
	    VIRTIO14_PACKED_EVENT_F_DISABLE);
	ATF_CHECK_EQ(VRING_PACKED_EVENT_FLAG_DESC,
	    VIRTIO14_PACKED_EVENT_F_DESC);
	ATF_CHECK_EQ(VRING_PACKED_EVENT_OFF_MASK,
	    VIRTIO14_PACKED_EVENT_OFFSET_MASK);
	ATF_CHECK_EQ(VRING_PACKED_EVENT_WRAP_CTR,
	    VIRTIO14_PACKED_EVENT_WRAP);
	ATF_CHECK_EQ(vring_packed_size(4), sizeof(storage));

	vring_packed_init(4, storage, base, &desc, &driver_event,
	    &device_event, &desc_paddr, &driver_paddr, &device_paddr);
	ATF_CHECK_EQ((void *)desc, (void *)&storage[0]);
	ATF_CHECK_EQ((void *)driver_event,
	    (void *)&storage[4 * VIRTIO14_PACKED_DESC_SIZE]);
	ATF_CHECK_EQ((void *)device_event,
	    (void *)&storage[4 * VIRTIO14_PACKED_DESC_SIZE +
	    VIRTIO14_PACKED_EVENT_SIZE]);
	ATF_CHECK_EQ(desc_paddr, base);
	ATF_CHECK_EQ(driver_paddr,
	    base + 4 * VIRTIO14_PACKED_DESC_SIZE);
	ATF_CHECK_EQ(device_paddr,
	    base + 4 * VIRTIO14_PACKED_DESC_SIZE +
	    VIRTIO14_PACKED_EVENT_SIZE);

	ATF_CHECK(!virtio_packed_queue_size_valid(0));
	ATF_CHECK(virtio_packed_queue_size_valid(1));
	ATF_CHECK(virtio_packed_queue_size_valid(3));
	ATF_CHECK(virtio_packed_queue_size_valid(
	    VIRTIO14_PACKED_QUEUE_SIZE_MAX));
	ATF_CHECK(!virtio_packed_queue_size_valid(
	    VIRTIO14_PACKED_QUEUE_SIZE_MAX + 1));
	ATF_CHECK(!virtio_packed_queue_size_valid(UINT32_MAX));
	/*
	 * Exhaust every cursor/event combination for small, including
	 * non-power-of-two, queue sizes.  The oracle walks the modulo-2N
	 * interval instead of repeating the production subtraction formula.
	 */
	for (num = 1; num <= 17; num++) {
		for (old = 0; old < 2 * num; old++) {
			for (added = 0; added <= num; added++) {
				offset = old % num;
				wrap = old >= num;
				ATF_REQUIRE(vring_packed_advance(num, &offset,
				    &wrap, added));
				new_position = (old + added) % (2 * num);
				ATF_REQUIRE_EQ(offset, new_position % num);
				ATF_REQUIRE_EQ(wrap,
				    new_position >= num);
				ATF_REQUIRE_EQ(vring_packed_off_wrap(offset,
				    wrap), (new_position % num) |
				    (new_position >= num ?
				    VIRTIO14_PACKED_EVENT_WRAP : 0));
				for (event = 0; event < 2 * num; event++) {
					event_off_wrap = (event % num) |
					    (event >= num ?
					    VIRTIO14_PACKED_EVENT_WRAP : 0);
					expected = packed_event_oracle(num,
					    event, old, added);
					ATF_REQUIRE_EQ(
					    vring_packed_need_event(num,
					    event_off_wrap, offset, wrap,
					    added), expected);
				}
			}
		}
	}
	offset = 0;
	wrap = true;
	ATF_CHECK(!vring_packed_advance(0, &offset, &wrap, 0));
	ATF_CHECK(!vring_packed_advance(4, &offset, &wrap, 5));
	offset = 4;
	ATF_CHECK(!vring_packed_advance(4, &offset, &wrap, 0));
	ATF_CHECK(vring_packed_need_event(4, 4, 0, true, 0));
	ATF_CHECK(vring_packed_need_event(4,
	    VIRTIO14_PACKED_EVENT_WRAP | 4, 0, true, 0));

	ATF_CHECK(vring_packed_desc_is_used(0, false));
	ATF_CHECK(!vring_packed_desc_is_used(0, true));
	ATF_CHECK(vring_packed_desc_is_used(
	    VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_USED, true));
	ATF_CHECK(!vring_packed_desc_is_used(
	    VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_USED, false));
	ATF_CHECK(!vring_packed_desc_is_used(
	    VIRTIO14_PACKED_DESC_F_AVAIL, false));
	ATF_CHECK(!vring_packed_desc_is_used(
	    VIRTIO14_PACKED_DESC_F_USED, true));
	/*
	 * Complete the ownership truth table: a descriptor with mismatched
	 * AVAIL/USED bits is owned by the driver regardless of the used wrap
	 * counter, so it must never read as device-used for either wrap phase.
	 */
	ATF_CHECK(!vring_packed_desc_is_used(
	    VIRTIO14_PACKED_DESC_F_AVAIL, true));
	ATF_CHECK(!vring_packed_desc_is_used(
	    VIRTIO14_PACKED_DESC_F_USED, false));
	ATF_CHECK_EQ(vring_packed_indirect_flags(false), 0);
	ATF_CHECK_EQ(vring_packed_indirect_flags(true),
	    VIRTIO14_PACKED_DESC_F_WRITE);
	ATF_CHECK_EQ(vring_packed_indirect_flags(true) &
	    (VIRTIO14_PACKED_DESC_F_NEXT |
	    VIRTIO14_PACKED_DESC_F_INDIRECT |
	    VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_USED), 0);

	/*
	 * A packed indirect element uses packed, not split, placement for id
	 * and flags even though both structures happen to be 16 bytes.
	 */
	memset(&indirect, 0xa5, sizeof(indirect));
	virtio14_store_le64((uint8_t *)&indirect.addr,
	    UINT64_C(0x1122334455667788));
	virtio14_store_le32((uint8_t *)&indirect.len,
	    UINT32_C(0x99aabbcc));
	virtio14_store_le16((uint8_t *)&indirect.id, 0);
	virtio14_store_le16((uint8_t *)&indirect.flags,
	    vring_packed_indirect_flags(true));
	ATF_CHECK_EQ(virtio14_load_le16(
	    (const uint8_t *)&indirect +
	    VIRTIO14_PACKED_DESC_ID_OFF), 0);
	ATF_CHECK_EQ(virtio14_load_le16(
	    (const uint8_t *)&indirect +
	    VIRTIO14_PACKED_DESC_FLAGS_OFF),
	    VIRTIO14_PACKED_DESC_F_WRITE);
}

ATF_TC_WITHOUT_HEAD(transport_feature_filter);
ATF_TC_BODY(transport_feature_filter, tc)
{
	const uint64_t requested = VIRTIO14_F_RING_INDIRECT_DESC |
	    VIRTIO14_F_RING_EVENT_IDX | VIRTIO14_F_VERSION_1 |
	    VIRTIO14_F_RING_PACKED |
	    VIRTIO14_F_NOTIFY_ON_EMPTY | VIRTIO14_F_ANY_LAYOUT |
	    VIRTIO14_F_RESERVED_25 | VIRTIO14_F_RESERVED_26 |
	    VIRTIO14_F_IN_ORDER | VIRTIO14_F_ORDER_PLATFORM |
	    VIRTIO14_F_NOTIFICATION_DATA | VIRTIO14_F_NOTIF_CONFIG_DATA |
	    VIRTIO14_F_RING_RESET | VIRTIO14_F_ADMIN_VQ |
	    VIRTIO14_NET_F_GUEST_RSC6 | VIRTIO14_F_SUSPEND |
	    VIRTIO14_F_RESERVED_44 | VIRTIO14_F_RESERVED_49 |
	    VIRTIO14_NET_F_MTU | VIRTIO14_DEVICE_FEATURE_HIGH_FIRST;
	const uint64_t legacy_neutral_expected =
	    VIRTIO14_F_NOTIFY_ON_EMPTY | VIRTIO14_F_ANY_LAYOUT |
	    VIRTIO14_F_RING_INDIRECT_DESC |
	    VIRTIO14_F_RING_EVENT_IDX | VIRTIO14_F_VERSION_1 |
	    VIRTIO14_F_RING_PACKED |
	    VIRTIO14_F_IN_ORDER | VIRTIO14_F_NOTIFICATION_DATA |
	    VIRTIO14_F_NOTIF_CONFIG_DATA |
	    VIRTIO14_F_RING_RESET | VIRTIO14_F_ADMIN_VQ |
	    VIRTIO14_NET_F_GUEST_RSC6 | VIRTIO14_F_SUSPEND |
	    VIRTIO14_NET_F_MTU |
	    VIRTIO14_DEVICE_FEATURE_HIGH_FIRST;
	const uint64_t modern_expected = legacy_neutral_expected &
	    ~(VIRTIO14_F_NOTIFY_ON_EMPTY | VIRTIO14_F_ANY_LAYOUT |
	    VIRTIO14_F_ADMIN_VQ | VIRTIO14_NET_F_GUEST_RSC6);

	/*
	 * These legacy-only assignments drive the transport policy below.
	 * Compare the public constants directly with the document oracle so a
	 * production renumbering cannot make the filtering test self-confirm.
	 */
	ATF_CHECK_EQ((uint64_t)VIRTIO_F_NOTIFY_ON_EMPTY,
	    VIRTIO14_F_NOTIFY_ON_EMPTY);
	ATF_CHECK_EQ((uint64_t)VIRTIO_F_ANY_LAYOUT,
	    VIRTIO14_F_ANY_LAYOUT);
	ATF_CHECK_EQ(virtio_supported_transport_features(requested),
	    legacy_neutral_expected);
	ATF_CHECK_EQ(virtio_modern_supported_transport_features(requested),
	    modern_expected);
	ATF_CHECK_EQ(virtio_mmio_supported_transport_features(
	    VIRTIO14_MMIO_MODERN_VERSION, requested),
	    modern_expected & ~VIRTIO14_F_NOTIF_CONFIG_DATA);
	ATF_CHECK_EQ(virtio_mmio_supported_transport_features(
	    VIRTIO14_MMIO_LEGACY_VERSION, requested),
	    legacy_neutral_expected &
	    ~(VIRTIO14_F_RING_RESET | VIRTIO14_F_SUSPEND |
	    VIRTIO14_F_NOTIF_CONFIG_DATA));
}

ATF_TC_WITHOUT_HEAD(suspend_status_predicates);
ATF_TC_BODY(suspend_status_predicates, tc)
{

	ATF_CHECK(virtio_device_suspend_complete(VIRTIO14_STATUS_SUSPEND));
	ATF_CHECK(virtio_device_suspend_complete(
	    VIRTIO14_STATUS_SUSPEND | VIRTIO14_STATUS_FEATURES_OK));
	ATF_CHECK(!virtio_device_suspend_complete(
	    VIRTIO14_STATUS_SUSPEND | VIRTIO14_STATUS_DRIVER_OK));
	ATF_CHECK(!virtio_device_suspend_complete(
	    VIRTIO14_STATUS_DRIVER_OK));
	ATF_CHECK(virtio_device_suspend_request_allowed(
	    VIRTIO14_STATUS_DRIVER_OK));
	ATF_CHECK(!virtio_device_suspend_request_allowed(0));
	ATF_CHECK(!virtio_device_suspend_request_allowed(
	    VIRTIO14_STATUS_DRIVER_OK | VIRTIO14_STATUS_DEVICE_NEEDS_RESET));
	ATF_CHECK(!virtio_device_suspend_request_allowed(
	    VIRTIO14_STATUS_DRIVER_OK | VIRTIO14_STATUS_FAILED));

	ATF_CHECK(virtio_device_resume_complete(
	    VIRTIO14_STATUS_DRIVER_OK));
	ATF_CHECK(virtio_device_resume_complete(
	    VIRTIO14_STATUS_DRIVER_OK | VIRTIO14_STATUS_FEATURES_OK));
	ATF_CHECK(!virtio_device_resume_complete(
	    VIRTIO14_STATUS_SUSPEND | VIRTIO14_STATUS_DRIVER_OK));
	ATF_CHECK(!virtio_device_resume_complete(
	    VIRTIO14_STATUS_SUSPEND));

	ATF_CHECK_EQ(virtio_device_lifecycle_state(
	    VIRTIO14_STATUS_DRIVER_OK), VIRTIO_DEVICE_LIFECYCLE_RUNNING);
	ATF_CHECK_EQ(virtio_device_lifecycle_state(
	    VIRTIO14_STATUS_SUSPEND), VIRTIO_DEVICE_LIFECYCLE_SUSPENDED);
	ATF_CHECK_EQ(virtio_device_lifecycle_state(
	    VIRTIO14_STATUS_SUSPEND | VIRTIO14_STATUS_DRIVER_OK),
	    VIRTIO_DEVICE_LIFECYCLE_TRANSITION);
	ATF_CHECK_EQ(virtio_device_lifecycle_state(0),
	    VIRTIO_DEVICE_LIFECYCLE_TRANSITION);
	ATF_CHECK_EQ(virtio_device_lifecycle_state(
	    VIRTIO14_STATUS_DRIVER_OK | VIRTIO14_STATUS_DEVICE_NEEDS_RESET),
	    VIRTIO_DEVICE_LIFECYCLE_FAILED);
	ATF_CHECK_EQ(virtio_device_lifecycle_state(
	    VIRTIO14_STATUS_SUSPEND | VIRTIO14_STATUS_FAILED),
	    VIRTIO_DEVICE_LIFECYCLE_FAILED);
}

ATF_TC_WITHOUT_HEAD(mmio_transport_policy);
ATF_TC_BODY(mmio_transport_policy, tc)
{
	const uint64_t child = VIRTIO14_NET_F_MTU;
	const uint64_t host = VIRTIO14_F_VERSION_1 |
	    VIRTIO14_F_RING_PACKED | VIRTIO14_F_NOTIFICATION_DATA |
	    VIRTIO14_F_SUSPEND | VIRTIO14_F_RING_RESET;
	const uint64_t modern_requested = child | VIRTIO14_F_VERSION_1 |
	    VIRTIO14_F_RING_PACKED | VIRTIO14_F_NOTIFICATION_DATA |
	    VIRTIO14_F_SUSPEND;

	/* RingReset remains a function-driver opt-in operation. */
	ATF_CHECK_EQ(virtio_mmio_requested_transport_features(
	    VIRTIO14_MMIO_MODERN_VERSION, child, host), modern_requested);
	ATF_CHECK_EQ(virtio_mmio_requested_transport_features(
	    VIRTIO14_MMIO_MODERN_VERSION, child, 0),
	    child | VIRTIO14_F_VERSION_1);
	ATF_CHECK_EQ(virtio_mmio_requested_transport_features(
	    VIRTIO14_MMIO_LEGACY_VERSION, child, host), child);

	/* Packed queues need not have the split ring's power-of-two size. */
	ATF_CHECK(!virtio_queue_size_valid(false, 3));
	ATF_CHECK(virtio_queue_size_valid(true, 3));
	ATF_CHECK(virtio_queue_size_valid(false, 32768));
	ATF_CHECK(virtio_queue_size_valid(true, 32768));
	ATF_CHECK(!virtio_queue_size_valid(false, 32769));
	ATF_CHECK(!virtio_queue_size_valid(true, 32769));
}

ATF_TC_WITHOUT_HEAD(device_config_ranges);
ATF_TC_BODY(device_config_ranges, tc)
{

	ATF_CHECK(virtio_config_range_valid(16, 0,
	    VIRTIO14_CONFIG_FIELD_U8_SIZE));
	ATF_CHECK(virtio_config_range_valid(16, 8,
	    VIRTIO14_CONFIG_FIELD_U64_SIZE));
	ATF_CHECK(virtio_config_range_valid(16, 16, 0));
	ATF_CHECK(!virtio_config_range_valid(0, 0, 1));
	ATF_CHECK(!virtio_config_range_valid(16, 16, 1));
	ATF_CHECK(!virtio_config_range_valid(16, 17, 0));
	ATF_CHECK(!virtio_config_range_valid(16, UINT64_MAX, 1));
	ATF_CHECK(!virtio_config_range_valid(UINT64_MAX, UINT64_MAX, 1));

	ATF_CHECK(virtio_modern_config_access_valid(16, 0,
	    VIRTIO14_CONFIG_FIELD_U8_SIZE));
	ATF_CHECK(virtio_modern_config_access_valid(16, 2,
	    VIRTIO14_CONFIG_FIELD_U16_SIZE));
	ATF_CHECK(virtio_modern_config_access_valid(16, 4,
	    VIRTIO14_CONFIG_FIELD_U32_SIZE));
	ATF_CHECK(virtio_modern_config_access_valid(16, 8,
	    VIRTIO14_CONFIG_FIELD_U64_SIZE));
	ATF_CHECK(!virtio_modern_config_access_valid(16, 1,
	    VIRTIO14_CONFIG_FIELD_U16_SIZE));
	ATF_CHECK(!virtio_modern_config_access_valid(16, 2,
	    VIRTIO14_CONFIG_FIELD_U32_SIZE));
	ATF_CHECK(!virtio_modern_config_access_valid(16, 2,
	    VIRTIO14_CONFIG_FIELD_U64_SIZE));
	ATF_CHECK(!virtio_modern_config_access_valid(16, 0, 3));
	ATF_CHECK(!virtio_modern_config_access_valid(16, 12,
	    VIRTIO14_CONFIG_FIELD_U64_SIZE));
}

ATF_TC_WITHOUT_HEAD(device_config_64bit_parts);
ATF_TC_BODY(device_config_64bit_parts, tc)
{
	const uint64_t value = UINT64_C(0x1122334455667788);
	uint8_t wire[8];
	uint32_t high, low;

	/*
	 * Inspect the bytes produced by the DUT with the independent wire
	 * decoder.  Decoding low and high with virtio_htog32() here would
	 * reuse the production endian primitive and let matching encode/decode
	 * defects self-confirm on a big-endian guest.
	 */
	virtio_config_write64_parts(true, value, &low, &high);
	ATF_CHECK_EQ(virtio14_load_le32((const uint8_t *)&low),
	    UINT32_C(0x55667788));
	ATF_CHECK_EQ(virtio14_load_le32((const uint8_t *)&high),
	    UINT32_C(0x11223344));
	ATF_CHECK_EQ(virtio_config_read64_parts(true, low, high), value);

	/*
	 * Feed the read helper independently assembled little-endian register
	 * values instead of feeding its paired write helper back to it.
	 */
	virtio14_store_le64(wire, value);
	memcpy(&low, &wire[0], sizeof(low));
	memcpy(&high, &wire[4], sizeof(high));
	ATF_CHECK_EQ(virtio_config_read64_parts(true, low, high), value);

	/* Legacy configuration halves remain in guest-native byte order. */
	virtio_config_write64_parts(false, value, &low, &high);
	ATF_CHECK_EQ(low, UINT32_C(0x55667788));
	ATF_CHECK_EQ(high, UINT32_C(0x11223344));
	ATF_CHECK_EQ(virtio_config_read64_parts(false, low, high), value);
}

ATF_TC_WITHOUT_HEAD(pci_capability_bar_ranges);
ATF_TC_BODY(pci_capability_bar_ranges, tc)
{

	ATF_CHECK(VIRTIO_PCI_CAP_BAR_VALID(VIRTIO14_PCI_MIN_BAR));
	ATF_CHECK(VIRTIO_PCI_CAP_BAR_VALID(VIRTIO14_PCI_MAX_BAR));
	ATF_CHECK(!VIRTIO_PCI_CAP_BAR_VALID(VIRTIO14_PCI_MAX_BAR + 1));
	ATF_CHECK(!VIRTIO_PCI_CAP_BAR_VALID(UINT8_MAX));
}

ATF_TC_WITHOUT_HEAD(pci_capability_resource_ranges);
ATF_TC_BODY(pci_capability_resource_ranges, tc)
{
	const uint64_t bar_size = UINT64_C(0x1000);

	ATF_CHECK(virtio_pci_cap_range_valid(bar_size, 0, 1, 1, 1));
	ATF_CHECK(virtio_pci_cap_range_valid(bar_size, 4, 0x20, 0x10, 4));
	ATF_CHECK(virtio_pci_cap_range_valid(bar_size, 0xff0, 0x10, 1, 4));

	/*
	 * cap.length is a byte count.  In particular, zero must not reach
	 * bus_map_resource(), where zero has the different meaning "map the
	 * entire resource".
	 */
	ATF_CHECK(!virtio_pci_cap_range_valid(bar_size, 0, 0, 0, 1));
	ATF_CHECK(!virtio_pci_cap_range_valid(bar_size, 0, 0xf, 0x10, 1));
	ATF_CHECK(!virtio_pci_cap_range_valid(bar_size, 2, 4, 1, 4));
	ATF_CHECK(!virtio_pci_cap_range_valid(bar_size, 0, 4, 1, 0));
	ATF_CHECK(!virtio_pci_cap_range_valid(bar_size, 0xfff, 2, 1, 1));
	ATF_CHECK(!virtio_pci_cap_range_valid(bar_size + 1, UINT32_MAX, 3,
	    1, 1));
}

ATF_TC_WITHOUT_HEAD(queue_reset_poll_deadline);
ATF_TC_BODY(queue_reset_poll_deadline, tc)
{

	/* Private host timing policy, deliberately independent of VirtIO fields. */
	ATF_CHECK_EQ(VIRTIO_RESET_POLL_DELAY_US, 1000U);
	ATF_CHECK_EQ(VIRTIO_QUEUE_RESET_TIMEOUT_US, 1000000U);
	ATF_CHECK_EQ(VIRTIO_QUEUE_RESET_POLLS, 1000U);
	ATF_CHECK_EQ(VIRTIO_QUEUE_RESET_PROBES, 1001U);
	ATF_CHECK(virtio_queue_reset_probe_should_delay(999U));
	ATF_CHECK(!virtio_queue_reset_probe_should_delay(1000U));
}

/*
 * Independent oracle for the split-ring event-idx suppression formula
 * (VirtIO 1.4 section 2.7.7.2).  A notification is required exactly when the
 * consumer-published event index lies in the half-open window of ring slots
 * [old, new_idx) that the producer has just made available.  The oracle walks
 * that window explicitly instead of reusing the production subtraction, so a
 * regression in vring_need_event's modular arithmetic cannot self-confirm.
 */
static bool
split_event_oracle(uint16_t event_idx, uint16_t new_idx, uint16_t old)
{
	uint16_t count, i, position;

	count = (uint16_t)(new_idx - old);
	position = old;
	for (i = 0; i < count; i++) {
		if (position == event_idx)
			return (true);
		position++;
	}
	return (false);
}

ATF_TC_WITHOUT_HEAD(split_event_idx_contract);
ATF_TC_BODY(split_event_idx_contract, tc)
{
	/*
	 * Anchor windows at the 16-bit wrap boundary, where an off-by-one or a
	 * signed comparison in the production formula would diverge from the
	 * oracle.  0x7fff/0x8000 also probe the point at which an accidental
	 * signed cast of the intermediate difference would flip.
	 */
	static const uint16_t bases[] = {
		0x0000, 0x0001, 0x7fff, 0x8000, 0xfff8, 0xffff
	};
	unsigned int b, added;
	int delta;
	uint16_t old, new_idx, event_idx;

	for (b = 0; b < sizeof(bases) / sizeof(bases[0]); b++) {
		old = bases[b];
		for (added = 0; added <= 64; added++) {
			new_idx = (uint16_t)(old + added);
			/* Sweep the event index across and beyond the window. */
			for (delta = -4; delta <= 68; delta++) {
				event_idx = (uint16_t)(old + delta);
				ATF_REQUIRE_EQ(
				    vring_need_event(event_idx, new_idx,
				    old) != 0,
				    split_event_oracle(event_idx, new_idx,
				    old));
			}
		}
	}

	/*
	 * Boundary anchors verified by hand: publishing zero new buffers must
	 * never request a notification, and a window that wraps the whole 16-bit
	 * index space still fires for an event index inside it.
	 */
	ATF_CHECK(!vring_need_event(5, 5, 5));
	ATF_CHECK(!vring_need_event(0, 0, 0));
	ATF_CHECK(!vring_need_event(0x1234, 0x1234, 0x1234));
	ATF_CHECK(vring_need_event(0, 3, 0));
	ATF_CHECK(vring_need_event(2, 3, 0));
	ATF_CHECK(!vring_need_event(3, 3, 0));
	ATF_CHECK(vring_need_event(0xffff, 0x0000, 0x0001));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, reinit_feature_ceiling);
	ATF_TP_ADD_TC(tp, split_event_idx_contract);
	ATF_TP_ADD_TC(tp, notification_write_width);
	ATF_TP_ADD_TC(tp, notification_feature_validation);
	ATF_TP_ADD_TC(tp, split_queue_size_limits);
	ATF_TP_ADD_TC(tp, packed_queue_contract);
	ATF_TP_ADD_TC(tp, transport_feature_filter);
	ATF_TP_ADD_TC(tp, suspend_status_predicates);
	ATF_TP_ADD_TC(tp, mmio_transport_policy);
	ATF_TP_ADD_TC(tp, device_config_ranges);
	ATF_TP_ADD_TC(tp, device_config_64bit_parts);
	ATF_TP_ADD_TC(tp, pci_capability_bar_ranges);
	ATF_TP_ADD_TC(tp, pci_capability_resource_ranges);
	ATF_TP_ADD_TC(tp, queue_reset_poll_deadline);
	ATF_TP_ADD_TC(tp, virtio_1_4_wire_constants);
	ATF_TP_ADD_TC(tp, scsi_event_used_length_contract);
	ATF_TP_ADD_TC(tp, scsi_response_bounds_contract);
	ATF_TP_ADD_TC(tp, console_control_used_length_contract);
	ATF_TP_ADD_TC(tp, vsock_used_length_contract);
	ATF_TP_ADD_TC(tp, random_used_length_contract);
	ATF_TP_ADD_TC(tp, balloon_statistics_wire_contract);
	ATF_TP_ADD_TC(tp, balloon_page_poison_wire_contract);
	ATF_TP_ADD_TC(tp, balloon_request_failure_contract);
	ATF_TP_ADD_TC(tp, balloon_lowmem_target_contract);
	ATF_TP_ADD_TC(tp, balloon_pfn_portability_contract);
	ATF_TP_ADD_TC(tp, gpu_wire_and_geometry_contract);
	ATF_TP_ADD_TC(tp, rtc_guest_wire_contract);
	ATF_TP_ADD_TC(tp, input_guest_wire_contract);
	ATF_TP_ADD_TC(tp, virtio_1_4_pci_layout);
	ATF_TP_ADD_TC(tp, virtio_1_4_mmio_layout);

	return (atf_no_error());
}
