/*
 * Independent VirtIO 1.4 section 5.19 protocol tests.
 */
#include <sys/endian.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include <dev/virtio/pmem/virtio_pmem.h>

#include "virtio_pmem_host.c"
#include "virtio_1_4_spec.h"

struct flush_state {
	unsigned int calls;
	int result;
};

ATF_TC_WITHOUT_HEAD(virtio_1_4_wire_layout);
ATF_TC_BODY(virtio_1_4_wire_layout, tc)
{

	ATF_CHECK_EQ(VIRTIO14_PMEM_DEVICE_ID, 27);
	ATF_CHECK_EQ(VIRTIO14_PMEM_F_SHMEM_REGION, 0);
	ATF_CHECK_EQ(VIRTIO14_PMEM_SHMEM_REGION_ID, 0);
	ATF_CHECK_EQ(VIRTIO14_PMEM_REQUESTQ, 0);
	ATF_CHECK_EQ(BHYVE_VIRTIO_PMEM_CONFIG_SIZE,
	    VIRTIO14_PMEM_CONFIG_SIZE);
	ATF_CHECK_EQ(BHYVE_VIRTIO_PMEM_REQUEST_SIZE,
	    VIRTIO14_PMEM_REQUEST_SIZE);
	ATF_CHECK_EQ(BHYVE_VIRTIO_PMEM_RESPONSE_SIZE,
	    VIRTIO14_PMEM_RESPONSE_SIZE);
	ATF_CHECK_EQ(VIRTIO_PMEM_F_SHMEM_REGION,
	    UINT64_C(1) << VIRTIO14_PMEM_F_SHMEM_REGION);
	ATF_CHECK_EQ(VIRTIO_PMEM_SHMEM_REGION_ID,
	    VIRTIO14_PMEM_SHMEM_REGION_ID);
	ATF_CHECK_EQ(VIRTIO_PMEM_REQ_TYPE_FLUSH,
	    VIRTIO14_PMEM_REQ_TYPE_FLUSH);
	ATF_CHECK_EQ(VIRTIO_PMEM_RESP_OK, VIRTIO14_PMEM_RET_SUCCESS);
	ATF_CHECK_EQ(VIRTIO_PMEM_RESP_ERR, VIRTIO14_PMEM_RET_FAILURE);
	ATF_CHECK_EQ(sizeof(struct virtio_pmem_config),
	    VIRTIO14_PMEM_CONFIG_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_pmem_req),
	    VIRTIO14_PMEM_REQUEST_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_pmem_resp),
	    VIRTIO14_PMEM_RESPONSE_SIZE);
}

static int
test_flush(void *arg)
{
	struct flush_state *state;

	state = arg;
	state->calls++;
	return (state->result);
}

ATF_TC_WITHOUT_HEAD(configuration_paths);
ATF_TC_BODY(configuration_paths, tc)
{
	uint8_t config[VIRTIO14_PMEM_CONFIG_SIZE], before[sizeof(config)];

	memset(config, 0xa5, sizeof(config));
	ATF_REQUIRE_EQ(virtio_pmem_config_encode(
	    UINT64_C(0x0102030405060708), UINT64_C(0x1112131415161718),
	    false, config, sizeof(config)), 0);
	ATF_CHECK_EQ(le64dec(config), UINT64_C(0x0102030405060708));
	ATF_CHECK_EQ(le64dec(config + 8), UINT64_C(0x1112131415161718));
	ATF_REQUIRE_EQ(virtio_pmem_config_encode(UINT64_MAX, 1, false,
	    config, sizeof(config)), 0);
	ATF_CHECK_EQ(le64dec(config), UINT64_MAX);
	ATF_CHECK_EQ(le64dec(config + 8), 1);

	memset(config, 0xa5, sizeof(config));
	ATF_REQUIRE_EQ(virtio_pmem_config_encode(UINT64_MAX, UINT64_MAX,
	    true, config, sizeof(config)), 0);
	for (size_t i = 0; i < sizeof(config); i++)
		ATF_CHECK_EQ(config[i], 0);

	memcpy(before, config, sizeof(before));
	ATF_CHECK_EQ(virtio_pmem_config_encode(UINT64_MAX, 2, false,
	    config, sizeof(config)), EINVAL);
	ATF_CHECK_EQ(memcmp(config, before, sizeof(config)), 0);
	ATF_CHECK_EQ(virtio_pmem_config_encode(0, 0, false, config,
	    sizeof(config)), EINVAL);
	ATF_CHECK_EQ(virtio_pmem_config_encode(0, 1, false, config,
	    sizeof(config) - 1), EINVAL);
}

ATF_TC_WITHOUT_HEAD(flush_result_is_literal);
ATF_TC_BODY(flush_result_is_literal, tc)
{
	static const uint8_t request[VIRTIO14_PMEM_REQUEST_SIZE] = { 0, 0, 0, 0 };
	struct flush_state state;
	uint8_t response[VIRTIO14_PMEM_RESPONSE_SIZE];
	size_t written;

	memset(&state, 0, sizeof(state));
	memset(response, 0xa5, sizeof(response));
	ATF_REQUIRE_EQ(virtio_pmem_process_request(request, sizeof(request),
	    response, sizeof(response), test_flush, &state, &written), 0);
	ATF_CHECK_EQ(written, sizeof(response));
	ATF_CHECK_EQ(le32dec(response), 0);
	ATF_CHECK_EQ(state.calls, 1);

	state.result = EIO;
	ATF_REQUIRE_EQ(virtio_pmem_process_request(request, sizeof(request),
	    response, sizeof(response), test_flush, &state, &written), 0);
	ATF_CHECK_EQ(le32dec(response), UINT32_MAX);
	ATF_CHECK_EQ(state.calls, 2);
}

ATF_TC_WITHOUT_HEAD(decode_and_response_helpers);
ATF_TC_BODY(decode_and_response_helpers, tc)
{
	uint8_t request[4] = { 0, 0, 0, 0 };
	uint8_t response[4];

	ATF_CHECK_EQ(virtio_pmem_request_decode(request, sizeof(request)), 0);
	request[0] = 1;
	ATF_CHECK_EQ(virtio_pmem_request_decode(request, sizeof(request)),
	    EINVAL);
	ATF_CHECK_EQ(virtio_pmem_request_decode(request, 3), EINVAL);
	ATF_REQUIRE_EQ(virtio_pmem_response_encode(0, response,
	    sizeof(response)), 0);
	ATF_CHECK_EQ(le32dec(response), 0);
	ATF_REQUIRE_EQ(virtio_pmem_response_encode(EIO, response,
	    sizeof(response)), 0);
	ATF_CHECK_EQ(le32dec(response), UINT32_MAX);
	ATF_CHECK_EQ(virtio_pmem_response_encode(0, response, 3), EINVAL);
}

ATF_TC_WITHOUT_HEAD(malformed_requests_are_bounded);
ATF_TC_BODY(malformed_requests_are_bounded, tc)
{
	uint8_t request[8], response[8], before[sizeof(response)];
	struct flush_state state;
	size_t written, written_before;

	memset(&state, 0, sizeof(state));
	memset(request, 0, sizeof(request));
	request[0] = 1;
	memset(response, 0xa5, sizeof(response));
	written = 0xa5;
	ATF_REQUIRE_EQ(virtio_pmem_process_request(request, sizeof(request),
	    response, sizeof(response), test_flush, &state, &written), 0);
	ATF_CHECK_EQ(written, VIRTIO14_PMEM_RESPONSE_SIZE);
	ATF_CHECK_EQ(le32dec(response), UINT32_MAX);
	ATF_CHECK_EQ(state.calls, 0);
	for (size_t i = VIRTIO14_PMEM_RESPONSE_SIZE; i < sizeof(response); i++)
		ATF_CHECK_EQ(response[i], 0xa5);

	memcpy(before, response, sizeof(before));
	written_before = written;
	ATF_CHECK_EQ(virtio_pmem_process_request(request, 3, response,
	    sizeof(response), test_flush, &state, &written), EINVAL);
	ATF_CHECK_EQ(memcmp(response, before, sizeof(response)), 0);
	ATF_CHECK_EQ(written, written_before);
	ATF_CHECK_EQ(virtio_pmem_process_request(request, sizeof(request),
	    response, 3, test_flush, &state, &written), EINVAL);
	ATF_CHECK_EQ(state.calls, 0);
}

ATF_TC_WITHOUT_HEAD(aliasing_is_rejected_transactionally);
ATF_TC_BODY(aliasing_is_rejected_transactionally, tc)
{
	struct flush_state state;
	uint8_t storage[16], before[sizeof(storage)];
	size_t written;

	memset(&state, 0, sizeof(state));
	memset(storage, 0, sizeof(storage));
	memcpy(before, storage, sizeof(before));
	written = 7;
	ATF_CHECK_EQ(virtio_pmem_process_request(storage, 4, storage, 4,
	    test_flush, &state, &written), EINVAL);
	ATF_CHECK_EQ(memcmp(storage, before, sizeof(storage)), 0);
	ATF_CHECK_EQ(written, 7);
	ATF_CHECK_EQ(state.calls, 0);

	ATF_CHECK_EQ(virtio_pmem_process_request(storage, 4, storage + 8, 4,
	    test_flush, &state, (size_t *)(void *)storage), EINVAL);
	ATF_CHECK_EQ(memcmp(storage, before, sizeof(storage)), 0);
	ATF_CHECK_EQ(state.calls, 0);
}

ATF_TC_WITHOUT_HEAD(exclusive_file_backing_is_durable);
ATF_TC_BODY(exclusive_file_backing_is_durable, tc)
{
	struct virtio_pmem_backing backing, competing;
	char path[] = "/tmp/virtio-pmem.XXXXXX";
	uint8_t check[4];
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(ftruncate(fd, 4096), 0);
	ATF_REQUIRE_EQ(close(fd), 0);

	virtio_pmem_backing_init(&backing);
	virtio_pmem_backing_init(&competing);
	ATF_REQUIRE_EQ(virtio_pmem_backing_open(&backing, path), 0);
	ATF_CHECK_EQ(backing.size, 4096);
	ATF_CHECK_EQ(virtio_pmem_backing_open(&competing, path), EWOULDBLOCK);
	memcpy(backing.mapping, "pmem", sizeof(check));
	ATF_REQUIRE_EQ(virtio_pmem_backing_flush(&backing), 0);

	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(pread(fd, check, sizeof(check), 0), sizeof(check));
	ATF_CHECK_EQ(memcmp(check, "pmem", sizeof(check)), 0);
	ATF_REQUIRE_EQ(close(fd), 0);

	virtio_pmem_backing_close(&backing);
	ATF_CHECK_EQ(backing.fd, -1);
	ATF_CHECK(backing.mapping == NULL);
	ATF_CHECK_EQ(backing.size, 0);
	ATF_REQUIRE_EQ(unlink(path), 0);
}

ATF_TC_WITHOUT_HEAD(file_backing_rejects_identity_changes);
ATF_TC_BODY(file_backing_rejects_identity_changes, tc)
{
	struct virtio_pmem_backing backing;
	char empty[] = "/tmp/virtio-pmem-empty.XXXXXX";
	char path[] = "/tmp/virtio-pmem-size.XXXXXX";
	int fd;

	virtio_pmem_backing_init(&backing);
	fd = mkstemp(empty);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(close(fd), 0);
	ATF_CHECK_EQ(virtio_pmem_backing_open(&backing, empty), EINVAL);
	ATF_REQUIRE_EQ(unlink(empty), 0);

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(ftruncate(fd, 4096), 0);
	ATF_REQUIRE_EQ(close(fd), 0);
	ATF_REQUIRE_EQ(virtio_pmem_backing_open(&backing, path), 0);
	ATF_REQUIRE_EQ(truncate(path, 8192), 0);
	ATF_CHECK_EQ(virtio_pmem_backing_flush(&backing), EINVAL);
	virtio_pmem_backing_close(&backing);
	ATF_REQUIRE_EQ(unlink(path), 0);
}

ATF_TC_WITHOUT_HEAD(file_backing_services_flush_request);
ATF_TC_BODY(file_backing_services_flush_request, tc)
{
	static const uint8_t request[VIRTIO14_PMEM_REQUEST_SIZE] = { 0, 0, 0, 0 };
	struct virtio_pmem_backing backing;
	char path[] = "/tmp/virtio-pmem-request.XXXXXX";
	uint8_t response[VIRTIO14_PMEM_RESPONSE_SIZE];
	size_t written;
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(ftruncate(fd, 4096), 0);
	ATF_REQUIRE_EQ(close(fd), 0);
	virtio_pmem_backing_init(&backing);
	ATF_REQUIRE_EQ(virtio_pmem_backing_open(&backing, path), 0);
	memcpy(backing.mapping, "data", 4);
	ATF_REQUIRE_EQ(virtio_pmem_process_request(request, sizeof(request),
	    response, sizeof(response), virtio_pmem_backing_flush, &backing,
	    &written), 0);
	ATF_CHECK_EQ(written, sizeof(response));
	ATF_CHECK_EQ(le32dec(response), VIRTIO14_PMEM_RET_SUCCESS);

	ATF_REQUIRE_EQ(truncate(path, 8192), 0);
	ATF_REQUIRE_EQ(virtio_pmem_process_request(request, sizeof(request),
	    response, sizeof(response), virtio_pmem_backing_flush, &backing,
	    &written), 0);
	ATF_CHECK_EQ(written, sizeof(response));
	ATF_CHECK_EQ(le32dec(response), VIRTIO14_PMEM_RET_FAILURE);
	virtio_pmem_backing_close(&backing);
	ATF_REQUIRE_EQ(unlink(path), 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, virtio_1_4_wire_layout);
	ATF_TP_ADD_TC(tp, configuration_paths);
	ATF_TP_ADD_TC(tp, flush_result_is_literal);
	ATF_TP_ADD_TC(tp, decode_and_response_helpers);
	ATF_TP_ADD_TC(tp, malformed_requests_are_bounded);
	ATF_TP_ADD_TC(tp, aliasing_is_rejected_transactionally);
	ATF_TP_ADD_TC(tp, exclusive_file_backing_is_durable);
	ATF_TP_ADD_TC(tp, file_backing_rejects_identity_changes);
	ATF_TP_ADD_TC(tp, file_backing_services_flush_request);
	return (atf_no_error());
}
