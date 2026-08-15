/*
 * Independent VirtIO 1.4 section 5.13 configuration-layout tests.
 */
#include <sys/endian.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_iommu_state.c"
#include "virtio_iommu_config.c"

#define	DOC_F_INPUT_RANGE	(1ULL << 0)
#define	DOC_F_DOMAIN_RANGE	(1ULL << 1)
#define	DOC_F_PROBE		(1ULL << 4)
#define	DOC_F_BYPASS_CONFIG	(1ULL << 6)

static void *
config_map_gpa(void *arg __unused, uint64_t address __unused,
    size_t length __unused, enum virtio_dma_direction direction __unused)
{

	return (NULL);
}

static struct virtio_iommu_state *
config_state(bool bypass)
{
	struct virtio_iommu_limits limits;
	struct virtio_iommu_ops ops;
	struct virtio_iommu_state *state;

	limits = (struct virtio_iommu_limits) {
		.page_size_mask = UINT64_C(1) << 12,
		.input_start = 0,
		.input_end = UINT32_MAX,
		.domain_start = 0,
		.domain_end = UINT32_MAX,
		.max_domains = 1,
		.max_endpoints = 1,
		.max_mappings = 1,
		.max_faults = 1,
		.default_bypass = bypass,
	};
	ops = (struct virtio_iommu_ops) {
		.map_gpa = config_map_gpa,
	};
	ATF_REQUIRE_EQ(virtio_iommu_state_create(&limits, &ops, &state), 0);
	return (state);
}

ATF_TC_WITHOUT_HEAD(literal_layout);
ATF_TC_BODY(literal_layout, tc)
{
	const struct virtio_iommu_config_values values = {
		.page_size_mask = UINT64_C(0x1000),
		.input_start = UINT64_C(0x1122334455667788),
		.input_end = UINT64_C(0x99aabbccddeeff00),
		.domain_start = UINT32_C(0x10203040),
		.domain_end = UINT32_C(0x50607080),
		.probe_size = UINT32_C(0x90a0b0c0),
	};
	uint8_t output[40];
	uint64_t features;

	features = DOC_F_INPUT_RANGE | DOC_F_DOMAIN_RANGE | DOC_F_PROBE |
	    DOC_F_BYPASS_CONFIG;
	memset(output, 0xa5, sizeof(output));
	ATF_REQUIRE_EQ(virtio_iommu_config_encode(&values, features, true,
	    output), 0);
	ATF_CHECK_EQ(le64dec(output + 0), UINT64_C(0x1000));
	ATF_CHECK_EQ(le64dec(output + 8), values.input_start);
	ATF_CHECK_EQ(le64dec(output + 16), values.input_end);
	ATF_CHECK_EQ(le32dec(output + 24), values.domain_start);
	ATF_CHECK_EQ(le32dec(output + 28), values.domain_end);
	ATF_CHECK_EQ(le32dec(output + 32), values.probe_size);
	ATF_CHECK_EQ(output[36], 1);
	ATF_CHECK_EQ(output[37], 0);
	ATF_CHECK_EQ(output[38], 0);
	ATF_CHECK_EQ(output[39], 0);
}

ATF_TC_WITHOUT_HEAD(unoffered_fields_are_zero);
ATF_TC_BODY(unoffered_fields_are_zero, tc)
{
	const struct virtio_iommu_config_values values = {
		.page_size_mask = UINT64_C(0x1000),
		.input_start = 1,
		.input_end = 2,
		.domain_start = 3,
		.domain_end = 4,
		.probe_size = 5,
	};
	uint8_t output[40];
	size_t i;

	memset(output, 0xa5, sizeof(output));
	ATF_REQUIRE_EQ(virtio_iommu_config_encode(&values, 0, false,
	    output), 0);
	ATF_CHECK_EQ(le64dec(output), UINT64_C(0x1000));
	for (i = 8; i < sizeof(output); i++)
		ATF_CHECK_EQ(output[i], 0);
	ATF_CHECK_EQ(virtio_iommu_config_encode(&values, 0, true, output),
	    EINVAL);
}

ATF_TC_WITHOUT_HEAD(bypass_write_contract);
ATF_TC_BODY(bypass_write_contract, tc)
{
	struct virtio_iommu_state *state;

	state = config_state(false);
	ATF_CHECK(!virtio_iommu_default_bypass(state));
	ATF_REQUIRE_EQ(virtio_iommu_config_write(state,
	    DOC_F_BYPASS_CONFIG, 36, 1, 1), 0);
	ATF_CHECK(virtio_iommu_default_bypass(state));
	/*
	 * Reset must restore the power-on (boot) bypass value, not preserve a
	 * guest-written one: leaving default_bypass=1 after reset would let
	 * every detached endpoint DMA the whole guest as identity-mapped,
	 * defeating the isolation a freshly reset IOMMU must provide.
	 */
	virtio_iommu_state_reset(state);
	ATF_CHECK(!virtio_iommu_default_bypass(state));
	/* Re-arm bypass to prove invalid writes cannot change it. */
	ATF_REQUIRE_EQ(virtio_iommu_config_write(state,
	    DOC_F_BYPASS_CONFIG, 36, 1, 1), 0);
	ATF_CHECK(virtio_iommu_default_bypass(state));
	ATF_CHECK_EQ(virtio_iommu_config_write(state, 0, 36, 1, 0),
	    EINVAL);
	ATF_CHECK_EQ(virtio_iommu_config_write(state,
	    DOC_F_BYPASS_CONFIG, 35, 1, 0), EINVAL);
	ATF_CHECK_EQ(virtio_iommu_config_write(state,
	    DOC_F_BYPASS_CONFIG, 36, 2, 0), EINVAL);
	ATF_CHECK_EQ(virtio_iommu_config_write(state,
	    DOC_F_BYPASS_CONFIG, 36, 1, 2), EINVAL);
	ATF_CHECK(virtio_iommu_default_bypass(state));
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(argument_validation);
ATF_TC_BODY(argument_validation, tc)
{
	struct virtio_iommu_config_values values;
	uint8_t output[40];

	memset(&values, 0, sizeof(values));
	values.page_size_mask = UINT64_C(0x1000);
	values.input_end = 1;
	values.domain_end = 1;
	ATF_CHECK_EQ(virtio_iommu_config_encode(NULL, 0, false, output),
	    EINVAL);
	ATF_CHECK_EQ(virtio_iommu_config_encode(&values, 0, false, NULL),
	    EINVAL);
	values.page_size_mask = 0;
	ATF_CHECK_EQ(virtio_iommu_config_encode(&values, 0, false, output),
	    EINVAL);
	values.page_size_mask = UINT64_C(0x1000);
	values.input_start = 2;
	ATF_CHECK_EQ(virtio_iommu_config_encode(&values, 0, false, output),
	    EINVAL);
	values.input_start = 0;
	values.domain_start = 2;
	ATF_CHECK_EQ(virtio_iommu_config_encode(&values, 0, false, output),
	    EINVAL);
	ATF_CHECK_EQ(virtio_iommu_config_write(NULL,
	    DOC_F_BYPASS_CONFIG, 36, 1, 0), EINVAL);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, literal_layout);
	ATF_TP_ADD_TC(tp, unoffered_fields_are_zero);
	ATF_TP_ADD_TC(tp, bypass_write_contract);
	ATF_TP_ADD_TC(tp, argument_validation);
	return (atf_no_error());
}
