/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <atf-c.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "checkpoint_topology.c"

ATF_TC_WITHOUT_HEAD(exact_named_device_set);
ATF_TC_BODY(exact_named_device_set, tc)
{
	const char *source[] = { "hostbridge", "virtio-net0", "atkbdc" };
	const char *reordered[] = { "atkbdc", "hostbridge", "virtio-net0" };
	const char *missing[] = { "hostbridge", "virtio-net0" };
	const char *changed[] = { "hostbridge", "virtio-block0", "atkbdc" };
	const char *extra[] = {
		"hostbridge", "virtio-net0", "atkbdc", "virtio-rng0"
	};

	ATF_CHECK_EQ(checkpoint_topology_validate(source, 3, reordered, 3), 0);
	ATF_CHECK_EQ(checkpoint_topology_validate(source, 3, missing, 2),
	    ENODEV);
	ATF_CHECK_EQ(checkpoint_topology_validate(source, 3, changed, 3),
	    ENODEV);
	ATF_CHECK_EQ(checkpoint_topology_validate(source, 3, extra, 4),
	    ENODEV);
}

ATF_TC_WITHOUT_HEAD(rejects_ambiguous_or_invalid_names);
ATF_TC_BODY(rejects_ambiguous_or_invalid_names, tc)
{
	const char *valid[] = { "hostbridge", "virtio-net0" };
	const char *duplicate[] = { "hostbridge", "hostbridge" };
	const char *empty[] = { "hostbridge", "" };
	const char *null_name[] = { "hostbridge", NULL };

	ATF_CHECK_EQ(checkpoint_topology_validate(duplicate, 2, valid, 2),
	    EEXIST);
	ATF_CHECK_EQ(checkpoint_topology_validate(valid, 2, duplicate, 2),
	    EEXIST);
	ATF_CHECK_EQ(checkpoint_topology_validate(empty, 2, valid, 2), EINVAL);
	ATF_CHECK_EQ(checkpoint_topology_validate(null_name, 2, valid, 2),
	    EINVAL);
	ATF_CHECK_EQ(checkpoint_topology_validate(NULL, 1, valid, 2), EINVAL);
	ATF_CHECK_EQ(checkpoint_topology_validate(NULL, 0, NULL, 0), 0);
}

ATF_TC_WITHOUT_HEAD(exact_record_partition);
ATF_TC_BODY(exact_record_partition, tc)
{
	const struct checkpoint_record_range ordered[] = {
		{ .offset = 0, .length = 16 },
		{ .offset = 16, .length = 32 },
		{ .offset = 48, .length = 8 },
	};
	const struct checkpoint_record_range reordered[] = {
		{ .offset = 48, .length = 8 },
		{ .offset = 0, .length = 16 },
		{ .offset = 16, .length = 32 },
	};
	const struct checkpoint_record_range overlap[] = {
		{ .offset = 0, .length = 32 },
		{ .offset = 16, .length = 40 },
	};
	const struct checkpoint_record_range gap[] = {
		{ .offset = 0, .length = 16 },
		{ .offset = 17, .length = 39 },
	};
	const struct checkpoint_record_range zero[] = {
		{ .offset = 0, .length = 0 },
	};
	const struct checkpoint_record_range overflow[] = {
		{ .offset = UINT64_MAX - 1, .length = 4 },
	};

	ATF_CHECK_EQ(checkpoint_record_layout_validate(ordered, 3, 56), 0);
	ATF_CHECK_EQ(checkpoint_record_layout_validate(reordered, 3, 56), 0);
	ATF_CHECK_EQ(checkpoint_record_layout_validate(overlap, 2, 56), EINVAL);
	ATF_CHECK_EQ(checkpoint_record_layout_validate(gap, 2, 56), EINVAL);
	ATF_CHECK_EQ(checkpoint_record_layout_validate(zero, 1, 1), EINVAL);
	ATF_CHECK_EQ(checkpoint_record_layout_validate(ordered, 3, 57), EINVAL);
	ATF_CHECK_EQ(checkpoint_record_layout_validate(ordered, 3, 2), EINVAL);
	ATF_CHECK_EQ(checkpoint_record_layout_validate(overflow, 1,
	    UINT64_MAX), EINVAL);
	ATF_CHECK_EQ(checkpoint_record_layout_validate(NULL, 0, 0), 0);
	ATF_CHECK_EQ(checkpoint_record_layout_validate(NULL, 0, 1), EINVAL);
	ATF_CHECK_EQ(checkpoint_record_layout_validate(NULL, 1, 1), EINVAL);
}

ATF_TC_WITHOUT_HEAD(exact_record_consumption);

ATF_TC_WITHOUT_HEAD(large_unordered_record_partition);
ATF_TC_BODY(large_unordered_record_partition, tc)
{
	const size_t count = 32768;
	struct checkpoint_record_range *ranges;

	(void)tc;
	ranges = calloc(count, sizeof(*ranges));
	ATF_REQUIRE(ranges != NULL);
	for (size_t i = 0; i < count; i++) {
		ranges[i].offset = count - i - 1;
		ranges[i].length = 1;
	}
	ATF_CHECK_EQ(checkpoint_record_layout_validate(ranges, count,
	    count), 0);
	/* Validation must not reorder the caller's metadata. */
	ATF_CHECK_EQ(ranges[0].offset, count - 1);
	ATF_CHECK_EQ(ranges[count - 1].offset, 0);
	ranges[count / 2].offset = count;
	ATF_CHECK_EQ(checkpoint_record_layout_validate(ranges, count,
	    count), EINVAL);
	free(ranges);
}

ATF_TC_BODY(exact_record_consumption, tc)
{

	ATF_CHECK_EQ(checkpoint_record_consumption_validate(0, 0), 0);
	ATF_CHECK_EQ(checkpoint_record_consumption_validate(1, 0), 0);
	ATF_CHECK_EQ(checkpoint_record_consumption_validate(SIZE_MAX, 0), 0);
	ATF_CHECK_EQ(checkpoint_record_consumption_validate(1, 1), EINVAL);
	ATF_CHECK_EQ(checkpoint_record_consumption_validate(8, 3), EINVAL);
	ATF_CHECK_EQ(checkpoint_record_consumption_validate(0, 1), EINVAL);
	ATF_CHECK_EQ(checkpoint_record_consumption_validate(7, 8), EINVAL);
}

ATF_TC_WITHOUT_HEAD(cpu_topology_product_and_bounds);
ATF_TC_BODY(cpu_topology_product_and_bounds, tc)
{

	ATF_CHECK_EQ(checkpoint_cpu_topology_validate(8, 2, 2, 2), 0);
	ATF_CHECK_EQ(checkpoint_cpu_topology_validate(8, 1, 4, 2), 0);
	ATF_CHECK_EQ(checkpoint_cpu_topology_validate(7, 2, 2, 2), EINVAL);
	ATF_CHECK_EQ(checkpoint_cpu_topology_validate(0, 1, 1, 1), EINVAL);
	ATF_CHECK_EQ(checkpoint_cpu_topology_validate(1, 0, 1, 1), EINVAL);
	ATF_CHECK_EQ(checkpoint_cpu_topology_validate(1, 1, 0, 1), EINVAL);
	ATF_CHECK_EQ(checkpoint_cpu_topology_validate(1, 1, 1, 0), EINVAL);
	ATF_CHECK_EQ(checkpoint_cpu_topology_validate(UINT16_MAX + 1ULL,
	    1, 1, 1), EINVAL);
	ATF_CHECK_EQ(checkpoint_cpu_topology_validate(1,
	    UINT16_MAX + 1ULL, 1, 1), EINVAL);
	ATF_CHECK_EQ(checkpoint_cpu_topology_validate(1, 1,
	    UINT16_MAX + 1ULL, 1), EINVAL);
	ATF_CHECK_EQ(checkpoint_cpu_topology_validate(1, 1, 1,
	    UINT16_MAX + 1ULL), EINVAL);
}

ATF_TC_WITHOUT_HEAD(numa_topology_is_an_exact_partition);
ATF_TC_BODY(numa_topology_is_an_exact_partition, tc)
{
	/* Two domains (3 GiB, 1 GiB); vCPUs 0 and 2 in domain 0, 1 and 3 in 1. */
	const uint64_t sizes[] = { 3ULL << 30, 1ULL << 30 };
	const uint16_t mapping[] = { 0, 1, 0, 1 };
	const uint16_t outside[] = { 0, 1, 0, 2 };
	const uint16_t unpopulated[] = { 0, 0, 0, 0 };
	uint64_t changed[nitems(sizes)];

	/* Private checkpoint-format policy, not a guest architecture cap. */
	ATF_REQUIRE_EQ(CHECKPOINT_NUMA_MAX_DOMAINS, 8);
	ATF_REQUIRE_EQ(checkpoint_numa_mapping_validate(sizes, nitems(sizes),
	    mapping, nitems(mapping), 4ULL << 30), 0);

	/* Every vCPU names an existing domain and every domain has a vCPU. */
	ATF_CHECK_EQ(checkpoint_numa_mapping_validate(sizes, nitems(sizes),
	    outside, nitems(outside), 4ULL << 30), EINVAL);
	ATF_CHECK_EQ(checkpoint_numa_mapping_validate(sizes, nitems(sizes),
	    unpopulated, nitems(unpopulated), 4ULL << 30), EINVAL);

	/* Domain memory covers guest memory exactly, without overflow. */
	memcpy(changed, sizes, sizeof(changed));
	changed[1]--;
	ATF_CHECK_EQ(checkpoint_numa_mapping_validate(changed,
	    nitems(changed), mapping, nitems(mapping), 4ULL << 30), ERANGE);
	changed[0] = UINT64_MAX;
	ATF_CHECK_EQ(checkpoint_numa_mapping_validate(changed,
	    nitems(changed), mapping, nitems(mapping), 4ULL << 30), EINVAL);
	memcpy(changed, sizes, sizeof(changed));
	changed[0] = 0;
	ATF_CHECK_EQ(checkpoint_numa_mapping_validate(changed,
	    nitems(changed), mapping, nitems(mapping), 4ULL << 30), EINVAL);

	ATF_CHECK_EQ(checkpoint_numa_mapping_validate(NULL, 1, mapping,
	    nitems(mapping), 4ULL << 30), EINVAL);
	ATF_CHECK_EQ(checkpoint_numa_mapping_validate(sizes, 0, mapping,
	    nitems(mapping), 4ULL << 30), EINVAL);
	ATF_CHECK_EQ(checkpoint_numa_mapping_validate(sizes,
	    CHECKPOINT_NUMA_MAX_DOMAINS + 1, mapping, nitems(mapping),
	    4ULL << 30), EINVAL);
	ATF_CHECK_EQ(checkpoint_numa_mapping_validate(sizes, nitems(sizes),
	    NULL, nitems(mapping), 4ULL << 30), EINVAL);
	ATF_CHECK_EQ(checkpoint_numa_mapping_validate(sizes, nitems(sizes),
	    mapping, 0, 4ULL << 30), EINVAL);
	ATF_CHECK_EQ(checkpoint_numa_mapping_validate(sizes, nitems(sizes),
	    mapping, UINT16_MAX + 1, 4ULL << 30), EINVAL);
	ATF_CHECK_EQ(checkpoint_numa_mapping_validate(sizes, nitems(sizes),
	    mapping, nitems(mapping), 0), EINVAL);
}

ATF_TC_WITHOUT_HEAD(memory_geometry_is_exact_and_portable);
ATF_TC_BODY(memory_geometry_is_exact_and_portable, tc)
{
	const struct checkpoint_memory_geometry split = {
		.page_size = 4096,
		.lowmem_size = 3ULL << 30,
		.highmem_base = 4ULL << 30,
		.highmem_size = 1ULL << 30,
	};
	struct checkpoint_memory_geometry changed;

	ATF_REQUIRE_EQ(checkpoint_memory_geometry_validate(&split,
	    4ULL << 30), 0);
	ATF_CHECK_EQ(checkpoint_memory_geometry_match(&split, &split,
	    4ULL << 30), 0);

	changed = split;
	changed.highmem_base = 5ULL << 30;
	ATF_CHECK_EQ(checkpoint_memory_geometry_match(&split, &changed,
	    4ULL << 30), EXDEV);
	changed = split;
	changed.page_size = 8192;
	ATF_CHECK_EQ(checkpoint_memory_geometry_match(&split, &changed,
	    4ULL << 30), EXDEV);
	changed = split;
	changed.highmem_size -= 4096;
	ATF_CHECK_EQ(checkpoint_memory_geometry_validate(&changed,
	    4ULL << 30), ERANGE);
	changed = split;
	changed.lowmem_size++;
	ATF_CHECK_EQ(checkpoint_memory_geometry_validate(&changed,
	    4ULL << 30), EINVAL);
	changed = split;
	changed.page_size = 3072;
	ATF_CHECK_EQ(checkpoint_memory_geometry_validate(&changed,
	    4ULL << 30), EINVAL);
	changed = split;
	changed.highmem_base = 2ULL << 30;
	ATF_CHECK_EQ(checkpoint_memory_geometry_validate(&changed,
	    4ULL << 30), EINVAL);
	changed = split;
	changed.highmem_base = UINT64_MAX - 4095;
	ATF_CHECK_EQ(checkpoint_memory_geometry_validate(&changed,
	    4ULL << 30), EINVAL);
	ATF_CHECK_EQ(checkpoint_memory_geometry_validate(NULL, 4ULL << 30),
	    EINVAL);
	ATF_CHECK_EQ(checkpoint_memory_geometry_validate(&split, 0), EINVAL);
}

/*
 * A refused restore names the device: the counts and the first unmatched
 * device on a cardinality mismatch, or the absent name when counts agree.
 */
ATF_TC_WITHOUT_HEAD(restore_mismatch_names_the_device);
ATF_TC_BODY(restore_mismatch_names_the_device, tc)
{
	const char *source[] = {
		"hostbridge@pci.0.0.0", "virtio-net@pci.0.2.0", "atkbdc"
	};
	const char *reordered[] = {
		"atkbdc", "hostbridge@pci.0.0.0", "virtio-net@pci.0.2.0"
	};
	const char *missing[] = { "hostbridge@pci.0.0.0", "atkbdc" };
	const char *changed[] = {
		"hostbridge@pci.0.0.0", "virtio-net@pci.0.3.0", "atkbdc"
	};
	const char *extra[] = {
		"hostbridge@pci.0.0.0", "virtio-net@pci.0.2.0", "atkbdc",
		"virtio-rnd@pci.0.4.0"
	};
	const char *duplicate[] = {
		"hostbridge@pci.0.0.0", "hostbridge@pci.0.0.0", "atkbdc"
	};
	char buf[256];

	ATF_CHECK_EQ(checkpoint_topology_describe_mismatch(source, 3, 3,
	    reordered, 3, buf, sizeof(buf)), 0);
	ATF_CHECK_STREQ(buf, "");

	/* Source has a device the destination lacks. */
	ATF_CHECK_EQ(checkpoint_topology_describe_mismatch(source, 3, 3,
	    missing, 2, buf, sizeof(buf)), ENODEV);
	ATF_CHECK_STREQ(buf, "device count: source 3, destination 2; source "
	    "device \"virtio-net@pci.0.2.0\" (entry 1) is absent at the "
	    "destination");

	/* Same count, device moved to another slot. */
	ATF_CHECK_EQ(checkpoint_topology_describe_mismatch(source, 3, 3,
	    changed, 3, buf, sizeof(buf)), ENODEV);
	ATF_CHECK_STREQ(buf, "source device \"virtio-net@pci.0.2.0\" "
	    "(entry 1) is absent at the destination");

	/* Destination has a device the checkpoint lacks. */
	ATF_CHECK_EQ(checkpoint_topology_describe_mismatch(source, 3, 3,
	    extra, 4, buf, sizeof(buf)), ENODEV);
	ATF_CHECK_STREQ(buf, "device count: source 3, destination 4; "
	    "destination device \"virtio-rnd@pci.0.4.0\" is absent from the "
	    "checkpoint");

	/*
	 * A caller bounds allocation to destination_count + 1 source names;
	 * that prefix still names the difference.  Here 3 of 1000 entries
	 * are seen against a 2-device destination.
	 */
	ATF_CHECK_EQ(checkpoint_topology_describe_mismatch(source, 3, 1000,
	    missing, 2, buf, sizeof(buf)), ENODEV);
	ATF_CHECK(strstr(buf, "device count: source 1000, destination 2; ") ==
	    buf);
	ATF_CHECK(strstr(buf, "\"virtio-net@pci.0.2.0\"") != NULL);
	ATF_CHECK_EQ(checkpoint_topology_describe_mismatch(duplicate, 3, 3,
	    source, 3, buf, sizeof(buf)), EEXIST);
	ATF_CHECK_STREQ(buf, "source device \"hostbridge@pci.0.0.0\" is "
	    "recorded more than once");

	/* Truncation is safe. */
	ATF_CHECK_EQ(checkpoint_topology_describe_mismatch(source, 3, 3,
	    changed, 3, buf, 8), ENODEV);
	ATF_CHECK_EQ(strlen(buf), 7);
	ATF_CHECK_EQ(checkpoint_topology_describe_mismatch(source, 3, 3,
	    changed, 3, NULL, 0), EINVAL);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, exact_named_device_set);
	ATF_TP_ADD_TC(tp, rejects_ambiguous_or_invalid_names);
	ATF_TP_ADD_TC(tp, restore_mismatch_names_the_device);
	ATF_TP_ADD_TC(tp, exact_record_partition);
	ATF_TP_ADD_TC(tp, large_unordered_record_partition);
	ATF_TP_ADD_TC(tp, exact_record_consumption);
	ATF_TP_ADD_TC(tp, cpu_topology_product_and_bounds);
	ATF_TP_ADD_TC(tp, numa_topology_is_an_exact_partition);
	ATF_TP_ADD_TC(tp, memory_geometry_is_exact_and_portable);
	return (atf_no_error());
}
