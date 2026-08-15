/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <atf-c.h>
#include <errno.h>
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
	ATF_CHECK_EQ(checkpoint_record_layout_validate(overflow, 1,
	    UINT64_MAX), EINVAL);
	ATF_CHECK_EQ(checkpoint_record_layout_validate(NULL, 0, 0), 0);
	ATF_CHECK_EQ(checkpoint_record_layout_validate(NULL, 0, 1), EINVAL);
	ATF_CHECK_EQ(checkpoint_record_layout_validate(NULL, 1, 1), EINVAL);
}

ATF_TC_WITHOUT_HEAD(exact_record_consumption);
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
	const uint16_t cpus0[] = { 0, 2 };
	const uint16_t cpus1[] = { 1, 3 };
	const uint16_t duplicate[] = { 0, 3 };
	const uint16_t outside[] = { 1, 4 };
	const uint16_t missing[] = { 1 };
	const struct checkpoint_numa_domain valid[] = {
		{ .memory_size = 3ULL << 30, .vcpus = cpus0,
		    .vcpu_count = nitems(cpus0) },
		{ .memory_size = 1ULL << 30, .vcpus = cpus1,
		    .vcpu_count = nitems(cpus1) },
	};
	struct checkpoint_numa_domain changed[nitems(valid)];

	/* Private checkpoint-format policy, not a guest architecture cap. */
	ATF_REQUIRE_EQ(CHECKPOINT_NUMA_MAX_DOMAINS, 8);
	ATF_REQUIRE_EQ(checkpoint_numa_topology_validate(valid, nitems(valid),
	    4, 4ULL << 30), 0);

	memcpy(changed, valid, sizeof(changed));
	changed[1].vcpus = duplicate;
	ATF_CHECK_EQ(checkpoint_numa_topology_validate(changed,
	    nitems(changed), 4, 4ULL << 30), EINVAL);
	changed[1].vcpus = outside;
	ATF_CHECK_EQ(checkpoint_numa_topology_validate(changed,
	    nitems(changed), 4, 4ULL << 30), EINVAL);
	changed[1].vcpus = missing;
	changed[1].vcpu_count = nitems(missing);
	ATF_CHECK_EQ(checkpoint_numa_topology_validate(changed,
	    nitems(changed), 4, 4ULL << 30), EINVAL);

	memcpy(changed, valid, sizeof(changed));
	changed[1].memory_size--;
	ATF_CHECK_EQ(checkpoint_numa_topology_validate(changed,
	    nitems(changed), 4, 4ULL << 30), EINVAL);
	changed[0].memory_size = UINT64_MAX;
	ATF_CHECK_EQ(checkpoint_numa_topology_validate(changed,
	    nitems(changed), 4, 4ULL << 30), EINVAL);

	memcpy(changed, valid, sizeof(changed));
	changed[0].memory_size = 0;
	ATF_CHECK_EQ(checkpoint_numa_topology_validate(changed,
	    nitems(changed), 4, 4ULL << 30), EINVAL);
	changed[0] = valid[0];
	changed[0].vcpu_count = 0;
	ATF_CHECK_EQ(checkpoint_numa_topology_validate(changed,
	    nitems(changed), 4, 4ULL << 30), EINVAL);
	changed[0].vcpu_count = SIZE_MAX;
	ATF_CHECK_EQ(checkpoint_numa_topology_validate(changed,
	    nitems(changed), 4, 4ULL << 30), EINVAL);
	ATF_CHECK_EQ(checkpoint_numa_topology_validate(NULL, 1, 4,
	    4ULL << 30), EINVAL);
	ATF_CHECK_EQ(checkpoint_numa_topology_validate(valid, 0, 4,
	    4ULL << 30), EINVAL);
	ATF_CHECK_EQ(checkpoint_numa_topology_validate(valid,
	    CHECKPOINT_NUMA_MAX_DOMAINS + 1, 4, 4ULL << 30), EINVAL);
	ATF_CHECK_EQ(checkpoint_numa_topology_validate(valid, nitems(valid),
	    0, 4ULL << 30), EINVAL);
	ATF_CHECK_EQ(checkpoint_numa_topology_validate(valid, nitems(valid),
	    4, 0), EINVAL);
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

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, exact_named_device_set);
	ATF_TP_ADD_TC(tp, rejects_ambiguous_or_invalid_names);
	ATF_TP_ADD_TC(tp, exact_record_partition);
	ATF_TP_ADD_TC(tp, exact_record_consumption);
	ATF_TP_ADD_TC(tp, cpu_topology_product_and_bounds);
	ATF_TP_ADD_TC(tp, numa_topology_is_an_exact_partition);
	ATF_TP_ADD_TC(tp, memory_geometry_is_exact_and_portable);
	return (atf_no_error());
}
