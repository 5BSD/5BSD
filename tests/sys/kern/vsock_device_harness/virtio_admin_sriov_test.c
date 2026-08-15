/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "virtio_admin_sriov.c"

struct update_context {
	struct virtio_admin_sriov_lifecycle *lifecycle;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	bool started;
	_Atomic(bool) completed;
	int error;
};

static void *
update_thread(void *argument)
{
	struct update_context *context;

	context = argument;
	pthread_mutex_lock(&context->mutex);
	context->started = true;
	pthread_cond_signal(&context->cond);
	pthread_mutex_unlock(&context->mutex);
	context->error = virtio_admin_sriov_lifecycle_update(
	    context->lifecycle, true, false, false, 4);
	atomic_store_explicit(&context->completed, true, memory_order_release);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(group_visibility_and_membership);
ATF_TC_BODY(group_visibility_and_membership, tc)
{
	struct virtio_admin_sriov_lifecycle *lifecycle;
	struct virtio_admin_sriov_state before, after;
	uint16_t qualifier;

	ATF_REQUIRE_EQ(virtio_admin_sriov_lifecycle_create(&lifecycle), 0);
	ATF_CHECK(!virtio_admin_sriov_group_available(lifecycle));
	qualifier = 0;
	ATF_CHECK_EQ(virtio_admin_sriov_group_begin(lifecycle, &qualifier),
	    ENXIO);
	ATF_CHECK_EQ(qualifier,
	    BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_GROUP);
	ATF_CHECK_EQ(virtio_admin_sriov_lifecycle_update(lifecycle, false,
	    true, false, 1), EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_sriov_lifecycle_update(lifecycle, true,
	    false, false, 8), 0);
	ATF_CHECK(!virtio_admin_sriov_group_available(lifecycle));
	ATF_REQUIRE_EQ(virtio_admin_sriov_lifecycle_update(lifecycle, true,
	    true, false, 8), 0);
	ATF_CHECK(virtio_admin_sriov_group_available(lifecycle));
	ATF_CHECK(!virtio_admin_sriov_member_valid(lifecycle, 0));
	ATF_CHECK(virtio_admin_sriov_member_valid(lifecycle, 1));
	ATF_CHECK(virtio_admin_sriov_member_valid(lifecycle, 8));
	ATF_CHECK(!virtio_admin_sriov_member_valid(lifecycle, 9));

	ATF_REQUIRE_EQ(virtio_admin_sriov_lifecycle_get(lifecycle, &before),
	    0);
	ATF_REQUIRE_EQ(virtio_admin_sriov_lifecycle_update(lifecycle, true,
	    true, false, 8), 0);
	ATF_REQUIRE_EQ(virtio_admin_sriov_lifecycle_get(lifecycle, &after), 0);
	ATF_CHECK_EQ(before.generation, after.generation);
	ATF_REQUIRE_EQ(virtio_admin_sriov_lifecycle_update(lifecycle, true,
	    true, true, 8), 0);
	ATF_REQUIRE_EQ(virtio_admin_sriov_lifecycle_get(lifecycle, &after), 0);
	ATF_CHECK(after.vf_migration_capable);
	ATF_CHECK(after.generation != before.generation);
	qualifier = 0;
	ATF_CHECK_EQ(virtio_admin_sriov_group_begin(lifecycle, &qualifier),
	    EBUSY);
	ATF_CHECK_EQ(qualifier, BHYVE_VIRTIO_ADMIN_QUALIFIER_TRYAGAIN);

	virtio_admin_sriov_lifecycle_destroy(lifecycle);
}

ATF_TC_WITHOUT_HEAD(command_lease_fences_pci_lifecycle_change);
ATF_TC_BODY(command_lease_fences_pci_lifecycle_change, tc)
{
	struct virtio_admin_sriov_lifecycle *lifecycle;
	struct update_context context;
	pthread_t thread;
	uint16_t qualifier;

	ATF_REQUIRE_EQ(virtio_admin_sriov_lifecycle_create(&lifecycle), 0);
	ATF_REQUIRE_EQ(virtio_admin_sriov_lifecycle_update(lifecycle, true,
	    true, false, 8), 0);
	qualifier = 0;
	ATF_REQUIRE_EQ(virtio_admin_sriov_group_begin(lifecycle, &qualifier),
	    0);
	context = (struct update_context) {
		.lifecycle = lifecycle,
		.mutex = PTHREAD_MUTEX_INITIALIZER,
		.cond = PTHREAD_COND_INITIALIZER,
	};
	atomic_init(&context.completed, false);
	ATF_REQUIRE_EQ(pthread_create(&thread, NULL, update_thread, &context),
	    0);
	pthread_mutex_lock(&context.mutex);
	while (!context.started)
		pthread_cond_wait(&context.cond, &context.mutex);
	pthread_mutex_unlock(&context.mutex);

	/*
	 * The updater has announced its lifecycle change and cannot complete
	 * publication while this command owns the read lease.
	 */
	ATF_CHECK(!atomic_load_explicit(&context.completed,
	    memory_order_acquire));
	ATF_CHECK(virtio_admin_sriov_member_valid(lifecycle, 8));
	virtio_admin_sriov_group_end(lifecycle);
	ATF_REQUIRE_EQ(pthread_join(thread, NULL), 0);
	ATF_CHECK_EQ(context.error, 0);
	ATF_CHECK(atomic_load_explicit(&context.completed,
	    memory_order_acquire));
	ATF_CHECK(!virtio_admin_sriov_group_available(lifecycle));
	pthread_cond_destroy(&context.cond);
	pthread_mutex_destroy(&context.mutex);
	virtio_admin_sriov_lifecycle_destroy(lifecycle);
}

ATF_TC_WITHOUT_HEAD(publication_aliases_are_rejected);
ATF_TC_BODY(publication_aliases_are_rejected, tc)
{
	struct virtio_admin_sriov_lifecycle *lifecycle;
	struct virtio_admin_sriov_state state;
	uint16_t qualifier;

	ATF_REQUIRE_EQ(virtio_admin_sriov_lifecycle_create(&lifecycle), 0);
	ATF_REQUIRE_EQ(virtio_admin_sriov_lifecycle_update(lifecycle, true,
	    true, false, 4), 0);
	ATF_CHECK_EQ(virtio_admin_sriov_lifecycle_get(lifecycle,
	    (struct virtio_admin_sriov_state *)lifecycle), EINVAL);
	ATF_CHECK_EQ(virtio_admin_sriov_group_begin(lifecycle,
	    (uint16_t *)lifecycle), EINVAL);
	/* Rejected begin released its lease, so a writer still makes progress. */
	ATF_REQUIRE_EQ(virtio_admin_sriov_lifecycle_update(lifecycle, true,
	    true, false, 3), 0);
	ATF_REQUIRE_EQ(virtio_admin_sriov_lifecycle_get(lifecycle, &state), 0);
	ATF_CHECK_EQ(state.num_vfs, 3);
	qualifier = UINT16_MAX;
	ATF_REQUIRE_EQ(virtio_admin_sriov_group_begin(lifecycle, &qualifier),
	    0);
	virtio_admin_sriov_group_end(lifecycle);
	virtio_admin_sriov_lifecycle_destroy(lifecycle);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, group_visibility_and_membership);
	ATF_TP_ADD_TC(tp, command_lease_fences_pci_lifecycle_change);
	ATF_TP_ADD_TC(tp, publication_aliases_are_rejected);
	return (atf_no_error());
}
