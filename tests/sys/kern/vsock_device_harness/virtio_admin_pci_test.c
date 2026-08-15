/*
 * Exercise the production administration-virtqueue PCI ring adapter.
 * The controller is mocked at its narrow value boundary so these cases can
 * force split-ring parser outcomes which the controller-only tests cannot.
 */
#include <sys/param.h>
#include <sys/uio.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

typedef struct nvlist nvlist_t;

#include "virtio.h"
#include "virtio_admin_queue.h"

struct virtio_admin_pci_controller {
	struct virtio_admin_pci_queue_namespace name_space;
	unsigned int process_calls;
	unsigned int drain_calls;
	unsigned int reset_calls;
	unsigned int seal_calls;
	int process_error;
	int drain_error;
	int seal_error;
	uint32_t last_drain_selected;
	uint32_t used;
	uint32_t state;
};

struct ring_fixture {
	int results[3];
	unsigned int result_count;
	unsigned int get_calls;
	unsigned int release_calls;
	unsigned int end_calls;
	unsigned int last_idx;
	uint32_t last_used;
	int last_end_interrupt;
	struct vi_req request;
};

static struct ring_fixture ring_fixture;

const struct virtio_admin_pci_queue_namespace *
virtio_admin_pci_controller_namespace(
    const struct virtio_admin_pci_controller *controller)
{

	return (controller == NULL ? NULL : &controller->name_space);
}

int
virtio_admin_pci_controller_seal(
    struct virtio_admin_pci_controller *controller)
{

	if (controller == NULL)
		return (EINVAL);
	controller->seal_calls++;
	return (controller->seal_error);
}

int
virtio_admin_pci_controller_process_chain(
    struct virtio_admin_pci_controller *controller, uint32_t selected,
    const struct iovec *iov __unused, size_t niov, size_t readable,
    size_t writable, bool ordered, bool lengths_known,
    uint64_t writable_bytes, uint32_t *used)
{

	ATF_REQUIRE(controller != NULL);
	ATF_CHECK_EQ(selected, controller->name_space.admin_index);
	ATF_CHECK_EQ(niov, 2);
	ATF_CHECK_EQ(readable, 1);
	ATF_CHECK_EQ(writable, 1);
	ATF_CHECK(ordered);
	ATF_CHECK(lengths_known);
	ATF_CHECK_EQ(writable_bytes, 16);
	controller->process_calls++;
	if (controller->process_error != 0)
		return (controller->process_error);
	*used = controller->used;
	return (0);
}

int
virtio_admin_pci_controller_drain_queue(
    struct virtio_admin_pci_controller *controller, uint32_t selected)
{

	if (controller == NULL || selected < controller->name_space.admin_index ||
	    selected >= controller->name_space.admin_index +
	    controller->name_space.admin_count)
		return (EINVAL);
	controller->drain_calls++;
	controller->last_drain_selected = selected;
	return (controller->drain_error);
}

void
virtio_admin_pci_controller_reset(
    struct virtio_admin_pci_controller *controller)
{

	if (controller != NULL)
		controller->reset_calls++;
}

int
virtio_admin_pci_controller_snapshot_size(
    struct virtio_admin_pci_controller *controller, size_t *result)
{

	if (controller == NULL || result == NULL)
		return (EINVAL);
	*result = sizeof(controller->state);
	return (0);
}

int
virtio_admin_pci_controller_snapshot(
    struct virtio_admin_pci_controller *controller, void *buffer,
    size_t length)
{

	if (controller == NULL || buffer == NULL ||
	    length != sizeof(controller->state))
		return (EINVAL);
	memcpy(buffer, &controller->state, length);
	return (0);
}

int
virtio_admin_pci_controller_restore(
    struct virtio_admin_pci_controller *controller, const void *buffer,
    size_t length)
{

	if (controller == NULL || buffer == NULL ||
	    length != sizeof(controller->state))
		return (EINVAL);
	memcpy(&controller->state, buffer, length);
	return (0);
}

int
virtio_admin_pci_controller_restore_validate(
    struct virtio_admin_pci_controller *controller, const void *buffer,
    size_t length)
{

	if (controller == NULL || buffer == NULL ||
	    length != sizeof(controller->state))
		return (EINVAL);
	return (0);
}

int
vi_pci_stage_admin_queues(struct virtio_softc *vs, struct vqueue_info *vqs,
    uint16_t index, uint16_t count)
{

	if (vs == NULL || vqs == NULL || count == 0 ||
	    vs->vs_admin_queues != NULL)
		return (EINVAL);
	vs->vs_admin_queues = vqs;
	vs->vs_admin_queue_index = index;
	vs->vs_admin_queue_count = count;
	for (uint16_t i = 0; i < count; i++) {
		vqs[i].vq_vs = vs;
		vqs[i].vq_num = index + i;
	}
	return (0);
}

bool
vi_pci_queue_is_admin(const struct virtio_softc *vs,
    const struct vqueue_info *vq)
{

	return (vs != NULL && vq != NULL && vs->vs_admin_queues != NULL &&
	    vq >= vs->vs_admin_queues &&
	    vq < vs->vs_admin_queues + vs->vs_admin_queue_count);
}

void
vi_set_needs_reset(struct virtio_softc *vs)
{

	vs->vs_status |= VIRTIO_CONFIG_S_NEEDS_RESET;
}

int
vq_getchain(struct vqueue_info *vq __unused, struct iovec *iov,
    int niov, struct vi_req *request)
{
	int result;

	ATF_REQUIRE(ring_fixture.get_calls < ring_fixture.result_count);
	result = ring_fixture.results[ring_fixture.get_calls++];
	if (result > 0) {
		ATF_REQUIRE(niov >= result);
		memset(iov, 0, (size_t)result * sizeof(*iov));
		*request = ring_fixture.request;
	}
	return (result);
}

void
vq_relchain(struct vqueue_info *vq __unused, uint16_t idx, uint32_t used)
{

	ring_fixture.release_calls++;
	ring_fixture.last_idx = idx;
	ring_fixture.last_used = used;
}

void
vq_endchains(struct vqueue_info *vq __unused, int interrupt)
{

	ring_fixture.end_calls++;
	ring_fixture.last_end_interrupt = interrupt;
}

#include "virtio_admin_pci.c"

/*
 * Compile the adapter with its production declarations, then obtain the
 * observable status values from the independent VirtIO 1.4 fixture.  Keeping
 * the aliases below the DUT inclusion ensures this test detects an incorrect
 * production definition rather than recompiling the DUT to match the oracle.
 */
#include "virtio_1_4_spec.h"
#undef VIRTIO_CONFIG_STATUS_DRIVER_OK
#define VIRTIO_CONFIG_STATUS_DRIVER_OK VIRTIO14_STATUS_DRIVER_OK
#undef VIRTIO_CONFIG_S_NEEDS_RESET
#define VIRTIO_CONFIG_S_NEEDS_RESET VIRTIO14_STATUS_DEVICE_NEEDS_RESET

static void
fixture_init(struct virtio_softc *vs, struct virtio_consts *constants,
    struct virtio_admin_pci_controller *controller,
    struct vqueue_info queues[2])
{

	memset(vs, 0, sizeof(*vs));
	memset(constants, 0, sizeof(*constants));
	memset(controller, 0, sizeof(*controller));
	memset(queues, 0, 2 * sizeof(*queues));
	constants->vc_nvq = 2;
	vs->vs_vc = constants;
	controller->name_space.ordinary_count = 2;
	controller->name_space.admin_index = 4;
	controller->name_space.admin_count = 2;
}

struct resume_fixture {
	int calls;
	int error;
};

static int
resume_result(void *argument)
{
	struct resume_fixture *resume;

	resume = argument;
	resume->calls++;
	return (resume->error);
}

ATF_TC_WITHOUT_HEAD(binding_lifecycle);
ATF_TC_BODY(binding_lifecycle, tc)
{
	struct virtio_admin_pci_binding *binding;
	struct virtio_admin_pci_controller controller;
	struct virtio_consts constants;
	struct virtio_softc vs;
	struct vqueue_info queues[2], foreign;
	uint8_t state[sizeof(uint32_t)];
	size_t state_size;
	struct resume_fixture resume;

	fixture_init(&vs, &constants, &controller, queues);
	binding = (void *)(uintptr_t)0xa5;
	ATF_REQUIRE_EQ(virtio_admin_pci_binding_create(&binding, &vs,
	    &controller, queues, 8), 0);
	ATF_REQUIRE(binding != NULL);
	ATF_CHECK_EQ(controller.seal_calls, 1);
	ATF_CHECK_EQ(vs.vs_admin_binding, binding);
	ATF_CHECK_EQ(vs.vs_admin_queues, queues);
	ATF_CHECK_EQ(vs.vs_admin_queue_index, 4);
	ATF_CHECK_EQ(vs.vs_admin_queue_count, 2);
	for (unsigned int i = 0; i < 2; i++) {
		ATF_CHECK_EQ(queues[i].vq_num, 4 + i);
		ATF_CHECK_EQ(queues[i].vq_qsize, 8);
		ATF_REQUIRE(queues[i].vq_notify != NULL);
		ATF_CHECK_EQ(virtio_admin_pci_binding_enable(binding,
		    &queues[i]), 0);
	}
	memset(&foreign, 0, sizeof(foreign));
	foreign.vq_vs = &vs;
	ATF_CHECK_EQ(virtio_admin_pci_binding_enable(binding, &foreign),
	    EINVAL);
	ATF_REQUIRE_EQ(virtio_admin_pci_binding_drain(binding, &queues[1]),
	    0);
	ATF_CHECK_EQ(controller.drain_calls, 1);
	ATF_CHECK_EQ(controller.last_drain_selected, 5);
	ATF_REQUIRE_EQ(virtio_admin_pci_binding_state_size(binding,
	    &state_size), 0);
	ATF_CHECK_EQ(state_size, sizeof(state));
	ATF_CHECK_EQ(virtio_admin_pci_binding_state_save(binding, state,
	    sizeof(state)), EBUSY);
	ATF_REQUIRE_EQ(virtio_admin_pci_binding_quiesce(binding), 0);
	ATF_CHECK_EQ(controller.drain_calls, 3);
	ATF_CHECK_EQ(controller.last_drain_selected, 5);
	controller.state = 0x12345678;
	ATF_REQUIRE_EQ(virtio_admin_pci_binding_state_save(binding, state,
	    sizeof(state)), 0);
	controller.state = 0;
	ATF_REQUIRE_EQ(virtio_admin_pci_binding_state_restore(binding, state,
	    sizeof(state)), 0);
	ATF_CHECK_EQ(controller.state, 0x12345678);
	memset(&ring_fixture, 0, sizeof(ring_fixture));
	ring_fixture.results[0] = 0;
	ring_fixture.result_count = 1;
	queues[0].vq_notify(NULL, &queues[0]);
	ATF_CHECK_EQ(ring_fixture.get_calls, 0);
	ATF_CHECK_EQ(ring_fixture.end_calls, 0);
	ATF_CHECK(queues[0].vq_notify_pending);
	ATF_REQUIRE_EQ(virtio_admin_pci_binding_quiesce(binding), 0);
	ATF_CHECK_EQ(controller.drain_calls, 5);
	ATF_REQUIRE_EQ(virtio_admin_pci_binding_unquiesce(binding), 0);
	queues[0].vq_notify(NULL, &queues[0]);
	ATF_CHECK_EQ(ring_fixture.get_calls, 0);
	ATF_REQUIRE_EQ(virtio_admin_pci_binding_unquiesce(binding), 0);
	queues[0].vq_notify_pending = false;
	queues[0].vq_notify(NULL, &queues[0]);
	ATF_CHECK_EQ(ring_fixture.get_calls, 1);
	ATF_CHECK_EQ(ring_fixture.end_calls, 1);
	ATF_CHECK_EQ(virtio_admin_pci_binding_unquiesce(binding), EINVAL);
	memset(&resume, 0, sizeof(resume));
	ATF_CHECK_EQ(virtio_admin_pci_binding_resume(binding, resume_result,
	    &resume), EINVAL);
	ATF_CHECK_EQ(resume.calls, 0);
	ATF_REQUIRE_EQ(virtio_admin_pci_binding_quiesce(binding), 0);
	resume.error = EBUSY;
	ATF_CHECK_EQ(virtio_admin_pci_binding_resume(binding, resume_result,
	    &resume), EBUSY);
	ATF_CHECK_EQ(resume.calls, 1);
	ring_fixture.get_calls = 0;
	queues[0].vq_notify(NULL, &queues[0]);
	ATF_CHECK_EQ(ring_fixture.get_calls, 0);
	resume.error = 0;
	ATF_REQUIRE_EQ(virtio_admin_pci_binding_resume(binding, resume_result,
	    &resume), 0);
	ATF_CHECK_EQ(resume.calls, 2);
	queues[0].vq_notify_pending = false;
	queues[0].vq_notify(NULL, &queues[0]);
	ATF_CHECK_EQ(ring_fixture.get_calls, 1);
	controller.drain_error = EIO;
	ATF_CHECK_EQ(virtio_admin_pci_binding_quiesce(binding), EIO);
	ATF_CHECK_EQ(controller.drain_calls, 8);
	ATF_CHECK_EQ(controller.last_drain_selected, 4);
	controller.drain_error = 0;
	virtio_admin_pci_binding_reset(binding);
	ATF_CHECK_EQ(controller.reset_calls, 1);

	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	ATF_CHECK_EQ(virtio_admin_pci_binding_destroy(binding), EBUSY);
	vs.vs_status = 0;
	ATF_REQUIRE_EQ(virtio_admin_pci_binding_destroy(binding), 0);
	ATF_CHECK_EQ(vs.vs_admin_binding, NULL);
	ATF_CHECK_EQ(vs.vs_admin_queues, NULL);
	ATF_CHECK_EQ(vs.vs_admin_queue_count, 0);
}

ATF_TC_WITHOUT_HEAD(parser_outcomes_are_distinct);
ATF_TC_BODY(parser_outcomes_are_distinct, tc)
{
	struct virtio_admin_pci_binding *binding;
	struct virtio_admin_pci_controller controller;
	struct virtio_consts constants;
	struct virtio_softc vs;
	struct vqueue_info queues[2];

	fixture_init(&vs, &constants, &controller, queues);
	ATF_REQUIRE_EQ(virtio_admin_pci_binding_create(&binding, &vs,
	    &controller, queues, 8), 0);

	/* Empty queues are ordinary and request an end-of-batch interrupt. */
	memset(&ring_fixture, 0, sizeof(ring_fixture));
	ring_fixture.results[0] = 0;
	ring_fixture.result_count = 1;
	queues[0].vq_notify(NULL, &queues[0]);
	ATF_CHECK_EQ(vs.vs_status, 0);
	ATF_CHECK_EQ(ring_fixture.end_calls, 1);
	ATF_CHECK_EQ(ring_fixture.last_end_interrupt, 1);

	/* A parser failure has no trustworthy head and must fail the device. */
	memset(&ring_fixture, 0, sizeof(ring_fixture));
	ring_fixture.results[0] = -1;
	ring_fixture.result_count = 1;
	queues[0].vq_notify(NULL, &queues[0]);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK_EQ(ring_fixture.release_calls, 0);
	ATF_CHECK_EQ(ring_fixture.end_calls, 1);
	ATF_CHECK_EQ(ring_fixture.last_end_interrupt, 0);

	/* A valid request publishes the controller's exact used length. */
	vs.vs_status = 0;
	memset(&ring_fixture, 0, sizeof(ring_fixture));
	ring_fixture.results[0] = 2;
	ring_fixture.results[1] = 0;
	ring_fixture.result_count = 2;
	ring_fixture.request.idx = 7;
	ring_fixture.request.readable = 1;
	ring_fixture.request.writable = 1;
	ring_fixture.request.writable_bytes = 16;
	ring_fixture.request.ordered = true;
	ring_fixture.request.lengths_known = true;
	ring_fixture.request.outstanding = true;
	controller.used = 12;
	queues[0].vq_notify(NULL, &queues[0]);
	ATF_CHECK_EQ(controller.process_calls, 1);
	ATF_CHECK_EQ(ring_fixture.release_calls, 1);
	ATF_CHECK_EQ(ring_fixture.last_idx, 7);
	ATF_CHECK_EQ(ring_fixture.last_used, 12);
	ATF_CHECK_EQ(vs.vs_status, 0);

	/* A rejected command retires its known head with zero and stops. */
	memset(&ring_fixture, 0, sizeof(ring_fixture));
	ring_fixture.results[0] = 2;
	ring_fixture.result_count = 1;
	ring_fixture.request.idx = 9;
	ring_fixture.request.readable = 1;
	ring_fixture.request.writable = 1;
	ring_fixture.request.writable_bytes = 16;
	ring_fixture.request.ordered = true;
	ring_fixture.request.lengths_known = true;
	ring_fixture.request.outstanding = true;
	controller.process_error = EINVAL;
	queues[0].vq_notify(NULL, &queues[0]);
	ATF_CHECK_EQ(ring_fixture.release_calls, 1);
	ATF_CHECK_EQ(ring_fixture.last_idx, 9);
	ATF_CHECK_EQ(ring_fixture.last_used, 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);

	vs.vs_status = 0;
	ATF_REQUIRE_EQ(virtio_admin_pci_binding_destroy(binding), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, binding_lifecycle);
	ATF_TP_ADD_TC(tp, parser_outcomes_are_distinct);
	return (atf_no_error());
}
