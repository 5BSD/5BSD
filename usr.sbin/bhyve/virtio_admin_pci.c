/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/uio.h>

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio.h"
#include "virtio_admin_pci.h"
#include "virtio_admin_queue.h"

#define	VADMIN_PCI_IOV_BYTES_MAX	(16U * 1024U * 1024U)

struct vadmin_pci_queue {
	struct iovec *iov;
	size_t iov_count;
};

struct virtio_admin_pci_binding {
	struct virtio_softc *vs;
	struct virtio_admin_pci_controller *controller;
	struct vadmin_pci_queue *queues;
	pthread_rwlock_t lifecycle;
	unsigned int quiesce_depth;
	uint16_t count;
};

static void
vadmin_pci_notify(void *argument __unused, struct vqueue_info *vq)
{
	struct virtio_admin_pci_binding *binding;
	struct vadmin_pci_queue *queue;
	struct vi_req req;
	uint32_t used;
	uint16_t local;
	int error, n;

	binding = vq->vq_vs->vs_admin_binding;
	if (binding == NULL || vq->vq_num < vq->vq_vs->vs_admin_queue_index) {
		vi_set_needs_reset(vq->vq_vs);
		return;
	}
	local = vq->vq_num - vq->vq_vs->vs_admin_queue_index;
	if (local >= binding->count) {
		vi_set_needs_reset(vq->vq_vs);
		return;
	}
	queue = &binding->queues[local];
	pthread_rwlock_rdlock(&binding->lifecycle);
	if (binding->quiesce_depth != 0) {
		/* Preserve a kick which raced the transport lifecycle fence. */
		vq->vq_notify_pending = true;
		pthread_rwlock_unlock(&binding->lifecycle);
		return;
	}
	for (;;) {
		n = vq_getchain(vq, queue->iov, (int)queue->iov_count, &req);
		if (n < 0) {
			/*
			 * A negative parser result is a malformed descriptor chain,
			 * not an empty-queue race.  Fail the device immediately so a
			 * broken administration request cannot be retried forever on
			 * every kick.  There is no trustworthy head to complete here.
			 */
			vi_set_needs_reset(vq->vq_vs);
			break;
		}
		if (n == 0)
			break;
		used = 0;
		error = virtio_admin_pci_controller_process_chain(
		    binding->controller, vq->vq_num, queue->iov, (size_t)n,
		    (size_t)req.readable, (size_t)req.writable, req.ordered,
		    req.lengths_known, req.writable_bytes, &used);
		if (error != 0) {
			vq_relchain_req(vq, &req, 0);
			vi_set_needs_reset(vq->vq_vs);
			break;
		}
		vq_relchain_req(vq, &req, used);
		if ((vq->vq_vs->vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
			break;
	}
	vq_endchains(vq, n == 0);
	pthread_rwlock_unlock(&binding->lifecycle);
}

int
virtio_admin_pci_binding_create(struct virtio_admin_pci_binding **result,
    struct virtio_softc *vs, struct virtio_admin_pci_controller *controller,
    struct vqueue_info *vqs, uint16_t queue_size)
{
	const struct virtio_admin_pci_queue_namespace *name_space;
	struct virtio_admin_pci_binding *binding;
	size_t bytes;
	int error;

	if (result == NULL)
		return (EINVAL);
	*result = NULL;
	name_space = virtio_admin_pci_controller_namespace(controller);
	if (vs == NULL || vs->vs_vc == NULL || name_space == NULL || vqs == NULL ||
	    vs->vs_admin_binding != NULL || queue_size == 0 ||
	    queue_size > BHYVE_VIRTIO_ADMIN_QUEUE_IOV_MAX ||
	    name_space->ordinary_count != vs->vs_vc->vc_nvq ||
	    __builtin_mul_overflow((size_t)name_space->admin_count,
	    (size_t)queue_size * sizeof(struct iovec), &bytes) ||
	    bytes > VADMIN_PCI_IOV_BYTES_MAX)
		return (EINVAL);
	binding = calloc(1, sizeof(*binding));
	if (binding == NULL)
		return (ENOMEM);
	error = virtio_admin_pci_controller_seal(controller);
	if (error != 0) {
		free(binding);
		return (error);
	}
	error = pthread_rwlock_init(&binding->lifecycle, NULL);
	if (error != 0) {
		free(binding);
		return (error);
	}
	binding->queues = calloc(name_space->admin_count,
	    sizeof(*binding->queues));
	if (binding->queues == NULL) {
		pthread_rwlock_destroy(&binding->lifecycle);
		free(binding);
		return (ENOMEM);
	}
	for (uint16_t i = 0; i < name_space->admin_count; i++) {
		binding->queues[i].iov = calloc(queue_size,
		    sizeof(*binding->queues[i].iov));
		if (binding->queues[i].iov == NULL) {
			error = ENOMEM;
			goto fail;
		}
		binding->queues[i].iov_count = queue_size;
	}
	binding->vs = vs;
	binding->controller = controller;
	binding->count = name_space->admin_count;
	error = vi_pci_stage_admin_queues(vs, vqs, name_space->admin_index,
	    name_space->admin_count);
	if (error != 0)
		goto fail;
	for (uint16_t i = 0; i < binding->count; i++) {
		vqs[i].vq_qsize = queue_size;
		vqs[i].vq_notify = vadmin_pci_notify;
	}
	vs->vs_admin_binding = binding;
	*result = binding;
	return (0);

fail:
	for (uint16_t i = 0; i < name_space->admin_count; i++)
		free(binding->queues[i].iov);
	free(binding->queues);
	pthread_rwlock_destroy(&binding->lifecycle);
	free(binding);
	return (error);
}

int
virtio_admin_pci_binding_destroy(struct virtio_admin_pci_binding *binding)
{
	struct virtio_softc *vs;

	if (binding == NULL)
		return (EINVAL);
	vs = binding->vs;
	if (vs->vs_modern != NULL || vs->vs_status != 0 ||
	    vs->vs_admin_binding != binding)
		return (EBUSY);
	for (uint16_t i = 0; i < binding->count; i++) {
		free(binding->queues[i].iov);
		memset(&vs->vs_admin_queues[i], 0,
		    sizeof(vs->vs_admin_queues[i]));
	}
	vs->vs_admin_binding = NULL;
	vs->vs_admin_queues = NULL;
	vs->vs_admin_queue_index = 0;
	vs->vs_admin_queue_count = 0;
	free(binding->queues);
	pthread_rwlock_destroy(&binding->lifecycle);
	free(binding);
	return (0);
}

int
virtio_admin_pci_binding_enable(struct virtio_admin_pci_binding *binding,
    struct vqueue_info *vq)
{

	return (binding == NULL || vq == NULL ||
	    binding != vq->vq_vs->vs_admin_binding ||
	    !vi_pci_queue_is_admin(binding->vs, vq) ? EINVAL : 0);
}

int
virtio_admin_pci_binding_drain(struct virtio_admin_pci_binding *binding,
    struct vqueue_info *vq)
{

	if (binding == NULL || vq == NULL || binding != vq->vq_vs->vs_admin_binding ||
	    !vi_pci_queue_is_admin(binding->vs, vq))
		return (EINVAL);
	return (virtio_admin_pci_controller_drain_queue(binding->controller,
	    vq->vq_num));
}

int
virtio_admin_pci_binding_quiesce(struct virtio_admin_pci_binding *binding)
{
	int error;

	if (binding == NULL || binding->vs == NULL ||
	    binding->vs->vs_admin_binding != binding ||
	    binding->vs->vs_admin_queues == NULL || binding->count == 0 ||
	    binding->count != binding->vs->vs_admin_queue_count)
		return (EINVAL);
	pthread_rwlock_wrlock(&binding->lifecycle);
	if (binding->quiesce_depth == UINT_MAX) {
		pthread_rwlock_unlock(&binding->lifecycle);
		return (EOVERFLOW);
	}
	binding->quiesce_depth++;
	for (uint16_t i = 0; i < binding->count; i++) {
		error = virtio_admin_pci_controller_drain_queue(
		    binding->controller,
		    (uint32_t)binding->vs->vs_admin_queue_index + i);
		if (error != 0) {
			binding->quiesce_depth--;
			pthread_rwlock_unlock(&binding->lifecycle);
			return (error);
		}
	}
	pthread_rwlock_unlock(&binding->lifecycle);
	return (0);
}

int
virtio_admin_pci_binding_unquiesce(struct virtio_admin_pci_binding *binding)
{

	if (binding == NULL || binding->vs == NULL ||
	    binding->vs->vs_admin_binding != binding)
		return (EINVAL);
	pthread_rwlock_wrlock(&binding->lifecycle);
	if (binding->quiesce_depth == 0) {
		pthread_rwlock_unlock(&binding->lifecycle);
		return (EINVAL);
	}
	binding->quiesce_depth--;
	pthread_rwlock_unlock(&binding->lifecycle);
	return (0);
}

int
virtio_admin_pci_binding_resume(struct virtio_admin_pci_binding *binding,
    int (*resume)(void *), void *argument)
{
	int error;

	if (binding == NULL || resume == NULL || binding->vs == NULL ||
	    binding->vs->vs_admin_binding != binding)
		return (EINVAL);
	/*
	 * Validate ownership before changing the backend, and retain exclusive
	 * command admission throughout the callback.  A successful backend resume
	 * therefore cannot be followed by a fallible fence-release step which
	 * would make a retry invoke the callback twice.
	 */
	pthread_rwlock_wrlock(&binding->lifecycle);
	if (binding->quiesce_depth == 0) {
		pthread_rwlock_unlock(&binding->lifecycle);
		return (EINVAL);
	}
	error = resume(argument);
	if (error == 0)
		binding->quiesce_depth--;
	pthread_rwlock_unlock(&binding->lifecycle);
	return (error);
}

int
virtio_admin_pci_binding_state_size(struct virtio_admin_pci_binding *binding,
    size_t *result)
{

	if (binding == NULL || result == NULL || binding->vs == NULL ||
	    binding->vs->vs_admin_binding != binding)
		return (EINVAL);
	return (virtio_admin_pci_controller_snapshot_size(binding->controller,
	    result));
}

int
virtio_admin_pci_binding_state_save(struct virtio_admin_pci_binding *binding,
    void *buffer, size_t length)
{
	int error;

	if (binding == NULL || buffer == NULL || binding->vs == NULL ||
	    binding->vs->vs_admin_binding != binding)
		return (EINVAL);
	pthread_rwlock_rdlock(&binding->lifecycle);
	if (binding->quiesce_depth == 0)
		error = EBUSY;
	else
		error = virtio_admin_pci_controller_snapshot(binding->controller,
		    buffer, length);
	pthread_rwlock_unlock(&binding->lifecycle);
	return (error);
}

int
virtio_admin_pci_binding_state_restore(
    struct virtio_admin_pci_binding *binding, const void *buffer,
    size_t length)
{
	int error;

	if (binding == NULL || buffer == NULL || binding->vs == NULL ||
	    binding->vs->vs_admin_binding != binding)
		return (EINVAL);
	pthread_rwlock_rdlock(&binding->lifecycle);
	if (binding->quiesce_depth == 0)
		error = EBUSY;
	else
		error = virtio_admin_pci_controller_restore(binding->controller,
		    buffer, length);
	pthread_rwlock_unlock(&binding->lifecycle);
	return (error);
}

int
virtio_admin_pci_binding_state_restore_validate(
    struct virtio_admin_pci_binding *binding, const void *buffer,
    size_t length)
{
	int error;

	if (binding == NULL || buffer == NULL || binding->vs == NULL ||
	    binding->vs->vs_admin_binding != binding)
		return (EINVAL);
	pthread_rwlock_rdlock(&binding->lifecycle);
	if (binding->quiesce_depth == 0)
		error = EBUSY;
	else
		error = virtio_admin_pci_controller_restore_validate(
		    binding->controller, buffer, length);
	pthread_rwlock_unlock(&binding->lifecycle);
	return (error);
}

void
virtio_admin_pci_binding_reset(struct virtio_admin_pci_binding *binding)
{

	if (binding != NULL) {
		pthread_rwlock_wrlock(&binding->lifecycle);
		binding->quiesce_depth = 0;
		virtio_admin_pci_controller_reset(binding->controller);
		pthread_rwlock_unlock(&binding->lifecycle);
	}
}
