/* SPDX-License-Identifier: BSD-2-Clause */
#ifdef BHYVE_SNAPSHOT
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "migration_session.h"
#include "migration_credentials.h"

struct migration_receiver {
	pthread_mutex_t mutex;
	pthread_cond_t changed;
	pthread_t thread;
	bool ready, running, ack_sent;
	int listener, listener_flags;
	struct migration_tls_credentials credentials;
	struct migration_prod_dest *owner;
};

int
migration_recovery_listener_check(int fd)
{
	int value;
	socklen_t length = sizeof(value);
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &value, &length) != 0)
		return (errno);
	if (length != sizeof(value) || value != SOCK_STREAM)
		return (EINVAL);
	length = sizeof(value);
	if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &value, &length) != 0)
		return (errno);
	return (length == sizeof(value) && value != 0 ? 0 : EINVAL);
}

static void *
migration_receiver_worker(void *arg)
{
	struct migration_receiver *receiver = arg;
	int previous_error = 0;

	pthread_mutex_lock(&receiver->mutex);
	while (!receiver->ready)
		pthread_cond_wait(&receiver->changed, &receiver->mutex);
	bool retained = receiver->owner != NULL;
	pthread_mutex_unlock(&receiver->mutex);
	if (!retained)
		return (NULL);
	/* Owner lifetime is the VM process lifetime. Once COMMIT might have
	 * retired the source, listener/peer failures cannot tear this owner down. */
	for (;;) {
		struct pollfd pollfd = { .fd = receiver->listener, .events = POLLIN };
		int error = 0, client = -1;
		int n = poll(&pollfd, 1, -1);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			error = errno;
		else if ((pollfd.revents & POLLIN) == 0)
			error = EIO;
		else {
			client = accept4(receiver->listener, NULL, NULL, SOCK_CLOEXEC);
			if (client < 0) {
				if (errno == EINTR || errno == EAGAIN)
					continue;
				error = errno;
			}
		}
		if (client >= 0) {
			bool running, uncertain, acknowledged;
			pthread_mutex_lock(&receiver->mutex);
			error = migration_prod_dest_recover_release(receiver->owner,
			    client, &receiver->credentials);
			migration_prod_dest_recovery_status(receiver->owner,
			    &running, &uncertain, &acknowledged);
			receiver->running = running && !uncertain;
			receiver->ack_sent = acknowledged;
			pthread_cond_broadcast(&receiver->changed);
			pthread_mutex_unlock(&receiver->mutex);
			close(client);
		}
		if (error != 0 && error != previous_error)
			warnx("migration recovery attempt failed: %d; retaining destination", error);
		previous_error = error;
		if (client < 0) {
			/* Avoid spinning on persistent local resource/listener failure.
			 * Keep the owner stopped/retained until service is possible. */
			struct timespec delay = { .tv_sec = 1 };
			nanosleep(&delay, NULL);
		}
	}
}

static void
migration_receiver_free(struct migration_receiver *receiver)
{
	/* Only valid before an owner is published; active receivers are kept
	 * until VM process exit, including after successful acknowledgment. */
	if (receiver->listener >= 0) {
		if (receiver->listener_flags >= 0)
			(void)fcntl(receiver->listener, F_SETFL, receiver->listener_flags);
		close(receiver->listener);
	}
	if (receiver->credentials.certificate_fd >= 0) close(receiver->credentials.certificate_fd);
	if (receiver->credentials.private_key_fd >= 0) close(receiver->credentials.private_key_fd);
	if (receiver->credentials.trust_fd >= 0) close(receiver->credentials.trust_fd);
	free(receiver);
}

/* Initial state source for a managed owner: a migration stream or a
 * preserved image. Both must leave *owner NULL unless it is retained. */
typedef int (*migration_receiver_source_t)(void *, struct vmctx *,
    const struct migration_session_config *, struct migration_dest_result *,
    struct migration_prod_dest **);

static int
migration_receiver_run(struct vmctx *ctx, int listener,
    const struct migration_session_config *config, struct migration_dest_result *result,
    migration_receiver_source_t source, void *source_arg)
{
	struct migration_receiver *receiver;
	struct migration_session_config managed;
	int error;

	error = migration_recovery_listener_check(listener);
	if (error != 0)
		return (error);
	receiver = calloc(1, sizeof(*receiver));
	if (receiver == NULL)
		return (ENOMEM);
	receiver->listener = receiver->listener_flags = -1;
	receiver->credentials = *config->tls_credentials;
	receiver->credentials.certificate_fd = -1;
	receiver->credentials.private_key_fd = -1;
	receiver->credentials.trust_fd = -1;
	receiver->listener = fcntl(listener, F_DUPFD_CLOEXEC, 0);
	if (receiver->listener < 0) { error = errno; goto fail; }
	receiver->listener_flags = fcntl(receiver->listener, F_GETFL);
	if (receiver->listener_flags < 0 || fcntl(receiver->listener, F_SETFL,
	    receiver->listener_flags | O_NONBLOCK) != 0) { error = errno; goto fail; }
	receiver->credentials.certificate_fd = fcntl(config->tls_credentials->certificate_fd, F_DUPFD_CLOEXEC, 0);
	if (receiver->credentials.certificate_fd < 0) { error = errno; goto fail; }
	receiver->credentials.private_key_fd = fcntl(config->tls_credentials->private_key_fd, F_DUPFD_CLOEXEC, 0);
	if (receiver->credentials.private_key_fd < 0) { error = errno; goto fail; }
	receiver->credentials.trust_fd = fcntl(config->tls_credentials->trust_fd, F_DUPFD_CLOEXEC, 0);
	if (receiver->credentials.trust_fd < 0) { error = errno; goto fail; }
	error = pthread_mutex_init(&receiver->mutex, NULL);
	if (error != 0) goto fail;
	error = pthread_cond_init(&receiver->changed, NULL);
	if (error != 0) { pthread_mutex_destroy(&receiver->mutex); goto fail; }
	error = pthread_create(&receiver->thread, NULL, migration_receiver_worker, receiver);
	if (error != 0) {
		pthread_cond_destroy(&receiver->changed);
		pthread_mutex_destroy(&receiver->mutex);
		goto fail;
	}
	/* All worker/resources exist before COMMIT can make failure irreversible. */
	managed = *config;
	managed.tls_credentials = &receiver->credentials;
	error = source(source_arg, ctx, &managed, result, &receiver->owner);
	pthread_mutex_lock(&receiver->mutex);
	receiver->running = result->resumed;
	receiver->ack_sent = result->release_ack_sent;
	receiver->ready = true;
	pthread_cond_broadcast(&receiver->changed);
	if (receiver->owner == NULL) {
		pthread_mutex_unlock(&receiver->mutex);
		pthread_join(receiver->thread, NULL);
		pthread_cond_destroy(&receiver->changed);
		pthread_mutex_destroy(&receiver->mutex);
		goto fail;
	}
	(void)pthread_detach(receiver->thread);
	if (!receiver->running)
		warnx("migration destination retained; awaiting authenticated recovery");
	while (!receiver->running)
		pthread_cond_wait(&receiver->changed, &receiver->mutex);
	result->resumed = true;
	result->retained = false;
	result->phase = MIGRATION_PHASE_COMPLETED;
	result->release_ack_sent = receiver->ack_sent;
	result->reason = receiver->ack_sent ? MIGRATION_REASON_NONE : MIGRATION_REASON_TRANSPORT;
	pthread_mutex_unlock(&receiver->mutex);
	return (0);
fail:
	migration_receiver_free(receiver);
	return (error);
}

static int
migration_receiver_stream(void *arg, struct vmctx *ctx,
    const struct migration_session_config *config, struct migration_dest_result *result,
    struct migration_prod_dest **owner)
{
	return (migration_prod_dest_serve_prepared(ctx, *(int *)arg, config, result, owner));
}

int
migration_prod_dest_serve_managed(struct vmctx *ctx, int fd, int listener,
    const struct migration_session_config *config, struct migration_dest_result *result)
{
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
		result->phase = MIGRATION_PHASE_FAILED;
		result->reason = MIGRATION_REASON_STATE;
	}
	if (ctx == NULL || config == NULL || result == NULL ||
	    !config->recovery_enabled || config->tls_credentials == NULL)
		return (EINVAL);
	return (migration_receiver_run(ctx, listener, config, result,
	    migration_receiver_stream, &fd));
}

struct migration_receiver_image {
	struct migration_prod_reconstruct *state;
};

static int
migration_receiver_image(void *arg, struct vmctx *ctx,
    const struct migration_session_config *config, struct migration_dest_result *result,
    struct migration_prod_dest **owner)
{
	struct migration_receiver_image *image = arg;
	struct migration_prod_reconstruct *state = image->state;

	image->state = NULL;	/* consumed even on failure */
	return (migration_prod_dest_reconstruct_prepared(ctx, state, config, result, owner));
}

/* A successor of a lost destination controller. The worker exists before the
 * reconstructed owner is published; the guest stays fenced until recovery. */
int
migration_prod_dest_reconstruct_managed(struct vmctx *ctx,
    struct migration_prod_reconstruct *state, int listener,
    const struct migration_session_config *config, struct migration_dest_result *result)
{
	struct migration_receiver_image image = { .state = state };
	int error;

	if (result != NULL) {
		memset(result, 0, sizeof(*result));
		result->phase = MIGRATION_PHASE_FAILED;
		result->reason = MIGRATION_REASON_STATE;
	}
	if (state == NULL || ctx == NULL || config == NULL || result == NULL ||
	    !config->recovery_enabled || config->tls_credentials == NULL)
		error = EINVAL;
	else
		error = migration_receiver_run(ctx, listener, config, result,
		    migration_receiver_image, &image);
	/* Setup failure before the source ran: release the admitted controller. */
	if (image.state != NULL)
		migration_prod_dest_reconstruct_abandon(image.state);
	return (error);
}
#endif
