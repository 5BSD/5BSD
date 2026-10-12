/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The system.SystemExtension client, moved out of libservice: service_ensure_extension(3), service_extension_*(3) and service_session_extension_*(3).
 * The record protocol and behaviour are unchanged.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <libservice_session.h>
#include <sysext_proto.h>
#include "extensioncmp.h"

static struct service_session *service_sysext_session;
#define SESSIONS_FORGET() do { service_sysext_session = NULL; } while (0)



/*
 * One process-wide provider session, opened by name on first use.  A
 * session that failed terminally (the provider died or was relaunched) is
 * replaced; a session inherited across fork or pdfork belongs to the parent
 * and is abandoned (libservice's fork handling severs its channel).
 */
static pthread_mutex_t service_state_lock = PTHREAD_MUTEX_INITIALIZER;
static pid_t service_session_owner;

static int
service_cached_session_get(const char *name, struct service_session **slot)
    __no_lock_analysis
{
	struct service_session *candidate;
	int error, fd;

	error = pthread_mutex_lock(&service_state_lock);
	if (error != 0)
		return (errno = error, -1);
	if (service_session_owner != getpid()) {
		/* Never close an inherited session: it is the parent's. */
		SESSIONS_FORGET();
		service_session_owner = getpid();
	}
	if (*slot != NULL) {
		struct service_session *dead = NULL;

		if (service_session_is_dead(*slot)) {
			dead = *slot;
			*slot = NULL;
		}
		(void)pthread_mutex_unlock(&service_state_lock);
		if (dead == NULL)
			return (0);
		service_session_close(dead);
	} else
		(void)pthread_mutex_unlock(&service_state_lock);

	if (service_open(name, &fd) == -1)
		return (-1);
	if (service_session_create(fd, &candidate) == -1) {
		error = errno;
		(void)close(fd);
		errno = error;
		return (-1);
	}

	error = pthread_mutex_lock(&service_state_lock);
	if (error != 0) {
		service_session_close(candidate);
		errno = error;
		return (-1);
	}
	if (*slot == NULL) {
		*slot = candidate;
		candidate = NULL;
	}
	(void)pthread_mutex_unlock(&service_state_lock);
	if (candidate != NULL)
		service_session_close(candidate);
	return (0);
}

/*
 * Ensure a named kernel extension is loaded via bsdextension.  bsdextension is a
 * socket-free provider: libservice opens a system.SystemExtension channel by
 * name and asks it to load the module.  The channel is cached (all of a
 * service's ensures share it).  The discovery domain layer resolves the name
 * only for SYSTEM-domain callers, so a user service's lookup fails closed here.
 */

static int
service_extension_session(struct service_context *context)
{
	if (service_context_check(context) != 0) {
		errno = EINVAL;
		return (-1);
	}
	return (service_cached_session_get(SYSEXT_SERVICE_NAME,
	    &service_sysext_session));
}

int
service_ensure_extension(struct service_context *context, const char *module)
{
	if (service_extension_session(context) == -1)
		return (-1);
	return (service_session_extension_load(service_sysext_session, module));
}

int
service_extension_stat(struct service_context *context, const char *module,
    int *loadedp)
{
	if (service_extension_session(context) == -1)
		return (-1);
	return (service_session_extension_stat(service_sysext_session, module,
	    loadedp));
}

int
service_extension_list(struct service_context *context,
    char (*names)[SERVICE_EXTENSION_NAME_MAX], size_t max, size_t *countp)
{
	if (service_extension_session(context) == -1)
		return (-1);
	return (service_session_extension_list(service_sysext_session, names,
	    max, countp));
}
