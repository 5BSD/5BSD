/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Retirement work runs outside the control dispatcher.  Owner-scoped process
 * descriptors fence already-open sessions before persistent names are removed.
 */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/procdesc.h>

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libservice.h"
#include "service_private.h"
#include "switchboard_lifecycle.h"
#include "switchboard_svc_proto.h"

struct retirement {
	struct retirement *next;
	struct svc_reclaim_label_msg message;
	bool pending;
	bool complete;
};
struct owned_worker {
	struct owned_worker *next;
	char owner[64];
	int pd;
};
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wake = PTHREAD_COND_INITIALIZER;
static struct retirement *retirements;
static struct owned_worker *workers;
static int worker_kq = -1;
static int (*handler)(const char *, void *);
static void *handler_context;
static bool started;
static bool tracking_failed;
static bool forking;

static bool
retired_locked(const char *owner)
{
	for (struct retirement *r = retirements; r != NULL; r = r->next)
		if (strcmp(r->message.owner, owner) == 0)
			return (true);
	return (false);
}

bool
service_reclaim_owner_retired(const char *owner)
{
	bool result;

	pthread_mutex_lock(&lock);
	result = retired_locked(owner);
	pthread_mutex_unlock(&lock);
	return (result);
}

/* Consume NOTE_EXIT, including exits that preceded registration. */
static int
collect_workers(bool wait)
{
	struct kevent ev;
	struct timespec timeout = { .tv_sec = wait ? 5 : 0 };
	struct owned_worker **p, *w;
	int n;

	n = kevent(worker_kq, NULL, 0, &ev, 1, &timeout);
	if (n <= 0)
		return (n);
	for (p = &workers; (w = *p) != NULL; p = &w->next) {
		if ((uintptr_t)w->pd != ev.ident)
			continue;
		if ((ev.flags & EV_ERROR) != 0 || (ev.fflags & NOTE_EXIT) == 0)
			return (errno = EIO, -1);
		*p = w->next;
		close(w->pd);
		free(w);
		break;
	}
	return (1);
}

static int
stop_owner_locked(const char *owner) __requires_exclusive(lock)
{
	bool found;

	while (forking)
		pthread_cond_wait(&wake, &lock);
	if (tracking_failed)
		return (errno = EIO, -1);

	for (struct owned_worker *w = workers; w != NULL; w = w->next)
		if (strcmp(w->owner, owner) == 0 &&
		    pdkill(w->pd, SIGKILL) == -1 && errno != ESRCH)
			return (-1);
	for (;;) {
		found = false;
		for (struct owned_worker *w = workers; w != NULL; w = w->next)
			if (strcmp(w->owner, owner) == 0)
				found = true;
		if (!found)
			return (0);
		if (collect_workers(true) <= 0)
			return (errno = ETIMEDOUT, -1);
	}
}

static void *
reclaim_thread(void *unused __unused)
{
	struct retirement *r;
	int status;

	pthread_mutex_lock(&lock);
	for (;;) {
		for (r = retirements; r != NULL && !r->pending; r = r->next)
			;
		if (r == NULL) {
			pthread_cond_wait(&wake, &lock);
			continue;
		}
		r->pending = false;
		status = r->complete ? 0 :
		    (stop_owner_locked(r->message.owner) == -1 ? errno : 0);
		pthread_mutex_unlock(&lock);
		if (status == 0 && !r->complete) {
			status = handler(r->message.owner, handler_context);
			if (status < 0 || status > ELAST)
				status = EIO;
		}
		pthread_mutex_lock(&lock);
		if (status == 0)
			r->complete = true;
		pthread_mutex_unlock(&lock);
		(void)service_reclaim_send_result(&r->message, status);
		pthread_mutex_lock(&lock);
	}
}

int
service_set_reclaim_handler(int (*fn)(const char *, void *), void *context)
{
	pthread_t thread;
	int error;

	pthread_mutex_lock(&lock);
	if (started || fn == NULL) {
		pthread_mutex_unlock(&lock);
		return (errno = EINVAL, -1);
	}
	worker_kq = kqueue();
	if (worker_kq == -1 ||
	    cap_clofork_limit(worker_kq, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(worker_kq, CAP_CLOEXEC_LOCKED) == -1 ||
	    cap_xfer_limit(worker_kq, CAP_XFER_NONE) == -1) {
		error = errno;
		if (worker_kq >= 0)
			close(worker_kq);
		worker_kq = -1;
		pthread_mutex_unlock(&lock);
		return (errno = error, -1);
	}
	handler = fn;
	handler_context = context;
	error = pthread_create(&thread, NULL, reclaim_thread, NULL);
	if (error != 0) {
		close(worker_kq);
		worker_kq = -1;
		handler = NULL;
		pthread_mutex_unlock(&lock);
		return (errno = error, -1);
	}
	pthread_detach(thread);
	started = true;
	pthread_mutex_unlock(&lock);
	return (0);
}

bool
service_reclaim_registered(void)
{
	bool value;

	pthread_mutex_lock(&lock);
	value = started;
	pthread_mutex_unlock(&lock);
	return (value);
}

int
service_reclaim_enqueue(const struct svc_reclaim_label_msg *message)
{
	struct retirement *r;

	pthread_mutex_lock(&lock);
	if (!started) {
		pthread_mutex_unlock(&lock);
		return (errno = ENOTSUP, -1);
	}
	for (r = retirements; r != NULL; r = r->next)
		if (memcmp(r->message.generation, message->generation, 16) == 0 &&
		    strcmp(r->message.label, message->label) == 0)
			break;
	if (r == NULL) {
		r = calloc(1, sizeof(*r));
		if (r == NULL) {
			pthread_mutex_unlock(&lock);
			return (-1);
		}
		r->message = *message;
		r->next = retirements;
		retirements = r;
	} else if (strcmp(r->message.owner, message->owner) != 0) {
		pthread_mutex_unlock(&lock);
		return (errno = EPROTO, -1);
	}
	r->pending = true;
	pthread_cond_signal(&wake);
	pthread_mutex_unlock(&lock);
	return (0);
}

pid_t
service_reclaim_fork(const char *owner) __no_lock_analysis
{
	struct owned_worker *w;
	struct kevent ev;
	pid_t pid;
	int error, collected;

	if (!sl_label_valid(owner))
		return (errno = EINVAL, -1);
	pthread_mutex_lock(&lock);
	while (forking)
		pthread_cond_wait(&wake, &lock);
	if (!started || tracking_failed || retired_locked(owner)) {
		pthread_mutex_unlock(&lock);
		return (errno = ESTALE, -1);
	}
	while ((collected = collect_workers(false)) > 0)
		;
	if (collected < 0) {
		error = errno;
		tracking_failed = true;
		pthread_mutex_unlock(&lock);
		return (errno = error, -1);
	}
	w = calloc(1, sizeof(*w));
	if (w == NULL) {
		pthread_mutex_unlock(&lock);
		return (-1);
	}
	strlcpy(w->owner, owner, sizeof(w->owner));
	/*
	 * atfork handlers may take libservice locks used by event dispatch.
	 * Omit PD_DAEMON: provider death must also terminate its workers, so
	 * a restarted provider never acknowledges cleanup over orphan sessions.
	 */
	forking = true;
	pthread_mutex_unlock(&lock);
	pid = pdfork(&w->pd, PD_CLOEXEC);
	if (pid == 0) {
		/* No parent-owned descriptors survive this fork. */
		workers = NULL;
		retirements = NULL;
		started = false;
		worker_kq = -1;
		forking = false;
		lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
		return (0);
	}
	error = errno;
	pthread_mutex_lock(&lock);
	forking = false;
	pthread_cond_broadcast(&wake);
	if (pid == -1) {
		free(w);
		pthread_mutex_unlock(&lock);
		return (errno = error, -1);
	}
	EV_SET(&ev, w->pd, EVFILT_PROCDESC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, NULL);
	if (cap_clofork_limit(w->pd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(w->pd, CAP_CLOEXEC_LOCKED) == -1 ||
	    cap_xfer_limit(w->pd, CAP_XFER_NONE) == -1 ||
	    kevent(worker_kq, &ev, 1, NULL, 0, NULL) == -1) {
		error = errno;
		tracking_failed = true;
		(void)pdkill(w->pd, SIGKILL);
		close(w->pd);
		free(w);
		pthread_mutex_unlock(&lock);
		return (errno = error, -1);
	}
	w->next = workers;
	workers = w;
	pthread_mutex_unlock(&lock);
	return (pid);
}
