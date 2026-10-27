/* SPDX-License-Identifier: BSD-2-Clause */
/* Controlled failure only. Never compiled into the installed provider. */
#include <sys/types.h>
#include <sys/event.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int bsdfilesystem_crash_test_watch(int);
void bsdfilesystem_crash_test_event(const struct kevent *);
void bsdfilesystem_crash_test_request(void);

static int trigger[2] = {-1, -1};
static int event_identity;

int
bsdfilesystem_crash_test_watch(int kq)
{
	struct kevent event;
	int saved;
	if (pipe2(trigger, O_CLOEXEC) == -1) return (-1);
	EV_SET(&event, trigger[0], EVFILT_READ, EV_ADD, 0, 0, &event_identity);
	if (kevent(kq, &event, 1, NULL, 0, NULL) == 0) return (0);
	saved = errno;
	close(trigger[0]); close(trigger[1]);
	trigger[0] = trigger[1] = -1;
	return (errno = saved, -1);
}

void
bsdfilesystem_crash_test_event(const struct kevent *event)
{
	char byte;
	if (event->filter == EVFILT_READ && event->udata == &event_identity &&
	    event->ident == (uintptr_t)trigger[0] && read(trigger[0], &byte, 1) == 1)
		_exit(75); /* Abrupt parent exit: no provider cleanup path. */
}

void
bsdfilesystem_crash_test_request(void)
{
	ssize_t result;
	do { result = write(trigger[1], "x", 1); } while (result == -1 && errno == EINTR);
	if (result != 1) _exit(76);
	/* Keep the requesting worker alive with its grants and pending reply.
	 * Only the parent crashes. Its process-descriptor and supervisor cleanup
	 * must retire this worker; the fixture does not clean it up itself. */
	for (;;) pause();
}
