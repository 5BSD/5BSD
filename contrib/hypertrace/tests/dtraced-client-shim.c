/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Preloaded by dtraced-client.py for the session scenario: scripts the
 * process-descriptor birth identity so its malformed cases can be tested.
 * Only pdself(), pdopenpid(getpid()) and PDIOC_GET_BIRTH_IDENTITY on the
 * placeholder descriptor are affected, and only after dtc_birth_set(1, ...).
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/procdesc.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define	BIRTH_SEC	0x0102030405060708ULL
#define	BIRTH_USEC	123456ULL

static int interposed, birth_fd = -1, mode;

void
dtc_birth_set(int on, int m)
{
	interposed = on;
	mode = m;
}

int
pdself(int *fdp, int flags)
{
	static int (*real)(int *, int);

	if (!interposed) {
		if (real == NULL)
			real = (int (*)(int *, int))dlsym(RTLD_NEXT, "pdself");
		return (real(fdp, flags));
	}
	*fdp = birth_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	return (*fdp < 0 ? -1 : 0);
}

/* The ambient test process names itself with pdopenpid(2) (pdself(2) is
 * capability-mode only): scripted the same way once interposed. */
int
pdopenpid(pid_t pid, int flags)
{
	static int (*real)(pid_t, int);

	if (!interposed || pid != getpid()) {
		if (real == NULL)
			real = (int (*)(pid_t, int))dlsym(RTLD_NEXT,
			    "pdopenpid");
		return (real(pid, flags));
	}
	return (birth_fd = open("/dev/null", O_RDONLY | O_CLOEXEC));
}

int
ioctl(int fd, unsigned long request, ...)
{
	static int (*real)(int, unsigned long, ...);
	struct pd_birth_identity *b;
	va_list ap;
	void *arg;

	va_start(ap, request);
	arg = va_arg(ap, void *);
	va_end(ap);
	if (interposed && fd == birth_fd &&
	    request == PDIOC_GET_BIRTH_IDENTITY) {
		b = arg;
		memset(b, 0, sizeof (*b));
		b->pid = getpid() + (mode == 1);
		b->start_sec = mode == 3 ? 0 : BIRTH_SEC;
		b->start_usec = mode == 3 ? 0 : mode == 2 ? 1000000 : BIRTH_USEC;
		b->reserved = mode == 4;
		return (0);
	}
	if (real == NULL)
		real = (int (*)(int, unsigned long, ...))dlsym(RTLD_NEXT,
		    "ioctl");
	return (real(fd, request, arg));
}
