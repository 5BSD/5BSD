/*
 * OES kldunload event test.
 *
 * Tests NOTIFY_KLDUNLOAD event by loading and unloading a kernel module.
 * Requires root privileges.
 */
#include <sys/ioctl.h>
#include <sys/linker.h>
#include <sys/poll.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <security/oes/oes.h>
#include "test_common.h"

/* Modules to try - must be loadable and unloadable */
static const char *test_modules[] = {
	"filemon",	/* File monitoring for make(1) - usually safe */
	"accf_data",
	"accf_http",
	NULL
};

static int
read_events(int fd, int *kldunload_seen, const char *expected_name)
{
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;

	for (;;) {
		if (test_wait_event(fd, msg, 10) != 0)
			return (0);

		if (msg->em_event == OES_EVENT_NOTIFY_KLDUNLOAD) {
			fprintf(stderr, "  got NOTIFY_KLDUNLOAD: name=%s\n",
			    msg->em_event_data.kldunload.name);
			if (expected_name != NULL &&
			    strcmp(msg->em_event_data.kldunload.name,
			    expected_name) == 0) {
				*kldunload_seen = 1;
			} else if (expected_name == NULL) {
				*kldunload_seen = 1;
			}
		}
	}
}

int
main(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = {
		OES_EVENT_NOTIFY_KLDUNLOAD,
	};
	int kldunload_seen = 0;
	struct pollfd pfd;
	struct timespec start;
	int fileid = -1;
	int was_loaded = 0;
	const char *modname = NULL;
	int i;

	printf("Testing NOTIFY_KLDUNLOAD event...\n");

	if (geteuid() != 0) {
		printf("SKIP: test requires root\n");
		return (0);
	}

	/* Print securelevel for diagnostic purposes */
	{
		int securelevel;
		size_t len = sizeof(securelevel);
		if (sysctlbyname("kern.securelevel", &securelevel, &len,
		    NULL, 0) == 0) {
			fprintf(stderr, "  securelevel=%d\n", securelevel);
		}
	}

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = sizeof(events) / sizeof(events[0]);
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	/* Try each module until we find one we can load */
	for (i = 0; test_modules[i] != NULL; i++) {
		modname = test_modules[i];

		/* Check if module is already loaded - skip it, we need fresh load */
		fileid = kldfind(modname);
		if (fileid >= 0) {
			fprintf(stderr, "  %s: already loaded, skipping\n", modname);
			fileid = -1;  /* Reset so we try next module */
			continue;
		}

		/* Try to load it */
		fileid = kldload(modname);
		if (fileid >= 0) {
			fprintf(stderr, "  loaded %s (fileid=%d)\n", modname, fileid);
			was_loaded = 0;
			break;
		}
		/* EEXIST means compiled into kernel, skip to next */
		if (errno == EEXIST) {
			fprintf(stderr, "  %s: compiled into kernel\n", modname);
		} else {
			fprintf(stderr, "  %s: %s (errno=%d)\n",
			    modname, strerror(errno), errno);
		}
	}

	if (fileid < 0) {
		printf("SKIP: cannot load any test module\n");
		close(fd);
		return (0);
	}

	fprintf(stderr, "  using module: %s (fileid=%d)\n", modname, fileid);

	/* Unload - this should trigger the event */
	if (kldunload(fileid) < 0) {
		int err = errno;
		if (err == EPERM || err == ENOTSUP || err == EOPNOTSUPP) {
			fprintf(stderr, "  kldunload failed: %s (errno=%d)\n",
			    strerror(err), err);
			printf("SKIP: kldunload not permitted\n");
			close(fd);
			return (0);
		}
		if (errno == EBUSY) {
			fprintf(stderr, "  %s is busy, trying next module\n", modname);
			/* Module is in use, can't test with it */
			printf("SKIP: all available modules are in use\n");
			close(fd);
			return (0);
		}
		perror("kldunload");
		close(fd);
		return (1);
	}

	/* Wait for and read events */
	clock_gettime(CLOCK_MONOTONIC, &start);
	pfd.fd = fd;
	pfd.events = POLLIN;

	while (1) {
		struct timespec now;
		long elapsed_ms;

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
		    (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms > 2000)
			break;

		if (poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
			if (read_events(fd, &kldunload_seen, modname) < 0) {
				close(fd);
				return (1);
			}
		}

		if (kldunload_seen)
			break;
	}

	/* Reload module if it was loaded before the test */
	if (was_loaded) {
		(void)kldload(modname);
	}

	close(fd);

	if (!kldunload_seen) {
		fprintf(stderr, "FAIL: NOTIFY_KLDUNLOAD not received\n");
		return (1);
	}

	printf("  PASS: NOTIFY_KLDUNLOAD received\n");
	printf("kldunload event: ok\n");
	return (0);
}
