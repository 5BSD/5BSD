/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

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

/*
 * Modules to try: small, without dependencies, and unloadable when nothing
 * uses them.  Two families are deliberately absent because they load but
 * do not unload, so a test that tried them first neither saw the event nor
 * took the module out again: filemon(4), whose MOD_QUIESCE handler always
 * answers EBUSY, and the accept filters, which answer EOPNOTSUPP unless
 * net.inet.accf.unloadable is set.
 */
static const char *test_modules[] = {
	"if_disc",
	"nullfs",
	NULL
};

/* The event names the file ("accf_data.ko"), the test the module. */
static int
kld_name_matches(const char *name, const char *modname)
{
	size_t len = strlen(modname);

	return (strncmp(name, modname, len) == 0 &&
	    (name[len] == '\0' || strcmp(name + len, ".ko") == 0));
}

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
			    kld_name_matches(msg->em_event_data.kldunload.name,
			    expected_name)) {
				*kldunload_seen = 1;
			} else if (expected_name == NULL) {
				*kldunload_seen = 1;
			}
		}
	}
}

/*
 * In the actor: load a module that is not loaded yet and unload it again.
 * One that loads but will not unload is left and the next one tried.
 * Exits with 1 + the index of the module it unloaded, or 0.
 */
static int
load_unload(void *arg __unused)
{
	const char *modname;
	int fileid, i;

	for (i = 0; test_modules[i] != NULL; i++) {
		modname = test_modules[i];

		if (kldfind(modname) >= 0) {
			fprintf(stderr, "  %s: already loaded, not ours to "
			    "unload\n", modname);
			continue;
		}
		fileid = kldload(modname);
		if (fileid < 0) {
			fprintf(stderr, "  %s: kldload: %s (errno=%d)\n",
			    modname, strerror(errno), errno);
			continue;
		}
		fprintf(stderr, "  loaded %s (fileid=%d)\n", modname, fileid);
		if (kldunload(fileid) == 0)
			return (i + 1);
		fprintf(stderr, "  %s: kldunload: %s (errno=%d)\n", modname,
		    strerror(errno), errno);
	}
	return (0);
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
	int unloaded = 0, status;
	const char *modname = NULL;
	pid_t actor;

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
	/*
	 * The unload is done by an actor child: the test opened the client,
	 * so its own events never reach it (oes(4)).
	 */
	actor = test_in_child(load_unload, NULL, &status);
	if (actor > 0 && WIFEXITED(status) && WEXITSTATUS(status) != 0) {
		unloaded = 1;
		modname = test_modules[WEXITSTATUS(status) - 1];
	}

	if (!unloaded) {
		int securelevel = -1;
		size_t len = sizeof(securelevel);

		/* A raised securelevel forbids both calls to everybody. */
		(void)sysctlbyname("kern.securelevel", &securelevel, &len,
		    NULL, 0);
		close(fd);
		if (securelevel > 0) {
			printf("SKIP: securelevel %d forbids loading and "
			    "unloading modules\n", securelevel);
			return (0);
		}
		fprintf(stderr, "FAIL: no test module could be loaded and "
		    "unloaded\n");
		return (1);
	}

	fprintf(stderr, "  unloaded %s\n", modname);

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

	close(fd);

	if (!kldunload_seen) {
		fprintf(stderr, "FAIL: NOTIFY_KLDUNLOAD not received\n");
		return (1);
	}

	printf("  PASS: NOTIFY_KLDUNLOAD received\n");
	printf("kldunload event: ok\n");
	return (0);
}
