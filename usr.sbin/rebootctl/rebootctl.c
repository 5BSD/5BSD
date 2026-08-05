/*- SPDX-License-Identifier: BSD-2-Clause */

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include <rebootctl.h>

#include "rebootd_policy.h"

static void usage(void) __dead2;

static void
usage(void)
{
	fprintf(stderr, "usage: rebootctl configtest [file]\n"
	    "       rebootctl status\n"
	    "       rebootctl cancel\n"
	    "       rebootctl reboot [delay-seconds]\n"
	    "       rebootctl reroot [delay-seconds]\n"
	    "       rebootctl shutdown [delay-seconds]\n");
	exit(EX_USAGE);
}

int
main(int argc, char **argv)
{
	struct rebootd_policy policy;
	struct rebootctl_client *client;
	const char *path;
	struct rebootctl_status_reply status;
	const char *errstr;
	uint32_t delay_ms;
	long long delay;
	int error;

	if (argc >= 2 && strcmp(argv[1], "configtest") == 0 && argc <= 3) {
		path = argc == 3 ? argv[2] : REBOOTD_POLICY_PATH;
		if (rebootd_policy_load(path, &policy) == -1)
			err(EX_DATAERR, "%s", path);
		printf("%s: valid (labels=%zu, default=%s)\n", path, policy.count,
		    policy.count == 0 ? "deny" : "explicit-allow");
		return (0);
	}
	if (argc == 2 && strcmp(argv[1], "status") == 0) {
		if (rebootctl_client_open(&client) == -1)
			err(EX_UNAVAILABLE, "open %s", REBOOTCTL_INTERFACE);
		if (rebootctl_status_detailed(client, &status) == -1) {
			error = errno;

			rebootctl_client_close(client);
			errno = error;
			err(EX_UNAVAILABLE, "status");
		}
		rebootctl_client_close(client);
		printf("pending=%s request_id=%" PRIu64
		    " requested_at_ns=%" PRIu64 " execute_at_ns=%" PRIu64
		    " howto=%u\n", status.pending ? "yes" : "no",
		    status.request_id, status.requested_at_ns,
		    status.execute_at_ns, status.howto);
		return (status.pending ? 1 : 0);
	}
	if (argc == 2 && strcmp(argv[1], "cancel") == 0) {
		if (rebootctl_client_open(&client) == -1)
			err(EX_UNAVAILABLE, "open %s", REBOOTCTL_INTERFACE);
		if (rebootctl_cancel(client) == -1) {
			error = errno;
			rebootctl_client_close(client);
			errno = error;
			err(EX_UNAVAILABLE, "cancel");
		}
		rebootctl_client_close(client);
		printf("cancelled=yes\n");
		return (0);
	}
	if ((argc == 2 || argc == 3) && (strcmp(argv[1], "reboot") == 0 ||
	    strcmp(argv[1], "reroot") == 0 ||
	    strcmp(argv[1], "shutdown") == 0)) {
		delay_ms = REBOOTCTL_DEFAULT_DELAY_MS;
		if (argc == 3) {
			delay = strtonum(argv[2], 0,
			    REBOOTCTL_MAX_DELAY_MS / 1000, &errstr);
			if (errstr != NULL)
				errx(EX_USAGE, "delay-seconds is %s: %s", errstr,
				    argv[2]);
			delay_ms = (uint32_t)delay * 1000;
		}
		if (rebootctl_client_open(&client) == -1)
			err(EX_UNAVAILABLE, "open %s", REBOOTCTL_INTERFACE);
		if ((strcmp(argv[1], "shutdown") == 0 ?
		    rebootctl_shutdown_after(client, delay_ms) :
		    rebootctl_reboot_after(client,
		    strcmp(argv[1], "reroot") == 0 ? RB_REROOT : 0,
		    delay_ms)) == -1) {
			error = errno;
			rebootctl_client_close(client);
			errno = error;
			err(EX_UNAVAILABLE, "%s", argv[1]);
		}
		rebootctl_client_close(client);
		printf("requested=%s\n", argv[1]);
		return (0);
	}
	usage();
}
