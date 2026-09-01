/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * tzfsctl(8) — operator/inspector CLI for the tzfsd(8) storage daemon.
 *
 *   tzfsctl ping
 *   tzfsctl request [-l persistent|cache|boot|lease] [-r rights] [-m] name
 *   tzfsctl release name
 *
 * request drives the same path a service does: it asks tzfsd for a handle,
 * prints the resolved dataset, and (with -m) mounts it and prints the
 * directory it landed on before exiting (which unmounts/closes it — request
 * is a demonstration/health tool, not a way to hold storage open).
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <trustedzfs.h>
#include "tzfsd.h"

static const struct {
	const char	*name;
	uint64_t	 bit;
} rightnames[] = {
	{ "props_read", ZH_PROPS_READ }, { "props_write", ZH_PROPS_WRITE },
	{ "snapshot", ZH_SNAPSHOT }, { "snap_destroy", ZH_SNAP_DESTROY },
	{ "clone_src", ZH_CLONE_SRC }, { "create", ZH_CREATE },
	{ "destroy", ZH_DESTROY }, { "mount", ZH_MOUNT },
};

static uint64_t
parse_rights(const char *s)
{
	char buf[256], *p, *tok;
	uint64_t mask = 0;
	unsigned i;

	if (strcmp(s, "all") == 0 || strcmp(s, "*") == 0)
		return (ZH_ALL_RIGHTS);
	(void)strlcpy(buf, s, sizeof(buf));
	p = buf;
	while ((tok = strsep(&p, ",")) != NULL) {
		if (*tok == '\0')
			continue;
		for (i = 0; i < nitems(rightnames); i++)
			if (strcmp(tok, rightnames[i].name) == 0) {
				mask |= rightnames[i].bit;
				break;
			}
		if (i == nitems(rightnames))
			errx(1, "unknown right: %s", tok);
	}
	return (mask);
}

static int
cmd_request(int chan, int argc, char **argv)
{
	struct tzfsd_req req;
	struct tzfsd_grant grant;
	const char *rights = "mount,props_read";
	uint8_t lifetime = TZFSD_LEASE;
	bool domount = false;
	int ch;

	optind = 1;
	while ((ch = getopt(argc, argv, "l:r:m")) != -1) {
		switch (ch) {
		case 'r': rights = optarg; break;
		case 'm': domount = true; break;
		case 'l':
			if (strcmp(optarg, "persistent") == 0)
				lifetime = TZFSD_PERSISTENT;
			else if (strcmp(optarg, "cache") == 0)
				lifetime = TZFSD_CACHE;
			else if (strcmp(optarg, "boot") == 0)
				lifetime = TZFSD_BOOT;
			else if (strcmp(optarg, "lease") == 0)
				lifetime = TZFSD_LEASE;
			else
				errx(1, "lifetime must be persistent|cache|boot|lease");
			break;
		default:
			errx(1, "usage: tzfsctl request "
			    "[-l lifetime] [-r rights] [-m] name");
		}
	}
	if (optind >= argc)
		errx(1, "request: missing name");

	memset(&req, 0, sizeof(req));
	(void)strlcpy(req.dataset, argv[optind], sizeof(req.dataset));
	req.rights = parse_rights(rights);
	req.lifetime = lifetime;
	if (domount)
		req.rights |= ZH_MOUNT;

	if (tzfsd_request(chan, &req, &grant) == -1)
		err(1, "request %s", argv[optind]);
	printf("granted %s (lifetime=%u)\n", grant.dataset, lifetime);

	if (domount) {
		int dir = tzfsd_mount_dir(grant.handle_fd, 0);

		if (dir == -1)
			warn("mount");
		else {
			printf("mounted (dirfd %d)\n", dir);
			(void)close(dir);
		}
	}
	(void)close(grant.handle_fd);
	return (0);
}

static int
cmd_release(int chan, int argc, char **argv)
{
	if (argc < 2)
		errx(1, "release: missing name");
	if (tzfsd_release(chan, argv[1]) == -1)
		err(1, "release %s", argv[1]);
	printf("released %s\n", argv[1]);
	return (0);
}

int
main(int argc, char **argv)
{
	int chan, rc;

	if (argc < 2) {
		fprintf(stderr, "usage: tzfsctl <ping|request|"
		    "release> [args]\n");
		return (1);
	}
	chan = tzfsd_connect();
	if (chan == -1)
		err(1, "connect %s", TZFSD_SOCK_PATH);

	if (strcmp(argv[1], "ping") == 0) {
		rc = tzfsd_ping(chan);
		printf("%s\n", rc == 0 ? "ok" : "no response");
	} else if (strcmp(argv[1], "request") == 0)
		rc = cmd_request(chan, argc - 1, argv + 1);
	else if (strcmp(argv[1], "release") == 0)
		rc = cmd_release(chan, argc - 1, argv + 1);
	else
		errx(1, "unknown command: %s", argv[1]);

	(void)close(chan);
	return (rc == 0 ? 0 : 1);
}
