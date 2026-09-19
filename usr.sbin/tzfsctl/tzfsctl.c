/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * tzfsctl(8) — operator/inspector CLI for the bsdfilesystem(8) storage daemon.
 *
 *   tzfsctl ping
 *   tzfsctl request [-l persistent|cache|boot|lease] [-r rights] [-m] name
 *   tzfsctl release name
 *
 * request drives the same path a service does: it asks bsdfilesystem for a handle,
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
#include "bsdfilesystem.h"

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
	if (strlcpy(buf, s, sizeof(buf)) >= sizeof(buf))
		errx(1, "rights list is too long");
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
cmd_request(struct bsdfilesystem_client *chan, int argc, char **argv)
{
	struct bsdfilesystem_req req;
	struct bsdfilesystem_grant grant;
	const char *rights = "mount,props_read";
	uint8_t lifetime = BSDFILESYSTEM_LEASE;
	bool domount = false;
	int ch;

	optind = 1;
	while ((ch = getopt(argc, argv, "l:r:m")) != -1) {
		switch (ch) {
		case 'r': rights = optarg; break;
		case 'm': domount = true; break;
		case 'l':
			if (strcmp(optarg, "persistent") == 0)
				lifetime = BSDFILESYSTEM_PERSISTENT;
			else if (strcmp(optarg, "cache") == 0)
				lifetime = BSDFILESYSTEM_CACHE;
			else if (strcmp(optarg, "boot") == 0)
				lifetime = BSDFILESYSTEM_BOOT;
			else if (strcmp(optarg, "lease") == 0)
				lifetime = BSDFILESYSTEM_LEASE;
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
	if (optind + 1 != argc)
		errx(1, "request: too many names");

	memset(&req, 0, sizeof(req));
	if (strlcpy(req.dataset, argv[optind], sizeof(req.dataset)) >=
	    sizeof(req.dataset))
		errx(1, "request: dataset name is too long");
	req.rights = parse_rights(rights);
	req.lifetime = lifetime;
	if (domount)
		req.rights |= ZH_MOUNT;

	if (bsdfilesystem_request(chan, &req, &grant) == -1)
		err(1, "request %s", argv[optind]);
	printf("granted %s (lifetime=%u)\n", grant.dataset, lifetime);

	if (domount) {
		int dir = bsdfilesystem_mount_dir(grant.handle_fd, 0);

		if (dir == -1) {
			warn("mount");
			(void)close(grant.handle_fd);
			return (-1);
		}
		printf("mounted (dirfd %d)\n", dir);
		(void)close(dir);
	}
	(void)close(grant.handle_fd);
	return (0);
}

static int
cmd_release(struct bsdfilesystem_client *chan, int argc, char **argv)
{
	if (argc != 2)
		errx(1, "release: expected one name");
	if (bsdfilesystem_release(chan, argv[1]) == -1)
		err(1, "release %s", argv[1]);
	printf("released %s\n", argv[1]);
	return (0);
}

int
main(int argc, char **argv)
{
	struct bsdfilesystem_client *chan;
	int rc;

	if (argc < 2) {
		fprintf(stderr, "usage: tzfsctl <ping|request|"
		    "release> [args]\n");
		return (1);
	}
	if (strcmp(argv[1], "ping") == 0 && argc != 2)
		errx(1, "ping: too many arguments");
	if (strcmp(argv[1], "release") == 0 && argc != 3)
		errx(1, "release: expected one name");
	if (strcmp(argv[1], "ping") != 0 &&
	    strcmp(argv[1], "request") != 0 &&
	    strcmp(argv[1], "release") != 0)
		errx(1, "unknown command: %s", argv[1]);

	chan = bsdfilesystem_connect();
	if (chan == NULL)
		err(1, "connect %s", BSDFILESYSTEM_SERVICE_NAME);

	if (strcmp(argv[1], "ping") == 0) {
		rc = bsdfilesystem_ping(chan);
		printf("%s\n", rc == 0 ? "ok" : "no response");
	} else if (strcmp(argv[1], "request") == 0)
		rc = cmd_request(chan, argc - 1, argv + 1);
	else
		rc = cmd_release(chan, argc - 1, argv + 1);

	bsdfilesystem_close(chan);
	return (rc == 0 ? 0 : 1);
}
