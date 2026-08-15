/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * mount_virtiofs -- mount a virtio-fs shared directory.
 *
 * virtio-fs is FUSE-over-VirtIO, so the actual VFS is fusefs.  The virtio_fs(4)
 * transport publishes one /dev/virtiofsN character device per virtio-fs PCI
 * function; opening it creates an in-kernel FUSE session driven over the VirtIO
 * request queues.  This helper resolves the requested mount tag to that device
 * node, opens it, and hands the descriptor to the stock fusefs mount path
 * exactly as mount_fusefs(8) does for a userspace daemon.
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/uio.h>

#include <err.h>
#include <fcntl.h>
#include <mntopts.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

/*
 * A conservative default read bound.  The transport sizes a single reply
 * buffer per request; bounding max_read keeps each FUSE READ within one
 * descriptor chain.  Overridable with -o max_read=.
 */
#define	VIRTIOFS_DEFAULT_MAX_READ	131072

static struct mntopt mopts[] = {
	/* FUSE session options passed to fuse_vfsop_mount(). */
	{ "allow_other", 0, 0, 0 },
	{ "default_permissions", 0, 0, 0 },
	{ "intr", 0, 0, 0 },
	{ "push_symlinks_in", 0, 0, 0 },
	{ "auto_unmount", 0, 0, 0 },
	{ "max_read=", 0, 0, 0 },
	MOPT_STDOPTS,
	MOPT_END
};

/*
 * fusefs-specific flag options.  fuse_vfsop_mount() looks for each of these
 * (and its "__" prefixed twin); pass the underscored form so the kernel need
 * not re-parse the free-form option string.
 */
static const char *fuse_flags[] = {
	"allow_other",
	"default_permissions",
	"intr",
	"push_symlinks_in",
	"auto_unmount",
	NULL
};

static void	usage(void) __dead2;
static char	*resolve_tag(const char *tag);
static void	add_fuse_flags(struct iovec **, int *, const char *);
static char	*find_option_value(const char *, const char *);

int
main(int argc, char *argv[])
{
	struct iovec *iov = NULL;
	char *dev, *devbuf = NULL;
	char *mntpath, real_mntpath[MAXPATHLEN];
	char fdstr[16];
	char *tag;
	int ch, fd, iovlen = 0, mntflags = 0;
	char *max_read = NULL;
	char *options = NULL;

	while ((ch = getopt(argc, argv, "o:")) != -1) {
		switch (ch) {
		case 'o':
		{
			char *value;

			getmntopts(optarg, mopts, &mntflags, NULL);
			value = find_option_value(optarg, "max_read=");
			if (value != NULL) {
				free(max_read);
				max_read = value;
			}
			if (options == NULL)
				options = strdup(optarg);
			else {
				char *n;

				if (asprintf(&n, "%s,%s", options, optarg) < 0)
					err(EX_OSERR, "asprintf");
				free(options);
				options = n;
			}
			break;
		}
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (options == NULL)
		options = strdup("");

	if (argc != 2)
		usage();

	tag = argv[0];
	mntpath = argv[1];

	if (tag[0] == '/') {
		/* Explicit device node. */
		dev = tag;
	} else {
		devbuf = resolve_tag(tag);
		if (devbuf == NULL)
			errx(EX_USAGE, "no virtio-fs device with tag \"%s\"", tag);
		dev = devbuf;
	}

	if (realpath(mntpath, real_mntpath) == NULL)
		err(EX_USAGE, "%s", mntpath);
	mntpath = real_mntpath;

	if (checkpath(mntpath, real_mntpath) != 0)
		err(EX_USAGE, "%s", real_mntpath);

	fd = open(dev, O_RDWR);
	if (fd < 0)
		err(EX_OSERR, "%s", dev);
	snprintf(fdstr, sizeof(fdstr), "%d", fd);

	build_iovec(&iov, &iovlen, "fstype", __DECONST(void *, "fusefs"), -1);
	build_iovec(&iov, &iovlen, "fspath", mntpath, -1);
	build_iovec(&iov, &iovlen, "from", dev, -1);
	build_iovec(&iov, &iovlen, "fd", fdstr, -1);
	add_fuse_flags(&iov, &iovlen, options);
	if (max_read == NULL) {
		char mr[16];

		snprintf(mr, sizeof(mr), "%d", VIRTIOFS_DEFAULT_MAX_READ);
		build_iovec(&iov, &iovlen, "max_read=", mr, -1);
	} else {
		build_iovec(&iov, &iovlen, "max_read=", max_read, -1);
	}

	if (nmount(iov, iovlen, mntflags) < 0)
		err(EX_OSERR, "%s on %s", dev, mntpath);

	/*
	 * The FUSE session outlives this descriptor: once mounted, the
	 * virtio_fs(4) transport keeps serving the mount until it is
	 * unmounted, so there is no daemon to keep the fd open.
	 */
	close(fd);
	free(devbuf);
	free(max_read);
	free(options);
	return (0);
}

/*
 * For each recognised fusefs flag option present in the -o string, emit the
 * "__"-prefixed iovec that fuse_vfsop_mount() consumes.
 */
static void
add_fuse_flags(struct iovec **iov, int *iovlen, const char *options)
{
	char uscore[64];
	char *value;
	int i;

	for (i = 0; fuse_flags[i] != NULL; i++) {
		value = find_option_value(options, fuse_flags[i]);
		if (value == NULL)
			continue;
		free(value);
		snprintf(uscore, sizeof(uscore), "__%s", fuse_flags[i]);
		build_iovec(iov, iovlen, uscore, __DECONST(void *, ""), -1);
	}
}

/*
 * Return a copy of the value of an exact comma-delimited mount option.  A
 * flag option has an empty value, which lets add_fuse_flags() use this for
 * exact matching as well.  Do not use strstr(): for example, xallow_other
 * must not grant the allow_other session flag, and nomax_read must not
 * suppress the transport's bounded default.
 */
static char *
find_option_value(const char *options, const char *option)
{
	const char *end, *p;
	size_t option_len;

	if (options == NULL || option == NULL)
		return (NULL);
	option_len = strlen(option);
	for (p = options; *p != '\0'; p = end + 1) {
		end = strchr(p, ',');
		if (end == NULL)
			end = p + strlen(p);
		if ((size_t)(end - p) >= option_len &&
		    strncmp(p, option, option_len) == 0 &&
		    ((option[option_len - 1] == '=') ||
		    (size_t)(end - p) == option_len))
			return (strndup(p + option_len,
			    (size_t)(end - p) - option_len));
		if (*end == '\0')
			break;
	}
	return (NULL);
}

/*
 * Walk dev.virtio_fs.<unit>.tag until a match is found and return the
 * corresponding /dev/virtiofs<unit> path.
 */
static char *
resolve_tag(const char *tag)
{
	char oid[64], val[64];
	char *path;
	size_t len;
	int unit;

	for (unit = 0; unit < 256; unit++) {
		snprintf(oid, sizeof(oid), "dev.virtio_fs.%d.tag", unit);
		len = sizeof(val);
		if (sysctlbyname(oid, val, &len, NULL, 0) != 0)
			continue;
		if (strcmp(val, tag) != 0)
			continue;
		if (asprintf(&path, "/dev/virtiofs%d", unit) < 0)
			err(EX_OSERR, "asprintf");
		return (path);
	}
	return (NULL);
}

static void
usage(void)
{

	fprintf(stderr,
	    "usage: mount_virtiofs [-o options] tag | special node\n");
	exit(EX_USAGE);
}
