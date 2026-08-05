/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include <filesystemcmp.h>

static void usage(void) __dead2;

static void
usage(void)
{

	fprintf(stderr,
	    "usage: filesystemcmpctl config\n"
	    "       filesystemcmpctl info\n"
	    "       filesystemcmpctl stat namespace path\n");
	exit(EX_USAGE);
}

static uint32_t
parse_namespace(const char *name)
{

	if (strcmp(name, "scratch") == 0)
		return (FILESYSTEMCMP_NAMESPACE_SCRATCH);
	if (strcmp(name, "persistent") == 0)
		return (FILESYSTEMCMP_NAMESPACE_PERSISTENT);
	if (strcmp(name, "bundle") == 0)
		return (FILESYSTEMCMP_NAMESPACE_BUNDLE);
	errx(EX_USAGE, "invalid namespace: %s", name);
}

static struct filesystemcmp_client *
open_client(void)
{
	struct filesystemcmp_client *client;

	if (filesystemcmp_open(&client) == -1)
		err(EX_UNAVAILABLE, "open %s", FILESYSTEMCMP_INTERFACE);
	return (client);
}

static int
info(void)
{
	struct filesystemcmp_hello_reply hello;
	struct filesystemcmp_client *client;

	client = open_client();
	if (filesystemcmp_hello(client, &hello) == -1) {
		int error = errno;

		filesystemcmp_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "hello");
	}
	filesystemcmp_close(client);
	printf("version=%u features=0x%08x max_bytes=%" PRIu64
	    " max_objects=%" PRIu64 "\n", hello.version, hello.features,
	    hello.max_bytes, hello.max_objects);
	return (0);
}

static int
stat_path(const char *namespace_name, const char *path)
{
	struct filesystemcmp_path_context *context;
	struct filesystemcmp_handle_reply object;
	struct filesystemcmp_stat_reply status;
	uint32_t namespace_id;

	namespace_id = parse_namespace(namespace_name);
	if (filesystemcmp_path_context_open(namespace_id, &context) == -1)
		err(EX_UNAVAILABLE, "open %s namespace", namespace_name);
	if (filesystemcmp_path_lookup(context, path, &object) == -1) {
		int error = errno;

		filesystemcmp_path_context_close(context);
		errno = error;
		err(EX_NOINPUT, "%s", path);
	}
	if (filesystemcmp_path_stat(context, object.handle, &status) == -1) {
		int error = errno;

		(void)filesystemcmp_path_close_handle(context, object.handle);
		filesystemcmp_path_context_close(context);
		errno = error;
		err(EX_IOERR, "stat %s", path);
	}
	if (filesystemcmp_path_close_handle(context, object.handle) == -1) {
		int error = errno;

		filesystemcmp_path_context_close(context);
		errno = error;
		err(EX_IOERR, "close %s", path);
	}
	filesystemcmp_path_context_close(context);
	printf("namespace=%s path=%s type=%u mode=%#o size=%" PRIu64
	    " inode=%" PRIu64 " modified_sec=%" PRIu64 "\n",
	    namespace_name, path, status.type, status.mode, status.size,
	    status.inode, status.modified_sec);
	return (0);
}

int
main(int argc, char **argv)
{

	if (argc == 2 && strcmp(argv[1], "config") == 0) {
		puts("components = [\"filesystem\"];");
		return (0);
	}
	if (argc == 2 && strcmp(argv[1], "info") == 0)
		return (info());
	if (argc == 4 && strcmp(argv[1], "stat") == 0)
		return (stat_path(argv[2], argv[3]));
	usage();
}
