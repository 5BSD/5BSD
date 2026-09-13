/* SPDX-License-Identifier: BSD-2-Clause */
/* Managed client of the five production private-resource providers. */
#include <sys/types.h>
#include <sys/cryptodesc.h>
#include <sys/zfshandle.h>
#include <opencrypto/cryptodev.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libservice.h>
#include <tzfsd.h>
#include <cryptocmp.h>
#include <logcmp.h>
#include <warden_proto.h>
#include <vmd_proto.h>

static FILE *output;
#define REQUIRE(expr) do { if (!(expr)) { \
    fprintf(output, "FAIL line=%d errno=%d (%s)\n", __LINE__, errno, strerror(errno)); \
    fflush(output); return (1); } } while (0)

static int
request(struct service_context *ctx, const char *name, const void *data,
    size_t length, void *reply, size_t capacity, int *descriptor)
{
	struct service_session *session;
	struct service_message out = { .size = sizeof(out), .data = data, .length = length };
	struct service_reply in = { .size = sizeof(in), .data = reply, .capacity = capacity,
	    .fds = descriptor, .fd_capacity = descriptor != NULL ? 1 : 0 };
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct timespec started, finished;
	int fd, result, error;
	const char *stage;

	/* Match service_storage_open(): ZFS creation can span several syncs.
	 * The qualification harness bounds resource readiness for this process. */
	if (strcmp(name, TZFSD_SERVICE_NAME) != 0)
		options.timeout_ms = 10000;
	if (clock_gettime(CLOCK_MONOTONIC, &started) == -1)
		return (-1);
	stage = "connect";
	result = service_connect(ctx, name, &fd);
	if (result == 0) {
		stage = "session";
		result = service_session_create(fd, &session);
	}
	if (result == 0) {
		stage = "call";
		result = service_session_call(session, &out, &in, &options);
	}
	error = result == -1 ? errno : 0;
	if (clock_gettime(CLOCK_MONOTONIC, &finished) == -1)
		return (-1);
	fprintf(output, "request service=%s stage=%s result=%d errno=%d elapsed_ms=%jd\n",
	    name, stage, result, error,
	    (intmax_t)(finished.tv_sec - started.tv_sec) * 1000 +
	    (finished.tv_nsec - started.tv_nsec) / 1000000);
	if (result == -1)
		return (errno = error, -1);
	/* Keep the sessions and descriptors alive until the manager stops us. */
	if (result == 0 && in.length < sizeof(int32_t))
		return (errno = EPROTO, -1);
	if (result == 0 && *(int32_t *)reply != 0)
		return (errno = *(int32_t *)reply, -1);
	if (result == 0 && (in.length != capacity ||
	    in.nfds != (descriptor != NULL ? 1u : 0u)))
		return (errno = EPROTO, -1);
	return (result);
}

int
main(int argc, char **argv)
{
	struct service_context *ctx;
	struct service_provider *provider;
	struct tzfsd_request claim = { .op = TZFSD_OP_REQUEST,
	    .dataset = "cleanup", .rights = ZH_MOUNT,
	    .deliver = TZFSD_DELIVER_MOUNTED, .lifetime = TZFSD_PERSISTENT };
	struct tzfsd_reply grant;
	struct cryptocmp_client *crypto;
	struct cryptocmp_generate generate = { .cipher = CRYPTO_AES_CBC, .keylen = 32,
	    .rights = CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_DECRYPT,
	    .crid = CRYPTO_FLAG_SOFTWARE, .ivlen = 16 };
	struct logcmp_client *logs;
	struct logcmp_logger *logger;
	struct logcmp_emit_options event = { .size = sizeof(event),
	    .severity = LOGCMP_SEVERITY_INFO, .kind = LOGCMP_KIND_LOG,
	    .message_privacy = LOGCMP_PRIVACY_PUBLIC, .message = "installation cleanup fixture" };
	struct warden_request jail = { .op = WARDEN_OP_ENTER_JAIL };
	struct warden_reply jail_reply;
	struct vmd_request window = { .op = VMD_OP_VSOCK_BIND, .backlog = 1 };
	struct vmd_reply window_reply;
	uint64_t generation;
	int results, fd, directory, file, lease, jailfd, vsockfd, heartbeat;

	if (argc != 4 || service_resource_dir(argv[1], &results) == -1)
		return (2);
	fd = openat(results, argv[2], O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (fd == -1 || (output = fdopen(fd, "w")) == NULL)
		return (2);
	setvbuf(output, NULL, _IOLBF, 0);
	heartbeat = openat(results, "heartbeat", O_CREAT | O_WRONLY | O_TRUNC, 0600);
	REQUIRE(heartbeat >= 0);
	REQUIRE(service_acquire(&ctx) == 0);
	REQUIRE(service_provider_create(&provider) == 0);
	REQUIRE(service_provider_enter_capability_mode(provider) == 0);
	REQUIRE(service_provider_ready(provider) == 0);
	fprintf(output, "ready pid=%d\n", getpid());
	claim.owner_uid = getuid();
	claim.owner_gid = getgid();
	REQUIRE(request(ctx, TZFSD_SERVICE_NAME, &claim, sizeof(claim),
	    &grant, sizeof(grant), &directory) == 0);
	REQUIRE((file = openat(directory, "private-data", O_CREAT | O_RDWR, 0600)) >= 0);
	REQUIRE(write(file, "retained", 8) == 8 && fsync(file) == 0);
	fprintf(output, "filesystem=%s\n", grant.dataset);
	REQUIRE(cryptocmp_open(&crypto) == 0);
	REQUIRE(cryptocmp_named_create(crypto, "cleanup", &generate, &generation) == 0 ||
	    errno == EEXIST);
	REQUIRE(cryptocmp_named_lease(crypto, "cleanup", generate.rights, 0, &generation, &lease) == 0);
	fprintf(output, "crypto=%ju\n", (uintmax_t)generation);
	REQUIRE(logcmp_client_open(&logs) == 0);
	REQUIRE(logcmp_logger_create(logs, "org.test.cleanup", "private", &logger) == 0);
	REQUIRE(logcmp_emit(logger, &event) == 0 && logcmp_flush(logs) == 0);
	fprintf(output, "log=flushed\n");
	strlcpy(jail.path, argv[3], sizeof(jail.path));
	REQUIRE(request(ctx, "system.Namespace", &jail, sizeof(jail),
	    &jail_reply, sizeof(jail_reply), &jailfd) == 0);
	fprintf(output, "jail=%s\n", jail.path);
	REQUIRE(request(ctx, VMD_SERVICE_NAME, &window, sizeof(window),
	    &window_reply, sizeof(window_reply), &vsockfd) == 0);
	fprintf(output, "vsock=%u:%u\nPASS resources=5\n", window_reply.cid, window_reply.port);
	for (uint64_t beat = 1;; beat++) {
		char text[32];
		int length = snprintf(text, sizeof(text), "%ju\n", (uintmax_t)beat);
		REQUIRE(pwrite(file, &beat, sizeof(beat), 8) == sizeof(beat));
		REQUIRE(pwrite(heartbeat, text, length, 0) == length);
		sleep(1);
	}
}
