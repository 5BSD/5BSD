/* SPDX-License-Identifier: BSD-2-Clause */
/* Exercises the installed provider through normal signed bundle launch. */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/cap_authority.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/zfshandle.h>
#include <dev/mac_capability/mac_capability_ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libservice.h>
#include <filesystemcmp.h>
#include "storage_test.h"

#define CHECK(x) do { if (!(x)) { int saved = errno; printf("STORAGE_PROVIDER_FAIL line=%d expression=%s errno=%d\n", __LINE__, #x, saved); errno = saved; return (__LINE__); } } while (0)
static int
open_group(struct service_context *context, const char *name, int *directory)
{
	return (service_storage_open_group(context, "test.storage", name, directory));
}

static int
release_group(struct service_context *context, const char *name)
{
	return (service_storage_release_group(context, "test.storage", name));
}

/* Record every attempted operation, including unexpected success. Same-size
 * truncation and unchanged mode exercise checks without corrupting the parent's
 * challenge; unauthorized creation uses a separate name for parent cleanup. */
static void
namespace_probe(int directory, int file, const struct stat *original,
    const char *name, struct storage_operation_result *result)
{
	int fd;

	errno = 0;
	fd = openat(directory, "retained", O_RDWR);
	result[0] = (struct storage_operation_result){ fd >= 0 ? 0 : -1, errno };
	if (fd >= 0) close(fd);
	errno = 0;
	fd = openat(directory, name, O_CREAT | O_EXCL | O_RDWR, 0600);
	result[1] = (struct storage_operation_result){ fd >= 0 ? 0 : -1, errno };
	if (fd >= 0) close(fd);
	errno = 0;
	result[2].result = ftruncate(file, original->st_size);
	result[2].error = errno;
	errno = 0;
	result[3].result = fchmod(file, original->st_mode & 07777);
	result[3].error = errno;
}

/* The real provider returns this file's directory to the admitted client.
 * Keep the parent admitted and keep its data checks intact. In a child, drop
 * software membership while retaining the descriptor: possession alone must
 * not bypass mandatory storage authorization. No provider/test impersonation. */
static int
retained_access_probe(int directory, int file, struct storage_test_result *result)
{
	struct { int32_t count, error, written, write_error;
	    int32_t fork_count, fork_error, fork_written, fork_write_error;
	    struct storage_operation_result fork_namespace[STORAGE_NAMESPACE_OPERATIONS];
	    struct storage_operation_result clear_namespace[STORAGE_NAMESPACE_OPERATIONS]; } observed = {0};
	struct stat original;
	struct cap_authority_info authority;
	int channel[2], status;
	pid_t child;
	char byte;

	CHECK(pread(file, &byte, 1, 0) == 1);
	CHECK(pwrite(file, &byte, 1, 0) == 1);
	CHECK(fsync(file) == 0);
	CHECK(fstat(file, &original) == 0);
	/* Establish that these operations work for the admitted parent. */
	CHECK(ftruncate(file, original.st_size) == 0);
	CHECK(fchmod(file, original.st_mode & 07777) == 0);
	CHECK(pipe(channel) == 0);
	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		close(channel[0]);
		if (syscall(SYS_cap_process, CAP_AUTH_INFO, -1, 0, &authority) != 0 ||
		    !authority.valid)
			_exit(2);
		/* Software attribution survives fork; execution admission must not. */
		errno = 0;
		observed.fork_count = pread(file, &byte, 1, 0);
		observed.fork_error = errno;
		errno = 0;
		observed.fork_written = pwrite(file, &byte, 1, 0);
		observed.fork_write_error = errno;
		namespace_probe(directory, file, &original, "unauthorized-fork",
		    observed.fork_namespace);
		if (syscall(SYS_cap_process, CAP_AUTH_CLEAR, -1, 0, NULL) != 0 ||
		    syscall(SYS_cap_process, CAP_AUTH_INFO, -1, 0, &authority) != 0 ||
		    authority.valid)
			_exit(2);
		errno = 0;
		observed.count = pread(file, &byte, 1, 0);
		observed.error = errno;
		errno = 0;
		/* Same-byte write exposes unauthorized mutation without changing
		 * the expected challenge used by the authorized parent. */
		observed.written = pwrite(file, &byte, 1, 0);
		observed.write_error = errno;
		namespace_probe(directory, file, &original, "unauthorized-clear",
		    observed.clear_namespace);
		if (write(channel[1], &observed, sizeof(observed)) != sizeof(observed))
			_exit(3);
		close(channel[1]);
		_exit(0);
	}
	close(channel[1]);
	CHECK(read(channel[0], &observed, sizeof(observed)) == sizeof(observed));
	close(channel[0]);
	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	result->fork_read_result = observed.fork_count;
	result->fork_read_errno = observed.fork_error;
	result->fork_write_result = observed.fork_written;
	result->fork_write_errno = observed.fork_write_error;
	result->retained_read_result = observed.count;
	result->retained_read_errno = observed.error;
	result->retained_write_result = observed.written;
	result->retained_write_errno = observed.write_error;
	memcpy(result->fork_namespace, observed.fork_namespace, sizeof(result->fork_namespace));
	memcpy(result->clear_namespace, observed.clear_namespace, sizeof(result->clear_namespace));
	/* Clean unexpected creations as the still-admitted parent, preserving
	 * the observed success so cleanup cannot turn a failure into a pass. */
	if (observed.fork_namespace[1].result == 0)
		CHECK(unlinkat(directory, "unauthorized-fork", 0) == 0);
	if (observed.clear_namespace[1].result == 0)
		CHECK(unlinkat(directory, "unauthorized-clear", 0) == 0);
	CHECK(pread(file, &byte, 1, 0) == 1);
	return (0);
}

/* GETINFO is a valid, read-only transport admission probe: it always reaches
 * the same invocation check used by channel send/receive ioctls.
 * No malformed FIDL request or provider-side parser failure supplies denial. */
static int
channel_invocation_probe(struct service_context *context,
    struct storage_test_result *result)
{
	struct cap_authority_info authority;
	struct storage_operation_result observed = {-2, 0};
	struct mac_capability_info_args info;
	int fd, report[2], status;
	pid_t child;

	CHECK(service_connect(context, "system.Filesystem", &fd) == 0);
	CHECK(ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == 0);
	CHECK(pipe(report) == 0);
	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		close(report[0]);
		/* Distinguish invocation denial from missing fd/software authority. */
		if (fcntl(fd, F_GETFD) == -1 ||
		    syscall(SYS_cap_process, CAP_AUTH_INFO, -1, 0, &authority) == -1 ||
		    !authority.valid) _exit(1);
		errno = 0;
		observed.result = ioctl(fd, MAC_CAPABILITY_GETINFO, &info);
		observed.error = errno;
		_exit(write(report[1], &observed, sizeof(observed)) == sizeof(observed) ? 0 : 2);
	}
	close(report[1]);
	CHECK(read(report[0], &observed, sizeof(observed)) == sizeof(observed));
	CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK(ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == 0);
	CHECK(close(report[0]) == 0 && close(fd) == 0);
	result->channel_fork = observed;
	return (0);
}

static int
exercise(struct service_context *context, const struct storage_test_request *request,
    struct storage_test_result *result)
{
	static const struct {
		const char *value;
		int (*open)(struct service_context *, const char *, int *);
		int (*release)(struct service_context *, const char *);
	} scopes[] = {
		{ "unit", service_storage_open, service_storage_release },
		{ "cache", service_storage_open_cache, service_storage_release_cache },
		{ "shared", service_storage_open_shared, service_storage_release_shared },
		{ "group", open_group, release_group },
	};
	struct service_storage_stat_result info;
	char data[64], expected[64];
	int root, directory, file;
	unsigned mode;
	size_t i, length;

	setvbuf(stdout, NULL, _IONBF, 0);
	alarm(45);
	CHECK(cap_getmode(&mode) == 0 && mode == 1);
	int probe = channel_invocation_probe(context, result);
	if (probe != 0) return (probe);
	CHECK(service_capability_open(context, "storage-root", "zfshandle", &root) == -1 && errno == ENOENT);
	CHECK(open("/dev/zfs", O_RDWR) == -1 && errno == ECAPMODE);
	CHECK(service_storage_open(context, "../foreign", &directory) == -1 && errno == EINVAL);
	CHECK(service_storage_open_group(context, "foreign", "state", &directory) == -1 && errno == EPERM);
	/* Initial contents determine the phase; the host requires CREATED then
	 * RECOVERED on separate boots of this exact authenticated root image.
	 * Missing data on the second boot cannot pass by being initialized again.
	 */
	/* Actual management operations must work before testing file-data access.
	 * Independent result evidence prevents an early failure from looking like
	 * a completed worker grant test. */
	struct service_storage_claim claims[SERVICE_STORAGE_LIST_MAX];
	size_t count;
	uint32_t cursor = 0;
	CHECK(service_storage_list(context, claims, SERVICE_STORAGE_LIST_MAX, &count, &cursor) == 0);
	cursor = 0;
	CHECK(service_storage_list_shared(context, claims, SERVICE_STORAGE_LIST_MAX, &count, &cursor) == 0);
	cursor = 0;
	CHECK(service_storage_list_group(context, "test.storage", claims,
	    SERVICE_STORAGE_LIST_MAX, &count, &cursor) == 0);
	result->worker_management = 1;
	result->phase = 0;
	for (i = 0; i < sizeof(scopes) / sizeof(scopes[0]); i++) {
		CHECK(scopes[i].open(context, "state", &directory) == 0);
		file = openat(directory, "retained", O_RDWR);
		if (i == 0) {
			CHECK(file >= 0 || errno == ENOENT);
			result->phase = file >= 0 ? STORAGE_TEST_RECOVERED : STORAGE_TEST_CREATED;
		}
		length = sizeof(request->challenge) + strlen(scopes[i].value);
		CHECK(length < sizeof(expected));
		memcpy(expected, request->challenge, sizeof(request->challenge));
		memcpy(expected + sizeof(request->challenge), scopes[i].value,
		    strlen(scopes[i].value));
		if (result->phase == STORAGE_TEST_CREATED) {
			CHECK(file == -1 && errno == ENOENT);
			file = openat(directory, "retained", O_CREAT | O_EXCL | O_RDWR, 0600);
			CHECK(file >= 0);
			CHECK(write(file, expected, length) == (ssize_t)length);
			CHECK(fsync(file) == 0);
			CHECK(fsync(directory) == 0);
		} else {
			CHECK(file >= 0);
			CHECK(read(file, data, sizeof(data)) == (ssize_t)length);
			CHECK(memcmp(data, expected, length) == 0);
		}
		if (i == 0 && result->retained_read_result == -2) {
			int line = retained_access_probe(directory, file, result);
			if (line != 0)
				return (line);
		}
		CHECK(scopes[i].release(context, "state") == 0);
		/* Keep the actual delivered descriptors across the release reply.
		 * A successful release must not leave the client authorized through
		 * cached file or directory descriptors. No reopen precedes these probes. */
		errno = 0;
		result->release[i][0].result = pread(file, data, 1, 0);
		result->release[i][0].error = errno;
		errno = 0;
		result->release[i][1].result = pwrite(file, expected, 1, 0);
		result->release[i][1].error = errno;
		errno = 0;
		int reopened = openat(directory, "retained", O_RDONLY);
		result->release[i][2].result = reopened;
		result->release[i][2].error = errno;
		if (reopened >= 0) close(reopened);
		for (unsigned operation = 0; operation < STORAGE_RELEASE_OPERATIONS; operation++)
			CHECK(result->release[i][operation].result == -1 &&
			    (result->release[i][operation].error == EACCES ||
			    result->release[i][operation].error == EPERM));
		CHECK(close(file) == 0 && close(directory) == 0);
		CHECK(scopes[i].release(context, "state") == 0);
	}
	for (i = 0; i < sizeof(scopes) / sizeof(scopes[0]); i++) {
		CHECK(scopes[i].open(context, "state", &directory) == 0);
		file = openat(directory, "retained", O_RDONLY);
		CHECK(file >= 0);
		length = sizeof(request->challenge) + strlen(scopes[i].value);
		memcpy(expected, request->challenge, sizeof(request->challenge));
		memcpy(expected + sizeof(request->challenge), scopes[i].value,
		    strlen(scopes[i].value));
		CHECK(read(file, data, sizeof(data)) == (ssize_t)length);
		CHECK(memcmp(data, expected, length) == 0);
		CHECK(close(file) == 0 && close(directory) == 0);
		CHECK(scopes[i].release(context, "state") == 0);
	}
	if (request->flags & STORAGE_TEST_CRASH) {
		CHECK(service_storage_open(context, "state", &directory) == 0);
		file = openat(directory, "retained", O_RDWR);
		CHECK(file >= 0);
		CHECK(pread(file, data, 1, 0) == 1);
		CHECK(pwrite(file, data, 1, 0) == 1);
		CHECK(fsync(file) == 0);
		/* Only the explicitly selected fault build exits during this real
		 * request. A normal provider would return success and fail the test. */
		CHECK(service_storage_stat(context, "state", &info) == -1);
		for (unsigned attempt = 0; attempt < 50; attempt++) {
			errno = 0;
			result->restart_read.result = pread(file, expected, 1, 0);
			result->restart_read.error = errno;
			errno = 0;
			result->restart_write.result = pwrite(file, data, 1, 0);
			result->restart_write.error = errno;
			if (result->restart_read.result == -1 && result->restart_write.result == -1)
				break;
			usleep(100000);
		}
		CHECK(result->restart_read.result == -1 &&
		    (result->restart_read.error == EPERM || result->restart_read.error == EACCES));
		CHECK(result->restart_write.result == -1 &&
		    (result->restart_write.error == EPERM || result->restart_write.error == EACCES));
		CHECK(close(file) == 0 && close(directory) == 0);
		for (unsigned attempt = 0;; attempt++) {
			if (service_storage_open(context, "state", &directory) == 0) break;
			CHECK(attempt < 49 && (errno == EPIPE || errno == ECONNRESET ||
			    errno == ENOTCONN || errno == EAGAIN || errno == EBUSY ||
			    errno == ETIMEDOUT || errno == ENXIO));
			usleep(100000);
		}
		file = openat(directory, "retained", O_RDONLY);
		CHECK(file >= 0);
		length = sizeof(request->challenge) + strlen(scopes[0].value);
		memcpy(expected, request->challenge, sizeof(request->challenge));
		memcpy(expected + sizeof(request->challenge), scopes[0].value, strlen(scopes[0].value));
		CHECK(read(file, data, sizeof(data)) == (ssize_t)length);
		CHECK(memcmp(data, expected, length) == 0);
		CHECK(close(file) == 0 && close(directory) == 0);
		CHECK(service_storage_release(context, "state") == 0);
		result->restart_recovered = 1;
	} else
		CHECK(service_storage_stat(context, "state", &info) == 0);
	CHECK(result->channel_fork.result == -1 &&
	    (result->channel_fork.error == EPERM || result->channel_fork.error == EACCES));
	for (i = 0; i < STORAGE_NAMESPACE_OPERATIONS; i++) {
		CHECK(result->fork_namespace[i].result == -1 &&
		    (result->fork_namespace[i].error == EPERM || result->fork_namespace[i].error == EACCES));
		CHECK(result->clear_namespace[i].result == -1 &&
		    (result->clear_namespace[i].error == EPERM || result->clear_namespace[i].error == EACCES));
	}
	CHECK(result->fork_read_result == -1 &&
	    (result->fork_read_errno == EACCES || result->fork_read_errno == EPERM));
	CHECK(result->fork_write_result == -1 &&
	    (result->fork_write_errno == EACCES || result->fork_write_errno == EPERM));
	CHECK(result->retained_read_result == -1 &&
	    (result->retained_read_errno == EACCES ||
	    result->retained_read_errno == EPERM));
	CHECK(result->retained_write_result == -1 &&
	    (result->retained_write_errno == EACCES ||
	    result->retained_write_errno == EPERM));
	return (0);
}

int
main(void)
{
	struct service_context *context;
	struct service_provider *provider;
	struct service_listener *listener;
	struct service_identity identity = { .size = sizeof(identity) };
	struct storage_test_result result = { .channel_fork = {-2, 0}, .fork_read_result = -2,
	    .fork_write_result = -2, .retained_read_result = -2,
	    .retained_write_result = -2 };
	struct storage_test_request request;
	struct mac_capability_recvmsg_args receive = {
	    .payload = &request, .payload_len = sizeof(request),
	    .flags = MAC_CAPABILITY_RECV_F_WAIT, ._reserved = {45000} };
	struct mac_capability_sendmsg_args send = {
	    .payload = &result, .payload_len = sizeof(result) };
	int fd;

	if (service_acquire(&context) == -1 || service_provider_create(&provider) == -1 ||
	    service_provider_expose(provider, "test.StorageClient", &listener) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1 ||
	    service_listener_accept(listener, &identity, &fd) == -1 ||
	    ioctl(fd, MAC_CAPABILITY_RECVMSG, &receive) == -1 ||
    receive.payload_len != sizeof(request) || receive.nfds != 0 || request.version != STORAGE_TEST_VERSION ||
    (request.flags & ~STORAGE_TEST_CRASH) != 0)
		return (1);
	for (size_t i = 0; i < STORAGE_NAMESPACE_OPERATIONS; i++) {
		result.fork_namespace[i].result = -2;
		result.clear_namespace[i].result = -2;
	}
	result.line = exercise(context, &request, &result);
	result.error = result.line == 0 ? 0 : errno;
	send.reply_token = receive.reply_token;
	if (ioctl(fd, MAC_CAPABILITY_SENDMSG, &send) == -1)
		return (1);
	alarm(0);
	/* Keep the replied channel alive until VM cleanup. */
	for (;;) pause();
}
