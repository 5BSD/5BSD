/* SPDX-License-Identifier: BSD-2-Clause */
/* Real bhyvectl/libnv IPC, with a disposable controller and no kernel VM. */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/nv.h>
#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "migration_session.h"

int
main(int argc, char **argv)
{
	char dir[] = "/tmp/ht-cli-ipc.XXXXXX", path[104], opts[5][96];
	const char *pin = "--migrate-peer-sha256=0404040404040404040404040404040404040404040404040404040404040404";
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct stat before, after;
	int listener, streams[2], credentials[3], status;

	assert(argc == 2);
	alarm(40);
	assert(mkdtemp(dir) != NULL);
	listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	assert(listener >= 0);
	assert(snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/source", dir) > 0);
	addr.sun_len = SUN_LEN(&addr);
	assert(bind(listener, (struct sockaddr *)&addr, addr.sun_len) == 0);
	assert(listen(listener, 1) == 0);
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, streams) == 0);
	for (int i = 0; i < 3; i++) {
		snprintf(path, sizeof(path), "%s/credential%d", dir, i);
		credentials[i] = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
		assert(credentials[i] >= 0);
		assert(write(credentials[i], &i, sizeof(i)) == sizeof(i));
		assert(unlink(path) == 0);
	}
	snprintf(opts[1], sizeof(opts[1]), "--migrate-certificate-fd=%d", credentials[0]);
	snprintf(opts[2], sizeof(opts[2]), "--migrate-key-fd=%d", credentials[1]);
	snprintf(opts[3], sizeof(opts[3]), "--migrate-trust-fd=%d", credentials[2]);
	snprintf(opts[4], sizeof(opts[4]), "--rundir=%s", dir);
	for (int recover = 0; recover < 2; recover++) {
		for (int mode = 0; mode < 8; mode++) {
			snprintf(opts[0], sizeof(opts[0]), "--migrate-%sfd=%d",
			    recover ? "recover-" : "", streams[0]);
			pid_t child = fork();
			assert(child >= 0);
			if (child == 0) {
				close(streams[1]);
				execl(argv[1], argv[1], "--vm=source", opts[0], opts[1],
				    opts[2], opts[3], pin, opts[4], (char *)NULL);
				_exit(127);
			}
			int fd = accept(listener, NULL, NULL);
			assert(fd >= 0);
			nvlist_t *request = nvlist_recv(fd, 0);
			assert(request != NULL);
			assert(strcmp(nvlist_get_string(request, "cmd"),
			    recover ? "migrate_recover" : "migrate") == 0);
			assert(!nvlist_exists(request, "recovery_fddir"));
			assert(strcmp(nvlist_get_string(request, "tls_peer_sha256"),
			    pin + strlen("--migrate-peer-sha256=")) == 0);
			const char *names[] = { "tls_certificate_fd", "tls_private_key_fd", "tls_trust_fd" };
			for (int i = 0; i < 3; i++) {
				int got = nvlist_get_descriptor(request, names[i]);
				assert(fstat(credentials[i], &before) == 0 && fstat(got, &after) == 0);
				assert(before.st_dev == after.st_dev && before.st_ino == after.st_ino);
			}
			/* Prove that libnv transferred the connected stream, not its number. */
			char byte = 'x', received;
			assert(write(nvlist_get_descriptor(request, "fd"), &byte, 1) == 1);
			assert(read(streams[1], &received, 1) == 1 && received == byte);
			nvlist_destroy(request);
			if (mode != 1) {
				nvlist_t *reply = nvlist_create(0);
				if (mode == 2) nvlist_add_string(reply, "error", "injected refusal");
				if (mode == 7) nvlist_add_number(reply, "source_runnable", 0);
				else if (mode != 3) nvlist_add_bool(reply, "source_runnable", mode == 4);
				if (mode != 5) {
					nvlist_add_bool(reply, "confirmed", mode != 6);
					nvlist_add_number(reply, "phase", mode == 6 ? MIGRATION_PHASE_RECOVERY : MIGRATION_PHASE_COMPLETED);
					nvlist_add_number(reply, "reason", MIGRATION_REASON_NONE);
				}
				assert(nvlist_send(fd, reply) == 0);
				nvlist_destroy(reply);
			}
			close(fd);
			assert(waitpid(child, &status, 0) == child);
			assert(WIFEXITED(status));
			assert(WEXITSTATUS(status) == (mode == 0 ? 0 : 1));
			for (int i = 0; i < 3; i++) assert(fcntl(credentials[i], F_GETFD) >= 0);
		}
	}
	/* Rollback repair: only an explicit repaired, runnable reply succeeds. */
	for (int mode = 0; mode < 7; mode++) {
		pid_t child = fork();
		assert(child >= 0);
		if (child == 0) {
			execl(argv[1], argv[1], "--vm=source", "--migrate-repair",
			    opts[4], (char *)NULL);
			_exit(127);
		}
		int fd = accept(listener, NULL, NULL);
		assert(fd >= 0);
		nvlist_t *request = nvlist_recv(fd, 0);
		assert(request != NULL);
		assert(strcmp(nvlist_get_string(request, "cmd"), "migrate_repair") == 0);
		assert(!nvlist_exists(request, "fd") && !nvlist_exists(request, "tls_peer_sha256"));
		nvlist_destroy(request);
		if (mode != 1) {
			nvlist_t *reply = nvlist_create(0);
			if (mode == 2) nvlist_add_string(reply, "error", "migration repair: Operation not permitted");
			if (mode != 3) nvlist_add_bool(reply, "repaired", mode != 4);
			if (mode == 6) nvlist_add_number(reply, "source_runnable", 1);
			else nvlist_add_bool(reply, "source_runnable", mode != 4 && mode != 5);
			assert(nvlist_send(fd, reply) == 0);
			nvlist_destroy(reply);
		}
		close(fd);
		assert(waitpid(child, &status, 0) == child);
		assert(WIFEXITED(status));
		assert(WEXITSTATUS(status) == (mode == 0 ? 0 : 1));
	}
	/* Conflicting options are rejected before any controller connection. */
	const char *conflicts[][2] = {
		{ "--get-vm-pid", NULL }, { opts[0], NULL }, { pin, NULL },
	};
	assert(fcntl(listener, F_SETFL, O_NONBLOCK) == 0);
	for (unsigned i = 0; i < sizeof(conflicts) / sizeof(conflicts[0]); i++) {
		pid_t child = fork();
		assert(child >= 0);
		if (child == 0) {
			int null = open("/dev/null", O_WRONLY);
			dup2(null, 2);
			execl(argv[1], argv[1], "--vm=source", "--migrate-repair",
			    conflicts[i][0], opts[4], (char *)NULL);
			_exit(127);
		}
		assert(waitpid(child, &status, 0) == child);
		assert(WIFEXITED(status) && WEXITSTATUS(status) != 0 && WEXITSTATUS(status) != 127);
		assert(accept(listener, NULL, NULL) == -1);
	}
	close(listener); close(streams[0]); close(streams[1]);
	for (int i = 0; i < 3; i++) close(credentials[i]);
	assert(unlink(addr.sun_path) == 0 && rmdir(dir) == 0);
	puts("PASS: 26 compiled frontend IPC cases (16 migration/recovery, 7 repair replies, 3 repair conflicts); actual descriptor transfer; no VM");
	return (0);
}
