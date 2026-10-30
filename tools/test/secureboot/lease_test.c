/* SPDX-License-Identifier: BSD-2-Clause */
/* Real-kernel session lifetime tests; invoked by the fixture's PID 1. */
#include <sys/types.h>
#include <sys/cap_authority.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <dev/mac_capability/mac_capability_ioctl.h>
#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "lease_test.h"

#define CHECK(test) do { \
	if (!(test)) { \
		printf("LEASE_FAIL line=%d errno=%d test=%s\n", __LINE__, errno, #test); \
		return (1); \
	} \
} while (0)

static int
op(int command, int fd, void *data)
{
	return (syscall(SYS_cap_process, command, fd, 0, data));
}
static int
info(int fd)
{
	struct mac_capability_info_args args;
	return (ioctl(fd, MAC_CAPABILITY_GETINFO, &args));
}
static int
send_byte(int fd)
{
	char value = 'L';
	struct mac_capability_sendmsg_args args = { .payload = &value, .payload_len = 1 };
	return (ioctl(fd, MAC_CAPABILITY_SENDMSG, &args));
}
static int
recv_byte(int fd)
{
	char value = 0;
	struct mac_capability_recvmsg_args args = { .payload = &value, .payload_len = 1,
	    .flags = MAC_CAPABILITY_RECV_F_WAIT, ._reserved = {5000} };
	int result = ioctl(fd, MAC_CAPABILITY_RECVMSG, &args);
	if (result == 0 && (value != 'L' || args.payload_len != 1 || args.nfds != 0))
		return (errno = EPROTO, -1);
	return (result);
}
static int
bind_pair(int issuer, int control, int pair[2])
{
	struct cap_authority_lease_bind binding = { .lease_fd = control };
	CHECK(mac_capability_channel_create(pair) == 0);
	for (unsigned i = 0; i < 2; i++) {
		binding.capability_fd = pair[i];
		CHECK(op(CAP_AUTH_LEASE_BIND, issuer, &binding) == 0);
	}
	return (0);
}
static int
denied_pair(int pair[2])
{
	for (unsigned i = 0; i < 2; i++) {
		CHECK(info(pair[i]) == -1 && errno == EPERM);
		CHECK(send_byte(pair[i]) == -1 && errno == EPERM);
		CHECK(recv_byte(pair[i]) == -1 && errno == EPERM);
	}
	return (0);
}
static int
blocked_child(int fd, int gate, int control, int owner)
{
	/* The lifetime owner cannot accidentally escape into a forked worker. */
	CHECK(fcntl(control, F_GETFD) == -1 && errno == EBADF);
	CHECK(fcntl(owner, F_GETFD) == -1 && errno == EBADF);
	CHECK(write(gate, "R", 1) == 1);
	CHECK(recv_byte(fd) == -1 && errno == EPERM);
	return (0);
}

int
lease_test(int issuer, int grant)
{
	struct cap_authority_lease_create lease = { .seconds = 60 };
	struct cap_authority_lease_bind binding = {0};
	struct cap_authority_bind software = { .token_fd = grant };
	struct mac_capability_mint_instance_args mint = {0};
	struct kevent change, event;
	struct timespec timeout = { .tv_sec = 2 }, before, after;
	int pair[2], fresh[2], duplicate, other, queue, gate[2], status;
	pid_t child;
	char ready;

	lease.seconds = 0;
	CHECK(op(CAP_AUTH_LEASE_CREATE, issuer, &lease) == -1 && errno == EINVAL);
	lease.seconds = CAP_AUTH_LEASE_SECONDS_MAX + 1;
	CHECK(op(CAP_AUTH_LEASE_CREATE, issuer, &lease) == -1 && errno == EINVAL);
	lease.seconds = 60; lease.flags = 1;
	CHECK(op(CAP_AUTH_LEASE_CREATE, issuer, &lease) == -1 && errno == EINVAL);
	lease.flags = 0; lease.reserved = 1;
	CHECK(op(CAP_AUTH_LEASE_CREATE, issuer, &lease) == -1 && errno == EINVAL);
	lease.reserved = 0;
	CHECK(op(CAP_AUTH_LEASE_CREATE, issuer, &lease) == 0);
	CHECK(op(CAP_AUTH_LEASE_CHECK, lease.control_fd, NULL) == 0);
	CHECK(op(CAP_AUTH_LEASE_CHECK, lease.owner_fd, NULL) == -1 && errno == EINVAL);
	CHECK(syscall(SYS_cap_clofork_limit, lease.owner_fd, CAP_CLOFORK_UNLOCKED) == -1 && errno == ENOTCAPABLE);
	CHECK(syscall(SYS_cap_cloexec_limit, lease.owner_fd, CAP_CLOEXEC_UNLOCKED) == -1 && errno == ENOTCAPABLE);
	CHECK(fcntl(lease.owner_fd, F_SETFD, 0) == 0);
	CHECK(fcntl(lease.control_fd, F_SETFD, 0) == 0);
	CHECK(mac_capability_channel_create(pair) == 0);
	CHECK(ioctl(pair[0], MAC_CAPABILITY_MINT_INSTANCE, &mint) == 0);
	binding.lease_fd = lease.control_fd; binding.capability_fd = mint.fd;
	CHECK(op(CAP_AUTH_LEASE_BIND, issuer, &binding) == -1 && errno == EOPNOTSUPP);
	close(mint.fd);
	binding.lease_fd = lease.control_fd; binding.capability_fd = pair[0];
	other = op(CAP_AUTH_ISSUER_CREATE, -1, NULL); CHECK(other >= 0);
	CHECK(op(CAP_AUTH_LEASE_BIND, other, &binding) == -1 && errno == EPERM);
	close(other);
	binding.lease_fd = lease.owner_fd;
	CHECK(op(CAP_AUTH_LEASE_BIND, issuer, &binding) == -1 && errno == EINVAL);
	binding.lease_fd = lease.control_fd; binding.flags = 1;
	CHECK(op(CAP_AUTH_LEASE_BIND, issuer, &binding) == -1 && errno == EINVAL);
	binding.flags = 0; binding.reserved = 1;
	CHECK(op(CAP_AUTH_LEASE_BIND, issuer, &binding) == -1 && errno == EINVAL);
	binding.reserved = 0;
	for (unsigned i = 0; i < 2; i++) {
		binding.capability_fd = pair[i];
		CHECK(op(CAP_AUTH_LEASE_BIND, issuer, &binding) == 0);
		CHECK(op(CAP_AUTH_LEASE_BIND, issuer, &binding) == -1 && errno == EALREADY);
		CHECK(ioctl(pair[i], MAC_CAPABILITY_MINT_INSTANCE, &mint) == -1 && errno == EACCES);
	}
	/* A live lease cannot substitute for software authority, in either bind order. */
	CHECK(mac_capability_channel_create(fresh) == 0);
	software.capability_fd = fresh[0];
	CHECK(op(CAP_AUTH_BIND, issuer, &software) == 0);
	for (unsigned i = 0; i < 2; i++) {
		binding.capability_fd = fresh[i];
		CHECK(op(CAP_AUTH_LEASE_BIND, issuer, &binding) == 0);
	}
	software.capability_fd = fresh[1];
	CHECK(op(CAP_AUTH_BIND, issuer, &software) == 0);
	CHECK(op(CAP_AUTH_LEASE_CHECK, lease.control_fd, NULL) == 0);
	CHECK(denied_pair(fresh) == 0);
	close(fresh[0]); close(fresh[1]);
	CHECK(send_byte(pair[0]) == 0 && recv_byte(pair[1]) == 0);
	CHECK(send_byte(pair[1]) == 0 && recv_byte(pair[0]) == 0);
	duplicate = dup(lease.owner_fd); CHECK(duplicate >= 0);
	CHECK(close(lease.owner_fd) == 0);
	CHECK(op(CAP_AUTH_LEASE_CHECK, lease.control_fd, NULL) == 0);
	CHECK(send_byte(pair[0]) == 0 && send_byte(pair[1]) == 0); /* queued on both ends */
	queue = kqueue(); CHECK(queue >= 0);
	EV_SET(&change, pair[0], EVFILT_READ, EV_ADD, 0, 0, NULL);
	CHECK(kevent(queue, &change, 1, NULL, 0, NULL) == 0);
	CHECK(close(duplicate) == 0);
	CHECK(op(CAP_AUTH_LEASE_CHECK, lease.control_fd, NULL) == -1 && errno == EPERM);
	CHECK(kevent(queue, NULL, 0, &event, 1, &timeout) == 1 && (event.flags & EV_EOF));
	CHECK(denied_pair(pair) == 0); /* no queued-data exception */
	CHECK(mac_capability_channel_create(fresh) == 0);
	binding.capability_fd = fresh[0];
	CHECK(op(CAP_AUTH_LEASE_BIND, issuer, &binding) == -1 && errno == EPERM);
	close(fresh[0]); close(fresh[1]); close(queue);
	close(pair[0]); close(pair[1]); close(lease.control_fd);

	/* Closing either the broker control or the issuer revokes both endpoints. */
	for (unsigned phase = 0; phase < 2; phase++) {
		other = op(CAP_AUTH_ISSUER_CREATE, -1, NULL); CHECK(other >= 0);
		CHECK(op(CAP_AUTH_LEASE_CREATE, other, &lease) == 0);
		CHECK(bind_pair(other, lease.control_fd, pair) == 0);
		CHECK(info(pair[0]) == 0 && info(pair[1]) == 0);
		CHECK(close(phase == 0 ? lease.control_fd : other) == 0);
		CHECK(denied_pair(pair) == 0);
		close(phase == 0 ? other : lease.control_fd);
		close(lease.owner_fd); close(pair[0]); close(pair[1]);
	}

	/* A blocked receive must wake for both last-owner close and the deadline. */
	for (unsigned phase = 0; phase < 2; phase++) {
		lease.seconds = phase == 0 ? 60 : 2;
		CHECK(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
		CHECK(op(CAP_AUTH_LEASE_CREATE, issuer, &lease) == 0);
		CHECK(bind_pair(issuer, lease.control_fd, pair) == 0);
		CHECK(fcntl(lease.owner_fd, F_SETFD, 0) == 0);
		CHECK(fcntl(lease.control_fd, F_SETFD, 0) == 0);
		CHECK(pipe(gate) == 0);
		child = fork(); CHECK(child >= 0);
		if (child == 0) {
			close(gate[0]); close(pair[1]); close(issuer);
			_exit(blocked_child(pair[0], gate[1], lease.control_fd, lease.owner_fd));
		}
		close(gate[1]);
		CHECK(read(gate[0], &ready, 1) == 1 && ready == 'R');
		if (phase == 0) { usleep(100000); CHECK(close(lease.owner_fd) == 0); }
		CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
		CHECK(clock_gettime(CLOCK_MONOTONIC, &after) == 0);
		CHECK(after.tv_sec - before.tv_sec < 5);
		if (phase == 1) {
			CHECK(after.tv_sec - before.tv_sec >= 1);
			CHECK(close(lease.owner_fd) == 0);
		}
		CHECK(denied_pair(pair) == 0);
		close(gate[0]); close(pair[0]); close(pair[1]); close(lease.control_fd);
	}
	/* Exercise deferred destruction with live callouts and both close orders. */
	lease.seconds = 60;
	for (unsigned i = 0; i < 128; i++) {
		CHECK(op(CAP_AUTH_LEASE_CREATE, issuer, &lease) == 0);
		CHECK(bind_pair(issuer, lease.control_fd, pair) == 0);
		if (i & 1) { close(pair[0]); close(pair[1]); }
		close(lease.control_fd); close(lease.owner_fd);
		if (!(i & 1)) { close(pair[0]); close(pair[1]); }
	}
	puts("LEASE_PASS lifetime, duplication, queued data, blocked receive, kqueue, issuer and deadline revocation");
	return (0);
}
