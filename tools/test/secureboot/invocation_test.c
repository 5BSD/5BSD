/* SPDX-License-Identifier: BSD-2-Clause */
/* Real-kernel fixture: the issuer is PID 1, with no production test bypass. */
#include <sys/types.h>
#include <sys/cap_authority.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/procdesc.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <dev/mac_capability/mac_capability_ioctl.h>
#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "invocation_test.h"

#define CHECK(test) do { \
	if (!(test)) { \
		printf("INVOCATION_FAIL line=%d errno=%d test=%s\n", __LINE__, errno, #test); \
		return (1); \
	} \
	printf("INVOCATION_CHECK %s\n", #test); \
} while (0)

static int
op(int command, int fd, void *data)
{
	return (syscall(SYS_cap_process, command, fd, 0, data));
}

static int
send_byte(int fd, char value)
{
	struct mac_capability_sendmsg_args args = { .payload = &value, .payload_len = 1 };

	return (ioctl(fd, MAC_CAPABILITY_SENDMSG, &args));
}

static int
get_info(int fd)
{
	struct mac_capability_info_args args;

	return (ioctl(fd, MAC_CAPABILITY_GETINFO, &args));
}

static int
receive_byte(int fd, char expected, struct mac_capability_recvmsg_v3_args *args)
{
	char value = 0;

	memset(args, 0, sizeof(*args));
	args->message.payload = &value;
	args->message.payload_len = 1;
	args->message.flags = MAC_CAPABILITY_RECV_F_WAIT;
	args->message._reserved[0] = 5000;
	if (ioctl(fd, MAC_CAPABILITY_RECVMSG_V3, args) == -1)
		return (-1);
	return (args->message.payload_len == 1 && args->message.nfds == 0 &&
	    value == expected ? 0 : (errno = EPROTO, -1));
}

int
invocation_child(int argc, char **argv)
{
	struct cap_authority_info authority;
	struct mac_capability_recvmsg_args recv = {0};
	int route, bound, broad, gate, status, duplicate;
	char byte;
	pid_t child;

	setvbuf(stdout, NULL, _IONBF, 0);
	CHECK(op(CAP_AUTH_INFO, -1, &authority) == 0 && authority.valid);
	if (argc == 6 && strcmp(argv[1], "--invocation-reexec") == 0) {
		bound = atoi(argv[2]); broad = atoi(argv[3]);
		CHECK(get_info(bound) == -1 && errno == EPERM);
		CHECK(send_byte(bound, 'x') == -1 && errno == EPERM);
		CHECK(get_info(broad) == 0); /* Same software, new execution. */
		CHECK(send_byte(atoi(argv[4]), 'E') == 0);
		CHECK(read(atoi(argv[5]), &byte, 1) == 1 && byte == 'X');
		return (0);
	}
	CHECK(argc == 7 && strcmp(argv[1], "--invocation-owner") == 0);
	route = atoi(argv[2]); bound = atoi(argv[3]); broad = atoi(argv[4]); gate = atoi(argv[5]);
	CHECK(send_byte(route, 'H') == 0);
	CHECK(read(gate, &byte, 1) == 1 && byte == 'B');
	CHECK(get_info(bound) == 0 && get_info(broad) == 0);
	CHECK(send_byte(bound, 'A') == 0);
	if (strcmp(argv[6], "revoke") == 0) {
		CHECK(read(gate, &byte, 1) == 1 && byte == 'R');
		CHECK(get_info(bound) == -1 && errno == EPERM);
		CHECK(get_info(broad) == -1 && errno == EPERM);
		return (0);
	}
	duplicate = dup(bound);
	CHECK(duplicate >= 0 && get_info(duplicate) == 0);
	close(duplicate);
	/* UID changes preserve this invocation; they do not create a principal. */
	CHECK(seteuid(65534) == 0);
	CHECK(get_info(bound) == 0);
	CHECK(seteuid(0) == 0);
	execl("/no-such-image", "missing", (char *)NULL);
	CHECK(errno == ENOENT && get_info(bound) == 0);
	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		CHECK(get_info(broad) == 0);
		CHECK(get_info(bound) == -1 && errno == EPERM);
		CHECK(send_byte(bound, 'x') == -1 && errno == EPERM);
		CHECK(ioctl(bound, MAC_CAPABILITY_RECVMSG, &recv) == -1 && errno == EPERM);
		CHECK(seteuid(65534) == 0 && seteuid(0) == 0);
		CHECK(get_info(bound) == -1 && errno == EPERM);
		return (0);
	}
	CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK(get_info(bound) == 0);
	CHECK(fcntl(bound, F_SETFD, 0) == 0 && fcntl(broad, F_SETFD, 0) == 0);
	execl("/sbin/secureboot-init", "secureboot-init", "--invocation-reexec",
	    argv[3], argv[4], argv[2], argv[5], (char *)NULL);
	CHECK(0);
}

int
invocation_test(int issuer, int grant)
{
	struct cap_authority_info info;
	struct cap_authority_revoke revoke = { .token_fd = grant };
	struct mac_capability_recvmsg_v3_args received;
	struct cap_authority_bind software = { .token_fd = grant };
	struct cap_authority_bind_invocation binding;
	struct cap_authority_check_invocation current;
	struct kevent event;
	cap_rights_t rights;
	int pd, self, restricted, kq, foreign_gate[2];
	pid_t foreign;
	int bound[2], broad[2], route[2], gate[2], status, other_issuer;
	char fds[4][24];
	pid_t child;

	CHECK(op(CAP_AUTH_TOKEN_INFO, grant, &info) == 0);
	other_issuer = op(CAP_AUTH_ISSUER_CREATE, -1, NULL);
	CHECK(other_issuer >= 0);
	for (unsigned phase = 0; phase < 2; phase++) {
		CHECK(mac_capability_channel_create(bound) == 0);
		CHECK(mac_capability_channel_create(broad) == 0);
		CHECK(mac_capability_channel_create(route) == 0);
		CHECK(pipe(gate) == 0);
		software.capability_fd = broad[0];
		CHECK(op(CAP_AUTH_BIND, issuer, &software) == 0);
		child = pdfork(&pd, PD_DAEMON | PD_CLOEXEC); CHECK(child >= 0);
		if (child == 0) {
			int retained[] = {route[0], bound[0], broad[0], gate[0]};
			close(issuer); close(grant); close(other_issuer);
			close(route[1]); close(bound[1]); close(broad[1]); close(gate[1]);
			for (unsigned i = 0; i < 4; i++) {
				CHECK(fcntl(retained[i], F_SETFD, 0) == 0);
				snprintf(fds[i], sizeof(fds[i]), "%d", retained[i]);
			}
			execl("/sbin/secureboot-init", "secureboot-init", "--invocation-owner",
			    fds[0], fds[1], fds[2], fds[3], phase == 0 ? "exercise" : "revoke", (char *)NULL);
			CHECK(0);
		}
		close(route[0]); close(gate[0]);
		CHECK(receive_byte(route[1], 'H', &received) == 0);
		CHECK(received.authority.valid && received.authority.issuer == info.issuer &&
		    received.authority.identity == info.identity);
		memset(&binding, 0, sizeof(binding));
		binding.token_fd = grant;
		binding.capability_fd = bound[0];
		binding.process_identity = received.process.identity;
		binding.execution_nonce = received.message.trailer.nonce;
		CHECK(binding.process_identity != 0 && binding.execution_nonce != 0);
		CHECK(pd >= 0);
		current = (struct cap_authority_check_invocation){ .token_fd = grant,
		    .process_fd = pd, .process_identity = binding.process_identity,
		    .execution_nonce = binding.execution_nonce };
		CHECK(op(CAP_AUTH_CHECK_INVOCATION, issuer, &current) == 0);
		CHECK(op(CAP_AUTH_CHECK_INVOCATION, other_issuer, &current) == -1 && errno == EPERM);
		current.flags = 1;
		CHECK(op(CAP_AUTH_CHECK_INVOCATION, issuer, &current) == -1 && errno == EINVAL);
		current.flags = 0; current.reserved = 1;
		CHECK(op(CAP_AUTH_CHECK_INVOCATION, issuer, &current) == -1 && errno == EINVAL);
		current.reserved = 0; current.process_identity = 0;
		CHECK(op(CAP_AUTH_CHECK_INVOCATION, issuer, &current) == -1 && errno == EINVAL);
		current.process_identity = binding.process_identity ^ 1;
		if (current.process_identity == 0) current.process_identity = 2;
		CHECK(op(CAP_AUTH_CHECK_INVOCATION, issuer, &current) == -1 && errno == EPERM);
		current.process_identity = binding.process_identity; current.execution_nonce = 0;
		CHECK(op(CAP_AUTH_CHECK_INVOCATION, issuer, &current) == -1 && errno == EINVAL);
		current.execution_nonce = binding.execution_nonce ^ 1;
		if (current.execution_nonce == 0) current.execution_nonce = 2;
		CHECK(op(CAP_AUTH_CHECK_INVOCATION, issuer, &current) == -1 && errno == EPERM);
		current.execution_nonce = binding.execution_nonce;
		CHECK(pipe(foreign_gate) == 0);
		foreign = pdfork(&self, PD_DAEMON | PD_CLOEXEC); CHECK(foreign >= 0);
		if (foreign == 0) {
			char release;
			close(foreign_gate[1]);
			_exit(read(foreign_gate[0], &release, 1) == 1 ? 0 : 1);
		}
		close(foreign_gate[0]);
		current.process_fd = self;
		CHECK(op(CAP_AUTH_CHECK_INVOCATION, issuer, &current) == -1 && errno == EPERM);
		CHECK(write(foreign_gate[1], "X", 1) == 1);
		close(foreign_gate[1]);
		CHECK(waitpid(foreign, &status, 0) == foreign && WIFEXITED(status) && WEXITSTATUS(status) == 0);
		close(self);
		restricted = dup(pd); CHECK(restricted >= 0);
		CHECK(cap_rights_limit(restricted, cap_rights_init(&rights, CAP_EVENT)) == 0);
		current.process_fd = restricted;
		CHECK(op(CAP_AUTH_CHECK_INVOCATION, issuer, &current) == -1 && errno == ENOTCAPABLE);
		close(restricted); current.process_fd = pd;
		CHECK(op(CAP_AUTH_CHECK_INVOCATION, issuer, &current) == 0);
		CHECK(op(CAP_AUTH_BIND_INVOCATION, other_issuer, &binding) == -1 && errno == EPERM);
		binding.flags = 1;
		CHECK(op(CAP_AUTH_BIND_INVOCATION, issuer, &binding) == -1 && errno == EINVAL);
		binding.flags = 0; binding.reserved = 1;
		CHECK(op(CAP_AUTH_BIND_INVOCATION, issuer, &binding) == -1 && errno == EINVAL);
		binding.reserved = 0; binding.process_identity = 0;
		CHECK(op(CAP_AUTH_BIND_INVOCATION, issuer, &binding) == -1 && errno == EINVAL);
		binding.process_identity = received.process.identity;
		binding.execution_nonce = 0;
		CHECK(op(CAP_AUTH_BIND_INVOCATION, issuer, &binding) == -1 && errno == EINVAL);
		binding.execution_nonce = received.message.trailer.nonce;
		CHECK(op(CAP_AUTH_BIND_INVOCATION, issuer, &binding) == 0);
		CHECK(op(CAP_AUTH_BIND_INVOCATION, issuer, &binding) == -1 && errno == EALREADY);
		software.capability_fd = bound[0];
		CHECK(op(CAP_AUTH_BIND, issuer, &software) == -1 && errno == EALREADY);
		CHECK(get_info(bound[0]) == -1 && errno == EPERM);
		CHECK(write(gate[1], "B", 1) == 1);
		CHECK(receive_byte(bound[1], 'A', &received) == 0);
		if (phase == 1) {
			CHECK(op(CAP_AUTH_REVOKE, issuer, &revoke) == 0);
			CHECK(op(CAP_AUTH_CHECK_INVOCATION, issuer, &current) == -1 && errno == EPERM);
			CHECK(write(gate[1], "R", 1) == 1);
		} else {
			CHECK(receive_byte(route[1], 'E', &received) == 0);
			/* Deliberately install the watch after exec completed. A future
			 * event cannot be relied on to detect this stale observation. */
			kq = kqueue(); CHECK(kq >= 0);
			EV_SET(&event, pd, EVFILT_PROCDESC, EV_ADD | EV_ENABLE,
			    NOTE_EXIT | NOTE_EXEC, 0, NULL);
			CHECK(kevent(kq, &event, 1, NULL, 0, NULL) == 0);
			CHECK(op(CAP_AUTH_CHECK_INVOCATION, issuer, &current) == -1 && errno == EPERM);
			current.process_identity = received.process.identity;
			current.execution_nonce = received.message.trailer.nonce;
			CHECK(op(CAP_AUTH_CHECK_INVOCATION, issuer, &current) == 0);
			CHECK(write(gate[1], "X", 1) == 1);
			close(kq);
		}
		CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
		CHECK(op(CAP_AUTH_CHECK_INVOCATION, issuer, &current) == -1 && errno == ESRCH);
		close(pd);
		close(route[1]); close(gate[1]);
		close(bound[0]); close(bound[1]); close(broad[0]); close(broad[1]);
	}
	close(other_issuer);
	puts("INVOCATION_CURRENT_PASS");
	puts("INVOCATION_PASS owner use, fork/exec replay denial, credential independence and revocation");
	return (0);
}
