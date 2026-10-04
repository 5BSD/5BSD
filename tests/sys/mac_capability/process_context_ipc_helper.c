/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/cap_process.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <channel.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#define CHECK(x)                                                              \
	do {                                                                  \
		if (!(x))                                                     \
			errx(1, "line %d: %s errno=%d", __LINE__, #x, errno); \
	} while (0)
static int
op(int x, int fd, void *p)
{
	return syscall(SYS_cap_process, x, fd, 0, p);
}
int
main(void)
{
	int f[2], token, st, received = -1;
	pid_t child;
	struct mac_cap_process_info parent, sender, payload;
	struct mac_capability_sendmsg_args send = { 0 };
	struct mac_capability_recvmsg_v2_args recv = { 0 };
	CHECK(mac_capability_channel_create(f) == 0);
	CHECK(op(MAC_CAP_PROCESS_INFO, -1, &parent) == 0);
	token = op(MAC_CAP_PROCESS_ORIGIN_EXPORT, -1, NULL);
	CHECK(token >= 0);
	child = fork();
	CHECK(child >= 0);
	if (!child) {
		CHECK(op(MAC_CAP_PROCESS_ORIGIN_SET, token, NULL) == 0);
		CHECK(op(MAC_CAP_PROCESS_INFO, -1, &sender) == 0);
		int own = op(MAC_CAP_PROCESS_ORIGIN_EXPORT, -1, NULL);
		CHECK(own >= 0);
		send.payload = &sender;
		send.payload_len = sizeof(sender);
		send.fds = &own;
		send.nfds = 1;
		send.reply_token = 17;
		CHECK(ioctl(f[0], MAC_CAPABILITY_SENDMSG, &send) == 0);
		_exit(0);
	}
	CHECK(waitpid(child, &st, 0) == child);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
	recv.message.payload = &payload;
	recv.message.payload_len = sizeof(payload);
	recv.message.fds = &received;
	recv.message.nfds = 1;
	CHECK(ioctl(f[1], MAC_CAPABILITY_RECVMSG_V2, &recv) == 0);
	CHECK(recv.message.reply_token == 17);
	CHECK(recv.message.nfds == 1);
	CHECK(received >= 0);
	CHECK(recv.process.pid == child);
	CHECK(recv.process.identity == payload.identity);
	CHECK(recv.process.identity != parent.identity);
	CHECK(recv.process.responsible_identity == parent.identity);
	CHECK(recv.process.responsible_pid == getpid());
	puts("PASS kernel-sender-attribution-survives-exit");
	CHECK(op(MAC_CAP_PROCESS_ORIGIN_SET, received, NULL) == 0);
	CHECK(op(MAC_CAP_PROCESS_INFO, -1, &sender) == 0);
	CHECK(sender.responsible_identity == payload.identity);
	CHECK(sender.responsible_pid == child);
	close(received);
	puts("PASS origin-token-survives-origin-exit");
	send.payload = &parent;
	send.payload_len = sizeof(parent);
	send.reply_token = 18;
	CHECK(ioctl(f[0], MAC_CAPABILITY_SENDMSG, &send) == 0);
	struct mac_capability_recvmsg_args old = { 0 };
	old.payload = &payload;
	old.payload_len = sizeof(payload);
	CHECK(ioctl(f[1], MAC_CAPABILITY_RECVMSG, &old) == 0);
	CHECK(old.reply_token == 18);
	CHECK(old.trailer.uid == getuid());
	puts("PASS original-receive-ABI");
	close(token);
	close(f[0]);
	close(f[1]);
	puts("PROCESS_CONTEXT_IPC_PASS");
	return 0;
}
