/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Transport feasibility test, not a generated FIDL binding or runtime.
 * FIDL wire bytes and handles remain separate: only kernel-transferred
 * descriptors carry authority. No descriptor number is trusted from payload.
 */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <dev/mac_capability/mac_capability_ioctl.h>
#include <channel.h>
#include <lib/fidl/txn_header.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) errx(1, "%s:%d: %s (errno %d)", \
    __FILE__, __LINE__, #x, errno); } while (0)

struct packet {
    fidl_message_header_t header;
    uint32_t handle;
    uint32_t padding;
};
_Static_assert(sizeof(struct packet) == 24, "FIDL v2 resource struct layout");

int
main(void)
{
    struct packet outgoing = {0}, incoming = {0};
    struct mac_capability_sendmsg_args send = {0};
    struct mac_capability_recvmsg_v3_args receive = {0};
    cap_rights_t rights;
    int channel[2], data[2], received = -1, status;
    pid_t pid;
    char byte;

    alarm(10);
    CHECK(mac_capability_channel_create(channel) == 0);
    CHECK(pipe(data) == 0);
    CHECK(write(data[1], "F", 1) == 1);
    CHECK(close(data[1]) == 0);
    cap_rights_init(&rights, CAP_READ);
    CHECK(cap_rights_limit(data[0], &rights) == 0);
    CHECK(cap_xfer_limit(data[0], CAP_XFER_ONCE) == 0);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        alarm(10);
        close(channel[0]);
        close(data[0]);
        CHECK(cap_enter() == 0);
        receive.message.payload = &incoming;
        receive.message.payload_len = sizeof(incoming);
        receive.message.fds = &received;
        receive.message.nfds = 1;
        CHECK(ioctl(channel[1], MAC_CAPABILITY_RECVMSG_V3, &receive) == 0);
        CHECK(receive.message.payload_len == sizeof(incoming));
        CHECK(receive.message.nfds == 1);
        CHECK(received >= 0);
        CHECK(fidl_validate_txn_header(&incoming.header) == ZX_OK);
        CHECK(incoming.header.txid == 7);
        CHECK(incoming.header.ordinal == 0x123456789);
        CHECK(incoming.header.at_rest_flags[0] ==
            FIDL_MESSAGE_HEADER_AT_REST_FLAGS_0_USE_VERSION_V2);
        CHECK(incoming.handle == FIDL_HANDLE_PRESENT && incoming.padding == 0);
        CHECK(receive.process.pid == getppid());
        CHECK(cap_rights_get(received, &rights) == 0);
        CHECK(cap_rights_is_set(&rights, CAP_READ));
        CHECK(!cap_rights_is_set(&rights, CAP_WRITE));
        CHECK(read(received, &byte, 1) == 1 && byte == 'F');
        /* A second delegation of the one-hop capability must fail. */
        send.payload = &incoming;
        send.payload_len = sizeof(incoming);
        send.fds = &received;
        send.nfds = 1;
        CHECK(ioctl(channel[1], MAC_CAPABILITY_SENDMSG, &send) == -1);
        CHECK(errno == ENOTCAPABLE);
        close(received);
        close(channel[1]);
        _exit(0);
    }
    close(channel[1]);
    fidl_init_txn_header(&outgoing.header, 7, 0x123456789,
        FIDL_MESSAGE_HEADER_DYNAMIC_FLAGS_STRICT_METHOD);
    outgoing.handle = FIDL_HANDLE_PRESENT;
    send.payload = &outgoing;
    send.payload_len = sizeof(outgoing);
    send.fds = data;
    send.nfds = 1;
    CHECK(ioctl(channel[0], MAC_CAPABILITY_SENDMSG, &send) == 0);
    close(data[0]);
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(channel[0]);
    puts("FIDL wire bytes + native descriptor transfer, attenuation, sender stamp, capmode: PASS");
    return 0;
}
