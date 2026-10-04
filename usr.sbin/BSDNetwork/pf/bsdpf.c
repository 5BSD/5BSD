/* SPDX-License-Identifier: BSD-2-Clause */
/* The only authority delegated by this unit is a read-only PF state snapshot
 * ioctl. No rules, state killing, packet injection or writes are exposed. */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <logcmp.h>
#include <unistd.h>
#include <channel.h>
#include <libservice.h>
#include "pf_protocol.h"
struct request_state { int directory; bool done; };
static void request(struct channel *channel, struct channel_message *message, void *argument) {
    (void)channel;
    struct request_state *state = argument;
    if (state->done) { channel_message_free(message); return; }
    state->done = true;
    struct pf_monitor_message reply = { PF_MONITOR_MAGIC, EINVAL }, input;
    int fd = -1;
    if (channel_message_length(message) == sizeof(input) && channel_message_fd_count(message) == 0) {
        memcpy(&input, channel_message_data(message), sizeof(input));
        if (input.magic == PF_MONITOR_MAGIC && input.error == 0) {
            fd = openat(state->directory, "pf", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            reply.error = fd < 0 ? errno : 0;
            if (fd >= 0) {
                cap_rights_t rights;
                cap_rights_init(&rights, CAP_READ, CAP_FSTAT, CAP_IOCTL);
                const unsigned long commands[] = { PF_MONITOR_GETSTATES };
                if (cap_rights_limit(fd, &rights) || cap_ioctls_limit(fd, commands, 1) ||
                    cap_fcntls_limit(fd, 0) || service_harden_fd(fd, SERVICE_HARDEN_XFER_ONCE)) {
                    reply.error = errno; close(fd); fd = -1;
                }
            }
        }
    }
    struct channel_outgoing outgoing = CHANNEL_OUTGOING_INITIALIZER(&reply, sizeof(reply));
    outgoing.fds = fd >= 0 ? &fd : NULL;
    outgoing.nfds = fd >= 0 ? 1 : 0;
    if (channel_send_reply(message, &outgoing) < 0)
        logcmp_log(LOG_WARNING, "PF reply delivery failed: %s", strerror(errno));
    if (fd >= 0) close(fd);
    channel_message_free(message);
}
int main(void) {
    struct service_provider *provider;
    struct service_listener *listener;
    int directory;
    if (service_resource_dir("/dev", &directory) || service_provider_create(&provider) ||
        service_provider_authorize_capabilities(provider) ||
        service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL | SERVICE_PROTECT_NOEXEC) ||
        service_provider_expose(provider, PF_MONITOR_SERVICE, &listener) ||
        service_provider_enter_capability_mode(provider) || service_provider_ready(provider)) {
        perror("5BSD PF state broker startup"); return 1;
    }
    int queue = kqueue();
    if (queue < 0) return 1;
    struct kevent change, event;
    EV_SET(&change, service_listener_fd(listener), EVFILT_READ, EV_ADD, 0, 0, NULL);
    if (kevent(queue, &change, 1, NULL, 0, NULL)) return 1;
    for (;;) {
        if (kevent(queue, NULL, 0, &event, 1, NULL) < 0) { if (errno == EINTR) continue; return 1; }
        struct service_identity identity = { .size = sizeof(identity) };
        int fd;
        if (service_listener_accept(listener, &identity, &fd)) continue;
        /* switchboard admits only holders of system.network.pf.read.
         * Never interpret caller-supplied labels as authority. */
        if (!service_rights_allow(identity.rights, PF_MONITOR_RIGHT_READ)) {
            logcmp_log(LOG_NOTICE, "PF session lacks snapshot rights");
            close(fd); continue;
        }
        struct channel *channel;
        struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
        options.max_queued_messages = 2; options.max_queued_fds = 1; options.max_queued_bytes = 1024;
        if (channel_create(fd, &options, &channel)) { close(fd); continue; }
        struct request_state state = { directory, false };
        if (channel_set_request_handler(channel, request, &state) == 0) {
            /* A stalled authorized client gets at most 5s.
             * One request per connection. Keep the endpoint alive until the
             * client consumes its reply and closes; closing immediately can
             * discard the queued descriptor before the receiver takes it. */
            struct timespec started, now;
            if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
                channel_destroy(channel); continue;
            }
            while (true) {
                if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) break;
                long elapsed = (now.tv_sec - started.tv_sec) * 1000 +
                    (now.tv_nsec - started.tv_nsec) / 1000000;
                if (elapsed >= 5000) break;
                int ready = channel_wait(channel, channel_wants_write(channel) > 0, 5000 - elapsed);
                if (ready <= 0) {
                    if (!state.done) logcmp_log(LOG_WARNING, "PF request wait: %s",
                        ready == 0 ? "timed out" : strerror(errno));
                    break;
                }
                if ((ready & CHANNEL_WAIT_WRITE) && channel_flush(channel) < 0) break;
                if ((ready & CHANNEL_WAIT_READ) && channel_dispatch(channel) < 0) break;
            }
        }
        channel_destroy(channel);
    }
}
