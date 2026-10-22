/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef DTRACED_EVENTS_H
#define DTRACED_EVENTS_H
#include <cerrno>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include "dtraced_connection.h"
namespace dtraced {
/* Kqueue carries non-reused tokens, never pointers to reclaimable clients. */
class event_registry {
    std::mutex mutex;
    uintptr_t next = 1;
    std::unordered_map<uintptr_t, client_fd *> clients;
public:
    ~event_registry() {
        for (auto &entry : clients)
            entry.second->release();
    }
    uintptr_t add(client_fd *client) {
        std::lock_guard lock(mutex);
        if (next == 0) { errno = EOVERFLOW; return 0; }
        uintptr_t token = next++;
        clients.emplace(token, client);
        client->acquire();
        return token;
    }
    /* The returned reference must be released after handling the event. */
    client_fd *lookup(uintptr_t token, int fd) {
        std::lock_guard lock(mutex);
        auto found = clients.find(token);
        if (found == clients.end() || found->second->get_fd() != fd ||
            found->second->retired.load())
            return nullptr;
        found->second->acquire();
        return found->second;
    }
    void remove(uintptr_t token) {
        std::lock_guard lock(mutex);
        auto found = clients.find(token);
        if (found != clients.end()) {
            found->second->release();
            clients.erase(found);
        }
    }
};
}
#endif
