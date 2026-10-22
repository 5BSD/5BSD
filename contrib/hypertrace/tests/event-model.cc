// SPDX-License-Identifier: BSD-2-Clause
#include "dtraced_events.h"
#include <cassert>
#include <cstdio>
#include <fcntl.h>
#include <memory>
#include <random>
#include <sys/socket.h>
#include <vector>

int main() {
    std::mt19937 random(0x5b5d2026);
    dtd_initmsg_t init{};
    for (unsigned round = 0; round < 128; ++round) {
        int pair[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        const int owned = pair[0];
        {
            dtraced::client_fd client(-1, owned, init);
            client.cleaned_up = true;
            size_t references = 0;
            struct record { uintptr_t token; bool active; };
            std::vector<record> records;
            uintptr_t previous = 0;
            {
                dtraced::event_registry registry;
                for (unsigned step = 0; step < 512; ++step) {
                    unsigned op = random() % 5;
                    if (op == 0 || records.empty()) {
                        auto token = registry.add(&client);
                        assert(token > previous);
                        previous = token;
                        records.push_back({token, true});
                        ++references;
                    } else {
                        auto &record = records[random() % records.size()];
                        if (op == 1) {
                            registry.remove(record.token);
                            if (record.active) --references;
                            record.active = false;
                        } else if (op == 2 || op == 3) {
                            int fd = op == 2 ? owned : -1;
                            auto *found = registry.lookup(record.token, fd);
                            bool expected = record.active && fd == owned &&
                                !client.retired.load();
                            assert((found != nullptr) == expected);
                            if (found) {
                                assert(found == &client && !client.can_reap());
                                found->release();
                            }
                        } else {
                            // Retirement is terminal for this client.
                            client.retired.store(true);
                        }
                    }
                    assert(client.can_reap() == (references == 0));
                    assert(registry.lookup(0, owned) == nullptr);
                }
            }
            // Registry destruction releases every outstanding registration.
            assert(client.can_reap());
        }
        errno = 0;
        assert(fcntl(owned, F_GETFD) == -1 && errno == EBADF);
        assert(fcntl(pair[1], F_GETFD) != -1);
        assert(close(pair[1]) == 0);
    }
    puts("PASS: 65536 modeled event operations; reference release and socket ownership");
}
