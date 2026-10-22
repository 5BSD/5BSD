// SPDX-License-Identifier: BSD-2-Clause
#include <sys/event.h>
#include <sys/socket.h>
#include <cassert>
#include <chrono>
#include <thread>
#include "dtraced_events.h"
#include "dtraced_job.h"
#include "dtraced_state.h"
using namespace dtraced;
int main()
{
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    int kq = kqueue(); assert(kq >= 0);
    state s {};
    s.kq_hdl = kq;
    dtd_initmsg_t init {};
    auto *client = new client_fd(kq, pair[0], init);
    auto token = s.client_events.add(client);
    assert(token != 0);
    client->event_cookie = token;
    assert(client->enable_rw(reinterpret_cast<void *>(token)));
    s.sockfds.insert(client);
    auto *pinned = s.client_events.lookup(token, pair[0]);
    assert(pinned == client);
    auto *pending = new job(KILL, client);
    s.joblist.push_back(pending);
    client->acquire(); client->acquire();
    std::thread a([&] { s.kill_socket(client); client->release(); });
    std::thread b([&] { s.kill_socket(client); client->release(); });
    a.join(); b.join();
    assert(s.deadfds.size() == 1 && s.sockfds.empty());
    assert(s.client_events.lookup(token, pair[0]) == nullptr);
    assert(!client->re_enable_read() && !client->re_enable_write());
    assert(!client->is_dead());
    std::thread cleaner([&] { s.clean_jobs(); });
    bool cleaned = false;
    for (int i = 0; i < 1000 && !cleaned; i++) {
        {
            std::lock_guard lock(s.deadfdsmtx);
            cleaned = client->cleaned_up;
            if (!cleaned) s.jobcleancv.notify_all();
        }
        if (!cleaned) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    assert(cleaned);
    s.shutdown.store(1); s.jobcleancv.notify_all(); cleaner.join();
    assert(s.joblist.empty() && !client->can_reap());
    pinned->release(); assert(client->can_reap());
    s.deadfds.erase(client);
    int oldfd = pair[0];
    delete client; close(pair[1]);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    if (pair[0] != oldfd) {
        assert(pair[1] != oldfd);
        assert(dup2(pair[0], oldfd) == oldfd);
        close(pair[0]); pair[0] = oldfd;
    }
    auto *replacement = new client_fd(kq, pair[0], init);
    auto new_token = s.client_events.add(replacement);
    assert(new_token != token);
    // Old kqueue data cannot resolve to a new client using the same fd.
    assert(s.client_events.lookup(token, oldfd) == nullptr);
    assert(s.client_events.lookup(new_token, oldfd + 100) == nullptr);
    auto *current = s.client_events.lookup(new_token, oldfd);
    assert(current == replacement); current->release();
    s.client_events.remove(new_token);
    assert(replacement->is_dead());
    delete replacement;
    close(pair[1]); close(kq);
    puts("PASS: stale event tokens, fd reuse, pinned dispatch, concurrent retirement, queued job cleanup");
}
