/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef DTRACED_COLLECTOR_OWNER_H
#define DTRACED_COLLECTOR_OWNER_H
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <new>
#include <unistd.h>
namespace dtraced {
int collector_process_exited(int);
int collector_process_reaper_empty(int);
using collector_owner_key = std::array<uint8_t, 96>;
inline collector_owner_key
collector_owner_identity(const std::array<uint8_t, 16> &session,
    const std::array<uint8_t, 16> &birth, uint32_t uid, uint32_t pid,
    const std::array<uint8_t, 32> &program, const std::array<uint8_t, 24> &handle)
{
    collector_owner_key key{};
    memcpy(key.data(), session.data(), 16);
    memcpy(key.data() + 16, birth.data(), 16);
    for (unsigned i = 0; i < 4; i++) {
        key[32 + i] = (uint8_t)(uid >> (8 * i));
        key[36 + i] = (uint8_t)(pid >> (8 * i));
    }
    memcpy(key.data() + 40, program.data(), 32);
    memcpy(key.data() + 72, handle.data(), 24);
    return key;
}
/* Process evidence survives socket destruction. No eviction before durable
 * shared exit evidence: reaching the bound refuses new admission instead of losing proof.
 * Caller supplies only a descriptor verified against the authenticated birth. */
class collector_owner_registry {
    std::mutex mutex;
    std::map<collector_owner_key, int> owners;
    static constexpr size_t limit = 4096;
public:
    ~collector_owner_registry() {
        for (const auto &entry : owners) (void)close(entry.second);
    }
    int retain(const collector_owner_key &key, int verified_fd) {
        if (verified_fd < 0) { errno = EBADF; return -1; }
        std::lock_guard lock(mutex);
        if (owners.find(key) != owners.end()) return 0;
        if (owners.size() >= limit) { errno = ENOSPC; return -1; }
        int fd = fcntl(verified_fd, F_DUPFD_CLOEXEC, 0);
        if (fd < 0) return -1;
        try { owners.emplace(key, fd); }
        catch (const std::bad_alloc &) { close(fd); errno = ENOMEM; return -1; }
        return 0;
    }
    /* Caller must first sync shared exit evidence for this exact identity. */
    int release_after_durable_exit(const collector_owner_key &key) {
        std::lock_guard lock(mutex);
        auto found = owners.find(key);
        if (found == owners.end()) return 0;
        int fd = found->second;
        owners.erase(found);
        return close(fd); // Never retry close against a potentially reused fd.
    }
    bool retained(const collector_owner_key &key) {
        std::lock_guard lock(mutex);
        return owners.find(key) != owners.end();
    }
    /* Copy a bounded fair batch without holding the registry during I/O.
     * Removed cursors remain valid ordering points; each key appears once. */
    size_t batch_after(collector_owner_key &cursor,
        std::array<collector_owner_key, 32> &batch) {
        std::lock_guard lock(mutex);
        if (owners.empty()) return 0;
        auto it = owners.upper_bound(cursor);
        if (it == owners.end()) it = owners.begin();
        auto first = it;
        size_t count = 0;
        do {
            batch[count++] = it->first;
            if (++it == owners.end()) it = owners.begin();
        } while (count < batch.size() && it != first);
        cursor = batch[count - 1];
        return count;
    }
    int reaper_empty(const collector_owner_key &key) {
        std::lock_guard lock(mutex);
        auto found = owners.find(key);
        if (found == owners.end()) { errno = EAGAIN; return -1; }
        return collector_process_reaper_empty(found->second);
    }
    int exited(const collector_owner_key &key) {
        std::lock_guard lock(mutex);
        auto found = owners.find(key);
        if (found == owners.end()) { errno = EAGAIN; return -1; }
        return collector_process_exited(found->second);
    }
};
}
#endif
