/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/hypertrace.h>
#include <dev/dttransport/dttransport.h>
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <unistd.h>

#define DTRACED_SLEEPTIME 10000
static int64_t now_ms;
static int64_t dtraced_io_milliseconds(void) { return now_ms; }
static int64_t dtraced_io_deadline_after(int64_t delta) {
    return now_ms + delta;
}
enum class delivery_phase : char { pending = 'p', accepted = 'a', terminal = 't' };
struct durable_delivery {
    uint8_t scope = 0, journal_version = 3;
    uint64_t delivery_id = 71;
    std::array<uint8_t, 16> program_id{1}, source_id{2};
    std::array<uint8_t, 32> payload_digest{5};
};
struct durable_delivery_state {
    durable_delivery record;
    delivery_phase phase = delivery_phase::pending;
};
struct durable_kill {
    int pid = 123;
    std::array<uint8_t, 16> source_id{7};
};
static int callbacks, commits, queries, get_calls, temporary_ingress;
static int temporary_journal_io, temporary_commit_busy, temporary_pair_io;
static int expected_callbacks = 1;
static bool always_unavailable;
static int expected_queries = 3;
static bool hash_ok = true, deny_ingress, pair_complete = true;
static bool inbound_v4, inbound_missing, inbound_terminal,
    inbound_spool_mismatch;
struct dir {
    bool hash_identified_data(const uint8_t *, const uint8_t *,
        uint8_t digest[32], bool = false) {
        if (inbound_missing) { errno = ENOENT; return false; }
        if (!hash_ok) { errno = EPROTO; return false; }
        memset(digest, 0, 32);
        digest[0] = inbound_v4 && !inbound_spool_mismatch ? 5 : 3;
        return true;
    }
    int verify_pending_outbound(const durable_delivery &) { return 1; }
    bool rekey_guest_journals_with_receipts(dir &, uint16_t, uint64_t,
        uint16_t, uint64_t,
        const std::function<bool(const durable_delivery_state &)> &inbound,
        const std::function<bool(const durable_delivery_state &)> &outbound,
        const std::function<bool(const durable_kill &)> &kill) {
        durable_delivery_state record{};
        record.record.scope = 1;
        if (inbound_v4) {
            record.record.journal_version = 4;
            record.phase = inbound_terminal ? delivery_phase::terminal :
                delivery_phase::accepted;
        }
        ++callbacks;
        if (!inbound(record)) return false;
        record.record.scope = 2;
        record.record.journal_version = 4;
        record.phase = delivery_phase::pending;
        if (!outbound(record)) return false;
        if (!kill(durable_kill{})) return false;
        if (temporary_journal_io > 0) {
            --temporary_journal_io;
            errno = EIO;
            return false;
        }
        return true;
    }
    bool guest_rekey_pair_complete(dir &, uint16_t, uint64_t,
        uint16_t, uint64_t) {
        if (temporary_pair_io > 0) {
            --temporary_pair_io;
            errno = EIO;
            return false;
        }
        if (!pair_complete) {
            errno = EBUSY;
            return false;
        }
        return true;
    }
};
struct state { int dtt_fd = 4; dir *inbounddir, *outbounddir; };
static bool notice_pending, bad_notice, wrong_ack, local_committed,
    malformed_stale;
static int stale_pending;
static ssize_t fake_read(int fd, void *data, size_t size) {
    assert(fd == 4 && size == sizeof(dtt_entry_t));
    if (stale_pending > 0) {
        --stale_pending;
        dtt_entry_t stale{};
        stale.event_kind = DTT_REKEY_DELIVERY_RECEIPT;
        stale.u.installed.delivery_id = 71;
        stale.u.installed.vmid = 42;
        stale.u.installed.epoch = 99;
        stale.u.installed.query_id = 901;
        stale.u.installed.source_id[0] = 2;
        stale.u.installed.replay = malformed_stale ? 1 : 0;
        *static_cast<dtt_entry_t *>(data) = stale;
        return size;
    }
    if (!notice_pending) { errno = EAGAIN; return -1; }
    notice_pending = false;
    dtt_entry_t notice{};
    notice.event_kind = DTT_VM_REKEY;
    notice.u.installed.vmid = bad_notice ? 44 : 43;
    notice.u.installed.epoch = 100;
    *static_cast<dtt_entry_t *>(data) = notice;
    return size;
}
static int fake_ioctl(int fd, unsigned long op, void *data) {
    assert(fd == 4);
    auto *identity = static_cast<dtt_vm_identity *>(data);
    if (op == DTT_COMMIT_VM_REKEY) {
        assert(callbacks == expected_callbacks &&
            queries == expected_queries &&
            identity->flags == 0);
        ++commits;
        if (temporary_commit_busy > 0) {
            --temporary_commit_busy;
            errno = EBUSY;
            return -1;
        }
        return 0;
    }
    assert(op == DTT_GET_VM_IDENTITY);
    ++get_calls;
    identity->vmid = wrong_ack ? 44 : 43;
    identity->epoch = 100;
    identity->old_vmid = 42;
    identity->old_epoch = 99;
    identity->flags = get_calls == 1 ?
        DTT_IDENTITY_REKEY_LOCAL_COMMITTED : 0;
    return 0;
}
static int fake_usleep(unsigned int usec) {
    now_ms += usec / 1000;
    return 0;
}
namespace dtraced {
static bool query_guest_rekey_receipt(int fd, uint8_t kind,
    uint16_t old_vmid, uint64_t old_epoch, uint16_t new_vmid,
    uint64_t new_epoch, uint64_t delivery_id, const uint8_t program[16],
    const uint8_t source[16], const uint8_t digest[32],
    bool terminal_ok, int64_t deadline) {
    assert(fd == 4 && old_vmid == 42 && old_epoch == 99 &&
        new_vmid == 43 && new_epoch == 100 && deadline >= now_ms &&
        deadline - now_ms <= 50000);
    assert(source[0] != 0 && delivery_id != 0);
    if (kind == DTT_REKEY_DELIVERY_QUERY) {
        assert(terminal_ok == inbound_terminal);
        assert(program[0] == 1 && digest[0] ==
            (inbound_v4 ? 5 : 3));
    } else if (kind == DTT_REKEY_INGRESS_QUERY) {
        assert(!terminal_ok);
        assert(program[0] == 1 && digest[0] == 5);
    } else {
        assert(!terminal_ok);
        assert(kind == DTT_REKEY_KILL_QUERY && delivery_id == 123 &&
            program[0] == 0 && digest[0] == 0);
    }
    ++queries;
    if (kind == DTT_REKEY_INGRESS_QUERY &&
        (temporary_ingress > 0 || always_unavailable)) {
        if (temporary_ingress > 0) --temporary_ingress;
        errno = EAGAIN; return false;
    }
    if (kind == DTT_REKEY_INGRESS_QUERY && deny_ingress) {
        errno = EACCES; return false;
    }
    return true;
}
#define read fake_read
#define ioctl fake_ioctl
#define usleep fake_usleep
#include "guest-rekey-startup.inc"
#undef usleep
#undef ioctl
#undef read
}
int main(void) {
    dir inbound, outbound;
    state s{4, &inbound, &outbound};
    dtt_vm_identity identity{43, 42, DTT_IDENTITY_REKEY_PENDING, 100, 99};
    notice_pending = true;
    assert(dtraced::recover_guest_rekey(&s, identity));
    assert(commits == 1 && callbacks == 1 && queries == 3 && get_calls == 2);
    callbacks = commits = queries = get_calls = 0;
    temporary_journal_io = 1;
    temporary_commit_busy = 2;
    expected_callbacks = 2;
    expected_queries = 6;
    assert(dtraced::recover_guest_rekey(&s, identity));
    assert(callbacks == 2 && queries == 6 && commits == 3 &&
        temporary_journal_io == 0 && temporary_commit_busy == 0);
    callbacks = commits = queries = get_calls = 0;
    expected_callbacks = 1;
    expected_queries = 3;
    temporary_commit_busy = 10000;
    assert(!dtraced::recover_guest_rekey(&s, identity) &&
        errno == ETIMEDOUT);
    assert(callbacks == 1 && queries == 3 && commits > 1);
    temporary_commit_busy = 0;
    callbacks = commits = queries = get_calls = 0;
    stale_pending = 1;
    notice_pending = true;
    assert(dtraced::recover_guest_rekey(&s, identity));
    assert(commits == 1 && callbacks == 1 && queries == 3);
    callbacks = commits = queries = get_calls = 0;
    stale_pending = 3;
    notice_pending = true;
    assert(dtraced::recover_guest_rekey(&s, identity));
    assert(commits == 1 && callbacks == 1 && queries == 3);
    callbacks = commits = queries = get_calls = 0;
    stale_pending = 1;
    malformed_stale = true;
    assert(!dtraced::recover_guest_rekey(&s, identity) && errno == EPROTO);
    assert(commits == 0 && callbacks == 0);
    malformed_stale = false;
    stale_pending = 0;
    notice_pending = false;
    temporary_ingress = 1;
    expected_queries = 4;
    assert(dtraced::recover_guest_rekey(&s, identity));
    assert(commits == 1 && callbacks == 1 && queries == 4);
    expected_queries = 3;
    callbacks = commits = queries = get_calls = 0;
    inbound_v4 = true;
    assert(dtraced::recover_guest_rekey(&s, identity));
    assert(commits == 1 && callbacks == 1 && queries == 3);
    callbacks = commits = queries = get_calls = 0;
    inbound_spool_mismatch = true;
    assert(!dtraced::recover_guest_rekey(&s, identity) && errno == EPROTO);
    assert(commits == 0 && callbacks == 1 && queries == 0);
    inbound_spool_mismatch = false;
    callbacks = commits = queries = get_calls = 0;
    inbound_v4 = inbound_missing = true;
    assert(!dtraced::recover_guest_rekey(&s, identity) && errno == EPROTO);
    assert(commits == 0 && callbacks == 1 && queries == 0);
    inbound_v4 = inbound_missing = false;
    callbacks = commits = queries = get_calls = 0;
    inbound_v4 = inbound_missing = inbound_terminal = true;
    assert(dtraced::recover_guest_rekey(&s, identity));
    assert(commits == 1 && callbacks == 1 && queries == 3);
    inbound_v4 = inbound_missing = inbound_terminal = false;
    callbacks = commits = queries = get_calls = 0;
    always_unavailable = true;
    assert(!dtraced::recover_guest_rekey(&s, identity) &&
        errno == ETIMEDOUT && commits == 0);
    always_unavailable = false;
    callbacks = queries = get_calls = 0;
    bad_notice = notice_pending = true;
    assert(!dtraced::recover_guest_rekey(&s, identity) && errno == EPROTO);
    assert(commits == 0 && callbacks == 0);
    bad_notice = false;
    hash_ok = false;
    assert(!dtraced::recover_guest_rekey(&s, identity));
    assert(commits == 0 && callbacks == 1);
    hash_ok = true;
    callbacks = queries = 0;
    deny_ingress = true;
    assert(!dtraced::recover_guest_rekey(&s, identity) && errno == EACCES);
    assert(commits == 0 && queries == 2);
    deny_ingress = false;
    callbacks = queries = get_calls = 0;
    temporary_journal_io = 10000;
    assert(!dtraced::recover_guest_rekey(&s, identity) &&
        errno == ETIMEDOUT && commits == 0);
    assert(callbacks > 1);
    temporary_journal_io = 0;
    callbacks = queries = get_calls = 0;
    local_committed = true;
    identity.flags = DTT_IDENTITY_REKEY_LOCAL_COMMITTED;
    temporary_pair_io = 1;
    assert(dtraced::recover_guest_rekey(&s, identity));
    assert(temporary_pair_io == 0);
    assert(commits == 0 && callbacks == 0 && queries == 0);
    pair_complete = false;
    assert(!dtraced::recover_guest_rekey(&s, identity));
    pair_complete = true;
    local_committed = false;
    puts("PASS: startup rekey receipts precede commit; retries check durable completion");
}
