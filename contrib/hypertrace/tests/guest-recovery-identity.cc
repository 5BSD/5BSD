/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <dttransport.h>
#include <sys/hypertrace.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <vector>

struct durable_delivery {
    uint16_t vmid;
    uint64_t epoch;
    uint8_t scope;
};
struct durable_delivery_state { durable_delivery record; };
struct durable_kill { uint16_t vmid; uint64_t epoch; };

static int calls, pending, fail_errno;
static int64_t now_ms;
static int fail_clock_after = -1;
static dtt_vm_identity current{7, 0, 0, 11, 0};
static dtt_cleanup_state cleanup_state{};
static bool recovery_ready;
static int applied_reports;
static int report_error;
static uint8_t expected_report = DTT_CLEANUP_APPLIED;
static bool activate_after_ready;
static bool test_recover_guest_children(int directory, bool pending_cleanup) {
    assert(directory == 3);
    if (pending_cleanup && !recovery_ready) { errno = EBUSY; return false; }
    return true;
}
static ssize_t test_write(int fd, const void *buffer, size_t size) {
    assert(fd == 4 && size == sizeof(dtt_entry_t));
    const auto *report = static_cast<const dtt_entry_t *>(buffer);
    assert(report->event_kind == expected_report &&
        report->u.cleanup.delivery_id == 123 &&
        report->u.cleanup.vmid == 7 && report->u.cleanup.epoch == 11);
    ++applied_reports;
    if (report_error) {
        now_ms += 1000;
        errno = report_error;
        return -1;
    }
    if (activate_after_ready && report->event_kind == DTT_SESSION_READY)
        current.flags = DTT_IDENTITY_FRESH_ACTIVE;
    return size;
}
static int64_t dtraced_io_milliseconds(void) {
    if (fail_clock_after == 0) {
        errno = EIO;
        return -1;
    }
    if (fail_clock_after > 0)
        --fail_clock_after;
    return now_ms;
}
#include "guest-deadline.inc"
static int test_usleep(unsigned int usec) {
    now_ms += usec / 1000;
    return 0;
}
static int test_ioctl(int fd, unsigned long cmd, void *data) {
    assert(fd == 4);
    if (cmd == DTT_GET_CLEANUP_STATE) {
        *static_cast<dtt_cleanup_state *>(data) = cleanup_state;
        return 0;
    }
    assert(cmd == DTT_GET_VM_IDENTITY);
    ++calls;
    if (pending-- > 0 || fail_errno != 0) {
        errno = fail_errno != 0 ? fail_errno : EAGAIN;
        return -1;
    }
    *static_cast<dtt_vm_identity *>(data) = current;
    return 0;
}
#define ioctl test_ioctl
#define usleep test_usleep
#define recover_guest_children test_recover_guest_children
#define write test_write
#include "guest-recovery-identity.inc"
#undef ioctl
#undef usleep
#undef recover_guest_children
#undef write

int main(void) {
    std::vector<durable_delivery_state> outbound, inbound;
    std::vector<durable_kill> kills;
    assert(validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(calls == 1);
    assert(validate_guest_cleanup_recovery_state(4, 3));
    cleanup_state = {123, 11, 7, DTT_CLEANUP_STATE_PENDING, 0};
    assert(!validate_guest_cleanup_recovery_state(4, 3) && errno == EBUSY);
    recovery_ready = true;
    assert(validate_guest_cleanup_recovery_state(4, 3) &&
        applied_reports == 1);
    cleanup_state.flags |= DTT_CLEANUP_STATE_APPLIED;
    assert(validate_guest_cleanup_recovery_state(4, 3));
    cleanup_state.epoch = 10;
    assert(!validate_guest_cleanup_recovery_state(4, 3) && errno == EPROTO);
    cleanup_state.epoch = 11;
    cleanup_state.reserved = 1;
    assert(!validate_guest_cleanup_recovery_state(4, 3) && errno == EPROTO);
    cleanup_state.reserved = 0;
    cleanup_state.flags = DTT_CLEANUP_STATE_PENDING | DTT_CLEANUP_STATE_SESSION_STOP;
    expected_report = DTT_SESSION_STOPPED;
    recovery_ready = false;
    int reports_before = applied_reports;
    assert(!validate_guest_cleanup_recovery_state(4, 3) && errno == EBUSY);
    assert(applied_reports == reports_before);
    recovery_ready = true;
    assert(!validate_guest_cleanup_recovery_state(4, 3) && errno == ESHUTDOWN);
    assert(applied_reports == reports_before + 1);
    cleanup_state.flags |= DTT_CLEANUP_STATE_APPLIED;
    assert(!validate_guest_cleanup_recovery_state(4, 3) && errno == ESHUTDOWN);
    assert(applied_reports == reports_before + 2);
    current.flags = DTT_IDENTITY_REKEY_PENDING;
    assert(!validate_guest_cleanup_recovery_state(4, 3) && errno == EPROTO);
    assert(applied_reports == reports_before + 2);
    current.flags = 0;
    report_error = EIO;
    assert(!validate_guest_cleanup_recovery_state(4, 3) && errno == EIO);
    report_error = EINTR;
    assert(!validate_guest_cleanup_recovery_state(4, 3) && errno == ETIMEDOUT);
    report_error = 0;
    cleanup_state.flags = DTT_CLEANUP_STATE_SESSION_STOP;
    assert(!validate_guest_cleanup_recovery_state(4, 3) && errno == EPROTO);
    cleanup_state = {123, 10, 6, DTT_CLEANUP_STATE_PENDING |
        DTT_CLEANUP_STATE_APPLIED | DTT_CLEANUP_STATE_SESSION_STOP, 0};
    current = {7, 6, DTT_IDENTITY_FRESH_PENDING, 11, 10};
    auto proposed = current;
    expected_report = DTT_SESSION_READY;
    activate_after_ready = true;
    assert(activate_guest_fresh_session(4, proposed));
    assert(current.flags == DTT_IDENTITY_FRESH_ACTIVE);
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills) &&
        errno == ESTALE);
    assert(validate_guest_recovery_identity(4, outbound, inbound, kills,
        nullptr, true));
    current = proposed;
    activate_after_ready = false;
    assert(!activate_guest_fresh_session(4, proposed) && errno == ETIMEDOUT);
    cleanup_state.epoch++;
    assert(!activate_guest_fresh_session(4, proposed) && errno == EPROTO);
    cleanup_state.epoch--;
    current.epoch++;
    assert(!activate_guest_fresh_session(4, proposed) && errno == ESTALE);
    current = {7, 0, 0, 11, 0};
    cleanup_state = {};
    current.vmid = 0;
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(errno == EPROTO);
    current.vmid = 7;
    current.vmid = HYPERTRACE_MAX_VMS;
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(errno == EPROTO);
    current.vmid = 7;
    current.epoch = 0;
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(errno == EPROTO);
    current.epoch = 11;
    current.flags = 2;
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(errno == EPROTO);
    current.flags = 0;
    current.old_vmid = 6;
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(errno == EPROTO);
    current.old_vmid = 0;
    current.flags = DTT_IDENTITY_REKEY_PENDING;
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(errno == EPROTO);
    current.old_vmid = 6;
    current.old_epoch = 0;
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(errno == EPROTO);
    current.old_epoch = 10;
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(errno == ESTALE);
    dtt_vm_identity interrupted{};
    assert(validate_guest_recovery_identity(4, outbound, inbound, kills,
        &interrupted));
    assert(interrupted.vmid == 7 && interrupted.epoch == 11 &&
        interrupted.old_vmid == 6 && interrupted.old_epoch == 10 &&
        interrupted.flags == DTT_IDENTITY_REKEY_PENDING);
    current.flags = DTT_IDENTITY_REKEY_LOCAL_COMMITTED;
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(errno == ESTALE);
    current.flags |= DTT_IDENTITY_REKEY_PENDING;
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(errno == EPROTO);
    current.flags = 0;
    current.old_vmid = 0;
    current.old_epoch = 0;
    outbound.push_back({{7, 11, 2}});
    inbound.push_back({{7, 11, 1}});
    kills.push_back({7, 11});
    int before_retries = calls;
    pending = 2;
    assert(validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(calls == before_retries + 3);
    current.flags = DTT_IDENTITY_REKEY_PENDING;
    current.old_vmid = 6;
    current.old_epoch = 10;
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(errno == ESTALE);
    current.flags = 0;
    current.old_vmid = 0;
    current.old_epoch = 0;
    outbound[0].record.vmid = outbound[0].record.epoch = 0;
    assert(validate_guest_recovery_identity(4, outbound, inbound, kills));
    outbound[0].record.vmid = 7;
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(errno == ESTALE);
    outbound[0].record.epoch = 11;
    outbound[0].record.epoch = 10;
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(errno == ESTALE);
    outbound[0].record.epoch = 11;
    inbound[0].record.vmid = 8;
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(errno == ESTALE);
    inbound[0].record.vmid = 7;
    kills[0].epoch = 10;
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(errno == ESTALE);
    kills[0].epoch = 11;
    fail_errno = EIO;
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(errno == EIO);
    fail_errno = 0;
    fail_clock_after = 0;
    int before = calls;
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(errno == EIO && calls == before);
    fail_clock_after = 1;
    pending = 1;
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(errno == EIO && calls == before + 1);
    fail_clock_after = -1;
    fail_errno = ENXIO;
    now_ms = 0;
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(errno == ETIMEDOUT && now_ms >= 30000);
    fail_errno = 0;
    now_ms = INT64_MAX - 29999;
    before = calls;
    assert(!validate_guest_recovery_identity(4, outbound, inbound, kills));
    assert(errno == EOVERFLOW && calls == before);
    puts("PASS: guest recovery identity matches, rejects stale journals, and fails closed");
}
