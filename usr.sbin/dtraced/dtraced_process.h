/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef DTRACED_PROCESS_H
#define DTRACED_PROCESS_H
#include <sys/types.h>
#include <sys/procdesc.h>
#include <dttransport.h>
#include <array>
#include <cstdint>
#include <string>
namespace dtraced {
class state;
/* 1 final kernel state destruction, 0 live, -1 unproven/error. */
int collector_handle_retired(const std::array<uint8_t, 24> &);
/* Pin an independently known kernel birth; caller owns the returned descriptor.
 * PD_DAEMON prevents close from killing the observed process. */
int collector_process_pin(pid_t, const pd_birth_identity &, int *);
/* Verified pinned descriptor only: 1 explicit exit, 0 live, -1 unproven/error. */
int collector_process_exited(int);
/* 1 exited owning an empty reaper, 0 insufficient snapshot, -1 error. */
int collector_process_reaper_empty(int);
struct guest_delivery;
struct durable_delivery;
bool spool_identity_from_path(const std::string &,
    std::array<uint8_t, 16> &, std::array<uint8_t, 16> &);
bool find_guest_delivery(state &, const std::string &, guest_delivery &);
bool send_install_observation(int, const guest_delivery &);
bool send_uninstall_observation(int, const guest_delivery &);
bool send_status_query(int, const guest_delivery &, uint64_t);
void retire_guest_delivery(state &, const guest_delivery &);
bool finish_guest_delivery(state &, const guest_delivery &);
durable_delivery guest_delivery_record(const guest_delivery &);
bool handle_host_observation(state &, const dtt_entry_t &);
bool handle_host_status(state &, const dtt_entry_t &);
bool launch_program(state &, const std::string &, bool,
    const char * = "/usr/sbin/dtrace", bool *installed = nullptr,
    pid_t *registered_pid = nullptr, bool require_report = false);
}
#endif
