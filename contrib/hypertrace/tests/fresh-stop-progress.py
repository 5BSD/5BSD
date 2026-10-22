#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
s = (root / 'usr.sbin/dtraced/dtraced_state.cc').read_text()
a = s.index('int\nstate::stop_fresh_session_step(')
b = s.index('\nvoid\nstate::retire_handoff_consumers', a)
fixture = r'''
#include <array>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <mutex>
#include <vector>
#include <cstdint>
#include <sys/types.h>
constexpr int DTRACED_KIND_CONSUMER = 1, DTD_SUB_ELFWRITE = 1;
struct durable_session_stop { std::array<uint8_t,16> token{}, source_session{}; uint16_t vmid=1; uint64_t epoch=2; };
struct host_ingress_program_evidence {
 struct { std::array<uint8_t,16> consumer_session{}; uid_t consumer_uid=1; pid_t consumer_pid=1; } recipient;
 std::array<uint8_t,76> owner_wire{};
 std::array<uint8_t,32> program_digest{};
};
struct dtraced_consumer_stop_t {
 uint8_t token[16], source_session[16], consumer_session[16], program_digest[32];
 uint16_t vmid; uint64_t epoch;
};
static int requests, request_error, references, receipt_error, recoveries;
static int checkpoint_result = -1, reaper_result, handle_result, handle_queries;
struct client_fd {
 std::atomic_bool retired{false}; int kind=DTRACED_KIND_CONSUMER;
 bool consumer_replay_pending=false, consumer_birth_valid=true, consumer_program_valid=true;
 std::array<uint8_t,16> session_id{}, consumer_birth{};
 std::array<uint8_t,32> consumer_program_digest{};
 uid_t peer_uid=1; pid_t peer_pid=1;
 bool is_subscribed(int) { return true; }
 void acquire() { references++; }
 void release() { references--; }
 bool request_consumer_stop(const dtraced_consumer_stop_t &c) {
  assert(c.consumer_session[0] == session_id[0]); requests++;
  errno=request_error; return request_error==0;
 }
};
struct directory {
 template<class T> int consumer_reaper_exit_status(const T &) { return reaper_result; }
 template<class T> int consumer_kernel_handle_retired(const T &) { handle_queries++;return handle_result; }
 template<class T> int checkpoint_consumer_process_exit(const T &, int &) {
  errno=EAGAIN; return checkpoint_result;
 }
 template<class T> int recover_consumer_process(const T &, int &) {
  recoveries++; return 1; /* Pin recovered, but no collector-stop proof. */
 }
 std::vector<host_ingress_program_evidence> recipients;
 bool done[3] = {false,false,false};
 int completed = 0;
 int fresh_session_stop_completed(const durable_session_stop &) {
  if (completed < 0) errno=EPROTO;
  return completed;
 }
 int completion_error = 0;
 int complete_fresh_session_stop(directory &, const durable_session_stop &) {
  if (completion_error) { errno=completion_error; return -1; }
  return 1;
 }
 int fresh_session_consumers(directory &, const durable_session_stop &,
  std::vector<host_ingress_program_evidence> &out) { out=recipients; return 0; }
 int fresh_consumer_stop_receipt(directory &, const durable_session_stop &,
  const host_ingress_program_evidence &p, bool publish) {
  if (receipt_error) { errno=receipt_error; return -1; }
  unsigned id=p.recipient.consumer_session[0]; assert(id<3);
  if (publish) done[id]=true;
  return done[id] ? 1 : 0;
 }
};
struct state {
 directory *inbounddir, *outbounddir;
 int collector_owners = 0;
 std::mutex sockfdsmtx;
 std::vector<client_fd *> sockfds;
 bool is_control_machine() { return true; }
 void kill_socket(client_fd *c) { c->retired=true; }
 int stop_fresh_session_step(const durable_session_stop &);
};
'''
fixture += s[a:b]
fixture += r'''
int main() {
 directory in,out; state s{&in,&out}; durable_session_stop stop;
 for (unsigned id=0; id<3; id++) {
  host_ingress_program_evidence p; p.recipient.consumer_session[0]=id;
  in.recipients.push_back(p);
 }
 client_fd first,second; first.session_id[0]=1; second.session_id[0]=2;
 s.sockfds={&first,&second};
 /* Recipient zero crashed before proof. Later connected recipients still stop,
  * at most one RPC per step, without claiming whole-session completion. */
 assert(s.stop_fresh_session_step(stop)==1 && requests==1 && references==0);
 assert(in.done[1] && !in.done[0] && !in.done[2] && recoveries==1);
 assert(s.stop_fresh_session_step(stop)==1 && requests==2 && references==0);
 assert(in.done[2] && !in.done[0]);
 checkpoint_result=1; /* Durable process exit still is not FSA1. */
 assert(s.stop_fresh_session_step(stop)==-1 && errno==EAGAIN && requests==2);
 assert(handle_queries==0);
 for(int evidence : {-1,0}) {
  reaper_result=evidence;handle_result=1;
  assert(s.stop_fresh_session_step(stop)==-1 && errno==EAGAIN && !in.done[0]);
 }
 assert(handle_queries==0);
 reaper_result=1;
 for(int evidence : {-1,0}) {
  handle_result=evidence;
  assert(s.stop_fresh_session_step(stop)==-1 && errno==EAGAIN && !in.done[0]);
 }
 handle_result=1;
 assert(s.stop_fresh_session_step(stop)==0 && requests==2 && in.done[0]);
 assert(s.stop_fresh_session_step(stop)==0 && requests==2);
 in.completion_error=EIO;
 assert(s.stop_fresh_session_step(stop)==-1 && errno==EIO && requests==2);
 in.completion_error=0;
 assert(s.stop_fresh_session_step(stop)==0 && requests==2);
 out.completed=-1;
 assert(s.stop_fresh_session_step(stop)==-1 && errno==EPROTO && requests==2);
 out.completed=1; receipt_error=EIO;
 assert(s.stop_fresh_session_step(stop)==0 && requests==2);
 out.completed=0; receipt_error=0;
 reaper_result=handle_result=0;
 /* A reconnected but not-yet-audited consumer is also unproven. */
 in.done[0]=false; client_fd late; late.consumer_replay_pending=true;
 s.sockfds.push_back(&late);
 assert(s.stop_fresh_session_step(stop)==-1 && errno==EAGAIN);
 late.consumer_replay_pending=false; request_error=EPIPE;
 assert(s.stop_fresh_session_step(stop)==-1 && errno==EAGAIN && !in.done[0]);
 assert(references==0);
 receipt_error=EPROTO;
 assert(s.stop_fresh_session_step(stop)==-1 && errno==EPROTO);
 return 0;
}
'''
(out / 'progress.cc').write_text(fixture)
subprocess.run(['c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
    '-Wno-missing-field-initializers', '-fsanitize=address,undefined', '-pthread',
    str(out / 'progress.cc'), '-o', str(out / 'progress')], check=True)
subprocess.run([str(out / 'progress')], cwd=out, check=True, timeout=30)
print('PASS: missing collector does not starve later stops; missing proof never completes')
