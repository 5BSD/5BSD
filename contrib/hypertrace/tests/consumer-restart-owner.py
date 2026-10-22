#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise replacement-PID replay with explicit retirement evidence."""
from pathlib import Path
import subprocess,sys
root=Path(__file__).resolve().parents[3]
out=Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True,exist_ok=True)
s=(root/'usr.sbin/dtraced/dtraced_directory.cc').read_text()
a=s.index('static int\nconsumer_replay_owner(')
b=s.index('int\ndir::queue_recovered_consumer',a)
fixture=r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <sys/types.h>
#include <initializer_list>
enum class consumer_receipt_phase : char {
 pending='p',processed='c',no_derived='n',derived='d',
 executed_no_derived='N',executed_derived='D'
};
struct durable_consumer_receipt { uint32_t consumer_uid,consumer_pid; };
struct durable_consumer_receipt_state {
 durable_consumer_receipt record;consumer_receipt_phase phase;
};
struct collector_owner_registry {};
static int results[3],calls,prior,prior_calls;
struct dir {
 int consumer_prior_boot_retired(const durable_consumer_receipt &) {
  assert(calls==0);prior_calls++;errno=EPROTO;return prior;
 }
 int result(int stage) {assert(calls++==stage);errno=EIO;return results[stage];}
 int checkpoint_consumer_process_exit(const durable_consumer_receipt &,collector_owner_registry &) {return result(0);}
 int consumer_reaper_exit_status(const durable_consumer_receipt &) {return result(1);}
 int consumer_kernel_handle_retired(const durable_consumer_receipt &) {return result(2);}
};
'''+s[a:b]+r'''
int main() {
 durable_consumer_receipt_state entry{{100,42},consumer_receipt_phase::pending};
 assert(consumer_replay_owner(entry,100,42,true,false)==1);
 assert(consumer_replay_owner(entry,101,42,true,true)==-1 && errno==EPERM);
 for(auto phase:{consumer_receipt_phase::pending,consumer_receipt_phase::processed,
  consumer_receipt_phase::no_derived,consumer_receipt_phase::derived}) {
  entry.phase=phase;
  for(bool retired:{false,true})
   assert(consumer_replay_owner(entry,100,43,false,retired)==-1 && errno==EBUSY);
 }
 for(auto phase:{consumer_receipt_phase::executed_no_derived,consumer_receipt_phase::executed_derived}) {
  entry.phase=phase;
  errno=ESRCH; // A prior missing-PID result is never retirement evidence.
  assert(consumer_replay_owner(entry,100,43,false,false)==-1 && errno==EBUSY);
  assert(consumer_replay_owner(entry,100,43,false,true)==0);
  assert(consumer_replay_owner(entry,100,42,false,false)==-1 && errno==EBUSY);
  assert(consumer_replay_owner(entry,100,42,false,true)==0);
  assert(consumer_replay_owner(entry,101,43,false,true)==-1 && errno==EPERM);
 }
 dir directory;collector_owner_registry owners;
 for(int stage=0;stage<3;stage++)for(int value:{-1,0}) {
  results[0]=results[1]=results[2]=1;results[stage]=value;calls=0;
  assert(consumer_replay_retirement(directory,entry.record,owners)==value);
  assert(calls==stage+1);
  if(value<0)assert(errno==EIO);
 }
 results[0]=results[1]=results[2]=1;calls=0;
 assert(consumer_replay_retirement(directory,entry.record,owners)==1 && calls==3);
 /* A verified registration from an earlier kernel boot proves all three
  * facts without any same-boot query; damaged evidence fails closed. */
 results[0]=results[1]=results[2]=0;
 prior=1;calls=0;prior_calls=0;
 assert(consumer_replay_retirement(directory,entry.record,owners)==1 && calls==0 && prior_calls==1);
 prior=-1;
 assert(consumer_replay_retirement(directory,entry.record,owners)==-1 && errno==EPROTO && calls==0);
 prior=0;
 assert(consumer_replay_retirement(directory,entry.record,owners)==0 && calls==1);
 puts("PASS: replacement PID requires settled execution and explicit process/descendant/handle retirement or a prior-boot registration");
}
'''
(out/'restart.cc').write_text(fixture)
subprocess.run(['c++','-std=c++17','-Wall','-Wextra','-Werror','-UNDEBUG','-fsanitize=address,undefined',str(out/'restart.cc'),'-o',str(out/'restart')],check=True)
subprocess.run([str(out/'restart')],check=True,timeout=30)
