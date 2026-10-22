#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise startup collector pin recovery without starting a daemon."""
from pathlib import Path
import subprocess,sys
root=Path(__file__).resolve().parents[3]
out=Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True,exist_ok=True)
s=(root/'usr.sbin/dtraced/dtraced_state.cc').read_text()
a=s.index('bool\nstate::recover_collector_owners(')
b=s.index('int\nstate::stop_fresh_session_step(',a)
fixture=r'''
#include <cassert>
#include <cerrno>
#include <vector>
struct durable_consumer_receipt_state { int record; };
struct reply { bool recover; int id,result,error; };
static std::vector<reply> replies;
static unsigned cursor;
static int consume(bool recover,int id) {
 assert(cursor<replies.size());auto r=replies[cursor++];
 assert(r.recover==recover && r.id==id);errno=r.error;return r.result;
}
struct directory {
 int checkpoint_consumer_process_exit(int id,int &) {return consume(false,id);}
 int recover_consumer_process(int id,int &) {return consume(true,id);}
};
struct state {
 directory *inbounddir;
 int collector_owners=0;
 bool control=true;
 bool is_control_machine() {return control;}
 bool recover_collector_owners(const std::vector<durable_consumer_receipt_state> &);
};
'''+s[a:b]+r'''
int main() {
 directory in;state s{&in};
 auto check=[&](std::vector<reply> sequence,bool expected,unsigned count=1){
  replies=sequence;cursor=0;std::vector<durable_consumer_receipt_state> inventory;
  for(unsigned i=0;i<count;i++)inventory.push_back({int(i)});
  assert(s.recover_collector_owners(inventory)==expected);
  assert(cursor==replies.size());
 };
 check({},true,0);
 check({{false,0,1,0}},true); // Durable exit, no process lookup.
 check({{false,0,0,0}},true); // Existing live pin, no duplicate lookup.
 check({{false,0,-1,EAGAIN},{true,0,1,0},{false,0,0,0}},true);
 check({{false,0,-1,EAGAIN},{true,0,1,0},{false,0,1,0}},true); // Exit during pin.
 for(int error:{EAGAIN,ESRCH,ESTALE,ENOTTY,EOPNOTSUPP}) {
  check({{false,0,-1,error},{true,0,-1,error},{false,1,1,0}},true,2);
  check({{false,0,-1,EAGAIN},{true,0,1,0},{false,0,-1,error}},true);
 }
 for(int error:{EPROTO,EIO,ENOMEM,ENOSPC,EMFILE,EACCES}) {
  check({{false,0,-1,error}},false);
  check({{false,0,-1,EAGAIN},{true,0,-1,error}},false);
  check({{false,0,-1,EAGAIN},{true,0,1,0},{false,0,-1,error}},false);
 }
 replies.clear();cursor=0;s.control=false;
 assert(!s.recover_collector_owners({}) && errno==EINVAL && cursor==0);
 s.control=true;s.inbounddir=nullptr;
 assert(!s.recover_collector_owners({}) && errno==EINVAL && cursor==0);
}
'''
(out/'startup.cc').write_text(fixture)
subprocess.run(['c++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(out/'startup.cc'),'-o',str(out/'startup')],check=True)
subprocess.run([str(out/'startup')],check=True,timeout=30)
print('PASS: startup live-pin recovery, raced exit, unresolved ownership and fatal recovery errors')
